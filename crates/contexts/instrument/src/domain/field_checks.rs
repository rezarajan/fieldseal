//! Field checks over a set of records (INS §5.6, `EvaluateFieldChecks`).
//!
//! Field checks are advisory (INS-053): they never block anything. Each raised check names
//! the records involved (INS-052). Records are given in capture order; `drift` reads them in
//! that order. Each record is first evaluated as `EvaluateRules` would, so checks see the
//! same effective values: visible, converted to the item's unit, nonresponse excluded, and a
//! `measurement-pair` as the mean of its readings.
//!
//! Definitions where the specification leaves the bound open:
//! - `distribution` with `{mean, sd}` raises when the cohort mean lies further than
//!   `bound × sd / √n` from `mean` (a z-test of the mean; `bound` defaults to 3). With
//!   `{min, max}` it raises when the cohort mean is outside the range. Fewer than `minCount`
//!   values never raise.
//! - `drift` looks at the last `window` values; it raises when they never decrease and rise
//!   by more than `threshold` in total, or never increase and fall by more than it.
//! - `duplicates` raises once per cluster of records of different subjects linked by pairs
//!   that match on at least `minMatch` of `paths` (both set and equal).
//! - `completeness` raises for records whose share of unanswered, visible, non-optional
//!   items in scope exceeds `threshold`.
//! - `straightlining` raises for records where one code accounts for more than `threshold`
//!   of the answered single-code items in the group (at least two answered).

use std::collections::BTreeMap;

use fieldseal_kernel::{Decimal, Value};

use super::compiled::CompiledInstrument;
use super::definitions::{CheckKind, CheckScopeDef, Expected};
use super::element::DataType;
use super::evaluation::{Evaluation, RecordInput, Visibility, evaluate_record};
use super::instrument::Instrument;
use super::num::Num;
use super::rules::{EvaluationLimitExceeded, PathRef, Val};

/// One record of the local record (INS-051).
#[derive(Clone, Copy, Debug)]
pub struct RecordView<'a> {
    /// The record's identifier, so the collector can open it (INS-052).
    pub id: &'a str,
    /// The subject it is about.
    pub subject: &'a str,
    /// Its item values (WIRE-051).
    pub values: &'a BTreeMap<String, Value>,
    /// The subject's roster fields.
    pub roster: &'a BTreeMap<String, Value>,
    /// Its elapsed capture time in seconds, from its ticks, if known.
    pub elapsed_seconds: Option<u64>,
}

/// A raised field check (`FieldCheckRaised`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RaisedCheck {
    /// The compiled check id.
    pub check: String,
    /// The records involved, in input order.
    pub records: Vec<String>,
}

fn num(d: Decimal) -> Num {
    Num::from_decimal(d).unwrap_or(Num::ZERO)
}

fn path(p: &PathRef) -> &str {
    match p {
        PathRef::Item(s) | PathRef::Sibling(s) | PathRef::Roster(s) => s,
    }
}

fn overflow(_: super::num::NumError) -> EvaluationLimitExceeded {
    EvaluationLimitExceeded("arithmetic overflow".into())
}

/// Evaluates every field check over `records` (`EvaluateFieldChecks`).
pub fn evaluate_field_checks(instrument: &Instrument, records: &[RecordView<'_>]) -> Result<Vec<RaisedCheck>, EvaluationLimitExceeded> {
    let compiled = instrument.compiled();
    let evaluations: Vec<Evaluation> = records
        .iter()
        .map(|r| evaluate_record(instrument, RecordInput { values: r.values, roster: r.roster }))
        .collect::<Result<_, _>>()?;
    let mut raised = Vec::new();
    for check in compiled.field_checks() {
        let mut raise = |records: Vec<String>| {
            if !records.is_empty() {
                raised.push(RaisedCheck { check: check.id.clone(), records });
            }
        };
        match &check.kind {
            CheckKind::Distribution { path: p, expected, min_count, bound } => {
                let series = numbers(records, &evaluations, path(p));
                if series.is_empty() || series.len() < *min_count as usize {
                    continue;
                }
                let n = Num::int(series.len() as i128);
                let mut sum = Num::ZERO;
                for (_, v) in &series {
                    sum = sum.add(*v).map_err(overflow)?;
                }
                let mean = sum.div(n).map_err(overflow)?;
                let out = match expected {
                    Expected::Range { min, max } => mean < num(*min) || mean > num(*max),
                    Expected::MeanSd { mean: m, sd } => {
                        let d = mean.sub(num(*m)).map_err(overflow)?;
                        let lhs = d.mul(d).and_then(|x| x.mul(n)).map_err(overflow)?;
                        let b = num(*bound);
                        let s = num(*sd);
                        let rhs = b.mul(b).and_then(|x| x.mul(s)).and_then(|x| x.mul(s)).map_err(overflow)?;
                        lhs > rhs
                    }
                };
                if out {
                    raise(series.into_iter().map(|(id, _)| id).collect());
                }
            }
            CheckKind::Drift { path: p, window, threshold } => {
                let series = numbers(records, &evaluations, path(p));
                let w = *window as usize;
                if w < 2 || series.len() < w {
                    continue;
                }
                let tail = &series[series.len() - w..];
                let rising = tail.windows(2).all(|p| p[1].1 >= p[0].1);
                let falling = tail.windows(2).all(|p| p[1].1 <= p[0].1);
                let total = tail[w - 1].1.sub(tail[0].1).and_then(Num::abs).map_err(overflow)?;
                if (rising || falling) && total > num(*threshold) {
                    raise(tail.iter().map(|(id, _)| id.clone()).collect());
                }
            }
            CheckKind::Duplicates { paths, min_match } => {
                let n = records.len();
                let mut parent: Vec<usize> = (0..n).collect();
                fn find(parent: &mut [usize], i: usize) -> usize {
                    let mut r = i;
                    while parent[r] != r {
                        r = parent[r];
                    }
                    parent[i] = r;
                    r
                }
                let mut linked = vec![false; n];
                for i in 0..n {
                    for j in i + 1..n {
                        if records[i].subject == records[j].subject {
                            continue;
                        }
                        let matches = paths
                            .iter()
                            .filter(|p| {
                                let (a, b) = (evaluations[i].values.get(path(p)), evaluations[j].values.get(path(p)));
                                matches!((a, b), (Some(a), Some(b)) if same(a, b))
                            })
                            .count();
                        if matches >= *min_match as usize {
                            let (ri, rj) = (find(&mut parent, i), find(&mut parent, j));
                            parent[ri.max(rj)] = ri.min(rj);
                            linked[i] = true;
                            linked[j] = true;
                        }
                    }
                }
                let mut clusters: BTreeMap<usize, Vec<String>> = BTreeMap::new();
                for i in 0..n {
                    if linked[i] {
                        let root = find(&mut parent, i);
                        clusters.entry(root).or_default().push(records[i].id.to_owned());
                    }
                }
                for (_, ids) in clusters {
                    raise(ids);
                }
            }
            CheckKind::Timing { min_seconds, max_seconds } => {
                let ids = records
                    .iter()
                    .filter(|r| r.elapsed_seconds.is_some_and(|s| min_seconds.is_some_and(|m| s < m) || max_seconds.is_some_and(|m| s > m)))
                    .map(|r| r.id.to_owned())
                    .collect();
                raise(ids);
            }
            CheckKind::Completeness { scope, threshold } => {
                let items = scoped_items(compiled, scope);
                let mut ids = Vec::new();
                for (r, e) in records.iter().zip(&evaluations) {
                    let relevant: Vec<&String> = items
                        .iter()
                        .filter(|p| {
                            e.visibility_of(p) == Some(Visibility::Visible)
                                && compiled.question(p).is_some_and(|q| q.is_editable() && !q.optional)
                        })
                        .collect();
                    if relevant.is_empty() {
                        continue;
                    }
                    let missing = relevant.iter().filter(|p| e.unanswered.contains(p)).count();
                    let share = Num::ratio(missing as i128, relevant.len() as i128).map_err(overflow)?;
                    if share > num(*threshold) {
                        ids.push(r.id.to_owned());
                    }
                }
                raise(ids);
            }
            CheckKind::Straightlining { group, threshold } => {
                let items = scoped_items(compiled, &CheckScopeDef::Group(group.clone()));
                let mut ids = Vec::new();
                for (r, e) in records.iter().zip(&evaluations) {
                    let mut counts: BTreeMap<&str, i128> = BTreeMap::new();
                    let mut total = 0i128;
                    for p in &items {
                        if compiled.question(p).is_some_and(|q| q.data.data_type == DataType::Code)
                            && let Some(Val::Text(code)) = e.values.get(p) {
                                *counts.entry(code.as_str()).or_default() += 1;
                                total += 1;
                            }
                    }
                    let top = counts.values().max().copied().unwrap_or(0);
                    if total >= 2 && Num::ratio(top, total).map_err(overflow)? > num(*threshold) {
                        ids.push(r.id.to_owned());
                    }
                }
                raise(ids);
            }
        }
    }
    Ok(raised)
}

fn same(a: &Val, b: &Val) -> bool {
    match (a, b) {
        (Val::Num(x), Val::Num(y)) => x == y,
        _ => a == b,
    }
}

fn numbers(records: &[RecordView<'_>], evaluations: &[Evaluation], p: &str) -> Vec<(String, Num)> {
    records
        .iter()
        .zip(evaluations)
        .filter_map(|(r, e)| match e.values.get(p) {
            Some(Val::Num(n)) => Some((r.id.to_owned(), *n)),
            _ => None,
        })
        .collect()
}

fn scoped_items(compiled: &CompiledInstrument, scope: &CheckScopeDef) -> Vec<String> {
    match scope {
        CheckScopeDef::Paths(ps) => ps.iter().map(|p| path(p).to_owned()).collect(),
        CheckScopeDef::Group(s) => match compiled.node_index(path(s)) {
            Some(i) => compiled.questions_under(i).into_iter().map(|q| compiled.nodes()[q].path.clone()).collect(),
            None => Vec::new(),
        },
    }
}
