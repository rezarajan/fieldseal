//! Landing: from verified `items` records to rows of the generic long format, and from rows
//! to subject state (INT-050–055, INT-070, INT-071, INS-142, INS-161).
//!
//! Everything here is generic: it reads the instrument's compiled form and never names an
//! item (INT-058). Entry units are converted with the instrument's exact factors (INS-161)
//! by evaluating the merged record, and `not-applicable` is derived for every item a `when`
//! or `skip` hides (INS-142).

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_instrument::application::evaluate_rules;
use fieldseal_instrument::domain::element::DataType;
use fieldseal_instrument::domain::rules::Val;
use fieldseal_instrument::domain::{EvaluationLimitExceeded, Instrument, RecordInput};
use fieldseal_kernel::id::{Fingerprint, Generation, ItemPath, RecordId, Seq, SubjectId, TenancyId};
use fieldseal_kernel::payload::{ItemsPayload, Layout};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Decimal, Value, cbor};

use crate::data_contract::decimal_text;
use crate::domain::{LandedObservation, Nonresponse, Observation, ObservedValue, Reading};

/// What the landing of one record needs to know beyond its payload.
#[derive(Clone, Debug)]
pub struct RecordContext {
    /// The record.
    pub record: RecordId,
    /// Its tenancy.
    pub tenancy: TenancyId,
    /// The tenancy's generation for the subject's cohort.
    pub generation: Generation,
    /// Its `seq`.
    pub seq: Seq,
    /// The tick lower bound, if the anchors allow one.
    pub not_before: Option<AuthorityTime>,
    /// When the authority received it.
    pub received: AuthorityTime,
    /// The consent basis, as text.
    pub consent_basis: String,
    /// The record's flags.
    pub flags: BTreeSet<String>,
}

/// A subject's running state while records are applied in order: the raw values the
/// instrument sees (with entry-unit keys) and the items currently `not-applicable`.
#[derive(Clone, Default, Debug)]
pub struct RunningState {
    /// Item path to recorded value, including `<path>.unit` keys.
    pub values: BTreeMap<String, Value>,
    /// Items currently derived `not-applicable`.
    pub not_applicable: BTreeSet<String>,
}

fn nr_value(code: &str) -> Value {
    cbor::map([("nr", Value::Text(code.to_owned()))])
}

fn observed_to_value(v: &ObservedValue) -> Value {
    match v {
        ObservedValue::Bool(b) => Value::Bool(*b),
        ObservedValue::Int(i) => Value::Int(i128::from(*i)),
        ObservedValue::Decimal(t) => Decimal::parse(t).map_or_else(|_| Value::Text(t.clone()), Value::Decimal),
        ObservedValue::Text(t) | ObservedValue::Code(t) => Value::Text(t.clone()),
        ObservedValue::Codes(c) => Value::Array(c.iter().cloned().map(Value::Text).collect()),
    }
}

impl RunningState {
    /// Rebuilds the state from landed rows (excluded rows omitted, INT-055): the last write
    /// wins in `(generation, seq)` order (INT-053). Values come back as the unit they were
    /// landed in, so no `.unit` keys are kept.
    pub fn from_landed(rows: &[LandedObservation]) -> Self {
        let mut latest: BTreeMap<&ItemPath, &Observation> = BTreeMap::new();
        for row in rows.iter().filter(|r| r.excluded.is_none()) {
            let o = &row.observation;
            let newer = latest.get(&o.item).is_none_or(|p| (p.generation, p.seq) <= (o.generation, o.seq));
            if newer {
                latest.insert(&o.item, o);
            }
        }
        let mut state = Self::default();
        for (item, o) in latest {
            match &o.reading {
                Reading::Value(v) => {
                    state.values.insert(item.as_str().to_owned(), observed_to_value(v));
                }
                Reading::Nonresponse(Nonresponse::NotApplicable) => {
                    state.not_applicable.insert(item.as_str().to_owned());
                }
                Reading::Nonresponse(n) => {
                    state.values.insert(item.as_str().to_owned(), nr_value(n.code()));
                }
                Reading::Retracted => {}
            }
        }
        state
    }

    /// Applies one record's values: a retraction removes the item, an entry unit travels with
    /// its value and a value set without one replaces any earlier entry unit.
    pub fn apply(&mut self, payload: &ItemsPayload) {
        for (path, value) in &payload.values {
            let p = path.as_str();
            if p.ends_with(".unit") {
                continue;
            }
            self.values.remove(&format!("{p}.unit"));
            if is_retraction(value) {
                self.values.remove(p);
            } else {
                self.values.insert(p.to_owned(), value.clone());
            }
        }
        for (path, value) in &payload.values {
            let p = path.as_str();
            if p.ends_with(".unit") && self.values.contains_key(p.trim_end_matches(".unit")) {
                self.values.insert(p.to_owned(), value.clone());
            }
        }
    }
}

/// Whether a value is `{"retracted": true}` (WIRE-052).
pub fn is_retraction(v: &Value) -> bool {
    matches!(v, Value::Map(m) if m.len() == 1 && m.get("retracted") == Some(&Value::Bool(true)))
}

fn nr_of(v: &Value) -> Option<Nonresponse> {
    match v {
        Value::Map(m) if m.len() == 1 => match m.get("nr").and_then(Value::as_text) {
            Some("dont-know") => Some(Nonresponse::DontKnow),
            Some("refused") => Some(Nonresponse::Refused),
            _ => None,
        },
        _ => None,
    }
}

fn num_text(n: fieldseal_instrument::domain::Num, scale: Option<u32>) -> String {
    let exact = match scale {
        // Money keeps its currency's minor-unit digits (INS-162): `12.50`, not `12.5`.
        Some(digits) => n.round(digits).ok(),
        None => n.to_decimal().or_else(|| n.round(9).ok()),
    };
    exact.map_or_else(|| n.to_string(), decimal_text)
}

fn observed(data_type: DataType, v: &Val, scale: Option<u32>) -> Option<ObservedValue> {
    Some(match (data_type, v) {
        (DataType::Code, Val::Text(t)) => ObservedValue::Code(t.clone()),
        (DataType::Codes, Val::List(items)) => {
            ObservedValue::Codes(items.iter().filter_map(|i| if let Val::Text(t) = i { Some(t.clone()) } else { None }).collect())
        }
        (DataType::Integer, Val::Num(n)) => ObservedValue::Int(i64::try_from(n.numerator() / n.denominator()).ok()?),
        (DataType::Decimal | DataType::Money, Val::Num(n)) => ObservedValue::Decimal(num_text(*n, if data_type == DataType::Money { scale } else { None })),
        (DataType::Boolean, Val::Bool(b)) => ObservedValue::Bool(*b),
        (DataType::String | DataType::Date | DataType::Evidence, Val::Text(t)) => ObservedValue::Text(t.clone()),
        _ => return None,
    })
}

/// The subject, layout and languages of the record being landed.
#[derive(Clone, Debug)]
pub struct RecordFrame<'a> {
    /// The instrument's fingerprint.
    pub instrument: Fingerprint,
    /// The subject.
    pub subject: &'a SubjectId,
    /// The layout the record was collected with.
    pub layout: Layout,
    /// The languages administered.
    pub lang: &'a [String],
}

/// Lands one `items` record: applies it to `state`, evaluates the merged state with the
/// instrument, and returns the rows (INT-050, INT-051, INT-052):
///
/// - a row for each item the record set, with its value converted exactly to the item's
///   unit (INS-161), its nonresponse, or its retraction;
/// - a `not-applicable` row for each item a `when` or `skip` newly hides (INS-142).
///
/// Absent items produce no rows (INT-052). An item the record set but the merged state hides
/// lands as `not-applicable`; an item whose value the evaluator can't read lands no row (the
/// replay stage quarantines such records before they get here).
pub fn land_record(
    instrument: &Instrument,
    frame: &RecordFrame<'_>,
    ctx: &RecordContext,
    payload: &ItemsPayload,
    state: &mut RunningState,
) -> Result<Vec<Observation>, EvaluationLimitExceeded> {
    state.apply(payload);
    let roster = BTreeMap::new();
    let eval = evaluate_rules(instrument, RecordInput { values: &state.values, roster: &roster })?;
    let compiled = instrument.compiled();
    let row = |item: &str, reading: Reading, value_type: &'static str, unit: Option<String>| -> Option<Observation> {
        Some(Observation {
            instrument: frame.instrument,
            layout: frame.layout,
            lang: frame.lang.to_vec(),
            subject: frame.subject.clone(),
            item: ItemPath::new(item).ok()?,
            reading,
            value_type,
            unit,
            source: ctx.record,
            tenancy: ctx.tenancy,
            generation: ctx.generation,
            seq: ctx.seq,
            not_before: ctx.not_before,
            not_after: ctx.received,
            consent_basis: ctx.consent_basis.clone(),
            flags: ctx.flags.clone(),
        })
    };
    let spec = |path: &str| -> Option<(DataType, Option<String>, Option<u32>)> {
        let data = compiled.question(path).map(|q| &q.data).or_else(|| compiled.derived_value(path).map(|d| &d.data))?;
        let money = compiled.question(path).and_then(|q| match q.control.as_ref() {
            Some(fieldseal_instrument::domain::control::Control::Money(m)) => Some((m.currency.code().to_owned(), m.currency.minor_digits())),
            _ => None,
        });
        let unit = money.as_ref().map(|(c, _)| c.clone()).or_else(|| data.unit.as_ref().map(|u| u.as_str().to_owned()));
        Some((data.data_type, unit, money.map(|(_, d)| d)))
    };

    let mut rows = Vec::new();
    for (path, value) in &payload.values {
        let p = path.as_str();
        if p.ends_with(".unit") && compiled.question(p).is_none() {
            continue;
        }
        let Some((data_type, unit, scale)) = spec(p) else { continue };
        let vt = data_type.name();
        if is_retraction(value) {
            rows.extend(row(p, Reading::Retracted, vt, unit));
        } else if let Some(nr) = nr_of(value) {
            rows.extend(row(p, Reading::Nonresponse(nr), vt, unit));
        } else if eval.visibility_of(p).is_some_and(|v| v.is_hidden()) {
            // The merged state hides it: it is not applicable, not a value.
        } else if let Some(v) = eval.values.get(p).and_then(|v| observed(data_type, v, scale)) {
            rows.extend(row(p, Reading::Value(v), vt, unit));
        }
    }

    let mut hidden = BTreeSet::new();
    for (path, q) in compiled.questions() {
        if q.is_editable() && eval.visibility_of(path).is_some_and(|v| v.is_hidden()) {
            hidden.insert(path.to_owned());
        }
    }
    for path in &hidden {
        state.values.remove(path);
        state.values.remove(&format!("{path}.unit"));
        if !state.not_applicable.contains(path)
            && let Some((data_type, unit, _)) = spec(path)
        {
            rows.extend(row(path, Reading::Nonresponse(Nonresponse::NotApplicable), data_type.name(), unit));
        }
    }
    state.not_applicable = hidden;
    Ok(rows)
}

/// One candidate value for an item in subject state.
#[derive(Clone, PartialEq, Debug)]
pub struct Candidate {
    /// What the item holds.
    pub reading: Reading,
    /// The record it came from (each value keeps its source record, INT-053).
    pub source: RecordId,
    /// The tenancy it came from.
    pub tenancy: TenancyId,
    /// Its generation.
    pub generation: Generation,
    /// Its `seq`.
    pub seq: Seq,
}

/// An item's state.
#[derive(Clone, PartialEq, Debug)]
pub enum ItemState {
    /// One current value.
    Current(Candidate),
    /// Tenancies with no succession between them disagree; a custodian adjudicates
    /// (INT-054). Candidates are listed by tenancy.
    Conflict(Vec<Candidate>),
}

/// The merged current value per item for one subject and instrument.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct SubjectState {
    /// The items that have a state.
    pub items: BTreeMap<ItemPath, ItemState>,
}

impl SubjectState {
    /// The items in conflict.
    pub fn conflicts(&self) -> Vec<&ItemPath> {
        self.items.iter().filter(|(_, s)| matches!(s, ItemState::Conflict(_))).map(|(k, _)| k).collect()
    }
}

/// Folds landed rows into subject state (INT-053–055).
///
/// Rows of related tenancies (`lineage` maps a tenancy to the root of its succession chain)
/// are applied in ascending `(generation, seq)`, last write wins, each value keeping its
/// source record. Rows of tenancies with no succession between them are never ordered
/// against each other: if their latest values differ, the item is a [`ItemState::Conflict`]
/// (INT-054). Excluded rows are omitted (INT-055); a retraction removes the item's value.
pub fn fold_subject_state(rows: &[LandedObservation], lineage: &dyn Fn(&TenancyId) -> TenancyId) -> SubjectState {
    let mut by_item: BTreeMap<&ItemPath, BTreeMap<TenancyId, &Observation>> = BTreeMap::new();
    for row in rows.iter().filter(|r| r.excluded.is_none()) {
        let o = &row.observation;
        let slot = by_item.entry(&o.item).or_default().entry(lineage(&o.tenancy));
        slot.and_modify(|cur| {
            if (cur.generation, cur.seq, cur.tenancy) <= (o.generation, o.seq, o.tenancy) {
                *cur = o;
            }
        })
        .or_insert(o);
    }
    let mut out = SubjectState::default();
    for (item, per_lineage) in by_item {
        let candidates: Vec<Candidate> = per_lineage
            .values()
            .filter(|o| o.reading != Reading::Retracted)
            .map(|o| Candidate { reading: o.reading.clone(), source: o.source, tenancy: o.tenancy, generation: o.generation, seq: o.seq })
            .collect();
        match candidates.as_slice() {
            [] => {}
            [one] => {
                out.items.insert(item.clone(), ItemState::Current(one.clone()));
            }
            many if many.iter().all(|c| c.reading == many[0].reading) => {
                let best = many.iter().max_by_key(|c| (c.generation, c.seq, c.tenancy)).cloned().unwrap_or_else(|| many[0].clone());
                out.items.insert(item.clone(), ItemState::Current(best));
            }
            many => {
                out.items.insert(item.clone(), ItemState::Conflict(many.to_vec()));
            }
        }
    }
    out
}
