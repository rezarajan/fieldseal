//! Stage 10: replay of the instruments' rules (INT-012, INT-056, INT-057, INS-042).
//!
//! Each `items` record is replayed alone, as the device sealed it, and quarantined if its
//! verdicts differ from what the runtime recorded. Rules that span records then run on each
//! subject's merged state, and field checks over the submission's records (INS-042, INS-050);
//! their results are findings, or a quarantine where intake policy says so.

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_instrument::application::{evaluate_field_checks, evaluate_rules};
use fieldseal_instrument::domain::{Instrument, RecordInput, RecordView, Verdict};
use fieldseal_kernel::Value;
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::id::{Fingerprint, RecordId, SubjectId};
use fieldseal_kernel::payload::ItemsPayload;
use fieldseal_policy::domain::{DecisionPoint, Obligation};

use super::{Instruments, IntakeService, Part, Step, backend};
use crate::domain::{Finding, FindingKind, Submission};
use crate::landing::RunningState;
use crate::wire::Payload;

type Sample = (String, SubjectId, BTreeMap<String, Value>);

/// What stage 10 found.
#[derive(Clone, Debug, Default)]
pub(crate) struct ReplayResult {
    /// Records held for a custodian, with the reasons (INT-012).
    pub held: BTreeMap<RecordId, Vec<String>>,
    /// The number of data-quality failures (hard verdicts on merged state).
    pub quality_failures: usize,
}

/// The pseudonymous subject ID of an `items`, `status` or `consent` payload's subject bytes.
pub(crate) fn subject_id(bytes: &[u8]) -> Option<SubjectId> {
    SubjectId::new(lower_hex(bytes)).ok()
}

pub(crate) fn plain_values(p: &ItemsPayload) -> BTreeMap<String, Value> {
    p.values.iter().map(|(k, v)| (k.as_str().to_owned(), v.clone())).collect()
}

impl IntakeService<'_> {
    /// Replays one record alone, as the device saw it. Returns the reasons its verdicts differ
    /// from what the runtime recorded (empty when they match).
    fn replay_record(&self, instrument: &Instrument, p: &ItemsPayload) -> Vec<String> {
        let values = plain_values(p);
        let roster = BTreeMap::new();
        let eval = match evaluate_rules(instrument, RecordInput { values: &values, roster: &roster }) {
            Ok(e) => e,
            Err(l) => return vec![format!("rule evaluation exceeded its limits: {}", l.0)],
        };
        let mut reasons = Vec::new();
        for pr in &eval.problems {
            // The rule and the item only: the instrument's message may quote the offending value,
            // and a finding is kept and shown to operators, so personal data must not ride in it.
            reasons.push(format!("{} {}: the value is not valid for the item", pr.requirement, pr.path));
        }
        for id in eval.with_verdict(Verdict::Hard) {
            reasons.push(format!("hard rule `{id}` fires but the record was sealed"));
        }
        if !eval.cleared.is_empty() {
            reasons.push(format!("{} hidden item(s) present (INS-124)", eval.cleared.len()));
        }
        let flags: BTreeSet<&str> = p.flags.iter().flatten().map(String::as_str).collect();
        for id in eval.with_verdict(Verdict::Soft) {
            if !flags.contains(id) {
                reasons.push(format!("soft rule `{id}` fires but the record does not flag it"));
            }
        }
        for f in &flags {
            if instrument.compiled().rule(f).is_none() {
                reasons.push(format!("the record flags `{f}`, which is no rule of the instrument"));
            }
        }
        reasons
    }

    pub(super) fn stage_replay(&self, parts: &[Part], instruments: &Instruments, sub: &mut Submission) -> Step<ReplayResult> {
        let mut result = ReplayResult::default();
        // Per-record replay (INT-012).
        for part in parts {
            for (e, p) in part.entries.iter().zip(&part.payloads) {
                let id = e.record.header.record_id;
                let (fp, items) = match p {
                    Payload::Items(i) => (i.instrument, Some(i)),
                    Payload::Status { instrument, .. } | Payload::Consent { instrument, .. } => {
                        (Fingerprint::from(*instrument.as_bytes()), None)
                    }
                    _ => continue,
                };
                match instruments.by_fingerprint.get(&fp) {
                    Some(Some(inst)) => {
                        if let Some(items) = items {
                            let reasons = self.replay_record(inst, items);
                            if !reasons.is_empty() {
                                result.held.insert(id, reasons);
                            }
                        }
                    }
                    _ => {
                        result.held.insert(id, vec!["the record's instrument is not published (INT-070)".to_owned()]);
                    }
                }
            }
        }
        for (id, reasons) in &result.held {
            sub.record(Finding::new(FindingKind::Quarantine, "INT-012", format!("record {} held: {}", lower_hex(id.as_bytes()), reasons.join("; "))));
        }

        // Rules that span records, on each subject's merged state (INS-042).
        type Key = (Fingerprint, SubjectId);
        let mut groups: BTreeMap<Key, Vec<(&Part, usize)>> = BTreeMap::new();
        for part in parts {
            for (n, (e, p)) in part.entries.iter().zip(&part.payloads).enumerate() {
                if let Payload::Items(i) = p
                    && !result.held.contains_key(&e.record.header.record_id)
                    && let Some(s) = subject_id(&i.subject)
                {
                    groups.entry((i.instrument, s)).or_default().push((part, n));
                }
            }
        }
        let mut failing: BTreeSet<Key> = BTreeSet::new();
        let mut by_instrument: BTreeMap<Fingerprint, Vec<Sample>> = BTreeMap::new();
        for ((fp, subject), members) in &groups {
            let Some(Some(inst)) = instruments.by_fingerprint.get(fp) else { continue };
            let landed = self.platform.observations(fp).map_err(backend)?;
            let rows: Vec<_> = landed.into_iter().filter(|r| &r.observation.subject == subject).collect();
            let mut state = RunningState::from_landed(&rows);
            for (part, n) in members {
                if let Payload::Items(i) = &part.payloads[*n] {
                    state.apply(i);
                    by_instrument.entry(*fp).or_default().push((lower_hex(part.entries[*n].record.header.record_id.as_bytes()), subject.clone(), plain_values(i)));
                }
            }
            let roster = BTreeMap::new();
            match evaluate_rules(inst, RecordInput { values: &state.values, roster: &roster }) {
                Ok(eval) => {
                    for id in eval.with_verdict(Verdict::Hard) {
                        result.quality_failures += 1;
                        failing.insert((*fp, subject.clone()));
                        sub.record(Finding::new(FindingKind::Flag, "INT-057", format!("rule `{id}` fails on a subject's merged state (INS-042)")));
                    }
                    for id in eval.with_verdict(Verdict::Soft) {
                        sub.record(Finding::new(FindingKind::Flag, "INT-057", format!("rule `{id}` fires on a subject's merged state (INS-042)")));
                    }
                }
                Err(l) => sub.record(Finding::new(FindingKind::Flag, "INT-057", format!("merged-state evaluation exceeded its limits: {}", l.0))),
            }
        }
        // Field checks over the submission's records, one instrument at a time (INS-050).
        let empty = BTreeMap::new();
        for (fp, rows) in &by_instrument {
            let Some(Some(inst)) = instruments.by_fingerprint.get(fp) else { continue };
            let views: Vec<RecordView<'_>> = rows
                .iter()
                .map(|(id, subject, values)| RecordView { id, subject: subject.as_str(), values, roster: &empty, elapsed_seconds: None })
                .collect();
            if let Ok(raised) = evaluate_field_checks(inst, &views) {
                for r in raised {
                    sub.record(Finding::new(FindingKind::Flag, "INT-057", format!("field check `{}` raised for {} record(s)", r.check, r.records.len())));
                }
            }
        }

        if result.quality_failures > 0 {
            let facts = BTreeMap::from([
                ("sizeBytes".to_owned(), Value::Int(0)),
                ("qualityFailures".to_owned(), Value::Int(result.quality_failures as i128)),
            ]);
            match self.policy.evaluate(DecisionPoint::IntakeAccept, self.effective, &facts) {
                Ok(d) if d.obligations.contains(&Obligation::Quarantine) => {
                    for (fp, subject) in &failing {
                        for (part, n) in groups.get(&(*fp, subject.clone())).into_iter().flatten() {
                            let id = part.entries[*n].record.header.record_id;
                            result.held.entry(id).or_default().push("data-quality failure; intake policy says quarantine (INT-057)".to_owned());
                            sub.record(Finding::new(FindingKind::Quarantine, "INT-057", format!("record {} held for a data-quality failure", lower_hex(id.as_bytes()))));
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => sub.record(Finding::new(FindingKind::Flag, "POL-034", format!("intake.accept failed: {e}"))),
            }
        }
        Ok(result)
    }
}
