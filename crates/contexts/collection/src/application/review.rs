//! `Review` (COL-060–COL-063, COL-073, INS-050–INS-053): the local record grouped by cohort
//! and subject, each subject's current state and the records behind it with their delivery
//! state, the unanswered count, soft verdicts kept with a reason, and the instrument's field
//! checks evaluated over the local record only.

use std::collections::BTreeMap;

use fieldseal_instrument::application::{evaluate_field_checks, evaluate_rules};
use fieldseal_instrument::domain::evaluation::RecordInput;
use fieldseal_instrument::domain::field_checks::RecordView as CheckInput;
use fieldseal_kernel::Value;
use fieldseal_kernel::id::{CohortId, Fingerprint, Seq, SubjectId};
use fieldseal_kernel::local_record::LocalEntry;

use super::{CollectionError, CollectionEvent, Runtime, names};
use crate::domain::DeliveryState;
use crate::domain::local::{LocalEntryView, LocalNote, StateKey, SubjectState, fold};
use crate::domain::payload::{Payload, StatusCode};

/// What to review (COL §3 `Review`): every filter set must match.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ReviewFilter {
    /// Only this cohort.
    pub cohort: Option<CohortId>,
    /// Only this subject.
    pub subject: Option<SubjectId>,
    /// Only subjects involved in this field check.
    pub check: Option<String>,
}

/// One record in review.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecordView {
    /// Its `seq`.
    pub seq: Seq,
    /// Its payload type.
    pub kind: &'static str,
    /// For `items` records, the mode.
    pub mode: Option<&'static str>,
    /// Its delivery state.
    pub delivery: DeliveryState,
}

/// One subject in review.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SubjectReview {
    /// The subject's cohort, when it is on a held roster.
    pub cohort: Option<CohortId>,
    /// The subject.
    pub subject: SubjectId,
    /// The survey these answers are to: a person surveyed with two instruments has two rows.
    pub instrument: Fingerprint,
    /// Current values: records folded in `seq` order, last write wins (COL-061).
    pub current: BTreeMap<String, Value>,
    /// The records that produced it.
    pub records: Vec<RecordView>,
    /// The unanswered count for the current values (COL-063, COL-109).
    pub unanswered: usize,
    /// Soft verdicts kept with a reason: item path to reason (COL-063).
    pub kept_soft: BTreeMap<String, String>,
    /// The latest status recorded.
    pub status: Option<StatusCode>,
}

/// A raised field check with the records involved (INS-052).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CheckView {
    /// The compiled check id.
    pub check: String,
    /// The subjects involved.
    pub subjects: Vec<SubjectId>,
    /// Their `items` records, so the collector can open each one.
    pub records: Vec<Seq>,
}

/// Cleared records by delivery, as counts only (COL-073).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ClearedCounts {
    /// Cleared and covered by a verified receipt.
    pub delivered: u64,
    /// Cleared, with sealed copies kept until a receipt covers them (COL-106).
    pub awaiting: u64,
}

/// The review (COL §3 `Review`).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ReviewReport {
    /// Subjects, grouped by cohort then subject.
    pub subjects: Vec<SubjectReview>,
    /// Raised field checks (advisory only, INS-053).
    pub checks: Vec<CheckView>,
    /// Records in the local record that are about no subject (`open`, `import`, …).
    pub other_records: Vec<RecordView>,
    /// Cleared records (COL-073).
    pub cleared: ClearedCounts,
}

impl Runtime<'_> {
    /// Decrypts every local record entry (session class).
    pub(crate) fn local_entries(&self) -> Result<Vec<LocalEntryView>, CollectionError> {
        let session = self.session.as_ref().ok_or(CollectionError::Locked)?;
        let tenancy = self.meta()?.tenancy;
        let mut out = Vec::new();
        for name in self.p.storage.names(names::SESSION)? {
            let Some(seq) = names::seq_of(&name, "local/") else { continue };
            let Some(bytes) = self.p.storage.read(names::SESSION, &name)? else { continue };
            let entry = LocalEntry::decode(&bytes)?;
            if entry.seq != seq {
                return Err(CollectionError::Failed(format!("local entry {seq} names seq {}", entry.seq)));
            }
            let payload = Payload::decode(&entry.open(&session.key, &tenancy)?)?;
            let note = match self.p.storage.read(names::SESSION, &names::note(seq))? {
                Some(b) => LocalNote::decode(&LocalEntry::decode(&b)?.open(&session.key, &tenancy)?)?,
                None => LocalNote { record_id: fieldseal_kernel::id::RecordId::from([0; 16]), capture_ms: None },
            };
            out.push(LocalEntryView { seq: Seq(seq), payload, note });
        }
        out.sort_by_key(|e| e.seq);
        Ok(out)
    }

    pub(crate) fn local_state(&self) -> Result<BTreeMap<StateKey, SubjectState>, CollectionError> {
        Ok(fold(&self.local_entries()?))
    }

    /// A record's delivery state (DEL; moves only forward).
    pub fn delivery_state(&self, seq: Seq) -> DeliveryState {
        let Some(m) = self.meta.as_ref() else { return DeliveryState::None };
        if m.received.is_some_and(|(r, _)| seq.0 <= r) {
            DeliveryState::Received
        } else if m.saved.is_some_and(|s| seq.0 <= s) {
            DeliveryState::SavedAndChecked
        } else if m.handed_over.is_some_and(|s| seq.0 <= s) {
            DeliveryState::HandedOver
        } else {
            DeliveryState::None
        }
    }

    /// `Review` (COL-060–COL-063, COL-073).
    pub fn review(&mut self, filter: &ReviewFilter) -> Result<ReviewReport, CollectionError> {
        self.active()?;
        let entries = self.local_entries()?;
        let state = fold(&entries);
        let held = self.held().ok_or(CollectionError::NoBundle)?;
        let mut subjects = Vec::new();
        for ((bytes, fingerprint), s) in &state {
            let Ok(subject) = String::from_utf8(bytes.clone()).map_err(|_| ()).and_then(|t| SubjectId::new(t).map_err(|_| ())) else {
                continue;
            };
            let on_roster = held.subject(&subject);
            let roster = on_roster.map(|(_, e)| e.fields()).unwrap_or_default();
            // A record of a survey the held bundle no longer carries is still shown, unjudged.
            let unanswered = match held.instrument(fingerprint) {
                Some(h) if !s.items.is_empty() => {
                    evaluate_rules(&h.instrument, RecordInput { values: &s.current, roster: &roster })
                        .map_err(|e| CollectionError::Failed(format!("evaluation limit: {}", e.0)))?
                        .unanswered
                        .len()
                }
                _ => 0,
            };
            let records = s
                .records
                .iter()
                .map(|seq| {
                    let e = entries.iter().find(|e| e.seq == *seq).expect("folded from these entries");
                    RecordView { seq: *seq, kind: e.payload.kind(), mode: mode_of(&e.payload), delivery: self.delivery_state(*seq) }
                })
                .collect();
            subjects.push(SubjectReview {
                cohort: on_roster.map(|(r, _)| r.cohort.clone()),
                subject,
                instrument: *fingerprint,
                current: s.current.clone(),
                records,
                unanswered,
                kept_soft: s.overrides.clone(),
                status: s.status,
            });
        }
        subjects.sort_by(|a, b| (a.cohort.as_ref().map(CohortId::as_str), a.subject.as_str(), a.instrument).cmp(&(b.cohort.as_ref().map(CohortId::as_str), b.subject.as_str(), b.instrument)));

        // Field checks over the local record only (INS-051), one instrument at a time: one view
        // per subject's current state, identified by the subject so every record behind it can
        // be opened.
        let mut checks = Vec::new();
        for survey in &held.instruments {
            let key = |s: &SubjectReview| (s.subject.as_str().as_bytes().to_vec(), s.instrument);
            let about: Vec<&SubjectReview> = subjects.iter().filter(|s| s.instrument == survey.fingerprint && !state[&key(s)].items.is_empty()).collect();
            let rosters: Vec<BTreeMap<String, Value>> = about.iter().map(|s| held.subject(&s.subject).map(|(_, e)| e.fields()).unwrap_or_default()).collect();
            let views: Vec<CheckInput<'_>> = about
                .iter()
                .zip(&rosters)
                .map(|(s, roster)| {
                    let st = &state[&key(s)];
                    CheckInput { id: s.subject.as_str(), subject: s.subject.as_str(), values: &st.current, roster, elapsed_seconds: (st.capture_ms > 0).then_some(st.capture_ms / 1000) }
                })
                .collect();
            let raised = evaluate_field_checks(&survey.instrument, &views).map_err(|e| CollectionError::Failed(format!("evaluation limit: {}", e.0)))?;
            for r in raised {
                let involved: Vec<SubjectId> = r.records.iter().filter_map(|id| SubjectId::new(id.clone()).ok()).collect();
                let records = involved.iter().flat_map(|s| state[&(s.as_str().as_bytes().to_vec(), survey.fingerprint)].items.clone()).collect();
                checks.push(CheckView { check: r.check, subjects: involved, records });
            }
        }

        let other_records = entries
            .iter()
            .filter(|e| e.payload.subject().is_none())
            .map(|e| RecordView { seq: e.seq, kind: e.payload.kind(), mode: None, delivery: self.delivery_state(e.seq) })
            .collect();
        let cleared = self.cleared_counts();

        let checks_for_filter = checks.clone();
        subjects.retain(|s| {
            filter.cohort.as_ref().is_none_or(|c| s.cohort.as_ref() == Some(c))
                && filter.subject.as_ref().is_none_or(|x| &s.subject == x)
                && filter.check.as_ref().is_none_or(|c| checks_for_filter.iter().any(|k| &k.check == c && k.subjects.contains(&s.subject)))
        });
        if let Some(c) = &filter.check {
            checks.retain(|k| &k.check == c);
        }
        for c in &checks {
            self.events.push(CollectionEvent::FieldCheckRaised(c.check.clone()));
        }
        Ok(ReviewReport { subjects, checks, other_records, cleared })
    }

    pub(crate) fn cleared_counts(&self) -> ClearedCounts {
        let Some(m) = self.meta.as_ref() else { return ClearedCounts::default() };
        let Some(through) = m.cleared_through() else { return ClearedCounts::default() };
        let total = through + 1;
        let delivered = m.received.map_or(0, |(r, _)| r.min(through) + 1);
        ClearedCounts { delivered, awaiting: total - delivered }
    }
}

fn mode_of(p: &Payload) -> Option<&'static str> {
    match p {
        Payload::Items(i) => Some(match i.mode {
            fieldseal_kernel::payload::Mode::First => "first",
            fieldseal_kernel::payload::Mode::Resume => "resume",
            fieldseal_kernel::payload::Mode::Resurvey => "resurvey",
            fieldseal_kernel::payload::Mode::Correction => "correction",
        }),
        _ => None,
    }
}
