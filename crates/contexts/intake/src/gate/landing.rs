//! Stages 12–13: duplicate detection, landing and receipts (INT-013, INT-014, INT-020,
//! INT-050–055).

use std::collections::BTreeMap;

use fieldseal_kernel::crypto::{Purpose, tags};
use fieldseal_kernel::digest::{lower_hex, sha256};
use fieldseal_kernel::id::{Digest, Generation, RecordId, Seq};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_trust::domain::KeyRole;
use fieldseal_trust::ports::CustodyError;

use super::consent::ConsentResult;
use super::replay::{ReplayResult, subject_id};
use super::{Fail, IngestReport, Instruments, IntakeService, IssuedReceipt, LandingSummary, Part, RecordOutcome, Step, backend};
use crate::domain::{
    Code, Finding, FindingKind, GateState, LandedEnvelope, Rejection, Stage, Submission,
};
use crate::landing::{RecordContext, RecordFrame, RunningState, land_record};
use crate::ports::LandingBatch;
use crate::wire::{Payload, Receipt};

impl IntakeService<'_> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn stage_landing(
        &self,
        parts: &[Part],
        instruments: &Instruments,
        replay: ReplayResult,
        consent: ConsentResult,
        of: Digest,
        now: AuthorityTime,
        land: bool,
        sub: &mut Submission,
    ) -> Step<IngestReport> {
        let mut held = replay.held;
        for (k, v) in consent.held {
            held.entry(k).or_default().extend(v);
        }
        let mut summary = LandingSummary::default();
        let mut records = Vec::new();
        let mut batch = LandingBatch { submission: Some(*sub.id()), ..LandingBatch::default() };

        // Stage 12: duplicates (INT-013).
        struct Plan<'p> {
            part: &'p Part,
            n: usize,
            outcome: RecordOutcome,
        }
        let mut plans: Vec<Plan<'_>> = Vec::new();
        let mut known_after: Vec<BTreeMap<u64, Digest>> = Vec::new();
        for part in parts {
            let existing = self.platform.envelopes(&part.view.tenancy).map_err(backend)?;
            let by_id: BTreeMap<RecordId, &LandedEnvelope> = existing.iter().map(|e| (e.record, e)).collect();
            let by_seq: BTreeMap<u64, &LandedEnvelope> = existing.iter().map(|e| (e.seq.0, e)).collect();
            let mut all: BTreeMap<u64, Digest> = existing.iter().map(|e| (e.seq.0, e.hash)).collect();
            for (n, (e, p)) in part.entries.iter().zip(&part.payloads).enumerate() {
                let id = e.record.header.record_id;
                let seq = e.record.header.seq;
                let outcome = match (by_id.get(&id), by_seq.get(&seq)) {
                    (Some(env), _) if env.hash == e.hash => RecordOutcome::Duplicate,
                    (Some(_), _) => {
                        sub.record(Finding::new(FindingKind::Flag, "INT-013", format!("record {} was landed with different content; not landed again", lower_hex(id.as_bytes()))));
                        RecordOutcome::Conflict
                    }
                    (None, Some(env)) if env.hash != e.hash => {
                        sub.record(Finding::new(FindingKind::Flag, "INT-013", format!("seq {seq} is already landed as another record; the tenancy is flagged")));
                        RecordOutcome::Conflict
                    }
                    (None, _) if held.contains_key(&id) => RecordOutcome::Held,
                    (None, _) => RecordOutcome::Landed,
                };
                if matches!(outcome, RecordOutcome::Landed | RecordOutcome::Held) {
                    all.insert(seq, e.hash);
                    batch.envelopes.push(LandedEnvelope {
                        record: id,
                        tenancy: part.view.tenancy,
                        seq: Seq(seq),
                        hash: e.hash,
                        body: e.record.encode().map_err(|w| Fail::Reject(Rejection::new(Stage::Duplicates, Code::Wire(w.code), w.detail)))?,
                        evidence: match p {
                            Payload::Evidence { blob_id, bytes, .. } => Some((*blob_id, sha256(bytes))),
                            _ => None,
                        },
                    });
                }
                match outcome {
                    RecordOutcome::Landed => summary.landed += 1,
                    RecordOutcome::Duplicate => summary.duplicates += 1,
                    RecordOutcome::Held => summary.held += 1,
                    RecordOutcome::Conflict => summary.conflicts += 1,
                }
                if outcome != RecordOutcome::Duplicate && part.flags.contains_key(&seq) {
                    summary.flagged += 1;
                }
                records.push((id, outcome));
                plans.push(Plan { part, n, outcome });
            }
            known_after.push(all);
        }

        // Observations: each landed `items` record, subject by subject, in chain order
        // (INT-050–052, INS-142, INS-161).
        let mut states: BTreeMap<(fieldseal_kernel::id::Fingerprint, fieldseal_kernel::id::SubjectId), RunningState> = BTreeMap::new();
        for plan in &plans {
            if plan.outcome != RecordOutcome::Landed {
                continue;
            }
            let e = &plan.part.entries[plan.n];
            let Payload::Items(items) = &plan.part.payloads[plan.n] else { continue };
            let Some(Some(inst)) = instruments.by_fingerprint.get(&items.instrument) else { continue };
            let Some(subject) = subject_id(&items.subject) else { continue };
            let rid = e.record.header.record_id;
            let key = (items.instrument, subject.clone());
            if !states.contains_key(&key) {
                let rows = self.platform.observations(&items.instrument).map_err(backend)?;
                let rows: Vec<_> = rows.into_iter().filter(|r| r.observation.subject == subject).collect();
                states.insert(key.clone(), RunningState::from_landed(&rows));
            }
            let state = states.get_mut(&key).expect("inserted above");
            let seq = e.record.header.seq;
            let ctx = RecordContext {
                record: rid,
                tenancy: plan.part.view.tenancy,
                generation: Generation(consent.generation.get(&rid).copied().unwrap_or(0)),
                seq: Seq(seq),
                not_before: plan.part.bounds[plan.n],
                received: now,
                consent_basis: consent.basis.get(&rid).cloned().unwrap_or_else(|| "unknown".to_owned()),
                flags: plan.part.flags.get(&seq).cloned().unwrap_or_default(),
            };
            let frame = RecordFrame { instrument: items.instrument, subject: &subject, layout: items.layout, lang: &items.lang };
            match land_record(inst, &frame, &ctx, items, state) {
                Ok(rows) => {
                    summary.observations += rows.len();
                    batch.observations.extend(rows);
                }
                Err(l) => sub.record(Finding::new(FindingKind::Flag, "INT-012", format!("record {} landed no observations: {}", lower_hex(rid.as_bytes()), l.0))),
            }
        }
        batch.exclusions = consent
            .exclusions
            .iter()
            .filter(|(id, _)| records.iter().any(|(r, o)| r == *id && *o == RecordOutcome::Landed))
            .map(|(k, v)| (*k, v.clone()))
            .collect();

        for p in parts {
            for l in &p.losses {
                sub.record(Finding::new(
                    FindingKind::Loss,
                    "INT-020",
                    format!("seq {}..={} lost: {}", l.from.0, l.through.0, l.reason),
                ));
                batch.losses.push(l.clone());
            }
        }
        batch.consent = consent.cases.clone();

        // Stage 13: a receipt for each tenancy, covering the highest contiguous `seq` held
        // (INT-014, DEL-008). Signed before anything is written, so a failure lands nothing.
        let mut receipts = Vec::new();
        for (part, all) in parts.iter().zip(&known_after) {
            let Some((&first, _)) = all.iter().next() else { continue };
            let start = if all.contains_key(&0) { 0 } else { first };
            let mut last = start;
            while all.contains_key(&(last + 1)) {
                last += 1;
            }
            let hash_at = all[&last];
            let structure = Receipt::unsigned_structure(&part.view.tenancy, last, &hash_at, now, &of, &self.receipt_key);
            let sig = self
                .custody
                .sign(&self.receipt_key, KeyRole::Purpose(Purpose::Receipt), &tags::RECEIPT, &structure, self.caller)
                .map_err(|e| match e {
                    CustodyError::Backend(b) => backend(b),
                    other => Fail::Reject(Rejection::new(Stage::Receipt, Code::Wire(fieldseal_kernel::ErrorCode::Sig), format!("the receipt key could not sign: {other}"))),
                })?;
            let receipt = Receipt { tenancy: part.view.tenancy, last_seq: last, hash_at, received: now, of, signer: self.receipt_key, sig };
            let bytes = receipt.encode().map_err(|w| Fail::Reject(Rejection::new(Stage::Receipt, Code::Wire(w.code), w.detail)))?;
            receipts.push(IssuedReceipt { receipt, bytes });
        }

        let final_state = {
            let marked = summary.flagged > 0
                || summary.held > 0
                || summary.conflicts > 0
                || sub.findings().iter().any(|f| matches!(f.kind, FindingKind::Flag | FindingKind::Quarantine | FindingKind::Loss));
            if summary.landed + summary.duplicates == 0 && summary.held > 0 {
                GateState::Quarantined
            } else if marked {
                GateState::Flagged
            } else {
                GateState::Landed
            }
        };
        sub.advance(final_state).map_err(backend)?;
        batch.findings = sub.findings().to_vec();
        if land {
            self.platform.land(&batch).map_err(backend)?;
        }

        Ok(IngestReport {
            submission: sub.clone(),
            receipts,
            summary,
            losses: batch.losses.clone(),
            consent: batch.consent.clone(),
            records,
        })
    }
}

