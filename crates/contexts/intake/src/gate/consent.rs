//! Stage 11: consent basis decisions (INT-030–040, ADR 0022).
//!
//! Every `items` record about a subject must reference a consent basis that precedes it in
//! the chain. A roster basis is checked against the rosters issued to the tenancy; an
//! attestation against the roster the tenancy held, its evidence, and intake policy through
//! the policy engine (`consent.decide`). Records whose basis fails are held (quarantined);
//! rejected or pending bases exclude their observations by flag, never by deletion.

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_instrument::domain::metadata::ConsentRequirement;
use fieldseal_kernel::digest::{lower_hex, sha256};
use fieldseal_kernel::id::{Digest, Fingerprint, RecordId, SubjectId, TenancyId};
use fieldseal_kernel::payload::ConsentRef;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Decimal, Value};
use fieldseal_policy::domain::{DecisionPoint, IntakePolicy, Obligation, Verdict};

use super::replay::{ReplayResult, subject_id};
use super::{Instruments, IntakeService, Part, Step, backend};
use crate::domain::{
    ConsentBasis, ConsentCase, ConsentDecision, DecisionTrail, Finding, FindingKind, IssuedConsent, IssuedRoster,
    Submission,
};
use crate::wire::{EvidenceRef, ImportedRoster, Payload};

/// The heuristic window of `burst` (INT-037): attestations within it are counted. The
/// policy schema carries only heuristic names (POL §6.3), so the window and count are the
/// defaults of the spec's example (`count: 20, window: 10m`).
const BURST_WINDOW_MS: u64 = 10 * 60 * 1000;
const BURST_COUNT: usize = 20;

/// What stage 11 decided.
#[derive(Clone, Debug, Default)]
pub(crate) struct ConsentResult {
    /// Consent cases created or updated by this submission.
    pub cases: Vec<ConsentCase>,
    /// Records held for a custodian, with reasons (INT-030–034).
    pub held: BTreeMap<RecordId, Vec<String>>,
    /// Observations to land excluded, with the reason (INT-039, INT-055).
    pub exclusions: BTreeMap<RecordId, String>,
    /// The consent basis written to each record's observations.
    pub basis: BTreeMap<RecordId, String>,
    /// The tenancy's generation for each record's subject's cohort (INT-053).
    pub generation: BTreeMap<RecordId, u32>,
}

struct Import {
    seq: u64,
    lower: Option<AuthorityTime>,
    rosters: Vec<ImportedRoster>,
}

type Reject = (&'static str, String);
type Attested = Result<(ConsentDecision, bool, Vec<Digest>), Reject>;

fn check_roster_basis(issued: &[IssuedRoster], imports: &[Import], rec_seq: u64, roster: &Digest, version: u64, subject: &SubjectId) -> Result<IssuedRoster, Reject> {
    let Some(r) = issued.iter().find(|r| &r.address == roster && r.version == version) else {
        return Err(("INT-031", "the roster version named was not issued to this tenancy".into()));
    };
    let import_of = |addr: &Digest, ver: u64| imports.iter().find(|i| i.rosters.iter().any(|x| &x.address == addr && x.version == ver));
    if let Some(imp) = import_of(roster, version)
        && imp.seq > rec_seq
    {
        return Err(("INT-030", "the roster was imported after the record that relies on it".into()));
    }
    match r.consent.get(subject) {
        Some(IssuedConsent::Granted) => {}
        Some(IssuedConsent::Refused) => return Err(("INT-034", "the subject's consent is refused on the roster".into())),
        _ => return Err(("INT-031", "the roster does not grant the subject's consent".into())),
    }
    for later in issued.iter().filter(|x| x.cohort == r.cohort && x.version > version) {
        if later.consent.get(subject) != Some(&IssuedConsent::Refused) {
            continue;
        }
        let imported_before = imports.iter().any(|i| i.seq < rec_seq && i.rosters.iter().any(|x| x.address == later.address && x.version == later.version));
        let issued_before_import = import_of(roster, version).and_then(|i| i.lower).is_some_and(|t| later.issued_at <= t);
        if imported_before || issued_before_import {
            return Err(("INT-031", format!("roster version {} marks the subject refused and was issued before the tenancy imported version {version}", later.version)));
        }
    }
    Ok(r.clone())
}

impl IntakeService<'_> {
    fn sample_draw(&self) -> Decimal {
        let mut b = [0u8; 4];
        self.random.fill(&mut b);
        let n = u128::from(u32::from_be_bytes(b));
        Decimal { mantissa: ((n * 1_000_000_000) >> 32) as i128, exponent: -9 }
    }

    /// The consent records whose burst heuristic fires (INT-037).
    fn burst_hits(part: &Part) -> BTreeSet<RecordId> {
        let mut times: Vec<(u64, RecordId)> = part
            .entries
            .iter()
            .zip(&part.payloads)
            .zip(&part.bounds)
            .filter_map(|((e, p), b)| matches!(p, Payload::Consent { .. }).then_some(()).and(b.map(|b| (b.0, e.record.header.record_id))))
            .collect();
        times.sort();
        let mut hits = BTreeSet::new();
        let mut lo = 0;
        for hi in 0..times.len() {
            while times[hi].0 - times[lo].0 > BURST_WINDOW_MS {
                lo += 1;
            }
            if hi - lo + 1 > BURST_COUNT {
                hits.extend(times[lo..=hi].iter().map(|t| t.1));
            }
        }
        hits
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn stage_consent(
        &self,
        parts: &[Part],
        instruments: &Instruments,
        replay: &ReplayResult,
        now: AuthorityTime,
        sub: &mut Submission,
        intake: &IntakePolicy,
    ) -> Step<ConsentResult> {
        let mut out = ConsentResult::default();
        let policy_addrs = self.effective.sources.clone();
        let heuristics: BTreeSet<&str> = intake.consent.heuristics.iter().map(String::as_str).collect();
        if heuristics.iter().any(|h| !matches!(*h, "burst")) {
            sub.record(Finding::new(
                FindingKind::Flag,
                "INT-037",
                "a heuristic other than `burst` is configured; only `burst` is evaluated here (others need cohort history)",
            ));
        }
        let mut cases: BTreeMap<(TenancyId, SubjectId, Fingerprint), ConsentCase> = BTreeMap::new();
        // An attestation is decided once, however many records rely on it.
        let mut attested: BTreeMap<RecordId, Attested> = BTreeMap::new();

        for part in parts {
            let tenancy = part.view.tenancy;
            let issued = self.rosters.issued(&tenancy).map_err(backend)?;
            let mut imports = Vec::new();
            let mut evidence_in = BTreeMap::new();
            let mut consent_at: BTreeMap<RecordId, usize> = BTreeMap::new();
            for (n, ((e, p), b)) in part.entries.iter().zip(&part.payloads).zip(&part.bounds).enumerate() {
                match p {
                    Payload::Import { rosters, .. } => imports.push(Import { seq: e.record.header.seq, lower: *b, rosters: rosters.clone() }),
                    Payload::Evidence { blob_id, bytes, .. } => {
                        evidence_in.insert(*blob_id, (sha256(bytes), bytes.len() as u64, e.record.header.seq));
                    }
                    Payload::Consent { .. } => {
                        consent_at.insert(e.record.header.record_id, n);
                    }
                    _ => {}
                }
            }
            let bursts = if heuristics.contains("burst") { Self::burst_hits(part) } else { BTreeSet::new() };

            for (n, (e, p)) in part.entries.iter().zip(&part.payloads).enumerate() {
                let Payload::Items(items) = p else { continue };
                let rid = e.record.header.record_id;
                if replay.held.contains_key(&rid) {
                    continue;
                }
                let seq = e.record.header.seq;
                let Some(subject) = subject_id(&items.subject) else {
                    out.held.insert(rid, vec!["INT-030: the record names no subject".into()]);
                    continue;
                };
                let Some(Some(inst)) = instruments.by_fingerprint.get(&items.instrument) else { continue };
                let key = (tenancy, subject.clone(), items.instrument);
                let hold = |out: &mut ConsentResult, sub: &mut Submission, rule: &'static str, msg: String| {
                    sub.record(Finding::new(FindingKind::Quarantine, rule, format!("record {} held: {msg}", lower_hex(rid.as_bytes()))));
                    out.held.insert(rid, vec![format!("{rule}: {msg}")]);
                };
                // The subject's cohort generation, from the roster that lists them.
                let cohort = issued
                    .iter()
                    .rev()
                    .find(|r| r.consent.contains_key(&subject))
                    .map(|r| r.cohort.as_str().to_owned());
                let generation = cohort
                    .and_then(|c| part.cohorts.iter().find(|(name, _)| *name == c).map(|(_, g)| *g))
                    .and_then(|g| u32::try_from(g).ok())
                    .unwrap_or(0);
                out.generation.insert(rid, generation);

                let ConsentRequirement::Required { bases, .. } = &inst.definition().consent else {
                    out.basis.insert(rid, ConsentBasis::NotRequired.label());
                    let case = cases.entry(key.clone()).or_insert_with(|| ConsentCase {
                        tenancy,
                        subject: subject.clone(),
                        instrument: items.instrument,
                        basis: ConsentBasis::NotRequired,
                        decision: ConsentDecision::NotNeeded,
                        sampled: false,
                        evidence: vec![],
                        records: vec![],
                        history: vec![],
                    });
                    case.records.push(rid);
                    continue;
                };

                match &items.consent_ref {
                    // The instrument requires consent (the not-required case returned above),
                    // so a record claiming none is needed is held (INS-062).
                    ConsentRef::NotRequired => {
                        hold(&mut out, sub, "INT-030", "the record claims no consent is needed, but its instrument requires consent".into());
                    }
                    ConsentRef::Roster { roster, version } => {
                        match check_roster_basis(&issued, &imports, seq, roster, *version, &subject) {
                            Err((rule, msg)) => hold(&mut out, sub, rule, msg),
                            Ok(_) => {
                                let basis = ConsentBasis::Roster { roster: *roster, version: *version };
                                out.basis.insert(rid, basis.label());
                                let case = cases.entry(key.clone()).or_insert_with(|| ConsentCase {
                                    tenancy,
                                    subject: subject.clone(),
                                    instrument: items.instrument,
                                    basis,
                                    decision: ConsentDecision::NotNeeded,
                                    sampled: false,
                                    evidence: vec![],
                                    records: vec![],
                                    history: vec![DecisionTrail { by: "policy".into(), at: now, policy: policy_addrs.clone(), decision: ConsentDecision::NotNeeded }],
                                });
                                case.records.push(rid);
                            }
                        }
                    }
                    ConsentRef::Record(cid) => {
                        // A consent record in this submission, before the record; or the
                        // case an earlier submission already decided.
                        let prior = self
                            .platform
                            .consent_case(&tenancy, &subject, &items.instrument)
                            .map_err(backend)?
                            .filter(|c| matches!(&c.basis, ConsentBasis::Attestation { record, .. } if record == cid));
                        let (decision, sampled, ev, basis) = if let Some(c) = prior {
                            (c.decision, c.sampled, c.evidence.clone(), c.basis.clone())
                        } else {
                            let Some(&cn) = consent_at.get(cid) else {
                                hold(&mut out, sub, "INT-030", "the consent record the record references is not in the chain".into());
                                continue;
                            };
                            let cseq = part.entries[cn].record.header.seq;
                            if cseq >= seq {
                                hold(&mut out, sub, "INT-030", "the consent record does not precede the record".into());
                                continue;
                            }
                            let Payload::Consent { instrument, subject: csub, basis, evidence, .. } = &part.payloads[cn] else { continue };
                            if csub != &items.subject || instrument.as_bytes() != items.instrument.as_bytes() {
                                hold(&mut out, sub, "INT-030", "the consent record is about another subject or instrument".into());
                                continue;
                            }
                            let result = attested.entry(*cid).or_insert_with(|| {
                                self.decide_attestation(
                                    bases.iter().any(|b| &b.code == basis),
                                    &issued,
                                    &subject,
                                    evidence,
                                    &evidence_in,
                                    part.bounds[cn],
                                    bursts.contains(cid),
                                )
                            });
                            match result {
                                Err((rule, msg)) => {
                                    hold(&mut out, sub, rule, msg.clone());
                                    continue;
                                }
                                Ok((decision, sampled, ev)) => (*decision, *sampled, ev.clone(), ConsentBasis::Attestation { record: *cid, basis: basis.clone() }),
                            }
                        };
                        out.basis.insert(rid, basis.label());
                        match decision {
                            ConsentDecision::Rejected => {
                                out.exclusions.insert(rid, "consent-rejected".into());
                            }
                            ConsentDecision::Pending if intake.consent.exclude_pending_from_analysis => {
                                out.exclusions.insert(rid, "consent-pending".into());
                            }
                            _ => {}
                        }
                        let case = cases.entry(key.clone()).or_insert_with(|| ConsentCase {
                            tenancy,
                            subject: subject.clone(),
                            instrument: items.instrument,
                            basis,
                            decision,
                            sampled,
                            evidence: ev,
                            records: vec![],
                            history: vec![DecisionTrail { by: "policy".into(), at: now, policy: policy_addrs.clone(), decision }],
                        });
                        case.records.push(rid);
                    }
                }
                let _ = n;
            }
        }
        out.cases = cases.into_values().collect();
        for c in &out.cases {
            match c.decision {
                ConsentDecision::Pending => sub.record(Finding::new(FindingKind::Flag, "INT-035", "an attestation is pending review")),
                ConsentDecision::Rejected => sub.record(Finding::new(FindingKind::Flag, "INT-038", "an attestation was rejected by policy; its observations are excluded")),
                _ if c.sampled => sub.record(Finding::new(FindingKind::Flag, "INT-036", "an auto-accepted attestation was drawn for review")),
                _ => {}
            }
        }
        Ok(out)
    }

    /// Checks one attestation (INT-032, INT-033) and has policy decide it (INT-035–038).
    #[allow(clippy::too_many_arguments)]
    fn decide_attestation(
        &self,
        basis_listed: bool,
        issued: &[IssuedRoster],
        subject: &SubjectId,
        evidence: &[EvidenceRef],
        evidence_in: &BTreeMap<[u8; 16], (Digest, u64, u64)>,
        lower: Option<AuthorityTime>,
        burst: bool,
    ) -> Result<(ConsentDecision, bool, Vec<Digest>), Reject> {
        if !basis_listed {
            return Err(("INT-032", "the attested basis is not one the instrument lists (INS-061)".into()));
        }
        // INT-032: the roster the tenancy held had the subject as `unknown`.
        let held = issued
            .iter()
            .filter(|r| r.consent.contains_key(subject) && lower.is_none_or(|t| r.issued_at <= t))
            .max_by_key(|r| (r.issued_at, r.version));
        match held.and_then(|r| r.consent.get(subject)) {
            Some(IssuedConsent::Unknown) => {}
            Some(_) => return Err(("INT-032", "an attestation is accepted only where the roster had the subject's consent as unknown".into())),
            None => return Err(("INT-032", "the subject is on no roster the tenancy held".into())),
        }
        // INT-033: evidence present, hash matching.
        let mut hashes = Vec::new();
        for r in evidence {
            let in_chain = evidence_in.get(&r.blob_id).is_some_and(|(h, len, _)| h == &r.sha256 && *len == r.size);
            let earlier = !in_chain && self.platform.evidence(&r.blob_id).ok().flatten().is_some_and(|h| h == r.sha256);
            if !in_chain && !earlier {
                return Err(("INT-033", "referenced evidence is missing or its hash does not match".into()));
            }
            hashes.push(r.sha256);
        }
        let draw = self.sample_draw();
        let facts = BTreeMap::from([
            ("hasEvidence".to_owned(), Value::Bool(!evidence.is_empty())),
            (
                "heuristicHits".to_owned(),
                Value::Array(if burst { vec![Value::Text("burst".into())] } else { vec![] }),
            ),
            ("sampleDraw".to_owned(), Value::Decimal(draw)),
        ]);
        Ok(match self.policy.evaluate(DecisionPoint::ConsentDecide, self.effective, &facts) {
            Ok(d) => match d.verdict {
                Verdict::Allow => (ConsentDecision::AutoAccepted, d.obligations.contains(&Obligation::SampleForReview), hashes),
                Verdict::Deny => (ConsentDecision::Rejected, false, hashes),
                Verdict::Hold | Verdict::Flag => (ConsentDecision::Pending, false, hashes),
            },
            // A failing engine holds for review, never accepts (POL-034).
            Err(_) => (ConsentDecision::Pending, false, hashes),
        })
    }
}
