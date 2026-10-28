//! The verification gate (INT-001–014, INT-020): from an unknown file to landed records, in
//! the fixed order of INT-001.
//!
//! | Stage | Module | Fails with |
//! |---|---|---|
//! | 1 size and framing | [`framing`] | `INT-003`, `E_FRAME_*`, `E_VERSION`, `E_EXPORT_SECTION` |
//! | 2 parity repair | [`framing`] | (repairs, or takes the partial-loss path, INT-020) |
//! | 3 export signature | [`framing`] | `E_SIG`, `INT-004` |
//! | 4 tenancy certificate chain | [`records`] | `E_SIG`, `E_HASH`, `INT-006` |
//! | 5 key history | [`records`] | `INT-006`, `E_HASH` |
//! | 6 journal chain and checkpoints | [`records`] | `E_CRC`, `E_SIG`, `E_CHAIN`, `E_SEQ`, `E_HASH` |
//! | 7 record decryption | [`records`] | `E_RECIPIENT`, `E_DECRYPT` |
//! | 8 payload decoding | [`records`] | `E_UNKNOWN_FIELD`, `E_CHAIN`, `E_SEQ`, `E_SIZE` |
//! | 9 ticks and anchors | [`records`] | `E_TICK`, `INT-011` |
//! | 10 rule replay | [`replay`] | quarantines records (INT-012) |
//! | 11 consent decisions | [`consent`] | quarantines or excludes records (INT-030–039) |
//! | 12 replay and duplicates | [`landing`] | quarantines conflicts (INT-013) |
//! | 13 receipts | [`landing`] | `E_SIG` |
//!
//! A stage that rejects stops the run: no later stage executes, so a later fault is never
//! reported while an earlier one exists. Nothing is landed unless every stage passed, and
//! landing is a single atomic write ([`crate::ports::DataPlatform::land`]).

mod consent;
mod framing;
mod landing;
mod records;
mod replay;

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_instrument::domain::Instrument;
use fieldseal_kernel::crypto::P256PublicKey;
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::export::ExportSignature;
use fieldseal_kernel::id::{Digest, Fingerprint, KeyId, RecordId, TenancyId};
use fieldseal_kernel::record::JournalEntry;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::domain::EffectivePolicy;
use fieldseal_policy::ports::PolicyEngine;
use fieldseal_trust::domain::{Revocation, TrustBundle};
use fieldseal_trust::ports::{KeyCustody, RandomSource};
use zeroize::Zeroizing;

use crate::application::IntakeError;
use crate::domain::{
    ConsentCase, GateState, LossLedgerEntry, Rejection, Submission, SubmissionSource, TenancyView,
};
use crate::ports::{
    DataPlatform, InstrumentSource, RosterHistory, SubmissionStore, SubmissionStoreError, TenancyRegistry,
};
use crate::wire::{CertWindow, ExportManifest, Payload, Receipt};

/// A stage failed: the submission is refused, or a backing service failed.
pub(crate) enum Fail {
    Reject(Rejection),
    Backend(IntakeError),
}

impl From<Rejection> for Fail {
    fn from(r: Rejection) -> Self {
        Fail::Reject(r)
    }
}

pub(crate) type Step<T = ()> = Result<T, Fail>;

/// A gap in a part's chain waiting for a checkpoint (INT-009): the record at `seq` has a
/// `prev` that no earlier present record accounts for.
#[derive(Clone, Debug)]
pub(crate) struct Gap {
    pub seq: u64,
    pub prev: Digest,
    pub offset: usize,
    /// The `seq` of the last present record before the gap, if any.
    pub after: Option<u64>,
}

/// One part of the submission as it moves through the stages.
pub(crate) struct Part {
    pub sealed_manifest: Vec<u8>,
    pub journal: Vec<u8>,
    pub signature: Option<ExportSignature>,
    pub has_parity: bool,
    pub view: TenancyView,
    pub registered: bool,
    pub manifest: Option<ExportManifest>,
    pub keys: Vec<P256PublicKey>,
    pub entries: Vec<JournalEntry>,
    pub gaps: Vec<Gap>,
    pub flags: BTreeMap<u64, BTreeSet<String>>,
    pub plaintexts: Vec<Zeroizing<Vec<u8>>>,
    pub payloads: Vec<Payload>,
    pub bounds: Vec<Option<AuthorityTime>>,
    pub losses: Vec<LossLedgerEntry>,
    pub partial: bool,
    pub window: Option<CertWindow>,
    pub cohorts: Vec<(String, u64)>,
    pub record_key: Option<KeyId>,
}

impl Part {
    pub(crate) fn flag(&mut self, seq: u64, flag: &str) {
        self.flags.entry(seq).or_default().insert(flag.to_owned());
    }
}

/// What a record became at the end of the gate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordOutcome {
    /// Landed.
    Landed,
    /// Already landed with the same hash; no landed value changed (INT-013).
    Duplicate,
    /// Verified and kept, but its observations are held for a custodian.
    Held,
    /// Conflicts with a landed record; not landed.
    Conflict,
}

/// The counts of what a submission landed.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct LandingSummary {
    /// Records whose envelopes and observations landed.
    pub landed: usize,
    /// Records already landed.
    pub duplicates: usize,
    /// Records verified but held for a custodian (quarantine).
    pub held: usize,
    /// Records refused as conflicting with landed ones.
    pub conflicts: usize,
    /// Observation rows written.
    pub observations: usize,
    /// Records carrying at least one flag.
    pub flagged: usize,
}

/// An issued receipt and its canonical bytes (WIRE-142).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IssuedReceipt {
    /// The receipt.
    pub receipt: Receipt,
    /// Its canonical bytes, at most 300 (WIRE-144).
    pub bytes: Vec<u8>,
}

/// The result of running one submission through the gate.
#[derive(Clone, PartialEq, Debug)]
pub struct IngestReport {
    /// The submission, with its final state and findings.
    pub submission: Submission,
    /// Receipts, one per tenancy part acknowledged (INT-014).
    pub receipts: Vec<IssuedReceipt>,
    /// What landed.
    pub summary: LandingSummary,
    /// Loss-ledger entries written (INT-020).
    pub losses: Vec<LossLedgerEntry>,
    /// Consent cases written or updated.
    pub consent: Vec<ConsentCase>,
    /// What each record became, by record.
    pub records: Vec<(RecordId, RecordOutcome)>,
}

/// Intake's gate and landing, wired to its ports. Pure: keys are used through
/// [`KeyCustody`], time is passed in, randomness comes from [`RandomSource`].
pub struct IntakeService<'a> {
    /// Raw submissions, write-once (INT-002).
    pub store: &'a dyn SubmissionStore,
    /// Tenancies, keys, cutoffs and successions from Registration.
    pub registry: &'a dyn TenancyRegistry,
    /// Roster versions issued to tenancies.
    pub rosters: &'a dyn RosterHistory,
    /// Published instruments by fingerprint.
    pub instruments: &'a dyn InstrumentSource,
    /// Where landed data goes.
    pub platform: &'a dyn DataPlatform,
    /// Authority keys: the period's record key (`record`, `registration`) and the receipt key.
    pub custody: &'a dyn KeyCustody,
    /// Evaluates intake decisions.
    pub policy: &'a dyn PolicyEngine,
    /// The effective intake policy.
    pub effective: &'a EffectivePolicy,
    /// Randomness for consent sampling, auditable by seed.
    pub random: &'a dyn RandomSource,
    /// The trust bundle: authority roots and purpose-key certificates.
    pub trust: &'a TrustBundle,
    /// Revocations received since the bundle was issued.
    pub revocations: Vec<Revocation>,
    /// The key in custody that signs receipts.
    pub receipt_key: KeyId,
    /// The caller identity recorded with every custody use.
    pub caller: &'a str,
}

/// The facts about the instruments in play, loaded once per run.
pub(crate) struct Instruments {
    pub by_fingerprint: BTreeMap<Fingerprint, Option<Instrument>>,
}

fn backend(e: impl core::fmt::Display) -> Fail {
    Fail::Backend(IntakeError::Backend(e.to_string()))
}

impl IntakeService<'_> {
    /// `IngestSubmission` (INT-001–014): stores the raw bytes, then runs every stage in
    /// order. A refused submission returns `Ok` with state `Rejected` and the rejection's
    /// stage and code; `Err` is for a backing service that failed, in which case nothing
    /// was landed.
    pub fn ingest(&self, bytes: &[u8], source: SubmissionSource, now: AuthorityTime) -> Result<IngestReport, IntakeError> {
        self.ingest_with(bytes, source, now, true)
    }

    /// Runs every stage but writes nothing to the data platform: what `ReplaySubmission`
    /// and `fieldseal intake replay` use.
    pub fn dry_run(&self, bytes: &[u8], source: SubmissionSource, now: AuthorityTime) -> Result<IngestReport, IntakeError> {
        self.ingest_with(bytes, source, now, false)
    }

    fn ingest_with(&self, bytes: &[u8], source: SubmissionSource, now: AuthorityTime, land: bool) -> Result<IngestReport, IntakeError> {
        let of = sha256(bytes);
        let stored = match self.store.put(bytes) {
            Ok(id) => Ok(id),
            Err(SubmissionStoreError::TooLarge) => Err(true),
            Err(e) => return Err(IntakeError::Backend(e.to_string())),
        };
        let id = match stored {
            Ok(id) => id,
            Err(_) => {
                let mut sub = Submission::received(crate::domain::SubmissionId(of), source, now);
                let r = Rejection::new(
                    crate::domain::Stage::Framing,
                    crate::domain::Code::Int("INT-003"),
                    "the submission store refused the size",
                );
                sub.reject(r).map_err(|e| IntakeError::Backend(e.to_string()))?;
                return Ok(IngestReport::empty(sub));
            }
        };
        let mut sub = Submission::received(id, source, now);
        match self.run(bytes, of, now, land, &mut sub) {
            Ok(report) => Ok(report),
            Err(Fail::Reject(r)) => {
                sub.reject(r).map_err(|e| IntakeError::Backend(e.to_string()))?;
                Ok(IngestReport::empty(sub))
            }
            Err(Fail::Backend(e)) => Err(e),
        }
    }

    fn run(&self, bytes: &[u8], of: Digest, now: AuthorityTime, land: bool, sub: &mut Submission) -> Step<IngestReport> {
        let intake = self.effective.intake();
        // 1–3: size, framing, parity, export signature.
        let mut parts = self.stage_framing_to_signature(bytes, now, sub, &intake)?;
        // 4–6: certificate, key history, chain.
        if !parts.iter().all(|p| p.partial) {
            self.stage_certificate(&mut parts, sub)?;
            self.stage_key_history(&mut parts)?;
        }
        self.stage_chain(&mut parts, sub)?;
        // 7–8: decryption and decoding.
        self.stage_decrypt(&mut parts, sub)?;
        self.stage_payload(&mut parts)?;
        // 9: ticks and anchors.
        self.stage_ticks(&mut parts, now, sub, &intake)?;
        // 10–11: replay and consent.
        let instruments = self.load_instruments(&parts)?;
        let replay = self.stage_replay(&parts, &instruments, sub)?;
        sub.advance(GateState::Replayed).map_err(backend)?;
        let consent = self.stage_consent(&parts, &instruments, &replay, now, sub, &intake)?;
        sub.advance(GateState::ConsentChecked).map_err(backend)?;
        // 12–13: duplicates, landing, receipts.
        self.stage_landing(&parts, &instruments, replay, consent, of, now, land, sub)
    }

    fn load_instruments(&self, parts: &[Part]) -> Step<Instruments> {
        let mut by_fingerprint = BTreeMap::new();
        for p in parts {
            for payload in &p.payloads {
                let fp = match payload {
                    Payload::Items(i) => i.instrument,
                    Payload::Status { instrument, .. } | Payload::Consent { instrument, .. } => Fingerprint::from(*instrument.as_bytes()),
                    _ => continue,
                };
                if let std::collections::btree_map::Entry::Vacant(e) = by_fingerprint.entry(fp) {
                    e.insert(self.instruments.instrument(&fp).map_err(backend)?);
                }
            }
        }
        Ok(Instruments { by_fingerprint })
    }

    /// The tenancy view for a tenancy ID, if registered (used for succession lineage).
    pub(crate) fn view_of(&self, id: &TenancyId) -> Option<TenancyView> {
        self.registry.by_id(id).ok().flatten()
    }
}

impl IngestReport {
    /// A report for a submission that landed nothing.
    pub fn empty(submission: Submission) -> Self {
        Self {
            submission,
            receipts: vec![],
            summary: LandingSummary::default(),
            losses: vec![],
            consent: vec![],
            records: vec![],
        }
    }
}
