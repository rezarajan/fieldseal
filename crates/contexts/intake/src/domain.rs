//! Entities, value objects and invariants of the Intake context
//! (`docs/reference/spec/intake.md` §2).

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_kernel::ErrorCode;
use fieldseal_kernel::crypto::P256PublicKey;
use fieldseal_kernel::id::{
    CohortId, ContentAddress, Digest, Fingerprint, Generation, ItemPath, RecordId, Seq, SubjectId,
    TenancyHandle, TenancyId,
};
use fieldseal_kernel::payload::Layout;
use fieldseal_kernel::time::AuthorityTime;

/// A submission's identifier: the SHA-256 of its raw bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct SubmissionId(pub Digest);

/// How a submission arrived.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SubmissionSource {
    /// A background upload.
    Upload,
    /// An export file, by any route.
    File,
}

/// A position in the verification gate (intake spec, *Gate state machine*).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum GateState {
    /// Just stored.
    Received,
    /// Unreadable or over size.
    Rejected,
    /// The tenancy handle is known.
    Resolved,
    /// The handle is unknown; the manifest's registration request may resolve it.
    Unregistered,
    /// Held for a custodian.
    Quarantined,
    /// The file signature is valid.
    Signed,
    /// Being repaired from parity or another copy.
    Repair,
    /// Some data is beyond repair; intact runs salvaged.
    PartialLoss,
    /// The manifest is decrypted.
    Opened,
    /// The certificate chains to the root and keys aren't revoked.
    Certified,
    /// Record signatures are valid.
    RecordsOk,
    /// The chain is continuous and closing, checkpoint and cutoff rules hold.
    Chained,
    /// Ticks are monotonic and not running fast.
    Timed,
    /// Records are decrypted.
    Decrypted,
    /// Consent rules pass.
    ConsentChecked,
    /// Rule replay matches.
    Replayed,
    /// Deduplicated and landed.
    Landed,
    /// Landed with a flag, for a custodian.
    Flagged,
}

impl GateState {
    /// Whether the gate may move from `self` to `next`. Nothing is decrypted before
    /// the file and record signatures are checked: there is no path to `Opened` or
    /// `Decrypted` that skips them.
    ///
    /// Ticks are inside the sealed payload (WIRE-034), so records are decrypted before their
    /// ticks are checked; rule replay precedes the consent decisions (issue #53 spec notes).
    pub fn may_move_to(self, next: GateState) -> bool {
        use GateState::*;
        matches!(
            (self, next),
            (Received, Rejected | Resolved | Unregistered)
                | (Unregistered, Resolved | Quarantined | Rejected)
                | (Resolved, Signed | Repair | Rejected)
                | (Repair, Signed | PartialLoss | Rejected)
                | (Signed, Opened | Rejected)
                | (Opened, Certified | Rejected)
                | (Certified, RecordsOk | Flagged | Rejected)
                | (RecordsOk, Chained | Rejected)
                | (Chained | PartialLoss, Decrypted | Rejected)
                | (Decrypted, Timed | Rejected)
                | (Timed, Replayed | Flagged | Rejected)
                | (Replayed, ConsentChecked | Quarantined | Rejected)
                | (ConsentChecked, Landed | Flagged | Quarantined | Rejected)
        )
    }
}

/// What kind of finding was recorded.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum FindingKind {
    /// A flag for a custodian.
    Flag,
    /// A repair from parity or another copy.
    Repair,
    /// A loss beyond repair.
    Loss,
    /// A rejection.
    Rejection,
    /// A record held for a custodian (quarantine).
    Quarantine,
}

/// A recorded finding, with the rule that raised it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Finding {
    /// Its kind.
    pub kind: FindingKind,
    /// The requirement or rule, for example `INT-031`.
    pub rule: String,
    /// What was found, without personal data.
    pub detail: String,
}

impl Finding {
    /// A finding of `kind` under `rule`.
    pub fn new(kind: FindingKind, rule: &str, detail: impl Into<String>) -> Self {
        Self { kind, rule: rule.to_owned(), detail: detail.into() }
    }
}

/// The error code a rejection carries: a WIRE code (§6.8) or the INT requirement that
/// refused the submission.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Code {
    /// A WIRE error code, for example `E_SIG`.
    Wire(ErrorCode),
    /// An Intake requirement, for example `INT-003`.
    Int(&'static str),
}

impl core::fmt::Display for Code {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Code::Wire(c) => write!(f, "{c}"),
            Code::Int(r) => f.write_str(r),
        }
    }
}

/// The verification stages, in the fixed order of INT-001. A submission is rejected at the
/// first stage that fails, and no later stage runs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Stage {
    /// Size and framing.
    Framing = 1,
    /// Parity repair.
    Parity,
    /// The export signature, by the tenancy key.
    ExportSignature,
    /// The tenancy certificate's chain to the authority root.
    Certificate,
    /// The key history.
    KeyHistory,
    /// Record signatures, the journal hash chain and checkpoints.
    Chain,
    /// Record decryption.
    Decrypt,
    /// Payload decoding.
    Payload,
    /// Ticks and anchors.
    Ticks,
    /// Replay of the instruments' rules.
    Replay,
    /// Consent basis decisions.
    Consent,
    /// Replay and duplicate detection.
    Duplicates,
    /// Receipt issue.
    Receipt,
}

/// Why a submission was refused: nothing from it was landed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Rejection {
    /// The stage that failed.
    pub stage: Stage,
    /// The error code.
    pub code: Code,
    /// The byte offset in the submission, where one applies.
    pub offset: Option<usize>,
    /// What failed, without personal data.
    pub detail: String,
}

impl Rejection {
    /// A rejection at `stage` with `code`.
    pub fn new(stage: Stage, code: Code, detail: impl Into<String>) -> Self {
        Self { stage, code, offset: None, detail: detail.into() }
    }

    /// The same rejection, located at `offset`.
    pub fn at(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }
}

impl core::fmt::Display for Rejection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}: {}: {}", self.stage, self.code, self.detail)?;
        if let Some(o) = self.offset {
            write!(f, " (offset {o})")?;
        }
        Ok(())
    }
}

/// Why a submission couldn't move through the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("gate can't move from {from:?} to {to:?}")]
pub struct GateTransitionError {
    /// The current state.
    pub from: GateState,
    /// The state requested.
    pub to: GateState,
}

/// One received export or upload, as it moves through the gate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Submission {
    id: SubmissionId,
    source: SubmissionSource,
    received_at: AuthorityTime,
    state: GateState,
    findings: Vec<Finding>,
    rejection: Option<Rejection>,
}

impl Submission {
    /// A newly received submission.
    pub fn received(id: SubmissionId, source: SubmissionSource, received_at: AuthorityTime) -> Self {
        Self { id, source, received_at, state: GateState::Received, findings: vec![], rejection: None }
    }

    /// Moves to `next` if the state machine allows it.
    pub fn advance(&mut self, next: GateState) -> Result<(), GateTransitionError> {
        if !self.state.may_move_to(next) {
            return Err(GateTransitionError { from: self.state, to: next });
        }
        self.state = next;
        Ok(())
    }

    /// Records a finding.
    pub fn record(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Rejects the submission: it moves to `Rejected` and keeps the rejection. A
    /// submission that has reached a terminal state can't be rejected.
    pub fn reject(&mut self, rejection: Rejection) -> Result<(), GateTransitionError> {
        self.advance(GateState::Rejected)?;
        self.findings.push(Finding::new(FindingKind::Rejection, &rejection.code.to_string(), rejection.detail.clone()));
        self.rejection = Some(rejection);
        Ok(())
    }

    /// Its identifier.
    pub fn id(&self) -> &SubmissionId {
        &self.id
    }

    /// How it arrived.
    pub fn source(&self) -> SubmissionSource {
        self.source
    }

    /// When it arrived, by authority time.
    pub fn received_at(&self) -> AuthorityTime {
        self.received_at
    }

    /// Its gate state.
    pub fn state(&self) -> GateState {
        self.state
    }

    /// Its findings.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Why it was rejected, if it was.
    pub fn rejection(&self) -> Option<&Rejection> {
        self.rejection.as_ref()
    }
}

/// What intake knows about a tenancy, read from Registration.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TenancyView {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// Its export handle.
    pub handle: TenancyHandle,
    /// Its signing keys, with history: the index is the position.
    pub signing_keys: Vec<P256PublicKey>,
    /// For a revoked key (by index), the first `seq` it is revoked from (INT-006).
    pub key_revoked_from: BTreeMap<u64, Seq>,
    /// The deny-list or close cutoff, if any.
    pub cutoff: Option<Seq>,
    /// Whether it is deny-listed.
    pub deny_listed: bool,
    /// The tenancy this one succeeds, if any (`prev_closing`): observations of related
    /// tenancies are ordered against each other, unrelated ones are not (INT-054).
    pub predecessor: Option<TenancyId>,
}

impl TenancyView {
    /// A view with no revoked keys, no cutoff and no predecessor.
    pub fn new(tenancy: TenancyId, handle: TenancyHandle, signing_keys: Vec<P256PublicKey>) -> Self {
        Self {
            tenancy,
            handle,
            signing_keys,
            key_revoked_from: BTreeMap::new(),
            cutoff: None,
            deny_listed: false,
            predecessor: None,
        }
    }
}

/// A consent state as an authority-issued roster stated it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum IssuedConsent {
    /// Granted.
    Granted,
    /// Refused.
    Refused,
    /// Unknown.
    Unknown,
}

/// One roster version issued to a tenancy, for consent checks (INT, DIS).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IssuedRoster {
    /// The cohort.
    pub cohort: CohortId,
    /// The version.
    pub version: u64,
    /// The roster's content address, which records and imports name.
    pub address: Digest,
    /// When it was issued.
    pub issued_at: AuthorityTime,
    /// Each subject's consent state in this version.
    pub consent: BTreeMap<SubjectId, IssuedConsent>,
}

/// A consent decision (ADR 0022).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ConsentDecision {
    /// Consent from the roster; nothing to decide.
    NotNeeded,
    /// Waiting for a person.
    Pending,
    /// Accepted by policy without review.
    AutoAccepted,
    /// Accepted by a custodian.
    Accepted,
    /// Rejected; dependent observations are excluded, never deleted.
    Rejected,
}

/// The basis a subject's consent rests on.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ConsentBasis {
    /// The instrument needs no consent (INS-062).
    NotRequired,
    /// A roster version granted it (INT-031).
    Roster {
        /// The roster's content address.
        roster: Digest,
        /// Its version.
        version: u64,
    },
    /// The collector attested it (INT-032); the instrument's basis code.
    Attestation {
        /// The consent record.
        record: RecordId,
        /// The basis code.
        basis: String,
    },
}

impl ConsentBasis {
    /// The text written to the `consent_basis` column.
    pub fn label(&self) -> String {
        match self {
            ConsentBasis::NotRequired => "not-required".to_owned(),
            ConsentBasis::Roster { version, .. } => format!("roster:{version}"),
            ConsentBasis::Attestation { basis, .. } => format!("attestation:{basis}"),
        }
    }
}

/// Who decided a case, when, and under which policy (INT-040).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DecisionTrail {
    /// Who or what decided: `policy` or a custodian's identity.
    pub by: String,
    /// When.
    pub at: AuthorityTime,
    /// The effective policy's layer addresses.
    pub policy: Vec<ContentAddress>,
    /// The decision.
    pub decision: ConsentDecision,
}

/// A subject's consent basis in one tenancy.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConsentCase {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The subject.
    pub subject: SubjectId,
    /// The instrument the consent covers.
    pub instrument: Fingerprint,
    /// The basis.
    pub basis: ConsentBasis,
    /// The decision.
    pub decision: ConsentDecision,
    /// Whether it was drawn for review by sampling.
    pub sampled: bool,
    /// Hashes of evidence records.
    pub evidence: Vec<Digest>,
    /// The records whose observations depend on this case (INT-039).
    pub records: Vec<RecordId>,
    /// Every decision, oldest first (INT-040).
    pub history: Vec<DecisionTrail>,
}

/// Records lost beyond repair.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LossLedgerEntry {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// First `seq` lost.
    pub from: Seq,
    /// Last `seq` lost.
    pub through: Seq,
    /// Why.
    pub reason: String,
}

/// A landed value's type.
#[derive(Clone, PartialEq, Debug)]
pub enum ObservedValue {
    /// A boolean.
    Bool(bool),
    /// An integer.
    Int(i64),
    /// A decimal, in canonical text form.
    Decimal(String),
    /// Text.
    Text(String),
    /// A code from a coded list.
    Code(String),
    /// Several codes.
    Codes(Vec<String>),
}

/// Why an item has no value (INS-072, INS-141, INS-142).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Nonresponse {
    /// The subject doesn't know.
    DontKnow,
    /// The subject refused.
    Refused,
    /// A `skip` or `when` hid the item; derived by intake, never entered (INS-142).
    NotApplicable,
}

impl Nonresponse {
    /// The text written to the nonresponse column.
    pub fn code(self) -> &'static str {
        match self {
            Nonresponse::DontKnow => "dont-know",
            Nonresponse::Refused => "refused",
            Nonresponse::NotApplicable => "not-applicable",
        }
    }
}

/// What an observation row says about its item.
#[derive(Clone, PartialEq, Debug)]
pub enum Reading {
    /// A value.
    Value(ObservedValue),
    /// A nonresponse; the value column is empty.
    Nonresponse(Nonresponse),
    /// The earlier value is withdrawn with no replacement (WIRE-052).
    Retracted,
}

/// One landed row of the generic long format. Keyed by instrument fingerprint, never by
/// name (INT-070).
#[derive(Clone, PartialEq, Debug)]
pub struct Observation {
    /// The instrument's fingerprint.
    pub instrument: Fingerprint,
    /// The layout the record was collected with (INS-209).
    pub layout: Layout,
    /// BCP 47 tags of the languages the record was administered in (INT-071).
    pub lang: Vec<String>,
    /// The subject.
    pub subject: SubjectId,
    /// The item.
    pub item: ItemPath,
    /// The value, a nonresponse or a retraction.
    pub reading: Reading,
    /// The instrument's data type of the item, for example `decimal`.
    pub value_type: &'static str,
    /// The unit values are landed in (UCUM, or a currency).
    pub unit: Option<String>,
    /// The record it came from.
    pub source: RecordId,
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The tenancy's generation for the subject's cohort.
    pub generation: Generation,
    /// The record's `seq`.
    pub seq: Seq,
    /// Lower bound on when it was collected (from ticks), where anchors allow one.
    pub not_before: Option<AuthorityTime>,
    /// Upper bound (delivery time).
    pub not_after: AuthorityTime,
    /// The consent basis, as text.
    pub consent_basis: String,
    /// The record's flags.
    pub flags: BTreeSet<String>,
}

/// An observation as stored, with any exclusion.
#[derive(Clone, PartialEq, Debug)]
pub struct LandedObservation {
    /// The observation.
    pub observation: Observation,
    /// Why it is excluded, if it is; excluded observations are kept.
    pub excluded: Option<String>,
}

/// A verified record's raw envelope as landed (INT-050), kept for deduplication (INT-013)
/// and receipts (INT-014). Readable by the custodian role only (INT-060).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LandedEnvelope {
    /// The record.
    pub record: RecordId,
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The record's `seq`.
    pub seq: Seq,
    /// The record hash (WIRE-036).
    pub hash: Digest,
    /// The canonical record body, unchanged.
    pub body: Vec<u8>,
    /// For an `evidence` record, its `blob_id` and the SHA-256 of its bytes (INT-033).
    pub evidence: Option<([u8; 16], Digest)>,
}
