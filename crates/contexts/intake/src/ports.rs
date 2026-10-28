//! Driven ports owned by the Intake context (`docs/reference/spec/intake.md` §4).
//!
//! Intake also uses ports owned by inner contexts: Trust's `KeyCustody` (the spec's
//! `RecordKeyUnsealer`, purpose `record`, and `ReceiptSigner`, purpose `receipt`) and
//! `RandomSource` (consent sampling), and Policy's `PolicyEngine`. Published instruments
//! reach intake through [`InstrumentSource`], whose adapters fetch from Publishing's
//! `ArtefactRegistry` and verify the publication before returning it.

use fieldseal_instrument::domain::Instrument;
use fieldseal_kernel::id::{Fingerprint, RecordId, SubjectId, TenancyHandle, TenancyId};
use fieldseal_kernel::time::AuthorityTime;

use crate::domain::{
    ConsentCase, Finding, IssuedRoster, LandedEnvelope, LandedObservation, LossLedgerEntry, Observation,
    SubmissionId, TenancyView,
};

/// Remembers the proof-of-possession token identifiers seen within the freshness window, so
/// a captured token can't be replayed (DEL-003, WIRE-171).
///
/// Contract: the first use of a `(tenancy, jti)` returns `true`; a second use before
/// `until` returns `false`; once `until` has passed, the identifier may be forgotten and
/// used again (the freshness check on `iat` still refuses it).
pub trait PopLedger {
    /// Records a use of `jti` from `now` until `until`; `false` if it was already seen.
    fn first_use(&self, tenancy: &TenancyId, jti: &[u8; 16], now: AuthorityTime, until: AuthorityTime) -> Result<bool, String>;
}

/// Errors from [`SubmissionStore`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SubmissionStoreError {
    /// The submission is larger than the store accepts.
    #[error("too large")]
    TooLarge,
    /// The store failed.
    #[error("submission store: {0}")]
    Backend(String),
}

/// Write-once storage for raw submissions, addressed by content hash.
///
/// Contract: the identifier is the SHA-256 of the bytes; storing the same bytes again
/// returns the same identifier and changes nothing; there is no overwrite or delete.
pub trait SubmissionStore {
    /// Stores raw bytes.
    fn put(&self, bytes: &[u8]) -> Result<SubmissionId, SubmissionStoreError>;
    /// Reads raw bytes.
    fn get(&self, id: &SubmissionId) -> Result<Option<Vec<u8>>, SubmissionStoreError>;
}

/// Errors from [`TenancyRegistry`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TenancyRegistryError {
    /// Registration is unavailable.
    #[error("tenancy registry: {0}")]
    Unavailable(String),
}

/// A read-only view of Registration's tenancies, keys, cutoffs and deny-list.
///
/// Contract: read-only; a tenancy found by handle and by ID is the same view.
pub trait TenancyRegistry {
    /// A tenancy by export handle.
    fn by_handle(&self, handle: &TenancyHandle) -> Result<Option<TenancyView>, TenancyRegistryError>;
    /// A tenancy by ID.
    fn by_id(&self, id: &TenancyId) -> Result<Option<TenancyView>, TenancyRegistryError>;
}

/// Errors from [`RosterHistory`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RosterHistoryError {
    /// The source is unavailable.
    #[error("roster history: {0}")]
    Unavailable(String),
}

/// Every roster version issued to a tenancy, with consent states and issue times.
///
/// Contract: complete; ordered by cohort, then ascending version.
pub trait RosterHistory {
    /// The versions issued to `tenancy`.
    fn issued(&self, tenancy: &TenancyId) -> Result<Vec<IssuedRoster>, RosterHistoryError>;
}

/// Errors from [`InstrumentSource`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstrumentSourceError {
    /// The source is unavailable.
    #[error("instrument source: {0}")]
    Unavailable(String),
}

/// Published instruments by fingerprint (the spec's `ArtefactRegistry`, INT-070).
///
/// Contract: returns only instruments whose publication verified (PUB) and whose
/// fingerprint equals the one asked for; `None` for a fingerprint it doesn't hold.
pub trait InstrumentSource {
    /// The instrument published under `fingerprint`.
    fn instrument(&self, fingerprint: &Fingerprint) -> Result<Option<Instrument>, InstrumentSourceError>;
}

/// Errors from [`DataPlatform`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DataPlatformError {
    /// The platform failed.
    #[error("data platform: {0}")]
    Backend(String),
}

/// Everything one submission lands, written together (INT-050): nothing from a submission
/// is visible unless all of it is.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct LandingBatch {
    /// The submission.
    pub submission: Option<SubmissionId>,
    /// The raw envelopes of the verified records, unchanged.
    pub envelopes: Vec<LandedEnvelope>,
    /// The observations (the generic long format).
    pub observations: Vec<Observation>,
    /// The findings.
    pub findings: Vec<Finding>,
    /// The consent cases, current state.
    pub consent: Vec<ConsentCase>,
    /// The loss-ledger entries.
    pub losses: Vec<LossLedgerEntry>,
    /// Records whose observations land excluded, with the reason (INT-039, INT-055).
    pub exclusions: Vec<(RecordId, String)>,
}

/// Where landed data goes (a lakehouse is one adapter).
///
/// Contract: [`DataPlatform::land`] is atomic and append-only; exclusion is a flag on
/// existing observations, never a deletion; observations are keyed by instrument
/// fingerprint; a consent case is replaced by key (tenancy, subject, instrument) so the
/// latest decision is current; envelopes are found by tenancy and by evidence `blob_id`.
pub trait DataPlatform {
    /// Appends a submission's landing.
    fn land(&self, batch: &LandingBatch) -> Result<(), DataPlatformError>;
    /// Flags every observation from `sources` as excluded, with a reason.
    fn exclude(&self, sources: &[RecordId], reason: &str) -> Result<(), DataPlatformError>;
    /// Removes the exclusion from every observation from `sources` (a custodian reversing a
    /// rejection); the observations were never deleted.
    fn reinstate(&self, sources: &[RecordId]) -> Result<(), DataPlatformError>;
    /// Every observation for an instrument, with exclusions.
    fn observations(&self, instrument: &Fingerprint) -> Result<Vec<LandedObservation>, DataPlatformError>;
    /// The landed envelopes of a tenancy, by ascending `seq`.
    fn envelopes(&self, tenancy: &TenancyId) -> Result<Vec<LandedEnvelope>, DataPlatformError>;
    /// The SHA-256 of the evidence landed under `blob_id`, from this or an earlier submission.
    fn evidence(&self, blob_id: &[u8; 16]) -> Result<Option<fieldseal_kernel::id::Digest>, DataPlatformError>;
    /// A consent case, by tenancy, subject and instrument.
    fn consent_case(
        &self,
        tenancy: &TenancyId,
        subject: &SubjectId,
        instrument: &Fingerprint,
    ) -> Result<Option<ConsentCase>, DataPlatformError>;
    /// Every consent case, oldest first.
    fn consent_cases(&self) -> Result<Vec<ConsentCase>, DataPlatformError>;
    /// Every loss-ledger entry.
    fn losses(&self) -> Result<Vec<LossLedgerEntry>, DataPlatformError>;
    /// Every finding landed, with its submission.
    fn findings(&self) -> Result<Vec<(SubmissionId, Finding)>, DataPlatformError>;
}
