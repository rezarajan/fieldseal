//! Driven ports owned by the Publishing context (`docs/reference/spec/publishing.md` §4).
//! Publishing also uses Trust's `KeyCustody` and `RandomSource`, and reads the typed
//! publishing policy from the Policy context.

use fieldseal_kernel::id::{ContentAddress, Digest, ReviewerId};

use crate::domain::{
    Artefact, ArtefactKind, BuilderId, ConsistencyProof, Diagnostic, InclusionProof, LeafFormat, LogEntry, Publication,
    Review, ReviewerRole, RevisionId, SignedCheckpoint, SourceSnapshot, Withdrawal,
};

/// Errors from [`SourceRepository`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    /// No such revision.
    #[error("revision not found")]
    NotFound,
    /// The repository failed.
    #[error("source repository: {0}")]
    Backend(String),
}

/// Artefact sources at immutable revisions (PUB-002).
///
/// Contract: a revision always returns the same snapshot.
pub trait SourceRepository {
    /// The snapshot at `revision`.
    fn fetch(&self, revision: &RevisionId) -> Result<SourceSnapshot, SourceError>;
}

/// Errors from [`ReviewSystem`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReviewError {
    /// The reviewer already recorded a decision for this artefact and revision.
    #[error("review already recorded")]
    AlreadyRecorded,
    /// The review system failed.
    #[error("review system: {0}")]
    Backend(String),
}

/// Reviews by authenticated (pseudonymous) identity against exact revisions: the source of
/// the review records the approval rules are applied to (PUB-010–013).
///
/// Contract: reviews can't be altered after the fact; every review of an address is
/// returned, in recording order.
pub trait ReviewSystem {
    /// Records a review.
    fn record(&self, review: &Review) -> Result<(), ReviewError>;

    /// Every review of `address`, in recording order.
    fn reviews(&self, address: &ContentAddress) -> Result<Vec<Review>, ReviewError>;

    /// The roles `reviewer` holds (PUB-013, INS-083): the artefact kinds they may review
    /// and, for instruments, the languages they review. Empty for an unknown reviewer.
    fn roles(&self, reviewer: &ReviewerId) -> Result<Vec<ReviewerRole>, ReviewError>;
}

/// What a builder produced.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BuildOutput {
    /// The canonical bytes.
    pub canonical_bytes: Vec<u8>,
    /// The builder's attested identity.
    pub builder: BuilderId,
    /// Digest of the pinned build definition.
    pub definition: Digest,
}

/// Errors from [`Builder`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// The source couldn't be canonicalised.
    #[error("build failed: {0}")]
    Failed(String),
}

/// Canonicalises artefacts in an isolated, ephemeral environment (PUB-022, PUB-023).
///
/// Contract: deterministic for the same revision; reports its own identity.
pub trait Builder {
    /// Builds `snapshot`.
    fn build(&self, snapshot: &SourceSnapshot) -> Result<BuildOutput, BuildError>;
}

/// Kind-specific validation and lint (`fieldseal <kind> validate | lint`, PUB-003),
/// injected so that Publishing doesn't depend on what an instrument, layout or policy
/// contains. The secrets check (PUB-004) is Publishing's own and always runs as well.
pub trait ArtefactValidator {
    /// Findings for `artefact`; any blocking finding refuses submission, signing and
    /// verification.
    fn validate(&self, artefact: &Artefact) -> Vec<Diagnostic>;
}

/// The request a transparency-log adapter makes. Lookups carry only sizes and indices,
/// so the only request that can carry data is [`LogRequest::Append`], whose data is the
/// transmission's fields.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogRequest {
    /// Append one entry; the fields are the entry's, in the backend's mapped form.
    Append,
    /// Fetch the latest signed checkpoint.
    Checkpoint,
    /// Fetch an inclusion proof for a leaf against a tree size.
    Inclusion {
        /// The leaf.
        leaf_index: u64,
        /// The tree size.
        tree_size: u64,
    },
    /// Fetch a consistency proof between two tree sizes.
    Consistency {
        /// The earlier size.
        old_size: u64,
        /// The later size.
        new_size: u64,
    },
}

/// Exactly what a transparency-log adapter transmits for one request: the request and a
/// list of named fields. A transport renders it to the wire without adding anything but
/// fixed protocol constants, so contract tests that record transmissions see everything
/// that leaves (ADR 0030, PUB-104).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transmission {
    /// The request.
    pub request: LogRequest,
    /// Field name and value, as sent. Empty for every request but [`LogRequest::Append`].
    pub fields: Vec<(String, Vec<u8>)>,
}

/// Errors from [`LogTransport`] and [`TransparencyLog`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LogError {
    /// The log is unreachable or refused the request.
    #[error("transparency log: {0}")]
    Unavailable(String),
    /// A proof was requested for a size or index the log doesn't have.
    #[error("no such tree size or entry")]
    OutOfRange,
    /// The log's response was malformed or doesn't match the request.
    #[error("malformed response: {0}")]
    Malformed(String),
    /// The log's response was larger than allowed.
    #[error("response too large")]
    Oversized,
}

/// The outbound boundary of a transparency-log adapter (PUB-104). Adapters send every
/// request through it, so a recording transport can prove what they transmit.
pub trait LogTransport {
    /// Sends one transmission and returns the raw response body.
    fn send(&self, transmission: &Transmission) -> Result<Vec<u8>, LogError>;
}

impl<T: LogTransport + ?Sized> LogTransport for &T {
    fn send(&self, transmission: &Transmission) -> Result<Vec<u8>, LogError> {
        (**self).send(transmission)
    }
}

/// An entry once logged.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LoggedEntry {
    /// The entry.
    pub entry: LogEntry,
    /// How the log hashed it into a leaf.
    pub leaf: LeafFormat,
    /// Its inclusion proof.
    pub inclusion: InclusionProof,
    /// The checkpoint the proof is against.
    pub checkpoint: SignedCheckpoint,
}

/// A public, append-only transparency log (ADR 0030, PUB-100–106).
///
/// Contract ([`crate::contract::transparency_log_contract`]): accepts only [`LogEntry`];
/// transmits at most its four fields, in the backend's minimal hash-only form, and nothing
/// else; returns inclusion proofs and C2SP checkpoints that verify offline against the
/// log's pinned key; never rewrites history.
pub trait TransparencyLog {
    /// Appends `entry`.
    fn append(&self, entry: &LogEntry) -> Result<LoggedEntry, LogError>;

    /// The latest signed checkpoint.
    fn checkpoint(&self) -> Result<SignedCheckpoint, LogError>;

    /// An inclusion proof for `leaf_index` against `checkpoint`.
    fn prove_inclusion(&self, leaf_index: u64, checkpoint: &SignedCheckpoint) -> Result<InclusionProof, LogError>;

    /// A consistency proof from `old_size` to `checkpoint`.
    fn prove_consistency(&self, old_size: u64, checkpoint: &SignedCheckpoint) -> Result<ConsistencyProof, LogError>;
}

/// Errors from [`ArtefactRegistry`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// A different publication is already stored at this address.
    #[error("address already holds a different publication")]
    Conflict,
    /// This kind, name and version is already published at another address.
    #[error("version already published")]
    VersionTaken,
    /// The registry failed.
    #[error("artefact registry: {0}")]
    Backend(String),
}

/// Published artefacts by content address (PUB-060–062).
///
/// Contract ([`crate::contract::artefact_registry_contract`]): immutable; an address
/// always returns the same publication; storing the same publication again is a no-op; a
/// version is used once per kind and name; withdrawals are kept.
pub trait ArtefactRegistry {
    /// Stores a publication. Callers MUST verify it first (PUB-060).
    fn put(&self, publication: &Publication) -> Result<(), RegistryError>;

    /// The publication at `address`.
    fn get(&self, address: &ContentAddress) -> Result<Option<Publication>, RegistryError>;

    /// Versions of `kind` named `name`: (version label, address), in storing order.
    fn list(&self, kind: ArtefactKind, name: &str) -> Result<Vec<(String, ContentAddress)>, RegistryError>;

    /// Records a withdrawal. Callers MUST verify it first.
    fn withdraw(&self, withdrawal: &Withdrawal) -> Result<(), RegistryError>;

    /// Every recorded withdrawal.
    fn withdrawals(&self) -> Result<Vec<Withdrawal>, RegistryError>;
}
