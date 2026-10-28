//! Why a Publishing operation was refused.

use fieldseal_kernel::id::{KeyId, ReviewerId};
use fieldseal_kernel::{ErrorCode, WireError};
use fieldseal_trust::domain::TrustError;

use super::artefact::ArtefactKind;
use super::checkpoint::CheckpointError;

/// One finding from validating an artefact (its kind's validation and lint, PUB-003, or
/// the secrets check, PUB-004).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Diagnostic {
    /// A stable code, for example `PUB-004` or an `INS-…` requirement ID.
    pub code: String,
    /// What was found, without quoting secret material.
    pub message: String,
    /// Whether it blocks publication.
    pub blocking: bool,
}

/// A refusal from the Publishing context. Verification failures map to a WIRE §6.8 code
/// through [`PublishingError::code`] where one applies.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublishingError {
    /// The bytes are not a valid structure.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// The artefact's name, version, salt or identity is invalid.
    #[error("invalid artefact: {0}")]
    InvalidArtefact(&'static str),
    /// The artefact fails its kind's validation or the secrets check (PUB-003, PUB-004).
    #[error("artefact fails validation ({} blocking findings)", .0.iter().filter(|d| d.blocking).count())]
    Validation(Vec<Diagnostic>),

    // --- Key holders (PUB-043) ---------------------------------------------------------
    /// The threshold is met only by counting keys that one person holds.
    #[error("fewer distinct key holders than the publisher threshold")]
    SharedHolder,
    /// A counted key's holder couldn't be resolved in the key-holder registry.
    #[error("a publisher key's holder could not be resolved")]
    HolderUnresolved,

    // --- Review ----------------------------------------------------------------------
    /// Too few approving reviews for this exact address and revision (PUB-010–012).
    #[error("{have} approvals, {need} required")]
    NotEnoughApprovals {
        /// Approvals that count.
        have: u64,
        /// Approvals required by policy.
        need: u64,
    },
    /// An instrument declares a language that no counted reviewer holds the language role
    /// for (INS-083).
    #[error("no approving reviewer for language {0}")]
    MissingLanguageReview(String),
    /// A reviewer rejected this version.
    #[error("rejected by reviewer {0:?}")]
    Rejected(ReviewerId),
    /// A reviewer or other identity is not pseudonymous (PUB-107, PUB-108).
    #[error("identity attribute present: {0:?}")]
    IdentityAttribute(String),

    // --- Provenance --------------------------------------------------------------------
    /// The builder is not in `publishing.allowedBuilders` (PUB-023).
    #[error("builder {0} is not allowed by publishing policy")]
    BuilderNotAllowed(String),
    /// The source repository is not in `publishing.allowedSources` (PUB-033).
    #[error("source {0} is not allowed by publishing policy")]
    SourceNotAllowed(String),
    /// The provenance does not describe this artefact.
    #[error("provenance does not describe this artefact")]
    ProvenanceMismatch,
    /// The provenance signature is not by a trusted `builder` key (PUB-032).
    #[error("provenance signature: {0}")]
    ProvenanceSignature(TrustError),

    // --- Publisher signatures ------------------------------------------------------------
    /// The same key signed twice (PUB-040: distinct keys).
    #[error("key {0:?} signed more than once")]
    DuplicateSigner(KeyId),
    /// The signer is not listed in the trust bundle's `publishers` for this kind (PUB-040).
    #[error("key {key:?} is not a listed publisher for {kind}")]
    SignerNotListed {
        /// The signer.
        key: KeyId,
        /// The artefact kind.
        kind: ArtefactKind,
    },
    /// A publisher signature does not verify, or its key isn't a trusted `publisher` key at
    /// the signing time (PUB-041).
    #[error("publisher signature by {key:?}: {error}")]
    PublisherSignature {
        /// The signer.
        key: KeyId,
        /// Why.
        error: TrustError,
    },
    /// Fewer valid signatures than the threshold (PUB-040, PUB-080).
    #[error("{have} publisher signatures, {need} required")]
    BelowThreshold {
        /// Valid signatures.
        have: u64,
        /// Required by policy.
        need: u64,
    },

    // --- Transparency log ------------------------------------------------------------------
    /// A counted signature has no log entry, or a log entry matches no signature (PUB-103).
    #[error("log entries do not match the signatures one to one")]
    LogEntryMismatch,
    /// A log entry's digest or type is not that of this publication's statement.
    #[error("log entry does not commit to this publication")]
    LogEntryStatement,
    /// The checkpoint is malformed, not from a pinned log, or not signed by its key
    /// (PUB-106, PUB-109, TRU-093).
    #[error("checkpoint: {0}")]
    Checkpoint(CheckpointError),
    /// An inclusion proof does not verify against the checkpoint (PUB-054).
    #[error("inclusion proof does not verify")]
    Inclusion,

    // --- Tree-head age (PUB-072) -------------------------------------------------------------
    /// The tree head is older than `runtime.publishing.maxTreeHeadAge`, or carries no time
    /// token to measure its age from and is treated as too old (PUB-072).
    #[error("tree head too old ({})", match .age_ms { Some(a) => format!("{a} ms against a limit of {} ms", .max_ms), None => "no time token".to_owned() })]
    TreeHeadTooOld {
        /// The age in milliseconds, or `None` when no time token accompanied the checkpoint.
        age_ms: Option<u64>,
        /// The limit in milliseconds.
        max_ms: u64,
    },
    /// The time token that accompanied the checkpoint is malformed or not authentic.
    #[error("checkpoint time token: {0}")]
    CheckpointTime(String),

    // --- Withdrawal ------------------------------------------------------------------------
    /// The artefact has been withdrawn (PUB-070, PUB-080).
    #[error("withdrawn")]
    Withdrawn,
    /// A withdrawal is for another artefact.
    #[error("withdrawal is for another artefact")]
    WithdrawalMismatch,

    // --- Ports ---------------------------------------------------------------------------------
    /// Key custody refused or failed.
    #[error("key custody: {0}")]
    Custody(String),
    /// The transparency log failed.
    #[error("transparency log: {0}")]
    Log(String),
    /// The registry refused or failed.
    #[error("registry: {0}")]
    Registry(String),
    /// The review system failed.
    #[error("review system: {0}")]
    Review(String),
}

impl PublishingError {
    /// The WIRE §6.8 code for this failure, where it is a wire-level one: decoding keeps
    /// its own code; every untrusted or invalid signature (publisher, builder, log) is
    /// `E_SIG`; a log entry or proof that doesn't match its content is `E_HASH`.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Wire(e) => Some(e.code),
            // A name, version or salt the structure doesn't allow (PUB-001, PUB-090).
            Self::InvalidArtefact(_) => Some(ErrorCode::UnknownField),
            Self::ProvenanceSignature(e) | Self::PublisherSignature { error: e, .. } => {
                Some(e.code().unwrap_or(ErrorCode::Sig))
            }
            Self::SignerNotListed { .. } | Self::DuplicateSigner(_) => Some(ErrorCode::Sig),
            Self::Checkpoint(CheckpointError::Malformed(_)) => Some(ErrorCode::UnknownField),
            Self::Checkpoint(_) => Some(ErrorCode::Sig),
            Self::Inclusion | Self::LogEntryStatement | Self::ProvenanceMismatch => Some(ErrorCode::Hash),
            _ => None,
        }
    }
}

impl From<CheckpointError> for PublishingError {
    fn from(e: CheckpointError) -> Self {
        Self::Checkpoint(e)
    }
}
