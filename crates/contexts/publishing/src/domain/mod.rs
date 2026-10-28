//! Entities, value objects and invariants of the Publishing context
//! (`docs/reference/spec/publishing.md` §2).
//!
//! - [`artefact`]: the `Artefact` aggregate, kinds, names, versions and identities.
//! - [`review`]: reviews and the approval rules.
//! - [`provenance`]: the in-toto / SLSA provenance statement.
//! - [`statement`]: what reaches the public log, fixed by type (ADR 0030).
//! - [`merkle`], [`checkpoint`]: RFC 9162 proofs and C2SP signed checkpoints.
//! - [`publication`]: publications, drafts and withdrawals, and their encodings.
//! - [`verify`]: the checks that make them valid.
//! - [`secrets`]: the PUB-004 secrets check.
//! - [`encoding`]: base64, DER and PEM, exactly as the log formats need them.

pub mod artefact;
pub mod checkpoint;
pub mod encoding;
pub mod error;
pub mod merkle;
pub mod provenance;
pub mod publication;
pub mod review;
pub mod secrets;
pub mod statement;
pub mod verify;

pub use artefact::{Artefact, ArtefactKind, artefact_address, is_valid_name, is_valid_version, new_salt};
pub use checkpoint::{CHECKPOINT_FORMAT, CheckpointBody, CheckpointError, NoteSignature, SignedCheckpoint, TreeHeadTracker, key_hash};
pub use error::{Diagnostic, PublishingError};
pub use merkle::{ConsistencyProof, InclusionProof};
pub use provenance::{BuilderId, ProvenanceStatement, SignedProvenance, SourceRef};
pub use publication::{
    Approval, LogRecord, Publication, PublicationDraft, SignerSignature, Withdrawal, WithdrawalDraft, WithdrawalStatement,
    artefact_signed_structure,
};
pub use review::{
    Review, ReviewDecision, ReviewerRole, ReviewerRoles, RevisionId, RoleRules, SourceSnapshot, counted_approvals, is_pseudonymous,
};
pub use statement::{LeafFormat, LogEntry, LogEntryType, PublicationStatement, hashedrekord_json};
