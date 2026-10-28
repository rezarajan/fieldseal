//! The checks that make a publication or withdrawal valid, as pure functions of the trust
//! store and publishing policy (PUB-010, PUB-023, PUB-032, PUB-033, PUB-040, PUB-041,
//! PUB-054, PUB-080, PUB-103, PUB-106–109). The use cases in
//! [`crate::application`] compose them.

use std::collections::BTreeSet;

use fieldseal_kernel::Value;
use fieldseal_kernel::crypto::{DomainTag, tags};
use fieldseal_kernel::id::KeyId;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::domain::PublishingPolicy;
use fieldseal_trust::domain::TrustStore;

use super::artefact::{Artefact, ArtefactKind};
use super::checkpoint::SignedCheckpoint;
use super::error::PublishingError;
use super::merkle::{leaf_hash, verify_inclusion};
use super::provenance::SignedProvenance;
use super::publication::{LogRecord, SignerSignature};
use super::review::is_pseudonymous;
use super::statement::{LogEntry, PublicationStatement};

/// The code's floor for approvals and signature thresholds: policy can raise them, and a
/// missing or zero value never lowers them below this (PUB §6.3 defaults).
pub const FLOOR: u64 = 2;

/// The thresholds publishing policy sets for one artefact kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KindThresholds {
    /// Approving reviews needed (PUB-010).
    pub approvals: u64,
    /// Publisher signatures needed (PUB-040).
    pub publish: u64,
    /// Publisher signatures needed to withdraw (PUB-080).
    pub withdraw: u64,
}

/// The thresholds for `kind`. A kind the policy doesn't list gets the floor; a value
/// below one counts as one (the Policy context enforces the real floors, POL invariants).
pub fn thresholds(policy: &PublishingPolicy, kind: ArtefactKind) -> KindThresholds {
    match policy.kinds.get(kind.as_str()) {
        Some(k) => KindThresholds {
            approvals: k.required_approvals.max(1),
            publish: k.publisher_threshold.m.max(1),
            withdraw: k.withdrawal_threshold.m.max(1),
        },
        None => KindThresholds { approvals: FLOOR, publish: FLOOR, withdraw: FLOOR },
    }
}

/// Checks that `provenance` describes `artefact` (PUB-030), names only pseudonymous
/// reviewers (PUB-107, PUB-108) and enough of them (PUB-010, PUB-031), is signed by a
/// trusted `builder` key at its build time (PUB-032), and comes from an allowed builder
/// (PUB-023) and source (PUB-033).
pub fn check_provenance(
    store: &TrustStore<'_>,
    policy: &PublishingPolicy,
    provenance: &SignedProvenance,
    artefact: &Artefact,
) -> Result<(), PublishingError> {
    let st = provenance.statement();
    if !st.describes(artefact) || &st.address() != artefact.address() {
        return Err(PublishingError::ProvenanceMismatch);
    }
    store
        .verify_signature(
            provenance.signer(),
            &[],
            &tags::PROVENANCE,
            &st.to_value(),
            provenance.signature(),
            st.finished,
        )
        .map_err(PublishingError::ProvenanceSignature)?;
    if !policy.allowed_builders.iter().any(|b| b == &st.builder.0) {
        return Err(PublishingError::BuilderNotAllowed(st.builder.0.clone()));
    }
    if !policy.allowed_sources.iter().any(|s| s == &st.source.uri) {
        return Err(PublishingError::SourceNotAllowed(st.source.uri.clone()));
    }
    let mut reviewers = BTreeSet::new();
    for r in &st.reviewers {
        if !is_pseudonymous(r) {
            return Err(PublishingError::IdentityAttribute(r.as_str().to_owned()));
        }
        reviewers.insert(r);
    }
    let need = thresholds(policy, artefact.kind()).approvals;
    if (reviewers.len() as u64) < need {
        return Err(PublishingError::NotEnoughApprovals { have: reviewers.len() as u64, need });
    }
    Ok(())
}

/// Checks a set of publisher signatures over `structure` under `tag`, made at `at`, for an
/// artefact of `kind` (PUB-040, PUB-041, PUB-080): every signer distinct, listed in the
/// trust bundle's `publishers` for the kind, certified as a `publisher` at `at` and with a
/// valid signature; and at least `threshold` of them. Any bad signature refuses the whole
/// set: a publication is valid only as a whole.
pub fn check_signatures(
    store: &TrustStore<'_>,
    kind: ArtefactKind,
    tag: &DomainTag,
    structure: &Value,
    signatures: &[SignerSignature],
    at: AuthorityTime,
    threshold: u64,
) -> Result<Vec<KeyId>, PublishingError> {
    let listed: BTreeSet<KeyId> = store.bundle().publishers_for(kind.as_str()).into_iter().map(|c| *c.key_id()).collect();
    let mut seen = BTreeSet::new();
    for s in signatures {
        if !seen.insert(s.signer) {
            return Err(PublishingError::DuplicateSigner(s.signer));
        }
        if !listed.contains(&s.signer) {
            return Err(PublishingError::SignerNotListed { key: s.signer, kind });
        }
        store
            .verify_signature(&s.signer, &[], tag, structure, &s.sig, at)
            .map_err(|error| PublishingError::PublisherSignature { key: s.signer, error })?;
    }
    let have = seen.len() as u64;
    if have < threshold {
        return Err(PublishingError::BelowThreshold { have, need: threshold });
    }
    Ok(seen.into_iter().collect())
}

/// The tree-head age check of PUB-072. C2SP checkpoints carry no time, so the age is the
/// time from the authority time token or receipt that accompanied the checkpoint
/// (`checkpoint_time`, already verified by the caller) to the bundle's time token
/// (`bundle_time`). A tree head with no such token is too old. A token dated after the
/// bundle's counts as age zero.
pub fn check_tree_head_age(
    checkpoint_time: Option<AuthorityTime>,
    bundle_time: AuthorityTime,
    max_age_ms: u64,
) -> Result<(), PublishingError> {
    let Some(at) = checkpoint_time else {
        return Err(PublishingError::TreeHeadTooOld { age_ms: None, max_ms: max_age_ms });
    };
    let age_ms = bundle_time.0.saturating_sub(at.0);
    if age_ms > max_age_ms {
        return Err(PublishingError::TreeHeadTooOld { age_ms: Some(age_ms), max_ms: max_age_ms });
    }
    Ok(())
}

/// Checks one log entry: it is of `statement`'s type, its digest is the statement's
/// (WIRE-191), and its signature is the statement signed by a trusted `publisher` key at
/// `at` whose public key is the entry's (PUB-101).
pub fn check_entry(
    store: &TrustStore<'_>,
    entry: &LogEntry,
    statement: &PublicationStatement,
    at: AuthorityTime,
) -> Result<(), PublishingError> {
    if entry.entry_type() != statement.entry_type() || entry.digest() != &statement.digest() {
        return Err(PublishingError::LogEntryStatement);
    }
    let signer = entry.key_id();
    let cert = store
        .verify_signature(&signer, &[], &tags::PUBLICATION, &statement.to_value(), entry.signature(), at)
        .map_err(|error| PublishingError::PublisherSignature { key: signer, error })?;
    if cert.public_key().as_p256() != Some(entry.public_key()) {
        return Err(PublishingError::LogEntryStatement);
    }
    Ok(())
}

/// Checks the transparency-log evidence for a set of counted signers (PUB-054, PUB-103,
/// PUB-106, PUB-109): the checkpoint is signed by a log pinned in the trust bundle; there is
/// exactly one log record per signer and no other; each entry commits to `statement`
/// ([`check_entry`]); and each inclusion proof reaches the checkpoint's root.
pub fn check_log(
    store: &TrustStore<'_>,
    policy: &PublishingPolicy,
    signers: &[KeyId],
    records: &[LogRecord],
    checkpoint: &SignedCheckpoint,
    statement: &PublicationStatement,
    at: AuthorityTime,
) -> Result<(), PublishingError> {
    checkpoint.verify(&store.bundle().contents().logs, policy.required_witness_cosignatures)?;
    if records.len() != signers.len() {
        return Err(PublishingError::LogEntryMismatch);
    }
    let mut covered = BTreeSet::new();
    for r in records {
        let key = r.entry.key_id();
        if !signers.contains(&key) || !covered.insert(key) {
            return Err(PublishingError::LogEntryMismatch);
        }
        check_entry(store, &r.entry, statement, at)?;
        if r.inclusion.tree_size != checkpoint.size()
            || !verify_inclusion(&leaf_hash(&r.leaf.leaf(&r.entry)), &r.inclusion, checkpoint.root())
        {
            return Err(PublishingError::Inclusion);
        }
    }
    Ok(())
}
