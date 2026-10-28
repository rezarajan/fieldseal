//! Use cases offered by the Publishing context (PUB §3), shaped for the `fieldseal
//! artefact …`, `fieldseal log prove` and `fieldseal <kind> hash` commands:
//!
//! | Command | Use case |
//! |---|---|
//! | `instrument hash` (and other kinds) | [`hash_artefact`] |
//! | `<kind> validate` before review | [`SubmitForReview`] |
//! | review recording | [`RecordReview`] |
//! | `artefact provenance` | [`BuildProvenance`] |
//! | `artefact verify` (draft or publication) | [`VerifyPublication`] |
//! | `artefact sign` | [`SignPublication`] |
//! | `artefact publish` | [`Publish`] (refuses anything `verify` would, CLI-012) |
//! | `artefact withdraw` | [`SignWithdrawal`], [`Withdraw`] |
//! | `log prove` | [`ProveInclusion`] |
//!
//! Every use case is pure apart from the ports it is given: time and randomness come in
//! as values or through ports, never from the environment.

use fieldseal_kernel::crypto::{P256PublicKey, Purpose, Signature, tags, DomainTag};
use fieldseal_kernel::id::{ContentAddress, Digest, KeyId, ReviewerId, Salt};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::Value;
use fieldseal_policy::domain::PublishingPolicy;
use fieldseal_trust::domain::{AccessContext, KeyRole, TrustStore};
use fieldseal_trust::ports::{KeyCustody, KeyHolderRegistry};

use crate::domain::secrets::find_secrets;
use crate::domain::verify::{check_entry, check_log, check_provenance, check_signatures, thresholds};
use crate::domain::{
    Approval, Artefact, ArtefactKind, BuilderId, Diagnostic, LogEntry, LogRecord, ProvenanceStatement, Publication,
    PublicationDraft, PublishingError, Review, ReviewerRoles, RevisionId, RoleRules, SignedCheckpoint, SignedProvenance, SignerSignature,
    SourceRef, TreeHeadTracker, Withdrawal, WithdrawalDraft, artefact_address, counted_approvals, is_pseudonymous,
};
use crate::ports::{ArtefactRegistry, ArtefactValidator, ReviewSystem, TransparencyLog};

/// `fieldseal instrument hash` and its equivalents (PUB-022): the identity of canonical
/// bytes, computed locally exactly as the registry computes it.
pub fn hash_artefact(kind: ArtefactKind, canonical: &[u8], salt: Option<&Salt>) -> Result<ContentAddress, PublishingError> {
    artefact_address(kind, canonical, salt)
}

/// Runs the secrets check (PUB-004) and the kind's validation (PUB-003). Returns the
/// non-blocking findings, or every finding if any blocks.
pub fn validate(artefact: &Artefact, validator: Option<&dyn ArtefactValidator>) -> Result<Vec<Diagnostic>, PublishingError> {
    let mut findings = find_secrets(artefact.canonical_bytes());
    if let Some(v) = validator {
        findings.extend(v.validate(artefact));
    }
    if findings.iter().any(|d| d.blocking) { Err(PublishingError::Validation(findings)) } else { Ok(findings) }
}

/// A request for review of one artefact version at one revision.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReviewRequest {
    /// The artefact's identity; approvals are tied to it (PUB-011).
    pub address: ContentAddress,
    /// The kind.
    pub kind: ArtefactKind,
    /// The name, as a label.
    pub name: String,
    /// The version, as a label.
    pub version: String,
    /// The revision to review.
    pub revision: RevisionId,
    /// Non-blocking findings.
    pub warnings: Vec<Diagnostic>,
}

/// `SubmitForReview` (PUB §3): an artefact must pass validation and the secrets check
/// before it is submitted (PUB-003, PUB-004).
pub struct SubmitForReview<'a> {
    validator: &'a dyn ArtefactValidator,
}

impl<'a> SubmitForReview<'a> {
    /// Submits with `validator` as the kind's validation.
    pub fn new(validator: &'a dyn ArtefactValidator) -> Self {
        Self { validator }
    }

    /// Validates `artefact` and produces the review request for `revision`.
    pub fn submit(&self, artefact: &Artefact, revision: RevisionId) -> Result<ReviewRequest, PublishingError> {
        let warnings = validate(artefact, Some(self.validator))?;
        Ok(ReviewRequest {
            address: *artefact.address(),
            kind: artefact.kind(),
            name: artefact.name().to_owned(),
            version: artefact.version().to_owned(),
            revision,
            warnings,
        })
    }
}

/// `RecordReview` (PUB §3): records a reviewer's decision, refusing a reviewer identity
/// that is not pseudonymous (PUB-107).
pub struct RecordReview<'a> {
    reviews: &'a dyn ReviewSystem,
}

impl<'a> RecordReview<'a> {
    /// Records into `reviews`.
    pub fn new(reviews: &'a dyn ReviewSystem) -> Self {
        Self { reviews }
    }

    /// Records `review`.
    pub fn record(&self, review: &Review) -> Result<(), PublishingError> {
        if !is_pseudonymous(&review.reviewer) {
            return Err(PublishingError::IdentityAttribute(review.reviewer.as_str().to_owned()));
        }
        self.reviews.record(review).map_err(|e| PublishingError::Review(e.to_string()))
    }
}

/// What CI knows about one build.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BuildInput {
    /// The artefact built (for an instrument, with its salt, PUB-090).
    pub artefact: Artefact,
    /// The source repository and revision.
    pub source: SourceRef,
    /// The revision's author, pseudonymously (PUB-012).
    pub author: ReviewerId,
    /// The builder's identity.
    pub builder: BuilderId,
    /// Digest of the pinned build definition.
    pub definition: Digest,
    /// When the build finished, from the authority clock.
    pub finished: AuthorityTime,
    /// For an instrument, every language whose translation it declares (INS-083): the
    /// review must include an approving reviewer holding the role for each. The default
    /// language is the source text that every reviewer of the kind reads, so callers leave
    /// it out. Empty for other kinds and single-language instruments.
    pub languages: Vec<String>,
}

/// `BuildArtefact`'s provenance step (`fieldseal artefact provenance`, PUB-030–033):
/// checks the approvals for the exact address and revision, the builder and the source
/// against publishing policy, and signs the provenance with the `builder` key.
pub struct BuildProvenance<'a> {
    custody: &'a dyn KeyCustody,
    reviews: &'a dyn ReviewSystem,
    policy: &'a PublishingPolicy,
    builder_key: KeyId,
    caller: &'a str,
}

impl<'a> BuildProvenance<'a> {
    /// Builds provenance signed by `builder_key` (held in `custody` for purpose `builder`).
    pub fn new(
        custody: &'a dyn KeyCustody,
        reviews: &'a dyn ReviewSystem,
        policy: &'a PublishingPolicy,
        builder_key: KeyId,
        caller: &'a str,
    ) -> Self {
        Self { custody, reviews, policy, builder_key, caller }
    }

    /// Produces the draft publication: the artefact and its signed provenance.
    pub fn build(&self, input: BuildInput) -> Result<PublicationDraft, PublishingError> {
        let BuildInput { artefact, source, author, builder, definition, finished, languages } = input;
        if !self.policy.allowed_builders.iter().any(|b| b == &builder.0) {
            return Err(PublishingError::BuilderNotAllowed(builder.0));
        }
        if !self.policy.allowed_sources.iter().any(|s| s == &source.uri) {
            return Err(PublishingError::SourceNotAllowed(source.uri));
        }
        let reviews = self.reviews.reviews(artefact.address()).map_err(|e| PublishingError::Review(e.to_string()))?;
        let mut roles = ReviewerRoles::new();
        for r in &reviews {
            if !roles.contains_key(&r.reviewer) {
                let held = self.reviews.roles(&r.reviewer).map_err(|e| PublishingError::Review(e.to_string()))?;
                roles.insert(r.reviewer.clone(), held);
            }
        }
        let reviewers = counted_approvals(
            &reviews,
            artefact.address(),
            &source.revision,
            &author,
            self.policy.author_may_approve,
            thresholds(self.policy, artefact.kind()).approvals,
            RoleRules { kind: artefact.kind(), roles: &roles, languages: &languages },
        )?;
        let statement = ProvenanceStatement::for_artefact(&artefact, source, reviewers, definition, builder, finished);
        let sig = self
            .custody
            .sign(&self.builder_key, KeyRole::Purpose(Purpose::Builder), &tags::PROVENANCE, &statement.to_value(), self.caller)
            .map_err(|e| PublishingError::Custody(e.to_string()))?;
        Ok(PublicationDraft::new(artefact, SignedProvenance::new(statement, self.builder_key, sig)))
    }
}

/// How much of the provenance a verifier checks (PUB-073).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProvenanceCheck {
    /// Everything: builder signature, allowed builder and source, reviewers. Required of
    /// the factory, intake and publishing (PUB-073).
    Full,
    /// Only that the provenance describes the artefact; a runtime MAY skip the rest.
    DescribesOnly,
}

/// What a verified publication established.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VerifiedPublication {
    /// The artefact's identity.
    pub address: ContentAddress,
    /// The kind.
    pub kind: ArtefactKind,
    /// The publisher keys counted toward the threshold.
    pub signers: Vec<KeyId>,
    /// Non-blocking validation findings.
    pub warnings: Vec<Diagnostic>,
}

/// The state of a draft (`fieldseal artefact verify` before publishing).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DraftStatus {
    /// Valid publisher approvals so far.
    pub signatures: u64,
    /// The threshold for the kind.
    pub threshold: u64,
    /// Non-blocking validation findings.
    pub warnings: Vec<Diagnostic>,
}

impl DraftStatus {
    /// Whether the threshold is met.
    pub fn complete(&self) -> bool {
        self.signatures >= self.threshold
    }
}

/// `VerifyPublication` (PUB §3, PUB-060, PUB-070–073): what a factory, runtime, intake or
/// operator runs before relying on an artefact. Checks, in order: validation and the
/// secrets check; provenance; the publisher threshold signatures against the trust
/// bundle's publishers for the kind; one log entry per signature, each committing to the
/// publication statement and included under a checkpoint signed by a pinned log; and that
/// no valid withdrawal names the artefact.
///
/// Certificates are checked at the provenance's build time (publisher signatures) or the
/// withdrawal's issue time, so a key that rotates later doesn't invalidate what it signed
/// while valid (TRU-015), and a key revoked with effect before then is refused (TRU-042).
pub struct VerifyPublication<'a> {
    store: TrustStore<'a>,
    policy: &'a PublishingPolicy,
    validator: Option<&'a dyn ArtefactValidator>,
    provenance: ProvenanceCheck,
    holders: Option<(&'a dyn KeyHolderRegistry, &'a AccessContext)>,
}

impl<'a> VerifyPublication<'a> {
    /// A full verifier against `store` (the trust bundle and any later revocations) and
    /// the current publishing policy.
    pub fn new(store: TrustStore<'a>, policy: &'a PublishingPolicy) -> Self {
        Self { store, policy, validator: None, provenance: ProvenanceCheck::Full, holders: None }
    }

    /// Also runs the kind's validation.
    pub fn with_validator(mut self, validator: &'a dyn ArtefactValidator) -> Self {
        self.validator = Some(validator);
        self
    }

    /// Also requires the publisher threshold to be met by distinct people, read from the
    /// authority's private key-holder registry (PUB-043, TRU-094). Devices have no registry
    /// and leave this unset.
    pub fn with_key_holders(mut self, registry: &'a dyn KeyHolderRegistry, ctx: &'a AccessContext) -> Self {
        self.holders = Some((registry, ctx));
        self
    }

    /// Sets how much provenance to check.
    pub fn with_provenance_check(mut self, check: ProvenanceCheck) -> Self {
        self.provenance = check;
        self
    }

    /// The trust store.
    pub fn store(&self) -> &TrustStore<'a> {
        &self.store
    }

    /// The publishing policy.
    pub fn policy(&self) -> &PublishingPolicy {
        self.policy
    }

    fn artefact_and_provenance(&self, artefact: &Artefact, provenance: &SignedProvenance) -> Result<Vec<Diagnostic>, PublishingError> {
        let warnings = validate(artefact, self.validator)?;
        match self.provenance {
            ProvenanceCheck::Full => check_provenance(&self.store, self.policy, provenance, artefact)?,
            ProvenanceCheck::DescribesOnly => {
                if !provenance.statement().describes(artefact) {
                    return Err(PublishingError::ProvenanceMismatch);
                }
            }
        }
        Ok(warnings)
    }

    fn approvals(
        &self,
        kind: ArtefactKind,
        tag: &DomainTag,
        structure: &Value,
        statement: &crate::domain::PublicationStatement,
        approvals: &[Approval],
        at: AuthorityTime,
    ) -> Result<u64, PublishingError> {
        let sigs: Vec<SignerSignature> = approvals.iter().map(|a| a.signature.clone()).collect();
        check_signatures(&self.store, kind, tag, structure, &sigs, at, 0)?;
        for a in approvals {
            if a.entry.key_id() != a.signature.signer {
                return Err(PublishingError::LogEntryMismatch);
            }
            check_entry(&self.store, &a.entry, statement, at)?;
        }
        Ok(approvals.len() as u64)
    }

    /// Verifies a draft: everything but the log (PUB-042: what `artefact sign` checks
    /// before signing, and `artefact verify` reports as "signatures so far").
    pub fn verify_draft(&self, draft: &PublicationDraft) -> Result<DraftStatus, PublishingError> {
        let warnings = self.artefact_and_provenance(&draft.artefact, &draft.provenance)?;
        let at = draft.provenance.statement().finished;
        let kind = draft.artefact.kind();
        let signatures = self.approvals(kind, &tags::ARTEFACT, &draft.signed_structure(), &draft.statement(), &draft.approvals, at)?;
        Ok(DraftStatus { signatures, threshold: thresholds(self.policy, kind).publish, warnings })
    }

    /// Verifies a publication (PUB-060, PUB-070, PUB-071), and that none of `withdrawals`
    /// validly withdraws it. Withdrawals that don't verify are ignored, so a forged one
    /// can't deny service.
    pub fn verify(&self, publication: &Publication, withdrawals: &[Withdrawal]) -> Result<VerifiedPublication, PublishingError> {
        let warnings = self.artefact_and_provenance(&publication.artefact, &publication.provenance)?;
        let kind = publication.artefact.kind();
        let at = publication.provenance.statement().finished;
        let signers = check_signatures(
            &self.store,
            kind,
            &tags::ARTEFACT,
            &publication.signed_structure(),
            &publication.signatures,
            at,
            thresholds(self.policy, kind).publish,
        )?;
        check_distinct_holders(&signers, thresholds(self.policy, kind).publish, self.holders, at)?;
        check_log(&self.store, self.policy, &signers, &publication.log, &publication.checkpoint, &publication.statement(), at)?;
        if withdrawals.iter().any(|w| w.address() == publication.address() && self.verify_withdrawal(w, publication).is_ok()) {
            return Err(PublishingError::Withdrawn);
        }
        Ok(VerifiedPublication { address: *publication.address(), kind, signers, warnings })
    }

    /// Verifies that `withdrawal` validly withdraws `publication` (PUB-080): it names the
    /// publication's address and provenance, carries the withdrawal threshold of publisher
    /// signatures for the kind over `fieldseal.dev/withdrawal/v1`, and is logged.
    pub fn verify_withdrawal(&self, withdrawal: &Withdrawal, publication: &Publication) -> Result<(), PublishingError> {
        let st = &withdrawal.statement;
        if &st.address != publication.address() || st.provenance_sha256 != publication.provenance.digest() {
            return Err(PublishingError::WithdrawalMismatch);
        }
        let kind = publication.artefact.kind();
        let signers = check_signatures(
            &self.store,
            kind,
            &tags::WITHDRAWAL,
            &st.signed_structure(),
            &withdrawal.signatures,
            st.issued,
            thresholds(self.policy, kind).withdraw,
        )?;
        check_log(&self.store, self.policy, &signers, &withdrawal.log, &withdrawal.checkpoint, &st.log_statement(), st.issued)
    }

    /// Verifies a withdrawal draft against `publication`; returns valid approvals so far
    /// and the threshold.
    pub fn verify_withdrawal_draft(&self, draft: &WithdrawalDraft, publication: &Publication) -> Result<DraftStatus, PublishingError> {
        let st = &draft.statement;
        if &st.address != publication.address() || st.provenance_sha256 != publication.provenance.digest() {
            return Err(PublishingError::WithdrawalMismatch);
        }
        let kind = publication.artefact.kind();
        let signatures =
            self.approvals(kind, &tags::WITHDRAWAL, &st.signed_structure(), &st.log_statement(), &draft.approvals, st.issued)?;
        Ok(DraftStatus { signatures, threshold: thresholds(self.policy, kind).withdraw, warnings: Vec::new() })
    }
}

fn publisher_key(custody: &dyn KeyCustody, key: &KeyId) -> Result<P256PublicKey, PublishingError> {
    let k = custody.public_key(key).map_err(|e| PublishingError::Custody(e.to_string()))?;
    k.public_key.as_p256().cloned().ok_or(PublishingError::Custody("a publisher key is P-256".into()))
}

fn sign_as_publisher(
    custody: &dyn KeyCustody,
    key: &KeyId,
    tag: &DomainTag,
    structure: &Value,
    caller: &str,
) -> Result<Signature, PublishingError> {
    custody
        .sign(key, KeyRole::Purpose(Purpose::Publisher), tag, structure, caller)
        .map_err(|e| PublishingError::Custody(e.to_string()))
}

fn check_may_sign(verifier: &VerifyPublication<'_>, kind: ArtefactKind, key: &KeyId, approvals: &[Approval]) -> Result<(), PublishingError> {
    if !verifier.store().bundle().publishers_for(kind.as_str()).iter().any(|c| c.key_id() == key) {
        return Err(PublishingError::SignerNotListed { key: *key, kind });
    }
    if approvals.iter().any(|a| &a.signature.signer == key) {
        return Err(PublishingError::DuplicateSigner(*key));
    }
    Ok(())
}

/// `SignArtefact` (`fieldseal artefact sign`, PUB-041, PUB-042, PUB-101): one publisher
/// approves a draft. Refuses unless the draft's validation, provenance and reviews pass,
/// and the key is a listed publisher for the kind that hasn't signed yet. The publisher
/// signs twice through key custody: the artefact structure (PUB-041) and the log statement
/// (PUB-101).
pub struct SignPublication<'a> {
    custody: &'a dyn KeyCustody,
    verifier: &'a VerifyPublication<'a>,
    caller: &'a str,
}

impl<'a> SignPublication<'a> {
    /// Signs through `custody`, checking with `verifier`.
    pub fn new(custody: &'a dyn KeyCustody, verifier: &'a VerifyPublication<'a>, caller: &'a str) -> Self {
        Self { custody, verifier, caller }
    }

    /// The draft with `key`'s approval added.
    pub fn sign(&self, draft: &PublicationDraft, key: &KeyId) -> Result<PublicationDraft, PublishingError> {
        self.verifier.verify_draft(draft)?;
        check_may_sign(self.verifier, draft.artefact.kind(), key, &draft.approvals)?;
        let public_key = publisher_key(self.custody, key)?;
        let sig = sign_as_publisher(self.custody, key, &tags::ARTEFACT, &draft.signed_structure(), self.caller)?;
        let statement = draft.statement();
        let entry_sig = sign_as_publisher(self.custody, key, &tags::PUBLICATION, &statement.to_value(), self.caller)?;
        let mut out = draft.clone();
        out.approvals.push(Approval {
            signature: SignerSignature { signer: *key, sig },
            entry: LogEntry::for_statement(&statement, entry_sig, public_key),
        });
        Ok(out)
    }
}

fn log_all(log: &dyn TransparencyLog, approvals: &[Approval]) -> Result<(Vec<LogRecord>, SignedCheckpoint), PublishingError> {
    let err = |e: crate::ports::LogError| PublishingError::Log(e.to_string());
    let logged = approvals.iter().map(|a| log.append(&a.entry).map_err(err)).collect::<Result<Vec<_>, _>>()?;
    let checkpoint = log.checkpoint().map_err(err)?;
    let mut records = Vec::with_capacity(logged.len());
    for l in logged {
        let inclusion = if l.checkpoint == checkpoint {
            l.inclusion
        } else {
            log.prove_inclusion(l.inclusion.leaf_index, &checkpoint).map_err(err)?
        };
        records.push(LogRecord { entry: l.entry, leaf: l.leaf, inclusion });
    }
    Ok((records, checkpoint))
}

/// `PublishArtefact` (`fieldseal artefact publish`, PUB-050, PUB-060, CLI-012): logs
/// one entry per publisher approval, proves them all against one checkpoint, verifies the
/// result exactly as [`VerifyPublication::verify`] does, and only then stores it in the
/// registry. A draft below threshold or failing any check is refused before anything is
/// logged.
pub struct Publish<'a> {
    log: &'a dyn TransparencyLog,
    registry: &'a dyn ArtefactRegistry,
    verifier: &'a VerifyPublication<'a>,
    checkpoint_time: Option<Vec<u8>>,
}

impl<'a> Publish<'a> {
    /// Publishes through `log` into `registry`, checking with `verifier`.
    pub fn new(log: &'a dyn TransparencyLog, registry: &'a dyn ArtefactRegistry, verifier: &'a VerifyPublication<'a>) -> Self {
        Self { log, registry, verifier, checkpoint_time: None }
    }

    /// Attaches the authority time token (encoded) obtained with the log's checkpoint, so
    /// that consumers can measure the tree head's age (PUB-061, PUB-072). Without it a
    /// runtime treats the tree head as too old.
    pub fn with_checkpoint_time(mut self, token: Vec<u8>) -> Self {
        self.checkpoint_time = Some(token);
        self
    }

    /// Publishes `draft`. `withdrawals` are those known to the publisher, so a withdrawn
    /// artefact is not republished.
    pub fn publish(&self, draft: &PublicationDraft, withdrawals: &[Withdrawal]) -> Result<Publication, PublishingError> {
        let status = self.verifier.verify_draft(draft)?;
        if !status.complete() {
            return Err(PublishingError::BelowThreshold { have: status.signatures, need: status.threshold });
        }
        let (log, checkpoint) = log_all(self.log, &draft.approvals)?;
        let publication = Publication {
            artefact: draft.artefact.clone(),
            provenance: draft.provenance.clone(),
            signatures: draft.approvals.iter().map(|a| a.signature.clone()).collect(),
            log,
            checkpoint,
            checkpoint_time: self.checkpoint_time.clone(),
        };
        self.verifier.verify(&publication, withdrawals)?;
        self.registry.put(&publication).map_err(|e| PublishingError::Registry(e.to_string()))?;
        Ok(publication)
    }
}

/// `WithdrawArtefact`, one publisher's step (`fieldseal artefact withdraw`, PUB-080):
/// signs the withdrawal statement under `fieldseal.dev/withdrawal/v1` and its log
/// statement under `fieldseal.dev/publication/v1`.
pub struct SignWithdrawal<'a> {
    custody: &'a dyn KeyCustody,
    verifier: &'a VerifyPublication<'a>,
    caller: &'a str,
}

impl<'a> SignWithdrawal<'a> {
    /// Signs through `custody`, checking with `verifier`.
    pub fn new(custody: &'a dyn KeyCustody, verifier: &'a VerifyPublication<'a>, caller: &'a str) -> Self {
        Self { custody, verifier, caller }
    }

    /// The draft with `key`'s approval added. `publication` is the artefact withdrawn.
    pub fn sign(&self, draft: &WithdrawalDraft, publication: &Publication, key: &KeyId) -> Result<WithdrawalDraft, PublishingError> {
        self.verifier.verify_withdrawal_draft(draft, publication)?;
        check_may_sign(self.verifier, publication.artefact.kind(), key, &draft.approvals)?;
        let public_key = publisher_key(self.custody, key)?;
        let sig = sign_as_publisher(self.custody, key, &tags::WITHDRAWAL, &draft.statement.signed_structure(), self.caller)?;
        let statement = draft.statement.log_statement();
        let entry_sig = sign_as_publisher(self.custody, key, &tags::PUBLICATION, &statement.to_value(), self.caller)?;
        let mut out = draft.clone();
        out.approvals.push(Approval {
            signature: SignerSignature { signer: *key, sig },
            entry: LogEntry::for_statement(&statement, entry_sig, public_key),
        });
        Ok(out)
    }
}

/// `WithdrawArtefact`, the final step (PUB-050, PUB-080): logs the approvals, verifies the
/// withdrawal and records it in the registry.
pub struct Withdraw<'a> {
    log: &'a dyn TransparencyLog,
    registry: &'a dyn ArtefactRegistry,
    verifier: &'a VerifyPublication<'a>,
}

impl<'a> Withdraw<'a> {
    /// Withdraws through `log` into `registry`, checking with `verifier`.
    pub fn new(log: &'a dyn TransparencyLog, registry: &'a dyn ArtefactRegistry, verifier: &'a VerifyPublication<'a>) -> Self {
        Self { log, registry, verifier }
    }

    /// Withdraws `publication` with the approvals in `draft`.
    pub fn withdraw(&self, draft: &WithdrawalDraft, publication: &Publication) -> Result<Withdrawal, PublishingError> {
        let status = self.verifier.verify_withdrawal_draft(draft, publication)?;
        if !status.complete() {
            return Err(PublishingError::BelowThreshold { have: status.signatures, need: status.threshold });
        }
        let (log, checkpoint) = log_all(self.log, &draft.approvals)?;
        let withdrawal = Withdrawal {
            statement: draft.statement.clone(),
            signatures: draft.approvals.iter().map(|a| a.signature.clone()).collect(),
            log,
            checkpoint,
        };
        self.verifier.verify_withdrawal(&withdrawal, publication)?;
        self.registry.withdraw(&withdrawal).map_err(|e| PublishingError::Registry(e.to_string()))?;
        Ok(withdrawal)
    }
}

/// `fieldseal log prove` (PUB-054, PUB-055): re-proves a publication's log entries against
/// the log's latest checkpoint, after checking that checkpoint is signed by the pinned log
/// and consistent with the one the publication carries. Returns the publication with the
/// fresh proofs and checkpoint, verified.
pub struct ProveInclusion<'a> {
    log: &'a dyn TransparencyLog,
    verifier: &'a VerifyPublication<'a>,
    checkpoint_time: Option<Vec<u8>>,
}

impl<'a> ProveInclusion<'a> {
    /// Proves against `log`, checking with `verifier`.
    pub fn new(log: &'a dyn TransparencyLog, verifier: &'a VerifyPublication<'a>) -> Self {
        Self { log, verifier, checkpoint_time: None }
    }

    /// Attaches the authority time token (encoded) obtained with the fresh checkpoint
    /// (PUB-072). The old token belonged to the old checkpoint and is dropped either way.
    pub fn with_checkpoint_time(mut self, token: Vec<u8>) -> Self {
        self.checkpoint_time = Some(token);
        self
    }

    /// The publication with proofs against the latest checkpoint.
    pub fn prove(&self, publication: &Publication) -> Result<Publication, PublishingError> {
        let err = |e: crate::ports::LogError| PublishingError::Log(e.to_string());
        let pins = &self.verifier.store().bundle().contents().logs;
        let witnesses = self.verifier.policy().required_witness_cosignatures;
        publication.checkpoint.verify(pins, witnesses)?;
        let latest = self.log.checkpoint().map_err(err)?;
        latest.verify(pins, witnesses)?;
        let consistency = self.log.prove_consistency(publication.checkpoint.size(), &latest).map_err(err)?;
        TreeHeadTracker::new(&publication.checkpoint).advance(&latest, &consistency)?;
        let mut out = publication.clone();
        for r in &mut out.log {
            r.inclusion = self.log.prove_inclusion(r.inclusion.leaf_index, &latest).map_err(err)?;
        }
        out.checkpoint = latest;
        out.checkpoint_time = self.checkpoint_time.clone();
        self.verifier.verify(&out, &[])?;
        Ok(out)
    }
}

/// Checks that the keys counted toward `threshold` belong to at least `threshold` distinct
/// people (PUB-043). With no registry it passes, because devices can't see the private
/// mapping. A key whose holder can't be resolved fails closed with
/// [`PublishingError::HolderUnresolved`]. Call it after the signatures themselves verify.
pub fn check_distinct_holders(
    signers: &[KeyId],
    threshold: u64,
    registry: Option<(&dyn KeyHolderRegistry, &AccessContext)>,
    at: AuthorityTime,
) -> Result<(), PublishingError> {
    let Some((registry, ctx)) = registry else {
        return Ok(());
    };
    let mut holders = std::collections::BTreeSet::new();
    for key in signers {
        let holder = registry.key_holder(key, at, ctx).map_err(|_| PublishingError::HolderUnresolved)?;
        holders.insert(holder.0);
    }
    if (holders.len() as u64) < threshold {
        return Err(PublishingError::SharedHolder);
    }
    Ok(())
}
