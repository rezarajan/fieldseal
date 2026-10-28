//! In-memory adapters for the Publishing context's driven ports.
//!
//! [`MemoryTransparencyLog`] is a real RFC 9162 Merkle log (SHA-256, through the
//! Publishing domain's tree functions) whose checkpoints are C2SP signed notes made with a
//! real P-256 key, so its proofs verify exactly as a public log's do. It sends every request
//! through its [`LogTransport`] as a real adapter would, so the ADR 0030 contract applies
//! to it unchanged. Its key is derived from its origin unless one is given: a test or
//! simulator log, never a public one.

use std::collections::BTreeMap;
use std::sync::Mutex;

use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{ContentAddress, Digest, ReviewerId};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_publishing::domain::merkle::{audit_path, consistency_path, leaf_hash, root};
use fieldseal_publishing::domain::{
    Artefact, ArtefactKind, BuilderId, CHECKPOINT_FORMAT, CheckpointBody, ConsistencyProof, Diagnostic, InclusionProof,
    LeafFormat, LogEntry, Publication, Review, ReviewerRole, RevisionId, SignedCheckpoint, SourceSnapshot, Withdrawal,
};
use fieldseal_publishing::ports::{
    ArtefactRegistry, ArtefactValidator, BuildError, BuildOutput, Builder, LogError, LogRequest, LogTransport,
    LoggedEntry, RegistryError, ReviewError, ReviewSystem, SourceError, SourceRepository, Transmission, TransparencyLog,
};
use fieldseal_trust::domain::LogPin;

/// An in-memory [`SourceRepository`].
#[derive(Default)]
pub struct MemorySourceRepository {
    revisions: Mutex<BTreeMap<RevisionId, SourceSnapshot>>,
}

impl MemorySourceRepository {
    /// An empty repository.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a snapshot; revisions are immutable, so an existing revision is kept.
    pub fn add(&self, snapshot: SourceSnapshot) {
        self.revisions.lock().expect("lock").entry(snapshot.revision.clone()).or_insert(snapshot);
    }
}

impl SourceRepository for MemorySourceRepository {
    fn fetch(&self, revision: &RevisionId) -> Result<SourceSnapshot, SourceError> {
        self.revisions.lock().expect("lock").get(revision).cloned().ok_or(SourceError::NotFound)
    }
}

/// An in-memory, append-only [`ReviewSystem`].
#[derive(Default)]
pub struct MemoryReviewSystem {
    reviews: Mutex<Vec<Review>>,
    roles: Mutex<BTreeMap<ReviewerId, Vec<ReviewerRole>>>,
}

impl MemoryReviewSystem {
    /// No reviews yet, and no reviewer holds a role.
    pub fn new() -> Self {
        Self::default()
    }

    /// Grants `reviewer` a role (PUB-013, INS-083). Roles are kept apart from reviews; a
    /// real review system takes them from its own access control.
    pub fn grant(&self, reviewer: &ReviewerId, role: ReviewerRole) {
        let mut roles = self.roles.lock().expect("lock");
        let held = roles.entry(reviewer.clone()).or_default();
        if !held.contains(&role) {
            held.push(role);
        }
    }

    /// Grants `reviewer` the reviewer role for `kind`.
    pub fn grant_kind(&self, reviewer: &ReviewerId, kind: ArtefactKind) {
        self.grant(reviewer, ReviewerRole::of_kind(kind));
    }
}

impl ReviewSystem for MemoryReviewSystem {
    fn record(&self, review: &Review) -> Result<(), ReviewError> {
        let mut reviews = self.reviews.lock().expect("lock");
        if reviews
            .iter()
            .any(|r| r.address == review.address && r.revision == review.revision && r.reviewer == review.reviewer)
        {
            return Err(ReviewError::AlreadyRecorded);
        }
        reviews.push(review.clone());
        Ok(())
    }

    fn reviews(&self, address: &ContentAddress) -> Result<Vec<Review>, ReviewError> {
        Ok(self.reviews.lock().expect("lock").iter().filter(|r| &r.address == address).cloned().collect())
    }

    fn roles(&self, reviewer: &ReviewerId) -> Result<Vec<ReviewerRole>, ReviewError> {
        Ok(self.roles.lock().expect("lock").get(reviewer).cloned().unwrap_or_default())
    }
}

/// A [`Builder`] whose canonical form is the document itself. For tests; real
/// canonicalisation is the format core's.
pub struct PassThroughBuilder {
    identity: BuilderId,
}

impl PassThroughBuilder {
    /// A builder reporting `identity`.
    pub fn new(identity: &str) -> Self {
        Self { identity: BuilderId(identity.into()) }
    }
}

impl Builder for PassThroughBuilder {
    fn build(&self, snapshot: &SourceSnapshot) -> Result<BuildOutput, BuildError> {
        Ok(BuildOutput {
            canonical_bytes: snapshot.document.clone(),
            builder: self.identity.clone(),
            definition: sha256(b"fieldseal.dev/memory/pass-through-builder/v1"),
        })
    }
}

/// An [`ArtefactValidator`] that accepts every artefact (the secrets check still runs).
pub struct AcceptingValidator;

impl ArtefactValidator for AcceptingValidator {
    fn validate(&self, _artefact: &Artefact) -> Vec<Diagnostic> {
        Vec::new()
    }
}

/// An in-memory [`TransparencyLog`] that transmits through `T`.
pub struct MemoryTransparencyLog<T: LogTransport> {
    transport: T,
    leaves: Mutex<Vec<Digest>>,
    origin: String,
    key: SigningKey,
}

impl<T: LogTransport> MemoryTransparencyLog<T> {
    /// A log named `origin` that sends through `transport`, with a key derived from the
    /// origin.
    pub fn new(origin: &str, transport: T) -> Self {
        let scalar = sha256(format!("fieldseal.dev/memory/transparency-log/{origin}").as_bytes());
        let key = SigningKey::from_scalar(scalar.as_bytes()).expect("a SHA-256 output is a valid scalar");
        Self::with_key(origin, key, transport)
    }

    /// A log named `origin` signing with `key`.
    pub fn with_key(origin: &str, key: SigningKey, transport: T) -> Self {
        Self { transport, leaves: Mutex::default(), origin: origin.into(), key }
    }

    /// The log's pin, for a trust bundle (TRU-093).
    pub fn pin(&self) -> LogPin {
        LogPin {
            origin: self.origin.clone(),
            public_key: self.key.public_key().as_bytes().to_vec(),
            format: CHECKPOINT_FORMAT.into(),
        }
    }

    fn sign_checkpoint(&self, leaves: &[Digest]) -> SignedCheckpoint {
        SignedCheckpoint::sign(
            CheckpointBody { origin: self.origin.clone(), size: leaves.len() as u64, root: root(leaves), extensions: vec![] },
            &self.origin,
            &self.key,
        )
    }

    fn size_of(&self, checkpoint: &SignedCheckpoint, leaves: &[Digest]) -> Result<usize, LogError> {
        let size = usize::try_from(checkpoint.size()).map_err(|_| LogError::OutOfRange)?;
        if checkpoint.origin() != self.origin || size > leaves.len() || &root(&leaves[..size]) != checkpoint.root() {
            return Err(LogError::OutOfRange);
        }
        Ok(size)
    }

    fn lookup(&self, request: LogRequest) -> Result<(), LogError> {
        self.transport.send(&Transmission { request, fields: Vec::new() }).map(|_| ())
    }
}

impl<T: LogTransport> TransparencyLog for MemoryTransparencyLog<T> {
    fn append(&self, entry: &LogEntry) -> Result<LoggedEntry, LogError> {
        self.transport.send(&Transmission {
            request: LogRequest::Append,
            fields: vec![
                ("type".into(), entry.entry_type().as_str().as_bytes().to_vec()),
                ("digest".into(), entry.digest().as_bytes().to_vec()),
                ("signature".into(), entry.signature().0.clone()),
                ("publicKey".into(), entry.public_key().as_bytes().to_vec()),
            ],
        })?;
        let mut leaves = self.leaves.lock().expect("lock");
        leaves.push(leaf_hash(&LeafFormat::Fieldseal.leaf(entry)));
        let index = leaves.len() - 1;
        let checkpoint = self.sign_checkpoint(&leaves);
        let inclusion = InclusionProof { leaf_index: index as u64, tree_size: checkpoint.size(), path: audit_path(index, &leaves) };
        Ok(LoggedEntry { entry: entry.clone(), leaf: LeafFormat::Fieldseal, inclusion, checkpoint })
    }

    fn checkpoint(&self) -> Result<SignedCheckpoint, LogError> {
        self.lookup(LogRequest::Checkpoint)?;
        Ok(self.sign_checkpoint(&self.leaves.lock().expect("lock")))
    }

    fn prove_inclusion(&self, leaf_index: u64, checkpoint: &SignedCheckpoint) -> Result<InclusionProof, LogError> {
        self.lookup(LogRequest::Inclusion { leaf_index, tree_size: checkpoint.size() })?;
        let leaves = self.leaves.lock().expect("lock");
        let size = self.size_of(checkpoint, &leaves)?;
        let m = usize::try_from(leaf_index).map_err(|_| LogError::OutOfRange)?;
        if m >= size {
            return Err(LogError::OutOfRange);
        }
        Ok(InclusionProof { leaf_index, tree_size: checkpoint.size(), path: audit_path(m, &leaves[..size]) })
    }

    fn prove_consistency(&self, old_size: u64, checkpoint: &SignedCheckpoint) -> Result<ConsistencyProof, LogError> {
        self.lookup(LogRequest::Consistency { old_size, new_size: checkpoint.size() })?;
        let leaves = self.leaves.lock().expect("lock");
        let size = self.size_of(checkpoint, &leaves)?;
        let m = usize::try_from(old_size).map_err(|_| LogError::OutOfRange)?;
        if m > size {
            return Err(LogError::OutOfRange);
        }
        Ok(ConsistencyProof { old_size, new_size: checkpoint.size(), path: consistency_path(m, &leaves[..size]) })
    }
}

/// An in-memory, immutable [`ArtefactRegistry`].
#[derive(Default)]
pub struct MemoryArtefactRegistry {
    publications: Mutex<Vec<Publication>>,
    withdrawals: Mutex<Vec<Withdrawal>>,
}

impl MemoryArtefactRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtefactRegistry for MemoryArtefactRegistry {
    fn put(&self, publication: &Publication) -> Result<(), RegistryError> {
        let mut pubs = self.publications.lock().expect("lock");
        if let Some(existing) = pubs.iter().find(|p| p.address() == publication.address()) {
            return if existing == publication { Ok(()) } else { Err(RegistryError::Conflict) };
        }
        let a = &publication.artefact;
        if pubs.iter().any(|p| p.artefact.kind() == a.kind() && p.artefact.name() == a.name() && p.artefact.version() == a.version()) {
            return Err(RegistryError::VersionTaken);
        }
        pubs.push(publication.clone());
        Ok(())
    }

    fn get(&self, address: &ContentAddress) -> Result<Option<Publication>, RegistryError> {
        Ok(self.publications.lock().expect("lock").iter().find(|p| p.address() == address).cloned())
    }

    fn list(&self, kind: ArtefactKind, name: &str) -> Result<Vec<(String, ContentAddress)>, RegistryError> {
        Ok(self
            .publications
            .lock()
            .expect("lock")
            .iter()
            .filter(|p| p.artefact.kind() == kind && p.artefact.name() == name)
            .map(|p| (p.artefact.version().to_owned(), *p.address()))
            .collect())
    }

    fn withdraw(&self, withdrawal: &Withdrawal) -> Result<(), RegistryError> {
        let mut ws = self.withdrawals.lock().expect("lock");
        if !ws.contains(withdrawal) {
            ws.push(withdrawal.clone());
        }
        Ok(())
    }

    fn withdrawals(&self) -> Result<Vec<Withdrawal>, RegistryError> {
        Ok(self.withdrawals.lock().expect("lock").clone())
    }
}
