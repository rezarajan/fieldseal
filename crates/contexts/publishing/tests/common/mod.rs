//! Fixtures shared by the Publishing integration tests: an authority whose keys are
//! derived from labels (so every run gives the same bytes), a trust bundle listing
//! publishers per kind and pinning a log, a publishing policy, a software key custody, and
//! small in-test adapters for the log, registry and review system built only from the
//! Publishing domain (a context can't depend on the adapter crates).

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::BTreeMap;

use fieldseal_kernel::Value;
use fieldseal_kernel::crypto::{DomainTag, Purpose, Signature, tags};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{ContentAddress, Digest, KeyId, ReviewerId, Salt};
use fieldseal_kernel::seal::SealedBox;
use fieldseal_kernel::sign::SigningKey;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::domain::{Controls, PublishingPolicy};
use fieldseal_publishing::application::{
    BuildInput, BuildProvenance, Publish, SignPublication, VerifyPublication,
};
use fieldseal_publishing::domain::merkle::{audit_path, consistency_path, leaf_hash, root};
use fieldseal_publishing::domain::{
    Artefact, ArtefactKind, BuilderId, CHECKPOINT_FORMAT, CheckpointBody, ConsistencyProof, InclusionProof, LeafFormat,
    LogEntry, Publication, PublicationDraft, Review, ReviewDecision, ReviewerRole, RevisionId, SignedCheckpoint, SourceRef, Withdrawal,
};
use fieldseal_publishing::ports::{
    ArtefactRegistry, LogError, LoggedEntry, RegistryError, ReviewError, ReviewSystem, TransparencyLog,
};
use fieldseal_trust::domain::{
    AuthorityPublicKey, BundleSignature, BundleVersion, CertificateRequest, CustodyKey, IssueTerms, KeyAlgorithm,
    KeyCertificate, KeyOperation, KeyRole, KeyUse, LogPin, Revocation, TrustBundle, TrustBundleContents,
    UnsignedCertificate, UnsignedTrustBundle, may_sign,
};
use fieldseal_trust::ports::{CustodyError, KeyCustody};
use zeroize::Zeroizing;

/// 2027-01-15T08:00:00Z, in milliseconds.
pub const T0: AuthorityTime = AuthorityTime(1_800_000_000_000);
pub const DAY: u64 = AuthorityTime::DAY;

pub fn at(days: u64) -> AuthorityTime {
    AuthorityTime(T0.0 + days * DAY)
}

pub fn seed(label: &str) -> [u8; 32] {
    *sha256(format!("fieldseal.dev/vectors/publishing/{label}").as_bytes()).as_bytes()
}

pub fn signing_key(label: &str) -> SigningKey {
    SigningKey::from_scalar(&seed(label)).expect("seed is a valid scalar")
}

pub fn key_id_of(key: &SigningKey) -> KeyId {
    fieldseal_kernel::digest::key_id(key.public_key().as_bytes())
}

pub const BUILDER: &str = "https://ci.example.org/builders/fieldseal-publish";
pub const SOURCE: &str = "https://git.example.org/authority/artefacts";
pub const LOG_ORIGIN: &str = "log.example.org/v1";

/// A test-only [`KeyCustody`] holding imported software P-256 keys.
#[derive(Default)]
pub struct LabelCustody {
    keys: RefCell<BTreeMap<KeyId, (CustodyKey, SigningKey)>>,
    log: RefCell<Vec<KeyUse>>,
}

impl LabelCustody {
    pub fn import(&self, role: KeyRole, label: &str) -> KeyId {
        let key = signing_key(label);
        let public_key = AuthorityPublicKey::P256(key.public_key());
        let k = CustodyKey { id: public_key.key_id(), public_key, role };
        let id = k.id;
        self.keys.borrow_mut().insert(id, (k, key));
        id
    }
}

impl KeyCustody for LabelCustody {
    fn generate(&self, _role: KeyRole, _algorithm: KeyAlgorithm) -> Result<CustodyKey, CustodyError> {
        Err(CustodyError::Unsupported)
    }

    fn sign(&self, key: &KeyId, role: KeyRole, tag: &DomainTag, structure: &Value, caller: &str) -> Result<Signature, CustodyError> {
        let keys = self.keys.borrow();
        let (k, sk) = keys.get(key).ok_or(CustodyError::UnknownKey)?;
        if k.role != role {
            return Err(CustodyError::WrongPurpose { held: k.role, requested: role });
        }
        if !may_sign(role, tag) {
            return Err(CustodyError::TagNotAllowed { role, tag: tag.as_str() });
        }
        self.log.borrow_mut().push(KeyUse { key: *key, role, operation: KeyOperation::Sign, caller: caller.into() });
        sk.sign(tag, structure).map_err(|e| CustodyError::Backend(e.to_string()))
    }

    fn open(&self, _: &KeyId, _: Purpose, _: &DomainTag, _: &SealedBox, _: &str) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
        Err(CustodyError::Unsupported)
    }

    fn public_key(&self, key: &KeyId) -> Result<CustodyKey, CustodyError> {
        self.keys.borrow().get(key).map(|(k, _)| k.clone()).ok_or(CustodyError::UnknownKey)
    }

    fn usage_log(&self) -> Vec<KeyUse> {
        self.log.borrow().clone()
    }
}

/// An RFC 9162 log built from the Publishing domain's tree functions, with a C2SP
/// checkpoint signed by `key`, and a switch to fork its history for PUB-055 tests.
pub struct TestLog {
    pub origin: String,
    pub key: SigningKey,
    pub leaves: RefCell<Vec<Digest>>,
    pub appended: RefCell<Vec<LogEntry>>,
}

impl TestLog {
    pub fn new(origin: &str, label: &str) -> Self {
        Self { origin: origin.into(), key: signing_key(label), leaves: RefCell::default(), appended: RefCell::default() }
    }

    pub fn pin(&self) -> LogPin {
        LogPin { origin: self.origin.clone(), public_key: self.key.public_key().as_bytes().to_vec(), format: CHECKPOINT_FORMAT.into() }
    }

    fn sign(&self, leaves: &[Digest]) -> SignedCheckpoint {
        SignedCheckpoint::sign(
            CheckpointBody { origin: self.origin.clone(), size: leaves.len() as u64, root: root(leaves), extensions: vec![] },
            &self.origin,
            &self.key,
        )
    }

    /// Appends an unrelated leaf, so the tree grows.
    pub fn grow(&self) {
        let n = self.leaves.borrow().len();
        self.leaves.borrow_mut().push(leaf_hash(format!("other entry {n}").as_bytes()));
    }

    /// Rewrites leaf `i`: a forked log.
    pub fn rewrite(&self, i: usize) {
        self.leaves.borrow_mut()[i] = leaf_hash(b"rewritten");
    }
}

impl TransparencyLog for TestLog {
    fn append(&self, entry: &LogEntry) -> Result<LoggedEntry, LogError> {
        self.appended.borrow_mut().push(entry.clone());
        let mut leaves = self.leaves.borrow_mut();
        leaves.push(leaf_hash(&LeafFormat::Fieldseal.leaf(entry)));
        let i = leaves.len() - 1;
        let checkpoint = self.sign(&leaves);
        Ok(LoggedEntry {
            entry: entry.clone(),
            leaf: LeafFormat::Fieldseal,
            inclusion: InclusionProof { leaf_index: i as u64, tree_size: leaves.len() as u64, path: audit_path(i, &leaves) },
            checkpoint,
        })
    }

    fn checkpoint(&self) -> Result<SignedCheckpoint, LogError> {
        Ok(self.sign(&self.leaves.borrow()))
    }

    fn prove_inclusion(&self, leaf_index: u64, checkpoint: &SignedCheckpoint) -> Result<InclusionProof, LogError> {
        let leaves = self.leaves.borrow();
        let size = checkpoint.size() as usize;
        if size > leaves.len() || leaf_index >= checkpoint.size() {
            return Err(LogError::OutOfRange);
        }
        Ok(InclusionProof { leaf_index, tree_size: checkpoint.size(), path: audit_path(leaf_index as usize, &leaves[..size]) })
    }

    fn prove_consistency(&self, old_size: u64, checkpoint: &SignedCheckpoint) -> Result<ConsistencyProof, LogError> {
        let leaves = self.leaves.borrow();
        let size = checkpoint.size() as usize;
        if size > leaves.len() || old_size > checkpoint.size() {
            return Err(LogError::OutOfRange);
        }
        Ok(ConsistencyProof { old_size, new_size: checkpoint.size(), path: consistency_path(old_size as usize, &leaves[..size]) })
    }
}

/// A registry that keeps what it is given.
#[derive(Default)]
pub struct TestRegistry {
    pub publications: RefCell<Vec<Publication>>,
    pub withdrawals: RefCell<Vec<Withdrawal>>,
}

impl ArtefactRegistry for TestRegistry {
    fn put(&self, publication: &Publication) -> Result<(), RegistryError> {
        self.publications.borrow_mut().push(publication.clone());
        Ok(())
    }
    fn get(&self, address: &ContentAddress) -> Result<Option<Publication>, RegistryError> {
        Ok(self.publications.borrow().iter().find(|p| p.address() == address).cloned())
    }
    fn list(&self, _: ArtefactKind, _: &str) -> Result<Vec<(String, ContentAddress)>, RegistryError> {
        Ok(vec![])
    }
    fn withdraw(&self, withdrawal: &Withdrawal) -> Result<(), RegistryError> {
        self.withdrawals.borrow_mut().push(withdrawal.clone());
        Ok(())
    }
    fn withdrawals(&self) -> Result<Vec<Withdrawal>, RegistryError> {
        Ok(self.withdrawals.borrow().clone())
    }
}

/// Reviews kept in order.
#[derive(Default)]
pub struct TestReviews(pub RefCell<Vec<Review>>, pub RefCell<Vec<(ReviewerId, ReviewerRole)>>);

impl ReviewSystem for TestReviews {
    fn record(&self, review: &Review) -> Result<(), ReviewError> {
        self.0.borrow_mut().push(review.clone());
        Ok(())
    }
    fn reviews(&self, address: &ContentAddress) -> Result<Vec<Review>, ReviewError> {
        Ok(self.0.borrow().iter().filter(|r| &r.address == address).cloned().collect())
    }
    fn roles(&self, reviewer: &ReviewerId) -> Result<Vec<ReviewerRole>, ReviewError> {
        Ok(self.1.borrow().iter().filter(|(r, _)| r == reviewer).map(|(_, role)| role.clone()).collect())
    }
}

/// Grants `who` the reviewer role for `kind`, and for each of `languages`.
pub fn grant(reviews: &TestReviews, who: &str, kind: ArtefactKind, languages: &[&str]) {
    reviews.1.borrow_mut().push((reviewer(who), ReviewerRole::of_kind(kind)));
    for l in languages {
        reviews.1.borrow_mut().push((reviewer(who), ReviewerRole::for_language(kind, l)));
    }
}

pub fn reviewer(id: &str) -> ReviewerId {
    ReviewerId::new(id).unwrap()
}

/// Records an approval by `who`, who is also granted the reviewer role for the kind.
pub fn approve(reviews: &TestReviews, artefact: &Artefact, revision: &str, who: &str) {
    grant(reviews, who, artefact.kind(), &[]);
    reviews
        .record(&Review {
            address: *artefact.address(),
            revision: RevisionId(revision.into()),
            reviewer: reviewer(who),
            decision: ReviewDecision::Approve,
        })
        .unwrap();
}

fn certify(root_key: &SigningKey, root: &KeyCertificate, key: &SigningKey, purpose: Purpose, from: u64, to: u64, serial: u64) -> KeyCertificate {
    let request = CertificateRequest::new(AuthorityPublicKey::P256(key.public_key()), None, &BTreeMap::new())
        .unwrap()
        .signed_by(key)
        .unwrap();
    let unsigned = UnsignedCertificate::issue(root, &request, IssueTerms { purpose, record: None, not_before: at(from), not_after: at(to), serial }).unwrap();
    let sig = root_key.sign(&tags::KEY_CERTIFICATE, &unsigned.signed_structure()).unwrap();
    unsigned.finish(sig, &root_key.public_key()).unwrap()
}

/// The publishers `a`, `b`, `c` are listed for every kind; `d` is certified as a
/// publisher but listed for nothing; `p` is listed for `Policy` only.
pub const PUBLISHERS: [&str; 3] = ["publisher-a", "publisher-b", "publisher-c"];

pub struct Authority {
    pub root_key: SigningKey,
    pub root: KeyCertificate,
    pub certificates: Vec<KeyCertificate>,
    pub log: TestLog,
    pub bundle: TrustBundle,
    pub policy: PublishingPolicy,
    pub custody: LabelCustody,
    pub builder: KeyId,
    pub publishers: Vec<KeyId>,
    pub unlisted: KeyId,
    pub policy_only: KeyId,
}

impl Authority {
    pub fn key(&self, label: &str) -> KeyId {
        key_id_of(&signing_key(label))
    }

    /// A trust bundle like this authority's, with `edit` applied to its contents.
    pub fn bundle_with(&self, edit: impl FnOnce(&mut TrustBundleContents)) -> TrustBundle {
        let mut contents = self.bundle.contents().clone();
        edit(&mut contents);
        sign_bundle(&self.root_key, contents)
    }

    pub fn revoke(&self, label: &str, effective: AuthorityTime) -> Revocation {
        use fieldseal_trust::domain::{RevocationReason, RevocationTarget, UnsignedRevocation};
        let unsigned = UnsignedRevocation::new(
            &self.root,
            RevocationTarget::key(self.key(label)),
            RevocationReason::Compromised,
            effective,
            effective,
        )
        .unwrap();
        let sig = self.root_key.sign(&tags::REVOCATION, &unsigned.signed_structure()).unwrap();
        unsigned.finish(sig, &self.root_key.public_key()).unwrap()
    }
}

pub fn sign_bundle(root_key: &SigningKey, contents: TrustBundleContents) -> TrustBundle {
    let unsigned = UnsignedTrustBundle::new(contents).unwrap();
    let sig = root_key.sign(&tags::TRUST_BUNDLE, &unsigned.signed_structure()).unwrap();
    unsigned.finish(vec![BundleSignature { signer: key_id_of(root_key), sig }]).unwrap()
}

pub fn policy() -> PublishingPolicy {
    let mut p = Controls::defaults().publishing();
    p.allowed_builders = vec![BUILDER.into()];
    p.allowed_sources = vec![SOURCE.into()];
    p
}

pub fn authority() -> Authority {
    let root_key = signing_key("root");
    let unsigned = UnsignedCertificate::root(root_key.public_key(), T0, AuthorityTime(T0.0 + 5 * 365 * DAY), 1).unwrap();
    let sig = root_key.sign(&tags::KEY_CERTIFICATE, &unsigned.signed_structure()).unwrap();
    let root = unsigned.finish(sig, &root_key.public_key()).unwrap();

    let custody = LabelCustody::default();
    let mut certificates = Vec::new();
    let mut serial = 10;
    let mut publishers = Vec::new();
    for label in PUBLISHERS.iter().chain(&["publisher-d", "publisher-p"]) {
        certificates.push(certify(&root_key, &root, &signing_key(label), Purpose::Publisher, 0, 700, serial));
        serial += 1;
        let id = custody.import(KeyRole::Purpose(Purpose::Publisher), label);
        if PUBLISHERS.contains(label) {
            publishers.push(id);
        }
    }
    certificates.push(certify(&root_key, &root, &signing_key("builder"), Purpose::Builder, 0, 300, serial));
    let builder = custody.import(KeyRole::Purpose(Purpose::Builder), "builder");
    let unlisted = key_id_of(&signing_key("publisher-d"));
    let policy_only = key_id_of(&signing_key("publisher-p"));

    let mut map = BTreeMap::new();
    for kind in ArtefactKind::ALL {
        map.insert(kind.as_str().to_owned(), publishers.clone());
    }
    map.get_mut("Policy").unwrap().push(policy_only);

    let log = TestLog::new(LOG_ORIGIN, "log-key");
    let contents = TrustBundleContents {
        name: "example-authority".into(),
        version: BundleVersion::parse("1.0.0").unwrap(),
        issued: at(1),
        roots: vec![root.clone()],
        certificates: certificates.clone(),
        publishers: map,
        attestation_roots: BTreeMap::new(),
        runtime_builds: vec![],
        logs: vec![log.pin()],
        revocations: vec![],
    };
    let bundle = sign_bundle(&root_key, contents);
    Authority { root_key, root, certificates, log, bundle, policy: policy(), custody, builder, publishers, unlisted, policy_only }
}

/// A fixed salt so that vectors are stable; CI draws a random one (PUB-090).
pub fn salt() -> Salt {
    Salt::from([0x5a; 32])
}

pub fn instrument(version: &str, bytes: &[u8]) -> Artefact {
    Artefact::new(ArtefactKind::Instrument, "health-check", version, bytes.to_vec(), Some(salt())).unwrap()
}

pub fn build_input(artefact: Artefact) -> BuildInput {
    BuildInput {
        artefact,
        source: SourceRef { uri: SOURCE.into(), revision: RevisionId("rev-1".into()) },
        author: reviewer("author-1"),
        builder: BuilderId(BUILDER.into()),
        definition: sha256(b"pipeline definition v1"),
        finished: at(10),
        languages: Vec::new(),
    }
}

/// An approved, built draft of `artefact` with two reviews.
pub fn draft(auth: &Authority, artefact: Artefact) -> PublicationDraft {
    let reviews = TestReviews::default();
    approve(&reviews, &artefact, "rev-1", "reviewer-1");
    approve(&reviews, &artefact, "rev-1", "reviewer-2");
    BuildProvenance::new(&auth.custody, &reviews, &auth.policy, auth.builder, "ci").build(build_input(artefact)).unwrap()
}

pub fn verifier(auth: &Authority) -> VerifyPublication<'_> {
    VerifyPublication::new(fieldseal_trust::domain::TrustStore::new(&auth.bundle), &auth.policy)
}

/// `draft` signed by each of `labels`.
pub fn signed(auth: &Authority, draft: &PublicationDraft, labels: &[&str]) -> PublicationDraft {
    let v = verifier(auth);
    let signer = SignPublication::new(&auth.custody, &v, "publisher");
    let mut d = draft.clone();
    for l in labels {
        d = signer.sign(&d, &auth.key(l)).unwrap();
    }
    d
}

/// A published instrument, signed by `a` and `b`.
pub fn published(auth: &Authority, version: &str, bytes: &[u8]) -> Publication {
    let d = signed(auth, &draft(auth, instrument(version, bytes)), &["publisher-a", "publisher-b"]);
    let v = verifier(auth);
    let registry = TestRegistry::default();
    Publish::new(&auth.log, &registry, &v).publish(&d, &[]).unwrap()
}
