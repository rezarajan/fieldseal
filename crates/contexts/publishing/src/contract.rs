//! Contract tests for adapters of the Publishing context's driven ports.
//!
//! The transparency-log suite enforces ADR 0030 by observation: adapters are built over
//! a [`RecordingTransport`], and the suite fails if anything other than an appended
//! entry's own fields (in the backend's mapped form) is ever transmitted, if a lookup
//! carries any field at all, or if a returned proof or checkpoint doesn't verify offline
//! against the log's pinned key (PUB-104–106). That `append` accepts nothing but a
//! [`LogEntry`] is a compile-time fact of [`TransparencyLog`]:
//!
//! ```compile_fail
//! use fieldseal_publishing::ports::TransparencyLog;
//! fn leak(log: &dyn TransparencyLog) {
//!     log.append(&"health-check 1.2.0"); // only a &LogEntry is accepted
//! }
//! ```

use std::sync::{Arc, Mutex};

use fieldseal_kernel::crypto::tags;
use fieldseal_kernel::digest::{lower_hex, sha256};
use fieldseal_kernel::id::{ContentAddress, Digest, KeyId, ReviewerId, Salt};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_trust::domain::LogPin;

use crate::domain::encoding::{base64_encode, p256_pem, p256_spki_der};
use crate::domain::merkle::{leaf_hash, root, verify_consistency, verify_inclusion};
use crate::domain::statement::entry_signature_der;
use crate::domain::{
    Artefact, ArtefactKind, BuilderId, CheckpointBody, LogEntry, LogEntryType, LogRecord, ProvenanceStatement, Publication,
    PublicationStatement, Review, ReviewDecision, RevisionId, SignedCheckpoint, SignedProvenance, SignerSignature,
    SourceRef, SourceSnapshot, Withdrawal, WithdrawalStatement, artefact_signed_structure,
};
use crate::ports::{
    ArtefactRegistry, Builder, LogError, LogRequest, LogTransport, LoggedEntry, RegistryError, ReviewError, ReviewSystem,
    SourceError, SourceRepository, Transmission, TransparencyLog,
};

type Inner = Arc<dyn LogTransport + Send + Sync>;

/// A [`LogTransport`] that records every transmission and either answers with an empty
/// body or forwards to another transport (for adapters that need a backend's answers).
#[derive(Clone, Default)]
pub struct RecordingTransport {
    sent: Arc<Mutex<Vec<Transmission>>>,
    inner: Option<Inner>,
}

impl RecordingTransport {
    /// A recorder that answers every request with an empty body.
    pub fn new() -> Self {
        Self::default()
    }

    /// A recorder in front of `inner`.
    pub fn forwarding(inner: impl LogTransport + Send + Sync + 'static) -> Self {
        Self { sent: Arc::default(), inner: Some(Arc::new(inner)) }
    }

    /// Everything transmitted so far.
    pub fn recorded(&self) -> Vec<Transmission> {
        self.sent.lock().expect("lock").clone()
    }
}

impl LogTransport for RecordingTransport {
    fn send(&self, transmission: &Transmission) -> Result<Vec<u8>, LogError> {
        self.sent.lock().expect("lock").push(transmission.clone());
        match &self.inner {
            Some(inner) => inner.send(transmission),
            None => Ok(Vec::new()),
        }
    }
}

/// [`SourceRepository`]: a revision always returns the same snapshot; unknown revisions fail.
pub fn source_repository_contract<S: SourceRepository>(make: impl Fn() -> (S, RevisionId)) {
    let (repo, revision) = make();
    let a = repo.fetch(&revision).expect("fetch a known revision");
    assert_eq!(repo.fetch(&revision).expect("fetch again"), a, "a revision must always return the same snapshot");
    assert_eq!(a.revision, revision, "the snapshot must name its revision");
    assert_eq!(repo.fetch(&RevisionId("no-such-revision".into())), Err(SourceError::NotFound), "unknown revisions fail");
}

/// [`ReviewSystem`]: reviews are recorded per exact address and revision, can't be
/// altered, and read back in order.
pub fn review_system_contract<R: ReviewSystem>(make: impl Fn() -> R) {
    let reviews = make();
    let review = |reviewer: &str, revision: &str, decision| Review {
        address: ContentAddress::from([1; 32]),
        revision: RevisionId(revision.into()),
        reviewer: ReviewerId::new(reviewer).expect("id"),
        decision,
    };
    let a = review("rev-a", "r1", ReviewDecision::Approve);
    let b = review("rev-b", "r1", ReviewDecision::Approve);
    let a_later = review("rev-a", "r2", ReviewDecision::Approve);
    reviews.record(&a).expect("record");
    reviews.record(&b).expect("record a second reviewer");
    reviews.record(&a_later).expect("the same reviewer may review a later revision");
    let mut changed = a.clone();
    changed.decision = ReviewDecision::Reject;
    assert_eq!(reviews.record(&changed), Err(ReviewError::AlreadyRecorded), "a review must not be altered after the fact");
    assert_eq!(reviews.reviews(&a.address), Ok(vec![a, b, a_later]), "recorded reviews read back unchanged, in order");
    assert_eq!(reviews.reviews(&ContentAddress::from([2; 32])), Ok(vec![]), "other artefacts have no reviews");
}

/// [`Builder`]: deterministic, and reports its identity.
pub fn builder_contract<B: Builder>(make: impl Fn() -> (B, SourceSnapshot)) {
    let (builder, snapshot) = make();
    let a = builder.build(&snapshot).expect("build");
    assert_eq!(builder.build(&snapshot).expect("build again"), a, "builds must be deterministic");
    assert!(!a.builder.0.is_empty(), "the builder must report its identity");
}

fn key(label: &str) -> SigningKey {
    SigningKey::from_scalar(sha256(format!("fieldseal.dev/contract/publishing/{label}").as_bytes()).as_bytes())
        .expect("a SHA-256 output is a valid scalar")
}

/// A genuinely signed log entry: publisher key `label` signs the statement for a made-up
/// artefact `n`.
pub fn sample_entry(label: &str, n: u8, entry_type: LogEntryType) -> LogEntry {
    let k = key(label);
    let statement = PublicationStatement::new(entry_type, ContentAddress::from([n; 32]), Digest::from([n ^ 0xff; 32]));
    let sig = k.sign(&tags::PUBLICATION, &statement.to_value()).expect("sign");
    LogEntry::for_statement(&statement, sig, k.public_key())
}

/// Every form in which a backend may carry one of `entry`'s fields: raw, lowercase hex,
/// base64, and for the signature ASN.1 DER, for the key SPKI DER and PEM (and base64 of
/// each), plus the whole entry's canonical CBOR.
fn mapped_values(entry: &LogEntry) -> Vec<Vec<u8>> {
    let raw = [
        entry.entry_type().as_str().as_bytes().to_vec(),
        entry.digest().as_bytes().to_vec(),
        entry.signature().0.clone(),
        entry.public_key().as_bytes().to_vec(),
        entry_signature_der(entry),
        p256_spki_der(entry.public_key()),
        p256_pem(entry.public_key()).into_bytes(),
        entry.encode(),
    ];
    let mut out = raw.to_vec();
    for r in &raw {
        out.push(lower_hex(r).into_bytes());
        out.push(base64_encode(r).into_bytes());
    }
    out
}

/// The field names an adapter may use for an entry's fields.
pub const ALLOWED_FIELD_NAMES: &[&str] = &["type", "digest", "signature", "sig", "publicKey", "pub", "entry"];

fn check_logged(l: &LoggedEntry, entry: &LogEntry, pin: &LogPin) {
    assert_eq!(&l.entry, entry, "the logged entry must be the entry appended");
    assert_eq!(l.inclusion.tree_size, l.checkpoint.size(), "the proof must be against the returned checkpoint");
    assert!(l.inclusion.leaf_index < l.checkpoint.size(), "the leaf must be inside the tree");
    l.checkpoint.verify(std::slice::from_ref(pin), 0).expect("the checkpoint must verify against the pinned log key (PUB-106)");
    assert!(
        verify_inclusion(&leaf_hash(&l.leaf.leaf(entry)), &l.inclusion, l.checkpoint.root()),
        "the inclusion proof must verify offline"
    );
}

/// [`TransparencyLog`] (ADR 0030, PUB-100–106): append-only with proofs that verify
/// offline against `pin`, and **transmits only appended entries' own fields**. `make`
/// builds the adapter over `transport` (a [`RecordingTransport`], forwarding to a backend
/// if the adapter needs answers).
pub fn transparency_log_contract<L: TransparencyLog>(transport: RecordingTransport, make: impl FnOnce(RecordingTransport) -> L, pin: &LogPin) {
    let log = make(transport.clone());
    let entries = [
        sample_entry("publisher-a", 2, LogEntryType::Publish),
        sample_entry("publisher-b", 2, LogEntryType::Publish),
        sample_entry("publisher-a", 3, LogEntryType::Withdraw),
    ];

    let mut last_size = 0;
    let mut logged = Vec::new();
    for entry in &entries {
        let l = log.append(entry).expect("append");
        check_logged(&l, entry, pin);
        assert!(l.checkpoint.size() > last_size, "every append must grow the log");
        last_size = l.checkpoint.size();
        logged.push(l);
    }

    let head = log.checkpoint().expect("checkpoint");
    head.verify(std::slice::from_ref(pin), 0).expect("the latest checkpoint must verify against the pinned key");
    assert!(head.size() >= last_size, "the checkpoint must cover every appended entry");
    for l in &logged {
        let proof = log.prove_inclusion(l.inclusion.leaf_index, &head).expect("inclusion proof against the latest checkpoint");
        assert_eq!(proof.tree_size, head.size(), "the proof must be for the requested checkpoint");
        assert!(verify_inclusion(&leaf_hash(&l.leaf.leaf(&l.entry)), &proof, head.root()), "the proof must verify");
    }
    let first = &logged[0].checkpoint;
    let consistency = log.prove_consistency(first.size(), &head).expect("consistency proof");
    assert_eq!((consistency.old_size, consistency.new_size), (first.size(), head.size()), "consistency sizes");
    assert!(verify_consistency(&consistency, first.root(), head.root()), "the log must extend its earlier tree head (PUB-054)");
    assert!(log.prove_consistency(head.size() + 1, &head).is_err(), "a future size can't be proven");

    // ADR 0030: nothing but the fields of appended entries may ever be transmitted.
    let sent = transport.recorded();
    let appends: Vec<&Transmission> = sent.iter().filter(|t| t.request == LogRequest::Append).collect();
    assert_eq!(appends.len(), entries.len(), "one append transmission per appended entry");
    for t in sent.iter().filter(|t| t.request != LogRequest::Append) {
        assert!(t.fields.is_empty(), "lookups must carry no fields, only sizes and indices: {t:?}");
    }
    for (t, entry) in appends.iter().zip(&entries) {
        let allowed = mapped_values(entry);
        assert!(t.fields.len() <= 4, "at most the four LogEntry fields may be sent (PUB-102)");
        for (name, value) in &t.fields {
            assert!(ALLOWED_FIELD_NAMES.contains(&name.as_str()), "field name `{name}` is not a LogEntry field");
            assert!(
                allowed.contains(value),
                "field `{name}` transmitted a value that is not one of this entry's own fields (PUB-104)"
            );
        }
        let carries = |forms: &[Vec<u8>]| t.fields.iter().any(|(_, v)| forms.contains(v));
        assert!(
            carries(&[entry.digest().as_bytes().to_vec(), lower_hex(entry.digest().as_bytes()).into_bytes(), entry.encode()]),
            "the digest must be transmitted"
        );
    }
}

/// A structurally complete publication of an instrument named `name` at `version`, with
/// signatures that are real but not trusted by any bundle. For registry contracts only;
/// it does not pass [`crate::application::VerifyPublication`].
pub fn sample_publication(name: &str, version: &str, bytes: &[u8]) -> Publication {
    let artefact = Artefact::new(ArtefactKind::Instrument, name, version, bytes.to_vec(), Some(Salt::from([7; 32])))
        .expect("sample artefact");
    let statement = ProvenanceStatement::for_artefact(
        &artefact,
        SourceRef { uri: "https://git.example/artefacts".into(), revision: RevisionId("r1".into()) },
        vec![ReviewerId::new("rev-a").expect("id"), ReviewerId::new("rev-b").expect("id")],
        Digest::from([3; 32]),
        BuilderId("https://ci.example/builder".into()),
        AuthorityTime(1),
    );
    let builder = key("builder");
    let sig = builder.sign(&tags::PROVENANCE, &statement.to_value()).expect("sign");
    let provenance = SignedProvenance::new(statement, fieldseal_kernel::digest::key_id(builder.public_key().as_bytes()), sig);
    let publisher = key("publisher-a");
    let signer: KeyId = fieldseal_kernel::digest::key_id(publisher.public_key().as_bytes());
    let structure = artefact_signed_structure(&artefact, &provenance.digest());
    let sig = publisher.sign(&tags::ARTEFACT, &structure).expect("sign");
    let st = PublicationStatement::new(LogEntryType::Publish, *artefact.address(), provenance.digest());
    let entry = LogEntry::for_statement(&st, publisher.sign(&tags::PUBLICATION, &st.to_value()).expect("sign"), publisher.public_key());
    let leaf = leaf_hash(&entry.encode());
    let checkpoint = SignedCheckpoint::sign(
        CheckpointBody { origin: "contract.example/log".into(), size: 1, root: root(&[leaf]), extensions: vec![] },
        "contract.example",
        &key("log"),
    );
    Publication {
        artefact,
        provenance,
        signatures: vec![SignerSignature { signer, sig }],
        log: vec![LogRecord {
            entry,
            leaf: crate::domain::LeafFormat::Fieldseal,
            inclusion: crate::domain::InclusionProof { leaf_index: 0, tree_size: 1, path: vec![] },
        }],
        checkpoint,
        checkpoint_time: None,
    }
}

/// [`ArtefactRegistry`] (PUB-060–062): immutable by address, one address per version,
/// listable by kind and name, keeps withdrawals.
pub fn artefact_registry_contract<R: ArtefactRegistry>(make: impl Fn() -> R) {
    let registry = make();
    let a = sample_publication("health-check", "1.0.0", b"version one");
    let b = sample_publication("health-check", "1.1.0", b"version two");
    assert_eq!(registry.get(a.address()), Ok(None), "an empty registry has nothing");
    registry.put(&a).expect("put");
    registry.put(&a).expect("putting the same publication again is a no-op");
    assert_eq!(registry.get(a.address()), Ok(Some(a.clone())), "an address returns what was stored");

    let mut different = a.clone();
    different.signatures[0].sig.0[0] ^= 1;
    assert_eq!(registry.put(&different), Err(RegistryError::Conflict), "an address can't be overwritten (PUB-062)");
    assert_eq!(registry.get(a.address()), Ok(Some(a.clone())), "a refused overwrite changes nothing");

    let reused = sample_publication("health-check", "1.0.0", b"other bytes, same version");
    assert_eq!(registry.put(&reused), Err(RegistryError::VersionTaken), "a version is used once per name (PUB §2)");

    registry.put(&b).expect("put a later version");
    assert_eq!(
        registry.list(ArtefactKind::Instrument, "health-check"),
        Ok(vec![("1.0.0".to_owned(), *a.address()), ("1.1.0".to_owned(), *b.address())]),
        "versions are listed by kind and name, in storing order"
    );
    assert_eq!(registry.list(ArtefactKind::Policy, "health-check"), Ok(vec![]), "kinds are separate");

    let withdrawal = Withdrawal {
        statement: WithdrawalStatement::of(&a, "superseded", AuthorityTime(2)),
        signatures: a.signatures.clone(),
        log: a.log.clone(),
        checkpoint: a.checkpoint.clone(),
    };
    registry.withdraw(&withdrawal).expect("withdraw");
    assert_eq!(registry.withdrawals(), Ok(vec![withdrawal]), "withdrawals are kept");
    assert_eq!(registry.get(a.address()), Ok(Some(a)), "a withdrawn publication is still returned (PUB-062)");
}

/// [`ArtefactValidator`] (PUB-003): the same artefact gets the same findings; a blocking
/// finding names a code and says what was found.
pub fn artefact_validator_contract<V: crate::ports::ArtefactValidator>(make: impl Fn() -> V, artefact: &Artefact) {
    let validator = make();
    let first = validator.validate(artefact);
    assert_eq!(first, validator.validate(artefact), "validation is deterministic");
    for d in first.iter().filter(|d| d.blocking) {
        assert!(!d.code.is_empty() && !d.message.is_empty(), "a blocking finding has a code and a message");
    }
}

/// [`LogTransport`] (PUB-104): every request kind is answered or refused with a
/// [`LogError`], never a panic; a lookup's outcome class is repeatable; a transport never
/// needs more than the transmission it is given.
pub fn log_transport_contract<T: LogTransport>(make: impl Fn() -> T) {
    let transport = make();
    let append = Transmission {
        request: LogRequest::Append,
        fields: vec![
            ("type".into(), b"publish".to_vec()),
            ("address".into(), vec![1; 32]),
            ("signature".into(), vec![2; 64]),
            ("key".into(), fieldseal_kernel::sign::SigningKey::from_scalar(&[3; 32]).expect("valid scalar").public_key().as_bytes().to_vec()),
        ],
    };
    let lookups = [
        LogRequest::Checkpoint,
        LogRequest::Inclusion { leaf_index: 0, tree_size: 1 },
        LogRequest::Consistency { old_size: 1, new_size: 2 },
    ];
    let _: Result<Vec<u8>, LogError> = transport.send(&append);
    for request in lookups {
        let t = Transmission { request, fields: vec![] };
        let (a, b) = (transport.send(&t), transport.send(&t));
        assert_eq!(a.is_ok(), b.is_ok(), "a lookup's outcome class is repeatable ({request:?})");
    }
}
