//! Test fixtures shared by the Trust integration tests: a software key custody whose keys
//! are derived from labels (so every run gives the same bytes), and helpers to build an
//! authority with a root, purpose keys and a trust bundle.

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::BTreeMap;

use fieldseal_kernel::Value;
use fieldseal_kernel::crypto::{DomainTag, Purpose, Signature};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{CollectionPeriodId, KeyId};
use fieldseal_kernel::seal::{RecipientKey, RecipientSecret, SealedBox, Suite};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_trust::application::Authority;
use fieldseal_trust::domain::{
    AuthorityPublicKey, Ceremony, CeremonyRecord, CertificateRequest, CollectionPeriod, CustodyKey, IssueTerms,
    KeyAlgorithm, KeyCertificate, KeyOperation, KeyRole, KeyUse, LogPin, RecordKeyTerms, Retention, RuntimeBuild,
    Threshold, TrustBundle, TrustBundleContents, BundleVersion, may_open, may_sign,
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
    *sha256(format!("fieldseal.dev/vectors/trust/{label}").as_bytes()).as_bytes()
}

pub fn signing_key(label: &str) -> SigningKey {
    SigningKey::from_scalar(&seed(label)).expect("seed is a valid scalar")
}

pub fn record_secret(label: &str) -> RecipientSecret {
    RecipientSecret::from_bytes(Suite::Fs1X, &seed(label)).expect("X25519 accepts any 32 bytes")
}

enum Secret {
    P256(SigningKey),
    X25519(RecipientSecret),
}

/// A test-only [`KeyCustody`] with software keys derived from labels.
#[derive(Default)]
pub struct LabelCustody {
    keys: RefCell<BTreeMap<KeyId, (CustodyKey, Secret)>>,
    labels: RefCell<Vec<String>>,
    log: RefCell<Vec<KeyUse>>,
}

impl LabelCustody {
    /// Generates under `label` (the next `generate` uses it).
    pub fn next_label(&self, label: &str) {
        self.labels.borrow_mut().push(label.to_owned());
    }

    /// Imports a P-256 key held outside (for tests that also need the key itself).
    pub fn import(&self, role: KeyRole, key: SigningKey) -> CustodyKey {
        let public_key = AuthorityPublicKey::P256(key.public_key());
        let k = CustodyKey { id: public_key.key_id(), public_key, role };
        self.keys.borrow_mut().insert(k.id, (k.clone(), Secret::P256(key)));
        k
    }
}

impl KeyCustody for LabelCustody {
    fn generate(&self, role: KeyRole, algorithm: KeyAlgorithm) -> Result<CustodyKey, CustodyError> {
        if !role.allows(algorithm) {
            return Err(CustodyError::Unsupported);
        }
        let label = self.labels.borrow_mut().pop().unwrap_or_else(|| format!("key-{}", self.keys.borrow().len()));
        let (public_key, secret) = match algorithm {
            KeyAlgorithm::P256 => {
                let k = signing_key(&label);
                (AuthorityPublicKey::P256(k.public_key()), Secret::P256(k))
            }
            KeyAlgorithm::X25519 => {
                let k = record_secret(&label);
                let RecipientKey::X25519(p) = k.public().unwrap() else { unreachable!() };
                (AuthorityPublicKey::X25519(p), Secret::X25519(k))
            }
        };
        let key = CustodyKey { id: public_key.key_id(), public_key, role };
        self.keys.borrow_mut().insert(key.id, (key.clone(), secret));
        Ok(key)
    }

    fn sign(&self, key: &KeyId, role: KeyRole, tag: &DomainTag, structure: &Value, caller: &str) -> Result<Signature, CustodyError> {
        let keys = self.keys.borrow();
        let (k, secret) = keys.get(key).ok_or(CustodyError::UnknownKey)?;
        if k.role != role {
            return Err(CustodyError::WrongPurpose { held: k.role, requested: role });
        }
        if !may_sign(role, tag) {
            return Err(CustodyError::TagNotAllowed { role, tag: tag.as_str() });
        }
        let Secret::P256(sk) = secret else { return Err(CustodyError::Unsupported) };
        self.log.borrow_mut().push(KeyUse { key: *key, role, operation: KeyOperation::Sign, caller: caller.into() });
        sk.sign(tag, structure).map_err(|e| CustodyError::Backend(e.to_string()))
    }

    fn open(&self, key: &KeyId, purpose: Purpose, tag: &DomainTag, sealed: &SealedBox, caller: &str) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
        let keys = self.keys.borrow();
        let (k, secret) = keys.get(key).ok_or(CustodyError::UnknownKey)?;
        let role = KeyRole::Purpose(purpose);
        if k.role != role {
            return Err(CustodyError::WrongPurpose { held: k.role, requested: role });
        }
        if !may_open(purpose, tag) {
            return Err(CustodyError::TagNotAllowed { role, tag: tag.as_str() });
        }
        let Secret::X25519(sk) = secret else { return Err(CustodyError::Unsupported) };
        self.log.borrow_mut().push(KeyUse { key: *key, role, operation: KeyOperation::Open, caller: caller.into() });
        fieldseal_kernel::seal::open(sk, tag, sealed).map_err(CustodyError::Open)
    }

    fn public_key(&self, key: &KeyId) -> Result<CustodyKey, CustodyError> {
        self.keys.borrow().get(key).map(|(k, _)| k.clone()).ok_or(CustodyError::UnknownKey)
    }

    fn usage_log(&self) -> Vec<KeyUse> {
        self.log.borrow().clone()
    }
}

pub fn ceremony(authority: &str) -> Ceremony {
    Ceremony {
        authority: authority.into(),
        threshold: Threshold::DEFAULT,
        custodians: vec!["custodian-a".into(), "custodian-b".into(), "custodian-c".into()],
        witnesses: vec!["witness-1".into()],
        held_at: T0,
        not_before: T0,
        not_after: AuthorityTime(T0.0 + 5 * 365 * DAY),
    }
}

/// A request for a P-256 key with no identity, signed by the key (TRU-016).
pub fn request_for(key: &SigningKey) -> CertificateRequest {
    CertificateRequest::new(AuthorityPublicKey::P256(key.public_key()), None, &BTreeMap::new()).unwrap().signed_by(key).unwrap()
}

pub fn terms(purpose: Purpose, from: u64, to: u64, serial: u64) -> IssueTerms {
    IssueTerms { purpose, record: None, not_before: at(from), not_after: at(to), serial }
}

pub fn period_terms() -> RecordKeyTerms {
    RecordKeyTerms {
        period: CollectionPeriod::new(CollectionPeriodId::new("2027-28").unwrap(), at(30), at(300)).unwrap(),
        retention: Retention(365 * DAY),
    }
}

/// An authority: a root in custody, purpose keys whose signing keys the test also holds,
/// and a trust bundle listing them.
pub struct World {
    pub custody: LabelCustody,
    pub ceremony: CeremonyRecord,
    pub root: KeyCertificate,
    pub factory_key: SigningKey,
    pub factory: KeyCertificate,
    pub receipt_key: SigningKey,
    pub receipt: KeyCertificate,
    pub receiver_key: SigningKey,
    pub receiver: KeyCertificate,
    pub record: KeyCertificate,
    pub bundle: TrustBundle,
}

pub fn contents(name: &str, version: &str, root: &KeyCertificate, certs: Vec<KeyCertificate>) -> TrustBundleContents {
    TrustBundleContents {
        name: name.into(),
        version: BundleVersion::parse(version).unwrap(),
        issued: at(1),
        roots: vec![root.clone()],
        certificates: certs,
        publishers: BTreeMap::new(),
        attestation_roots: BTreeMap::from([("android-key-attestation".to_owned(), vec![b"DER root".to_vec()])]),
        runtime_builds: vec![RuntimeBuild {
            platform: "android".into(),
            app_id: "dev.fieldseal.collect".into(),
            signing_digests: vec![sha256(b"signing certificate")],
        }],
        logs: vec![LogPin { origin: "log.example.org/v1".into(), public_key: log_key(), format: "c2sp-tlog-checkpoint".into() }],
        revocations: Vec::new(),
    }
}

pub fn world() -> World {
    let custody = LabelCustody::default();
    custody.next_label("root");
    let ceremony = Authority::new(&custody, "ceremony").init_root(ceremony("example-authority")).unwrap();
    let root = ceremony.root.clone();
    let authority = Authority::new(&custody, "ceremony");

    let factory_key = signing_key("factory");
    let factory = authority.issue(&root, &request_for(&factory_key), terms(Purpose::Factory, 0, 300, 1)).unwrap();
    let receipt_key = signing_key("receipt");
    let receipt = authority.issue(&root, &request_for(&receipt_key), terms(Purpose::Receipt, 0, 300, 2)).unwrap();
    let receiver_key = signing_key("receiver");
    let receiver = authority.issue(&root, &request_for(&receiver_key), terms(Purpose::Receiver, 0, 300, 3)).unwrap();

    custody.next_label("record-2027-28");
    let record_key = custody.generate(KeyRole::Purpose(Purpose::Record), KeyAlgorithm::X25519).unwrap();
    let record_request = CertificateRequest::new(record_key.public_key.clone(), Some(Purpose::Record), &BTreeMap::new()).unwrap();
    let record = authority.open_collection_period(&root, &record_request, period_terms(), at(0), 4).unwrap();

    let bundle = authority
        .build_bundle(
            contents("example-authority", "1.0.0", &root, vec![factory.clone(), receipt.clone(), receiver.clone(), record.clone()]),
            &[&root],
            None,
        )
        .unwrap();
    World { custody, ceremony, root, factory_key, factory, receipt_key, receipt, receiver_key, receiver, record, bundle }
}

/// A valid P-256 public key for the pinned log (WIRE-195 requires a point on the curve).
pub fn log_key() -> Vec<u8> {
    fieldseal_kernel::sign::SigningKey::from_scalar(&[0x42; 32]).expect("valid scalar").public_key().as_bytes().to_vec()
}
