//! A practice authority and a practice device: real keys, real seals and real signatures
//! from fixed seeds, so every run gives the same bytes. They build the exports that the
//! intake tests, `fieldseal intake` and conformance runs feed to the gate.
//!
//! **Not a device:** the practice device writes whatever records it is told to, in whatever
//! order, so that tests can break each rule on purpose. Nothing here is attested; production
//! factory policy refuses software keys (TRU-061).

use std::collections::BTreeMap;

use fieldseal_intake::wire::{
    CertWindow, CloseCertificate, ExportManifest, KeyEntry, ManifestEnd, Payload, RegistrationBody, TenancyCertificate,
};
use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::{P256PublicKey, Purpose, tags};
use fieldseal_kernel::digest::{key_id, sha256};
use fieldseal_kernel::export::{ExportFile, ExportHeader, ExportPart};
use fieldseal_kernel::frame::frame;
use fieldseal_kernel::id::{CollectionPeriodId, Digest, KeyId, RecordId, TenancyHandle, TenancyId};
use fieldseal_kernel::payload::Tick;
use fieldseal_kernel::record::{Record, RecordHeader, record_hash, record_id_from_random};
use fieldseal_kernel::seal::{RecipientKey, SealedBox, seal_value};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, WireError};
use fieldseal_trust::application::Authority;
use fieldseal_trust::domain::{
    BundleVersion, Ceremony, CertificateRequest, CollectionPeriod, CustodyKey, IssueTerms, KeyAlgorithm, KeyCertificate,
    KeyRole, RecordKeyTerms, Retention, Threshold, TrustBundle, TrustBundleContents,
};
use fieldseal_trust::ports::{KeyCustody, SourceRng};

use crate::trust::{MemoryKeyCustody, SeededRandom};

/// 2027-01-15T08:00:00Z, the practice authority's epoch, in milliseconds.
pub const T0: AuthorityTime = AuthorityTime(1_800_000_000_000);
/// One day, in milliseconds.
pub const DAY: u64 = AuthorityTime::DAY;

/// `T0` plus `days`.
pub fn at(days: u64) -> AuthorityTime {
    AuthorityTime(T0.0 + days * DAY)
}

/// The caller name practice authority operations log under.
pub const CALLER: &str = "practice";

/// A practice authority: a root, a registration key (to sign certificates and to open
/// registration requests), a receipt key, a record key for one collection period and a
/// trust bundle listing them, with the private keys held by an in-memory key custody.
pub struct PracticeAuthority {
    /// The key custody holding every private key.
    pub custody: MemoryKeyCustody<SeededRandom>,
    /// The root certificate.
    pub root: KeyCertificate,
    /// The trust bundle components verify against.
    pub bundle: TrustBundle,
    /// The registration signing key (P-256): signs tenancy and close certificates.
    pub registration_signer: KeyId,
    /// The registration key that opens requests and unregistered manifests (X25519).
    pub registration_opener: CustodyKey,
    /// The receipt key (P-256).
    pub receipt_key: KeyId,
    /// The record key of the collection period (X25519).
    pub record_key: CustodyKey,
    /// The receiver key (P-256) that answers upload challenges (WIRE-181).
    pub receiver_key: KeyId,
    /// The receiver key's certificate, as listed in the trust bundle.
    pub receiver_certificate: KeyCertificate,
}

impl PracticeAuthority {
    /// An authority whose keys come from `seed`.
    pub fn new(seed: u64) -> Self {
        let custody = MemoryKeyCustody::new(SeededRandom::new(seed));
        let a = Authority::new(&custody, CALLER);
        let ceremony = Ceremony {
            authority: "practice-authority".into(),
            threshold: Threshold::DEFAULT,
            custodians: vec!["custodian-a".into(), "custodian-b".into(), "custodian-c".into()],
            witnesses: vec!["witness-1".into()],
            held_at: T0,
            not_before: T0,
            not_after: at(5 * 365),
        };
        let root = a.init_root(ceremony).expect("practice ceremony").root;
        let registration = custody.generate(KeyRole::Purpose(Purpose::Registration), KeyAlgorithm::P256).expect("key");
        let opener = custody.generate(KeyRole::Purpose(Purpose::Registration), KeyAlgorithm::X25519).expect("key");
        let receipt = custody.generate(KeyRole::Purpose(Purpose::Receipt), KeyAlgorithm::P256).expect("key");
        let record = custody.generate(KeyRole::Purpose(Purpose::Record), KeyAlgorithm::X25519).expect("key");
        // Generated last, so the keys above keep the bytes earlier seeds gave them.
        let receiver = custody.generate(KeyRole::Purpose(Purpose::Receiver), KeyAlgorithm::P256).expect("key");
        let terms = |purpose, serial| IssueTerms { purpose, record: None, not_before: at(0), not_after: at(300), serial };
        let reg_cert = a
            .issue(&root, &a.request(&registration.id, Some(Purpose::Registration)).expect("request"), terms(Purpose::Registration, 1))
            .expect("certificate");
        let receipt_cert = a
            .issue(&root, &a.request(&receipt.id, Some(Purpose::Receipt)).expect("request"), terms(Purpose::Receipt, 2))
            .expect("certificate");
        let receiver_cert = a
            .issue(&root, &a.request(&receiver.id, Some(Purpose::Receiver)).expect("request"), terms(Purpose::Receiver, 4))
            .expect("certificate");
        let record_request = CertificateRequest::new(record.public_key.clone(), Some(Purpose::Record), &BTreeMap::new()).expect("request");
        let record_cert = a
            .open_collection_period(
                &root,
                &record_request,
                RecordKeyTerms {
                    period: CollectionPeriod::new(CollectionPeriodId::new("practice-period").expect("id"), at(30), at(300)).expect("period"),
                    retention: Retention(365 * DAY),
                },
                at(0),
                3,
            )
            .expect("certificate");
        let bundle = a
            .build_bundle(
                TrustBundleContents {
                    name: "practice-authority".into(),
                    version: BundleVersion::parse("1.0.0").expect("version"),
                    issued: at(1),
                    roots: vec![root.clone()],
                    certificates: vec![reg_cert, receipt_cert, record_cert, receiver_cert.clone()],
                    ..TrustBundleContents::default()
                },
                &[&root],
                None,
            )
            .expect("bundle");
        Self {
            custody,
            root,
            bundle,
            registration_signer: registration.id,
            registration_opener: opener,
            receipt_key: receipt.id,
            record_key: record,
            receiver_key: receiver.id,
            receiver_certificate: receiver_cert,
        }
    }

    /// The record key as a seal recipient.
    pub fn record_recipient(&self) -> RecipientKey {
        recipient(&self.record_key)
    }

    /// The registration opener as a seal recipient.
    pub fn registration_recipient(&self) -> RecipientKey {
        recipient(&self.registration_opener)
    }

    /// Signs a tenancy certificate for `device` with the registration key.
    pub fn tenancy_certificate(&self, device: &PracticeDevice, window: CertWindow, cohorts: &[(&str, u64)]) -> TenancyCertificate {
        self.tenancy_certificate_for(device.tenancy, device.handle, device.signing.public_key(), window, cohorts)
    }

    /// Signs a tenancy certificate for any device: its tenancy, export handle and signing
    /// key (also used as the agreement key here), as a runtime reports them.
    pub fn tenancy_certificate_for(
        &self,
        tenancy: TenancyId,
        handle: TenancyHandle,
        signing: P256PublicKey,
        window: CertWindow,
        cohorts: &[(&str, u64)],
    ) -> TenancyCertificate {
        let mut cert = TenancyCertificate {
            tenancy,
            collector: b"collector-ref".to_vec(),
            handle,
            keys: vec![(0, signing.clone())],
            agree_pub: signing,
            period: self.record_key.id,
            window,
            cohorts: cohorts.iter().map(|(c, g)| ((*c).to_owned(), *g)).collect(),
            serial: None,
            issued: at(2),
            policy: sha256(b"practice factory policy"),
            signer: self.registration_signer,
            sig: fieldseal_kernel::crypto::Signature(vec![0; 64]),
        };
        cert.sig = self
            .custody
            .sign(&self.registration_signer, KeyRole::Purpose(Purpose::Registration), &tags::TENANCY_CERTIFICATE, &cert.signed_structure(), CALLER)
            .expect("registration key signs");
        cert
    }

    /// Signs a close certificate for `device` with the registration key.
    pub fn close_certificate(&self, device: &PracticeDevice, cutoff_seq: u64) -> CloseCertificate {
        let mut c = CloseCertificate {
            tenancy: device.tenancy,
            cutoff_seq,
            reason: "absent".into(),
            issued: at(40),
            signer: self.registration_signer,
            sig: fieldseal_kernel::crypto::Signature(vec![0; 64]),
        };
        c.sig = self
            .custody
            .sign(&self.registration_signer, KeyRole::Purpose(Purpose::Registration), &tags::CLOSE_CERTIFICATE, &c.signed_structure(), CALLER)
            .expect("registration key signs");
        c
    }

    /// A registration request for `device`, sealed to the registration opener (WIRE-134).
    pub fn registration_request(&self, device: &PracticeDevice) -> SealedBox {
        self.registration_request_with(device, &[])
    }

    /// A registration request carrying `extra` fields next to `body` and `pop` (a malformed
    /// request, for tests of the gate's closed-schema check).
    pub fn registration_request_with(&self, device: &PracticeDevice, extra: &[(&str, Value)]) -> SealedBox {
        let body = RegistrationBody {
            token: [1; 16],
            nonce: [2; 32],
            tenancy: device.tenancy,
            sign_pub: device.signing.public_key(),
            agree_pub: device.signing.public_key(),
            build: "practice-build".into(),
        };
        let body_v = body.to_value();
        let body_sha = sha256(&cbor::encode(&body_v).expect("encodes"));
        let pop = device
            .signing
            .sign(
                &tags::REGISTRATION_POP,
                &cbor::map([("nonce", Value::Bytes(body.nonce.to_vec())), ("body_sha256", Value::Bytes(body_sha.as_bytes().to_vec()))]),
            )
            .expect("signs");
        let mut fields = vec![("body", body_v), ("pop", Value::Bytes(pop.0))];
        fields.extend(extra.iter().cloned());
        let plain = cbor::map(fields);
        seal_value(&mut SourceRng(&device.rng), &self.registration_recipient(), &tags::REGISTRATION_SEAL, &plain).expect("seals")
    }
}

fn recipient(key: &CustodyKey) -> RecipientKey {
    match key.public_key.as_p256() {
        Some(p) => RecipientKey::P256(p.clone()),
        None => {
            let mut k = [0u8; 32];
            k.copy_from_slice(key.public_key.encoded());
            RecipientKey::X25519(k)
        }
    }
}

/// A practice device: a fixed signing key, a tenancy and a handle derived from a label.
pub struct PracticeDevice {
    /// The tenancy signing key.
    pub signing: SigningKey,
    /// The tenancy, SHA-256 of the signing public key.
    pub tenancy: TenancyId,
    /// The export handle.
    pub handle: TenancyHandle,
    rng: SeededRandom,
}

impl PracticeDevice {
    /// A device whose keys derive from `label`.
    pub fn new(label: &str) -> Self {
        let seed = sha256(format!("fieldseal.dev/practice/device/{label}").as_bytes());
        let signing = SigningKey::from_scalar(seed.as_bytes()).expect("a SHA-256 is a valid scalar");
        let tenancy = TenancyId::from(*sha256(signing.public_key().as_bytes()).as_bytes());
        let handle_src = sha256(format!("fieldseal.dev/practice/handle/{label}").as_bytes());
        let mut handle = [0u8; 16];
        handle.copy_from_slice(&handle_src.as_bytes()[..16]);
        let n = u64::from_be_bytes(handle[..8].try_into().expect("8 bytes"));
        Self { signing, tenancy, handle: TenancyHandle::from(handle), rng: SeededRandom::new(n) }
    }

    /// A device whose signing key and export handle come from a registration (for example the
    /// key a software device registered with a factory, and the handle in the factory's
    /// tenancy certificate), instead of from a label. The randomness for its seals is seeded
    /// from `entropy`, which the caller draws from the operating system.
    pub fn registered(signing: SigningKey, handle: TenancyHandle, entropy: u64) -> Self {
        let tenancy = TenancyId::from(*sha256(signing.public_key().as_bytes()).as_bytes());
        Self { signing, tenancy, handle, rng: SeededRandom::new(entropy) }
    }

    /// The signing public key.
    pub fn public_key(&self) -> P256PublicKey {
        self.signing.public_key()
    }

    /// A journal that writes records to `period` (the authority's record key).
    pub fn journal<'a>(&'a self, recipient: RecipientKey, period: KeyId) -> JournalBuilder<'a> {
        JournalBuilder { device: self, recipient, period, key: 0, next_seq: 0, prev: Digest::from([0; 32]), counter: 0, frames: Vec::new(), records: Vec::new() }
    }
}

/// One record as written: its frame, body bytes, hash and identity.
#[derive(Clone, Debug)]
pub struct Written {
    /// The record's ID.
    pub id: RecordId,
    /// Its `seq`.
    pub seq: u64,
    /// Its record hash.
    pub hash: Digest,
    /// The canonical body.
    pub body: Vec<u8>,
    /// The frame (magic, length, CRC and body).
    pub frame: Vec<u8>,
}

/// Writes a journal record by record: real payload seals and signatures, chained by `prev`.
pub struct JournalBuilder<'a> {
    device: &'a PracticeDevice,
    recipient: RecipientKey,
    period: KeyId,
    key: u64,
    next_seq: u64,
    prev: Digest,
    counter: u64,
    frames: Vec<u8>,
    records: Vec<Written>,
}

impl JournalBuilder<'_> {
    /// Writes records with the key at `index` of the history from now on.
    pub fn use_key(&mut self, index: u64) {
        self.key = index;
    }

    /// Starts the next record at `seq` instead of the next one, keeping `prev` (to break
    /// continuity on purpose).
    pub fn skip_to(&mut self, seq: u64) {
        self.next_seq = seq;
    }

    /// Overrides the hash the next record names as `prev` (to break the chain on purpose).
    pub fn set_prev(&mut self, prev: Digest) {
        self.prev = prev;
    }

    /// The record ID the n-th record written gets: deterministic and UUIDv4-shaped.
    pub fn record_id(&self, n: u64) -> RecordId {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&n.to_be_bytes());
        b[8..].copy_from_slice(&self.device.tenancy.as_bytes()[..8]);
        record_id_from_random(b)
    }

    /// Writes `payload` as the next record.
    pub fn push(&mut self, payload: &Payload) -> Written {
        self.push_with(payload, None)
    }

    /// Writes `payload` with the given record ID instead of the next generated one.
    pub fn push_with(&mut self, payload: &Payload, id: Option<RecordId>) -> Written {
        let value = payload.to_value().expect("payload encodes");
        let sealed = seal_value(&mut SourceRng(&self.device.rng), &self.recipient, &tags::RECORD_SEAL, &value).expect("seals");
        self.write(sealed, id)
    }

    /// Writes a record whose sealed payload has a flipped ciphertext byte, signed over the
    /// damaged seal: it verifies, but cannot be decrypted.
    pub fn push_corrupt(&mut self, payload: &Payload) -> Written {
        let value = payload.to_value().expect("payload encodes");
        let mut sealed = seal_value(&mut SourceRng(&self.device.rng), &self.recipient, &tags::RECORD_SEAL, &value).expect("seals");
        sealed.ct[0] ^= 0xff;
        self.write(sealed, None)
    }

    /// Writes a record whose sealed plaintext is `plaintext`, whatever it is.
    pub fn push_plaintext(&mut self, plaintext: &[u8]) -> Written {
        let sealed = fieldseal_kernel::seal::seal(&mut SourceRng(&self.device.rng), &self.recipient, &tags::RECORD_SEAL, plaintext).expect("seals");
        self.write(sealed, None)
    }

    fn write(&mut self, sealed: SealedBox, id: Option<RecordId>) -> Written {
        let id = id.unwrap_or_else(|| self.record_id(self.counter));
        self.counter += 1;
        let header = RecordHeader { record_id: id, seq: self.next_seq, prev: self.prev, key: self.key, period: self.period };
        let record = Record::sign(&self.device.signing, header, sealed).expect("signs");
        let body = record.encode().expect("encodes");
        let hash = record_hash(&body);
        let framed = frame(&body).expect("frames");
        let w = Written { id, seq: self.next_seq, hash, body, frame: framed };
        self.frames.extend_from_slice(&w.frame);
        self.records.push(w.clone());
        self.next_seq += 1;
        self.prev = hash;
        w
    }

    /// Writes a record whose payload is sealed to `recipient` instead of the journal's.
    pub fn push_sealed_to(&mut self, payload: &Payload, recipient: &RecipientKey, period: KeyId) -> Written {
        let (r, p) = (std::mem::replace(&mut self.recipient, recipient.clone()), std::mem::replace(&mut self.period, period));
        let w = self.push(payload);
        self.recipient = r;
        self.period = p;
        w
    }

    /// The journal so far: every frame, in order.
    pub fn journal(&self) -> Vec<u8> {
        self.frames.clone()
    }

    /// The records written so far.
    pub fn records(&self) -> &[Written] {
        &self.records
    }

    /// The `open` payload for this device (WIRE-062) with `tick`.
    pub fn open_payload(&self, tick: Tick, build_anchor: Digest) -> Payload {
        Payload::Open {
            tick,
            tenancy: Digest::from(*self.device.tenancy.as_bytes()),
            sign_pub: self.device.signing.public_key(),
            agree_pub: self.device.signing.public_key(),
            evidence: vec![],
            build_anchor,
        }
    }
}

/// A tick at `slot` under `anchor`.
pub fn tick(anchor: Digest, slot: u64) -> Tick {
    Tick { anchor, slot, boot: 1, wall: None }
}

/// The manifest for `journal` written by `device`, as `Written` records describe it.
pub fn manifest_for(device: &PracticeDevice, records: &[Written], journal: &[u8], build_anchor: Digest) -> ExportManifest {
    let first = records.first().expect("a journal has records");
    let last = records.last().expect("a journal has records");
    ExportManifest {
        tenancy: device.tenancy,
        certificate: None,
        registration: None,
        keys: vec![KeyEntry { index: 0, public_key: device.signing.public_key(), evidence: Digest::from([0; 32]) }],
        records: records.len() as u64,
        first_seq: first.seq,
        last_seq: last.seq,
        first_hash: first.hash,
        last_hash: last.hash,
        journal_sha256: sha256(journal),
        end: None,
        build_anchor,
        instruments: vec![],
        policy: sha256(b"practice runtime policy"),
    }
}

/// How an export is sealed and signed.
pub struct ExportSpec<'a> {
    /// The device.
    pub device: &'a PracticeDevice,
    /// The manifest (its `journal_sha256` is taken from `journal` if `refresh` is set).
    pub manifest: ExportManifest,
    /// The journal section body.
    pub journal: Vec<u8>,
    /// Who the manifest is sealed to.
    pub seal_to: RecipientKey,
    /// The key index the export is signed with.
    pub key_index: u64,
    /// Whether to append parity.
    pub parity: bool,
}

impl ExportSpec<'_> {
    /// Seals the manifest, signs the export with the device and encodes the file.
    pub fn build(&self) -> Result<Vec<u8>, WireError> {
        let header = ExportHeader { handle: self.device.handle, parts: 1 };
        let manifest = seal_value(&mut SourceRng(&self.device.rng), &self.seal_to, &tags::EXPORT_MANIFEST_SEAL, &self.manifest.to_value())?;
        let part = ExportPart::sign(&header, manifest.encode(), self.journal.clone(), &self.device.signing, self.key_index)?;
        ExportFile { header, parts: vec![part] }.encode(self.parity)
    }
}

/// The public key of the practice device, as a manifest key entry.
pub fn key_entry(index: u64, key: P256PublicKey) -> KeyEntry {
    KeyEntry { index, public_key: key, evidence: Digest::from([0; 32]) }
}

/// The ID a key's public bytes give (WIRE-010).
pub fn key_id_of(key: &P256PublicKey) -> KeyId {
    key_id(key.as_bytes())
}

/// The manifest end naming a closing record.
pub fn closing(hash: Digest) -> ManifestEnd {
    ManifestEnd::Closing(hash)
}
