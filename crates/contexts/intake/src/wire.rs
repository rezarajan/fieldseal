//! The wire structures intake reads and writes beyond the kernel's export, record and
//! `items` types (WIRE §6.3, §6.5, §6.6): the export manifest, the tenancy and close
//! certificates, the registration request, the record payload types and receipts.
//!
//! Decoders reject unknown fields (WIRE-005) and return a WIRE error code, never a partial
//! value. Every structure also encodes, so fixtures and the CLI build real bytes.

use std::collections::BTreeMap;

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::{P256PublicKey, Signature};
use fieldseal_kernel::id::{Digest, KeyId, RecordId, TenancyHandle, TenancyId};
use fieldseal_kernel::payload::{ItemsPayload, Tick};
use fieldseal_kernel::seal::SealedBox;
use fieldseal_kernel::structure::{Fields, expect_bytes, expect_bytes_n, expect_uint};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{ErrorCode, Value, WireError};

fn bad(detail: &'static str) -> WireError {
    WireError::new(ErrorCode::UnknownField, 0, detail)
}

/// The media types an evidence image may carry (WIRE-214): the photographs a
/// device captures. Kept equal to the collection context's set.
pub const EVIDENCE_MEDIA_TYPES: [&str; 3] = ["image/jpeg", "image/png", "image/webp"];

fn evidence_media(media_type: String) -> Result<String, WireError> {
    if EVIDENCE_MEDIA_TYPES.contains(&media_type.as_str()) {
        Ok(media_type)
    } else {
        Err(bad("evidence media_type is not an allowed evidence media type"))
    }
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn uint(n: u64) -> Value {
    Value::Int(i128::from(n))
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn digest_array(v: Vec<Value>) -> Result<Vec<Digest>, WireError> {
    v.into_iter().map(|d| expect_bytes_n::<32>(d).map(Digest::from)).collect()
}

fn pubkey(v: Value) -> Result<P256PublicKey, WireError> {
    P256PublicKey::from_bytes(&expect_bytes(v)?).map_err(|_| bad("not a P-256 public key"))
}

/// One entry of a tenancy's key history (WIRE-104).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyEntry {
    /// The index records and signatures name.
    pub index: u64,
    /// The signing public key.
    pub public_key: P256PublicKey,
    /// The content address of its attestation evidence.
    pub evidence: Digest,
}

/// A close or reset certificate (WIRE-141, `cutoff_seq` is the highest `seq` the authority
/// had received).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CloseCertificate {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The highest `seq` to accept without a flag.
    pub cutoff_seq: u64,
    /// Why it was issued.
    pub reason: String,
    /// When it was issued.
    pub issued: AuthorityTime,
    /// The registration key that signed it.
    pub signer: KeyId,
    /// The signature.
    pub sig: Signature,
}

impl CloseCertificate {
    /// The structure the signature covers: every field but `sig` (WIRE-021).
    pub fn signed_structure(&self) -> Value {
        cbor::map([
            ("v", uint(1)),
            ("tenancy", bytes(self.tenancy.as_bytes())),
            ("cutoff_seq", uint(self.cutoff_seq)),
            ("reason", text(&self.reason)),
            ("issued", uint(self.issued.0)),
            ("signer", bytes(self.signer.as_bytes())),
        ])
    }

    /// The certificate as a value.
    pub fn to_value(&self) -> Value {
        let Value::Map(mut m) = self.signed_structure() else { unreachable!("a map") };
        m.insert("sig".to_owned(), Value::Bytes(self.sig.0.clone()));
        Value::Map(m)
    }

    /// Reads a certificate.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        f.version("v", &uint(1))?;
        let c = Self {
            tenancy: TenancyId::from(f.bytes_n::<32>("tenancy")?),
            cutoff_seq: f.uint("cutoff_seq")?,
            reason: f.text("reason")?,
            issued: AuthorityTime(f.uint("issued")?),
            signer: KeyId::from(f.bytes_n::<16>("signer")?),
            sig: Signature(f.bytes_n::<64>("sig")?.to_vec()),
        };
        f.finish()?;
        Ok(c)
    }
}

/// The end of a journal as the manifest states it (WIRE-104).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ManifestEnd {
    /// The hash of the closing record.
    Closing(Digest),
    /// A close or reset certificate.
    Certificate(CloseCertificate),
}

/// The export manifest (WIRE §6.5), the plaintext of the sealed manifest section.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExportManifest {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The tenancy certificate, if held.
    pub certificate: Option<TenancyCertificate>,
    /// The latest registration request, sealed to the registration key.
    pub registration: Option<SealedBox>,
    /// The key history.
    pub keys: Vec<KeyEntry>,
    /// The number of records in the journal section.
    pub records: u64,
    /// The first `seq` present.
    pub first_seq: u64,
    /// The last `seq` present.
    pub last_seq: u64,
    /// The hash of the first record present.
    pub first_hash: Digest,
    /// The hash of the last record present.
    pub last_hash: Digest,
    /// SHA-256 of the journal section body.
    pub journal_sha256: Digest,
    /// The closing record's hash, or a close or reset certificate.
    pub end: Option<ManifestEnd>,
    /// The runtime build's release anchor.
    pub build_anchor: Digest,
    /// The instruments in use.
    pub instruments: Vec<Digest>,
    /// The policy in use.
    pub policy: Digest,
}

impl ExportManifest {
    /// The manifest as a value.
    pub fn to_value(&self) -> Value {
        let keys = self
            .keys
            .iter()
            .map(|k| {
                cbor::map([
                    ("index", uint(k.index)),
                    ("public_key", bytes(k.public_key.as_bytes())),
                    ("evidence", bytes(k.evidence.as_bytes())),
                ])
            })
            .collect();
        let mut m = BTreeMap::from([
            ("tenancy".to_owned(), bytes(self.tenancy.as_bytes())),
            ("keys".to_owned(), Value::Array(keys)),
            ("records".to_owned(), uint(self.records)),
            ("first_seq".to_owned(), uint(self.first_seq)),
            ("last_seq".to_owned(), uint(self.last_seq)),
            ("first_hash".to_owned(), bytes(self.first_hash.as_bytes())),
            ("last_hash".to_owned(), bytes(self.last_hash.as_bytes())),
            ("journal_sha256".to_owned(), bytes(self.journal_sha256.as_bytes())),
            ("build_anchor".to_owned(), bytes(self.build_anchor.as_bytes())),
            ("instruments".to_owned(), Value::Array(self.instruments.iter().map(|d| bytes(d.as_bytes())).collect())),
            ("policy".to_owned(), bytes(self.policy.as_bytes())),
        ]);
        if let Some(c) = &self.certificate {
            m.insert("certificate".to_owned(), c.to_value());
        }
        if let Some(r) = &self.registration {
            m.insert("registration".to_owned(), r.to_value());
        }
        match &self.end {
            Some(ManifestEnd::Closing(h)) => {
                m.insert("end".to_owned(), bytes(h.as_bytes()));
            }
            Some(ManifestEnd::Certificate(c)) => {
                m.insert("end".to_owned(), c.to_value());
            }
            None => {}
        }
        Value::Map(m)
    }

    /// Canonical bytes of the manifest (the plaintext that gets sealed).
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        cbor::encode(&self.to_value())
    }

    /// Reads a manifest.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        let tenancy = TenancyId::from(f.bytes_n::<32>("tenancy")?);
        let certificate = f.take_opt("certificate").map(TenancyCertificate::from_value).transpose()?;
        let registration = f.take_opt("registration").map(SealedBox::from_value).transpose()?;
        let keys = f
            .array("keys")?
            .into_iter()
            .map(|k| {
                let mut kf = Fields::new(k)?;
                let e = KeyEntry {
                    index: kf.uint("index")?,
                    public_key: pubkey(kf.take("public_key")?)?,
                    evidence: Digest::from(kf.bytes_n::<32>("evidence")?),
                };
                kf.finish()?;
                Ok(e)
            })
            .collect::<Result<Vec<_>, WireError>>()?;
        let records = f.uint("records")?;
        let first_seq = f.uint("first_seq")?;
        let last_seq = f.uint("last_seq")?;
        let first_hash = Digest::from(f.bytes_n::<32>("first_hash")?);
        let last_hash = Digest::from(f.bytes_n::<32>("last_hash")?);
        let journal_sha256 = Digest::from(f.bytes_n::<32>("journal_sha256")?);
        let end = match f.take_opt("end") {
            None => None,
            Some(Value::Bytes(b)) => Some(ManifestEnd::Closing(Digest::from(
                <[u8; 32]>::try_from(b).map_err(|_| bad("end hash must be 32 bytes"))?,
            ))),
            Some(v) => Some(ManifestEnd::Certificate(CloseCertificate::from_value(v)?)),
        };
        let build_anchor = Digest::from(f.bytes_n::<32>("build_anchor")?);
        let instruments = digest_array(f.array("instruments")?)?;
        let policy = Digest::from(f.bytes_n::<32>("policy")?);
        f.finish()?;
        Ok(Self {
            tenancy,
            certificate,
            registration,
            keys,
            records,
            first_seq,
            last_seq,
            first_hash,
            last_hash,
            journal_sha256,
            end,
            build_anchor,
            instruments,
            policy,
        })
    }
}

/// A tenancy certificate's window (WIRE-140); times and `grace` in milliseconds (WIRE-008).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CertWindow {
    /// Earliest authority time records are expected.
    pub not_before: AuthorityTime,
    /// Latest authority time records are expected.
    pub not_after: AuthorityTime,
    /// Milliseconds after `not_after` before a delivery counts as late.
    pub grace: u64,
}

/// The tenancy certificate as it appears in an export (WIRE-140, §6.6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TenancyCertificate {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The opaque collector reference.
    pub collector: Vec<u8>,
    /// The export handle.
    pub handle: TenancyHandle,
    /// The key history `(index, public key)`.
    pub keys: Vec<(u64, P256PublicKey)>,
    /// The agreement public key.
    pub agree_pub: P256PublicKey,
    /// The authority record key of the collection period.
    pub period: KeyId,
    /// The window.
    pub window: CertWindow,
    /// Cohorts with the tenancy's generation for each.
    pub cohorts: Vec<(String, u64)>,
    /// The device serial, if attested and required.
    pub serial: Option<String>,
    /// When it was issued.
    pub issued: AuthorityTime,
    /// The factory policy that approved it.
    pub policy: Digest,
    /// The registration key that signed it.
    pub signer: KeyId,
    /// The signature.
    pub sig: Signature,
}

impl TenancyCertificate {
    /// The structure the signature covers: every field but `sig` (WIRE-021).
    pub fn signed_structure(&self) -> Value {
        let keys = self
            .keys
            .iter()
            .map(|(i, k)| cbor::map([("index", uint(*i)), ("public_key", bytes(k.as_bytes()))]))
            .collect();
        let cohorts = self.cohorts.iter().map(|(c, g)| cbor::map([("cohort", text(c)), ("generation", uint(*g))])).collect();
        let mut m = BTreeMap::from([
            ("v".to_owned(), uint(1)),
            ("tenancy".to_owned(), bytes(self.tenancy.as_bytes())),
            ("collector".to_owned(), bytes(&self.collector)),
            ("handle".to_owned(), bytes(self.handle.as_bytes())),
            ("keys".to_owned(), Value::Array(keys)),
            ("agree_pub".to_owned(), bytes(self.agree_pub.as_bytes())),
            ("period".to_owned(), bytes(self.period.as_bytes())),
            (
                "window".to_owned(),
                cbor::map([
                    ("not_before", uint(self.window.not_before.0)),
                    ("not_after", uint(self.window.not_after.0)),
                    ("grace", uint(self.window.grace)),
                ]),
            ),
            ("cohorts".to_owned(), Value::Array(cohorts)),
            ("issued".to_owned(), uint(self.issued.0)),
            ("policy".to_owned(), bytes(self.policy.as_bytes())),
            ("signer".to_owned(), bytes(self.signer.as_bytes())),
        ]);
        if let Some(s) = &self.serial {
            m.insert("serial".to_owned(), text(s));
        }
        Value::Map(m)
    }

    /// The certificate as a value.
    pub fn to_value(&self) -> Value {
        let Value::Map(mut m) = self.signed_structure() else { unreachable!("a map") };
        m.insert("sig".to_owned(), Value::Bytes(self.sig.0.clone()));
        Value::Map(m)
    }

    /// Reads a certificate.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        f.version("v", &uint(1))?;
        let tenancy = TenancyId::from(f.bytes_n::<32>("tenancy")?);
        let collector = f.bytes("collector")?;
        let handle = TenancyHandle::from(f.bytes_n::<16>("handle")?);
        let keys = f
            .array("keys")?
            .into_iter()
            .map(|k| {
                let mut kf = Fields::new(k)?;
                let e = (kf.uint("index")?, pubkey(kf.take("public_key")?)?);
                kf.finish()?;
                Ok(e)
            })
            .collect::<Result<Vec<_>, WireError>>()?;
        let agree_pub = pubkey(f.take("agree_pub")?)?;
        let period = KeyId::from(f.bytes_n::<16>("period")?);
        let window = {
            let mut w = Fields::new(f.take("window")?)?;
            let window = CertWindow {
                not_before: AuthorityTime(w.uint("not_before")?),
                not_after: AuthorityTime(w.uint("not_after")?),
                grace: w.uint("grace")?,
            };
            w.finish()?;
            window
        };
        let cohorts = f
            .array("cohorts")?
            .into_iter()
            .map(|c| {
                let mut cf = Fields::new(c)?;
                let e = (cf.text("cohort")?, cf.uint("generation")?);
                cf.finish()?;
                Ok(e)
            })
            .collect::<Result<Vec<_>, WireError>>()?;
        let serial = f.take_opt("serial").map(|v| match v {
            Value::Text(t) => Ok(t),
            _ => Err(bad("serial is text")),
        });
        let serial = serial.transpose()?;
        let issued = AuthorityTime(f.uint("issued")?);
        let policy = Digest::from(f.bytes_n::<32>("policy")?);
        let signer = KeyId::from(f.bytes_n::<16>("signer")?);
        let sig = Signature(f.bytes_n::<64>("sig")?.to_vec());
        f.finish()?;
        Ok(Self { tenancy, collector, handle, keys, agree_pub, period, window, cohorts, serial, issued, policy, signer, sig })
    }
}

/// A registration request body (WIRE-130), the part intake needs to register a tenancy from
/// a manifest (INT-004).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegistrationBody {
    /// The registration token's identifier.
    pub token: [u8; 16],
    /// The nonce.
    pub nonce: [u8; 32],
    /// The tenancy, the SHA-256 of `sign_pub` (WIRE-131).
    pub tenancy: TenancyId,
    /// The signing public key.
    pub sign_pub: P256PublicKey,
    /// The agreement public key.
    pub agree_pub: P256PublicKey,
    /// The runtime build.
    pub build: String,
}

impl RegistrationBody {
    /// The body as a value (`nonce_source` is written as `device`; `evidence` is empty here:
    /// attestation evidence is Registration's to verify).
    pub fn to_value(&self) -> Value {
        cbor::map([
            ("v", uint(1)),
            ("token", bytes(&self.token)),
            ("nonce", bytes(&self.nonce)),
            ("nonce_source", text("device")),
            ("tenancy", bytes(self.tenancy.as_bytes())),
            ("sign_pub", bytes(self.sign_pub.as_bytes())),
            ("agree_pub", bytes(self.agree_pub.as_bytes())),
            ("evidence", Value::Array(vec![])),
            ("build", text(&self.build)),
        ])
    }

    /// Reads a body. The `evidence`, `prev_closing` and `label` fields are read and ignored.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        f.version("v", &uint(1))?;
        let body = Self {
            token: f.bytes_n::<16>("token")?,
            nonce: f.bytes_n::<32>("nonce")?,
            tenancy: {
                let _ = f.text("nonce_source")?;
                TenancyId::from(f.bytes_n::<32>("tenancy")?)
            },
            sign_pub: pubkey(f.take("sign_pub")?)?,
            agree_pub: pubkey(f.take("agree_pub")?)?,
            build: {
                let _ = f.array("evidence")?;
                f.text("build")?
            },
        };
        let _ = f.take_opt("prev_closing");
        let _ = f.take_opt("label");
        f.finish()?;
        Ok(body)
    }
}

/// The most a receipt's canonical CBOR may take (WIRE-144).
pub const MAX_RECEIPT: usize = 300;

/// A receipt (WIRE-142, §6.6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Receipt {
    /// The tenancy acknowledged.
    pub tenancy: TenancyId,
    /// The highest contiguous `seq` held.
    pub last_seq: u64,
    /// The record hash at `last_seq`.
    pub hash_at: Digest,
    /// The authority's receive time.
    pub received: AuthorityTime,
    /// The content address of the export or upload acknowledged.
    pub of: Digest,
    /// The receipt key that signed it.
    pub signer: KeyId,
    /// The signature.
    pub sig: Signature,
}

impl Receipt {
    /// The structure the signature covers: every field but `sig` (WIRE-021).
    pub fn signed_structure(&self) -> Value {
        Self::unsigned_structure(&self.tenancy, self.last_seq, &self.hash_at, self.received, &self.of, &self.signer)
    }

    /// The structure to sign for the given fields.
    pub fn unsigned_structure(
        tenancy: &TenancyId,
        last_seq: u64,
        hash_at: &Digest,
        received: AuthorityTime,
        of: &Digest,
        signer: &KeyId,
    ) -> Value {
        cbor::map([
            ("v", uint(1)),
            ("tenancy", bytes(tenancy.as_bytes())),
            ("last_seq", uint(last_seq)),
            ("hash_at", bytes(hash_at.as_bytes())),
            ("received", uint(received.0)),
            ("of", bytes(of.as_bytes())),
            ("signer", bytes(signer.as_bytes())),
        ])
    }

    /// The receipt as a value.
    pub fn to_value(&self) -> Value {
        let Value::Map(mut m) = self.signed_structure() else { unreachable!("a map") };
        m.insert("sig".to_owned(), Value::Bytes(self.sig.0.clone()));
        Value::Map(m)
    }

    /// Canonical bytes, at most 300 (WIRE-144).
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let b = cbor::encode(&self.to_value())?;
        if b.len() > MAX_RECEIPT {
            return Err(WireError::new(ErrorCode::Size, 0, "receipt exceeds 300 bytes"));
        }
        Ok(b)
    }

    /// Reads a receipt.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        f.version("v", &uint(1))?;
        let r = Self {
            tenancy: TenancyId::from(f.bytes_n::<32>("tenancy")?),
            last_seq: f.uint("last_seq")?,
            hash_at: Digest::from(f.bytes_n::<32>("hash_at")?),
            received: AuthorityTime(f.uint("received")?),
            of: Digest::from(f.bytes_n::<32>("of")?),
            signer: KeyId::from(f.bytes_n::<16>("signer")?),
            sig: Signature(f.bytes_n::<64>("sig")?.to_vec()),
        };
        f.finish()?;
        Ok(r)
    }

    /// Decodes canonical bytes, refusing input over 300 bytes before parsing (WIRE-144,
    /// WIRE-160).
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        Self::from_value(cbor::decode_limited(b, MAX_RECEIPT)?)
    }

    /// The text form `FS1R:…` for a QR code (WIRE-144).
    pub fn to_text(&self) -> Result<String, WireError> {
        Ok(fieldseal_kernel::text::encode(fieldseal_kernel::text::RECEIPT_PREFIX, &self.encode()?))
    }

    /// Reads the text form.
    pub fn from_text(input: &str) -> Result<Self, WireError> {
        Self::decode(&fieldseal_kernel::text::decode(fieldseal_kernel::text::RECEIPT_PREFIX, input)?)
    }
}

/// The kind of an anchor record (WIRE-057).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnchorKind {
    /// The runtime build.
    Build,
    /// An imported bundle.
    Bundle,
    /// An authority receipt.
    Receipt,
    /// A time token.
    TimeToken,
}

impl AnchorKind {
    fn name(self) -> &'static str {
        match self {
            AnchorKind::Build => "build",
            AnchorKind::Bundle => "bundle",
            AnchorKind::Receipt => "receipt",
            AnchorKind::TimeToken => "time-token",
        }
    }

    fn parse(t: &str) -> Result<Self, WireError> {
        Ok(match t {
            "build" => Self::Build,
            "bundle" => Self::Bundle,
            "receipt" => Self::Receipt,
            "time-token" => Self::TimeToken,
            _ => return Err(bad("unknown anchor kind")),
        })
    }
}

/// Why a journal was closed (WIRE-061).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClosingReason {
    /// The collector closed it.
    Collector,
    /// A close certificate.
    CloseCertificate,
    /// A reset certificate.
    ResetCertificate,
    /// The device was returned.
    Returned,
}

impl ClosingReason {
    fn name(self) -> &'static str {
        match self {
            ClosingReason::Collector => "collector",
            ClosingReason::CloseCertificate => "close-certificate",
            ClosingReason::ResetCertificate => "reset-certificate",
            ClosingReason::Returned => "returned",
        }
    }

    fn parse(t: &str) -> Result<Self, WireError> {
        Ok(match t {
            "collector" => Self::Collector,
            "close-certificate" => Self::CloseCertificate,
            "reset-certificate" => Self::ResetCertificate,
            "returned" => Self::Returned,
            _ => return Err(bad("unknown closing reason")),
        })
    }
}

/// A reference to evidence in a consent payload (WIRE-055).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EvidenceRef {
    /// The evidence record's `blob_id`.
    pub blob_id: [u8; 16],
    /// SHA-256 of the evidence bytes.
    pub sha256: Digest,
    /// The media type.
    pub media_type: String,
    /// The size in bytes.
    pub size: u64,
}

/// A roster version imported by the tenancy (WIRE-058).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ImportedRoster {
    /// The cohort.
    pub cohort: String,
    /// The version.
    pub version: u64,
    /// The roster's content address.
    pub address: Digest,
}

/// A decoded record payload (WIRE §6.3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Payload {
    /// `open` (WIRE-062).
    Open {
        /// The tick.
        tick: Tick,
        /// The tenancy.
        tenancy: Digest,
        /// The signing key.
        sign_pub: P256PublicKey,
        /// The agreement key.
        agree_pub: P256PublicKey,
        /// Attestation evidence addresses.
        evidence: Vec<Digest>,
        /// The build's release anchor.
        build_anchor: Digest,
    },
    /// `items` (WIRE-051).
    Items(Box<ItemsPayload>),
    /// `status` (WIRE-054).
    Status {
        /// The tick.
        tick: Tick,
        /// The instrument.
        instrument: Digest,
        /// The subject.
        subject: Vec<u8>,
        /// `absent`, `declined` or `not-subject`.
        status: String,
    },
    /// `consent` (WIRE-055).
    Consent {
        /// The tick.
        tick: Tick,
        /// The instrument.
        instrument: Digest,
        /// The subject.
        subject: Vec<u8>,
        /// The basis code.
        basis: String,
        /// The consent statement's content address.
        statement: Digest,
        /// Evidence references.
        evidence: Vec<EvidenceRef>,
    },
    /// `evidence` (WIRE-056).
    Evidence {
        /// The tick.
        tick: Tick,
        /// The blob identifier.
        blob_id: [u8; 16],
        /// The media type.
        media_type: String,
        /// The bytes.
        bytes: Vec<u8>,
    },
    /// `anchor` (WIRE-057).
    Anchor {
        /// The tick.
        tick: Tick,
        /// The kind.
        kind: AnchorKind,
        /// The anchor's content address.
        address: Digest,
        /// The authority time it states.
        authority_time: AuthorityTime,
    },
    /// `import` (WIRE-058).
    Import {
        /// The tick.
        tick: Tick,
        /// The bundle.
        bundle: Digest,
        /// The artefacts loaded.
        artefacts: Vec<Digest>,
        /// The rosters loaded.
        rosters: Vec<ImportedRoster>,
    },
    /// `key-roll` (WIRE-059).
    KeyRoll {
        /// The tick.
        tick: Tick,
        /// The new key's index.
        index: u64,
        /// The new key.
        public_key: P256PublicKey,
        /// Its evidence.
        evidence: Digest,
    },
    /// `checkpoint` (WIRE-060).
    Checkpoint {
        /// The tick.
        tick: Tick,
        /// The highest `seq` cleared.
        cleared_through: u64,
        /// The record hash at that `seq`.
        hash_at: Digest,
        /// The delivery evidence.
        delivery: Digest,
    },
    /// `closing` (WIRE-061).
    Closing {
        /// The tick.
        tick: Tick,
        /// Its own `seq`.
        last_seq: u64,
        /// The hash of the record before it.
        prev_hash: Digest,
        /// Why.
        reason: ClosingReason,
    },
}

impl Payload {
    /// The payload's tick (WIRE-050).
    pub fn tick(&self) -> &Tick {
        match self {
            Payload::Items(p) => &p.tick,
            Payload::Open { tick, .. }
            | Payload::Status { tick, .. }
            | Payload::Consent { tick, .. }
            | Payload::Evidence { tick, .. }
            | Payload::Anchor { tick, .. }
            | Payload::Import { tick, .. }
            | Payload::KeyRoll { tick, .. }
            | Payload::Checkpoint { tick, .. }
            | Payload::Closing { tick, .. } => tick,
        }
    }

    /// The payload's `type`.
    pub fn type_name(&self) -> &'static str {
        match self {
            Payload::Open { .. } => "open",
            Payload::Items(_) => "items",
            Payload::Status { .. } => "status",
            Payload::Consent { .. } => "consent",
            Payload::Evidence { .. } => "evidence",
            Payload::Anchor { .. } => "anchor",
            Payload::Import { .. } => "import",
            Payload::KeyRoll { .. } => "key-roll",
            Payload::Checkpoint { .. } => "checkpoint",
            Payload::Closing { .. } => "closing",
        }
    }

    /// The payload as a value.
    pub fn to_value(&self) -> Result<Value, WireError> {
        let t = |tick: &Tick, kind: &str, mut rest: Vec<(&'static str, Value)>| {
            rest.push(("type", text(kind)));
            rest.push(("tick", tick.to_value()));
            cbor::map(rest)
        };
        Ok(match self {
            Payload::Items(p) => p.to_value()?,
            Payload::Open { tick, tenancy, sign_pub, agree_pub, evidence, build_anchor } => t(
                tick,
                "open",
                vec![
                    ("tenancy", bytes(tenancy.as_bytes())),
                    ("sign_pub", bytes(sign_pub.as_bytes())),
                    ("agree_pub", bytes(agree_pub.as_bytes())),
                    ("evidence", Value::Array(evidence.iter().map(|d| bytes(d.as_bytes())).collect())),
                    ("build_anchor", bytes(build_anchor.as_bytes())),
                ],
            ),
            Payload::Status { tick, instrument, subject, status } => t(
                tick,
                "status",
                vec![("instrument", bytes(instrument.as_bytes())), ("subject", bytes(subject)), ("status", text(status))],
            ),
            Payload::Consent { tick, instrument, subject, basis, statement, evidence } => t(
                tick,
                "consent",
                vec![
                    ("instrument", bytes(instrument.as_bytes())),
                    ("subject", bytes(subject)),
                    ("basis", text(basis)),
                    ("statement", bytes(statement.as_bytes())),
                    (
                        "evidence",
                        Value::Array(
                            evidence
                                .iter()
                                .map(|e| {
                                    cbor::map([
                                        ("blob_id", bytes(&e.blob_id)),
                                        ("sha256", bytes(e.sha256.as_bytes())),
                                        ("media_type", text(&e.media_type)),
                                        ("size", uint(e.size)),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                ],
            ),
            Payload::Evidence { tick, blob_id, media_type, bytes: b } => {
                t(tick, "evidence", vec![("blob_id", bytes(blob_id)), ("media_type", text(media_type)), ("bytes", bytes(b))])
            }
            Payload::Anchor { tick, kind, address, authority_time } => t(
                tick,
                "anchor",
                vec![
                    ("kind", text(kind.name())),
                    ("address", bytes(address.as_bytes())),
                    ("authority_time", uint(authority_time.0)),
                ],
            ),
            Payload::Import { tick, bundle, artefacts, rosters } => t(
                tick,
                "import",
                vec![
                    ("bundle", bytes(bundle.as_bytes())),
                    ("artefacts", Value::Array(artefacts.iter().map(|d| bytes(d.as_bytes())).collect())),
                    (
                        "rosters",
                        Value::Array(
                            rosters
                                .iter()
                                .map(|r| {
                                    cbor::map([
                                        ("cohort", text(&r.cohort)),
                                        ("version", uint(r.version)),
                                        ("address", bytes(r.address.as_bytes())),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                ],
            ),
            Payload::KeyRoll { tick, index, public_key, evidence } => t(
                tick,
                "key-roll",
                vec![("index", uint(*index)), ("public_key", bytes(public_key.as_bytes())), ("evidence", bytes(evidence.as_bytes()))],
            ),
            Payload::Checkpoint { tick, cleared_through, hash_at, delivery } => t(
                tick,
                "checkpoint",
                vec![
                    ("cleared_through", uint(*cleared_through)),
                    ("hash_at", bytes(hash_at.as_bytes())),
                    ("delivery", bytes(delivery.as_bytes())),
                ],
            ),
            Payload::Closing { tick, last_seq, prev_hash, reason } => t(
                tick,
                "closing",
                vec![("last_seq", uint(*last_seq)), ("prev_hash", bytes(prev_hash.as_bytes())), ("reason", text(reason.name()))],
            ),
        })
    }

    /// Reads a payload by its `type`; anything outside WIRE §6.3 is `E_UNKNOWN_FIELD`.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let kind = match &value {
            Value::Map(m) => match m.get("type") {
                Some(Value::Text(t)) => t.clone(),
                _ => return Err(bad("payload has no type")),
            },
            _ => return Err(bad("payload is not a map")),
        };
        if kind == "items" {
            return Ok(Payload::Items(Box::new(ItemsPayload::from_value(value)?)));
        }
        // The kernel's typed reader is the authority on every payload constraint (WIRE-163).
        fieldseal_kernel::payload::Payload::from_value(value.clone())?;
        let mut f = Fields::new(value)?;
        let _ = f.text("type")?;
        let tick = Tick::from_value(f.take("tick")?)?;
        let d = |f: &mut Fields, k: &str| f.bytes_n::<32>(k).map(Digest::from);
        let payload = match kind.as_str() {
            "open" => Payload::Open {
                tick,
                tenancy: d(&mut f, "tenancy")?,
                sign_pub: pubkey(f.take("sign_pub")?)?,
                agree_pub: pubkey(f.take("agree_pub")?)?,
                evidence: digest_array(f.array("evidence")?)?,
                build_anchor: d(&mut f, "build_anchor")?,
            },
            "status" => Payload::Status {
                tick,
                instrument: d(&mut f, "instrument")?,
                subject: f.bytes("subject")?,
                status: match f.text("status")?.as_str() {
                    s @ ("absent" | "declined" | "not-subject") => s.to_owned(),
                    _ => return Err(bad("unknown status code")),
                },
            },
            "consent" => Payload::Consent {
                tick,
                instrument: d(&mut f, "instrument")?,
                subject: f.bytes("subject")?,
                basis: f.text("basis")?,
                statement: d(&mut f, "statement")?,
                evidence: f
                    .array("evidence")?
                    .into_iter()
                    .map(|e| {
                        let mut ef = Fields::new(e)?;
                        let r = EvidenceRef {
                            blob_id: ef.bytes_n::<16>("blob_id")?,
                            sha256: Digest::from(ef.bytes_n::<32>("sha256")?),
                            media_type: evidence_media(ef.text("media_type")?)?,
                            size: ef.uint("size")?,
                        };
                        ef.finish()?;
                        Ok(r)
                    })
                    .collect::<Result<_, WireError>>()?,
            },
            "evidence" => Payload::Evidence {
                tick,
                blob_id: f.bytes_n::<16>("blob_id")?,
                media_type: evidence_media(f.text("media_type")?)?,
                bytes: f.bytes("bytes")?,
            },
            "anchor" => Payload::Anchor {
                tick,
                kind: AnchorKind::parse(&f.text("kind")?)?,
                address: d(&mut f, "address")?,
                authority_time: AuthorityTime(f.uint("authority_time")?),
            },
            "import" => Payload::Import {
                tick,
                bundle: d(&mut f, "bundle")?,
                artefacts: digest_array(f.array("artefacts")?)?,
                rosters: f
                    .array("rosters")?
                    .into_iter()
                    .map(|r| {
                        let mut rf = Fields::new(r)?;
                        let x = ImportedRoster {
                            cohort: rf.text("cohort")?,
                            version: rf.uint("version")?,
                            address: Digest::from(rf.bytes_n::<32>("address")?),
                        };
                        rf.finish()?;
                        Ok(x)
                    })
                    .collect::<Result<_, WireError>>()?,
            },
            "key-roll" => Payload::KeyRoll {
                tick,
                index: f.uint("index")?,
                public_key: pubkey(f.take("public_key")?)?,
                evidence: d(&mut f, "evidence")?,
            },
            "checkpoint" => Payload::Checkpoint {
                tick,
                cleared_through: f.uint("cleared_through")?,
                hash_at: d(&mut f, "hash_at")?,
                delivery: d(&mut f, "delivery")?,
            },
            "closing" => Payload::Closing {
                tick,
                last_seq: f.uint("last_seq")?,
                prev_hash: d(&mut f, "prev_hash")?,
                reason: ClosingReason::parse(&f.text("reason")?)?,
            },
            _ => return Err(bad("unknown payload type")),
        };
        f.finish()?;
        Ok(payload)
    }

    /// Decodes a payload from canonical CBOR.
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        Self::from_value(cbor::decode(b)?)
    }
}

/// A record identifier as hex, for logs (never ordering).
pub fn record_id_hex(id: &RecordId) -> String {
    fieldseal_kernel::digest::lower_hex(id.as_bytes())
}

/// Reads an unsigned integer value (re-exported for fixtures).
pub fn uint_of(v: Value) -> Result<u64, WireError> {
    expect_uint(v)
}
