//! Publications, drafts and withdrawals, and their canonical encodings (PUB §6.1,
//! PUB-041, PUB-061, PUB-080, WIRE-193).
//!
//! ```cddl
//! artefact-fields = ( "kind": "Instrument" / "Layout" / "Localisation" / "Policy" /
//!                             "TrustBundle" / "Deployment",
//!                     "name": tstr, "version": tstr, "address": hash,
//!                     "artefact": bstr,              ; canonical bytes
//!                     ? "salt": bstr .size 32 )      ; exactly for instruments
//! signer-sig  = { "signer": key-id, "sig": signature }
//! log-record  = { "entry": bstr,                     ; LogEntry, WIRE-191
//!                 "leaf": "fieldseal/v1" / "hashedrekord/v0.0.1",
//!                 "index": uint, "inclusion": [* hash] }
//! approval    = { "signer": key-id, "sig": signature, "entry": bstr }
//!
//! publication = { artefact-fields, "provenance": provenance,
//!                 "signatures": [+ signer-sig],      ; tag fieldseal.dev/artefact/v1
//!                 "log": [+ log-record],             ; one per signature (PUB-103)
//!                 "checkpoint": bstr,                ; C2SP signed note (WIRE-192)
//!                 ? "checkpoint_time": bstr }        ; the time token that accompanied it (PUB-072)
//! publication-draft = { artefact-fields, "provenance": provenance, "approvals": [* approval] }
//!
//! withdrawal-fields = ( "address": hash, "provenance_sha256": hash, "reason": tstr,
//!                       "issued": ms-time )
//! withdrawal = { withdrawal-fields, "signatures": [+ signer-sig],  ; tag …/withdrawal/v1
//!                "log": [+ log-record], "checkpoint": bstr }
//! withdrawal-draft = { withdrawal-fields, "approvals": [* approval] }
//! ```

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::Signature;
use fieldseal_kernel::id::{ContentAddress, Digest, KeyId, Salt};
use fieldseal_kernel::structure::{Fields, expect_bytes_n, expect_uint};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{ErrorCode, Value, WireError};

use super::artefact::{Artefact, ArtefactKind};
use super::checkpoint::SignedCheckpoint;
use super::error::PublishingError;
use super::merkle::{InclusionProof, MAX_PATH};
use super::provenance::SignedProvenance;
use super::statement::{LeafFormat, LogEntry, LogEntryType, PublicationStatement};

/// The largest publication, draft or withdrawal accepted: the bundle limit (WIRE §6.7).
pub const MAX_PUBLICATION: usize = 64 * 1024 * 1024;

/// The longest encoded time token or receipt a publication may carry with its checkpoint.
pub const MAX_CHECKPOINT_TIME: usize = 1024;

/// The most signatures or log records a publication may carry.
pub const MAX_SIGNATURES: usize = 64;

fn unknown(detail: &'static str) -> WireError {
    WireError::new(ErrorCode::UnknownField, 0, detail)
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

/// The structure a publisher signs under `fieldseal.dev/artefact/v1` (PUB-041):
/// `{kind, name, version, address, provenance_sha256}`.
pub fn artefact_signed_structure(artefact: &Artefact, provenance_sha256: &Digest) -> Value {
    cbor::map([
        ("kind", Value::Text(artefact.kind().as_str().into())),
        ("name", Value::Text(artefact.name().into())),
        ("version", Value::Text(artefact.version().into())),
        ("address", bytes(artefact.address().as_bytes())),
        ("provenance_sha256", bytes(provenance_sha256.as_bytes())),
    ])
}

/// One key's signature.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignerSignature {
    /// The signing key's identifier.
    pub signer: KeyId,
    /// The signature.
    pub sig: Signature,
}

impl SignerSignature {
    fn to_value(&self) -> Value {
        cbor::map([("signer", bytes(self.signer.as_bytes())), ("sig", bytes(&self.sig.0))])
    }

    fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        let signer = KeyId::from(f.bytes_n::<16>("signer")?);
        let sig = Signature(f.bytes_n::<64>("sig")?.to_vec());
        f.finish()?;
        Ok(Self { signer, sig })
    }
}

/// One publisher's contribution before logging: the signature over the artefact (or
/// withdrawal) and the signed statement for the log (PUB-041, PUB-101).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Approval {
    /// The signature under `fieldseal.dev/artefact/v1` (or `…/withdrawal/v1`).
    pub signature: SignerSignature,
    /// The log entry: the statement's digest, signed under `fieldseal.dev/publication/v1`.
    pub entry: LogEntry,
}

impl Approval {
    fn to_value(&self) -> Value {
        cbor::map([
            ("signer", bytes(self.signature.signer.as_bytes())),
            ("sig", bytes(&self.signature.sig.0)),
            ("entry", Value::Bytes(self.entry.encode())),
        ])
    }

    fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        let signer = KeyId::from(f.bytes_n::<16>("signer")?);
        let sig = Signature(f.bytes_n::<64>("sig")?.to_vec());
        let entry = LogEntry::decode(&f.bytes("entry")?)?;
        f.finish()?;
        if entry.key_id() != signer {
            return Err(WireError::new(ErrorCode::Sig, 0, "the log entry is by another key"));
        }
        Ok(Self { signature: SignerSignature { signer, sig }, entry })
    }
}

/// A logged entry as a publication carries it: the entry, how the log hashed it, and its
/// inclusion proof against the publication's checkpoint.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LogRecord {
    /// The entry.
    pub entry: LogEntry,
    /// The log's leaf form.
    pub leaf: LeafFormat,
    /// The inclusion proof; its `tree_size` is the checkpoint's size.
    pub inclusion: InclusionProof,
}

impl LogRecord {
    fn to_value(&self) -> Value {
        cbor::map([
            ("entry", Value::Bytes(self.entry.encode())),
            ("leaf", Value::Text(self.leaf.as_str().into())),
            ("index", Value::Int(i128::from(self.inclusion.leaf_index))),
            ("inclusion", Value::Array(self.inclusion.path.iter().map(|d| bytes(d.as_bytes())).collect())),
        ])
    }

    fn from_value(value: Value, tree_size: u64) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        let entry = LogEntry::decode(&f.bytes("entry")?)?;
        let leaf = LeafFormat::parse(&f.text("leaf")?).ok_or(unknown("unknown leaf format"))?;
        let leaf_index = f.uint("index")?;
        let path = f.array("inclusion")?;
        if path.len() > MAX_PATH {
            return Err(WireError::new(ErrorCode::Size, 0, "inclusion path too long"));
        }
        let path = path.into_iter().map(|v| expect_bytes_n::<32>(v).map(Digest::from)).collect::<Result<_, _>>()?;
        f.finish()?;
        Ok(Self { entry, leaf, inclusion: InclusionProof { leaf_index, tree_size, path } })
    }
}

fn artefact_fields(artefact: &Artefact) -> Vec<(&'static str, Value)> {
    let mut out = vec![
        ("kind", Value::Text(artefact.kind().as_str().into())),
        ("name", Value::Text(artefact.name().into())),
        ("version", Value::Text(artefact.version().into())),
        ("address", bytes(artefact.address().as_bytes())),
        ("artefact", bytes(artefact.canonical_bytes())),
    ];
    if let Some(salt) = artefact.salt() {
        out.push(("salt", bytes(salt.as_bytes())));
    }
    out
}

fn read_artefact(f: &mut Fields) -> Result<Artefact, PublishingError> {
    let kind = ArtefactKind::parse(&f.text("kind")?).ok_or(unknown("unknown artefact kind"))?;
    let name = f.text("name")?;
    let version = f.text("version")?;
    let address = ContentAddress::from(f.bytes_n::<32>("address")?);
    let canonical = f.bytes("artefact")?;
    let salt = f.take_opt("salt").map(expect_bytes_n::<32>).transpose()?.map(Salt::from);
    let artefact = Artefact::new(kind, &name, &version, canonical, salt)?;
    if artefact.address() != &address {
        return Err(WireError::new(ErrorCode::Hash, 0, "address does not match the artefact").into());
    }
    Ok(artefact)
}

fn list<T>(f: &mut Fields, key: &str, read: impl Fn(Value) -> Result<T, WireError>) -> Result<Vec<T>, WireError> {
    let items = f.array(key)?;
    if items.len() > MAX_SIGNATURES {
        return Err(WireError::new(ErrorCode::Size, 0, "too many signatures"));
    }
    items.into_iter().map(read).collect()
}

fn decode_map(bytes: &[u8]) -> Result<Fields, WireError> {
    Fields::new(cbor::decode_limited(bytes, MAX_PUBLICATION)?)
}

fn read_checkpoint(f: &mut Fields) -> Result<SignedCheckpoint, PublishingError> {
    Ok(SignedCheckpoint::parse(&f.bytes("checkpoint")?)?)
}

/// An artefact on its way to publication: built, with provenance, collecting publisher
/// approvals. This is what `fieldseal artefact sign` adds to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicationDraft {
    /// The artefact.
    pub artefact: Artefact,
    /// Its signed provenance.
    pub provenance: SignedProvenance,
    /// Publisher approvals so far.
    pub approvals: Vec<Approval>,
}

impl PublicationDraft {
    /// A draft with no approvals yet.
    pub fn new(artefact: Artefact, provenance: SignedProvenance) -> Self {
        Self { artefact, provenance, approvals: Vec::new() }
    }

    /// The statement every publisher's log entry signs (WIRE-190).
    pub fn statement(&self) -> PublicationStatement {
        PublicationStatement::new(LogEntryType::Publish, *self.artefact.address(), self.provenance.digest())
    }

    /// The structure every publisher signs under `fieldseal.dev/artefact/v1` (PUB-041).
    pub fn signed_structure(&self) -> Value {
        artefact_signed_structure(&self.artefact, &self.provenance.digest())
    }

    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut fields = artefact_fields(&self.artefact);
        fields.push(("provenance", self.provenance.to_value()));
        fields.push(("approvals", Value::Array(self.approvals.iter().map(Approval::to_value).collect())));
        cbor::encode(&cbor::map(fields)).expect("a draft always encodes")
    }

    /// Decodes canonical CBOR, refusing unknown keys and an address that doesn't match.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublishingError> {
        let mut f = decode_map(bytes)?;
        let artefact = read_artefact(&mut f)?;
        let provenance = SignedProvenance::from_value(f.take("provenance")?)?;
        let approvals = list(&mut f, "approvals", Approval::from_value)?;
        f.finish()?;
        Ok(Self { artefact, provenance, approvals })
    }
}

/// Everything a consumer needs to verify an artefact offline (PUB-061, WIRE-193): the
/// artefact, its provenance, the publisher signatures, one log record per signature, and
/// the checkpoint the proofs are against. A `Publication` value is only well formed;
/// [`crate::application::VerifyPublication`] decides whether it is valid.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Publication {
    /// The artefact.
    pub artefact: Artefact,
    /// Its signed provenance.
    pub provenance: SignedProvenance,
    /// Publisher signatures under `fieldseal.dev/artefact/v1`.
    pub signatures: Vec<SignerSignature>,
    /// One log record per signature (PUB-103).
    pub log: Vec<LogRecord>,
    /// The checkpoint every inclusion proof is against.
    pub checkpoint: SignedCheckpoint,
    /// The authority time token (or receipt) that accompanied the checkpoint when it was
    /// obtained, as encoded by its owner and opaque to this context. C2SP checkpoints carry
    /// no time, so a tree head's age is measured from this token (PUB-072). Not covered by
    /// the publisher signatures; consumers verify the token itself.
    pub checkpoint_time: Option<Vec<u8>>,
}

impl Publication {
    /// The artefact's identity.
    pub fn address(&self) -> &ContentAddress {
        self.artefact.address()
    }

    /// The statement every log entry of this publication signs (WIRE-190).
    pub fn statement(&self) -> PublicationStatement {
        PublicationStatement::new(LogEntryType::Publish, *self.artefact.address(), self.provenance.digest())
    }

    /// The structure every publisher signature is over (PUB-041).
    pub fn signed_structure(&self) -> Value {
        artefact_signed_structure(&self.artefact, &self.provenance.digest())
    }

    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut fields = artefact_fields(&self.artefact);
        fields.push(("provenance", self.provenance.to_value()));
        fields.push(("signatures", Value::Array(self.signatures.iter().map(SignerSignature::to_value).collect())));
        fields.push(("log", Value::Array(self.log.iter().map(LogRecord::to_value).collect())));
        fields.push(("checkpoint", bytes(self.checkpoint.note())));
        if let Some(t) = &self.checkpoint_time {
            fields.push(("checkpoint_time", bytes(t)));
        }
        cbor::encode(&cbor::map(fields)).expect("a publication always encodes")
    }

    /// Decodes canonical CBOR, refusing unknown keys, an address that doesn't match the
    /// artefact, and a malformed checkpoint.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublishingError> {
        let mut f = decode_map(bytes)?;
        let artefact = read_artefact(&mut f)?;
        let provenance = SignedProvenance::from_value(f.take("provenance")?)?;
        let signatures = list(&mut f, "signatures", SignerSignature::from_value)?;
        let checkpoint = read_checkpoint(&mut f)?;
        let checkpoint_time = match f.take_opt("checkpoint_time") {
            None => None,
            Some(Value::Bytes(b)) if !b.is_empty() && b.len() <= MAX_CHECKPOINT_TIME => Some(b),
            Some(_) => return Err(unknown("checkpoint_time is a short byte string").into()),
        };
        let size = checkpoint.size();
        let log = list(&mut f, "log", |v| LogRecord::from_value(v, size))?;
        f.finish()?;
        if signatures.is_empty() || log.is_empty() {
            return Err(unknown("a publication needs signatures and log records").into());
        }
        Ok(Self { artefact, provenance, signatures, log, checkpoint, checkpoint_time })
    }
}

/// What a withdrawal says: which artefact, which of its provenance, why and when
/// (PUB-080). Signed under `fieldseal.dev/withdrawal/v1`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WithdrawalStatement {
    /// The withdrawn artefact's identity.
    pub address: ContentAddress,
    /// The withdrawn publication's provenance digest.
    pub provenance_sha256: Digest,
    /// Why. Never logged; only signed.
    pub reason: String,
    /// When the withdrawal was issued, in authority time; certificates are checked then.
    pub issued: AuthorityTime,
}

impl WithdrawalStatement {
    /// The withdrawal of `publication`.
    pub fn of(publication: &Publication, reason: &str, issued: AuthorityTime) -> Self {
        Self { address: *publication.address(), provenance_sha256: publication.provenance.digest(), reason: reason.into(), issued }
    }

    fn fields(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("address", bytes(self.address.as_bytes())),
            ("provenance_sha256", bytes(self.provenance_sha256.as_bytes())),
            ("reason", Value::Text(self.reason.clone())),
            ("issued", Value::Int(i128::from(self.issued.0))),
        ]
    }

    fn read(f: &mut Fields) -> Result<Self, WireError> {
        Ok(Self {
            address: ContentAddress::from(f.bytes_n::<32>("address")?),
            provenance_sha256: Digest::from(f.bytes_n::<32>("provenance_sha256")?),
            reason: f.text("reason")?,
            issued: AuthorityTime(expect_uint(f.take("issued")?)?),
        })
    }

    /// The structure publishers sign under `fieldseal.dev/withdrawal/v1`.
    pub fn signed_structure(&self) -> Value {
        cbor::map(self.fields())
    }

    /// The statement the withdrawal's log entries sign (WIRE-190): type `withdraw`, the
    /// artefact's identity and the withdrawn publication's provenance digest.
    pub fn log_statement(&self) -> PublicationStatement {
        PublicationStatement::new(LogEntryType::Withdraw, self.address, self.provenance_sha256)
    }
}

/// A withdrawal collecting publisher approvals (`fieldseal artefact withdraw`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WithdrawalDraft {
    /// The statement.
    pub statement: WithdrawalStatement,
    /// Approvals so far.
    pub approvals: Vec<Approval>,
}

impl WithdrawalDraft {
    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut fields = self.statement.fields();
        fields.push(("approvals", Value::Array(self.approvals.iter().map(Approval::to_value).collect())));
        cbor::encode(&cbor::map(fields)).expect("a draft always encodes")
    }

    /// Decodes canonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublishingError> {
        let mut f = decode_map(bytes)?;
        let statement = WithdrawalStatement::read(&mut f)?;
        let approvals = list(&mut f, "approvals", Approval::from_value)?;
        f.finish()?;
        Ok(Self { statement, approvals })
    }
}

/// A signed, logged statement that an artefact version must no longer be used (PUB-080).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Withdrawal {
    /// The statement.
    pub statement: WithdrawalStatement,
    /// Publisher signatures under `fieldseal.dev/withdrawal/v1`.
    pub signatures: Vec<SignerSignature>,
    /// One log record per signature.
    pub log: Vec<LogRecord>,
    /// The checkpoint the proofs are against.
    pub checkpoint: SignedCheckpoint,
}

impl Withdrawal {
    /// The withdrawn artefact.
    pub fn address(&self) -> &ContentAddress {
        &self.statement.address
    }

    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut fields = self.statement.fields();
        fields.push(("signatures", Value::Array(self.signatures.iter().map(SignerSignature::to_value).collect())));
        fields.push(("log", Value::Array(self.log.iter().map(LogRecord::to_value).collect())));
        fields.push(("checkpoint", bytes(self.checkpoint.note())));
        cbor::encode(&cbor::map(fields)).expect("a withdrawal always encodes")
    }

    /// Decodes canonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublishingError> {
        let mut f = decode_map(bytes)?;
        let statement = WithdrawalStatement::read(&mut f)?;
        let signatures = list(&mut f, "signatures", SignerSignature::from_value)?;
        let checkpoint = read_checkpoint(&mut f)?;
        let size = checkpoint.size();
        let log = list(&mut f, "log", |v| LogRecord::from_value(v, size))?;
        f.finish()?;
        if signatures.is_empty() || log.is_empty() {
            return Err(unknown("a withdrawal needs signatures and log records").into());
        }
        Ok(Self { statement, signatures, log, checkpoint })
    }
}
