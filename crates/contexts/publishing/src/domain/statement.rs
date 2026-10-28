//! What reaches the public transparency log, fixed by type (ADR 0030 condition 1).
//!
//! A [`LogEntry`] has exactly four private fields and no extension mechanism; the
//! statement its digest commits to ([`PublicationStatement`]) holds only an enumeration and
//! two 32-byte hashes. Nothing else can be built into either, so names, versions, sources,
//! builders, reviewers and artefact bytes can't reach the log by construction (PUB-101,
//! PUB-102, PUB-104).
//!
//! ```compile_fail
//! // The fields are private: a LogEntry can't be built with anything extra, or at all,
//! // except through `LogEntry::new` from exactly its four parts.
//! use fieldseal_publishing::domain::LogEntry;
//! let e = LogEntry { entry_type: todo!(), digest: todo!(), signature: todo!(), public_key: todo!(), name: "x" };
//! ```

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::{P256PublicKey, Signature, tags};
use fieldseal_kernel::digest::{key_id, lower_hex, sha256};
use fieldseal_kernel::id::{ContentAddress, Digest, KeyId};
use fieldseal_kernel::sign::{SIGNATURE_LEN, signed_message};
use fieldseal_kernel::structure::Fields;
use fieldseal_kernel::{ErrorCode, Value, WireError};

use super::encoding::{base64_encode, ecdsa_der_from_raw, p256_pem};

/// Whether a statement or entry publishes or withdraws.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum LogEntryType {
    /// A publication.
    Publish,
    /// A withdrawal.
    Withdraw,
}

impl LogEntryType {
    /// The value as written in the wire formats (WIRE-190).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Withdraw => "withdraw",
        }
    }

    /// Parses the wire value.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "publish" => Some(Self::Publish),
            "withdraw" => Some(Self::Withdraw),
            _ => None,
        }
    }
}

fn unknown(detail: &'static str) -> WireError {
    WireError::new(ErrorCode::UnknownField, 0, detail)
}

/// What a publisher signs for logging (PUB-101, WIRE-190): only an enumeration, the
/// artefact's 32-byte identity (an instrument's fingerprint, any other artefact's content
/// address, PUB-092) and a provenance digest. No names, versions or locations.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PublicationStatement {
    entry_type: LogEntryType,
    subject: ContentAddress,
    provenance: Digest,
}

impl PublicationStatement {
    /// A statement about the artefact whose identity is `subject`.
    pub fn new(entry_type: LogEntryType, subject: ContentAddress, provenance: Digest) -> Self {
        Self { entry_type, subject, provenance }
    }

    /// Publish or withdraw.
    pub fn entry_type(&self) -> LogEntryType {
        self.entry_type
    }

    /// The artefact's identity (fingerprint or content address).
    pub fn subject(&self) -> &ContentAddress {
        &self.subject
    }

    /// The provenance digest.
    pub fn provenance(&self) -> &Digest {
        &self.provenance
    }

    /// The canonical structure `{"type", "fingerprint", "provenance"}` (WIRE-190).
    pub fn to_value(&self) -> Value {
        cbor::map([
            ("type", Value::Text(self.entry_type.as_str().into())),
            ("fingerprint", Value::Bytes(self.subject.as_bytes().to_vec())),
            ("provenance", Value::Bytes(self.provenance.as_bytes().to_vec())),
        ])
    }

    /// Reads the structure, refusing any other key (WIRE-190, WIRE-005).
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        let entry_type = LogEntryType::parse(&f.text("type")?).ok_or(unknown("unknown statement type"))?;
        let subject = ContentAddress::from(f.bytes_n::<32>("fingerprint")?);
        let provenance = Digest::from(f.bytes_n::<32>("provenance")?);
        f.finish()?;
        Ok(Self { entry_type, subject, provenance })
    }

    /// The digest the log records: SHA-256 of the signed message `[tag, statement]` under
    /// `fieldseal.dev/publication/v1` (WIRE-021, WIRE-191).
    pub fn digest(&self) -> Digest {
        let message = signed_message(&tags::PUBLICATION, &self.to_value()).expect("a statement always encodes");
        sha256(&message)
    }
}

/// The only thing the transparency log ever receives (ADR 0030, PUB-102, WIRE-191):
/// exactly an entry type, the digest of a signed [`PublicationStatement`], one signature
/// and one public key. The fields are private and there is no other constructor or
/// extension field, so nothing else can be logged (PUB-102, PUB-104):
///
/// ```compile_fail
/// use fieldseal_publishing::domain::LogEntry;
/// // A name, version or label can't be added: there is no such field to set.
/// fn leak(e: LogEntry) -> String {
///     e.name
/// }
/// ```
///
/// ```compile_fail
/// use fieldseal_publishing::domain::{LogEntry, LogEntryType};
/// use fieldseal_kernel::id::Digest;
/// use fieldseal_kernel::crypto::Signature;
/// // `new` takes exactly the four parts; a fifth argument is a type error.
/// fn leak(key: fieldseal_kernel::crypto::P256PublicKey) -> LogEntry {
///     LogEntry::new(LogEntryType::Publish, Digest::from([0; 32]), Signature(vec![]), key, "health-check 1.2.0")
/// }
/// ```
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct LogEntry {
    entry_type: LogEntryType,
    digest: Digest,
    signature: Signature,
    public_key: P256PublicKey,
}

impl LogEntry {
    /// Builds an entry from its four parts.
    pub fn new(entry_type: LogEntryType, digest: Digest, signature: Signature, public_key: P256PublicKey) -> Self {
        Self { entry_type, digest, signature, public_key }
    }

    /// The entry for `statement`, signed by `public_key`'s holder with `signature`.
    pub fn for_statement(statement: &PublicationStatement, signature: Signature, public_key: P256PublicKey) -> Self {
        Self::new(statement.entry_type(), statement.digest(), signature, public_key)
    }

    /// Publish or withdraw.
    pub fn entry_type(&self) -> LogEntryType {
        self.entry_type
    }

    /// Digest of the signed publication statement.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// The publisher's signature over the statement.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// The publisher's public key.
    pub fn public_key(&self) -> &P256PublicKey {
        &self.public_key
    }

    /// The publisher key's identifier (WIRE-010).
    pub fn key_id(&self) -> KeyId {
        key_id(self.public_key.as_bytes())
    }

    /// The canonical structure `{"type", "digest", "sig", "pub"}` (WIRE-191).
    pub fn to_value(&self) -> Value {
        cbor::map([
            ("type", Value::Text(self.entry_type.as_str().into())),
            ("digest", Value::Bytes(self.digest.as_bytes().to_vec())),
            ("sig", Value::Bytes(self.signature.0.clone())),
            ("pub", Value::Bytes(self.public_key.as_bytes().to_vec())),
        ])
    }

    /// Canonical CBOR (WIRE-191).
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("a log entry always encodes")
    }

    /// Reads the structure, refusing any other key (WIRE-191, WIRE-005).
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        let entry_type = LogEntryType::parse(&f.text("type")?).ok_or(unknown("unknown entry type"))?;
        let digest = Digest::from(f.bytes_n::<32>("digest")?);
        let sig = f.bytes("sig")?;
        if sig.len() != SIGNATURE_LEN {
            return Err(WireError::new(ErrorCode::Sig, 0, "signature is not 64 bytes"));
        }
        let public_key =
            P256PublicKey::from_bytes(&f.bytes_n::<65>("pub")?).map_err(|_| unknown("not an uncompressed P-256 key"))?;
        f.finish()?;
        Ok(Self { entry_type, digest, signature: Signature(sig), public_key })
    }

    /// Decodes canonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Self::from_value(cbor::decode(bytes)?)
    }
}

/// How a log hashes an entry into a leaf. A [`LogEntry`] is logged in the backend's
/// minimal hash-only form (PUB-105); a consumer recomputes the leaf from the entry and the
/// format, so the form is fixed here, not by the adapter.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum LeafFormat {
    /// The entry's canonical CBOR (WIRE-191). Used by Fieldseal-native logs.
    Fieldseal,
    /// A Rekor `hashedrekord` v0.0.1 entry in its canonical JSON (RFC 8785) form: the
    /// digest as `sha256` hex, the signature as base64 DER, the key as base64 PEM. Carries
    /// no entry type: the type is inside the statement the digest commits to.
    HashedRekord,
}

impl LeafFormat {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fieldseal => "fieldseal/v1",
            Self::HashedRekord => "hashedrekord/v0.0.1",
        }
    }

    /// Parses the wire name.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "fieldseal/v1" => Some(Self::Fieldseal),
            "hashedrekord/v0.0.1" => Some(Self::HashedRekord),
            _ => None,
        }
    }

    /// The exact leaf bytes the log hashes for `entry`.
    pub fn leaf(self, entry: &LogEntry) -> Vec<u8> {
        match self {
            Self::Fieldseal => entry.encode(),
            Self::HashedRekord => hashedrekord_json(entry).into_bytes(),
        }
    }
}

/// The ECDSA signature of a log entry in ASN.1 DER, as `hashedrekord` carries it.
pub fn entry_signature_der(entry: &LogEntry) -> Vec<u8> {
    let raw: [u8; 64] = entry.signature().0.as_slice().try_into().expect("a log entry's signature is 64 bytes");
    ecdsa_der_from_raw(&raw)
}

/// A `hashedrekord` v0.0.1 entry for `entry`, in RFC 8785 canonical JSON (keys sorted, no
/// whitespace). Every value is base64, hex or a fixed constant, so no escaping is needed.
pub fn hashedrekord_json(entry: &LogEntry) -> String {
    format!(
        concat!(
            r#"{{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{{"data":{{"hash":{{"algorithm":"sha256","value":"{}"}}}},"#,
            r#""signature":{{"content":"{}","publicKey":{{"content":"{}"}}}}}}}}"#
        ),
        lower_hex(entry.digest().as_bytes()),
        base64_encode(&entry_signature_der(entry)),
        base64_encode(p256_pem(entry.public_key()).as_bytes()),
    )
}
