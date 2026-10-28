//! Records and the journal's hash chain (WIRE-033..041, §6.3).
//!
//! A record is `{"header", "payload", "sig"}`: a plaintext header holding only identity,
//! order and chain fields, the payload sealed to the authority's record key, and the tenancy
//! key's signature over `{header, payload}` under `fieldseal.dev/record/v1`. The record hash
//! is SHA-256 of the record's canonical bytes, and each header's `prev` is the hash of the
//! record before it.

use crate::cbor;
use crate::crypto::{P256PublicKey, Signature, tags};
use crate::digest::sha256;
use crate::error::{ErrorCode, WireError};
use crate::frame::{MAX_RECORD, read_frames};
use crate::id::{Digest, RecordId, KeyId};
use crate::seal::{SealedBox, Suite};
use crate::sign::{SigningKey, verify};
use crate::structure::Fields;
use crate::value::Value;

/// Sets the UUIDv4 version and variant bits on 16 random bytes (WIRE-035).
pub fn record_id_from_random(mut bytes: [u8; 16]) -> RecordId {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    RecordId::from(bytes)
}

/// Whether a record ID carries the UUIDv4 version and variant bits (WIRE-035).
pub fn is_uuid_v4(id: &RecordId) -> bool {
    let b = id.as_bytes();
    b[6] >> 4 == 4 && b[8] >> 6 == 0b10
}

/// The plaintext record header (WIRE-034): exactly these five fields.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecordHeader {
    /// The record's random identifier.
    pub record_id: RecordId,
    /// Its position in the journal.
    pub seq: u64,
    /// The previous record's hash, or zeros at `seq = 0`.
    pub prev: Digest,
    /// Index of the signing key in the tenancy's key history.
    pub key: u64,
    /// The authority record key the payload is sealed to.
    pub period: KeyId,
}

impl RecordHeader {
    /// The header as a value.
    pub fn to_value(&self) -> Value {
        cbor::map([
            ("record_id", Value::Bytes(self.record_id.as_bytes().to_vec())),
            ("seq", Value::Int(i128::from(self.seq))),
            ("prev", Value::Bytes(self.prev.as_bytes().to_vec())),
            ("key", Value::Int(i128::from(self.key))),
            ("period", Value::Bytes(self.period.as_bytes().to_vec())),
        ])
    }

    /// Reads a header; any other field is `E_UNKNOWN_FIELD` (WIRE-034, WIRE-005).
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        let header = Self {
            record_id: RecordId::from(f.bytes_n::<16>("record_id")?),
            seq: f.uint("seq")?,
            prev: Digest::from(f.bytes_n::<32>("prev")?),
            key: f.uint("key")?,
            period: KeyId::from(f.bytes_n::<16>("period")?),
        };
        f.finish()?;
        if !is_uuid_v4(&header.record_id) {
            return Err(WireError::new(ErrorCode::UnknownField, 0, "record_id is not a version-4 UUID (WIRE-035)"));
        }
        Ok(header)
    }
}

/// A record (WIRE-033).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Record {
    /// The plaintext header.
    pub header: RecordHeader,
    /// The payload, sealed with `fs1-x` under `fieldseal.dev/record-seal/v1` (WIRE-038).
    pub payload: SealedBox,
    /// The signature over `{header, payload}` (WIRE-037).
    pub sig: Signature,
}

/// The structure a record signature covers: `{header, payload}` (WIRE-037).
pub fn record_signed_structure(header: &RecordHeader, payload: &SealedBox) -> Value {
    cbor::map([("header", header.to_value()), ("payload", payload.to_value())])
}

impl Record {
    /// Signs a header and sealed payload into a record. The payload must use `fs1-x`.
    pub fn sign(key: &SigningKey, header: RecordHeader, payload: SealedBox) -> Result<Self, WireError> {
        if payload.suite != Suite::Fs1X {
            return Err(WireError::new(ErrorCode::Suite, 0, "record payloads use fs1-x"));
        }
        let sig = key.sign(&tags::RECORD, &record_signed_structure(&header, &payload))?;
        Ok(Self { header, payload, sig })
    }

    /// The record as a value.
    pub fn to_value(&self) -> Value {
        cbor::map([
            ("header", self.header.to_value()),
            ("payload", self.payload.to_value()),
            ("sig", Value::Bytes(self.sig.0.clone())),
        ])
    }

    /// The canonical record body (WIRE-033). `E_SIZE` above 4 MiB (WIRE-042).
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let body = cbor::encode(&self.to_value())?;
        if body.len() > MAX_RECORD {
            return Err(WireError::new(ErrorCode::Size, 0, "record exceeds 4 MiB"));
        }
        Ok(body)
    }

    /// Decodes a record body, checking its size before parsing.
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let mut f = Fields::new(cbor::decode_limited(body, MAX_RECORD)?)?;
        let header = RecordHeader::from_value(f.take("header")?)?;
        let payload = SealedBox::from_value(f.take("payload")?)?;
        let sig = Signature(f.bytes_n::<64>("sig")?.to_vec());
        f.finish()?;
        if payload.suite != Suite::Fs1X {
            return Err(WireError::new(ErrorCode::Suite, 0, "record payloads use fs1-x"));
        }
        Ok(Self { header, payload, sig })
    }

    /// Verifies the record signature with the key its header names (WIRE-037).
    pub fn verify(&self, key: &P256PublicKey) -> Result<(), WireError> {
        verify(key, &tags::RECORD, &record_signed_structure(&self.header, &self.payload), &self.sig)
    }
}

/// The record hash: SHA-256 of the canonical record body (WIRE-036).
pub fn record_hash(body: &[u8]) -> Digest {
    sha256(body)
}

/// One link of the chain: where a record is, its order fields and its hash.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChainLink {
    /// Offset of the record's frame in the journal.
    pub offset: usize,
    /// The record's `seq`.
    pub seq: u64,
    /// The record's `prev`.
    pub prev: Digest,
    /// The record's own hash.
    pub hash: Digest,
}

/// Checks `prev` links and `seq` continuity (WIRE-030, WIRE-036, WIRE-041).
///
/// `cleared` holds `(seq, hash)` pairs stated by opened checkpoint payloads (`cleared_through`,
/// `hash_at`): a run of omitted frames is accepted only where the next frame's `prev` equals
/// the stated hash of the record just before it. Every failure is reported; the chain is
/// valid when the result is empty. A broken `prev` is `E_CHAIN`; a missing, repeated or
/// out-of-order `seq` is `E_SEQ`.
pub fn verify_chain(links: &[ChainLink], cleared: &[(u64, Digest)]) -> Vec<WireError> {
    let zero = Digest::from([0u8; 32]);
    let stated = |seq: u64, prev: &Digest| seq > 0 && cleared.iter().any(|(s, h)| *s == seq - 1 && h == prev);
    let mut errors = Vec::new();
    let mut last: Option<&ChainLink> = None;
    for link in links {
        match last {
            None if link.seq == 0 => {
                if link.prev != zero {
                    errors.push(WireError::new(ErrorCode::Chain, link.offset, "seq 0 must have a zero prev"));
                }
            }
            None => {
                if !stated(link.seq, &link.prev) {
                    errors.push(WireError::new(ErrorCode::Seq, link.offset, "journal does not start at seq 0"));
                }
            }
            Some(prev) if link.seq == prev.seq + 1 => {
                if link.prev != prev.hash {
                    errors.push(WireError::new(ErrorCode::Chain, link.offset, "prev is not the previous record's hash"));
                }
            }
            Some(prev) if link.seq <= prev.seq => {
                errors.push(WireError::new(ErrorCode::Seq, link.offset, "seq repeated or out of order"));
                continue;
            }
            Some(_) => {
                if !stated(link.seq, &link.prev) {
                    errors.push(WireError::new(ErrorCode::Seq, link.offset, "seq gap not covered by a checkpoint"));
                }
            }
        }
        last = Some(link);
    }
    errors
}

/// A record read from a journal, with its frame offset and hash.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct JournalEntry {
    /// Offset of the frame.
    pub offset: usize,
    /// The record.
    pub record: Record,
    /// Its record hash.
    pub hash: Digest,
}

/// The outcome of reading a journal: every record that passed the checks, and every failure.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct JournalReport {
    /// Records whose frame, header and signature verified, in journal order.
    pub entries: Vec<JournalEntry>,
    /// Every failure, each with its code and offset.
    pub errors: Vec<WireError>,
}

impl JournalReport {
    /// Whether the whole journal verified.
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Reads and verifies a journal in the order of WIRE-040: frames, header decoding, signature
/// with the key named by `key` from `key_history`, the `prev` chain, then `seq` continuity.
/// Payloads are not opened. `cleared` is as for [`verify_chain`].
pub fn read_journal(journal: &[u8], key_history: &[P256PublicKey], cleared: &[(u64, Digest)]) -> JournalReport {
    let scan = read_frames(journal);
    let mut report = JournalReport { errors: scan.damage, ..JournalReport::default() };
    for frame in scan.frames {
        let body_offset = frame.offset + crate::frame::FRAME_HEADER_LEN;
        let record = match Record::decode(frame.body) {
            Ok(r) => r,
            Err(e) => {
                report.errors.push(e.shifted(body_offset));
                continue;
            }
        };
        let key = usize::try_from(record.header.key).ok().and_then(|i| key_history.get(i));
        let verified = match key {
            Some(k) => record.verify(k),
            None => Err(WireError::new(ErrorCode::Sig, 0, "key index not in the key history")),
        };
        if let Err(e) = verified {
            report.errors.push(e.shifted(frame.offset));
            continue;
        }
        report.entries.push(JournalEntry { offset: frame.offset, hash: record_hash(frame.body), record });
    }
    let links: Vec<ChainLink> = report
        .entries
        .iter()
        .map(|e| ChainLink { offset: e.offset, seq: e.record.header.seq, prev: e.record.header.prev, hash: e.hash })
        .collect();
    report.errors.extend(verify_chain(&links, cleared));
    report.errors.sort_by_key(|e| e.offset);
    report
}
