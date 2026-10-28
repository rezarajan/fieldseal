//! The record payloads the runtime writes (WIRE §5.4, §6.3). The kernel types `items`
//! payloads and ticks; the other payloads are built and read here, field for field as the
//! CDDL gives them.

use fieldseal_distribution::domain::AnchorKind;
use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::P256PublicKey;
use fieldseal_kernel::error::{ErrorCode, WireError};
use fieldseal_kernel::id::{Digest, Fingerprint};
use fieldseal_kernel::payload::{ItemsPayload, Tick};
use fieldseal_kernel::structure::{Fields, expect_bytes_n};
use fieldseal_kernel::Value;

fn invalid(detail: &'static str) -> WireError {
    WireError::new(ErrorCode::UnknownField, 0, detail)
}

/// The media types an evidence image may carry (WIRE-214): the photographs a
/// device captures. Kept equal to the intake context's set.
pub const EVIDENCE_MEDIA_TYPES: [&str; 3] = ["image/jpeg", "image/png", "image/webp"];

fn evidence_media(media_type: String) -> Result<String, WireError> {
    if EVIDENCE_MEDIA_TYPES.contains(&media_type.as_str()) {
        Ok(media_type)
    } else {
        Err(invalid("evidence media_type is not an allowed evidence media type"))
    }
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn uint(n: u64) -> Value {
    Value::Int(i128::from(n))
}

fn text(t: &str) -> Value {
    Value::Text(t.to_owned())
}

/// A `status` payload's code (WIRE-054).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum StatusCode {
    /// The subject was absent.
    Absent,
    /// The subject declined.
    Declined,
    /// The person was not the subject.
    NotSubject,
}

impl StatusCode {
    /// The code as written.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Declined => "declined",
            Self::NotSubject => "not-subject",
        }
    }

    fn parse(t: &str) -> Result<Self, WireError> {
        Ok(match t {
            "absent" => Self::Absent,
            "declined" => Self::Declined,
            "not-subject" => Self::NotSubject,
            _ => return Err(invalid("unknown status code")),
        })
    }
}

/// Why a journal closed (WIRE-061).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ClosingReason {
    /// The collector ended the tenancy.
    Collector,
    /// A close certificate.
    CloseCertificate,
    /// A reset certificate.
    ResetCertificate,
    /// The device was returned.
    Returned,
}

impl ClosingReason {
    /// The reason as written.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collector => "collector",
            Self::CloseCertificate => "close-certificate",
            Self::ResetCertificate => "reset-certificate",
            Self::Returned => "returned",
        }
    }

    fn parse(t: &str) -> Result<Self, WireError> {
        Ok(match t {
            "collector" => Self::Collector,
            "close-certificate" => Self::CloseCertificate,
            "reset-certificate" => Self::ResetCertificate,
            "returned" => Self::Returned,
            _ => return Err(invalid("unknown closing reason")),
        })
    }
}

/// The anchor kind as written (WIRE-057).
pub fn anchor_kind_str(kind: AnchorKind) -> &'static str {
    match kind {
        AnchorKind::Build => "build",
        AnchorKind::Bundle => "bundle",
        AnchorKind::Receipt => "receipt",
        AnchorKind::TimeToken => "time-token",
    }
}

fn parse_anchor_kind(t: &str) -> Result<AnchorKind, WireError> {
    Ok(match t {
        "build" => AnchorKind::Build,
        "bundle" => AnchorKind::Bundle,
        "receipt" => AnchorKind::Receipt,
        "time-token" => AnchorKind::TimeToken,
        _ => return Err(invalid("unknown anchor kind")),
    })
}

/// An evidence reference in a consent payload (WIRE-055).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EvidenceRef {
    /// The evidence record's blob ID.
    pub blob_id: [u8; 16],
    /// SHA-256 of the evidence bytes.
    pub sha256: Digest,
    /// Its media type.
    pub media_type: String,
    /// Its size in bytes.
    pub size: u64,
}

/// A roster an `import` record names (WIRE-058).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ImportedRoster {
    /// The cohort.
    pub cohort: String,
    /// The roster version.
    pub version: u64,
    /// Its content address.
    pub address: Digest,
}

/// A record payload (WIRE-050).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Payload {
    /// `open` (WIRE-062): the journal's first record.
    Open {
        /// The tick.
        tick: Tick,
        /// The tenancy ID.
        tenancy: Digest,
        /// The signing public key.
        sign_pub: P256PublicKey,
        /// The agreement public key.
        agree_pub: P256PublicKey,
        /// Content addresses of the keys' attestation evidence.
        evidence: Vec<Digest>,
        /// The runtime build's release anchor.
        build_anchor: Digest,
    },
    /// `items` (WIRE-051).
    Items(ItemsPayload),
    /// `status` (WIRE-054).
    Status {
        /// The tick.
        tick: Tick,
        /// The instrument fingerprint.
        instrument: Fingerprint,
        /// The subject.
        subject: Vec<u8>,
        /// The status.
        status: StatusCode,
    },
    /// `consent` (WIRE-055).
    Consent {
        /// The tick.
        tick: Tick,
        /// The instrument fingerprint.
        instrument: Fingerprint,
        /// The subject.
        subject: Vec<u8>,
        /// The basis code, from the instrument's list.
        basis: String,
        /// The consent statement's content address.
        statement: Digest,
        /// Evidence references.
        evidence: Vec<EvidenceRef>,
    },
    /// `evidence` (WIRE-056). In the local record `bytes` is empty: the local record notes
    /// only that evidence exists (COL-043).
    Evidence {
        /// The tick.
        tick: Tick,
        /// The blob ID.
        blob_id: [u8; 16],
        /// The media type.
        media_type: String,
        /// The image bytes.
        bytes: Vec<u8>,
    },
    /// `anchor` (WIRE-057).
    Anchor {
        /// The tick.
        tick: Tick,
        /// The anchor's kind.
        kind: AnchorKind,
        /// Its content address.
        address: Digest,
        /// The authority time it states.
        authority_time: u64,
    },
    /// `import` (WIRE-058).
    Import {
        /// The tick.
        tick: Tick,
        /// The bundle's content address.
        bundle: Digest,
        /// Each artefact loaded.
        artefacts: Vec<Digest>,
        /// Each roster loaded.
        rosters: Vec<ImportedRoster>,
    },
    /// `checkpoint` (WIRE-060).
    Checkpoint {
        /// The tick.
        tick: Tick,
        /// Records with `seq` at or below this were cleared.
        cleared_through: u64,
        /// The record hash at `cleared_through`.
        hash_at: Digest,
        /// The delivery evidence that allowed journal deletion (a receipt's content address),
        /// or 32 zero bytes when none (ADR 0029: clear needs no delivery evidence).
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
        /// Why the journal closed.
        reason: ClosingReason,
    },
}

impl Payload {
    /// The payload's `type`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Open { .. } => "open",
            Self::Items(_) => "items",
            Self::Status { .. } => "status",
            Self::Consent { .. } => "consent",
            Self::Evidence { .. } => "evidence",
            Self::Anchor { .. } => "anchor",
            Self::Import { .. } => "import",
            Self::Checkpoint { .. } => "checkpoint",
            Self::Closing { .. } => "closing",
        }
    }

    /// The payload's tick.
    pub fn tick(&self) -> &Tick {
        match self {
            Self::Items(p) => &p.tick,
            Self::Open { tick, .. }
            | Self::Status { tick, .. }
            | Self::Consent { tick, .. }
            | Self::Evidence { tick, .. }
            | Self::Anchor { tick, .. }
            | Self::Import { tick, .. }
            | Self::Checkpoint { tick, .. }
            | Self::Closing { tick, .. } => tick,
        }
    }

    /// The subject a record is about, if any.
    pub fn subject(&self) -> Option<&[u8]> {
        match self {
            Self::Items(p) => Some(&p.subject),
            Self::Status { subject, .. } | Self::Consent { subject, .. } => Some(subject),
            _ => None,
        }
    }

    /// The payload as a value.
    pub fn to_value(&self) -> Result<Value, WireError> {
        let tick = |t: &Tick| t.to_value();
        Ok(match self {
            Self::Items(p) => return p.to_value(),
            Self::Open { tick: t, tenancy, sign_pub, agree_pub, evidence, build_anchor } => cbor::map([
                ("type", text("open")),
                ("tick", tick(t)),
                ("tenancy", bytes(tenancy.as_bytes())),
                ("sign_pub", bytes(sign_pub.as_bytes())),
                ("agree_pub", bytes(agree_pub.as_bytes())),
                ("evidence", Value::Array(evidence.iter().map(|d| bytes(d.as_bytes())).collect())),
                ("build_anchor", bytes(build_anchor.as_bytes())),
            ]),
            Self::Status { tick: t, instrument, subject, status } => cbor::map([
                ("type", text("status")),
                ("tick", tick(t)),
                ("instrument", bytes(instrument.as_bytes())),
                ("subject", bytes(subject)),
                ("status", text(status.as_str())),
            ]),
            Self::Consent { tick: t, instrument, subject, basis, statement, evidence } => cbor::map([
                ("type", text("consent")),
                ("tick", tick(t)),
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
            ]),
            Self::Evidence { tick: t, blob_id, media_type, bytes: b } => cbor::map([
                ("type", text("evidence")),
                ("tick", tick(t)),
                ("blob_id", bytes(blob_id)),
                ("media_type", text(media_type)),
                ("bytes", bytes(b)),
            ]),
            Self::Anchor { tick: t, kind, address, authority_time } => cbor::map([
                ("type", text("anchor")),
                ("tick", tick(t)),
                ("kind", text(anchor_kind_str(*kind))),
                ("address", bytes(address.as_bytes())),
                ("authority_time", uint(*authority_time)),
            ]),
            Self::Import { tick: t, bundle, artefacts, rosters } => cbor::map([
                ("type", text("import")),
                ("tick", tick(t)),
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
            ]),
            Self::Checkpoint { tick: t, cleared_through, hash_at, delivery } => cbor::map([
                ("type", text("checkpoint")),
                ("tick", tick(t)),
                ("cleared_through", uint(*cleared_through)),
                ("hash_at", bytes(hash_at.as_bytes())),
                ("delivery", bytes(delivery.as_bytes())),
            ]),
            Self::Closing { tick: t, last_seq, prev_hash, reason } => cbor::map([
                ("type", text("closing")),
                ("tick", tick(t)),
                ("last_seq", uint(*last_seq)),
                ("prev_hash", bytes(prev_hash.as_bytes())),
                ("reason", text(reason.as_str())),
            ]),
        })
    }

    /// Canonical CBOR.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        cbor::encode(&self.to_value()?)
    }

    /// Reads a payload; any field outside its type's CDDL is `E_UNKNOWN_FIELD`.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let kind = value
            .as_map()
            .and_then(|m| m.get("type"))
            .and_then(Value::as_text)
            .ok_or_else(|| invalid("payload has no type"))?
            .to_owned();
        if kind == "items" {
            return ItemsPayload::from_value(value).map(Self::Items);
        }
        // The kernel's typed reader is the authority on every payload constraint (WIRE-163).
        fieldseal_kernel::payload::Payload::from_value(value.clone())?;
        let mut f = Fields::new(value)?;
        f.text("type")?;
        let tick = Tick::from_value(f.take("tick")?)?;
        let digests = |v: Vec<Value>| v.into_iter().map(|d| expect_bytes_n::<32>(d).map(Digest::from)).collect::<Result<Vec<_>, _>>();
        let p256 = |b: [u8; 65]| P256PublicKey::from_bytes(&b).map_err(|_| invalid("not a P-256 key"));
        let payload = match kind.as_str() {
            "open" => Self::Open {
                tick,
                tenancy: Digest::from(f.bytes_n::<32>("tenancy")?),
                sign_pub: p256(f.bytes_n::<65>("sign_pub")?)?,
                agree_pub: p256(f.bytes_n::<65>("agree_pub")?)?,
                evidence: digests(f.array("evidence")?)?,
                build_anchor: Digest::from(f.bytes_n::<32>("build_anchor")?),
            },
            "status" => Self::Status {
                tick,
                instrument: Fingerprint::from(f.bytes_n::<32>("instrument")?),
                subject: f.bytes("subject")?,
                status: StatusCode::parse(&f.text("status")?)?,
            },
            "consent" => Self::Consent {
                tick,
                instrument: Fingerprint::from(f.bytes_n::<32>("instrument")?),
                subject: f.bytes("subject")?,
                basis: f.text("basis")?,
                statement: Digest::from(f.bytes_n::<32>("statement")?),
                evidence: f
                    .array("evidence")?
                    .into_iter()
                    .map(|e| {
                        let mut g = Fields::new(e)?;
                        let r = EvidenceRef {
                            blob_id: g.bytes_n::<16>("blob_id")?,
                            sha256: Digest::from(g.bytes_n::<32>("sha256")?),
                            media_type: evidence_media(g.text("media_type")?)?,
                            size: g.uint("size")?,
                        };
                        g.finish()?;
                        Ok(r)
                    })
                    .collect::<Result<Vec<_>, WireError>>()?,
            },
            "evidence" => Self::Evidence {
                tick,
                blob_id: f.bytes_n::<16>("blob_id")?,
                media_type: evidence_media(f.text("media_type")?)?,
                bytes: f.bytes("bytes")?,
            },
            "anchor" => Self::Anchor {
                tick,
                kind: parse_anchor_kind(&f.text("kind")?)?,
                address: Digest::from(f.bytes_n::<32>("address")?),
                authority_time: f.uint("authority_time")?,
            },
            "import" => Self::Import {
                tick,
                bundle: Digest::from(f.bytes_n::<32>("bundle")?),
                artefacts: digests(f.array("artefacts")?)?,
                rosters: f
                    .array("rosters")?
                    .into_iter()
                    .map(|r| {
                        let mut g = Fields::new(r)?;
                        let r = ImportedRoster {
                            cohort: g.text("cohort")?,
                            version: g.uint("version")?,
                            address: Digest::from(g.bytes_n::<32>("address")?),
                        };
                        g.finish()?;
                        Ok(r)
                    })
                    .collect::<Result<Vec<_>, WireError>>()?,
            },
            "checkpoint" => Self::Checkpoint {
                tick,
                cleared_through: f.uint("cleared_through")?,
                hash_at: Digest::from(f.bytes_n::<32>("hash_at")?),
                delivery: Digest::from(f.bytes_n::<32>("delivery")?),
            },
            "closing" => Self::Closing {
                tick,
                last_seq: f.uint("last_seq")?,
                prev_hash: Digest::from(f.bytes_n::<32>("prev_hash")?),
                reason: ClosingReason::parse(&f.text("reason")?)?,
            },
            _ => return Err(invalid("unknown payload type")),
        };
        f.finish()?;
        Ok(payload)
    }

    /// Decodes canonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Self::from_value(cbor::decode(bytes)?)
    }
}
