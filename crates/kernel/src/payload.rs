//! Typed record payloads (WIRE §5.4, §5.5, §6.3): ticks, the `items` payload and the nine
//! other payload types (`open`, `status`, `consent`, `evidence`, `anchor`, `import`,
//! `key-roll`, `checkpoint`, `closing`). Every reader is closed (unknown fields refused),
//! exact in its types and checks each constraint the spec declares (WIRE-163).

use std::collections::BTreeMap;

use crate::cbor;
use crate::error::{ErrorCode, WireError};
use crate::crypto::P256PublicKey;
use crate::id::{ContentAddress, Digest, Fingerprint, ItemPath, RecordId};
use crate::structure::{Fields, expect_uint};
use crate::value::Value;

fn invalid(detail: &'static str) -> WireError {
    WireError::new(ErrorCode::UnknownField, 0, detail)
}

/// A record's tick (WIRE-070): `{anchor, slot, boot, ? wall}`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tick {
    /// Content address of the latest anchor in the journal (or the build anchor).
    pub anchor: Digest,
    /// Milliseconds since that anchor by the monotonic clock.
    pub slot: u64,
    /// The platform's boot counter.
    pub boot: u64,
    /// The device's wall clock, an untrusted hint, in ms since the Unix epoch.
    pub wall: Option<u64>,
}

impl Tick {
    /// The tick as a value.
    pub fn to_value(&self) -> Value {
        let mut m = BTreeMap::from([
            ("anchor".to_owned(), Value::Bytes(self.anchor.as_bytes().to_vec())),
            ("slot".to_owned(), Value::Int(i128::from(self.slot))),
            ("boot".to_owned(), Value::Int(i128::from(self.boot))),
        ]);
        if let Some(w) = self.wall {
            m.insert("wall".to_owned(), Value::Int(i128::from(w)));
        }
        Value::Map(m)
    }

    /// Reads a tick.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        let tick = Self {
            anchor: Digest::from(f.bytes_n::<32>("anchor")?),
            slot: f.uint("slot")?,
            boot: f.uint("boot")?,
            wall: f.take_opt("wall").map(expect_uint).transpose()?,
        };
        f.finish()?;
        Ok(tick)
    }
}

/// Whether `tag` is a well-formed BCP 47 language tag (RFC 5646 syntax, WIRE-051): a language
/// subtag with optional script, region, variants, extensions and private use, in ASCII,
/// hyphen separated. Case is not significant. Only syntax is checked, not registry membership.
pub fn is_bcp47(tag: &str) -> bool {
    tag.is_ascii() && tag.parse::<icu_locale_core::Locale>().is_ok()
}

/// Whether a value is a permitted item value (WIRE-052): text, integer, decimal, boolean, an
/// array of these, `{"nr": "dont-know" / "refused"}` or `{"retracted": true}`.
pub fn is_item_value(value: &Value) -> bool {
    let scalar = |v: &Value| matches!(v, Value::Text(_) | Value::Int(_) | Value::Decimal(_) | Value::Bool(_));
    match value {
        Value::Array(items) => items.iter().all(scalar),
        Value::Map(m) if m.len() == 1 => match m.iter().next() {
            Some((k, Value::Text(t))) if k == "nr" => t == "dont-know" || t == "refused",
            Some((k, Value::Bool(true))) => k == "retracted",
            _ => false,
        },
        v => scalar(v),
    }
}

/// The layout an `items` record was collected with (WIRE-051).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Layout {
    /// The generated default layout (INS-209), written `"default"`.
    Default,
    /// A published layout, by content address.
    Published(ContentAddress),
}

/// How an `items` record refers to the subject's consent (§6.3 `consent-ref`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ConsentRef {
    /// A consent record in the journal.
    Record(RecordId),
    /// Consent carried by a roster version.
    Roster {
        /// The roster's content address.
        roster: Digest,
        /// Its version.
        version: u64,
    },
    /// The instrument requires no consent (INS-062, COL-041), written `"not-required"`.
    NotRequired,
}

/// Why an `items` record was written (WIRE-051).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// A first capture.
    First,
    /// Continuing an interrupted capture.
    Resume,
    /// A repeat survey of the same subject.
    Resurvey,
    /// A correction of earlier values.
    Correction,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::First => "first",
            Mode::Resume => "resume",
            Mode::Resurvey => "resurvey",
            Mode::Correction => "correction",
        }
    }

    fn parse(text: &str) -> Result<Self, WireError> {
        Ok(match text {
            "first" => Mode::First,
            "resume" => Mode::Resume,
            "resurvey" => Mode::Resurvey,
            "correction" => Mode::Correction,
            _ => return Err(invalid("unknown items mode")),
        })
    }
}

/// An `items` payload (WIRE-051..053).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ItemsPayload {
    /// The record's tick.
    pub tick: Tick,
    /// The instrument's fingerprint (WIRE-186).
    pub instrument: Fingerprint,
    /// The layout used.
    pub layout: Layout,
    /// BCP 47 tags of every instrument language shown, in order of first use; never empty.
    pub lang: Vec<String>,
    /// The subject's identifier.
    pub subject: Vec<u8>,
    /// The consent the capture relied on.
    pub consent_ref: ConsentRef,
    /// Why the record was written.
    pub mode: Mode,
    /// Only the items the collector set (WIRE-051); each a permitted item value (WIRE-052).
    pub values: BTreeMap<ItemPath, Value>,
    /// Soft rules the collector confirmed, item path to reason code (WIRE-053).
    pub overrides: Option<BTreeMap<ItemPath, String>>,
    /// Rule identifiers raised at sealing (WIRE-053).
    pub flags: Option<Vec<String>>,
}

fn path(key: String) -> Result<ItemPath, WireError> {
    ItemPath::new(key).map_err(|_| invalid("not an item path"))
}

impl ItemsPayload {
    /// The payload as a value. Fails if a value is not a permitted item value or `lang` is
    /// empty.
    pub fn to_value(&self) -> Result<Value, WireError> {
        self.check()?;
        let mut m = BTreeMap::from([
            ("type".to_owned(), Value::Text("items".to_owned())),
            ("tick".to_owned(), self.tick.to_value()),
            ("instrument".to_owned(), Value::Bytes(self.instrument.as_bytes().to_vec())),
            (
                "layout".to_owned(),
                match self.layout {
                    Layout::Default => Value::Text("default".to_owned()),
                    Layout::Published(a) => Value::Bytes(a.as_bytes().to_vec()),
                },
            ),
            ("lang".to_owned(), Value::Array(self.lang.iter().cloned().map(Value::Text).collect())),
            ("subject".to_owned(), Value::Bytes(self.subject.clone())),
            (
                "consent_ref".to_owned(),
                match &self.consent_ref {
                    ConsentRef::Record(id) => cbor::map([("record", Value::Bytes(id.as_bytes().to_vec()))]),
                    ConsentRef::Roster { roster, version } => cbor::map([
                        ("roster", Value::Bytes(roster.as_bytes().to_vec())),
                        ("version", Value::Int(i128::from(*version))),
                    ]),
                    ConsentRef::NotRequired => Value::Text("not-required".to_owned()),
                },
            ),
            ("mode".to_owned(), Value::Text(self.mode.as_str().to_owned())),
            ("values".to_owned(), Value::Map(self.values.iter().map(|(k, v)| (k.as_str().to_owned(), v.clone())).collect())),
        ]);
        if let Some(o) = &self.overrides {
            let o = o.iter().map(|(k, v)| (k.as_str().to_owned(), Value::Text(v.clone()))).collect();
            m.insert("overrides".to_owned(), Value::Map(o));
        }
        if let Some(f) = &self.flags {
            m.insert("flags".to_owned(), Value::Array(f.iter().cloned().map(Value::Text).collect()));
        }
        Ok(Value::Map(m))
    }

    fn check(&self) -> Result<(), WireError> {
        if self.lang.is_empty() {
            return Err(invalid("lang must name at least one language"));
        }
        let mut seen = std::collections::BTreeSet::new();
        if !self.lang.iter().all(|l| !l.is_empty() && seen.insert(l.as_str())) {
            return Err(invalid("lang tags are non-empty and listed once, in order of first use"));
        }
        if !self.lang.iter().all(|l| is_bcp47(l)) {
            return Err(invalid("lang tags are well-formed BCP 47 language tags (WIRE-051)"));
        }
        if !self.values.values().all(is_item_value) {
            return Err(invalid("not a permitted item value"));
        }
        Ok(())
    }

    /// Reads an `items` payload; anything outside WIRE-051..053 is `E_UNKNOWN_FIELD`.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        if f.text("type")? != "items" {
            return Err(invalid("not an items payload"));
        }
        let tick = Tick::from_value(f.take("tick")?)?;
        let instrument = Fingerprint::from(f.bytes_n::<32>("instrument")?);
        let layout = match f.take("layout")? {
            Value::Text(t) if t == "default" => Layout::Default,
            Value::Bytes(b) => Layout::Published(ContentAddress::from_bytes(&b).map_err(|_| invalid("layout is not a hash"))?),
            _ => return Err(invalid("layout is a hash or \"default\"")),
        };
        let lang = f
            .array("lang")?
            .into_iter()
            .map(|v| match v {
                Value::Text(t) => Ok(t),
                _ => Err(invalid("lang entries are text")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let subject = f.bytes("subject")?;
        let consent_ref = match f.take("consent_ref")? {
            Value::Text(t) if t == "not-required" => ConsentRef::NotRequired,
            Value::Text(_) => return Err(invalid("consent_ref text must be \"not-required\"")),
            other => {
            let mut c = Fields::new(other)?;
            let r = match c.take_opt("record") {
                Some(v) => ConsentRef::Record(RecordId::from(crate::structure::expect_bytes_n::<16>(v)?)),
                None => ConsentRef::Roster { roster: Digest::from(c.bytes_n::<32>("roster")?), version: c.uint("version")? },
            };
            c.finish()?;
            r
            }
        };
        let mode = Mode::parse(&f.text("mode")?)?;
        let values = match f.take("values")? {
            Value::Map(m) => m.into_iter().map(|(k, v)| Ok((path(k)?, v))).collect::<Result<BTreeMap<_, _>, WireError>>()?,
            _ => return Err(invalid("values is a map")),
        };
        let overrides = match f.take_opt("overrides") {
            None => None,
            Some(Value::Map(m)) => Some(
                m.into_iter()
                    .map(|(k, v)| match v {
                        Value::Text(t) => Ok((path(k)?, t)),
                        _ => Err(invalid("override reasons are text")),
                    })
                    .collect::<Result<BTreeMap<_, _>, WireError>>()?,
            ),
            Some(_) => return Err(invalid("overrides is a map")),
        };
        let flags = match f.take_opt("flags") {
            None => None,
            Some(Value::Array(a)) => Some(
                a.into_iter()
                    .map(|v| match v {
                        Value::Text(t) => Ok(t),
                        _ => Err(invalid("flags are text")),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Some(_) => return Err(invalid("flags is an array")),
        };
        f.finish()?;
        let payload = Self { tick, instrument, layout, lang, subject, consent_ref, mode, values, overrides, flags };
        payload.check()?;
        Ok(payload)
    }
}

/// The largest evidence image a payload may carry (§6.7: evidence bytes, 3 MiB).
pub const MAX_EVIDENCE_BYTES: u64 = 3 * 1024 * 1024;

/// The media types an evidence image may carry (WIRE-214).
pub const EVIDENCE_MEDIA_TYPES: [&str; 3] = ["image/jpeg", "image/png", "image/webp"];

fn bytes_value(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn uint_value(n: u64) -> Value {
    Value::Int(i128::from(n))
}

fn text_value(t: &str) -> Value {
    Value::Text(t.to_owned())
}

fn evidence_media(media_type: String) -> Result<String, WireError> {
    if EVIDENCE_MEDIA_TYPES.contains(&media_type.as_str()) {
        Ok(media_type)
    } else {
        Err(invalid("media_type is not an allowed evidence media type"))
    }
}

fn unique<T: Ord>(items: &[T], detail: &'static str) -> Result<(), WireError> {
    let mut seen = std::collections::BTreeSet::new();
    if items.iter().all(|i| seen.insert(i)) { Ok(()) } else { Err(invalid(detail)) }
}

fn digests(values: Vec<Value>) -> Result<Vec<Digest>, WireError> {
    values.into_iter().map(|d| crate::structure::expect_bytes_n::<32>(d).map(Digest::from)).collect()
}

fn digest_values(items: &[Digest]) -> Value {
    Value::Array(items.iter().map(|d| bytes_value(d.as_bytes())).collect())
}

fn p256(f: &mut Fields, key: &str) -> Result<P256PublicKey, WireError> {
    let b = f.bytes_n::<65>(key)?;
    P256PublicKey::from_bytes(&b).map_err(|_| invalid("not a valid uncompressed P-256 public key"))
}

macro_rules! text_enum {
    ($(#[$m:meta])* $name:ident, $what:literal, { $($(#[$vm:meta])* $variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        pub enum $name {
            $($(#[$vm])* $variant),+
        }

        impl $name {
            /// The code as written on the wire.
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }

            /// Parses the code; any other text is `E_UNKNOWN_FIELD`.
            pub fn parse(text: &str) -> Result<Self, WireError> {
                match text { $($text => Ok(Self::$variant),)+ _ => Err(invalid($what)) }
            }
        }
    };
}

text_enum!(
    /// A `status` payload's code (WIRE-054).
    StatusCode, "unknown status code", {
        /// The subject was absent.
        Absent => "absent",
        /// The subject declined.
        Declined => "declined",
        /// The person was not the subject.
        NotSubject => "not-subject",
    }
);

text_enum!(
    /// The kind of an `anchor` payload (WIRE-057).
    AnchorKind, "unknown anchor kind", {
        /// The runtime build.
        Build => "build",
        /// An imported bundle.
        Bundle => "bundle",
        /// An authority receipt.
        Receipt => "receipt",
        /// A time token.
        TimeToken => "time-token",
    }
);

text_enum!(
    /// Why a journal closed (WIRE-061).
    ClosingReason, "unknown closing reason", {
        /// The collector ended the tenancy.
        Collector => "collector",
        /// A close certificate.
        CloseCertificate => "close-certificate",
        /// A reset certificate.
        ResetCertificate => "reset-certificate",
        /// The device was returned.
        Returned => "returned",
    }
);

/// An evidence reference in a `consent` payload (WIRE-055).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EvidenceRef {
    /// The evidence record's blob ID.
    pub blob_id: [u8; 16],
    /// SHA-256 of the evidence bytes.
    pub sha256: Digest,
    /// Its media type (one of [`EVIDENCE_MEDIA_TYPES`]).
    pub media_type: String,
    /// Its size in bytes, 1 to [`MAX_EVIDENCE_BYTES`].
    pub size: u64,
}

/// A roster version an `import` payload names (WIRE-058).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ImportedRoster {
    /// The cohort, non-empty.
    pub cohort: String,
    /// The roster version.
    pub version: u64,
    /// Its content address.
    pub address: Digest,
}

/// An `open` payload (WIRE-062).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OpenPayload {
    /// The tick.
    pub tick: Tick,
    /// The tenancy ID.
    pub tenancy: Digest,
    /// The signing public key.
    pub sign_pub: P256PublicKey,
    /// The agreement public key.
    pub agree_pub: P256PublicKey,
    /// Content addresses of the keys' attestation evidence, each listed once.
    pub evidence: Vec<Digest>,
    /// The runtime build's release anchor.
    pub build_anchor: Digest,
}

/// A `status` payload (WIRE-054).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StatusPayload {
    /// The tick.
    pub tick: Tick,
    /// The instrument's fingerprint.
    pub instrument: Fingerprint,
    /// The subject.
    pub subject: Vec<u8>,
    /// The status code.
    pub status: StatusCode,
}

/// A `consent` payload (WIRE-055).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConsentPayload {
    /// The tick.
    pub tick: Tick,
    /// The instrument's fingerprint.
    pub instrument: Fingerprint,
    /// The subject.
    pub subject: Vec<u8>,
    /// The basis code, non-empty, from the instrument's list.
    pub basis: String,
    /// The consent statement's content address.
    pub statement: Digest,
    /// Evidence references; each blob ID appears once.
    pub evidence: Vec<EvidenceRef>,
}

/// An `evidence` payload (WIRE-056). In a local record `bytes` is empty (COL-043).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EvidencePayload {
    /// The tick.
    pub tick: Tick,
    /// The blob ID.
    pub blob_id: [u8; 16],
    /// The media type (one of [`EVIDENCE_MEDIA_TYPES`]).
    pub media_type: String,
    /// The image bytes, at most [`MAX_EVIDENCE_BYTES`].
    pub bytes: Vec<u8>,
}

/// An `anchor` payload (WIRE-057).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AnchorPayload {
    /// The tick.
    pub tick: Tick,
    /// The anchor's kind.
    pub kind: AnchorKind,
    /// Its content address.
    pub address: Digest,
    /// The authority time it states, in milliseconds (WIRE-008).
    pub authority_time: u64,
}

/// An `import` payload (WIRE-058).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ImportPayload {
    /// The tick.
    pub tick: Tick,
    /// The bundle's content address.
    pub bundle: Digest,
    /// Each artefact loaded, listed once.
    pub artefacts: Vec<Digest>,
    /// Each roster version loaded, listed once per cohort and version.
    pub rosters: Vec<ImportedRoster>,
}

/// A `key-roll` payload (WIRE-059).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyRollPayload {
    /// The tick.
    pub tick: Tick,
    /// The new key's index.
    pub index: u64,
    /// The new signing key.
    pub public_key: P256PublicKey,
    /// The content address of its attestation evidence.
    pub evidence: Digest,
}

/// A `checkpoint` payload (WIRE-060).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CheckpointPayload {
    /// The tick.
    pub tick: Tick,
    /// Records with `seq` at or below this were cleared.
    pub cleared_through: u64,
    /// The record hash at `cleared_through`.
    pub hash_at: Digest,
    /// The delivery evidence that allowed the clear (32 zero bytes when none, ADR 0029).
    pub delivery: Digest,
}

/// A `closing` payload (WIRE-061).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClosingPayload {
    /// The tick.
    pub tick: Tick,
    /// The closing record's own `seq`.
    pub last_seq: u64,
    /// The hash of the record before it.
    pub prev_hash: Digest,
    /// Why the journal closed.
    pub reason: ClosingReason,
}

/// Any record payload (WIRE-050), read strictly by its `type`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Payload {
    /// `open` (WIRE-062).
    Open(OpenPayload),
    /// `items` (WIRE-051).
    Items(Box<ItemsPayload>),
    /// `status` (WIRE-054).
    Status(StatusPayload),
    /// `consent` (WIRE-055).
    Consent(ConsentPayload),
    /// `evidence` (WIRE-056).
    Evidence(EvidencePayload),
    /// `anchor` (WIRE-057).
    Anchor(AnchorPayload),
    /// `import` (WIRE-058).
    Import(ImportPayload),
    /// `key-roll` (WIRE-059).
    KeyRoll(KeyRollPayload),
    /// `checkpoint` (WIRE-060).
    Checkpoint(CheckpointPayload),
    /// `closing` (WIRE-061).
    Closing(ClosingPayload),
}

fn typed(kind: &str, tick: &Tick, rest: Vec<(&'static str, Value)>) -> Value {
    let mut m: BTreeMap<String, Value> = rest.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
    m.insert("type".to_owned(), text_value(kind));
    m.insert("tick".to_owned(), tick.to_value());
    Value::Map(m)
}

impl Payload {
    /// The payload's `type` (WIRE-050).
    pub fn type_name(&self) -> &'static str {
        match self {
            Payload::Open(_) => "open",
            Payload::Items(_) => "items",
            Payload::Status(_) => "status",
            Payload::Consent(_) => "consent",
            Payload::Evidence(_) => "evidence",
            Payload::Anchor(_) => "anchor",
            Payload::Import(_) => "import",
            Payload::KeyRoll(_) => "key-roll",
            Payload::Checkpoint(_) => "checkpoint",
            Payload::Closing(_) => "closing",
        }
    }

    /// The payload's tick.
    pub fn tick(&self) -> &Tick {
        match self {
            Payload::Open(p) => &p.tick,
            Payload::Items(p) => &p.tick,
            Payload::Status(p) => &p.tick,
            Payload::Consent(p) => &p.tick,
            Payload::Evidence(p) => &p.tick,
            Payload::Anchor(p) => &p.tick,
            Payload::Import(p) => &p.tick,
            Payload::KeyRoll(p) => &p.tick,
            Payload::Checkpoint(p) => &p.tick,
            Payload::Closing(p) => &p.tick,
        }
    }

    /// The payload as a value. Fails if a constraint of its type is broken, so a writer cannot
    /// emit what a reader refuses.
    pub fn to_value(&self) -> Result<Value, WireError> {
        let value = match self {
            Payload::Items(p) => return p.to_value(),
            Payload::Open(p) => typed(
                "open",
                &p.tick,
                vec![
                    ("tenancy", bytes_value(p.tenancy.as_bytes())),
                    ("sign_pub", bytes_value(p.sign_pub.as_bytes())),
                    ("agree_pub", bytes_value(p.agree_pub.as_bytes())),
                    ("evidence", digest_values(&p.evidence)),
                    ("build_anchor", bytes_value(p.build_anchor.as_bytes())),
                ],
            ),
            Payload::Status(p) => typed(
                "status",
                &p.tick,
                vec![
                    ("instrument", bytes_value(p.instrument.as_bytes())),
                    ("subject", bytes_value(&p.subject)),
                    ("status", text_value(p.status.as_str())),
                ],
            ),
            Payload::Consent(p) => typed(
                "consent",
                &p.tick,
                vec![
                    ("instrument", bytes_value(p.instrument.as_bytes())),
                    ("subject", bytes_value(&p.subject)),
                    ("basis", text_value(&p.basis)),
                    ("statement", bytes_value(p.statement.as_bytes())),
                    (
                        "evidence",
                        Value::Array(
                            p.evidence
                                .iter()
                                .map(|e| {
                                    cbor::map([
                                        ("blob_id", bytes_value(&e.blob_id)),
                                        ("sha256", bytes_value(e.sha256.as_bytes())),
                                        ("media_type", text_value(&e.media_type)),
                                        ("size", uint_value(e.size)),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                ],
            ),
            Payload::Evidence(p) => typed(
                "evidence",
                &p.tick,
                vec![
                    ("blob_id", bytes_value(&p.blob_id)),
                    ("media_type", text_value(&p.media_type)),
                    ("bytes", bytes_value(&p.bytes)),
                ],
            ),
            Payload::Anchor(p) => typed(
                "anchor",
                &p.tick,
                vec![
                    ("kind", text_value(p.kind.as_str())),
                    ("address", bytes_value(p.address.as_bytes())),
                    ("authority_time", uint_value(p.authority_time)),
                ],
            ),
            Payload::Import(p) => typed(
                "import",
                &p.tick,
                vec![
                    ("bundle", bytes_value(p.bundle.as_bytes())),
                    ("artefacts", digest_values(&p.artefacts)),
                    (
                        "rosters",
                        Value::Array(
                            p.rosters
                                .iter()
                                .map(|r| {
                                    cbor::map([
                                        ("cohort", text_value(&r.cohort)),
                                        ("version", uint_value(r.version)),
                                        ("address", bytes_value(r.address.as_bytes())),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                ],
            ),
            Payload::KeyRoll(p) => typed(
                "key-roll",
                &p.tick,
                vec![
                    ("index", uint_value(p.index)),
                    ("public_key", bytes_value(p.public_key.as_bytes())),
                    ("evidence", bytes_value(p.evidence.as_bytes())),
                ],
            ),
            Payload::Checkpoint(p) => typed(
                "checkpoint",
                &p.tick,
                vec![
                    ("cleared_through", uint_value(p.cleared_through)),
                    ("hash_at", bytes_value(p.hash_at.as_bytes())),
                    ("delivery", bytes_value(p.delivery.as_bytes())),
                ],
            ),
            Payload::Closing(p) => typed(
                "closing",
                &p.tick,
                vec![
                    ("last_seq", uint_value(p.last_seq)),
                    ("prev_hash", bytes_value(p.prev_hash.as_bytes())),
                    ("reason", text_value(p.reason.as_str())),
                ],
            ),
        };
        // Constraints are checked on the way out by reading the value back.
        Payload::from_value(value.clone())?;
        Ok(value)
    }

    /// Canonical CBOR.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        cbor::encode(&self.to_value()?)
    }

    /// Reads a payload by its `type`. A missing or non-text `type`, an unknown type, an unknown
    /// or missing field, a wrongly typed field or a broken constraint is `E_UNKNOWN_FIELD`.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let kind = match &value {
            Value::Map(m) => match m.get("type") {
                Some(Value::Text(t)) => t.clone(),
                _ => return Err(invalid("payload has no text type")),
            },
            _ => return Err(invalid("payload is not a map")),
        };
        if kind == "items" {
            return ItemsPayload::from_value(value).map(|p| Payload::Items(Box::new(p)));
        }
        let mut f = Fields::new(value)?;
        f.text("type")?;
        let tick = Tick::from_value(f.take("tick")?)?;
        let payload = match kind.as_str() {
            "open" => {
                let p = OpenPayload {
                    tick,
                    tenancy: Digest::from(f.bytes_n::<32>("tenancy")?),
                    sign_pub: p256(&mut f, "sign_pub")?,
                    agree_pub: p256(&mut f, "agree_pub")?,
                    evidence: digests(f.array("evidence")?)?,
                    build_anchor: Digest::from(f.bytes_n::<32>("build_anchor")?),
                };
                unique(&p.evidence, "open evidence addresses are listed once")?;
                Payload::Open(p)
            }
            "status" => Payload::Status(StatusPayload {
                tick,
                instrument: Fingerprint::from(f.bytes_n::<32>("instrument")?),
                subject: f.bytes("subject")?,
                status: StatusCode::parse(&f.text("status")?)?,
            }),
            "consent" => {
                let p = ConsentPayload {
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
                            if r.size == 0 || r.size > MAX_EVIDENCE_BYTES {
                                return Err(invalid("evidence size is 1 byte to 3 MiB"));
                            }
                            Ok(r)
                        })
                        .collect::<Result<Vec<_>, WireError>>()?,
                };
                if p.basis.is_empty() {
                    return Err(invalid("consent basis is not empty"));
                }
                unique(&p.evidence.iter().map(|e| e.blob_id).collect::<Vec<_>>(), "evidence blob IDs are listed once")?;
                Payload::Consent(p)
            }
            "evidence" => {
                let p = EvidencePayload {
                    tick,
                    blob_id: f.bytes_n::<16>("blob_id")?,
                    media_type: evidence_media(f.text("media_type")?)?,
                    bytes: f.bytes("bytes")?,
                };
                if p.bytes.len() as u64 > MAX_EVIDENCE_BYTES {
                    return Err(WireError::new(ErrorCode::Size, 0, "evidence bytes exceed 3 MiB"));
                }
                Payload::Evidence(p)
            }
            "anchor" => Payload::Anchor(AnchorPayload {
                tick,
                kind: AnchorKind::parse(&f.text("kind")?)?,
                address: Digest::from(f.bytes_n::<32>("address")?),
                authority_time: f.uint("authority_time")?,
            }),
            "import" => {
                let p = ImportPayload {
                    tick,
                    bundle: Digest::from(f.bytes_n::<32>("bundle")?),
                    artefacts: digests(f.array("artefacts")?)?,
                    rosters: f
                        .array("rosters")?
                        .into_iter()
                        .map(|r| {
                            let mut g = Fields::new(r)?;
                            let x = ImportedRoster {
                                cohort: g.text("cohort")?,
                                version: g.uint("version")?,
                                address: Digest::from(g.bytes_n::<32>("address")?),
                            };
                            g.finish()?;
                            if x.cohort.is_empty() {
                                return Err(invalid("roster cohort is not empty"));
                            }
                            Ok(x)
                        })
                        .collect::<Result<Vec<_>, WireError>>()?,
                };
                unique(&p.artefacts, "imported artefacts are listed once")?;
                unique(&p.rosters.iter().map(|r| (r.cohort.clone(), r.version)).collect::<Vec<_>>(), "roster versions are listed once")?;
                Payload::Import(p)
            }
            "key-roll" => Payload::KeyRoll(KeyRollPayload {
                tick,
                index: f.uint("index")?,
                public_key: p256(&mut f, "public_key")?,
                evidence: Digest::from(f.bytes_n::<32>("evidence")?),
            }),
            "checkpoint" => Payload::Checkpoint(CheckpointPayload {
                tick,
                cleared_through: f.uint("cleared_through")?,
                hash_at: Digest::from(f.bytes_n::<32>("hash_at")?),
                delivery: Digest::from(f.bytes_n::<32>("delivery")?),
            }),
            "closing" => Payload::Closing(ClosingPayload {
                tick,
                last_seq: f.uint("last_seq")?,
                prev_hash: Digest::from(f.bytes_n::<32>("prev_hash")?),
                reason: ClosingReason::parse(&f.text("reason")?)?,
            }),
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
