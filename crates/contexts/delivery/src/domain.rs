//! Entities, value objects and invariants of the Delivery context
//! (`docs/reference/spec/delivery.md` §2).

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::Signature;
use fieldseal_kernel::id::{Digest, KeyId, Nonce, Seq, TenancyHandle};
use fieldseal_kernel::sign::SIGNATURE_LEN;
use fieldseal_kernel::structure::Fields;
use fieldseal_kernel::{ErrorCode, Value, WireError};
use fieldseal_policy::domain::ExportDestination;
use fieldseal_trust::domain::KeyCertificate;

use crate::ports::{ReceiverCheck, ReceiverCheckError};

/// Where an export copy went, decided from the destination, never from the collector's word.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DestinationClass {
    /// An authorised upload destination.
    Upload,
    /// On-device storage.
    Local,
    /// Removable storage (USB, SD card).
    Removable,
    /// A cloud provider through the file picker.
    Cloud,
    /// Another app through the share sheet.
    Share,
}

/// What a copy attempt achieved.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AttemptOutcome {
    /// The authority sent a receipt that verified.
    ReceiptVerified,
    /// Written, synced and read back identical.
    ReadBackMatched,
    /// Handed over; nothing could be checked.
    HandedOver,
    /// It failed.
    Failed,
}

impl DestinationClass {
    /// The policy name of the class (`runtime.export.destinations`, DEL-021).
    pub fn destination(self) -> ExportDestination {
        match self {
            Self::Upload => ExportDestination::Upload,
            Self::Local => ExportDestination::Local,
            Self::Removable => ExportDestination::Removable,
            Self::Cloud => ExportDestination::Cloud,
            Self::Share => ExportDestination::Share,
        }
    }
}

/// What the collector is told (ADR 0021).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DeliveryLabel {
    /// "Received".
    Received,
    /// "Saved and checked".
    SavedAndChecked,
    /// "Handed over — not confirmed".
    HandedOverNotConfirmed,
    /// "Failed".
    Failed,
}

impl DeliveryLabel {
    /// The label's exact text (DEL-027); a shell translates it only through its
    /// localisation catalogue, with the same meaning.
    pub fn text(self) -> &'static str {
        match self {
            Self::Received => "Received",
            Self::SavedAndChecked => "Saved and checked",
            Self::HandedOverNotConfirmed => "Handed over \u{2014} not confirmed",
            Self::Failed => "Failed",
        }
    }
}

/// The label a copy earns: only a verified receipt is "Received", only a read-back on
/// local or removable storage is "Saved and checked"; anything else is at most
/// "Handed over" (a handed-over copy never counts as delivered).
pub fn label_for(class: DestinationClass, outcome: AttemptOutcome) -> DeliveryLabel {
    match (class, outcome) {
        (_, AttemptOutcome::Failed) => DeliveryLabel::Failed,
        (DestinationClass::Upload, AttemptOutcome::ReceiptVerified) => DeliveryLabel::Received,
        (DestinationClass::Local | DestinationClass::Removable, AttemptOutcome::ReadBackMatched) => {
            DeliveryLabel::SavedAndChecked
        }
        _ => DeliveryLabel::HandedOverNotConfirmed,
    }
}

/// Where an address came from. Every source is untrusted (DEL-061).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum HintSource {
    /// Device provisioning configuration.
    DeviceConfiguration,
    /// A scanned QR code.
    ScannedQr,
    /// Typed by the collector.
    CollectorEntry,
    /// A previous successful upload.
    PreviousSuccess,
    /// An advisory hint in a bundle.
    BundleHint,
}

/// A destination address: a hint, never a reason to trust (ADR 0021).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct AddressHint {
    /// The address.
    pub address: String,
    /// Where it came from.
    pub source: HintSource,
}

/// The challenge a destination must answer before anything is uploaded (WIRE-180).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReceiverChallenge {
    nonce: Nonce,
    tenancy_handle: TenancyHandle,
}

impl ReceiverChallenge {
    /// The purpose bound into every challenge.
    pub const PURPOSE: &'static str = "upload";

    /// A challenge for one tenancy, with a fresh nonce from the caller.
    pub fn new(nonce: Nonce, tenancy_handle: TenancyHandle) -> Self {
        Self { nonce, tenancy_handle }
    }

    /// The nonce.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// The tenancy handle.
    pub fn tenancy_handle(&self) -> &TenancyHandle {
        &self.tenancy_handle
    }

    /// The challenge as a value: `{"v": 1, "nonce", "tenancy_handle", "purpose": "upload"}`.
    pub fn to_value(&self) -> Value {
        cbor::map([
            ("v", Value::Int(1)),
            ("nonce", Value::Bytes(self.nonce.as_bytes().to_vec())),
            ("tenancy_handle", Value::Bytes(self.tenancy_handle.as_bytes().to_vec())),
            ("purpose", Value::Text(Self::PURPOSE.to_owned())),
        ])
    }

    /// Canonical CBOR, the body of the challenge request.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("a challenge encodes")
    }

    /// Reads a challenge; a purpose other than `upload` or a version other than 1 is refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut f = Fields::new(cbor::decode_limited(bytes, 256)?)?;
        f.version("v", &Value::Int(1))?;
        let nonce = Nonce::from(f.bytes_n::<32>("nonce")?);
        let tenancy_handle = TenancyHandle::from(f.bytes_n::<16>("tenancy_handle")?);
        f.version("purpose", &Value::Text(Self::PURPOSE.to_owned()))?;
        f.finish()?;
        Ok(Self { nonce, tenancy_handle })
    }
}

/// A destination's answer: its receiver certificate and a signature over the challenge.
/// It never depends on the destination's address (WIRE-182).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReceiverProof {
    /// The `receiver` key certificate.
    pub certificate: KeyCertificate,
    /// The receiver key's signature over the challenge.
    pub signature: Signature,
}

impl ReceiverProof {
    /// Canonical CBOR: `{"v": 1, "cert": KeyCertificate, "sig": Signature}` (WIRE-181).
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&cbor::map([
            ("v", Value::Int(1)),
            ("cert", self.certificate.to_value()),
            ("sig", Value::Bytes(self.signature.0.clone())),
        ]))
        .expect("a proof encodes")
    }

    /// Reads an answer (at most 4 KiB).
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut f = Fields::new(cbor::decode_limited(bytes, 4096)?)?;
        f.version("v", &Value::Int(1))?;
        let cert = f.take("cert")?;
        let certificate = KeyCertificate::from_value(cert).map_err(|e| WireError::new(ErrorCode::UnknownField, 0, if e.code == ErrorCode::Sig { "receiver certificate signature" } else { "receiver certificate" }))?;
        let signature = Signature(f.bytes_n::<SIGNATURE_LEN>("sig")?.to_vec());
        f.finish()?;
        Ok(Self { certificate, signature })
    }
}

/// A destination that proved it holds an authority-certified receiver key. It can only
/// be created by [`AuthorisedDestination::authorise`], so nothing is uploaded to an
/// address that hasn't passed the challenge (DEL-062).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthorisedDestination {
    address: AddressHint,
    receiver: KeyId,
}

impl AuthorisedDestination {
    /// Checks a destination's answer to `challenge`.
    pub fn authorise(
        address: AddressHint,
        challenge: &ReceiverChallenge,
        proof: &ReceiverProof,
        check: &(impl ReceiverCheck + ?Sized),
    ) -> Result<Self, ReceiverCheckError> {
        let receiver = check.verify(challenge, proof)?;
        Ok(Self { address, receiver })
    }

    /// Where to send.
    pub fn address(&self) -> &AddressHint {
        &self.address
    }

    /// The receiver key that authorised it.
    pub fn receiver(&self) -> &KeyId {
        &self.receiver
    }
}

/// The routes of an upload endpoint. Paths are protocol constants; the base URL is never
/// compiled in (DEL-060).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum UploadRoute {
    /// The receiver challenge (WIRE-180).
    Challenge,
    /// An active tenancy's upload, with a proof-of-possession token (DEL-002).
    Tenancy,
    /// An outbox part, with no live key (DEL-052).
    Outbox,
}

impl UploadRoute {
    /// The route's path.
    pub fn path(self) -> &'static str {
        match self {
            Self::Challenge => "/v1/challenge",
            Self::Tenancy => "/v1/upload",
            Self::Outbox => "/v1/upload/outbox",
        }
    }

    /// The route's URL under `base`, which must be an untrusted hint's address.
    pub fn url(self, base: &str) -> String {
        format!("{}{}", base.trim_end_matches('/'), self.path())
    }
}

/// One upload request: the route, the body and, for a tenancy upload, the token.
///
/// The body is an export file without parity (DEL-016).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UploadRequest {
    /// Which route.
    pub route: UploadRoute,
    /// The export file.
    pub body: Vec<u8>,
    /// The proof-of-possession token, bound to this request's method and URL.
    pub pop: Option<PopToken>,
}

pub use fieldseal_kernel::pop::{POP_HEADER, PopToken};

/// An export's identifier: the SHA-256 of its file.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ExportId(pub Digest);

/// One export file built from the journal or an outbox part (DEL §2 `Export`). The file
/// itself is in private storage under [`Export::id`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Export {
    /// Its identifier.
    pub id: ExportId,
    /// The tenancy it exports; `None` for an outbox export, which holds closed tenancies.
    pub tenancy: Option<fieldseal_kernel::id::TenancyId>,
    /// First `seq` included.
    pub from: Seq,
    /// Last `seq` included.
    pub through: Seq,
    /// Records in it.
    pub records: u64,
    /// Whether Reed-Solomon parity is included.
    pub parity: bool,
    /// The file's size in bytes.
    pub size: u64,
    /// Its readable name (DEL-017).
    pub name: String,
}

/// One copy attempt and what it earned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DestinationAttempt {
    /// Where it went.
    pub class: DestinationClass,
    /// What happened.
    pub outcome: AttemptOutcome,
    /// What the collector is told.
    pub label: DeliveryLabel,
}

impl DestinationAttempt {
    /// An attempt with its label derived by [`label_for`].
    pub fn new(class: DestinationClass, outcome: AttemptOutcome) -> Self {
        Self { class, outcome, label: label_for(class, outcome) }
    }
}

/// The date `ms` milliseconds after the Unix epoch falls on, as `(year, month, day)` in UTC.
pub fn civil_date(ms: u64) -> (i64, u32, u32) {
    // Howard Hinnant's days-to-civil algorithm.
    let z = (ms / 86_400_000) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The export file name: `<prefix> export <YYYY-MM-DD> (<n>).<ext>` (DEL-017). It carries
/// the deployment's prefix and extension, the device's wall-clock date and a per-tenancy
/// counter, and nothing that identifies a subject, cohort, collector, device or count.
/// Without a wall clock the date reads `0000-00-00`.
pub fn export_file_name(prefix: &str, extension: &str, wall_ms: Option<u64>, n: u64) -> String {
    let date = wall_ms.map_or("0000-00-00".to_owned(), |ms| {
        let (y, m, d) = civil_date(ms);
        format!("{y:04}-{m:02}-{d:02}")
    });
    format!("{prefix} export {date} ({n}).{extension}")
}
