//! Use cases: the driving ports the Collection context offers
//! (`docs/reference/spec/collection.md` §3), implemented by [`Runtime`].
//!
//! [`Runtime`] is the device-side application service. It is pure in the ADR 0028 sense:
//! time, randomness, keys, storage, the display, device policy and the camera all come
//! through the ports in [`Platform`]. A platform shell (Android, the CLI simulator) builds a
//! [`Platform`] from its adapters and drives the runtime; every durable effect goes through
//! [`crate::ports::SecureStorage`] so the shell's process can be killed at any point
//! (COL-092, COL-093).
//!
//! | Spec port | Methods |
//! |---|---|
//! | `CreateTenancy`, `OpenSession`, `LockSession` | [`Runtime::create_tenancy`], [`Runtime::open_session`], [`Runtime::lock`], [`Runtime::on_lock_trigger`] |
//! | `StartCapture`, `SetValue`, `ClearValue`, `AcknowledgeIncomplete`, `Seal` | [`Runtime::start_capture`], [`Runtime::set_value`], [`Runtime::clear_value`], [`Runtime::override_soft`], [`Runtime::acknowledge_incomplete`], [`Runtime::seal`], [`Runtime::pause`], [`Runtime::discard_capture`] |
//! | `RecordConsent`, `RecordStatus` | [`Runtime::record_consent`], [`Runtime::record_status`] |
//! | `Review` | [`Runtime::review`] |
//! | `Clear` | [`Runtime::clear_preview`], [`Runtime::clear`], [`Runtime::apply_receipt`], [`Runtime::clear_offer`] |
//! | `EndTenancy`, `ApplyCloseCertificate` | [`Runtime::end_tenancy`], [`Runtime::apply_close_certificate`] |
//! | bundle import (DIS) | [`Runtime::import_bundle`] |

mod bundle;
mod capture;
mod clear;
mod close;
mod export;
mod records;
mod recover;
mod review;
mod session;

use fieldseal_kernel::id::{Digest, Seq, SubjectId, TenancyId};
use fieldseal_kernel::local_record::SessionKey;
use fieldseal_kernel::time::ElapsedReading;
use fieldseal_policy::domain::{PublishingPolicy, RuntimeEvaluator};
use fieldseal_trust::domain::TrustBundle;
use fieldseal_trust::ports::{Attestor, RandomSource, SecureKeyStore};

use crate::domain::TenancyState;
use crate::domain::capture::Capture;
use crate::domain::meta::TenancyMeta;
use crate::domain::ticks::TickState;
use crate::domain::{StorageClass, StorageName, WindowId};
use crate::ports::{
    BundleOpener, Camera, DevicePolicy, ElapsedClock, MemoryHardHash, SecureDisplay, SecureStorage, StorageError,
    WallClock,
};

pub use self::bundle::Held;
pub use self::capture::{CaptureView, ConsentInput, StatusOutcome};
pub use self::clear::{ClearOutcome, ClearPreview, ReceiptOutcome};
pub use self::close::{OutboxEntry, OutboxSummary};
pub use self::export::ExportSource;
pub use self::recover::RecoveryReport;
pub use self::review::{CheckView, ClearedCounts, RecordView, ReviewFilter, ReviewReport, SubjectReview};
pub use self::session::SessionInfo;
pub use crate::domain::capture::CaptureMode;

/// Why a collection use case failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CollectionError {
    /// The platform can't meet an invariant (secure display, hardware keys) (PLAT-045).
    #[error("platform unsupported: {0}")]
    PlatformUnsupported(String),
    /// There is no tenancy on the device.
    #[error("no tenancy")]
    NoTenancy,
    /// A tenancy is already open on the device (COL-001).
    #[error("a tenancy is already open on this device")]
    TenancyExists,
    /// The tenancy's state doesn't allow this.
    #[error("not allowed in state {0:?}")]
    WrongState(TenancyState),
    /// The runtime PIN is shorter than policy allows (COL-021).
    #[error("PIN too short: at least {0} digits")]
    PinTooShort(u64),
    /// No session is open.
    #[error("session locked")]
    Locked,
    /// Wrong PIN; wait this many seconds before the next try (COL-023).
    #[error("wrong PIN; wait {0} s")]
    WrongPin(u64),
    /// Too many wrong PINs; wait this many seconds (COL-023).
    #[error("locked out for {0} s")]
    LockedOut(u64),
    /// The clear was cancelled: the two PIN entries differed, or the PIN was wrong. It
    /// counts toward lockout (COL-101).
    #[error("clear cancelled: {0}")]
    ClearCancelled(String),
    /// The subject refused consent: nothing may be recorded (COL-030, ADR 0022).
    #[error("consent refused")]
    ConsentRefused,
    /// Consent must be recorded first (COL-031).
    #[error("consent needed")]
    ConsentNeeded,
    /// The subject isn't on any roster held.
    #[error("not in roster")]
    NotInRoster,
    /// No bundle is held.
    #[error("no bundle held")]
    NoBundle,
    /// No capture is open.
    #[error("no capture open")]
    NoCapture,
    /// A capture with unsealed values is open; seal, pause or discard it first (COL-038).
    #[error("a capture with unsealed values is open")]
    CaptureOpen,
    /// The item can't be set now (COL §3 `NotEditable`).
    #[error("not editable: {0}")]
    NotEditable(String),
    /// The value isn't one the control accepts (COL §3 `OutOfRange`).
    #[error("out of range: {0}")]
    OutOfRange(String),
    /// A hard verdict or value problem blocks sealing (COL-035).
    #[error("hard verdict: {0}")]
    HardVerdict(String),
    /// A soft verdict lacks a changed answer or a reason (COL-035).
    #[error("soft verdict needs a changed answer or a reason: {0}")]
    SoftVerdict(String),
    /// Unanswered items must be acknowledged first (COL-036).
    #[error("{0} unanswered items not acknowledged")]
    IncompleteNotAcknowledged(usize),
    /// Nothing was set or changed.
    #[error("nothing to seal")]
    NothingToSeal,
    /// The operation isn't allowed (COL §3 `NotAllowed`).
    #[error("not allowed: {0}")]
    NotAllowed(String),
    /// A bundle, publication or artefact in it was refused.
    #[error("bundle rejected: {0}")]
    BundleRejected(String),
    /// A close certificate was refused (COL-007).
    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),
    /// Sealing, storage or the key store failed (COL §3 `SealFailed`).
    #[error("operation failed: {0}")]
    Failed(String),
}

impl From<StorageError> for CollectionError {
    fn from(e: StorageError) -> Self {
        Self::Failed(format!("storage: {e}"))
    }
}

impl From<fieldseal_kernel::WireError> for CollectionError {
    fn from(e: fieldseal_kernel::WireError) -> Self {
        Self::Failed(format!("format: {e}"))
    }
}

impl From<fieldseal_trust::ports::KeyStoreError> for CollectionError {
    fn from(e: fieldseal_trust::ports::KeyStoreError) -> Self {
        match e {
            fieldseal_trust::ports::KeyStoreError::Locked => Self::NotAllowed("unlock the device first".into()),
            e => Self::Failed(format!("key store: {e}")),
        }
    }
}

/// The platform ports a runtime runs on (COL §4, PLAT §4).
#[derive(Clone, Copy)]
pub struct Platform<'a> {
    /// The hardware-backed key store (Trust's `SecureKeyStore`, the spec's `KeyStore`).
    pub keys: &'a dyn SecureKeyStore,
    /// Attestation evidence at key creation.
    pub attestor: &'a dyn Attestor,
    /// The monotonic clock and boot count.
    pub clock: &'a dyn ElapsedClock,
    /// The untrusted wall clock.
    pub wall: &'a dyn WallClock,
    /// Atomic, durable storage.
    pub storage: &'a dyn SecureStorage,
    /// Secure display.
    pub display: &'a dyn SecureDisplay,
    /// Device lock-down.
    pub device: &'a dyn DevicePolicy,
    /// Evidence capture into memory.
    pub camera: &'a dyn Camera,
    /// Argon2id for the PIN.
    pub hash: &'a dyn MemoryHardHash,
    /// Cryptographically secure randomness.
    pub random: &'a dyn RandomSource,
    /// Distribution's bundle opener.
    pub bundles: &'a dyn BundleOpener,
}

/// What device provisioning gives the runtime (COL §7, DEP-024): trust and the build's
/// identity. Nothing deployment-specific is compiled in.
#[derive(Clone, Copy)]
pub struct Provisioning<'a> {
    /// The trust bundle, against which publications are verified.
    pub trust: &'a TrustBundle,
    /// The publishing policy thresholds the trust bundle's publishers must meet.
    pub publishing: &'a PublishingPolicy,
    /// The runtime build's release anchor (the first tick anchor, WIRE-062).
    pub build_anchor: Digest,
    /// The authority key records are sealed to before registration (`fs1-x`).
    pub provisional_record_key: [u8; 32],
    /// The windows the shell shows, each protected by secure display (COL-091).
    pub windows: &'a [WindowId],
}

/// A domain event (COL §2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CollectionEvent {
    /// A tenancy was created.
    TenancyCreated(TenancyId),
    /// A session opened.
    SessionOpened,
    /// The session locked, with the reason.
    SessionLocked(&'static str),
    /// Too many wrong PINs: wait this many seconds.
    PinLockedOut(u64),
    /// A record was sealed in the journal and the local record.
    RecordSealed {
        /// Its `seq`.
        seq: Seq,
        /// Its payload type.
        kind: &'static str,
    },
    /// A consent record was sealed.
    ConsentRecorded(SubjectId),
    /// An evidence image was sealed into the journal.
    EvidenceCaptured,
    /// Review raised a field check.
    FieldCheckRaised(String),
    /// The local record was cleared through a `seq`.
    LocalRecordCleared(Seq),
    /// The tenancy closed.
    TenancyClosed(TenancyId),
    /// The tenancy's keys and local data were deleted.
    TenancyErased(TenancyId),
}

pub(crate) struct Session {
    key: SessionKey,
    last_activity: ElapsedReading,
    policy: RuntimeEvaluator,
    held: Option<Held>,
    languages: Vec<String>,
    window_class: fieldseal_instrument::domain::WindowClass,
}

/// The device runtime: one device, at most one open tenancy (COL-001), its session, and the
/// capture in progress.
pub struct Runtime<'a> {
    p: Platform<'a>,
    prov: Provisioning<'a>,
    meta: Option<TenancyMeta>,
    ticks: Option<TickState>,
    session: Option<Session>,
    capture: Option<Capture>,
    events: Vec<CollectionEvent>,
    recovery: RecoveryReport,
}

pub(crate) mod names {
    use super::{StorageClass, StorageName};

    pub const DEVICE: StorageClass = StorageClass::DeviceEncrypted;
    pub const SESSION: StorageClass = StorageClass::SessionEncrypted;

    pub fn n(s: &str) -> StorageName {
        StorageName(s.to_owned())
    }

    pub fn tenancy() -> StorageName {
        n("tenancy")
    }
    pub fn journal() -> StorageName {
        n("journal")
    }
    pub fn pin_attempts() -> StorageName {
        n("pin-attempts")
    }
    pub fn ticks() -> StorageName {
        n("ticks")
    }
    pub fn seal_marker() -> StorageName {
        n("marker/seal")
    }
    pub fn op_marker() -> StorageName {
        n("marker/operation")
    }
    pub fn bundle() -> StorageName {
        n("bundle")
    }
    pub fn registration() -> StorageName {
        n("registration")
    }
    pub fn applied_policies() -> StorageName {
        n("policy-versions")
    }
    pub fn progress() -> StorageName {
        n("progress")
    }
    pub fn local(seq: u64) -> StorageName {
        StorageName(format!("local/{seq:020}"))
    }
    pub fn note(seq: u64) -> StorageName {
        StorageName(format!("note/{seq:020}"))
    }
    pub fn pending_local(seq: u64) -> StorageName {
        StorageName(format!("pending/local/{seq:020}"))
    }
    pub fn pending_note(seq: u64) -> StorageName {
        StorageName(format!("pending/note/{seq:020}"))
    }
    pub fn outbox(id: &str) -> StorageName {
        StorageName(format!("outbox/{id}"))
    }

    /// The `seq` of a `local/…` or `note/…` name.
    pub fn seq_of(name: &StorageName, prefix: &str) -> Option<u64> {
        name.0.strip_prefix(prefix).and_then(|s| s.parse().ok())
    }
}

impl<'a> Runtime<'a> {
    /// Loads the runtime from storage, recovering any interrupted operation first
    /// (COL-092, COL-093). The report is available from [`Runtime::recovery`].
    pub fn load(platform: Platform<'a>, provisioning: Provisioning<'a>) -> Result<Self, CollectionError> {
        let mut rt = Self {
            p: platform,
            prov: provisioning,
            meta: None,
            ticks: None,
            session: None,
            capture: None,
            events: Vec::new(),
            recovery: RecoveryReport::default(),
        };
        rt.recover()?;
        Ok(rt)
    }

    /// What recovery did when the runtime loaded.
    pub fn recovery(&self) -> &RecoveryReport {
        &self.recovery
    }

    /// Takes the domain events raised since the last call.
    pub fn take_events(&mut self) -> Vec<CollectionEvent> {
        std::mem::take(&mut self.events)
    }

    /// The tenancy's state, or `None` when the device has no tenancy.
    pub fn state(&self) -> Option<TenancyState> {
        self.meta.as_ref().map(|m| m.state)
    }

    /// The tenancy ID.
    pub fn tenancy(&self) -> Option<TenancyId> {
        self.meta.as_ref().map(|m| m.tenancy)
    }

    /// Whether a session is open.
    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    /// The journal's bytes: sealed frames, readable without a session (COL-008).
    pub fn journal(&self) -> Result<Vec<u8>, CollectionError> {
        Ok(self.p.storage.read(names::DEVICE, &names::journal())?.unwrap_or_default())
    }

    /// The tenancy's key history (signing public keys by index), for verifying the journal.
    pub fn key_history(&self) -> Vec<fieldseal_kernel::crypto::P256PublicKey> {
        self.meta.iter().map(|m| m.sign_pub.clone()).collect()
    }

    /// Checkpoints sealed: `(cleared_through, hash_at)`, for verifying the journal across
    /// cleared frames (WIRE-041).
    pub fn checkpoints(&self) -> Vec<(u64, Digest)> {
        self.meta.as_ref().map(|m| m.cleared.clone()).unwrap_or_default()
    }

    /// Anchors chained into the journal, in order (for checking ticks, WIRE-071).
    pub fn anchors(&self) -> Vec<Digest> {
        self.meta.as_ref().map(|m| m.anchors.clone()).unwrap_or_default()
    }

    /// The latest posture findings (PLAT-043), as `(restriction, state)` names, for the
    /// next posture report (PLAT-044).
    pub fn posture_findings(&self) -> Vec<(String, String)> {
        self.meta.as_ref().map(|m| m.posture.clone()).unwrap_or_default()
    }

    fn meta(&self) -> Result<&TenancyMeta, CollectionError> {
        self.meta.as_ref().ok_or(CollectionError::NoTenancy)
    }

    fn save_meta(&mut self) -> Result<(), CollectionError> {
        let bytes = self.meta()?.encode();
        self.p.storage.write(names::DEVICE, &names::tenancy(), &bytes)?;
        Ok(())
    }

    fn now(&self) -> ElapsedReading {
        self.p.clock.now()
    }

    fn random<const N: usize>(&self) -> [u8; N] {
        let mut b = [0u8; N];
        self.p.random.fill(&mut b);
        b
    }
}
