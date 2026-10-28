//! Driven ports owned by the Collection context: the runtime's platform ports
//! (`docs/reference/spec/collection.md` §4, `platform-profiles.md`).
//!
//! Collection also uses ports owned by inner contexts: Trust's `SecureKeyStore` (the
//! spec's `KeyStore`), `Attestor` and `RandomSource`. Distribution plugs in through
//! [`BundleOpener`], Registration through [`CloseCertificateCheck`].

use std::collections::BTreeMap;

use fieldseal_kernel::time::ElapsedReading;

use crate::domain::bundle::{CloseCertificate, OpenedBundle};
use crate::domain::{
    CaptureConstraints, CapturedImage, HashParams, ManagementMode, ReceiptClaim, Restriction,
    RestrictionState, RuntimePin, StorageClass, StorageName, WindowId,
};

/// The platform's monotonic clock and boot counter (ADR 0020).
///
/// Contract: within one boot count, readings never decrease; the user can't set it.
pub trait ElapsedClock {
    /// The current reading.
    fn now(&self) -> ElapsedReading;
}

/// Errors from [`SecureStorage`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    /// Session-encrypted storage is unavailable outside an unlocked session.
    #[error("session storage is locked")]
    Locked,
    /// The device is out of space.
    #[error("storage full")]
    Full,
    /// The platform failed.
    #[error("storage: {0}")]
    Backend(String),
}

/// Durable, atomic storage in two classes (PLAT §Storage).
///
/// Contract: a write either fully replaces the object or leaves the old one; an append
/// either adds all its bytes to the end of the object or none of them; once `write` or
/// `append` returns, the data survives a power cut (it is synced); classes are separate
/// namespaces; deleted objects are unrecoverable through the port.
///
/// The runtime does not rely on `append` being atomic for safety: a torn journal frame is
/// detected and truncated on recovery (COL-093).
pub trait SecureStorage {
    /// Atomically and durably writes an object.
    fn write(&self, class: StorageClass, name: &StorageName, bytes: &[u8])
    -> Result<(), StorageError>;

    /// Atomically and durably appends to an object, creating it if absent.
    fn append(&self, class: StorageClass, name: &StorageName, bytes: &[u8])
    -> Result<(), StorageError>;

    /// Reads an object.
    fn read(&self, class: StorageClass, name: &StorageName) -> Result<Option<Vec<u8>>, StorageError>;

    /// Deletes an object.
    fn delete(&self, class: StorageClass, name: &StorageName) -> Result<(), StorageError>;

    /// Names of the objects in a class.
    fn names(&self, class: StorageClass) -> Result<Vec<StorageName>, StorageError>;
}

/// Errors from [`SecureDisplay`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DisplayError {
    /// The platform can't protect this surface; an invariant is unmet (PLAT-045).
    #[error("secure display unavailable")]
    Unavailable,
}

/// Protection against screenshots, recent-task snapshots, content capture and overlays.
///
/// Contract: once `protect` succeeds, `is_protected` reports true for that window.
pub trait SecureDisplay {
    /// Protects a window.
    fn protect(&self, window: &WindowId) -> Result<(), DisplayError>;

    /// Whether a window is protected.
    fn is_protected(&self, window: &WindowId) -> bool;
}

/// Errors from [`DevicePolicy`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DevicePolicyError {
    /// Only a self-managed adapter can apply restrictions.
    #[error("not device owner: restrictions are managed elsewhere")]
    NotDeviceOwner,
    /// The platform refused a restriction.
    #[error("platform refused {0:?}")]
    Refused(Restriction),
}

/// Device lock-down (ADR 0031, PLAT-040–PLAT-046).
///
/// Contract: `effective_restrictions` reads each restriction from the platform's live
/// state, never from configuration or an earlier `apply`; anything it can't read is
/// `Unknown`; in EMM mode `apply` returns [`DevicePolicyError::NotDeviceOwner`].
pub trait DevicePolicy {
    /// How the device is managed.
    fn mode(&self) -> ManagementMode;

    /// Applies restrictions (self-managed only).
    fn apply(&self, required: &[Restriction]) -> Result<(), DevicePolicyError>;

    /// What is actually in force now.
    fn effective_restrictions(&self) -> BTreeMap<Restriction, RestrictionState>;
}

/// Errors from [`Camera`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CameraError {
    /// The collector cancelled.
    #[error("cancelled")]
    Cancelled,
    /// No camera is available.
    #[error("camera unavailable")]
    Unavailable,
}

/// Captures evidence images straight into memory (no gallery, no file, no media store).
pub trait Camera {
    /// Captures one image within `constraints`.
    fn capture(&self, constraints: CaptureConstraints) -> Result<CapturedImage, CameraError>;
}

/// The PIN's memory-hard hash (Argon2id in the format core).
///
/// Contract: deterministic for the same inputs; different PINs or salts give different
/// outputs; refuses parameters below the floor.
pub trait MemoryHardHash {
    /// Hashes `pin` with `salt` under `params`; `None` if `params` are below the floor.
    fn hash(&self, pin: &RuntimePin, salt: &[u8; 16], params: HashParams) -> Option<[u8; 32]>;
}

/// Why a receipt didn't verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptCheckError {
    /// The signer isn't a current `receipt` key chaining to the trust root.
    #[error("receipt signer not trusted")]
    UntrustedSigner,
    /// The signature doesn't verify.
    #[error("bad receipt signature")]
    BadSignature,
}

/// Verifies authority receipts against the runtime's trust bundle (TRU, DEL-064).
/// Delivery uses this same port as its `ReceiptVerifier`.
///
/// Contract: accepts a receipt only if it is signed by a `receipt` key that chains to
/// the trust root, whatever route it arrived by.
pub trait ReceiptCheck {
    /// Verifies `claim`.
    fn verify(&self, claim: &ReceiptClaim) -> Result<(), ReceiptCheckError>;
}

/// The device's wall clock: an untrusted hint only (COL-080, WIRE-070).
///
/// Contract: none beyond returning milliseconds since the Unix epoch when known. The runtime
/// never triggers anything irreversible from it (COL-083).
pub trait WallClock {
    /// The device's idea of the time, if it has one.
    fn now_ms(&self) -> Option<u64>;
}

/// Errors from [`FileAccess`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FileAccessError {
    /// The collector cancelled the picker.
    #[error("cancelled")]
    Cancelled,
    /// The file couldn't be read.
    #[error("file access: {0}")]
    Unreadable(String),
}

/// The source side of the platform's `FileAccess` port (PLAT §4): reading a file the
/// collector picks, for importing a bundle. The destination side (write, sync, read back,
/// report) is Delivery's `FileAccess`.
///
/// Contract: returns exactly the bytes of the file picked; offers no gallery or media
/// index, so it can't be used for evidence (COL-042).
pub trait FileAccess {
    /// Lets the collector pick a file and returns its bytes.
    fn pick_source(&self) -> Result<Vec<u8>, FileAccessError>;
}

/// Why a bundle couldn't be opened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleOpenError {
    /// The envelope, signature or chain failed (WIRE-090..093).
    #[error("bundle rejected: {0}")]
    Rejected(String),
    /// The bundle is sealed to another device's agreement key (DIS-042).
    #[error("bundle is for another device")]
    WrongDevice,
}

/// Distribution's side of a bundle import: checks a bundle file's size, signer, chain and
/// signature, opens its seal with the device agreement key, and decodes its content
/// (WIRE-090..095). The bundle format belongs to Distribution (issue #49). Collection then
/// verifies every publication the bundle carries with Publishing's verifier, validates the
/// instrument and layouts, and holds the rosters only in memory.
///
/// Contract: returns contents only from a bundle whose envelope verified and whose seal was
/// addressed to this device; the same bytes always open to the same contents.
pub trait BundleOpener {
    /// Verifies and opens a bundle file.
    fn open(&self, file: &[u8]) -> Result<OpenedBundle, BundleOpenError>;
}

impl<T: BundleOpener + ?Sized> BundleOpener for &T {
    fn open(&self, file: &[u8]) -> Result<OpenedBundle, BundleOpenError> {
        (**self).open(file)
    }
}

/// Why a close certificate was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CloseCertificateError {
    /// The signature or chain didn't verify against the trust bundle (COL-007).
    #[error("close certificate does not verify: {0}")]
    Invalid(String),
}

/// The check of a close or reset certificate (WIRE-141, COL-007), provided by
/// Registration.
///
/// Contract: accepts only a certificate signed under `fieldseal.dev/close-certificate/v1`
/// or `fieldseal.dev/reset-certificate/v1` by a registration key that chains to the trust
/// root; never needs the runtime PIN or any tenancy key.
pub trait CloseCertificateCheck {
    /// Verifies a certificate's bytes and returns what it states.
    fn verify(&self, bytes: &[u8]) -> Result<CloseCertificate, CloseCertificateError>;
}
