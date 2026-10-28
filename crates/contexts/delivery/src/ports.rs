//! Driven ports owned by the Delivery context (`docs/reference/spec/delivery.md` §4).
//!
//! Delivery also uses ports owned by inner contexts: Trust's `SecureKeyStore` (the
//! spec's `ProofSigner`), `RandomSource`, and Collection's `ReceiptCheck` (the spec's
//! `ReceiptVerifier`) and `WallClock`.

use fieldseal_collection::domain::ReceiptClaim;
use fieldseal_kernel::Value;
use fieldseal_kernel::id::{KeyId, TenancyId};

use crate::domain::{
    AddressHint, AuthorisedDestination, DestinationClass, ExportId, ReceiverChallenge, ReceiverProof,
    UploadRequest,
};

/// Errors from [`UploadTransport`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UploadError {
    /// No network, or the address didn't answer.
    #[error("unreachable")]
    Unreachable,
    /// The proof-of-possession token was refused.
    #[error("token rejected")]
    TokenRejected,
    /// The destination refused the upload.
    #[error("rejected: {0}")]
    Rejected(String),
    /// The destination answered with something that isn't a valid answer.
    #[error("malformed answer: {0}")]
    Malformed(String),
}

/// A way to reach an upload endpoint at an untrusted address (the spec's `UploadEndpoint`).
///
/// Contract: `challenge` returns the receiver's certificate and signature over the
/// challenge, which don't depend on the address; `upload` is idempotent, so sending the
/// same body again returns an equivalent receipt. The transport trusts nothing it is told
/// by the address: authorisation is the caller's, by receiver key.
pub trait UploadTransport {
    /// Asks the destination at `address` to answer `challenge`.
    fn challenge(&self, address: &AddressHint, challenge: &ReceiverChallenge) -> Result<ReceiverProof, UploadError>;

    /// Uploads to a destination that passed the challenge. The receipts are as received,
    /// unverified: one per tenancy part acknowledged.
    fn upload(&self, destination: &AuthorisedDestination, request: &UploadRequest) -> Result<Vec<ReceiptClaim>, UploadError>;
}

/// What the registration records add to an export's manifest (WIRE-104): the tenancy
/// certificate if one is held, and the latest registration request. Collection keeps only
/// the certificate's content address, so the full documents come from this port.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ManifestAttachments {
    /// The tenancy certificate, as a value.
    pub certificate: Option<Value>,
    /// The sealed registration request, as a value.
    pub registration: Option<Value>,
}

/// The registration documents a manifest carries.
///
/// Contract: returns the same documents for the same tenancy until they change; `None`
/// fields for an unknown tenancy.
pub trait RegistrationRecords {
    /// The attachments for `tenancy`.
    fn attachments(&self, tenancy: &TenancyId) -> ManifestAttachments;
}

/// Why a receiver proof was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReceiverCheckError {
    /// The certificate isn't a current `receiver` certificate chaining to the trust root.
    #[error("receiver not authorised")]
    NotAuthorised,
    /// The signature over the challenge doesn't verify.
    #[error("bad challenge signature")]
    BadSignature,
}

/// Verifies receiver proofs against the runtime's trust bundle (TRU-080–TRU-082).
///
/// Contract: authorises solely by a `receiver` certificate chaining to the trust root,
/// current and unrevoked, with a valid signature over exactly this challenge; never by
/// address, domain name or TLS certificate.
pub trait ReceiverCheck {
    /// Returns the receiver key that answered, if the proof checks out.
    fn verify(
        &self,
        challenge: &ReceiverChallenge,
        proof: &ReceiverProof,
    ) -> Result<KeyId, ReceiverCheckError>;
}

/// Errors from [`FileAccess`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FileAccessError {
    /// The collector cancelled the picker.
    #[error("cancelled")]
    Cancelled,
    /// Writing or syncing failed.
    #[error("write failed: {0}")]
    WriteFailed(String),
    /// The destination can't be read back.
    #[error("read-back unavailable")]
    ReadBackUnavailable,
}

/// A destination chosen through the platform's file picker.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct DestinationHandle(pub String);

/// What the platform says about a destination.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DestinationReport {
    /// The storage provider's identity (for example a document-provider authority).
    pub provider: String,
    /// Its class, derived from the provider.
    pub class: DestinationClass,
}

/// Files at destinations chosen through the platform's picker (PLAT §FileAccess).
///
/// Contract: `sync` makes the write durable at the destination; `read_back` reads
/// through the destination, not from a local copy the adapter kept; `report` names the
/// provider, so the class is decided from the destination.
pub trait FileAccess {
    /// Lets the collector choose a destination.
    fn pick_destination(&self) -> Result<DestinationHandle, FileAccessError>;
    /// Writes bytes.
    fn write(&self, handle: &DestinationHandle, bytes: &[u8]) -> Result<(), FileAccessError>;
    /// Syncs the write to storage.
    fn sync(&self, handle: &DestinationHandle) -> Result<(), FileAccessError>;
    /// Reads the file back through the destination.
    fn read_back(&self, handle: &DestinationHandle) -> Result<Vec<u8>, FileAccessError>;
    /// Describes the destination.
    fn report(&self, handle: &DestinationHandle) -> DestinationReport;
}

/// What happened when a file was shared.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShareOutcome {
    /// Handed to another app.
    Shared,
    /// The collector cancelled.
    Cancelled,
    /// It failed.
    Failed,
}

/// Hands a file to another app; only success or failure is known.
pub trait ShareTarget {
    /// Shares `bytes` with one of the `allowed` targets.
    fn share(&self, bytes: &[u8], allowed: &[String]) -> ShareOutcome;
}

/// Errors from [`PrivateStorage`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrivateStorageError {
    /// Out of space.
    #[error("storage full")]
    Full,
    /// The platform failed.
    #[error("private storage: {0}")]
    Backend(String),
}

/// Device-encrypted storage for exports being built, and for small delivery markers.
///
/// Contract: what is stored is returned unchanged until deleted; named markers are
/// separate from exports and replace on write.
pub trait PrivateStorage {
    /// Stores an export.
    fn put(&self, id: &ExportId, bytes: &[u8]) -> Result<(), PrivateStorageError>;
    /// Reads an export.
    fn get(&self, id: &ExportId) -> Result<Option<Vec<u8>>, PrivateStorageError>;
    /// Deletes an export.
    fn delete(&self, id: &ExportId) -> Result<(), PrivateStorageError>;
    /// Stores a named marker (the export counter, the upload retry state).
    fn put_marker(&self, name: &str, bytes: &[u8]) -> Result<(), PrivateStorageError>;
    /// Reads a named marker.
    fn get_marker(&self, name: &str) -> Result<Option<Vec<u8>>, PrivateStorageError>;
}

/// Errors from [`QrScanner`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QrError {
    /// The collector cancelled.
    #[error("cancelled")]
    Cancelled,
    /// No camera.
    #[error("camera unavailable")]
    Unavailable,
}

/// Reads a QR code from the camera straight into memory.
pub trait QrScanner {
    /// The decoded bytes of one QR code.
    fn scan(&self) -> Result<Vec<u8>, QrError>;
}
