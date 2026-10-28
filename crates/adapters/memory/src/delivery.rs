//! In-memory adapters for the Delivery context's driven ports, and the in-process upload
//! endpoint that connects a device to Intake's gate without a network.
//!
//! Nothing here is cryptography of its own: challenge answers, tokens and receipts are the
//! real, signed structures, made by the practice authority's keys.

use std::collections::BTreeMap;
use std::sync::Mutex;

use fieldseal_collection::domain::ReceiptClaim;
use fieldseal_delivery::checks::receipts_from_response;
use fieldseal_delivery::domain::{
    AddressHint, AuthorisedDestination, DestinationClass, ExportId, ReceiverChallenge, ReceiverProof, UploadRequest, UploadRoute,
};
use fieldseal_delivery::ports::{
    DestinationHandle, DestinationReport, FileAccess, FileAccessError, ManifestAttachments, PrivateStorage, PrivateStorageError,
    QrError, QrScanner, RegistrationRecords, ShareOutcome, ShareTarget, UploadError, UploadTransport,
};
use fieldseal_intake::ports::PopLedger;
use fieldseal_intake::upload::{TOKEN_HEADER, UploadRefusal, UploadService};
use fieldseal_kernel::id::TenancyId;
use fieldseal_kernel::time::AuthorityTime;

/// In-memory [`FileAccess`] for one destination class; read-back goes through the
/// simulated destination, which a test can corrupt or make fail.
pub struct MemoryFileAccess {
    class: DestinationClass,
    files: Mutex<BTreeMap<DestinationHandle, Vec<u8>>>,
    counter: Mutex<u64>,
    fail_writes: Mutex<bool>,
    synced: Mutex<std::collections::BTreeSet<DestinationHandle>>,
}

impl MemoryFileAccess {
    /// Destinations of `class`.
    pub fn new(class: DestinationClass) -> Self {
        Self { class, files: Mutex::new(BTreeMap::new()), counter: Mutex::new(0), fail_writes: Mutex::new(false), synced: Mutex::default() }
    }

    /// Corrupts a stored file, to test read-back mismatches.
    pub fn corrupt(&self, handle: &DestinationHandle) {
        if let Some(f) = self.files.lock().expect("lock").get_mut(handle)
            && let Some(b) = f.first_mut()
        {
            *b ^= 0xff;
        }
    }

    /// Makes the next writes fail, as a full or removed medium does.
    pub fn fail_writes(&self, fail: bool) {
        *self.fail_writes.lock().expect("lock") = fail;
    }

    /// The bytes now stored at a destination, as the destination holds them.
    pub fn stored(&self, handle: &DestinationHandle) -> Option<Vec<u8>> {
        self.files.lock().expect("lock").get(handle).cloned()
    }

    /// Whether the file at a destination was synced after its last write.
    pub fn is_synced(&self, handle: &DestinationHandle) -> bool {
        self.synced.lock().expect("lock").contains(handle)
    }

    /// Changes a stored file's bytes (a test may damage it in place).
    pub fn replace(&self, handle: &DestinationHandle, bytes: Vec<u8>) {
        self.files.lock().expect("lock").insert(handle.clone(), bytes);
    }
}

impl FileAccess for MemoryFileAccess {
    fn pick_destination(&self) -> Result<DestinationHandle, FileAccessError> {
        let mut n = self.counter.lock().expect("lock");
        *n += 1;
        Ok(DestinationHandle(format!("memory://{:?}/{n}", self.class)))
    }

    fn write(&self, handle: &DestinationHandle, bytes: &[u8]) -> Result<(), FileAccessError> {
        if *self.fail_writes.lock().expect("lock") {
            return Err(FileAccessError::WriteFailed("no space left".into()));
        }
        self.files.lock().expect("lock").insert(handle.clone(), bytes.to_vec());
        self.synced.lock().expect("lock").remove(handle);
        Ok(())
    }

    fn sync(&self, handle: &DestinationHandle) -> Result<(), FileAccessError> {
        self.synced.lock().expect("lock").insert(handle.clone());
        Ok(())
    }

    fn read_back(&self, handle: &DestinationHandle) -> Result<Vec<u8>, FileAccessError> {
        self.files.lock().expect("lock").get(handle).cloned().ok_or(FileAccessError::ReadBackUnavailable)
    }

    fn report(&self, _handle: &DestinationHandle) -> DestinationReport {
        DestinationReport { provider: format!("memory-{:?}", self.class).to_lowercase(), class: self.class }
    }
}

/// In-memory [`ShareTarget`] with a fixed outcome.
pub struct MemoryShareTarget(pub ShareOutcome);

impl ShareTarget for MemoryShareTarget {
    fn share(&self, _bytes: &[u8], _allowed: &[String]) -> ShareOutcome {
        self.0
    }
}

/// In-memory [`PrivateStorage`].
#[derive(Default)]
pub struct MemoryPrivateStorage {
    exports: Mutex<BTreeMap<ExportId, Vec<u8>>>,
    markers: Mutex<BTreeMap<String, Vec<u8>>>,
    full: Mutex<bool>,
}

impl MemoryPrivateStorage {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes storing exports fail with `Full`.
    pub fn set_full(&self, full: bool) {
        *self.full.lock().expect("lock") = full;
    }
}

impl PrivateStorage for MemoryPrivateStorage {
    fn put(&self, id: &ExportId, bytes: &[u8]) -> Result<(), PrivateStorageError> {
        if *self.full.lock().expect("lock") {
            return Err(PrivateStorageError::Full);
        }
        self.exports.lock().expect("lock").insert(*id, bytes.to_vec());
        Ok(())
    }

    fn get(&self, id: &ExportId) -> Result<Option<Vec<u8>>, PrivateStorageError> {
        Ok(self.exports.lock().expect("lock").get(id).cloned())
    }

    fn delete(&self, id: &ExportId) -> Result<(), PrivateStorageError> {
        self.exports.lock().expect("lock").remove(id);
        Ok(())
    }

    fn put_marker(&self, name: &str, bytes: &[u8]) -> Result<(), PrivateStorageError> {
        self.markers.lock().expect("lock").insert(name.to_owned(), bytes.to_vec());
        Ok(())
    }

    fn get_marker(&self, name: &str) -> Result<Option<Vec<u8>>, PrivateStorageError> {
        Ok(self.markers.lock().expect("lock").get(name).cloned())
    }
}

/// In-memory [`QrScanner`] that returns queued codes.
#[derive(Default)]
pub struct MemoryQrScanner {
    queue: Mutex<Vec<Vec<u8>>>,
}

impl MemoryQrScanner {
    /// Queues a code to be scanned.
    pub fn queue(&self, bytes: Vec<u8>) {
        self.queue.lock().expect("lock").push(bytes);
    }
}

impl QrScanner for MemoryQrScanner {
    fn scan(&self) -> Result<Vec<u8>, QrError> {
        let mut q = self.queue.lock().expect("lock");
        if q.is_empty() {
            return Err(QrError::Cancelled);
        }
        Ok(q.remove(0))
    }
}

/// In-memory [`RegistrationRecords`]: the documents a manifest carries, by tenancy.
#[derive(Default)]
pub struct MemoryRegistrationRecords {
    by_tenancy: Mutex<BTreeMap<TenancyId, ManifestAttachments>>,
}

impl MemoryRegistrationRecords {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the documents for a tenancy.
    pub fn set(&self, tenancy: TenancyId, attachments: ManifestAttachments) {
        self.by_tenancy.lock().expect("lock").insert(tenancy, attachments);
    }
}

impl RegistrationRecords for MemoryRegistrationRecords {
    fn attachments(&self, tenancy: &TenancyId) -> ManifestAttachments {
        self.by_tenancy.lock().expect("lock").get(tenancy).cloned().unwrap_or_default()
    }
}

/// In-memory [`PopLedger`].
#[derive(Default)]
pub struct MemoryPopLedger {
    seen: Mutex<BTreeMap<(TenancyId, [u8; 16]), AuthorityTime>>,
}

impl MemoryPopLedger {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }
}

impl PopLedger for MemoryPopLedger {
    fn first_use(&self, tenancy: &TenancyId, jti: &[u8; 16], now: AuthorityTime, until: AuthorityTime) -> Result<bool, String> {
        let mut seen = self.seen.lock().expect("lock");
        seen.retain(|_, u| *u > now);
        Ok(seen.insert((*tenancy, *jti), until).is_none())
    }
}

/// An [`UploadTransport`] that reaches an [`UploadService`] in the same process, ignoring
/// the address as an HTTP deployment's several host names do. Requests are authenticated
/// and gated exactly as the HTTP adapter does.
pub struct LoopbackTransport<'a, 'g> {
    service: &'a UploadService<'a, 'g>,
    now: Box<dyn Fn() -> AuthorityTime + 'a>,
}

impl<'a, 'g> LoopbackTransport<'a, 'g> {
    /// A transport to `service`, whose clock reads `now`.
    pub fn new(service: &'a UploadService<'a, 'g>, now: impl Fn() -> AuthorityTime + 'a) -> Self {
        Self { service, now: Box::new(now) }
    }
}

impl UploadTransport for LoopbackTransport<'_, '_> {
    fn challenge(&self, _address: &AddressHint, challenge: &ReceiverChallenge) -> Result<ReceiverProof, UploadError> {
        let bytes = self.service.answer_challenge(&challenge.encode()).map_err(|e| refusal_to_error(&e))?;
        ReceiverProof::decode(&bytes).map_err(|e| UploadError::Malformed(e.to_string()))
    }

    fn upload(&self, destination: &AuthorisedDestination, request: &UploadRequest) -> Result<Vec<ReceiptClaim>, UploadError> {
        let now = (self.now)();
        let _ = destination;
        if request.route == UploadRoute::Tenancy {
            let header = request.pop.as_ref().map(|p| p.to_header());
            self.service.authenticate(header.as_deref(), "POST", request.route, now).map_err(|e| refusal_to_error(&e))?;
        }
        let body = self.service.receive(&request.body, now).map_err(|e| refusal_to_error(&e))?;
        receipts_from_response(&body).map_err(|e| UploadError::Malformed(e.to_string()))
    }
}

/// Turns a refusal into the transport error a client sees: a token refusal is
/// `TokenRejected`, a failed backing service is `Unreachable` (retry later), anything else
/// is a rejection with the reason.
pub fn refusal_to_error(refusal: &UploadRefusal) -> UploadError {
    match refusal {
        UploadRefusal::TokenRejected(_) => UploadError::TokenRejected,
        UploadRefusal::Backend(_) => UploadError::Unreachable,
        other => UploadError::Rejected(other.to_string()),
    }
}

/// The header an HTTP client sends the token in.
pub const POP_HEADER_NAME: &str = TOKEN_HEADER;
