//! The `web` platform profile's ports (PLAT-100 and following, ADR 0036): what the Collection
//! and Delivery contexts need from a platform, implemented for a browser tab.
//!
//! Every adapter here is plain Rust with no browser calls, so it is tested natively; the
//! WebAssembly binding supplies the clocks and the HTTP call as closures. Persistence is a
//! write-through log: [`WebStorage`] keeps the objects in memory and records each change,
//! which the JavaScript side drains into IndexedDB after every call.
//!
//! **Honest limits** (the profile is development only): keys are software keys held in the
//! page's memory while it runs and in IndexedDB at rest, so they are unattested (CLI-007,
//! REG-017); there is no operating-system secure display or device lock-down; storage is not
//! encrypted by the platform (the host script wraps secrets with a non-extractable WebCrypto
//! key where the browser allows it).

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use fieldseal_collection::domain::{CaptureConstraints, CapturedImage, HashParams, ManagementMode, Restriction, RestrictionState, RuntimePin, StorageClass, StorageName, WindowId};
use fieldseal_collection::ports::{
    Camera, CameraError, DevicePolicy, DevicePolicyError, DisplayError, ElapsedClock, MemoryHardHash, SecureDisplay, SecureStorage, StorageError, WallClock,
};
use fieldseal_delivery::domain::DestinationClass;
use fieldseal_delivery::ports::{DestinationHandle, DestinationReport, FileAccess, FileAccessError, ShareOutcome, ShareTarget};
use fieldseal_kernel::crypto::{P256PublicKey, Signature};
use fieldseal_kernel::id::Nonce;
use fieldseal_kernel::seal::{RecipientSecret, Suite};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_kernel::time::ElapsedReading;
use fieldseal_trust::domain::{AttestationEvidence, DeviceKeyKind, KeyHandle, KeyProtection};
use fieldseal_trust::ports::{Attestor, AttestorError, KeyStoreError, RandomSource, SecureKeyStore, SourceRng};
use zeroize::Zeroizing;

/// Which namespace of the host's persistent store an object lives in.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Namespace {
    /// Runtime objects that need no PIN (the sealed journal, outbox, markers).
    Device,
    /// Runtime objects readable only in an unlocked session (the local record, rosters).
    Session,
    /// Private key material. The host wraps this namespace with a non-extractable key.
    Keys,
}

impl Namespace {
    /// The name the host stores it under.
    pub fn name(self) -> &'static str {
        match self {
            Namespace::Device => "device",
            Namespace::Session => "session",
            Namespace::Keys => "keys",
        }
    }

    /// Parses [`Namespace::name`].
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "device" => Some(Namespace::Device),
            "session" => Some(Namespace::Session),
            "keys" => Some(Namespace::Keys),
            _ => None,
        }
    }
}

/// One change to the persistent store: `bytes` is `None` for a deletion.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Change {
    /// The namespace.
    pub namespace: Namespace,
    /// The object's name.
    pub name: String,
    /// The new content, or `None` when the object was deleted.
    pub bytes: Option<Vec<u8>>,
}

/// Write-through storage: objects in memory, every change logged for the host to persist.
///
/// Contract of [`SecureStorage`]: writes replace whole objects, appends add to the end, and
/// once a call returns the change is in the log. The host persists the log before it reports
/// the operation done to the collector (IndexedDB transactions are atomic), so a closed tab
/// keeps everything the runtime had acknowledged.
#[derive(Default)]
pub struct WebStorage {
    objects: Mutex<BTreeMap<(Namespace, String), Vec<u8>>>,
    log: Mutex<Vec<Change>>,
}

impl WebStorage {
    /// Empty storage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads persisted objects without logging them as changes.
    pub fn load(&self, namespace: Namespace, name: &str, bytes: Vec<u8>) {
        self.objects.lock().expect("lock").insert((namespace, name.to_owned()), bytes);
    }

    /// Takes the changes made since the last call, in order.
    pub fn drain_changes(&self) -> Vec<Change> {
        std::mem::take(&mut *self.log.lock().expect("lock"))
    }

    /// Reads an object.
    pub fn get(&self, namespace: Namespace, name: &str) -> Option<Vec<u8>> {
        self.objects.lock().expect("lock").get(&(namespace, name.to_owned())).cloned()
    }

    /// Replaces an object and logs it.
    pub fn put(&self, namespace: Namespace, name: &str, bytes: &[u8]) {
        self.objects.lock().expect("lock").insert((namespace, name.to_owned()), bytes.to_vec());
        self.log.lock().expect("lock").push(Change { namespace, name: name.to_owned(), bytes: Some(bytes.to_vec()) });
    }

    /// Deletes an object and logs it.
    pub fn remove(&self, namespace: Namespace, name: &str) {
        self.objects.lock().expect("lock").remove(&(namespace, name.to_owned()));
        self.log.lock().expect("lock").push(Change { namespace, name: name.to_owned(), bytes: None });
    }

    /// The names in a namespace.
    pub fn names_in(&self, namespace: Namespace) -> Vec<String> {
        self.objects.lock().expect("lock").keys().filter(|(n, _)| *n == namespace).map(|(_, name)| name.clone()).collect()
    }

    /// Every object, for the host to show how much is held.
    pub fn sizes(&self) -> Vec<(Namespace, String, usize)> {
        self.objects.lock().expect("lock").iter().map(|((n, name), b)| (*n, name.clone(), b.len())).collect()
    }
}

fn namespace_of(class: StorageClass) -> Namespace {
    match class {
        StorageClass::DeviceEncrypted => Namespace::Device,
        StorageClass::SessionEncrypted => Namespace::Session,
    }
}

impl SecureStorage for WebStorage {
    fn write(&self, class: StorageClass, name: &StorageName, bytes: &[u8]) -> Result<(), StorageError> {
        self.put(namespace_of(class), &name.0, bytes);
        Ok(())
    }

    fn append(&self, class: StorageClass, name: &StorageName, bytes: &[u8]) -> Result<(), StorageError> {
        let ns = namespace_of(class);
        let mut whole = self.get(ns, &name.0).unwrap_or_default();
        whole.extend_from_slice(bytes);
        self.put(ns, &name.0, &whole);
        Ok(())
    }

    fn read(&self, class: StorageClass, name: &StorageName) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.get(namespace_of(class), &name.0))
    }

    fn delete(&self, class: StorageClass, name: &StorageName) -> Result<(), StorageError> {
        self.remove(namespace_of(class), &name.0);
        Ok(())
    }

    fn names(&self, class: StorageClass) -> Result<Vec<StorageName>, StorageError> {
        Ok(self.names_in(namespace_of(class)).into_iter().map(StorageName).collect())
    }
}

/// Randomness from the browser's `crypto.getRandomValues` (through `getrandom`'s `js`
/// feature in the WebAssembly build) or the operating system when run natively.
#[derive(Default)]
pub struct WebRandom;

impl RandomSource for WebRandom {
    fn fill(&self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("the platform's secure random source");
    }
}

/// The wall clock: an untrusted hint (COL-080), supplied by the host.
pub struct WebWall {
    now_ms: Box<dyn Fn() -> f64>,
}

impl WebWall {
    /// A wall clock reading `now_ms` (milliseconds since the Unix epoch).
    pub fn new(now_ms: impl Fn() -> f64 + 'static) -> Self {
        Self { now_ms: Box::new(now_ms) }
    }
}

impl WallClock for WebWall {
    fn now_ms(&self) -> Option<u64> {
        let t = (self.now_ms)();
        (t.is_finite() && t > 0.0).then_some(t as u64)
    }
}

/// The monotonic clock: `performance.now()` since the page loaded, with one boot per page
/// load (a reload is a reboot, ADR 0020). The boot count is kept by the host.
pub struct WebElapsed {
    elapsed_ms: Box<dyn Fn() -> f64>,
    boot_count: u32,
}

impl WebElapsed {
    /// A clock reading `elapsed_ms` since this boot.
    pub fn new(elapsed_ms: impl Fn() -> f64 + 'static, boot_count: u32) -> Self {
        Self { elapsed_ms: Box::new(elapsed_ms), boot_count }
    }
}

impl ElapsedClock for WebElapsed {
    fn now(&self) -> ElapsedReading {
        ElapsedReading { elapsed_ms: (self.elapsed_ms)().max(0.0) as u64, boot_count: self.boot_count }
    }
}

/// Argon2id for the PIN (ADR 0017): the real algorithm from the `argon2` crate, at the
/// parameters the runtime asks for (never below the floor).
#[derive(Default)]
pub struct ArgonHash;

impl MemoryHardHash for ArgonHash {
    fn hash(&self, pin: &RuntimePin, salt: &[u8; 16], params: HashParams) -> Option<[u8; 32]> {
        if !params.meets_floor() {
            return None;
        }
        let p = argon2::Params::new(params.memory_kib, params.iterations, params.parallelism, Some(32)).ok()?;
        let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
        let mut out = [0u8; 32];
        a.hash_password_into(pin.digits().as_bytes(), salt, &mut out).ok()?;
        Some(out)
    }
}

/// A browser tab cannot ask the operating system to hide its contents. This adapter accepts
/// the request so the runtime can run, and records which windows were asked for; the host
/// script covers the page when the tab is hidden (a privacy cover, not OS protection).
#[derive(Default)]
pub struct WebDisplay {
    protected: Mutex<Vec<WindowId>>,
}

impl SecureDisplay for WebDisplay {
    fn protect(&self, window: &WindowId) -> Result<(), DisplayError> {
        let mut p = self.protected.lock().expect("lock");
        if !p.contains(window) {
            p.push(window.clone());
        }
        Ok(())
    }

    fn is_protected(&self, window: &WindowId) -> bool {
        self.protected.lock().expect("lock").contains(window)
    }
}

/// A browser tab has no device lock-down: the mode is "managed elsewhere" and every
/// restriction reads `Unknown`, so posture findings list them all (PLAT-043, PLAT-044:
/// findings never block).
#[derive(Default)]
pub struct WebDevicePolicy;

impl DevicePolicy for WebDevicePolicy {
    fn mode(&self) -> ManagementMode {
        ManagementMode::EmmManaged
    }

    fn apply(&self, _required: &[Restriction]) -> Result<(), DevicePolicyError> {
        Err(DevicePolicyError::NotDeviceOwner)
    }

    fn effective_restrictions(&self) -> BTreeMap<Restriction, RestrictionState> {
        Restriction::ALL.iter().map(|r| (*r, RestrictionState::Unknown)).collect()
    }
}

/// No in-memory camera path in the first version of the web profile.
#[derive(Default)]
pub struct WebCamera;

impl Camera for WebCamera {
    fn capture(&self, _constraints: CaptureConstraints) -> Result<CapturedImage, CameraError> {
        Err(CameraError::Unavailable)
    }
}

/// Where an export is written: the browser's download. The host turns each write into a
/// download; a download cannot be read back through the destination, so read-back is
/// unavailable and Delivery says so (the export is verified before it is written instead).
#[derive(Default)]
pub struct WebDownloads {
    files: Mutex<Vec<(String, Vec<u8>)>>,
    counter: Mutex<u64>,
}

impl WebDownloads {
    /// Takes the files written since the last call.
    pub fn take(&self) -> Vec<(String, Vec<u8>)> {
        std::mem::take(&mut *self.files.lock().expect("lock"))
    }
}

impl FileAccess for WebDownloads {
    fn pick_destination(&self) -> Result<DestinationHandle, FileAccessError> {
        let mut n = self.counter.lock().expect("lock");
        *n += 1;
        Ok(DestinationHandle(format!("download://{n}")))
    }

    fn write(&self, handle: &DestinationHandle, bytes: &[u8]) -> Result<(), FileAccessError> {
        self.files.lock().expect("lock").push((handle.0.clone(), bytes.to_vec()));
        Ok(())
    }

    fn sync(&self, _handle: &DestinationHandle) -> Result<(), FileAccessError> {
        Ok(())
    }

    fn read_back(&self, handle: &DestinationHandle) -> Result<Vec<u8>, FileAccessError> {
        // Honest limit: a browser download cannot be read back from where it lands. What is
        // returned is the bytes handed to the browser, so verification covers the file as
        // written, not what the browser then did with it.
        self.files.lock().expect("lock").iter().rev().find(|(h, _)| h == &handle.0).map(|(_, b)| b.clone()).ok_or(FileAccessError::ReadBackUnavailable)
    }

    fn report(&self, _handle: &DestinationHandle) -> DestinationReport {
        DestinationReport { provider: "browser-download".to_owned(), class: DestinationClass::Local }
    }
}

/// The web profile has no share sheet.
#[derive(Default)]
pub struct NoShare;

impl ShareTarget for NoShare {
    fn share(&self, _bytes: &[u8], _allowed: &[String]) -> ShareOutcome {
        ShareOutcome::Failed
    }
}

// ---- the key store -----------------------------------------------------------------------

enum Secret {
    Sign(SigningKey),
    Agree(Zeroizing<[u8; 32]>),
    Wrap(Zeroizing<[u8; 32]>),
}

struct Entry {
    kind: DeviceKeyKind,
    protection: KeyProtection,
    secret: Secret,
    scalar: Zeroizing<[u8; 32]>,
    public: Option<P256PublicKey>,
    challenge: Nonce,
}

fn kind_code(k: DeviceKeyKind) -> u8 {
    match k {
        DeviceKeyKind::Signing => 0,
        DeviceKeyKind::Agreement => 1,
        DeviceKeyKind::Wrapping => 2,
    }
}

fn kind_of(code: u8) -> Option<DeviceKeyKind> {
    match code {
        0 => Some(DeviceKeyKind::Signing),
        1 => Some(DeviceKeyKind::Agreement),
        2 => Some(DeviceKeyKind::Wrapping),
        _ => None,
    }
}

/// Software keys with real cryptography: P-256 ECDSA signing, P-256 agreement (HPKE `fs1-p`
/// opens inside the core) and an AES-256-GCM wrapping key. Keys are generated from the
/// browser's CSPRNG, persisted through [`WebStorage`] in [`Namespace::Keys`], and **never
/// attested** (CLI-007): this is a software key store, not a hardware boundary.
pub struct WebKeyStore {
    storage: &'static WebStorage,
    random: &'static WebRandom,
    keys: Mutex<BTreeMap<String, Entry>>,
    locked: std::sync::atomic::AtomicBool,
}

impl WebKeyStore {
    /// A key store over `storage`, loading the keys it holds.
    pub fn open(storage: &'static WebStorage, random: &'static WebRandom) -> Self {
        let store = Self { storage, random, keys: Mutex::new(BTreeMap::new()), locked: std::sync::atomic::AtomicBool::new(false) };
        for name in storage.names_in(Namespace::Keys) {
            if let Some(entry) = storage.get(Namespace::Keys, &name).and_then(|b| Self::decode(&b)) {
                store.keys.lock().expect("lock").insert(name, entry);
            }
        }
        store
    }

    fn encode(e: &Entry) -> Vec<u8> {
        let mut out = vec![kind_code(e.kind), u8::from(e.protection.unlocked_required)];
        out.extend_from_slice(&e.scalar[..]);
        out.extend_from_slice(e.challenge.as_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Entry> {
        let kind = kind_of(*bytes.first()?)?;
        let unlocked_required = *bytes.get(1)? != 0;
        let scalar: [u8; 32] = bytes.get(2..34)?.try_into().ok()?;
        let challenge: [u8; 32] = bytes.get(34..66)?.try_into().ok()?;
        Self::entry(kind, KeyProtection { unlocked_required }, Zeroizing::new(scalar), Nonce::from(challenge)).ok()
    }

    fn entry(kind: DeviceKeyKind, protection: KeyProtection, scalar: Zeroizing<[u8; 32]>, challenge: Nonce) -> Result<Entry, KeyStoreError> {
        let bad = |what: &str| KeyStoreError::Backend(format!("key material: {what}"));
        let (secret, public) = match kind {
            DeviceKeyKind::Signing => {
                let k = SigningKey::from_scalar(&scalar[..]).map_err(|_| bad("signing scalar"))?;
                let p = k.public_key();
                (Secret::Sign(k), Some(p))
            }
            DeviceKeyKind::Agreement => {
                let s = RecipientSecret::from_bytes(Suite::Fs1P, &scalar[..]).map_err(|_| bad("agreement scalar"))?;
                let p = match s.public().map_err(|_| bad("agreement public key"))? {
                    fieldseal_kernel::seal::RecipientKey::P256(p) => p,
                    _ => return Err(bad("agreement suite")),
                };
                (Secret::Agree(scalar.clone()), Some(p))
            }
            DeviceKeyKind::Wrapping => (Secret::Wrap(scalar.clone()), None),
        };
        Ok(Entry { kind, protection, secret, scalar, public, challenge })
    }

    /// Locks or unlocks the "device": a browser tab has no OS lock, so the page's own lock
    /// stands in. Keys created as unlock-bound refuse to work while it is locked.
    pub fn set_locked(&self, locked: bool) {
        self.locked.store(locked, std::sync::atomic::Ordering::SeqCst);
    }

    fn with_key<T>(&self, handle: &KeyHandle, kind: DeviceKeyKind, f: impl FnOnce(&Entry) -> Result<T, KeyStoreError>) -> Result<T, KeyStoreError> {
        let keys = self.keys.lock().expect("lock");
        let entry = keys.get(&handle.0).ok_or(KeyStoreError::UnknownKey)?;
        if entry.kind != kind {
            return Err(KeyStoreError::WrongKind(entry.kind));
        }
        if entry.protection.unlocked_required && self.locked.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(KeyStoreError::Locked);
        }
        f(entry)
    }

    /// The handle of the signing key whose public half is `public`.
    pub fn signing_handle(&self, public: &P256PublicKey) -> Option<KeyHandle> {
        self.keys.lock().expect("lock").iter().find(|(_, k)| k.kind == DeviceKeyKind::Signing && k.public.as_ref() == Some(public)).map(|(h, _)| KeyHandle(h.clone()))
    }

    /// The agreement public key bundles are sealed to (the most recently generated one).
    pub fn agreement_public(&self) -> Option<P256PublicKey> {
        self.keys.lock().expect("lock").values().rev().find(|k| k.kind == DeviceKeyKind::Agreement).and_then(|k| k.public.clone())
    }

    /// The runtime's agreement key for opening bundles: HPKE opens inside the core with the
    /// stored scalar.
    pub fn agreement_key(&self) -> Option<fieldseal_adapters_memory::distribution::SoftwareAgreementKey> {
        let keys = self.keys.lock().expect("lock");
        let scalar = keys.values().rev().find_map(|k| match &k.secret {
            Secret::Agree(s) => Some(s.clone()),
            _ => None,
        })?;
        let secret = RecipientSecret::from_bytes(Suite::Fs1P, &scalar[..]).ok()?;
        fieldseal_adapters_memory::distribution::SoftwareAgreementKey::new(secret).ok()
    }

    /// How many keys are held.
    pub fn key_count(&self) -> usize {
        self.keys.lock().expect("lock").len()
    }
}

impl SecureKeyStore for WebKeyStore {
    fn generate(&self, kind: DeviceKeyKind, protection: KeyProtection, challenge: Option<Nonce>) -> Result<(KeyHandle, Option<P256PublicKey>), KeyStoreError> {
        let mut keys = self.keys.lock().expect("lock");
        let scalar = loop {
            let mut b = Zeroizing::new([0u8; 32]);
            self.random.fill(&mut b[..]);
            let valid = match kind {
                DeviceKeyKind::Signing => SigningKey::from_scalar(&b[..]).is_ok(),
                DeviceKeyKind::Agreement => RecipientSecret::from_bytes(Suite::Fs1P, &b[..]).and_then(|s| s.public()).is_ok(),
                DeviceKeyKind::Wrapping => true,
            };
            if valid {
                break b;
            }
        };
        let _ = SourceRng(self.random);
        let entry = Self::entry(kind, protection, scalar, challenge.unwrap_or(Nonce::from([0; 32])))?;
        let n = keys.keys().filter_map(|h| h.strip_prefix("web-key-").and_then(|n| n.parse::<u64>().ok())).max().map_or(0, |n| n + 1);
        let handle = format!("web-key-{n}");
        self.storage.put(Namespace::Keys, &handle, &Self::encode(&entry));
        let public = entry.public.clone();
        keys.insert(handle.clone(), entry);
        Ok((KeyHandle(handle), public))
    }

    fn sign(&self, key: &KeyHandle, message: &[u8]) -> Result<Signature, KeyStoreError> {
        self.with_key(key, DeviceKeyKind::Signing, |e| match &e.secret {
            Secret::Sign(k) => Ok(k.sign_message(message)),
            _ => Err(KeyStoreError::WrongKind(e.kind)),
        })
    }

    fn agree(&self, key: &KeyHandle, peer: &P256PublicKey) -> Result<Vec<u8>, KeyStoreError> {
        self.with_key(key, DeviceKeyKind::Agreement, |e| {
            let secret = p256::SecretKey::from_slice(&e.scalar[..]).map_err(|_| KeyStoreError::Backend("agreement scalar".into()))?;
            let peer = p256::PublicKey::from_sec1_bytes(peer.as_bytes()).map_err(|_| KeyStoreError::Backend("peer public key".into()))?;
            let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        })
    }

    fn wrap(&self, key: &KeyHandle, data: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        self.with_key(key, DeviceKeyKind::Wrapping, |e| {
            let Secret::Wrap(s) = &e.secret else { return Err(KeyStoreError::WrongKind(e.kind)) };
            let cipher = Aes256Gcm::new_from_slice(&s[..]).map_err(|_| KeyStoreError::Backend("wrapping key".into()))?;
            let mut nonce = [0u8; 12];
            self.random.fill(&mut nonce);
            let ct = cipher.encrypt(&GcmNonce::from(nonce), Payload { msg: data, aad: b"fieldseal.dev/web-wrap/v1" }).map_err(|_| KeyStoreError::Backend("wrap".into()))?;
            let mut out = nonce.to_vec();
            out.extend_from_slice(&ct);
            Ok(out)
        })
    }

    fn unwrap(&self, key: &KeyHandle, wrapped: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        self.with_key(key, DeviceKeyKind::Wrapping, |e| {
            let Secret::Wrap(s) = &e.secret else { return Err(KeyStoreError::WrongKind(e.kind)) };
            let cipher = Aes256Gcm::new_from_slice(&s[..]).map_err(|_| KeyStoreError::Backend("wrapping key".into()))?;
            let (nonce, ct) = wrapped.split_at_checked(12).ok_or(KeyStoreError::Unwrap)?;
            let nonce: [u8; 12] = nonce.try_into().map_err(|_| KeyStoreError::Unwrap)?;
            cipher.decrypt(&GcmNonce::from(nonce), Payload { msg: ct, aad: b"fieldseal.dev/web-wrap/v1" }).map_err(|_| KeyStoreError::Unwrap)
        })
    }

    fn delete(&self, key: &KeyHandle) -> Result<(), KeyStoreError> {
        self.keys.lock().expect("lock").remove(&key.0).ok_or(KeyStoreError::UnknownKey)?;
        self.storage.remove(Namespace::Keys, &key.0);
        Ok(())
    }

    fn exists(&self, key: &KeyHandle) -> bool {
        self.keys.lock().expect("lock").contains_key(&key.0)
    }
}

impl Attestor for WebKeyStore {
    fn evidence(&self, key: &KeyHandle) -> Result<AttestationEvidence, AttestorError> {
        let keys = self.keys.lock().expect("lock");
        let e = keys.get(&key.0).ok_or(AttestorError::UnknownKey)?;
        let public = e.public.as_ref().ok_or_else(|| AttestorError::Unavailable("wrapping keys have no public key".into()))?;
        Ok(software_evidence(e.kind, e.protection.unlocked_required, &e.challenge, public))
    }
}

/// Interior-mutable cell used by hosts that need to share a value between ports.
pub type Shared<T> = std::rc::Rc<RefCell<T>>;

/// A `Cell` holding the tenancy the bundle opener opens for.
pub type TenancyCell = Cell<Option<fieldseal_kernel::id::TenancyId>>;

/// The development checksum of the `software` evidence format: the in-memory adapters'
/// `toy_digest`, computed with 64-bit lengths so that a 32-bit WebAssembly build produces the
/// same bytes as the 64-bit verifier (`write_usize` writes pointer-width bytes). **Not
/// cryptography**: software evidence says "unattested" and nothing more (TRU-061).
pub fn toy_digest64(parts: &[&[u8]]) -> [u8; 32] {
    use std::hash::Hasher;
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        h.write(&[i as u8]);
        for p in parts {
            h.write(&(p.len() as u64).to_ne_bytes());
            h.write(p);
        }
        chunk.copy_from_slice(&h.finish().to_be_bytes());
    }
    out
}

/// Software (unattested) key evidence, byte-for-byte what `software_evidence` in the in-memory
/// registration adapter makes on a 64-bit host (see [`toy_digest64`]).
pub fn software_evidence(kind: DeviceKeyKind, unlocked_required: bool, challenge: &Nonce, key: &P256PublicKey) -> AttestationEvidence {
    let code = match kind {
        DeviceKeyKind::Signing => 0u8,
        DeviceKeyKind::Agreement => 1,
        DeviceKeyKind::Wrapping => 2,
    };
    let mut data = vec![code, u8::from(unlocked_required)];
    data.extend_from_slice(challenge.as_bytes());
    data.extend_from_slice(key.as_bytes());
    let check = toy_digest64(&[b"evidence", &data]);
    data.extend_from_slice(&check[..8]);
    AttestationEvidence { format: fieldseal_trust::application::SOFTWARE_EVIDENCE_FORMAT.into(), data }
}
