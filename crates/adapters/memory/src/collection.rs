//! In-memory adapters for the Collection context's platform ports, and a simulated
//! authority and device for `fieldseal device simulate` and end-to-end tests.
//!
//! **Not cryptography, not a platform.** The "memory-hard hash", key wrapping, key
//! agreement, close certificates and "receipt signatures" here are deterministic stand-ins
//! built from a non-cryptographic hash. Record signatures, seals and publications are real
//! (format core), so what the simulator writes verifies like a device's.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use fieldseal_collection::application::Platform;
use fieldseal_collection::domain::bundle::{CloseCertificate, HeldRoster, OpenedBundle, RegistrationGrant, RosterSubject, TimeAnchor};
use fieldseal_distribution::domain::AnchorKind;
use fieldseal_collection::domain::payload::Payload;
use fieldseal_collection::domain::{
    CaptureConstraints, CapturedImage, HashParams, ManagementMode, ReceiptClaim, ReceiptCoverage, Restriction,
    RestrictionState, RuntimePin, StorageClass, StorageName, WindowId,
};
use fieldseal_collection::ports::{
    BundleOpenError, BundleOpener, Camera, CameraError, CloseCertificateCheck, CloseCertificateError, DevicePolicy,
    DevicePolicyError, DisplayError, ElapsedClock, FileAccess, FileAccessError, MemoryHardHash, ReceiptCheck,
    ReceiptCheckError, SecureDisplay, SecureStorage, StorageError, WallClock,
};
use fieldseal_kernel::crypto::{DomainTag, P256PublicKey, Purpose, Signature, tags};
use fieldseal_kernel::id::{Digest, KeyId, Nonce, ReviewerId, Salt, Seq, TenancyHandle, TenancyId};
use fieldseal_kernel::seal::{self, RecipientKey, RecipientSecret, SealedBox, Suite};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_kernel::time::{AuthorityTime, ElapsedReading};
use fieldseal_kernel::{Value, WireError};
use fieldseal_policy::domain::{Controls, PublishingPolicy};
use fieldseal_publishing::application::{BuildInput, BuildProvenance, Publish, SignPublication, VerifyPublication};
use fieldseal_publishing::domain::{Artefact, ArtefactKind, BuilderId, Publication, Review, ReviewDecision, RevisionId, SourceRef};
use fieldseal_publishing::ports::{LogError, LogTransport, ReviewSystem, Transmission};
use fieldseal_trust::domain::{
    AttestationEvidence, AuthorityPublicKey, BundleSignature, BundleVersion, CertificateRequest, CustodyKey, DeviceKeyKind,
    IssueTerms, KeyAlgorithm, KeyCertificate, KeyHandle, KeyProtection, KeyRole, KeyUse, TrustBundle, TrustBundleContents,
    TrustStore, UnsignedCertificate, UnsignedTrustBundle, may_sign,
};
use fieldseal_trust::ports::{
    Attestor, AttestorError, CustodyError, KeyCustody, KeyStoreError, RandomSource, SecureKeyStore, SourceRng,
};
use zeroize::Zeroizing;

use crate::trust::{SOFTWARE_EVIDENCE_FORMAT, SeededRandom, toy_digest};

/// In-memory [`ElapsedClock`]: advanced by the test, with simulated reboots.
#[derive(Default)]
pub struct MemoryElapsedClock {
    elapsed_ms: AtomicU64,
    boot_count: AtomicU32,
}

impl MemoryElapsedClock {
    /// At zero, boot 1.
    pub fn new() -> Self {
        let c = Self::default();
        c.boot_count.store(1, Ordering::SeqCst);
        c
    }

    /// Advances elapsed time.
    pub fn advance_ms(&self, ms: u64) {
        self.elapsed_ms.fetch_add(ms, Ordering::SeqCst);
    }

    /// Simulates a reboot: elapsed time restarts, the boot count increases.
    pub fn reboot(&self) {
        self.elapsed_ms.store(0, Ordering::SeqCst);
        self.boot_count.fetch_add(1, Ordering::SeqCst);
    }
}

impl ElapsedClock for MemoryElapsedClock {
    fn now(&self) -> ElapsedReading {
        ElapsedReading {
            elapsed_ms: self.elapsed_ms.load(Ordering::SeqCst),
            boot_count: self.boot_count.load(Ordering::SeqCst),
        }
    }
}

/// Fault injection for [`MemorySecureStorage`]: simulated power loss and torn writes.
#[derive(Default, Debug)]
struct Faults {
    /// Mutating operations allowed before the simulated power cut.
    remaining: Option<u64>,
    /// Bytes of the next append that reach storage before the power cut.
    tear_next_append: Option<usize>,
    /// The device is "off": every operation fails until [`MemorySecureStorage::restart`].
    crashed: bool,
    /// Mutating operations performed so far.
    ops: u64,
}

/// In-memory [`SecureStorage`]. Session-encrypted storage can be locked, and faults can be
/// injected: a power cut after a number of writes ([`Self::crash_after`]) or in the middle
/// of an append ([`Self::tear_next_append`]). After a fault every operation fails until
/// [`Self::restart`], which keeps exactly what reached storage, as a reboot would.
#[derive(Default)]
pub struct MemorySecureStorage {
    objects: Mutex<BTreeMap<(StorageClass, StorageName), Vec<u8>>>,
    session_locked: Mutex<bool>,
    faults: Mutex<Faults>,
}

const CRASHED: &str = "simulated power loss";

impl MemorySecureStorage {
    /// Empty, unlocked.
    pub fn new() -> Self {
        Self::default()
    }

    /// Locks or unlocks session-encrypted storage.
    pub fn set_session_locked(&self, locked: bool) {
        *self.session_locked.lock().expect("lock") = locked;
    }

    /// Allows `n` more writes, appends or deletes, then cuts the power: the next one fails
    /// without effect, and so does everything after it until [`Self::restart`].
    pub fn crash_after(&self, n: u64) {
        self.faults.lock().expect("lock").remaining = Some(n);
    }

    /// The next append writes only its first `keep` bytes, then the power is cut.
    pub fn tear_next_append(&self, keep: usize) {
        self.faults.lock().expect("lock").tear_next_append = Some(keep);
    }

    /// Restarts after a fault: storage keeps what was written, and faults are cleared.
    pub fn restart(&self) {
        let ops = self.ops();
        *self.faults.lock().expect("lock") = Faults { ops, ..Faults::default() };
    }

    /// Whether a fault has cut the power.
    pub fn crashed(&self) -> bool {
        self.faults.lock().expect("lock").crashed
    }

    /// Mutating operations performed so far (to inject a fault at every step).
    pub fn ops(&self) -> u64 {
        self.faults.lock().expect("lock").ops
    }

    /// Reads an object directly, bypassing faults and locks (for test assertions).
    pub fn peek(&self, class: StorageClass, name: &str) -> Option<Vec<u8>> {
        self.objects.lock().expect("lock").get(&(class, StorageName(name.into()))).cloned()
    }

    /// Overwrites an object directly, bypassing faults (to simulate tampering or damage).
    pub fn poke(&self, class: StorageClass, name: &str, bytes: Vec<u8>) {
        self.objects.lock().expect("lock").insert((class, StorageName(name.into())), bytes);
    }

    /// Every object name in a class, bypassing faults and locks.
    pub fn list(&self, class: StorageClass) -> Vec<String> {
        self.objects.lock().expect("lock").keys().filter(|(c, _)| *c == class).map(|(_, n)| n.0.clone()).collect()
    }

    fn check(&self, class: StorageClass) -> Result<(), StorageError> {
        if self.faults.lock().expect("lock").crashed {
            return Err(StorageError::Backend(CRASHED.into()));
        }
        if class == StorageClass::SessionEncrypted && *self.session_locked.lock().expect("lock") {
            return Err(StorageError::Locked);
        }
        Ok(())
    }

    /// Counts a mutating operation; `Err` if the power is cut before it.
    fn mutate(&self, class: StorageClass) -> Result<(), StorageError> {
        self.check(class)?;
        let mut f = self.faults.lock().expect("lock");
        if let Some(r) = f.remaining.as_mut() {
            if *r == 0 {
                f.crashed = true;
                return Err(StorageError::Backend(CRASHED.into()));
            }
            *r -= 1;
        }
        f.ops += 1;
        Ok(())
    }
}

impl SecureStorage for MemorySecureStorage {
    fn write(
        &self,
        class: StorageClass,
        name: &StorageName,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        self.mutate(class)?;
        self.objects
            .lock()
            .expect("lock")
            .insert((class, name.clone()), bytes.to_vec());
        Ok(())
    }

    fn append(&self, class: StorageClass, name: &StorageName, bytes: &[u8]) -> Result<(), StorageError> {
        self.mutate(class)?;
        let tear = self.faults.lock().expect("lock").tear_next_append.take();
        let mut objects = self.objects.lock().expect("lock");
        let object = objects.entry((class, name.clone())).or_default();
        match tear {
            Some(keep) => {
                object.extend_from_slice(&bytes[..keep.min(bytes.len())]);
                self.faults.lock().expect("lock").crashed = true;
                Err(StorageError::Backend(CRASHED.into()))
            }
            None => {
                object.extend_from_slice(bytes);
                Ok(())
            }
        }
    }

    fn read(&self, class: StorageClass, name: &StorageName) -> Result<Option<Vec<u8>>, StorageError> {
        self.check(class)?;
        Ok(self
            .objects
            .lock()
            .expect("lock")
            .get(&(class, name.clone()))
            .cloned())
    }

    fn delete(&self, class: StorageClass, name: &StorageName) -> Result<(), StorageError> {
        self.mutate(class)?;
        self.objects.lock().expect("lock").remove(&(class, name.clone()));
        Ok(())
    }

    fn names(&self, class: StorageClass) -> Result<Vec<StorageName>, StorageError> {
        self.check(class)?;
        Ok(self
            .objects
            .lock()
            .expect("lock")
            .keys()
            .filter(|(c, _)| *c == class)
            .map(|(_, n)| n.clone())
            .collect())
    }
}

/// In-memory [`SecureDisplay`].
#[derive(Default)]
pub struct MemorySecureDisplay {
    protected: Mutex<BTreeSet<WindowId>>,
}

impl MemorySecureDisplay {
    /// No windows protected.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecureDisplay for MemorySecureDisplay {
    fn protect(&self, window: &WindowId) -> Result<(), DisplayError> {
        self.protected.lock().expect("lock").insert(window.clone());
        Ok(())
    }

    fn is_protected(&self, window: &WindowId) -> bool {
        self.protected.lock().expect("lock").contains(window)
    }
}

/// In-memory [`DevicePolicy`] over a simulated platform. The platform state is
/// separate from what the adapter applied, so tests can change it "out of band"
/// and check the adapter reads it live (PLAT-033).
pub struct MemoryDevicePolicy {
    mode: ManagementMode,
    platform: Mutex<BTreeMap<Restriction, RestrictionState>>,
}

impl MemoryDevicePolicy {
    /// A self-managed device with nothing applied yet.
    pub fn self_managed() -> Self {
        Self {
            mode: ManagementMode::SelfManaged,
            platform: Mutex::new(
                Restriction::ALL
                    .iter()
                    .map(|r| (*r, RestrictionState::Missing))
                    .collect(),
            ),
        }
    }

    /// An EMM-managed device whose EMM applied `in_force`; everything else is unreadable.
    pub fn emm_managed(in_force: &[Restriction]) -> Self {
        Self {
            mode: ManagementMode::EmmManaged,
            platform: Mutex::new(
                Restriction::ALL
                    .iter()
                    .map(|r| {
                        let state = if in_force.contains(r) {
                            RestrictionState::InForce
                        } else {
                            RestrictionState::Unknown
                        };
                        (*r, state)
                    })
                    .collect(),
            ),
        }
    }

    /// Simulates someone removing a restriction behind the adapter's back.
    pub fn remove_out_of_band(&self, restriction: Restriction) {
        self.platform
            .lock()
            .expect("lock")
            .insert(restriction, RestrictionState::Missing);
    }
}

impl DevicePolicy for MemoryDevicePolicy {
    fn mode(&self) -> ManagementMode {
        self.mode
    }

    fn apply(&self, required: &[Restriction]) -> Result<(), DevicePolicyError> {
        if self.mode != ManagementMode::SelfManaged {
            return Err(DevicePolicyError::NotDeviceOwner);
        }
        let mut platform = self.platform.lock().expect("lock");
        for r in required {
            platform.insert(*r, RestrictionState::InForce);
        }
        Ok(())
    }

    fn effective_restrictions(&self) -> BTreeMap<Restriction, RestrictionState> {
        self.platform.lock().expect("lock").clone()
    }
}

/// In-memory [`Camera`]: returns a fixed placeholder image.
#[derive(Default)]
pub struct MemoryCamera;

impl Camera for MemoryCamera {
    fn capture(&self, constraints: CaptureConstraints) -> Result<CapturedImage, CameraError> {
        let mut bytes = b"FIELDSEAL-TEST-IMAGE:".to_vec();
        bytes.extend_from_slice(&constraints.max_edge.to_be_bytes());
        Ok(CapturedImage(bytes))
    }
}

/// In-memory [`MemoryHardHash`]. **Not memory-hard and not Argon2**: an iterated toy digest.
#[derive(Default)]
pub struct ToyMemoryHardHash;

impl MemoryHardHash for ToyMemoryHardHash {
    fn hash(&self, pin: &RuntimePin, salt: &[u8; 16], params: HashParams) -> Option<[u8; 32]> {
        if !params.meets_floor() {
            return None;
        }
        let mut out = toy_digest(&[b"pin", pin.digits().as_bytes(), salt]);
        for _ in 0..params.iterations {
            out = toy_digest(&[&out, salt]);
        }
        Some(out)
    }
}

const RECEIPT_TAG: &[u8] = b"fieldseal.dev/receipt/v1";

/// A toy authority that issues receipts and verifies them: an in-memory
/// [`ReceiptCheck`] that trusts only its own receipt key. **Not cryptography.**
pub struct ToyReceiptAuthority {
    secret: [u8; 32],
    key: KeyId,
}

impl ToyReceiptAuthority {
    /// An authority whose receipt key is derived from `seed`.
    pub fn new(seed: &[u8]) -> Self {
        let secret = toy_digest(&[b"receipt-secret", seed]);
        Self {
            secret,
            key: fieldseal_kernel::digest::key_id(&toy_digest(&[b"receipt-key", &secret])),
        }
    }

    /// The receipt key's identifier.
    pub fn key(&self) -> KeyId {
        self.key
    }

    fn statement(tenancy: &TenancyId, last_seq: Seq, hash: &Digest, time: AuthorityTime) -> Vec<u8> {
        let mut s = tenancy.as_bytes().to_vec();
        s.extend_from_slice(&last_seq.0.to_be_bytes());
        s.extend_from_slice(hash.as_bytes());
        s.extend_from_slice(&time.0.to_be_bytes());
        s
    }

    /// Issues a receipt.
    pub fn issue(
        &self,
        tenancy: TenancyId,
        last_seq: Seq,
        journal_hash: Digest,
        time: AuthorityTime,
    ) -> ReceiptClaim {
        let statement = Self::statement(&tenancy, last_seq, &journal_hash, time);
        ReceiptClaim {
            tenancy,
            last_seq,
            journal_hash,
            time,
            signer: self.key,
            signature: Signature(toy_digest(&[&self.secret, RECEIPT_TAG, &statement]).to_vec()),
            statement,
        }
    }
}

impl ReceiptCheck for ToyReceiptAuthority {
    fn verify(&self, claim: &ReceiptClaim) -> Result<(), ReceiptCheckError> {
        if claim.signer != self.key {
            return Err(ReceiptCheckError::UntrustedSigner);
        }
        let expected = Self::statement(&claim.tenancy, claim.last_seq, &claim.journal_hash, claim.time);
        if claim.statement != expected
            || claim.signature.0 != toy_digest(&[&self.secret, RECEIPT_TAG, &claim.statement])
        {
            return Err(ReceiptCheckError::BadSignature);
        }
        Ok(())
    }
}

/// A software [`SecureKeyStore`] and [`Attestor`] for the device simulator, whose signing
/// keys are real P-256 keys (so journals verify with the format core), drawn from a seeded
/// random source. Keys honour `unlocked_required` against a simulated device lock, and
/// deletion is final. Evidence is marked unattested ([`SOFTWARE_EVIDENCE_FORMAT`], CLI-007).
/// **Not a hardware boundary.** Key agreement and wrapping are deterministic stand-ins.
pub struct SimulatedKeyStore {
    random: SeededRandom,
    /// Keys that already exist (a device that registered with a factory): the next signing
    /// and agreement keys generated are these instead of fresh ones.
    preset: Mutex<(Option<SigningKey>, Option<[u8; 32]>)>,
    keys: Mutex<BTreeMap<String, SimKey>>,
    counter: AtomicU64,
    locked: AtomicBool,
}

enum SimSecret {
    Sign(SigningKey),
    Agree([u8; 32]),
    Wrap([u8; 32]),
}

struct SimKey {
    kind: DeviceKeyKind,
    protection: KeyProtection,
    secret: SimSecret,
    public: Option<P256PublicKey>,
    challenge: Nonce,
}

impl SimulatedKeyStore {
    /// An empty, unlocked store whose keys come from `seed`.
    pub fn new(seed: u64) -> Self {
        Self { random: SeededRandom::new(seed), preset: Mutex::default(), keys: Mutex::default(), counter: AtomicU64::new(0), locked: AtomicBool::new(false) }
    }

    /// A store whose first signing key and first agreement key are the given ones: the
    /// runtime of a device that registered with a factory under those keys creates its
    /// tenancy with them. `agreement` is the P-256 scalar (suite `fs1-p`).
    pub fn with_keys(seed: u64, signing: SigningKey, agreement: [u8; 32]) -> Self {
        let store = Self::new(seed);
        *store.preset.lock().expect("lock") = (Some(signing), Some(agreement));
        store
    }

    /// Simulates locking or unlocking the device.
    pub fn set_locked(&self, locked: bool) {
        self.locked.store(locked, Ordering::SeqCst);
    }

    /// How many keys the store holds (deleted keys are gone).
    pub fn key_count(&self) -> usize {
        self.keys.lock().expect("lock").len()
    }

    fn with_key<T>(&self, handle: &KeyHandle, kind: DeviceKeyKind, f: impl FnOnce(&SimKey) -> Result<T, KeyStoreError>) -> Result<T, KeyStoreError> {
        let keys = self.keys.lock().expect("lock");
        let entry = keys.get(&handle.0).ok_or(KeyStoreError::UnknownKey)?;
        if entry.kind != kind {
            return Err(KeyStoreError::WrongKind(entry.kind));
        }
        if entry.protection.unlocked_required && self.locked.load(Ordering::SeqCst) {
            return Err(KeyStoreError::Locked);
        }
        f(entry)
    }

    fn keystream(secret: &[u8; 32], len: usize) -> Vec<u8> {
        (0..len.div_ceil(32)).flat_map(|i| toy_digest(&[b"stream", secret, &(i as u64).to_be_bytes()])).take(len).collect()
    }

    /// The most recently generated agreement key, as the runtime's [`AgreementKey`] for
    /// opening bundles (the simulator's stand-in for the platform key store performing the
    /// HPKE key agreement).
    ///
    /// [`AgreementKey`]: fieldseal_distribution::ports::AgreementKey
    pub fn agreement_key(&self) -> Option<crate::distribution::SoftwareAgreementKey> {
        let keys = self.keys.lock().expect("lock");
        let scalar = keys.values().rev().find_map(|k| match &k.secret {
            SimSecret::Agree(s) => Some(*s),
            _ => None,
        })?;
        let secret = RecipientSecret::from_bytes(Suite::Fs1P, &scalar).ok()?;
        crate::distribution::SoftwareAgreementKey::new(secret).ok()
    }

    /// The handle of the signing key whose public half is `public`, so a test can drive the
    /// key store the way a registration request does (proof of possession).
    pub fn signing_handle(&self, public: &P256PublicKey) -> Option<KeyHandle> {
        let keys = self.keys.lock().expect("lock");
        keys.iter().find(|(_, k)| k.kind == DeviceKeyKind::Signing && k.public.as_ref() == Some(public)).map(|(h, _)| KeyHandle(h.clone()))
    }

    /// The agreement public key of [`SimulatedKeyStore::agreement_key`].
    pub fn agreement_public(&self) -> Option<P256PublicKey> {
        let keys = self.keys.lock().expect("lock");
        keys.values().rev().find(|k| matches!(k.secret, SimSecret::Agree(_))).and_then(|k| k.public.clone())
    }
}

impl SecureKeyStore for SimulatedKeyStore {
    fn generate(&self, kind: DeviceKeyKind, protection: KeyProtection, challenge: Option<Nonce>) -> Result<(KeyHandle, Option<P256PublicKey>), KeyStoreError> {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        let mut seed = [0u8; 32];
        self.random.fill(&mut seed);
        let (secret, public) = match kind {
            DeviceKeyKind::Signing => {
                let preset = self.preset.lock().expect("lock").0.take();
                let k = preset.unwrap_or_else(|| SigningKey::generate(&mut SourceRng(&self.random)));
                let p = k.public_key();
                (SimSecret::Sign(k), Some(p))
            }
            DeviceKeyKind::Agreement => {
                // A real P-256 key, so a bundle can be sealed to it with HPKE.
                let preset = self.preset.lock().expect("lock").1.take();
                let secret = match preset {
                    Some(scalar) => RecipientSecret::from_bytes(Suite::Fs1P, &scalar).map_err(|_| KeyStoreError::Backend("agreement key".into()))?,
                    None => RecipientSecret::generate(Suite::Fs1P, &mut SourceRng(&self.random)),
                };
                let (RecipientSecret::P256(scalar), Ok(RecipientKey::P256(p))) = (&secret, secret.public()) else {
                    return Err(KeyStoreError::Backend("agreement key generation".into()));
                };
                (SimSecret::Agree(**scalar), Some(p))
            }
            DeviceKeyKind::Wrapping => (SimSecret::Wrap(seed), None),
        };
        let handle = KeyHandle(format!("sim-key-{n}"));
        let entry = SimKey { kind, protection, secret, public: public.clone(), challenge: challenge.unwrap_or(Nonce::from([0; 32])) };
        self.keys.lock().expect("lock").insert(handle.0.clone(), entry);
        Ok((handle, public))
    }

    fn sign(&self, key: &KeyHandle, message: &[u8]) -> Result<Signature, KeyStoreError> {
        self.with_key(key, DeviceKeyKind::Signing, |e| match &e.secret {
            SimSecret::Sign(k) => Ok(k.sign_message(message)),
            _ => Err(KeyStoreError::WrongKind(e.kind)),
        })
    }

    fn agree(&self, key: &KeyHandle, peer: &P256PublicKey) -> Result<Vec<u8>, KeyStoreError> {
        self.with_key(key, DeviceKeyKind::Agreement, |e| {
            let own = e.public.as_ref().expect("agreement keys have a public key");
            let (a, b) = if own.as_bytes()[..] <= peer.as_bytes()[..] { (own, peer) } else { (peer, own) };
            Ok(toy_digest(&[b"agree", a.as_bytes(), b.as_bytes()]).to_vec())
        })
    }

    fn wrap(&self, key: &KeyHandle, data: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        self.with_key(key, DeviceKeyKind::Wrapping, |e| {
            let SimSecret::Wrap(s) = &e.secret else { return Err(KeyStoreError::WrongKind(e.kind)) };
            let mut out = toy_digest(&[b"tag", s, data])[..8].to_vec();
            out.extend(data.iter().zip(Self::keystream(s, data.len())).map(|(d, k)| d ^ k));
            Ok(out)
        })
    }

    fn unwrap(&self, key: &KeyHandle, wrapped: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        self.with_key(key, DeviceKeyKind::Wrapping, |e| {
            let SimSecret::Wrap(s) = &e.secret else { return Err(KeyStoreError::WrongKind(e.kind)) };
            let (tag, body) = wrapped.split_at_checked(8).ok_or(KeyStoreError::Unwrap)?;
            let data: Vec<u8> = body.iter().zip(Self::keystream(s, body.len())).map(|(d, k)| d ^ k).collect();
            if tag != &toy_digest(&[b"tag", s, &data])[..8] {
                return Err(KeyStoreError::Unwrap);
            }
            Ok(data)
        })
    }

    fn delete(&self, key: &KeyHandle) -> Result<(), KeyStoreError> {
        self.keys.lock().expect("lock").remove(&key.0).map(|_| ()).ok_or(KeyStoreError::UnknownKey)
    }

    fn exists(&self, key: &KeyHandle) -> bool {
        self.keys.lock().expect("lock").contains_key(&key.0)
    }
}

impl Attestor for SimulatedKeyStore {
    fn evidence(&self, key: &KeyHandle) -> Result<AttestationEvidence, AttestorError> {
        let keys = self.keys.lock().expect("lock");
        let entry = keys.get(&key.0).ok_or(AttestorError::UnknownKey)?;
        let public = entry.public.as_ref().ok_or_else(|| AttestorError::Unavailable("wrapping keys have no public key".into()))?;
        let mut data = b"unattested:".to_vec();
        data.extend_from_slice(entry.challenge.as_bytes());
        data.extend_from_slice(public.as_bytes());
        Ok(AttestationEvidence { format: SOFTWARE_EVIDENCE_FORMAT.into(), data })
    }
}

/// In-memory [`WallClock`]: a settable hint, `None` when unknown.
#[derive(Default)]
pub struct MemoryWallClock(Mutex<Option<u64>>);

impl MemoryWallClock {
    /// A clock reading `ms` since the epoch.
    pub fn at(ms: u64) -> Self {
        Self(Mutex::new(Some(ms)))
    }

    /// Sets the device's wall clock (anyone can, which is why it is only a hint).
    pub fn set(&self, ms: Option<u64>) {
        *self.0.lock().expect("lock") = ms;
    }
}

impl WallClock for MemoryWallClock {
    fn now_ms(&self) -> Option<u64> {
        *self.0.lock().expect("lock")
    }
}

/// In-memory [`FileAccess`]: the "picker" returns the bytes it was given.
pub struct MemoryFileSource(Mutex<Option<Vec<u8>>>);

impl MemoryFileSource {
    /// A picker that offers `bytes`.
    pub fn offering(bytes: &[u8]) -> Self {
        Self(Mutex::new(Some(bytes.to_vec())))
    }
}

impl FileAccess for MemoryFileSource {
    fn pick_source(&self) -> Result<Vec<u8>, FileAccessError> {
        self.0.lock().expect("lock").clone().ok_or(FileAccessError::Cancelled)
    }
}

/// In-memory [`BundleOpener`]: opens only bundle files registered with it, standing in for
/// Distribution's envelope check and seal opening (issue #49).
#[derive(Default)]
pub struct MemoryBundleOpener {
    bundles: Mutex<BTreeMap<Vec<u8>, OpenedBundle>>,
}

impl MemoryBundleOpener {
    /// An opener that knows no bundles.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a bundle: returns the "file" bytes that open to `contents`.
    pub fn register(&self, contents: OpenedBundle) -> Vec<u8> {
        let mut file = b"FSB1".to_vec();
        file.extend_from_slice(contents.address.as_bytes());
        self.bundles.lock().expect("lock").insert(file.clone(), contents);
        file
    }
}

impl BundleOpener for MemoryBundleOpener {
    fn open(&self, file: &[u8]) -> Result<OpenedBundle, BundleOpenError> {
        self.bundles.lock().expect("lock").get(file).cloned().ok_or(BundleOpenError::WrongDevice)
    }
}

/// A toy authority that issues close certificates and checks them: an in-memory
/// [`CloseCertificateCheck`]. **Not cryptography.**
pub struct ToyCloseAuthority {
    secret: [u8; 32],
}

impl ToyCloseAuthority {
    /// An authority whose key is derived from `seed`.
    pub fn new(seed: &[u8]) -> Self {
        Self { secret: toy_digest(&[b"close-secret", seed]) }
    }

    /// Issues a close certificate.
    pub fn issue(&self, tenancy: TenancyId, cutoff: Seq, reason: &str) -> Vec<u8> {
        let mut body = tenancy.as_bytes().to_vec();
        body.extend_from_slice(&cutoff.0.to_be_bytes());
        body.extend_from_slice(reason.as_bytes());
        let mut out = toy_digest(&[&self.secret, &body]).to_vec();
        out.extend(body);
        out
    }
}

impl CloseCertificateCheck for ToyCloseAuthority {
    fn verify(&self, bytes: &[u8]) -> Result<CloseCertificate, CloseCertificateError> {
        let bad = || CloseCertificateError::Invalid("bad signature".into());
        let (mac, body) = bytes.split_at_checked(32).ok_or_else(bad)?;
        if mac != toy_digest(&[&self.secret, body]) || body.len() < 40 {
            return Err(bad());
        }
        let tenancy = TenancyId::from_bytes(&body[..32]).map_err(|_| bad())?;
        let cutoff = u64::from_be_bytes(body[32..40].try_into().expect("8 bytes"));
        let reason = String::from_utf8(body[40..].to_vec()).map_err(|_| bad())?;
        Ok(CloseCertificate { tenancy, cutoff_seq: Seq(cutoff), reset: false, reason, bytes: bytes.to_vec() })
    }
}

/// A [`LogTransport`] that accepts every transmission: the simulator's log never leaves
/// memory.
pub struct LocalTransport;

impl LogTransport for LocalTransport {
    fn send(&self, _: &Transmission) -> Result<Vec<u8>, LogError> {
        Ok(Vec::new())
    }
}

/// A [`KeyCustody`] holding software keys derived from labels, so a simulated authority's
/// trust bundle is the same on every run. **Not a hardware boundary.**
#[derive(Default)]
struct LabelCustody {
    keys: Mutex<BTreeMap<KeyId, (CustodyKey, SigningKey)>>,
}

fn label_key(label: &str) -> SigningKey {
    let scalar = fieldseal_kernel::digest::sha256(format!("fieldseal.dev/simulator/{label}").as_bytes());
    SigningKey::from_scalar(scalar.as_bytes()).expect("a SHA-256 output is a valid scalar")
}

impl LabelCustody {
    fn import(&self, role: KeyRole, label: &str) -> KeyId {
        let key = label_key(label);
        let public_key = AuthorityPublicKey::P256(key.public_key());
        let k = CustodyKey { id: public_key.key_id(), public_key, role };
        let id = k.id;
        self.keys.lock().expect("lock").insert(id, (k, key));
        id
    }
}

impl KeyCustody for LabelCustody {
    fn generate(&self, _: KeyRole, _: KeyAlgorithm) -> Result<CustodyKey, CustodyError> {
        Err(CustodyError::Unsupported)
    }

    fn sign(&self, key: &KeyId, role: KeyRole, tag: &DomainTag, structure: &Value, _: &str) -> Result<Signature, CustodyError> {
        let keys = self.keys.lock().expect("lock");
        let (k, sk) = keys.get(key).ok_or(CustodyError::UnknownKey)?;
        if k.role != role {
            return Err(CustodyError::WrongPurpose { held: k.role, requested: role });
        }
        if !may_sign(role, tag) {
            return Err(CustodyError::TagNotAllowed { role, tag: tag.as_str() });
        }
        sk.sign(tag, structure).map_err(|e| CustodyError::Backend(e.to_string()))
    }

    fn open(&self, _: &KeyId, _: Purpose, _: &DomainTag, _: &SealedBox, _: &str) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
        Err(CustodyError::Unsupported)
    }

    fn public_key(&self, key: &KeyId) -> Result<CustodyKey, CustodyError> {
        self.keys.lock().expect("lock").get(key).map(|(k, _)| k.clone()).ok_or(CustodyError::UnknownKey)
    }

    fn usage_log(&self) -> Vec<KeyUse> {
        Vec::new()
    }
}

/// When the simulated authority's world starts: 2027-01-15T08:00:00Z.
pub const SIMULATION_T0: AuthorityTime = AuthorityTime(1_800_000_000_000);

const BUILDER: &str = "https://ci.example.org/builders/fieldseal-simulator";
const SOURCE: &str = "https://git.example.org/authority/artefacts";

/// A whole simulated authority for the device simulator and end-to-end tests: a root, two
/// publishers and a builder certified in a signed trust bundle, a real Merkle transparency
/// log, a publishing policy, an X25519 record key (so the simulator can open what devices
/// seal, as intake would), and a receipt authority. Everything is derived from labels and
/// a seed: the same inputs give the same bytes. **For simulation only.**
pub struct SimulatedAuthority {
    custody: LabelCustody,
    log: crate::publishing::MemoryTransparencyLog<LocalTransport>,
    registry: crate::publishing::MemoryArtefactRegistry,
    builder: KeyId,
    receipt: KeyId,
    publishers: Vec<KeyId>,
    /// The trust bundle devices are provisioned with.
    pub trust: TrustBundle,
    /// The publishing policy.
    pub policy: PublishingPolicy,
    record: RecipientSecret,
    /// The receipt authority.
    pub receipts: ToyReceiptAuthority,
    /// The close-certificate authority.
    pub closes: ToyCloseAuthority,
    salt_counter: AtomicU64,
}

fn certify(root_key: &SigningKey, root: &KeyCertificate, key: &SigningKey, purpose: Purpose, days: u64, serial: u64) -> KeyCertificate {
    let request = CertificateRequest::new(AuthorityPublicKey::P256(key.public_key()), None, &BTreeMap::new())
        .expect("request")
        .signed_by(key)
        .expect("signed request");
    let terms = IssueTerms {
        purpose,
        record: None,
        not_before: SIMULATION_T0,
        not_after: AuthorityTime(SIMULATION_T0.0 + days * AuthorityTime::DAY),
        serial,
    };
    let unsigned = UnsignedCertificate::issue(root, &request, terms).expect("issue");
    let sig = root_key.sign(&tags::KEY_CERTIFICATE, &unsigned.signed_structure()).expect("sign");
    unsigned.finish(sig, &root_key.public_key()).expect("certificate")
}

impl SimulatedAuthority {
    /// An authority derived from `seed`.
    pub fn new(seed: u64) -> Self {
        let root_key = label_key("root");
        let unsigned = UnsignedCertificate::root(root_key.public_key(), SIMULATION_T0, AuthorityTime(SIMULATION_T0.0 + 5 * 365 * AuthorityTime::DAY), 1).expect("root");
        let sig = root_key.sign(&tags::KEY_CERTIFICATE, &unsigned.signed_structure()).expect("sign");
        let root = unsigned.finish(sig, &root_key.public_key()).expect("root certificate");
        let custody = LabelCustody::default();
        let mut certificates = Vec::new();
        let mut publishers = Vec::new();
        for (i, label) in ["publisher-a", "publisher-b"].iter().enumerate() {
            certificates.push(certify(&root_key, &root, &label_key(label), Purpose::Publisher, 700, 10 + i as u64));
            publishers.push(custody.import(KeyRole::Purpose(Purpose::Publisher), label));
        }
        certificates.push(certify(&root_key, &root, &label_key("builder"), Purpose::Builder, 300, 20));
        let builder = custody.import(KeyRole::Purpose(Purpose::Builder), "builder");
        certificates.push(certify(&root_key, &root, &label_key("receipt"), Purpose::Receipt, 300, 21));
        let receipt = custody.import(KeyRole::Purpose(Purpose::Receipt), "receipt");
        let log = crate::publishing::MemoryTransparencyLog::new("log.simulator.example/v1", LocalTransport);
        let contents = TrustBundleContents {
            name: "simulated-authority".into(),
            version: BundleVersion::parse("1.0.0").expect("version"),
            issued: SIMULATION_T0,
            roots: vec![root.clone()],
            certificates,
            publishers: ArtefactKind::ALL.iter().map(|k| (k.as_str().to_owned(), publishers.clone())).collect(),
            attestation_roots: BTreeMap::new(),
            runtime_builds: vec![],
            logs: vec![log.pin()],
            revocations: vec![],
        };
        let unsigned = UnsignedTrustBundle::new(contents).expect("trust bundle");
        let sig = root_key.sign(&tags::TRUST_BUNDLE, &unsigned.signed_structure()).expect("sign");
        let trust = unsigned
            .finish(vec![BundleSignature { signer: fieldseal_kernel::digest::key_id(root_key.public_key().as_bytes()), sig }])
            .expect("signed trust bundle");
        let mut policy = Controls::defaults().publishing();
        policy.allowed_builders = vec![BUILDER.into()];
        policy.allowed_sources = vec![SOURCE.into()];
        let record = RecipientSecret::generate(Suite::Fs1X, &mut SourceRng(&SeededRandom::new(seed ^ 0x5eed)));
        Self {
            custody,
            log,
            registry: crate::publishing::MemoryArtefactRegistry::new(),
            builder,
            receipt,
            publishers,
            trust,
            policy,
            record,
            receipts: ToyReceiptAuthority::new(&seed.to_be_bytes()),
            closes: ToyCloseAuthority::new(&seed.to_be_bytes()),
            salt_counter: AtomicU64::new(seed),
        }
    }

    /// The authority record key's public part (`fs1-x`), which devices seal records to.
    pub fn record_key(&self) -> [u8; 32] {
        match self.record.public().expect("valid key") {
            RecipientKey::X25519(k) => k,
            RecipientKey::P256(_) => unreachable!("an fs1-x key"),
        }
    }

    /// Opens a record payload the way intake does, with the record key.
    pub fn open_payload(&self, sealed: &SealedBox) -> Result<Payload, WireError> {
        Payload::from_value(seal::open_value(&self.record, &tags::RECORD_SEAL, sealed)?)
    }

    /// Opens a sealed export manifest.
    pub fn open_manifest(&self, sealed: &SealedBox) -> Result<Value, WireError> {
        seal::open_value(&self.record, &tags::EXPORT_MANIFEST_SEAL, sealed)
    }

    /// Publishes a document (canonical CBOR of its decoded value) as `kind`, built,
    /// reviewed twice, signed by both publishers and logged.
    pub fn publish(&self, kind: ArtefactKind, name: &str, version: &str, document: &Value) -> Result<Publication, String> {
        let bytes = fieldseal_kernel::cbor::encode(document).map_err(|e| e.to_string())?;
        let salt = (kind == ArtefactKind::Instrument).then(|| {
            let n = self.salt_counter.fetch_add(1, Ordering::SeqCst);
            Salt::from(toy_digest(&[b"salt", &n.to_be_bytes()]))
        });
        let artefact = Artefact::new(kind, name, version, bytes, salt).map_err(|e| e.to_string())?;
        let reviews = crate::publishing::MemoryReviewSystem::new();
        for who in ["reviewer-1", "reviewer-2"] {
            reviews.grant_kind(&ReviewerId::new(who).expect("id"), artefact.kind());
            reviews
                .record(&Review {
                    address: *artefact.address(),
                    revision: RevisionId("rev-1".into()),
                    reviewer: ReviewerId::new(who).expect("id"),
                    decision: ReviewDecision::Approve,
                })
                .map_err(|e| e.to_string())?;
        }
        let input_finished = AuthorityTime(SIMULATION_T0.0 + 10 * AuthorityTime::DAY);
        let input = BuildInput {
            artefact,
            source: SourceRef { uri: SOURCE.into(), revision: RevisionId("rev-1".into()) },
            author: ReviewerId::new("author-1").expect("id"),
            builder: BuilderId(BUILDER.into()),
            definition: fieldseal_kernel::digest::sha256(b"fieldseal.dev/simulator/build/v1"),
            finished: input_finished,
            languages: Vec::new(),
        };
        let draft = BuildProvenance::new(&self.custody, &reviews, &self.policy, self.builder, "simulator").build(input).map_err(|e| e.to_string())?;
        let verifier = VerifyPublication::new(TrustStore::new(&self.trust), &self.policy);
        let signer = SignPublication::new(&self.custody, &verifier, "simulator");
        let mut d = draft;
        for p in &self.publishers {
            d = signer.sign(&d, p).map_err(|e| e.to_string())?;
        }
        // The tree head is dated by a time token from the receipt-and-time key (PUB-072).
        let token = crate::distribution::sign_time_token(&self.custody, &self.receipt, input_finished).map_err(|e| e.to_string())?;
        Publish::new(&self.log, &self.registry, &verifier)
            .with_checkpoint_time(token.encode())
            .publish(&d, &[])
            .map_err(|e| e.to_string())
    }

    /// The registration grant a verified tenancy certificate gives (COL-005).
    pub fn grant(&self, handle_seed: u8) -> RegistrationGrant {
        let key = self.record_key();
        RegistrationGrant {
            certificate: fieldseal_kernel::digest::sha256(&[b"certificate".as_slice(), &[handle_seed]].concat()),
            record_key: key,
            period: fieldseal_kernel::digest::key_id(&key),
            handle: TenancyHandle::from([handle_seed; 16]),
            not_before: SIMULATION_T0,
            not_after: AuthorityTime(SIMULATION_T0.0 + 365 * AuthorityTime::DAY),
            document: None,
        }
    }

    /// Builds a bundle's contents for `tenancy` (what Distribution would seal): publishes the
    /// instrument and each layout (canonicalised to name the instrument's fingerprint,
    /// INS-200), and attaches the rosters, a registration grant if `register`, and a time
    /// token. `issued_day` sets the issue time, in days after [`SIMULATION_T0`].
    pub fn bundle(&self, tenancy: TenancyId, spec: BundleSpec<'_>) -> Result<OpenedBundle, String> {
        let meta = |doc: &Value, key: &str| -> Result<String, String> {
            doc.as_map()
                .and_then(|m| m.get("metadata"))
                .and_then(Value::as_map)
                .and_then(|m| m.get(key))
                .and_then(Value::as_text)
                .map(str::to_owned)
                .ok_or_else(|| format!("document has no metadata.{key}"))
        };
        let instrument = self.publish(ArtefactKind::Instrument, &meta(spec.instrument, "name")?, &meta(spec.instrument, "version")?, spec.instrument)?;
        let fingerprint = instrument.artefact.fingerprint().ok_or("an instrument has a fingerprint")?;
        let mut layouts = Vec::new();
        for l in spec.layouts {
            let mut doc = l.clone();
            if let Some(Value::Map(spec_map)) = doc.as_map().and_then(|m| m.get("spec")).cloned().map(|v| match v {
                Value::Map(mut m) => {
                    m.insert("instrument".into(), Value::Bytes(fingerprint.as_bytes().to_vec()));
                    Value::Map(m)
                }
                other => other,
            }) && let Value::Map(root) = &mut doc
            {
                root.insert("spec".into(), Value::Map(spec_map));
            }
            layouts.push(self.publish(ArtefactKind::Layout, &meta(&doc, "name")?, &meta(&doc, "version")?, &doc)?);
        }
        let issued = AuthorityTime(SIMULATION_T0.0 + spec.issued_day * AuthorityTime::DAY);
        let mut address_input = tenancy.as_bytes().to_vec();
        address_input.extend_from_slice(instrument.address().as_bytes());
        address_input.extend_from_slice(&issued.0.to_be_bytes());
        for r in &spec.rosters {
            address_input.extend_from_slice(r.address.as_bytes());
        }
        let address = fieldseal_kernel::digest::sha256(&address_input);
        let token = fieldseal_kernel::digest::sha256(&[b"time-token".as_slice(), address.as_bytes()].concat());
        Ok(OpenedBundle {
            address,
            tenancy,
            seq: spec.seq,
            issued,
            registration: spec.register.then(|| self.grant(1)),
            time_tokens: vec![TimeAnchor { kind: AnchorKind::TimeToken, address: token, authority_time: AuthorityTime(issued.0 + 60_000) }],
            instrument,
            layouts,
            policy: vec![],
            rosters: spec.rosters,
            withdrawals: vec![],
        })
    }

    /// A verified receipt covering `through` (WIRE-142).
    pub fn receipt(&self, tenancy: TenancyId, through: Seq, hash_at: Digest, time: AuthorityTime) -> ReceiptCoverage {
        ReceiptCoverage::verify(&self.receipts.issue(tenancy, through, hash_at, time), &self.receipts).expect("own receipt verifies")
    }
}

/// What [`SimulatedAuthority::bundle`] puts in a bundle.
pub struct BundleSpec<'a> {
    /// The instrument document (decoded, as authored).
    pub instrument: &'a Value,
    /// Layout documents for it.
    pub layouts: &'a [Value],
    /// The rosters.
    pub rosters: Vec<HeldRoster>,
    /// Whether the bundle carries the tenancy certificate (registers the tenancy).
    pub register: bool,
    /// The issue day, after [`SIMULATION_T0`].
    pub issued_day: u64,
    /// The bundle sequence number.
    pub seq: u64,
}

/// A roster's content address: SHA-256 over its cohort, version and subject IDs.
pub fn roster_address(cohort: &str, version: u64, subjects: &[RosterSubject]) -> Digest {
    let mut b = cohort.as_bytes().to_vec();
    b.extend_from_slice(&version.to_be_bytes());
    for s in subjects {
        b.extend_from_slice(s.subject.as_str().as_bytes());
        b.push(0);
    }
    fieldseal_kernel::digest::sha256(&b)
}

/// The adapters a simulated device runs on, wired together.
pub struct SimulatedDevice {
    /// The key store.
    pub keys: SimulatedKeyStore,
    /// The monotonic clock.
    pub clock: MemoryElapsedClock,
    /// The wall clock.
    pub wall: MemoryWallClock,
    /// Storage, with fault injection.
    pub storage: MemorySecureStorage,
    /// Secure display.
    pub display: MemorySecureDisplay,
    /// Device policy.
    pub device: MemoryDevicePolicy,
    /// The camera.
    pub camera: MemoryCamera,
    /// The PIN hash.
    pub hash: ToyMemoryHardHash,
    /// Randomness.
    pub random: SeededRandom,
    /// The bundle opener.
    pub bundles: MemoryBundleOpener,
}

impl SimulatedDevice {
    /// A fresh device, self-managed with every restriction applied, whose randomness comes
    /// from `seed`.
    pub fn new(seed: u64) -> Self {
        let device = MemoryDevicePolicy::self_managed();
        device.apply(&Restriction::ALL).expect("self-managed");
        Self {
            keys: SimulatedKeyStore::new(seed),
            clock: MemoryElapsedClock::new(),
            wall: MemoryWallClock::at(SIMULATION_T0.0 + 20 * AuthorityTime::DAY),
            storage: MemorySecureStorage::new(),
            display: MemorySecureDisplay::new(),
            device,
            camera: MemoryCamera,
            hash: ToyMemoryHardHash,
            random: SeededRandom::new(seed.wrapping_add(1)),
            bundles: MemoryBundleOpener::new(),
        }
    }

    /// A fresh device whose first signing and agreement keys are the given ones (see
    /// [`SimulatedKeyStore::with_keys`]).
    pub fn with_keys(seed: u64, signing: SigningKey, agreement: [u8; 32]) -> Self {
        let mut d = Self::new(seed);
        d.keys = SimulatedKeyStore::with_keys(seed, signing, agreement);
        d
    }

    /// The device's ports, for [`fieldseal_collection::application::Runtime::load`].
    pub fn platform(&self) -> Platform<'_> {
        Platform {
            keys: &self.keys,
            attestor: &self.keys,
            clock: &self.clock,
            wall: &self.wall,
            storage: &self.storage,
            display: &self.display,
            device: &self.device,
            camera: &self.camera,
            hash: &self.hash,
            random: &self.random,
            bundles: &self.bundles,
        }
    }
}
