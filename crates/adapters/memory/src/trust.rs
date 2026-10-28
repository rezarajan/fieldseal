//! In-memory adapters for the Trust context's driven ports.
//!
//! [`MemoryKeyCustody`] holds real software keys (P-256 and X25519, through the kernel),
//! generated from an injected [`RandomSource`]: its signatures and seals are the real wire
//! formats, but its keys sit in process memory, not behind a hardware boundary.
//!
//! **Not cryptography:** the device key store's "signatures", "public keys", wrapping and
//! "attestation" are deterministic stand-ins built from a non-cryptographic hash, and
//! [`SeededRandom`] is not random, so tests and the CLI simulator can run without hardware.
//! Everything the device store produces is marked unattested ([`SecurityLevel::Software`],
//! evidence format [`SOFTWARE_EVIDENCE_FORMAT`]); production factory policy refuses it
//! (TRU-061).

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hasher};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use fieldseal_kernel::Value;
use fieldseal_kernel::crypto::{DomainTag, P256PublicKey, Purpose, Signature};
use fieldseal_kernel::id::{KeyId, Nonce, ReviewerId};
use fieldseal_kernel::seal::{self, RecipientKey, RecipientSecret, SealedBox, Suite};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_kernel::time::AuthorityTime;
pub use fieldseal_trust::application::SOFTWARE_EVIDENCE_FORMAT;
use fieldseal_trust::domain::{
    AccessContext, AttestationClaims, AttestationEvidence, AuthorityPublicKey, BootState,
    CustodyKey, DeviceKeyKind, KeyAlgorithm, KeyHandle, KeyOperation, KeyProtection, KeyRole,
    KeyUse, PersonRef, HoldingBounds, KeyHolding, RevocationStatus, SecurityLevel, may_open, may_sign,
};
use fieldseal_trust::ports::{
    AttestationVerifier, Attestor, AttestorError, AuthorityClock, CustodyError,
    HolderRegistryError, KeyCustody, KeyHolderRegistry, KeyStoreError, RandomSource,
    RevocationSource, RevocationSourceError, SecureKeyStore, SourceRng, VerificationError,
};
use zeroize::Zeroizing;

/// A deterministic, **non-cryptographic** 32-byte digest, for in-memory adapters only.
pub fn toy_digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let mut h = DefaultHasher::new();
        h.write_u8(i as u8);
        for p in parts {
            h.write_usize(p.len());
            h.write(p);
        }
        chunk.copy_from_slice(&h.finish().to_be_bytes());
    }
    out
}

/// A stand-in P-256 public key derived from a secret.
fn toy_public_key(secret: &[u8; 32]) -> P256PublicKey {
    // A real curve point (WIRE-009 keys must lie on P-256): the public key of a scalar derived
    // from the secret. The toy digest is below the group order with overwhelming probability.
    let scalar = toy_digest(&[b"pub", secret]);
    fieldseal_kernel::sign::SigningKey::from_scalar(&scalar).expect("a valid P-256 scalar").public_key()
}

enum CustodySecret {
    P256(SigningKey),
    X25519(RecipientSecret),
}

struct CustodyEntry {
    key: CustodyKey,
    secret: CustodySecret,
}

/// In-memory [`KeyCustody`] with real software keys drawn from an injected
/// [`RandomSource`]. Private keys never leave it: the port has no export, and the keys are
/// zeroised when the custody is dropped. **Not a hardware boundary**: for tests, the CLI
/// simulator and practice ceremonies only.
pub struct MemoryKeyCustody<R: RandomSource = SeededRandom> {
    random: R,
    keys: Mutex<BTreeMap<KeyId, CustodyEntry>>,
    log: Mutex<Vec<KeyUse>>,
}

impl<R: RandomSource> MemoryKeyCustody<R> {
    /// Empty custody whose keys are generated from `random`.
    pub fn new(random: R) -> Self {
        Self { random, keys: Mutex::default(), log: Mutex::default() }
    }

    fn record(&self, key: &KeyId, role: KeyRole, operation: KeyOperation, caller: &str) {
        self.log.lock().expect("lock").push(KeyUse { key: *key, role, operation, caller: caller.into() });
    }
}

impl<R: RandomSource> KeyCustody for MemoryKeyCustody<R> {
    fn generate(&self, role: KeyRole, algorithm: KeyAlgorithm) -> Result<CustodyKey, CustodyError> {
        if !role.allows(algorithm) {
            return Err(CustodyError::Unsupported);
        }
        let mut rng = SourceRng(&self.random);
        let (public_key, secret) = match algorithm {
            KeyAlgorithm::P256 => {
                let sk = SigningKey::generate(&mut rng);
                (AuthorityPublicKey::P256(sk.public_key()), CustodySecret::P256(sk))
            }
            KeyAlgorithm::X25519 => {
                let sk = RecipientSecret::generate(Suite::Fs1X, &mut rng);
                let RecipientKey::X25519(public) = sk.public().map_err(|e| CustodyError::Backend(e.to_string()))? else {
                    return Err(CustodyError::Backend("X25519 key with a P-256 public key".into()));
                };
                (AuthorityPublicKey::X25519(public), CustodySecret::X25519(sk))
            }
        };
        let key = CustodyKey { id: public_key.key_id(), public_key, role };
        self.keys.lock().expect("lock").insert(key.id, CustodyEntry { key: key.clone(), secret });
        Ok(key)
    }

    fn sign(
        &self,
        key: &KeyId,
        role: KeyRole,
        tag: &DomainTag,
        structure: &Value,
        caller: &str,
    ) -> Result<Signature, CustodyError> {
        let keys = self.keys.lock().expect("lock");
        let entry = keys.get(key).ok_or(CustodyError::UnknownKey)?;
        if entry.key.role != role {
            return Err(CustodyError::WrongPurpose { held: entry.key.role, requested: role });
        }
        if !may_sign(role, tag) {
            return Err(CustodyError::TagNotAllowed { role, tag: tag.as_str() });
        }
        let CustodySecret::P256(sk) = &entry.secret else {
            return Err(CustodyError::Unsupported);
        };
        let sig = sk.sign(tag, structure).map_err(|e| CustodyError::Backend(e.to_string()))?;
        self.record(key, role, KeyOperation::Sign, caller);
        Ok(sig)
    }

    fn open(
        &self,
        key: &KeyId,
        purpose: Purpose,
        tag: &DomainTag,
        sealed: &SealedBox,
        caller: &str,
    ) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
        let keys = self.keys.lock().expect("lock");
        let entry = keys.get(key).ok_or(CustodyError::UnknownKey)?;
        let role = KeyRole::Purpose(purpose);
        if entry.key.role != role {
            return Err(CustodyError::WrongPurpose { held: entry.key.role, requested: role });
        }
        if !may_open(purpose, tag) {
            return Err(CustodyError::TagNotAllowed { role, tag: tag.as_str() });
        }
        let CustodySecret::X25519(sk) = &entry.secret else {
            return Err(CustodyError::Unsupported);
        };
        self.record(key, role, KeyOperation::Open, caller);
        seal::open(sk, tag, sealed).map_err(CustodyError::Open)
    }

    fn public_key(&self, key: &KeyId) -> Result<CustodyKey, CustodyError> {
        self.keys.lock().expect("lock").get(key).map(|e| e.key.clone()).ok_or(CustodyError::UnknownKey)
    }

    fn usage_log(&self) -> Vec<KeyUse> {
        self.log.lock().expect("lock").clone()
    }
}


struct DeviceEntry {
    kind: DeviceKeyKind,
    protection: KeyProtection,
    secret: [u8; 32],
    public: Option<P256PublicKey>,
    challenge: Nonce,
}

/// In-memory [`SecureKeyStore`] and [`Attestor`]: a software key store whose keys are
/// unattested. Key agreement works between keys of the same store.
#[derive(Default)]
pub struct MemorySecureKeyStore {
    keys: Mutex<BTreeMap<String, DeviceEntry>>,
    counter: AtomicU64,
    locked: std::sync::atomic::AtomicBool,
}

impl MemorySecureKeyStore {
    /// An empty, unlocked store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulates locking or unlocking the device.
    pub fn set_locked(&self, locked: bool) {
        self.locked.store(locked, Ordering::SeqCst);
    }

    fn with_key<T>(
        &self,
        handle: &KeyHandle,
        kind: DeviceKeyKind,
        f: impl FnOnce(&DeviceEntry) -> Result<T, KeyStoreError>,
    ) -> Result<T, KeyStoreError> {
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
        (0..len.div_ceil(32))
            .flat_map(|i| toy_digest(&[b"stream", secret, &(i as u64).to_be_bytes()]))
            .take(len)
            .collect()
    }
}

impl SecureKeyStore for MemorySecureKeyStore {
    fn generate(
        &self,
        kind: DeviceKeyKind,
        protection: KeyProtection,
        challenge: Option<Nonce>,
    ) -> Result<(KeyHandle, Option<P256PublicKey>), KeyStoreError> {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        let secret = toy_digest(&[b"device", &n.to_be_bytes()]);
        let public = (kind != DeviceKeyKind::Wrapping).then(|| toy_public_key(&secret));
        let handle = KeyHandle(format!("mem-key-{n}"));
        let entry = DeviceEntry {
            kind,
            protection,
            secret,
            public: public.clone(),
            challenge: challenge.unwrap_or(Nonce::from([0; 32])),
        };
        self.keys
            .lock()
            .expect("lock")
            .insert(handle.0.clone(), entry);
        Ok((handle, public))
    }

    fn sign(&self, key: &KeyHandle, message: &[u8]) -> Result<Signature, KeyStoreError> {
        self.with_key(key, DeviceKeyKind::Signing, |e| {
            Ok(Signature(toy_digest(&[&e.secret, message]).to_vec()))
        })
    }

    fn agree(&self, key: &KeyHandle, peer: &P256PublicKey) -> Result<Vec<u8>, KeyStoreError> {
        self.with_key(key, DeviceKeyKind::Agreement, |e| {
            let own = e.public.as_ref().expect("agreement keys have a public key");
            let (a, b) = if own.as_bytes()[..] <= peer.as_bytes()[..] {
                (own, peer)
            } else {
                (peer, own)
            };
            Ok(toy_digest(&[b"agree", a.as_bytes(), b.as_bytes()]).to_vec())
        })
    }

    fn wrap(&self, key: &KeyHandle, data: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        self.with_key(key, DeviceKeyKind::Wrapping, |e| {
            let mut out = toy_digest(&[b"tag", &e.secret, data])[..8].to_vec();
            out.extend(
                data.iter()
                    .zip(Self::keystream(&e.secret, data.len()))
                    .map(|(d, k)| d ^ k),
            );
            Ok(out)
        })
    }

    fn unwrap(&self, key: &KeyHandle, wrapped: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        self.with_key(key, DeviceKeyKind::Wrapping, |e| {
            let (tag, body) = wrapped.split_at_checked(8).ok_or(KeyStoreError::Unwrap)?;
            let data: Vec<u8> = body
                .iter()
                .zip(Self::keystream(&e.secret, body.len()))
                .map(|(d, k)| d ^ k)
                .collect();
            if tag != &toy_digest(&[b"tag", &e.secret, &data])[..8] {
                return Err(KeyStoreError::Unwrap);
            }
            Ok(data)
        })
    }

    fn delete(&self, key: &KeyHandle) -> Result<(), KeyStoreError> {
        self.keys
            .lock()
            .expect("lock")
            .remove(&key.0)
            .map(|_| ())
            .ok_or(KeyStoreError::UnknownKey)
    }

    fn exists(&self, key: &KeyHandle) -> bool {
        self.keys.lock().expect("lock").contains_key(&key.0)
    }
}

impl Attestor for MemorySecureKeyStore {
    fn evidence(&self, key: &KeyHandle) -> Result<AttestationEvidence, AttestorError> {
        let keys = self.keys.lock().expect("lock");
        let entry = keys.get(&key.0).ok_or(AttestorError::UnknownKey)?;
        let public = entry
            .public
            .as_ref()
            .ok_or_else(|| AttestorError::Unavailable("wrapping keys have no public key".into()))?;
        let kind = match entry.kind {
            DeviceKeyKind::Signing => 0u8,
            DeviceKeyKind::Agreement => 1,
            DeviceKeyKind::Wrapping => 2,
        };
        let mut data = vec![kind, entry.protection.unlocked_required as u8];
        data.extend_from_slice(entry.challenge.as_bytes());
        data.extend_from_slice(public.as_bytes());
        let check = toy_digest(&[b"evidence", &data]);
        data.extend_from_slice(&check[..8]);
        Ok(AttestationEvidence {
            format: SOFTWARE_EVIDENCE_FORMAT.into(),
            data,
        })
    }
}

/// [`AttestationVerifier`] for [`SOFTWARE_EVIDENCE_FORMAT`]. Its claims always carry
/// [`SecurityLevel::Software`]: verified, but unattested.
#[derive(Default)]
pub struct SoftwareAttestationVerifier;

impl AttestationVerifier for SoftwareAttestationVerifier {
    fn format(&self) -> &str {
        SOFTWARE_EVIDENCE_FORMAT
    }

    fn verify(
        &self,
        evidence: &AttestationEvidence,
        expected_challenge: &Nonce,
        key: &P256PublicKey,
        _roots: &[Vec<u8>],
    ) -> Result<AttestationClaims, VerificationError> {
        // Software evidence has no attestation roots (TRU §6.2): there is no chain to check.
        if evidence.format != SOFTWARE_EVIDENCE_FORMAT {
            return Err(VerificationError::UnsupportedFormat(
                evidence.format.clone(),
            ));
        }
        let d = &evidence.data;
        if d.len() != 2 + 32 + 65 + 8 {
            return Err(VerificationError::Invalid("length".into()));
        }
        let (body, check) = d.split_at(d.len() - 8);
        if check != &toy_digest(&[b"evidence", body])[..8] {
            return Err(VerificationError::Invalid("checksum".into()));
        }
        if &body[2..34] != expected_challenge.as_bytes() {
            return Err(VerificationError::ChallengeMismatch);
        }
        if &body[34..] != key.as_bytes() {
            return Err(VerificationError::KeyMismatch);
        }
        let kind = match body[0] {
            0 => DeviceKeyKind::Signing,
            1 => DeviceKeyKind::Agreement,
            _ => return Err(VerificationError::Invalid("kind".into())),
        };
        Ok(AttestationClaims {
            security_level: SecurityLevel::Software,
            origin_generated: true,
            kind,
            unlocked_required: Some(body[1] == 1),
            challenge: *expected_challenge,
            app_id: Some("fieldseal-simulator".to_owned()),
            app_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            os_patch_level: None,
            boot_state: Some(BootState::Unverified),
            bootloader_locked: Some(false),
            device_serial: None,
        })
    }
}

/// In-memory [`RevocationSource`] with a fixed retrieval time.
pub struct MemoryRevocationSource {
    revoked: Mutex<BTreeSet<Vec<u8>>>,
    retrieved_at: AuthorityTime,
}

impl MemoryRevocationSource {
    /// A source reporting `retrieved_at` and nothing revoked.
    pub fn new(retrieved_at: AuthorityTime) -> Self {
        Self {
            revoked: Mutex::default(),
            retrieved_at,
        }
    }

    /// Marks a certificate as revoked.
    pub fn revoke(&self, certificate_id: &[u8]) {
        self.revoked
            .lock()
            .expect("lock")
            .insert(certificate_id.to_vec());
    }
}

impl RevocationSource for MemoryRevocationSource {
    fn status(&self, certificate_id: &[u8]) -> Result<RevocationStatus, RevocationSourceError> {
        Ok(RevocationStatus {
            revoked: self.revoked.lock().expect("lock").contains(certificate_id),
            retrieved_at: self.retrieved_at,
        })
    }
}

/// A settable [`AuthorityClock`].
pub struct FixedClock(AtomicU64);

impl FixedClock {
    /// A clock reading `start`.
    pub fn new(start: AuthorityTime) -> Self {
        Self(AtomicU64::new(start.0))
    }

    /// Moves time forward by `seconds`.
    pub fn advance(&self, seconds: u64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl AuthorityClock for FixedClock {
    fn now(&self) -> AuthorityTime {
        AuthorityTime(self.0.load(Ordering::SeqCst))
    }
}

/// A seeded, deterministic [`RandomSource`]. **Not random**: for tests and simulation only.
pub struct SeededRandom {
    seed: u64,
    counter: AtomicU64,
}

impl SeededRandom {
    /// A source producing the same sequence for the same seed.
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            counter: AtomicU64::new(0),
        }
    }
}

impl RandomSource for SeededRandom {
    fn fill(&self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(32) {
            let n = self.counter.fetch_add(1, Ordering::SeqCst);
            let block = toy_digest(&[&self.seed.to_be_bytes(), &n.to_be_bytes()]);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}

/// In-memory [`KeyHolderRegistry`].
#[derive(Default)]
pub struct MemoryKeyHolderRegistry {
    keys: Mutex<BTreeMap<KeyId, (PersonRef, HoldingBounds)>>,
    reviewers: Mutex<BTreeMap<ReviewerId, PersonRef>>,
}

impl MemoryKeyHolderRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }
}

fn authorise(ctx: &AccessContext) -> Result<(), HolderRegistryError> {
    if ctx.may_resolve_holders {
        Ok(())
    } else {
        Err(HolderRegistryError::Denied)
    }
}

impl KeyHolderRegistry for MemoryKeyHolderRegistry {
    fn register_key_holder(
        &self,
        key: &KeyId,
        holder: PersonRef,
        bounds: HoldingBounds,
        ctx: &AccessContext,
    ) -> Result<(), HolderRegistryError> {
        authorise(ctx)?;
        if let (Some(start), Some(end)) = (bounds.not_before, bounds.not_after)
            && end <= start
        {
            return Err(HolderRegistryError::InvalidBounds);
        }
        let mut keys = self.keys.lock().expect("lock");
        if keys.contains_key(key) {
            return Err(HolderRegistryError::AlreadyRegistered);
        }
        keys.insert(*key, (holder, bounds));
        Ok(())
    }

    fn register_reviewer(
        &self,
        reviewer: &ReviewerId,
        person: PersonRef,
        ctx: &AccessContext,
    ) -> Result<(), HolderRegistryError> {
        authorise(ctx)?;
        let mut reviewers = self.reviewers.lock().expect("lock");
        if reviewers.contains_key(reviewer) {
            return Err(HolderRegistryError::AlreadyRegistered);
        }
        reviewers.insert(reviewer.clone(), person);
        Ok(())
    }

    fn key_holder(
        &self,
        key: &KeyId,
        at: AuthorityTime,
        ctx: &AccessContext,
    ) -> Result<PersonRef, HolderRegistryError> {
        authorise(ctx)?;
        match self.keys.lock().expect("lock").get(key) {
            Some((holder, bounds)) if bounds.covers(at) => Ok(holder.clone()),
            _ => Err(HolderRegistryError::NotFound),
        }
    }

    fn holder_keys(
        &self,
        holder: &PersonRef,
        ctx: &AccessContext,
    ) -> Result<Vec<KeyHolding>, HolderRegistryError> {
        authorise(ctx)?;
        Ok(self
            .keys
            .lock()
            .expect("lock")
            .iter()
            .filter(|(_, (h, _))| h == holder)
            .map(|(key, (h, bounds))| KeyHolding { key: *key, holder: h.clone(), bounds: *bounds })
            .collect())
    }

    fn end_holding(
        &self,
        key: &KeyId,
        at: AuthorityTime,
        ctx: &AccessContext,
    ) -> Result<(), HolderRegistryError> {
        authorise(ctx)?;
        let mut keys = self.keys.lock().expect("lock");
        match keys.get_mut(key) {
            Some((_, bounds)) if bounds.not_after.is_none_or(|end| at < end) => {
                bounds.not_after = Some(at);
                Ok(())
            }
            _ => Err(HolderRegistryError::NotFound),
        }
    }

    fn reviewer(
        &self,
        reviewer: &ReviewerId,
        ctx: &AccessContext,
    ) -> Result<PersonRef, HolderRegistryError> {
        authorise(ctx)?;
        self.reviewers
            .lock()
            .expect("lock")
            .get(reviewer)
            .cloned()
            .ok_or(HolderRegistryError::NotFound)
    }
}
