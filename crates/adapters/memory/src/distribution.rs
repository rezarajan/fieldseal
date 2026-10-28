//! In-memory adapters for the Distribution context's driven ports.
//!
//! The roster, bundle and profile stores keep what they are given. [`MemoryAnchorSource`]
//! signs real time tokens through a `KeyCustody`, and [`SoftwareAgreementKey`] opens real
//! HPKE seals with a software key: both are the wire formats, not stand-ins, but their keys
//! sit in process memory, not behind a hardware boundary.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use fieldseal_distribution::domain::{Roster, RuntimeProfile, SealedBundle, TimeToken};
use fieldseal_distribution::ports::{
    AgreementError, AgreementKey, AnchorSource, AnchorSourceError, BundleStore, BundleStoreError, ProfileError, RosterSource,
    RosterSourceError, RuntimeProfiles, TrustStore, TrustStoreError,
};
use fieldseal_kernel::crypto::{DomainTag, Purpose, tags};
use fieldseal_kernel::id::{CohortId, KeyId, TenancyId};
use fieldseal_kernel::seal::{RecipientSecret, SealedBox, open_with_context};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_trust::domain::{KeyRole, TrustBundle};
use fieldseal_trust::ports::KeyCustody;
use zeroize::Zeroizing;

/// In-memory [`RosterSource`]: rosters set by the test, per tenancy.
#[derive(Default)]
pub struct MemoryRosterSource {
    rosters: Mutex<BTreeMap<TenancyId, Vec<Roster>>>,
}

impl MemoryRosterSource {
    /// No assignments.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a tenancy's rosters. Versions must not go down; a source that went back would
    /// break the contract, so this refuses to.
    pub fn assign(&self, tenancy: TenancyId, rosters: Vec<Roster>) {
        let mut all = self.rosters.lock().expect("lock");
        if let Some(held) = all.get(&tenancy) {
            for r in &rosters {
                if let Some(h) = held.iter().find(|h| h.cohort == r.cohort) {
                    h.may_be_followed_by(r).expect("roster versions never decrease");
                }
            }
        }
        all.insert(tenancy, rosters);
    }
}

impl RosterSource for MemoryRosterSource {
    fn current_rosters(&self, tenancy: &TenancyId) -> Result<Vec<Roster>, RosterSourceError> {
        self.rosters.lock().expect("lock").get(tenancy).cloned().ok_or(RosterSourceError::UnknownTenancy)
    }

    fn active_tenancies(&self, cohort: &CohortId, except: &TenancyId) -> Result<u64, RosterSourceError> {
        let all = self.rosters.lock().expect("lock");
        Ok(all.iter().filter(|(t, rs)| *t != except && rs.iter().any(|r| &r.cohort == cohort)).count() as u64)
    }
}

/// An [`AnchorSource`] that signs a real time token a second after the last, with a `receipt`
/// key held in a [`KeyCustody`].
pub struct MemoryAnchorSource<'a> {
    next: AtomicU64,
    custody: &'a dyn KeyCustody,
    signer: KeyId,
}

impl<'a> MemoryAnchorSource<'a> {
    /// Starts at `start`, signing with `signer`, a receipt key in `custody`.
    pub fn new(start: AuthorityTime, custody: &'a dyn KeyCustody, signer: KeyId) -> Self {
        Self { next: AtomicU64::new(start.0), custody, signer }
    }
}

impl AnchorSource for MemoryAnchorSource<'_> {
    fn time_token(&self) -> Result<TimeToken, AnchorSourceError> {
        let t = self.next.fetch_add(AuthorityTime::SECOND, Ordering::SeqCst);
        sign_time_token(self.custody, &self.signer, AuthorityTime(t))
    }
}

/// Signs a time token stating `at` with the `receipt` key `signer` held in `custody`. Used
/// for anchors and for the token that accompanies a log checkpoint (PUB-072).
pub fn sign_time_token(custody: &dyn KeyCustody, signer: &KeyId, at: AuthorityTime) -> Result<TimeToken, AnchorSourceError> {
    let mut token = TimeToken { authority_time: at, nonce: None, signer: *signer, signature: fieldseal_kernel::crypto::Signature(vec![]) };
    token.signature = custody
        .sign(signer, KeyRole::Purpose(Purpose::Receipt), &tags::TIME_TOKEN, &token.signed_structure(), "memory-anchor-source")
        .map_err(|e| AnchorSourceError::Unavailable(e.to_string()))?;
    Ok(token)
}

/// In-memory [`TrustStore`], provisioned with an initial trust bundle.
pub struct MemoryTrustStore {
    current: Mutex<TrustBundle>,
}

impl MemoryTrustStore {
    /// Provisioned with `initial`.
    pub fn new(initial: TrustBundle) -> Self {
        Self { current: Mutex::new(initial) }
    }
}

impl TrustStore for MemoryTrustStore {
    fn current(&self) -> Result<TrustBundle, TrustStoreError> {
        Ok(self.current.lock().expect("lock").clone())
    }

    fn replace(&self, next: TrustBundle) -> Result<(), TrustStoreError> {
        let mut current = self.current.lock().expect("lock");
        current.check_update(&next).map_err(|e| TrustStoreError::NotAcceptable(e.to_string()))?;
        *current = next;
        Ok(())
    }
}

/// In-memory [`BundleStore`].
#[derive(Default)]
pub struct MemoryBundleStore {
    bundles: Mutex<BTreeMap<TenancyId, SealedBundle>>,
}

impl MemoryBundleStore {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }
}

impl BundleStore for MemoryBundleStore {
    fn put(&self, bundle: &SealedBundle) -> Result<(), BundleStoreError> {
        let mut bundles = self.bundles.lock().expect("lock");
        if let Some(held) = bundles.get(&bundle.tenancy)
            && bundle.seq <= held.seq
        {
            return Err(BundleStoreError::NotNewer { held: held.seq, offered: bundle.seq });
        }
        bundles.insert(bundle.tenancy, bundle.clone());
        Ok(())
    }

    fn latest(&self, tenancy: &TenancyId) -> Result<Option<SealedBundle>, BundleStoreError> {
        Ok(self.bundles.lock().expect("lock").get(tenancy).cloned())
    }
}

/// An [`AgreementKey`] holding a software key. For tests and the CLI simulator: a platform
/// key store keeps the private key inside the hardware boundary.
pub struct SoftwareAgreementKey {
    secret: RecipientSecret,
    id: KeyId,
}

impl SoftwareAgreementKey {
    /// Wraps `secret`, which must be a valid private key.
    pub fn new(secret: RecipientSecret) -> Result<Self, fieldseal_kernel::KernelError> {
        let id = secret.public()?.key_id();
        Ok(Self { secret, id })
    }
}

impl AgreementKey for SoftwareAgreementKey {
    fn key_id(&self) -> KeyId {
        self.id
    }

    fn open(&self, tag: &DomainTag, context: &[u8], sealed: &SealedBox) -> Result<Zeroizing<Vec<u8>>, AgreementError> {
        if sealed.recipient != self.id {
            return Err(AgreementError::WrongRecipient);
        }
        open_with_context(&self.secret, tag, context, sealed).map_err(AgreementError::Open)
    }
}

/// In-memory [`RuntimeProfiles`]: what each tenancy's runtime reported, set by the caller.
#[derive(Default)]
pub struct MemoryRuntimeProfiles {
    profiles: Mutex<BTreeMap<TenancyId, RuntimeProfile>>,
}

impl MemoryRuntimeProfiles {
    /// No profiles.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a tenancy's profile.
    pub fn record(&self, tenancy: TenancyId, profile: RuntimeProfile) {
        self.profiles.lock().expect("lock").insert(tenancy, profile);
    }
}

impl RuntimeProfiles for MemoryRuntimeProfiles {
    fn profile(&self, tenancy: &TenancyId) -> Result<Option<RuntimeProfile>, ProfileError> {
        Ok(self.profiles.lock().expect("lock").get(tenancy).cloned())
    }
}
