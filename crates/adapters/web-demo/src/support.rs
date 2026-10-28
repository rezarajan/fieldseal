//! Small adapters the demo authority needs: a real-time clock, an operating-system random
//! source, a registry store that remembers which tenancies it has seen, and a live view of
//! the registry for intake.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::Instant;

use fieldseal_adapters_memory::registration::MemoryRegistryStore;
use fieldseal_intake::domain::TenancyView;
use fieldseal_intake::ports::{TenancyRegistry, TenancyRegistryError};
use fieldseal_kernel::crypto::P256PublicKey;
use fieldseal_kernel::id::{Nonce, Seq, TenancyHandle, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_registration::domain::{
    AccessToken, Account, AccountId, DeviceId, IssuedToken, KeyState, RegisteredDevice, TenancyRecord, TenancyState, TokenSecret,
};
use fieldseal_registration::ports::{IssuedNonce, RegistryStore, RegistryStoreError, TokenError};
use fieldseal_trust::domain::DeviceKeyKind;
use fieldseal_trust::ports::{AuthorityClock, RandomSource};

/// Wall-clock authority time: the start time the caller gave plus the time elapsed since.
pub(crate) struct RealClock {
    base_ms: u64,
    started: Instant,
}

impl RealClock {
    pub(crate) fn new(base_ms: u64) -> Self {
        Self { base_ms, started: Instant::now() }
    }
}

impl AuthorityClock for RealClock {
    fn now(&self) -> AuthorityTime {
        AuthorityTime(self.base_ms + u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}

/// The operating system's random source, for token secrets, nonces and session values.
pub(crate) struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("the operating system's random source");
    }
}

/// The world's registry store, remembering every tenancy written through it so the demo can
/// list them (the store port has no listing).
pub(crate) struct TrackingStore {
    pub(crate) inner: &'static MemoryRegistryStore,
    known: Mutex<BTreeSet<TenancyId>>,
}

impl TrackingStore {
    pub(crate) fn new(inner: &'static MemoryRegistryStore) -> Self {
        Self { inner, known: Mutex::default() }
    }

    /// Every tenancy written through the store, in identifier order.
    pub(crate) fn known(&self) -> Vec<TenancyId> {
        self.known.lock().expect("lock").iter().copied().collect()
    }
}

impl RegistryStore for TrackingStore {
    fn put_token(&self, token: &IssuedToken) -> Result<(), RegistryStoreError> {
        self.inner.put_token(token)
    }
    fn token(&self, secret: &TokenSecret) -> Result<Option<(IssuedToken, u32)>, RegistryStoreError> {
        self.inner.token(secret)
    }
    fn consume_token(&self, secret: &TokenSecret, now: AuthorityTime) -> Result<IssuedToken, TokenError> {
        self.inner.consume_token(secret, now)
    }
    fn put_account(&self, account: &Account) -> Result<(), RegistryStoreError> {
        self.inner.put_account(account)
    }
    fn account(&self, id: &AccountId) -> Result<Option<Account>, RegistryStoreError> {
        self.inner.account(id)
    }
    fn put_tenancy(&self, tenancy: &TenancyRecord) -> Result<(), RegistryStoreError> {
        self.inner.put_tenancy(tenancy)?;
        self.known.lock().expect("lock").insert(tenancy.id);
        Ok(())
    }
    fn tenancy(&self, id: &TenancyId) -> Result<Option<TenancyRecord>, RegistryStoreError> {
        self.inner.tenancy(id)
    }
    fn tenancy_by_handle(&self, handle: &TenancyHandle) -> Result<Option<TenancyRecord>, RegistryStoreError> {
        self.inner.tenancy_by_handle(handle)
    }
    fn tenancies_of(&self, account: &AccountId) -> Result<Vec<TenancyRecord>, RegistryStoreError> {
        self.inner.tenancies_of(account)
    }
    fn put_device(&self, device: &RegisteredDevice) -> Result<(), RegistryStoreError> {
        self.inner.put_device(device)
    }
    fn device(&self, id: &DeviceId) -> Result<Option<RegisteredDevice>, RegistryStoreError> {
        self.inner.device(id)
    }
    fn devices_of(&self, account: &AccountId) -> Result<Vec<RegisteredDevice>, RegistryStoreError> {
        self.inner.devices_of(account)
    }
    fn put_nonce(&self, nonce: &IssuedNonce) -> Result<(), RegistryStoreError> {
        self.inner.put_nonce(nonce)
    }
    fn take_nonce(&self, nonce: &Nonce, tenancy: &TenancyId, now: AuthorityTime) -> Result<bool, RegistryStoreError> {
        self.inner.take_nonce(nonce, tenancy, now)
    }
    fn record_jti(&self, tenancy: &TenancyId, jti: &[u8; 16], until: AuthorityTime, now: AuthorityTime) -> Result<bool, RegistryStoreError> {
        self.inner.record_jti(tenancy, jti, until, now)
    }
    fn put_access_token(&self, token: &AccessToken) -> Result<(), RegistryStoreError> {
        self.inner.put_access_token(token)
    }
    fn access_token(&self, value: &[u8; 32]) -> Result<Option<AccessToken>, RegistryStoreError> {
        self.inner.access_token(value)
    }
}

/// Intake's view of the registry: read live from the world's registry store on every
/// lookup, so a device that registers after the demo started is accepted by the upload
/// endpoint, and a tenancy that changes (lost, closed, keys rolled) is seen as changed.
pub struct LiveRegistry {
    store: &'static MemoryRegistryStore,
}

impl LiveRegistry {
    pub(crate) fn new(store: &'static MemoryRegistryStore) -> Self {
        Self { store }
    }
}

/// What intake is told about a registry record, or `None` while the tenancy has not
/// registered (pending, held or rejected requests are not tenancies yet).
pub(crate) fn view_of(record: &TenancyRecord) -> Option<TenancyView> {
    if matches!(record.state, TenancyState::Pending | TenancyState::Held | TenancyState::Rejected) {
        return None;
    }
    let mut signing: Vec<(u64, &P256PublicKey, KeyState)> =
        record.keys.iter().filter(|k| k.kind == DeviceKeyKind::Signing).map(|k| (u64::from(k.index), &k.public_key, k.state)).collect();
    signing.sort_by_key(|(i, _, _)| *i);
    let mut view = TenancyView::new(record.id, record.handle, signing.iter().map(|(_, k, _)| (*k).clone()).collect());
    let revoked_from: BTreeMap<u64, Seq> =
        signing.iter().enumerate().filter(|(_, (_, _, s))| *s == KeyState::Revoked).map(|(pos, _)| (pos as u64, record.cutoff.unwrap_or(Seq(0)))).collect();
    view.key_revoked_from = revoked_from;
    view.cutoff = record.cutoff;
    view.deny_listed = record.state == TenancyState::Lost;
    Some(view)
}

impl TenancyRegistry for LiveRegistry {
    fn by_handle(&self, handle: &TenancyHandle) -> Result<Option<TenancyView>, TenancyRegistryError> {
        let record = self.store.tenancy_by_handle(handle).map_err(|e| TenancyRegistryError::Unavailable(e.to_string()))?;
        Ok(record.as_ref().and_then(view_of))
    }

    fn by_id(&self, id: &TenancyId) -> Result<Option<TenancyView>, TenancyRegistryError> {
        let record = self.store.tenancy(id).map_err(|e| TenancyRegistryError::Unavailable(e.to_string()))?;
        Ok(record.as_ref().and_then(view_of))
    }
}
