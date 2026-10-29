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
use fieldseal_trust::ports::{AuthorityClock, KeyCustody};
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

/// An [`AnchorSource`] that signs the current time of an [`AuthorityClock`] with a `receipt`
/// key held in a [`KeyCustody`]: the factory's anchor, which is always as fresh as its clock.
pub struct ClockAnchorSource<'a> {
    clock: &'a dyn AuthorityClock,
    custody: &'a dyn KeyCustody,
    signer: KeyId,
}

impl<'a> ClockAnchorSource<'a> {
    /// Signs `clock.now()` with `signer`, a receipt key in `custody`.
    pub fn new(clock: &'a dyn AuthorityClock, custody: &'a dyn KeyCustody, signer: KeyId) -> Self {
        Self { clock, custody, signer }
    }
}

impl AnchorSource for ClockAnchorSource<'_> {
    fn time_token(&self) -> Result<TimeToken, AnchorSourceError> {
        sign_time_token(self.custody, &self.signer, self.clock.now())
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
    withheld: Mutex<BTreeMap<TenancyId, Vec<String>>>,
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

    fn withheld(&self, tenancy: &TenancyId) -> Result<Option<Vec<String>>, BundleStoreError> {
        Ok(self.withheld.lock().expect("lock").get(tenancy).cloned())
    }

    fn set_withheld(&self, tenancy: &TenancyId, reasons: Option<&[String]>) -> Result<(), BundleStoreError> {
        let mut all = self.withheld.lock().expect("lock");
        match reasons {
            Some(r) => all.insert(*tenancy, r.to_vec()),
            None => all.remove(tenancy),
        };
        Ok(())
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

    /// Forgets a tenancy's profile, as if its runtime had never reported one.
    pub fn forget(&self, tenancy: &TenancyId) {
        self.profiles.lock().expect("lock").remove(tenancy);
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

#[cfg(test)]
mod tests {
    use fieldseal_trust::domain::TrustStore;

    use super::*;
    use crate::demo::DemoWorld;
    use crate::trust::FixedClock;

    const T0: AuthorityTime = AuthorityTime(1_800_000_000_000);

    #[test]
    fn dis_010_the_clock_anchor_source_signs_the_current_time_of_its_clock() {
        let world = DemoWorld::new(7, T0).expect("world");
        let clock = FixedClock::new(world.now);
        let anchors = ClockAnchorSource::new(&clock, &world.custody, world.receipt);
        let first = anchors.time_token().expect("token");
        assert_eq!(first.authority_time, world.now);
        first.verify(&TrustStore::new(&world.trust)).expect("the token verifies against the trust bundle");
        // Unlike the counter, the source follows its clock and never invents time.
        clock.advance(90_000);
        let second = anchors.time_token().expect("token");
        assert_eq!(second.authority_time, AuthorityTime(world.now.0 + 90_000));
        assert_eq!(anchors.time_token().expect("token").authority_time, second.authority_time);
        second.verify(&TrustStore::new(&world.trust)).expect("the token verifies against the trust bundle");
    }

    #[test]
    fn dis_003_a_withheld_marker_stops_fetch_and_download_until_it_is_cleared() {
        use fieldseal_distribution::application::{BundleDelivery, BundleFetchResponse, DownloadBundle, FetchBundle};
        use fieldseal_distribution::domain::{BundleSeq, DistributionError, RuntimeProfile};
        use crate::demo::DEMO_SCHEMA;

        let world = DemoWorld::new(1, T0).expect("world");
        let device = world
            .register("device-a", &[("cohort-a", 1)], true, RuntimeProfile { instrument_schema: DEMO_SCHEMA, localisation_reference: None })
            .expect("registers");
        let bundle = SealedBundle::new(device.tenancy, BundleSeq(1), T0, b"FSB1 sealed bytes".to_vec());
        world.bundles.put(&bundle).expect("put");
        let delivery = BundleDelivery::new(&world.registry, &world.bundles);
        assert_eq!(delivery.fetch(&device.tenancy, None), Ok(BundleFetchResponse::Bundle(bundle.clone())));
        assert!(delivery.download(&device.device).is_ok());

        let reasons = vec!["policy-hold".to_owned()];
        world.bundles.set_withheld(&device.tenancy, Some(&reasons)).expect("set");
        let refused = Err(DistributionError::Withheld(reasons));
        assert_eq!(delivery.fetch(&device.tenancy, None), refused);
        assert_eq!(delivery.fetch(&device.tenancy, Some(BundleSeq(1))), refused, "a held sequence does not bypass it");
        assert_eq!(delivery.download(&device.device).map(|_| ()), Err(DistributionError::Withheld(vec!["policy-hold".to_owned()])));

        world.bundles.set_withheld(&device.tenancy, None).expect("clear");
        assert_eq!(delivery.fetch(&device.tenancy, None), Ok(BundleFetchResponse::Bundle(bundle)));
        assert!(delivery.download(&device.device).is_ok());
    }

    #[test]
    fn dis_003_a_store_that_cannot_read_the_marker_fails_closed() {
        use fieldseal_distribution::application::{BundleDelivery, FetchBundle};
        use fieldseal_distribution::domain::{BundleSeq, DistributionError, RuntimeProfile};
        use crate::demo::DEMO_SCHEMA;

        struct Broken;
        impl BundleStore for Broken {
            fn put(&self, _: &SealedBundle) -> Result<(), BundleStoreError> {
                Ok(())
            }
            fn latest(&self, t: &TenancyId) -> Result<Option<SealedBundle>, BundleStoreError> {
                Ok(Some(SealedBundle::new(*t, BundleSeq(1), T0, vec![1])))
            }
            fn withheld(&self, _: &TenancyId) -> Result<Option<Vec<String>>, BundleStoreError> {
                Err(BundleStoreError::Backend("disk".into()))
            }
            fn set_withheld(&self, _: &TenancyId, _: Option<&[String]>) -> Result<(), BundleStoreError> {
                Ok(())
            }
        }
        let world = DemoWorld::new(1, T0).expect("world");
        let device = world
            .register("device-a", &[("cohort-a", 1)], true, RuntimeProfile { instrument_schema: DEMO_SCHEMA, localisation_reference: None })
            .expect("registers");
        let r = BundleDelivery::new(&world.registry, &Broken).fetch(&device.tenancy, None);
        assert!(matches!(r, Err(DistributionError::Port { port: "BundleStore", .. })), "{r:?}");
    }
}
