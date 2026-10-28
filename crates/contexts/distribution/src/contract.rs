//! Contract tests for adapters of the Distribution context's driven ports.

use fieldseal_kernel::crypto::{DomainTag, tags};
use fieldseal_kernel::id::{ContentAddress, TenancyId};
use fieldseal_kernel::seal::{RecipientKey, SealedBox};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_trust::domain::TrustBundle;

use crate::domain::{BundleSeq, RuntimeProfile, SealedBundle, TimeToken};
use crate::ports::{
    AgreementError, AgreementKey, AnchorSource, BundleStore, BundleStoreError, RosterSource, RosterSourceError, RuntimeProfiles, TrustStore,
    TrustStoreError,
};

/// A sealed-bundle fixture.
pub fn sample_bundle(tenancy: u8, seq: u64) -> SealedBundle {
    SealedBundle {
        address: ContentAddress::from([seq as u8; 32]),
        tenancy: TenancyId::from([tenancy; 32]),
        seq: BundleSeq(seq),
        issued: AuthorityTime(1_800_000_000_000 + seq),
        bytes: vec![b'F', b'S', b'B', b'1', tenancy, seq as u8, 0xaa],
    }
}

/// [`RosterSource`]: for every cohort of `tenancy`, versions never decrease between calls;
/// an unknown tenancy is an error; active-tenancy counts are answered for assigned cohorts.
pub fn roster_source_contract<S: RosterSource>(make: impl Fn() -> S, tenancy: TenancyId) {
    let source = make();
    let first = source.current_rosters(&tenancy).expect("rosters");
    assert!(!first.is_empty(), "the fixture tenancy must have cohorts");
    let second = source.current_rosters(&tenancy).expect("rosters again");
    for a in &first {
        if let Some(b) = second.iter().find(|b| b.cohort == a.cohort) {
            a.may_be_followed_by(b).expect("roster versions never decrease");
        }
        let others = source.active_tenancies(&a.cohort, &tenancy).expect("a count for an assigned cohort");
        let all = source.active_tenancies(&a.cohort, &TenancyId::from([0xdd; 32])).expect("a count");
        assert_eq!(all, others + 1, "the tenancy being released is not counted among the others");
    }
    assert_eq!(
        source.current_rosters(&TenancyId::from([0xee; 32])),
        Err(RosterSourceError::UnknownTenancy),
        "an unknown tenancy has no rosters"
    );
}

/// [`AnchorSource`]: time tokens never go back in authority time and each is accepted by
/// `verifies` (the test's check against its trust bundle).
pub fn anchor_source_contract<S: AnchorSource>(make: impl Fn() -> S, verifies: impl Fn(&TimeToken) -> bool) {
    let source = make();
    let a = source.time_token().expect("time token");
    let b = source.time_token().expect("time token");
    assert!(b.authority_time >= a.authority_time, "time tokens never go back in time");
    assert!(verifies(&a) && verifies(&b), "time tokens verify against the trust bundle");
}

/// [`TrustStore`]: only a valid successor replaces the held trust bundle. `newer` must be a
/// valid successor of `held` (TRU-033) and `older` must not be.
pub fn trust_store_contract<S: TrustStore>(make: impl Fn(TrustBundle) -> S, held: TrustBundle, newer: TrustBundle, older: TrustBundle) {
    let store = make(held.clone());
    assert_eq!(store.current(), Ok(held.clone()));
    assert!(matches!(store.replace(held.clone()), Err(TrustStoreError::NotAcceptable(_))), "the same version is not newer");
    assert!(matches!(store.replace(older), Err(TrustStoreError::NotAcceptable(_))), "a trust bundle can't be rolled back");
    assert_eq!(store.current(), Ok(held), "a refused replacement changes nothing");
    store.replace(newer.clone()).expect("a valid successor is accepted");
    assert_eq!(store.current(), Ok(newer));
}

/// [`BundleStore`]: bytes unchanged, newer only, latest by sequence number.
pub fn bundle_store_contract<S: BundleStore>(make: impl Fn() -> S) {
    let store = make();
    let t = TenancyId::from([1; 32]);
    assert_eq!(store.latest(&t), Ok(None));
    store.put(&sample_bundle(1, 1)).expect("first");
    store.put(&sample_bundle(1, 2)).expect("newer");
    assert_eq!(store.latest(&t), Ok(Some(sample_bundle(1, 2))), "stored unchanged, latest wins");
    assert_eq!(
        store.put(&sample_bundle(1, 2)),
        Err(BundleStoreError::NotNewer { held: BundleSeq(2), offered: BundleSeq(2) })
    );
    assert!(store.put(&sample_bundle(1, 1)).is_err(), "older bundles are refused");
    store.put(&sample_bundle(2, 1)).expect("other tenancies are independent");
}

/// [`AgreementKey`]: opens a seal addressed to it under the tag and context it was sealed
/// with, and nothing else. `make` returns the key and its public key; `seal` is the kernel's
/// `seal_with_context` with the test's randomness.
pub fn agreement_key_contract<K: AgreementKey>(
    make: impl Fn() -> (K, RecipientKey),
    other: RecipientKey,
    seal: impl Fn(&RecipientKey, &DomainTag, &[u8], &[u8]) -> SealedBox,
) {
    let (key, public) = make();
    assert_eq!(key.key_id(), public.key_id());
    let sealed = seal(&public, &tags::BUNDLE_SEAL, b"tenancy-a", b"secret contents");
    assert_eq!(key.open(&tags::BUNDLE_SEAL, b"tenancy-a", &sealed).expect("opens").as_slice(), b"secret contents");
    assert!(
        matches!(key.open(&tags::BUNDLE_SEAL, b"tenancy-b", &sealed), Err(AgreementError::Open(_))),
        "a different context doesn't open it"
    );
    assert!(
        matches!(key.open(&tags::RECORD_SEAL, b"tenancy-a", &sealed), Err(AgreementError::Open(_))),
        "a different tag doesn't open it"
    );
    let elsewhere = seal(&other, &tags::BUNDLE_SEAL, b"tenancy-a", b"secret contents");
    assert_eq!(
        key.open(&tags::BUNDLE_SEAL, b"tenancy-a", &elsewhere),
        Err(AgreementError::WrongRecipient),
        "a seal to another key is refused before opening"
    );
}

/// [`RuntimeProfiles`]: returns what was recorded and `None` for an unknown tenancy.
pub fn runtime_profiles_contract<P: RuntimeProfiles>(make: impl Fn() -> P, known: TenancyId, expected: RuntimeProfile) {
    let profiles = make();
    assert_eq!(profiles.profile(&known), Ok(Some(expected)));
    assert_eq!(profiles.profile(&TenancyId::from([0xee; 32])), Ok(None));
}
