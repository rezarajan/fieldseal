//! Contract tests for adapters of the Registration context's driven ports.

use std::collections::BTreeMap;

use fieldseal_kernel::crypto::{P256PublicKey, Signature};
use fieldseal_kernel::id::{Digest, KeyId, Nonce, Seq, TenancyHandle, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_trust::domain::{AttestationEvidence, DeviceKeyKind};

use crate::domain::{
    AccessToken, Account, AccountId, AuthRecord, DeviceId, FingerprintWords, IssuedToken, KeyState, NonceSource,
    RegisteredDevice, RegisteredKey, RegistrationRoute, RegistrationToken, Role, TenancyRecord, TenancyState, TokenSecret,
    Window,
};
use crate::ports::{
    IdentityProvider, IssuedNonce, Notifier, PortalEvent, ReceivedProgress, RegistryStore, RegistryStoreError, SignInStart,
    TokenError,
};

/// A token fixture, bound to `account`.
pub fn sample_token(secret: u8, account: &str, max_uses: u32, expires_at: u64) -> IssuedToken {
    IssuedToken {
        token: RegistrationToken {
            factory: "https://factory.example".into(),
            trust_root: Digest::from([7; 32]),
            secret: TokenSecret::from_bytes([secret; 16]),
            nonce: Nonce::from([secret; 32]),
            route: RegistrationRoute::Online,
            issued_at: AuthorityTime(0),
            signer: KeyId::from([3; 16]),
            signature: Signature(vec![0; 64]),
        },
        account: AccountId(account.into()),
        expires_at: AuthorityTime(expires_at),
        max_uses,
        authentication: AuthRecord { methods: vec!["hwk".into()], phishing_resistant: true, asserted: false },
    }
}

fn sample_key(seed: u8) -> P256PublicKey {
    // A real curve point: the public key of the scalar [seed; 32] (seed below 0xff).
    fieldseal_kernel::sign::SigningKey::from_scalar(&[seed.max(1); 32]).expect("valid P-256 scalar").public_key()
}

/// A tenancy fixture with one active signing key.
pub fn sample_tenancy(id: u8, account: &str) -> TenancyRecord {
    TenancyRecord {
        id: TenancyId::from([id; 32]),
        handle: TenancyHandle::from([id; 16]),
        account: AccountId(account.into()),
        device: DeviceId(format!("device-{id}")),
        state: TenancyState::Pending,
        keys: vec![RegisteredKey {
            index: 0,
            kind: DeviceKeyKind::Signing,
            public_key: sample_key(id),
            evidence: AttestationEvidence { format: "software".into(), data: vec![id] },
            claims: None,
            state: KeyState::Active,
        }],
        window: Window { not_before: AuthorityTime(0), not_after: AuthorityTime(1_000), grace_ms: 100 },
        record_key: KeyId::from([4; 16]),
        cohorts: vec![],
        cutoff: None,
        words: FingerprintWords::from_indices([1, 2, 3, 4]).expect("in range"),
        token: TokenSecret::from_bytes([id; 16]),
        batch: false,
        pending_until: AuthorityTime(1_000),
        nonce_source: NonceSource::Factory,
        build: "test".into(),
        authentication: AuthRecord { methods: vec!["hwk".into()], phishing_resistant: true, asserted: false },
        reasons: vec![],
        certificate: None,
        last_seen: None,
    }
}

/// [`RegistryStore`]: single-use tokens consumed atomically, expiry by the given time, key
/// history kept, lookups by ID and handle, single-use nonces and `jti`s.
pub fn registry_store_contract<S: RegistryStore + Sync>(make: impl Fn() -> S) {
    // Single use (REG-005).
    let store = make();
    let token = sample_token(1, "acct-a", 1, 100);
    store.put_token(&token).expect("put token");
    assert_eq!(store.put_token(&token), Err(RegistryStoreError::DuplicateToken), "a token secret is unique");
    let secret = token.token.secret;
    assert_eq!(store.token(&secret), Ok(Some((token.clone(), 1))), "reading a token does not use it");
    assert_eq!(store.consume_token(&secret, AuthorityTime(10)), Ok(token.clone()));
    assert_eq!(store.token(&secret), Ok(Some((token.clone(), 0))));
    assert_eq!(store.consume_token(&secret, AuthorityTime(10)), Err(TokenError::Used), "a single-use token registers at most once");
    assert_eq!(store.consume_token(&TokenSecret::from_bytes([9; 16]), AuthorityTime(10)), Err(TokenError::Unknown));
    assert_eq!(store.token(&TokenSecret::from_bytes([9; 16])), Ok(None));

    // Expiry is judged by the time the factory passes, not by the device (REG-006).
    let expiring = sample_token(2, "acct-a", 1, 100);
    store.put_token(&expiring).expect("put");
    assert_eq!(store.consume_token(&expiring.token.secret, AuthorityTime(101)), Err(TokenError::Expired));
    assert_eq!(store.consume_token(&expiring.token.secret, AuthorityTime(100)), Ok(expiring.clone()), "expiry is inclusive");

    // Atomic consumption under concurrency.
    let store = make();
    let shared = sample_token(3, "acct-a", 1, 100);
    store.put_token(&shared).expect("put");
    let wins = std::thread::scope(|s| {
        let handles: Vec<_> = (0..8).map(|_| s.spawn(|| store.consume_token(&shared.token.secret, AuthorityTime(1)).is_ok())).collect();
        handles.into_iter().map(|h| h.join().expect("thread")).filter(|won| *won).count()
    });
    assert_eq!(wins, 1, "exactly one concurrent consumer may win a single-use token");

    // Batch tokens allow exactly max_uses (REG-044).
    let batch = sample_token(4, "operator", 3, 100);
    store.put_token(&batch).expect("put");
    for _ in 0..3 {
        store.consume_token(&batch.token.secret, AuthorityTime(1)).expect("use");
    }
    assert_eq!(store.consume_token(&batch.token.secret, AuthorityTime(1)), Err(TokenError::Used));

    // Accounts.
    let account = Account { id: AccountId("acct-a".into()), collector: [5; 16], roles: vec![Role::Collector] };
    store.put_account(&account).expect("put account");
    assert_eq!(store.account(&account.id), Ok(Some(account.clone())));
    assert_eq!(store.account(&AccountId("nobody".into())), Ok(None));

    // Tenancies: lookups, and key history never shrinks.
    let mut tenancy = sample_tenancy(5, "acct-a");
    store.put_tenancy(&tenancy).expect("put tenancy");
    assert_eq!(store.tenancy(&tenancy.id), Ok(Some(tenancy.clone())));
    assert_eq!(store.tenancy_by_handle(&tenancy.handle), Ok(Some(tenancy.clone())));
    assert_eq!(store.tenancies_of(&tenancy.account).expect("list").len(), 1);
    tenancy.state = TenancyState::Registered;
    store.put_tenancy(&tenancy).expect("update state");
    let mut shrunk = tenancy.clone();
    shrunk.keys.clear();
    assert_eq!(store.put_tenancy(&shrunk), Err(RegistryStoreError::HistoryViolation), "keys are never deleted from history");
    assert_eq!(store.tenancy(&TenancyId::from([0xee; 32])), Ok(None));

    // Devices.
    let device = RegisteredDevice {
        id: DeviceId("device-5".into()),
        account: AccountId("acct-a".into()),
        nickname: "blue".into(),
        words: tenancy.words,
        hardware_id: None,
        tenancies: vec![tenancy.id],
    };
    store.put_device(&device).expect("put device");
    assert_eq!(store.device(&device.id), Ok(Some(device.clone())));
    assert_eq!(store.devices_of(&device.account), Ok(vec![device]));

    // Nonces are single use, bound to a tenancy, and expire.
    let nonce = IssuedNonce { nonce: Nonce::from([6; 32]), tenancy: tenancy.id, expires_at: AuthorityTime(50) };
    store.put_nonce(&nonce).expect("put nonce");
    assert_eq!(store.take_nonce(&nonce.nonce, &TenancyId::from([1; 32]), AuthorityTime(1)), Ok(false), "another tenancy");
    assert_eq!(store.take_nonce(&nonce.nonce, &tenancy.id, AuthorityTime(1)), Ok(true));
    assert_eq!(store.take_nonce(&nonce.nonce, &tenancy.id, AuthorityTime(1)), Ok(false), "single use");
    let late = IssuedNonce { nonce: Nonce::from([7; 32]), tenancy: tenancy.id, expires_at: AuthorityTime(50) };
    store.put_nonce(&late).expect("put nonce");
    assert_eq!(store.take_nonce(&late.nonce, &tenancy.id, AuthorityTime(51)), Ok(false), "expired");

    // PoP jtis are remembered until they lapse (WIRE-171).
    assert_eq!(store.record_jti(&tenancy.id, &[1; 16], AuthorityTime(300), AuthorityTime(0)), Ok(true));
    assert_eq!(store.record_jti(&tenancy.id, &[1; 16], AuthorityTime(600), AuthorityTime(100)), Ok(false), "replay");
    assert_eq!(store.record_jti(&TenancyId::from([1; 32]), &[1; 16], AuthorityTime(300), AuthorityTime(0)), Ok(true));
    assert_eq!(store.record_jti(&tenancy.id, &[1; 16], AuthorityTime(900), AuthorityTime(301)), Ok(true), "lapsed");

    // Access tokens.
    let access = AccessToken { value: [8; 32], tenancy: tenancy.id, key: KeyId::from([9; 16]), expires_at: AuthorityTime(10) };
    store.put_access_token(&access).expect("put access token");
    assert_eq!(store.access_token(&[8; 32]), Ok(Some(access)));
    assert_eq!(store.access_token(&[0; 32]), Ok(None));
}

/// [`IdentityProvider`]: `complete` plays the browser and the provider for one sign-in,
/// returning the callback parameters for a person who authenticates with the methods the
/// test arranged. The adapter must authenticate that person, report
/// `expect_phishing_resistant`, return a stable subject, give every sign-in its own state,
/// and refuse a callback whose state doesn't match the pending sign-in.
pub fn identity_provider_contract<P: IdentityProvider>(
    idp: &P,
    redirect_uri: &str,
    complete: impl Fn(&SignInStart) -> BTreeMap<String, String>,
    expect_phishing_resistant: bool,
) {
    let start = idp.start_sign_in(redirect_uri).expect("start sign-in");
    assert!(!start.redirect_to.is_empty() && !start.pending.state.is_empty());
    let callback = complete(&start);
    let person = idp.finish_sign_in(&start.pending, &callback).expect("a valid callback authenticates");
    assert!(!person.account.0.is_empty(), "a stable subject identifier is returned");
    assert_eq!(
        person.authentication.phishing_resistant, expect_phishing_resistant,
        "the provider reports whether a phishing-resistant method was used"
    );

    let again = idp.start_sign_in(redirect_uri).expect("start again");
    assert_ne!(again.pending.state, start.pending.state, "every sign-in has its own state");
    let callback_again = complete(&again);
    assert_eq!(idp.finish_sign_in(&again.pending, &callback_again).expect("again").account, person.account, "stable subject");

    // A callback that belongs to another sign-in is refused.
    let third = idp.start_sign_in(redirect_uri).expect("start third");
    let callback_third = complete(&third);
    assert!(idp.finish_sign_in(&start.pending, &callback_third).is_err(), "state must match the pending sign-in");
    let mut tampered = callback_third.clone();
    tampered.insert("state".into(), "forged".into());
    assert!(idp.finish_sign_in(&third.pending, &tampered).is_err(), "a forged state is refused");
}

/// [`ReceivedProgress`]: `None` for a tenancy nothing has arrived from, else the highest
/// `seq` as `expected`.
pub fn received_progress_contract<R: ReceivedProgress>(source: &R, known: &TenancyId, expected: Seq) {
    assert_eq!(source.highest_received(known), Ok(Some(expected)));
    assert_eq!(source.highest_received(&TenancyId::from([0xab; 32])), Ok(None));
}

/// [`Notifier`]: accepts events; callers never depend on success.
pub fn notifier_contract<N: Notifier>(make: impl Fn() -> N) {
    let notifier = make();
    // Either outcome is acceptable; the call must simply return.
    let _ = notifier.notify(&AccountId("acct-a".into()), &PortalEvent::DeviceRegistered(DeviceId("d".into())));
}

/// [`FleetRegistry`] (REG-016): knows the serials it lists and no others; an empty or
/// near-miss serial is unknown.
pub fn fleet_registry_contract<F: crate::ports::FleetRegistry>(make: impl Fn() -> F, listed: &str) {
    let fleet = make();
    assert!(fleet.knows(listed), "a listed serial is known");
    assert!(!fleet.knows(""), "the empty serial is unknown");
    assert!(!fleet.knows(&format!("{listed}x")), "a near-miss serial is unknown");
    assert_eq!(fleet.knows(listed), fleet.knows(listed), "stable");
}
