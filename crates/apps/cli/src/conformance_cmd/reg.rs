//! The registration suites the spec's section 8 names: `reg-token`, `reg-verify` and
//! `reg-revoke`, run against the real factory use cases over the in-memory adapters (the
//! same cases as `crates/adapters/memory/tests/registration.rs`).

#![allow(dead_code, unused_imports, missing_docs, clippy::all)]

use super::harness::Check;
use super::Unit;


use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog};
use fieldseal_adapters_memory::registration::{
    DevAuthority, MemoryFleetRegistry, MemoryIdentityProvider, MemoryNotifier, MemoryReceivedProgress, MemoryRegistryStore,
    SoftwareDevice, dev_authority, software_evidence,
};
use fieldseal_adapters_memory::trust::{FixedClock, SeededRandom, SoftwareAttestationVerifier};
use fieldseal_kernel::crypto::tags;
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{Nonce, Seq, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, text};
use fieldseal_policy::domain::EffectivePolicy;
use fieldseal_policy::fixtures::{DocBuilder, effective, int, map, text as ptext, words};
use fieldseal_registration::application::{Factory, FactoryConfig, FactoryPorts, RegistrationError, Submission};
use fieldseal_registration::domain::auth::AuthRefusal;
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::domain::wire::{
    CloseCertificate, TenancyCertificate, TokenRefusal, decode_request_file, encode_request_file,
};
use fieldseal_registration::domain::{
    AuthenticatedPerson, CloseReason, DeviceId, IssuedToken, KeyState, MethodAssurance, RegistrationRoute, ReportedRestriction,
    TenancyState, TenancyTerms, Window,
};
use fieldseal_registration::ports::TokenError;
use fieldseal_trust::domain::DeviceKeyKind;

const T0: AuthorityTime = AuthorityTime(1_800_000_000_000);
const MINUTE: u64 = 60 * AuthorityTime::SECOND;

struct World {
    authority: DevAuthority<SeededRandom>,
    store: MemoryRegistryStore,
    verifier: SoftwareAttestationVerifier,
    engine: BuiltInPolicyEngine,
    log: MemoryDecisionLog,
    clock: FixedClock,
    random: SeededRandom,
    progress: MemoryReceivedProgress,
    fleet: MemoryFleetRegistry,
    notifier: MemoryNotifier,
    idp: MemoryIdentityProvider,
    policy: EffectivePolicy,
    config: FactoryConfig,
}

fn policy_with(sets: &[(&str, Value)]) -> EffectivePolicy {
    let mut doc = DocBuilder::deployment("test", "1.0.0");
    for (path, value) in sets {
        doc = doc.set(path, value.clone());
    }
    effective(&[doc.build()])
}

fn batch_policy() -> Vec<(&'static str, Value)> {
    vec![(
        "factory.registration.batchTokens",
        map(&[("allowed", Value::Bool(true)), ("roles", words(&["device-preparation"])), ("maxUses", int(10)), ("ttl", ptext("4h"))]),
    )]
}

impl World {
    fn new(sets: &[(&str, Value)], unattested: UnattestedKeys) -> Self {
        let authority = dev_authority(SeededRandom::new(1), T0, &["fieldseal-simulator"]).expect("dev authority");
        let config = FactoryConfig {
            factory_url: "https://factory.example.org".into(),
            signing_key: *authority.signing.key_id(),
            sealing_key: *authority.sealing.key_id(),
            terms: TenancyTerms {
                record_key: *authority.record.key_id(),
                window: Window { not_before: T0, not_after: AuthorityTime(T0.0 + 90 * AuthorityTime::DAY), grace_ms: 30 * AuthorityTime::DAY },
                cohorts: vec![],
            },
            unattested,
            posture_nonce_ttl_ms: 10 * MINUTE,
            access_token_ttl_ms: 10 * MINUTE,
        };
        let idp = MemoryIdentityProvider::new();
        idp.add("alice", "sub-alice", &["collector"], &["hwk", "user"], MethodAssurance::FromProvider);
        idp.add("bob", "sub-bob", &["collector"], &["hwk"], MethodAssurance::FromProvider);
        idp.add("olga", "sub-olga", &["operator", "device-preparation"], &["hwk"], MethodAssurance::FromProvider);
        idp.add("wally", "sub-wally", &["collector"], &["pwd", "otp"], MethodAssurance::FromProvider);
        idp.add("bert", "sub-bert", &["collector"], &["hwk"], MethodAssurance::Asserted);
        Self {
            authority,
            store: MemoryRegistryStore::new(),
            verifier: SoftwareAttestationVerifier,
            engine: BuiltInPolicyEngine,
            log: MemoryDecisionLog::new(),
            clock: FixedClock::new(T0),
            random: SeededRandom::new(2),
            progress: MemoryReceivedProgress::new(),
            fleet: MemoryFleetRegistry::new(),
            notifier: MemoryNotifier::new(),
            idp,
            policy: policy_with(sets),
            config,
        }
    }

    fn dev() -> Self {
        Self::new(&[], UnattestedKeys::AllowNonProduction)
    }

    fn factory(&self) -> Factory<'_> {
        Factory::new(
            FactoryPorts {
                store: &self.store,
                custody: &self.authority.custody,
                verifiers: vec![&self.verifier],
                engine: &self.engine,
                log: &self.log,
                clock: &self.clock,
                random: &self.random,
                progress: &self.progress,
                fleet: Some(&self.fleet),
                notifier: Some(&self.notifier),
            },
            &self.authority.bundle,
            &self.policy,
            &self.config,
        )
        .expect("factory")
    }

    fn person(&self, login: &str) -> AuthenticatedPerson {
        self.idp.person(login).expect("known person")
    }

    fn device(&self) -> SoftwareDevice {
        SoftwareDevice::new(&self.random)
    }

    fn token(&self, login: &str) -> IssuedToken {
        self.factory().issue_token(&self.person(login), RegistrationRoute::Online, 1).expect("token")
    }

    fn request(&self, device: &SoftwareDevice, token: &IssuedToken) -> fieldseal_kernel::seal::SealedBox {
        device.request(&self.random, &self.authority.bundle, &token.token, Some("blue")).expect("token verifies")
    }

    /// Issues a token to `login`, registers a new device and confirms it.
    fn registered(&self, login: &str) -> (SoftwareDevice, TenancyId) {
        let device = self.device();
        let token = self.token(login);
        let submitted = self.factory().submit(&self.request(&device, &token), Submission::Online).expect("submit");
        let record = self.factory().confirm(&self.person(login).account, &submitted.tenancy.id).expect("confirm");
        assert_eq!(record.state, TenancyState::Registered);
        (device, record.id)
    }

    fn advance(&self, ms: u64) {
        // FixedClock::advance adds its argument to the millisecond reading.
        self.clock.advance(ms);
    }
}

// ---------------------------------------------------------------------------------------
// Identity and tokens (REG-002..007).

pub fn reg_002_sign_in_without_a_phishing_resistant_method_gets_no_token() {
    let w = World::dev();
    let e = w.factory().issue_token(&w.person("wally"), RegistrationRoute::Online, 1).unwrap_err();
    assert_eq!(e, RegistrationError::Authentication(AuthRefusal::PhishingResistantRequired));
}

pub fn reg_002a_broker_asserted_methods_need_explicit_policy_and_are_recorded() {
    let w = World::dev();
    let e = w.factory().issue_token(&w.person("bert"), RegistrationRoute::Online, 1).unwrap_err();
    assert_eq!(e, RegistrationError::Authentication(AuthRefusal::AssertedNotAccepted));

    let w = World::new(&[("factory.registration.acceptAssertedAuthMethods", Value::Bool(true))], UnattestedKeys::AllowNonProduction);
    let (_, tenancy) = w.registered("bert");
    let record = w.factory().status(&tenancy).unwrap();
    assert!(record.authentication.asserted, "the registration records that it relied on an asserted method");
}

pub fn reg_004_token_carries_the_factory_root_secret_nonce_and_route_and_fits_a_qr_code() {
    let w = World::dev();
    let issued = w.factory().issue_token(&w.person("alice"), RegistrationRoute::AirGapped, 1).unwrap();
    let t = &issued.token;
    assert_eq!(t.factory, "https://factory.example.org");
    assert_eq!(t.trust_root, sha256(w.authority.root.public_key().encoded()));
    assert_eq!(t.route, RegistrationRoute::AirGapped);
    assert_ne!(t.secret.as_bytes(), &[0; 16]);
    assert!(t.encode().unwrap().len() <= text::MAX_QR_OBJECT, "WIRE-123");
    let text_form = t.to_text().unwrap();
    assert!(text_form.starts_with("FS1T:"));
    assert_eq!(&fieldseal_registration::domain::RegistrationToken::from_text(&text_form).unwrap(), t);
    assert!(t.verify(&w.authority.bundle).is_ok(), "signed by the factory's registration key");
    // REG-006: the air-gapped lifetime (24 h by default) is the factory's, not in the bytes.
    assert_eq!(issued.expires_at, AuthorityTime(T0.0 + 24 * 60 * MINUTE));
}

pub fn reg_005_a_token_registers_at_most_one_tenancy() {
    let w = World::dev();
    let token = w.token("alice");
    w.factory().submit(&w.request(&w.device(), &token), Submission::Online).unwrap();
    let e = w.factory().submit(&w.request(&w.device(), &token), Submission::Online).unwrap_err();
    assert_eq!(e, RegistrationError::Token(TokenError::Used));
}

pub fn reg_006_expiry_is_judged_on_the_factory_clock() {
    let w = World::dev();
    let token = w.token("alice");
    w.advance(10 * MINUTE + 1);
    let e = w.factory().submit(&w.request(&w.device(), &token), Submission::Online).unwrap_err();
    assert_eq!(e, RegistrationError::Token(TokenError::Expired));
}

pub fn reg_010_device_refuses_a_token_whose_root_it_does_not_trust() {
    let w = World::dev();
    let other = dev_authority(SeededRandom::new(99), T0, &["fieldseal-simulator"]).unwrap();
    let token = w.token("alice");
    assert_eq!(token.token.verify(&other.bundle), Err(TokenRefusal::UnknownRoot));
    let mut forged = token.token.clone();
    forged.nonce = Nonce::from([0; 32]);
    assert!(matches!(forged.verify(&w.authority.bundle), Err(TokenRefusal::Signature(_))));
}

// ---------------------------------------------------------------------------------------
// Requests and verification (REG-011..017).

pub fn reg_011_a_request_must_answer_the_token_nonce() {
    let w = World::dev();
    let token = w.token("alice");
    let device = w.device();
    let mut body = device.body(&token.token, None);
    body.nonce = Nonce::from([5; 32]);
    let sealed = device.seal(&w.random, &w.authority.bundle, T0, &body, None);
    assert_eq!(w.factory().submit(&sealed, Submission::Online).unwrap_err(), RegistrationError::NonceMismatch);
}

pub fn reg_013_a_request_sealed_to_another_key_cannot_be_opened() {
    let w = World::dev();
    let token = w.token("alice");
    let other = dev_authority(SeededRandom::new(98), T0, &["fieldseal-simulator"]).unwrap();
    let device = w.device();
    let sealed = device.seal(&w.random, &other.bundle, T0, &device.body(&token.token, None), None);
    assert!(matches!(w.factory().submit(&sealed, Submission::Online), Err(RegistrationError::Malformed(_))));
}

pub fn reg_014_a_bad_proof_of_possession_is_rejected_after_the_token_check() {
    let w = World::dev();
    let token = w.token("alice");
    let device = w.device();
    let impostor = w.device();
    let body = device.body(&token.token, None);
    // Signed by another key: the proof doesn't verify for sign_pub.
    let sealed = impostor.seal(&w.random, &w.authority.bundle, T0, &body, None);
    assert_eq!(w.factory().submit(&sealed, Submission::Online).unwrap_err(), RegistrationError::ProofInvalid);
    // The token was not consumed by the failed request.
    assert!(w.factory().submit(&w.request(&device, &token), Submission::Online).is_ok());

    // Order: an unknown token fails at step 1 even when the proof is also bad.
    let fresh = w.device();
    let mut body = fresh.body(&token.token, None);
    body.token = fieldseal_registration::domain::TokenSecret::from_bytes([1; 16]);
    let sealed = impostor.seal(&w.random, &w.authority.bundle, T0, &body, None);
    assert_eq!(w.factory().submit(&sealed, Submission::Online).unwrap_err(), RegistrationError::Token(TokenError::Unknown));
}

pub fn reg_014_evidence_that_does_not_verify_is_rejected() {
    let w = World::dev();
    let token = w.token("alice");
    let device = w.device();
    let mut body = device.body(&token.token, None);
    // Evidence bound to a different challenge.
    body.evidence[0].evidence = software_evidence(DeviceKeyKind::Signing, true, &Nonce::from([3; 32]), &device.sign_pub());
    let sealed = device.seal(&w.random, &w.authority.bundle, T0, &body, None);
    assert!(matches!(w.factory().submit(&sealed, Submission::Online), Err(RegistrationError::EvidenceRejected(_))));
    // Evidence missing for the agreement key.
    let mut body = device.body(&token.token, None);
    body.evidence.truncate(1);
    let sealed = device.seal(&w.random, &w.authority.bundle, T0, &body, None);
    assert!(matches!(w.factory().submit(&sealed, Submission::Online), Err(RegistrationError::EvidenceRejected(_))));
}

pub fn reg_017_unattested_keys_are_rejected_under_strict_policy() {
    let w = World::new(&[], UnattestedKeys::Refuse);
    let token = w.token("alice");
    let device = w.device();
    let e = w.factory().submit(&w.request(&device, &token), Submission::Online).unwrap_err();
    assert_eq!(e, RegistrationError::PolicyDenied(vec!["unattested-key".into()]));
    let record = w.factory().status(&device.tenancy()).unwrap();
    assert_eq!(record.state, TenancyState::Rejected, "kept with its reason for the portal (REG-031)");
    assert_eq!(record.reasons, ["unattested-key"]);
}

pub fn reg_015_runtime_versions_outside_policy_are_rejected() {
    let w = World::new(&[("factory.attestation.acceptedRuntimeVersions", ptext(">=1.0.0 <2.0.0"))], UnattestedKeys::AllowNonProduction);
    let token = w.token("alice");
    let e = w.factory().submit(&w.request(&w.device(), &token), Submission::Online).unwrap_err();
    assert_eq!(e, RegistrationError::PolicyDenied(vec!["runtime-version-not-accepted".into()]));
}

pub fn reg_015_runtime_builds_must_be_in_the_trust_bundle() {
    let mut w = World::dev();
    w.authority = dev_authority(SeededRandom::new(1), T0, &["another-app"]).unwrap();
    let token = w.token("alice");
    let e = w.factory().submit(&w.request(&w.device(), &token), Submission::Online).unwrap_err();
    assert_eq!(e, RegistrationError::PolicyDenied(vec!["runtime-build-not-accepted".into()]));
}

// ---------------------------------------------------------------------------------------
// Key roll, loss and revocation (REG-060..065).

pub fn reg_060_a_key_roll_needs_a_fresh_token_and_the_current_key() {
    let w = World::dev();
    let (current, tenancy) = w.registered("alice");
    let next = w.device();
    let token = w.token("alice");
    let body = next.body(&token.token, None);

    // Without the current key's signature (signed by a stranger instead): refused.
    let stranger = w.device();
    let forged = next.seal(&w.random, &w.authority.bundle, T0, &body, Some((&stranger, tenancy)));
    assert_eq!(w.factory().submit(&forged, Submission::Online).unwrap_err(), RegistrationError::ProofInvalid);
    // A token of another account: refused.
    let bobs = w.token("bob");
    let wrong = next.seal(&w.random, &w.authority.bundle, T0, &next.body(&bobs.token, None), Some((&current, tenancy)));
    assert_eq!(w.factory().submit(&wrong, Submission::Online).unwrap_err(), RegistrationError::WrongAccount);

    let sealed = next.seal(&w.random, &w.authority.bundle, T0, &body, Some((&current, tenancy)));
    let rolled = w.factory().submit(&sealed, Submission::Online).unwrap().tenancy;
    assert_eq!(rolled.id, tenancy, "the tenancy keeps its identifier");
    // REG-061: the old keys stay in history as rolled.
    let signing: Vec<_> = rolled.keys.iter().filter(|k| k.kind == DeviceKeyKind::Signing).collect();
    assert_eq!(signing.len(), 2);
    assert_eq!((signing[0].index, signing[0].state), (0, KeyState::Rolled));
    assert_eq!((signing[1].index, signing[1].state), (1, KeyState::Active));
    let cert = w.factory().certificate(&tenancy).unwrap();
    assert_eq!(cert.keys.len(), 2);
    assert_eq!(cert.agreement_key, next.agree_pub());
    assert!(cert.verify(&w.authority.bundle).is_ok());
    // The old key can no longer call the API.
    let pop = current.pop_token(tenancy, "GET", "https://factory.example.org/v1/certificate", T0, [1; 16], None);
    assert_eq!(
        w.factory().authenticate_api(&pop.to_header(), "GET", "https://factory.example.org/v1/certificate", None).unwrap_err(),
        RegistrationError::ProofInvalid
    );
}

pub fn reg_062_mark_lost_sets_the_cutoff_and_issues_a_close_certificate() {
    let w = World::dev();
    let (device, tenancy) = w.registered("alice");
    w.progress.received(tenancy, Seq(41));
    let device_id = w.factory().status(&tenancy).unwrap().device;
    assert_eq!(w.factory().mark_lost(&w.person("bob"), &device_id).unwrap_err(), RegistrationError::WrongAccount);
    let cert = w.factory().mark_lost(&w.person("alice"), &device_id).unwrap();
    assert_eq!(cert.cutoff, Seq(41));
    assert_eq!(cert.reason, CloseReason::Lost);
    let record = w.factory().status(&tenancy).unwrap();
    assert_eq!((record.state, record.cutoff), (TenancyState::Lost, Some(Seq(41))));
    // REG-064: QR-sized, text form, verifies.
    assert!(cert.encode().unwrap().len() <= text::MAX_QR_OBJECT);
    let decoded = CloseCertificate::from_text(&cert.to_text().unwrap()).unwrap();
    assert_eq!(decoded, cert);
    assert!(decoded.verify(&w.authority.bundle).is_ok());
    // REG-063: the device can no longer authenticate; nothing needed from it.
    let pop = device.pop_token(tenancy, "GET", "https://factory.example.org/v1/certificate", T0, [2; 16], None);
    assert_eq!(
        w.factory().authenticate_api(&pop.to_header(), "GET", "https://factory.example.org/v1/certificate", None).unwrap_err(),
        RegistrationError::Revoked
    );
    assert_eq!(w.factory().certificate(&tenancy).unwrap_err(), RegistrationError::Revoked);
    assert_eq!(w.notifier.delivered().last().unwrap().1, fieldseal_registration::ports::PortalEvent::DeviceMarkedLost(device_id));
}

pub fn reg_065_a_forgotten_pin_gets_a_reset_certificate() {
    let w = World::dev();
    let (_, tenancy) = w.registered("alice");
    assert!(matches!(w.factory().close(&w.person("alice"), &tenancy, CloseReason::ForgottenPin), Err(RegistrationError::NotAuthorised(_))));
    let cert = w.factory().close(&w.person("olga"), &tenancy, CloseReason::ForgottenPin).unwrap();
    assert_eq!(CloseCertificate::tag(cert.reason).as_str(), tags::RESET_CERTIFICATE.as_str());
    assert!(cert.verify(&w.authority.bundle).is_ok());
    assert_eq!(cert.cutoff, Seq(0), "nothing received yet");
    assert_eq!(w.factory().status(&tenancy).unwrap().state, TenancyState::Closing);
}

// ---------------------------------------------------------------------------------------
// After registration (REG-070..072, REG-080..082).

const URL: &str = "https://factory.example.org/v1/api-token";

pub fn reg_070_runtime_calls_carry_a_pop_token_bound_to_the_signing_key() {
    let w = World::dev();
    let (device, tenancy) = w.registered("alice");
    let f = w.factory();
    let ok = device.pop_token(tenancy, "POST", URL, T0, [1; 16], None);
    let record = f.authenticate_api(&ok.to_header(), "POST", URL, None).unwrap();
    // WIRE-171: replay, wrong method or URL, stale iat, wrong key.
    assert_eq!(f.authenticate_api(&ok.to_header(), "POST", URL, None).unwrap_err(), RegistrationError::Replay);
    let t = device.pop_token(tenancy, "POST", URL, T0, [2; 16], None);
    assert_eq!(f.authenticate_api(&t.to_header(), "GET", URL, None).unwrap_err(), RegistrationError::ProofInvalid);
    assert_eq!(f.authenticate_api(&t.to_header(), "POST", "https://elsewhere.example/v1", None).unwrap_err(), RegistrationError::ProofInvalid);
    let stale = device.pop_token(tenancy, "POST", URL, AuthorityTime(T0.0 - 301 * AuthorityTime::SECOND), [3; 16], None);
    assert_eq!(f.authenticate_api(&stale.to_header(), "POST", URL, None).unwrap_err(), RegistrationError::ProofInvalid);
    let mut forged = device.pop_token(tenancy, "POST", URL, T0, [4; 16], None);
    forged.signature = w.device().sign_message(&forged.message());
    assert_eq!(f.authenticate_api(&forged.to_header(), "POST", URL, None).unwrap_err(), RegistrationError::ProofInvalid);
    assert!(matches!(f.authenticate_api("not base64!", "POST", URL, None), Err(RegistrationError::Malformed(_))));

    // IssueApiToken: an access token used with a PoP token that carries its hash.
    let access = f.issue_api_token(&record).unwrap();
    let url = "https://factory.example.org/v1/posture";
    let with_ath = device.pop_token(tenancy, "GET", url, T0, [5; 16], Some(sha256(&access.value)));
    assert!(f.authenticate_api(&with_ath.to_header(), "GET", url, Some(&access.value)).is_ok());
    let without_ath = device.pop_token(tenancy, "GET", url, T0, [6; 16], None);
    assert_eq!(f.authenticate_api(&without_ath.to_header(), "GET", url, Some(&access.value)).unwrap_err(), RegistrationError::ProofInvalid);
    w.advance(10 * MINUTE + 1);
    let late = device.pop_token(tenancy, "GET", url, w.factory().now(), [7; 16], Some(sha256(&access.value)));
    assert_eq!(w.factory().authenticate_api(&late.to_header(), "GET", url, Some(&access.value)).unwrap_err(), RegistrationError::ProofInvalid);
}
// covers: REG-002, REG-002a, REG-004, REG-005, REG-006, REG-010, REG-011, REG-013, REG-014, REG-015, REG-017, REG-060, REG-061, REG-062, REG-063, REG-064, REG-065, WIRE-123

const fn c(reqs: &'static [&'static str], name: &'static str, run: fn()) -> Check {
    Check { reqs, name, run }
}

const TOKEN: &[Check] = &[
    c(&["REG-002"], "sign-in without a phishing-resistant method gets no token", reg_002_sign_in_without_a_phishing_resistant_method_gets_no_token),
    c(&["REG-002a"], "broker-asserted methods need explicit policy and are recorded", reg_002a_broker_asserted_methods_need_explicit_policy_and_are_recorded),
    c(&["REG-004", "REG-006", "WIRE-123"], "a token carries the factory, root, secret, nonce and route and fits a QR code", reg_004_token_carries_the_factory_root_secret_nonce_and_route_and_fits_a_qr_code),
    c(&["REG-005"], "a token registers at most one tenancy", reg_005_a_token_registers_at_most_one_tenancy),
    c(&["REG-006"], "expiry is judged on the factory clock", reg_006_expiry_is_judged_on_the_factory_clock),
];

const VERIFY: &[Check] = &[
    c(&["REG-010"], "a device refuses a token whose root it does not trust", reg_010_device_refuses_a_token_whose_root_it_does_not_trust),
    c(&["REG-011"], "a request must answer the token nonce", reg_011_a_request_must_answer_the_token_nonce),
    c(&["REG-013"], "a request sealed to another key cannot be opened", reg_013_a_request_sealed_to_another_key_cannot_be_opened),
    c(&["REG-014"], "a bad proof of possession is rejected after the token check", reg_014_a_bad_proof_of_possession_is_rejected_after_the_token_check),
    c(&["REG-014"], "evidence that does not verify is rejected", reg_014_evidence_that_does_not_verify_is_rejected),
    c(&["REG-017"], "unattested keys are rejected under strict policy", reg_017_unattested_keys_are_rejected_under_strict_policy),
    c(&["REG-015"], "runtime versions outside policy are rejected", reg_015_runtime_versions_outside_policy_are_rejected),
    c(&["REG-015"], "runtime builds must be in the trust bundle", reg_015_runtime_builds_must_be_in_the_trust_bundle),
];

const REVOKE: &[Check] = &[
    c(&["REG-060", "REG-061"], "a key roll needs a fresh token and the current key", reg_060_a_key_roll_needs_a_fresh_token_and_the_current_key),
    c(&["REG-062", "REG-063", "REG-064"], "mark as lost sets the cutoff and issues a close certificate", reg_062_mark_lost_sets_the_cutoff_and_issues_a_close_certificate),
    c(&["REG-065"], "a forgotten PIN gets a reset certificate", reg_065_a_forgotten_pin_gets_a_reset_certificate),
];

/// The units of the `reg-token`, `reg-verify` and `reg-revoke` suites.
pub fn units() -> Vec<Unit> {
    vec![
        Unit::table("reg:token", &["reg-token"], TOKEN),
        Unit::table("reg:verify", &["reg-verify"], VERIFY),
        Unit::table("reg:revoke", &["reg-revoke"], REVOKE),
    ]
}
