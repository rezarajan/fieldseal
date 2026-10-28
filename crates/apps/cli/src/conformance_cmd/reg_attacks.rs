//! The `reg-attacks` suite: each row of the registration spec's attack table (section 5.9)
//! is played against the real factory use cases over the in-memory adapters and must fail
//! (the same cases as `crates/apps/security-tests/tests/registration_attacks.rs`).

#![allow(dead_code, unused_imports, missing_docs, clippy::all)]

use super::harness::Check;
use super::Unit;


use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog};
use fieldseal_adapters_memory::registration::{
    DevAuthority, MemoryFleetRegistry, MemoryIdentityProvider, MemoryNotifier, MemoryReceivedProgress, MemoryRegistryStore, SoftwareDevice,
    dev_authority, software_evidence,
};
use fieldseal_adapters_memory::trust::{FixedClock, SeededRandom, SoftwareAttestationVerifier};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{Nonce, TenancyId};
use fieldseal_kernel::seal::SealedBox;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, text};
use fieldseal_policy::domain::EffectivePolicy;
use fieldseal_policy::fixtures::{DocBuilder, effective, int};
use fieldseal_registration::application::{Factory, FactoryConfig, FactoryPorts, RegistrationError, Submission};
use fieldseal_registration::domain::auth::AuthRefusal;
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::domain::wire::TokenRefusal;
use fieldseal_registration::domain::{
    AuthenticatedPerson, CloseReason, IssuedToken, MethodAssurance, RegistrationRoute, RegistrationToken, TenancyState, TenancyTerms, Window,
};
use fieldseal_registration::ports::TokenError;
use fieldseal_trust::domain::DeviceKeyKind;

const T0: AuthorityTime = AuthorityTime(1_800_000_000_000);
const MINUTE: u64 = 60 * AuthorityTime::SECOND;
const URL: &str = "https://factory.example.org/v1/api-token";

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
        idp.add("mallory", "sub-mallory", &["collector"], &["hwk"], MethodAssurance::FromProvider);
        idp.add("wally", "sub-wally", &["collector"], &["pwd", "otp"], MethodAssurance::FromProvider);
        idp.add("olga", "sub-olga", &["operator"], &["hwk"], MethodAssurance::FromProvider);
        let mut doc = DocBuilder::deployment("test", "1.0.0");
        for (path, value) in sets {
            doc = doc.set(path, value.clone());
        }
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
            policy: effective(&[doc.build()]),
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

    fn request(&self, device: &SoftwareDevice, token: &IssuedToken) -> SealedBox {
        device.request(&self.random, &self.authority.bundle, &token.token, Some("blue")).expect("token verifies")
    }

    fn registered(&self, login: &str) -> (SoftwareDevice, TenancyId) {
        let device = self.device();
        let token = self.token(login);
        let submitted = self.factory().submit(&self.request(&device, &token), Submission::Online).expect("submit");
        let record = self.factory().confirm(&self.person(login).account, &submitted.tenancy.id).expect("confirm");
        assert_eq!(record.state, TenancyState::Registered);
        (device, record.id)
    }
}

/// §5.9 code phishing (REG-001, REG-003, REG-007): tokens only flow from an authenticated,
/// phishing-resistant portal session to the device; no code originates on a device, and a
/// weakly authenticated session mints nothing.
pub fn reg_attack_code_phishing_there_is_no_device_originated_code_and_weak_sign_in_mints_no_token() {
    let w = World::dev();
    assert_eq!(
        w.factory().issue_token(&w.person("wally"), RegistrationRoute::Online, 1).unwrap_err(),
        RegistrationError::Authentication(AuthRefusal::PhishingResistantRequired)
    );
    // A device can only ever present a request; one that names a token the factory never
    // issued fails at the first step, before any proof is examined.
    let device = w.device();
    let real = w.token("alice");
    let mut body = device.body(&real.token, None);
    body.token = fieldseal_registration::domain::TokenSecret::from_bytes([0x66; 16]);
    let sealed = device.seal(&w.random, &w.authority.bundle, T0, &body, None);
    assert_eq!(w.factory().submit(&sealed, Submission::Online).unwrap_err(), RegistrationError::Token(TokenError::Unknown));
}

/// §5.9 token theft (REG-005, REG-006, REG-021): a stolen token is single-use, short-lived,
/// registers nothing until the token's own account confirms, and the attacker's device shows
/// words that differ from the victim's.
pub fn reg_attack_token_theft_single_use_short_lived_and_the_words_do_not_match() {
    let w = World::dev();
    let token = w.token("alice");
    let victim = w.device();
    let thief = w.device();
    let victim_words = fieldseal_registration::domain::FingerprintWords::from_body_digest(&victim.body(&token.token, Some("blue")).digest());
    let stolen = w.factory().submit(&w.request(&thief, &token), Submission::Online).expect("the thief submits first");
    assert_ne!(stolen.words, victim_words, "REG-021: what the portal shows is the thief's words, which the victim's device does not");
    // Another account cannot confirm it, and the victim's genuine request finds the token used.
    assert_eq!(w.factory().confirm(&w.person("mallory").account, &stolen.tenancy.id).unwrap_err(), RegistrationError::WrongAccount);
    assert_eq!(w.factory().status(&stolen.tenancy.id).unwrap().state, TenancyState::Pending);
    assert_eq!(w.factory().submit(&w.request(&victim, &token), Submission::Online).unwrap_err(), RegistrationError::Token(TokenError::Used));
    // And an unconfirmed theft lapses with the token.
    w.clock.advance(10 * MINUTE + 1);
    assert_eq!(w.factory().confirm(&w.person("alice").account, &stolen.tenancy.id).unwrap_err(), RegistrationError::ConfirmationExpired);
}

/// §5.9 key substitution (REG-012, REG-013): a carrier that swaps the keys in a request
/// invalidates the proof of possession; one that re-seals to its own key cannot be opened by
/// the factory; neither consumes the token.
pub fn reg_attack_key_substitution_by_a_relay_or_file_carrier_fails() {
    let w = World::dev();
    let token = w.token("alice");
    let device = w.device();
    let relay = w.device();
    // The relay builds a body with its own keys but lets the victim's proof of possession through.
    let mut forged = relay.body(&token.token, None);
    forged.sign_pub = device.sign_pub();
    let sealed = relay.seal(&w.random, &w.authority.bundle, T0, &forged, None);
    assert_eq!(w.factory().submit(&sealed, Submission::Online).unwrap_err(), RegistrationError::ProofInvalid);
    // The relay seals the victim's body to a key of its own.
    let other = dev_authority(SeededRandom::new(77), T0, &["fieldseal-simulator"]).unwrap();
    let sealed = device.seal(&w.random, &other.bundle, T0, &device.body(&token.token, None), None);
    assert!(matches!(w.factory().submit(&sealed, Submission::Online), Err(RegistrationError::Malformed(_))));
    // Bit flips anywhere in the sealed request never produce a registration.
    let genuine = w.request(&device, &token);
    let mut rng = Seeded::new(13);
    let bytes = genuine.encode();
    for _ in 0..200 {
        let mut b = bytes.clone();
        let i = rng.below(b.len());
        b[i] ^= 1 << rng.below(8);
        if let Ok(s) = SealedBox::decode(&b) {
            assert!(w.factory().submit(&s, Submission::Online).is_err(), "a flipped bit at {i} still registered");
        }
    }
    assert!(w.factory().submit(&genuine, Submission::Online).is_ok(), "the token survived every failed attempt");
}

/// §5.9 replay of an old request (REG-005, REG-011): the token is consumed, and a request that
/// answers the wrong nonce (an old attestation) fails.
pub fn reg_attack_replay_of_an_old_request_and_of_old_attestation() {
    let w = World::dev();
    let token = w.token("alice");
    let device = w.device();
    let sealed = w.request(&device, &token);
    w.factory().submit(&sealed, Submission::Online).unwrap();
    let again = w.factory().submit(&w.request(&w.device(), &token), Submission::Online).unwrap_err();
    assert_eq!(again, RegistrationError::Token(TokenError::Used));
    // Old attestation evidence (bound to another challenge) is refused.
    let t2 = w.token("alice");
    let d2 = w.device();
    let mut body = d2.body(&t2.token, None);
    body.evidence[0].evidence = software_evidence(DeviceKeyKind::Signing, true, &token.token.nonce, &d2.sign_pub());
    let sealed = d2.seal(&w.random, &w.authority.bundle, T0, &body, None);
    assert!(matches!(w.factory().submit(&sealed, Submission::Online), Err(RegistrationError::EvidenceRejected(_))));
}

/// §5.9 emulated or modified runtime (REG-014, REG-015, REG-017): software evidence is
/// refused by strict policy, and an unknown runtime build is refused.
pub fn reg_attack_emulated_runtime_is_refused_by_strict_policy_and_unknown_builds() {
    let strict = World::new(&[], UnattestedKeys::Refuse);
    let token = strict.token("alice");
    let e = strict.factory().submit(&strict.request(&strict.device(), &token), Submission::Online).unwrap_err();
    assert_eq!(e, RegistrationError::PolicyDenied(vec!["unattested-key".into()]));
    let mut w = World::dev();
    w.authority = dev_authority(SeededRandom::new(1), T0, &["some-other-app"]).unwrap();
    let token = w.token("alice");
    let e = w.factory().submit(&w.request(&w.device(), &token), Submission::Online).unwrap_err();
    assert_eq!(e, RegistrationError::PolicyDenied(vec!["runtime-build-not-accepted".into()]));
}

/// §5.9 account takeover (REG-002, REG-041, REG-043): weak sign-in gets nothing and a
/// takeover is capped by the device limit.
pub fn reg_attack_account_takeover_is_capped_by_the_device_limit() {
    let w = World::new(&[("factory.registration.maxDevicesPerAccount", int(2))], UnattestedKeys::AllowNonProduction);
    w.registered("alice");
    w.registered("alice");
    assert_eq!(w.factory().issue_token(&w.person("alice"), RegistrationRoute::Online, 1).unwrap_err(), RegistrationError::DeviceLimitReached);
}

/// §5.9 lost or stolen device (REG-062, REG-063): marking lost needs the owning account,
/// issues a signed close certificate and the device can no longer authenticate.
pub fn reg_attack_lost_device_cannot_authenticate_and_only_its_owner_can_mark_it() {
    let w = World::dev();
    let (device, tenancy) = w.registered("alice");
    let id = w.factory().status(&tenancy).unwrap().device;
    assert_eq!(w.factory().mark_lost(&w.person("mallory"), &id).unwrap_err(), RegistrationError::WrongAccount);
    let cert = w.factory().mark_lost(&w.person("alice"), &id).unwrap();
    assert!(cert.verify(&w.authority.bundle).is_ok());
    // A forged close certificate (bit flip) does not verify.
    let mut bytes = cert.encode().unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    if let Ok(forged) = fieldseal_registration::domain::wire::CloseCertificate::decode(&bytes) {
        assert!(forged.verify(&w.authority.bundle).is_err());
    }
    // A forgotten-PIN reset needs an operator, not the account holder.
    assert!(w.factory().close(&w.person("alice"), &tenancy, CloseReason::ForgottenPin).is_err());
    let pop = device.pop_token(tenancy, "GET", "https://factory.example.org/v1/certificate", T0, [2; 16], None);
    assert_eq!(w.factory().authenticate_api(&pop.to_header(), "GET", "https://factory.example.org/v1/certificate", None).unwrap_err(), RegistrationError::Revoked);
}

/// §5.9 stolen API token, REG-070: replayed, cross-method, cross-URL, stale, foreign-key,
/// cross-tenancy and mangled PoP tokens all fail; a stolen access token is useless without
/// the key.
pub fn reg_070_replayed_and_stolen_pop_tokens_fail() {
    let w = World::dev();
    let (device, tenancy) = w.registered("alice");
    let (other_device, other_tenancy) = w.registered("mallory");
    let f = w.factory();
    let ok = device.pop_token(tenancy, "POST", URL, T0, [1; 16], None);
    f.authenticate_api(&ok.to_header(), "POST", URL, None).expect("first use");
    assert_eq!(f.authenticate_api(&ok.to_header(), "POST", URL, None).unwrap_err(), RegistrationError::Replay, "replay");
    // The same jti under a different tenancy is a different token, but only for its own key.
    let swapped = other_device.pop_token(tenancy, "POST", URL, T0, [9; 16], None);
    assert_eq!(f.authenticate_api(&swapped.to_header(), "POST", URL, None).unwrap_err(), RegistrationError::ProofInvalid, "mallory's key claiming alice's tenancy");
    let _ = other_tenancy;
    let t = device.pop_token(tenancy, "POST", URL, T0, [2; 16], None);
    assert_eq!(f.authenticate_api(&t.to_header(), "GET", URL, None).unwrap_err(), RegistrationError::ProofInvalid, "wrong method");
    assert_eq!(f.authenticate_api(&t.to_header(), "POST", "https://elsewhere.example/", None).unwrap_err(), RegistrationError::ProofInvalid, "wrong URL");
    let stale = device.pop_token(tenancy, "POST", URL, AuthorityTime(T0.0 - 301 * AuthorityTime::SECOND), [3; 16], None);
    assert_eq!(f.authenticate_api(&stale.to_header(), "POST", URL, None).unwrap_err(), RegistrationError::ProofInvalid, "stale iat");
    let future = device.pop_token(tenancy, "POST", URL, AuthorityTime(T0.0 + 301 * AuthorityTime::SECOND), [4; 16], None);
    assert_eq!(f.authenticate_api(&future.to_header(), "POST", URL, None).unwrap_err(), RegistrationError::ProofInvalid, "iat from the future");
    // A bound access token presented without the key's proof that carries its hash.
    let record = f.authenticate_api(&device.pop_token(tenancy, "POST", URL, T0, [5; 16], None).to_header(), "POST", URL, None).unwrap();
    let access = f.issue_api_token(&record).unwrap();
    let url = "https://factory.example.org/v1/posture";
    let thief = other_device.pop_token(tenancy, "GET", url, T0, [6; 16], Some(sha256(&access.value)));
    assert!(f.authenticate_api(&thief.to_header(), "GET", url, Some(&access.value)).is_err(), "a stolen access token with another key");
    // Mangled headers never panic.
    let mut rng = Seeded::new(70);
    for _ in 0..300 {
        let n = rng.below(200);
        let junk: String = rng.bytes(n).iter().map(|b| (b % 95 + 32) as char).collect();
        assert!(f.authenticate_api(&junk, "POST", URL, None).is_err());
    }
}

/// REG-010: a token signed by a factory the device does not trust, or altered in transit, is
/// refused by the device before any request is built.
pub fn reg_010_a_forged_or_foreign_token_is_refused_by_the_device() {
    let w = World::dev();
    let token = w.token("alice").token;
    let foreign = dev_authority(SeededRandom::new(99), T0, &["fieldseal-simulator"]).unwrap();
    assert_eq!(token.verify(&foreign.bundle), Err(TokenRefusal::UnknownRoot));
    let mut forged = token.clone();
    forged.factory = "https://factory.attacker.example".into();
    assert!(forged.verify(&w.authority.bundle).is_err(), "a token's factory URL is signed");
    let text_form = token.to_text().unwrap();
    assert_eq!(RegistrationToken::from_text(&text_form).unwrap(), token);
    let mut damaged = text_form.clone().into_bytes();
    let i = damaged.len() - 5;
    damaged[i] = if damaged[i] == b'A' { b'B' } else { b'A' };
    assert!(RegistrationToken::from_text(std::str::from_utf8(&damaged).unwrap()).is_err(), "the check characters catch damage");
    assert!(text_form.len() < text::MAX_QR_OBJECT * 2);
}
/// A small seeded generator (xorshift64*), so the bit-flip and junk-header cases are reproducible.
struct Seeded(u64);

impl Seeded {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next_u64() % n as u64) as usize }
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
}

// covers: REG-002, REG-003, REG-005, REG-006, REG-010, REG-011, REG-012, REG-013, REG-014, REG-015, REG-017, REG-021, REG-041, REG-062, REG-063, REG-070

const fn c(reqs: &'static [&'static str], name: &'static str, run: fn()) -> Check {
    Check { reqs, name, run }
}

const ATTACKS: &[Check] = &[
    c(&["REG-002", "REG-003"], "code phishing: weak sign-in mints no token; a device cannot originate one", reg_attack_code_phishing_there_is_no_device_originated_code_and_weak_sign_in_mints_no_token),
    c(&["REG-005", "REG-006", "REG-021"], "token theft: single use, short lived, words do not match", reg_attack_token_theft_single_use_short_lived_and_the_words_do_not_match),
    c(&["REG-012", "REG-013"], "key substitution by a relay or file carrier fails", reg_attack_key_substitution_by_a_relay_or_file_carrier_fails),
    c(&["REG-005", "REG-011"], "replay of an old request and of old attestation", reg_attack_replay_of_an_old_request_and_of_old_attestation),
    c(&["REG-014", "REG-015", "REG-017"], "an emulated runtime is refused by strict policy and unknown builds", reg_attack_emulated_runtime_is_refused_by_strict_policy_and_unknown_builds),
    c(&["REG-041"], "account takeover is capped by the device limit", reg_attack_account_takeover_is_capped_by_the_device_limit),
    c(&["REG-062", "REG-063"], "a lost device cannot authenticate and only its owner can mark it", reg_attack_lost_device_cannot_authenticate_and_only_its_owner_can_mark_it),
    c(&["REG-070"], "replayed and stolen PoP tokens fail", reg_070_replayed_and_stolen_pop_tokens_fail),
    c(&["REG-010"], "a forged or foreign token is refused by the device", reg_010_a_forged_or_foreign_token_is_refused_by_the_device),
];

/// The unit of the `reg-attacks` suite.
pub fn units() -> Vec<Unit> {
    vec![Unit::table("reg:attacks", &["reg-attacks"], ATTACKS)]
}
