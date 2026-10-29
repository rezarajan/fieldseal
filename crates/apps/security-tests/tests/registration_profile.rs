//! The runtime profile in the registration request (WIRE-130, REG-091, DIS-012): the request
//! body carries the instrument-schema version and, when the build has one, the catalogue
//! version; both are inside the digest the proof of possession signs, are decoded strictly, and
//! are recorded with the tenancy exactly as signed. Each test plays the attack against the real
//! factory use cases over the in-memory adapters.

use std::collections::BTreeMap;

use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog};
use fieldseal_adapters_memory::registration::{
    DevAuthority, MemoryFleetRegistry, MemoryIdentityProvider, MemoryNotifier,
    MemoryReceivedProgress, MemoryRegistryStore, SoftwareDevice, dev_authority, reported_version,
};
use fieldseal_adapters_memory::trust::{FixedClock, SeededRandom, SoftwareAttestationVerifier};
use fieldseal_instrument::domain::{
    Compatibility, SchemaRange, SchemaVersion, check_compatibility,
};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::TenancyId;
use fieldseal_kernel::seal::{self, SealedBox};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, cbor, crypto::tags};
use fieldseal_policy::domain::EffectivePolicy;
use fieldseal_policy::fixtures::{DocBuilder, effective};
use fieldseal_registration::application::{
    Factory, FactoryConfig, FactoryPorts, RegistrationError, Submission,
};
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::domain::wire::{RequestBody, factory_sealing_key, pop_message};
use fieldseal_registration::domain::{
    AuthenticatedPerson, IssuedToken, MethodAssurance, RegistrationRoute, ReportedProfile,
    ReportedVersion, TenancyRecord, TenancyState, TenancyTerms, Window,
};
use fieldseal_registration::ports::RegistryStore;
use fieldseal_trust::ports::SourceRng;

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

impl World {
    fn new() -> Self {
        let authority = dev_authority(SeededRandom::new(1), T0, &["fieldseal-simulator"])
            .expect("dev authority");
        let config = FactoryConfig {
            factory_url: "https://factory.example.org".into(),
            signing_key: *authority.signing.key_id(),
            sealing_key: *authority.sealing.key_id(),
            terms: TenancyTerms {
                record_key: *authority.record.key_id(),
                window: Window {
                    not_before: T0,
                    not_after: AuthorityTime(T0.0 + 90 * AuthorityTime::DAY),
                    grace_ms: 30 * AuthorityTime::DAY,
                },
                cohorts: vec![],
            },
            unattested: UnattestedKeys::AllowNonProduction,
            posture_nonce_ttl_ms: 10 * MINUTE,
            access_token_ttl_ms: 10 * MINUTE,
        };
        let idp = MemoryIdentityProvider::new();
        for (login, sub) in [
            ("alice", "sub-alice"),
            ("bob", "sub-bob"),
            ("carol", "sub-carol"),
        ] {
            idp.add(
                login,
                sub,
                &["collector"],
                &["hwk", "user"],
                MethodAssurance::FromProvider,
            );
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
            policy: effective(&[DocBuilder::deployment("test", "1.0.0").build()]),
            config,
        }
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

    fn token(&self) -> IssuedToken {
        self.token_for("alice")
    }

    fn token_for(&self, login: &str) -> IssuedToken {
        self.factory()
            .issue_token(&self.person(login), RegistrationRoute::Online, 1)
            .expect("token")
    }

    /// Submits a request with `profile` as `alice` and confirms it; the tenancy is registered.
    fn register(&self, device: &SoftwareDevice, profile: ReportedProfile) -> TenancyRecord {
        self.register_as("alice", device, profile)
    }

    /// Like [`Self::register`], for another account (an account may hold few devices).
    fn register_as(
        &self,
        login: &str,
        device: &SoftwareDevice,
        profile: ReportedProfile,
    ) -> TenancyRecord {
        let token = self.token_for(login);
        let body = device.body_with_profile(&token.token, Some("blue"), profile);
        let sealed = device.seal(&self.random, &self.authority.bundle, T0, &body, None);
        let submitted = self
            .factory()
            .submit(&sealed, Submission::Online)
            .expect("submit");
        let record = self
            .factory()
            .confirm(&self.person(login).account, &submitted.tenancy.id)
            .expect("confirm");
        assert_eq!(record.state, TenancyState::Registered);
        record
    }

    /// Seals `body` to the factory with a proof of possession that `device` signed over
    /// `signed`: the sealed body may differ from what was signed.
    fn seal_value(&self, device: &SoftwareDevice, body: Value, signed: &RequestBody) -> SealedBox {
        let pop = device.sign_message(&signed.pop_message());
        let factory = factory_sealing_key(&self.authority.bundle, T0)
            .expect("the trust bundle certifies a registration sealing key");
        let plaintext = cbor::map([("body", body), ("pop", Value::Bytes(pop.0))]);
        seal::seal_value(
            &mut SourceRng(&self.random),
            &factory,
            &tags::REGISTRATION_SEAL,
            &plaintext,
        )
        .expect("sealable")
    }

    /// A request whose body is `body_of(genuine)` edited, signed properly over the edited body:
    /// only the edit can make the factory refuse it.
    fn well_signed(
        &self,
        device: &SoftwareDevice,
        token: &IssuedToken,
        edit: impl FnOnce(&mut BTreeMap<String, Value>),
    ) -> SealedBox {
        let genuine = device.body(&token.token, Some("blue"));
        let Value::Map(mut m) = genuine.to_value() else {
            unreachable!("a body is a map")
        };
        edit(&mut m);
        let edited = Value::Map(m);
        let digest = sha256(&cbor::encode(&edited).expect("encodable"));
        let pop = device.sign_message(&pop_message(&genuine.nonce, &digest));
        let factory =
            factory_sealing_key(&self.authority.bundle, T0).expect("registration sealing key");
        let plaintext = cbor::map([("body", edited), ("pop", Value::Bytes(pop.0))]);
        seal::seal_value(
            &mut SourceRng(&self.random),
            &factory,
            &tags::REGISTRATION_SEAL,
            &plaintext,
        )
        .expect("sealable")
    }

    fn recorded(&self, id: &TenancyId) -> Option<TenancyRecord> {
        self.store.tenancy(id).expect("store")
    }
}

fn profile(major: u32, minor: u32, patch: u32, catalogue: Option<&str>) -> ReportedProfile {
    ReportedProfile {
        instrument_schema: ReportedVersion {
            major,
            minor,
            patch,
        },
        catalogue_reference: catalogue.map(str::to_owned),
    }
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// Asserts the factory refused the request as malformed, recorded no tenancy for the device and
/// left the token usable: the genuine request still registers.
fn assert_refused_and_nothing_recorded(
    w: &World,
    device: &SoftwareDevice,
    token: &IssuedToken,
    sealed: &SealedBox,
    what: &str,
) {
    let err = w
        .factory()
        .submit(sealed, Submission::Online)
        .expect_err(what);
    assert!(
        matches!(err, RegistrationError::Malformed(_)),
        "{what}: refused as malformed, not {err:?}"
    );
    assert_eq!(
        w.recorded(&device.tenancy()),
        None,
        "{what}: nothing is recorded"
    );
    let genuine = device.seal(
        &w.random,
        &w.authority.bundle,
        T0,
        &device.body(&token.token, Some("blue")),
        None,
    );
    assert!(
        w.factory().submit(&genuine, Submission::Online).is_ok(),
        "{what}: the token was not spent by the refused request"
    );
}

// covers: WIRE-130
#[test]
fn wire_130_a_request_without_schema_is_refused() {
    let w = World::new();
    let (device, token) = (w.device(), w.token());
    let sealed = w.well_signed(&device, &token, |m| {
        m.remove("schema");
    });
    assert_refused_and_nothing_recorded(&w, &device, &token, &sealed, "no schema");
}

// covers: WIRE-130
#[test]
fn wire_130_unknown_keys_are_still_refused() {
    let w = World::new();
    for (key, value) in [
        ("extra", text("x")),
        ("schemas", text("1.0.0")),
        ("profile", Value::Map(BTreeMap::new())),
    ] {
        let (device, token) = (w.device(), w.token());
        let sealed = w.well_signed(&device, &token, |m| {
            m.insert(key.into(), value.clone());
        });
        assert_refused_and_nothing_recorded(
            &w,
            &device,
            &token,
            &sealed,
            &format!("unknown key {key}"),
        );
    }
}

// covers: WIRE-130
#[test]
fn wire_130_over_long_values_are_refused() {
    let w = World::new();
    let cases: Vec<(&str, &str, String)> = vec![
        (
            "schema",
            "a schema of 33 bytes",
            format!("1.0.{}", "9".repeat(27)),
        ),
        (
            "schema",
            "a schema of 5 KiB",
            format!("1.0.{}", "9".repeat(5_000)),
        ),
        ("catalogue", "a catalogue of 65 bytes", "c".repeat(65)),
        ("catalogue", "a catalogue of 5 KiB", "c".repeat(5_000)),
    ];
    for (key, what, long) in cases {
        let (device, token) = (w.device(), w.token());
        let sealed = w.well_signed(&device, &token, |m| {
            m.insert(key.into(), Value::Text(long.clone()));
        });
        assert_refused_and_nothing_recorded(&w, &device, &token, &sealed, what);
    }
    // The limits themselves are accepted: a 64-byte catalogue is a valid value.
    let (device, token) = (w.device(), w.token());
    let sealed = w.well_signed(&device, &token, |m| {
        m.insert("catalogue".into(), text(&"c".repeat(64)));
    });
    assert!(
        w.factory().submit(&sealed, Submission::Online).is_ok(),
        "a catalogue of exactly 64 bytes is accepted"
    );
}

// covers: WIRE-132
#[test]
fn wire_132_changing_the_reported_schema_breaks_the_proof_of_possession() {
    let w = World::new();
    // The device signs a body that reports 1.0.0; a carrier edits the profile after signing.
    for (what, key, value) in [
        ("schema raised", "schema", "1.9.0"),
        ("schema lowered", "schema", "0.1.0"),
        ("catalogue added", "catalogue", "ui-reference-9"),
    ] {
        let (device, token) = (w.device(), w.token());
        let signed = device.body(&token.token, Some("blue"));
        let Value::Map(mut m) = signed.to_value() else {
            unreachable!("a body is a map")
        };
        m.insert(key.into(), text(value));
        let sealed = w.seal_value(&device, Value::Map(m), &signed);
        assert_eq!(
            w.factory().submit(&sealed, Submission::Online).unwrap_err(),
            RegistrationError::ProofInvalid,
            "{what}"
        );
        assert_eq!(
            w.recorded(&device.tenancy()),
            None,
            "{what}: nothing is recorded"
        );
    }
    // The digest itself moves with each field.
    let device = w.device();
    let token = w.token();
    let base = device.body(&token.token, None).digest();
    assert_ne!(
        base,
        device
            .body_with_profile(&token.token, None, profile(1, 0, 1, None))
            .digest()
    );
    assert_ne!(
        base,
        device
            .body_with_profile(&token.token, None, profile(1, 0, 0, Some("ui")))
            .digest()
    );
}

// covers: REG-091
#[test]
fn reg_091_the_recorded_profile_is_the_signed_one() {
    let w = World::new();
    let signed = profile(1, 2, 3, Some("ui-reference-4.1"));
    let record = w.register(&w.device(), signed.clone());
    assert_eq!(record.profile, signed);
    assert_eq!(
        w.recorded(&record.id).expect("recorded").profile,
        signed,
        "the stored record holds what was signed"
    );
    let without = w.register(&w.device(), profile(1, 0, 0, None));
    assert_eq!(
        w.recorded(&without.id).expect("recorded").profile,
        profile(1, 0, 0, None),
        "no catalogue stays none"
    );
}

// covers: REG-091
#[test]
fn reg_091_a_malformed_semver_is_refused_and_nothing_is_recorded() {
    let w = World::new();
    for bad in [
        "",
        "1",
        "1.0",
        "1.0.0.0",
        "01.0.0",
        "1.0.0-rc1",
        "1.0.0+build",
        "v1.0.0",
        "1.-1.0",
        "1.0.x",
        " 1.0.0",
        "1.0.0 ",
        "99999999999.0.0",
    ] {
        let (device, token) = (w.device(), w.token());
        let sealed = w.well_signed(&device, &token, |m| {
            m.insert("schema".into(), text(bad));
        });
        assert_refused_and_nothing_recorded(
            &w,
            &device,
            &token,
            &sealed,
            &format!("schema {bad:?}"),
        );
    }
    for bad in [
        Value::Int(1),
        Value::Bytes(vec![1]),
        text(""),
        text("ui\nreference"),
        text("ui reference"),
        text("ui\u{202e}reference"),
        text("caf\u{e9}"),
    ] {
        let (device, token) = (w.device(), w.token());
        let sealed = w.well_signed(&device, &token, |m| {
            m.insert("catalogue".into(), bad.clone());
        });
        assert_refused_and_nothing_recorded(
            &w,
            &device,
            &token,
            &sealed,
            &format!("catalogue {bad:?}"),
        );
    }
}

// covers: REG-091
#[test]
fn reg_091_a_key_roll_cannot_raise_the_profile_without_the_new_key() {
    let w = World::new();
    let current = w.device();
    let tenancy = w.register(&current, profile(1, 0, 0, None)).id;
    let next = w.device();

    // The new key did not sign the raised profile (the body was edited after signing): refused.
    let token = w.token();
    let signed = next.body(&token.token, Some("blue"));
    let Value::Map(mut m) = signed.to_value() else {
        unreachable!("a body is a map")
    };
    m.insert("schema".into(), text("1.9.0"));
    let pop = next.sign_message(&signed.pop_message());
    let endorsement = current.sign_message(&signed.pop_message());
    let factory = factory_sealing_key(&w.authority.bundle, T0).expect("registration sealing key");
    let roll = cbor::map([
        ("tenancy", Value::Bytes(tenancy.as_bytes().to_vec())),
        ("sig", Value::Bytes(endorsement.0)),
    ]);
    let plaintext = cbor::map([
        ("body", Value::Map(m)),
        ("pop", Value::Bytes(pop.0)),
        ("roll", roll),
    ]);
    let sealed = seal::seal_value(
        &mut SourceRng(&w.random),
        &factory,
        &tags::REGISTRATION_SEAL,
        &plaintext,
    )
    .expect("sealable");
    assert_eq!(
        w.factory().submit(&sealed, Submission::Online).unwrap_err(),
        RegistrationError::ProofInvalid
    );
    assert_eq!(
        w.recorded(&tenancy).expect("recorded").profile,
        profile(1, 0, 0, None),
        "the recorded profile is unchanged"
    );

    // Only the current key endorsed a raised profile; the new key's proof is missing: refused.
    let token = w.token();
    let raised = next.body_with_profile(&token.token, Some("blue"), profile(1, 9, 0, None));
    let stranger = w.device();
    let sealed = next.seal(
        &w.random,
        &w.authority.bundle,
        T0,
        &raised,
        Some((&stranger, tenancy)),
    );
    assert_eq!(
        w.factory().submit(&sealed, Submission::Online).unwrap_err(),
        RegistrationError::ProofInvalid
    );
    assert_eq!(
        w.recorded(&tenancy).expect("recorded").profile,
        profile(1, 0, 0, None)
    );

    // Signed by both keys, the roll records the profile it carries.
    let token = w.token();
    let raised = next.body_with_profile(
        &token.token,
        Some("blue"),
        profile(1, 9, 0, Some("ui-reference-9")),
    );
    let sealed = next.seal(
        &w.random,
        &w.authority.bundle,
        T0,
        &raised,
        Some((&current, tenancy)),
    );
    let rolled = w
        .factory()
        .submit(&sealed, Submission::Online)
        .expect("a signed roll")
        .tenancy;
    assert_eq!(rolled.profile, profile(1, 9, 0, Some("ui-reference-9")));
    assert_eq!(
        w.recorded(&tenancy).expect("recorded").profile,
        profile(1, 9, 0, Some("ui-reference-9"))
    );
}

// covers: DIS-012
#[test]
fn dis_012_an_older_reported_schema_never_widens_what_a_tenancy_may_receive() {
    let w = World::new();
    // DIS-012 judges an instrument's range against the version recorded at registration.
    let needs_1_2 = SchemaRange::parse("^1.2").expect("range");
    let admits = |record: &TenancyRecord| {
        let v = reported_version_to_schema(record.profile.instrument_schema);
        check_compatibility(needs_1_2, v) == Compatibility::Compatible
    };
    let old = w.register_as("alice", &w.device(), profile(1, 0, 0, None));
    let new = w.register_as("bob", &w.device(), profile(1, 2, 0, None));
    assert!(
        !admits(&old),
        "a runtime that reported 1.0.0 is not given an instrument that needs 1.2"
    );
    assert!(admits(&new));

    // A runtime that is rolled onto an older build reports it, and the recorded version follows
    // it down: the tenancy stops receiving what the old build cannot open.
    let current = w.device();
    let tenancy = w.register_as("carol", &current, profile(1, 2, 0, None)).id;
    assert!(admits(&w.recorded(&tenancy).expect("recorded")));
    let next = w.device();
    let token = w.token_for("carol");
    let downgraded = next.body_with_profile(&token.token, Some("blue"), profile(1, 0, 0, None));
    let sealed = next.seal(
        &w.random,
        &w.authority.bundle,
        T0,
        &downgraded,
        Some((&current, tenancy)),
    );
    w.factory()
        .submit(&sealed, Submission::Online)
        .expect("a signed roll");
    assert!(
        !admits(&w.recorded(&tenancy).expect("recorded")),
        "the downgraded runtime is no longer given 1.2 instruments"
    );
    // And the conversion the adapters use keeps the numbers.
    assert_eq!(
        reported_version(SchemaVersion {
            major: 1,
            minor: 2,
            patch: 3
        }),
        ReportedVersion {
            major: 1,
            minor: 2,
            patch: 3
        }
    );
}

fn reported_version_to_schema(v: ReportedVersion) -> SchemaVersion {
    SchemaVersion {
        major: v.major,
        minor: v.minor,
        patch: v.patch,
    }
}
