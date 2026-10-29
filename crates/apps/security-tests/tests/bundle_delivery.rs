//! Bundle delivery (SR-2): `GET /v1/bundle` serves only what is stored, to the tenancy whose
//! key signed the request, and the bytes are sealed to that tenancy's agreement key (DIS-020).
//!
//! The bundles are built by the demo authority for devices whose keys the test holds, stored
//! in a bundle store, and fetched through `FactoryHttp::handle` over a factory in which the
//! same devices registered with their own keys.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};

use fieldseal_adapters_file::store::FileRegistryStore;
use fieldseal_adapters_file::tenancy::FileTenancyRegistry;
use fieldseal_adapters_factory_http::{BundleRoutes, FactoryHttp, HttpConfig, Request, Response};
use fieldseal_adapters_memory::demo::{DEMO_SCHEMA, DemoDevice, DemoWorld};
use fieldseal_adapters_memory::distribution::{MemoryBundleStore, SoftwareAgreementKey};
use fieldseal_adapters_memory::delivery::MemoryPopLedger;
use fieldseal_adapters_memory::intake::{MemoryDataPlatform, MemoryInstrumentSource, MemoryRosterHistory, MemorySubmissionStore};
use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog};
use fieldseal_adapters_memory::registration::{
    DevAuthority, MemoryFleetRegistry, MemoryIdentityProvider, MemoryNotifier, MemoryReceivedProgress, MemoryRegistryStore, SoftwareDevice, dev_authority,
};
use fieldseal_adapters_memory::trust::{FixedClock, SeededRandom, SoftwareAttestationVerifier};
use fieldseal_delivery::domain::UploadRoute;
use fieldseal_distribution::application::{BuildRequest, BundleDelivery};
use fieldseal_distribution::domain::{BundleContent, BundleFile, ConsentState, MAX_BUNDLE_FILE, Roster, RosterEntry, RuntimeProfile};
use fieldseal_distribution::ports::{AgreementError, AgreementKey, BundleStore};
use fieldseal_intake::gate::IntakeService;
use fieldseal_intake::upload::{UploadRefusal, UploadService};
use fieldseal_kernel::crypto::tags;
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{CohortId, Generation, Salt, SubjectId};
use fieldseal_kernel::seal::{RecipientSecret, Suite};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::value::Value;
use fieldseal_kernel::cbor;
use fieldseal_policy::domain::EffectivePolicy;
use fieldseal_policy::fixtures::{DocBuilder, effective};
use fieldseal_publishing::domain::{ArtefactKind, Publication};
use fieldseal_registration::application::{Factory, FactoryConfig, FactoryPorts, Submission};
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::domain::{MethodAssurance, RegistrationRoute, TenancyState, TenancyTerms, Window};
use fieldseal_registration::ports::RegistryStore;
use fieldseal_security_tests::{CANARIES, assert_no_canary};

const T0: AuthorityTime = AuthorityTime(1_800_000_000_000);
const HTTPS: &str = "https://factory.example.org";

static JTI: AtomicU8 = AtomicU8::new(1);

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// The keys the demo authority derives for `label`, as a device that holds them.
fn device_keys(label: &str) -> SoftwareDevice {
    let scalar = |purpose: &str| *sha256(format!("fieldseal.dev/demo/{purpose}/{label}").as_bytes()).as_bytes();
    SoftwareDevice::from_keys(SigningKey::from_scalar(&scalar("sign")).expect("scalar"), RecipientSecret::from_bytes(Suite::Fs1P, &scalar("agree")).expect("scalar"))
}

fn roster(cohort: &str, canary: &str) -> Roster {
    Roster {
        cohort: CohortId::new(cohort).expect("id"),
        version: 1,
        generation: Generation(1),
        entries: vec![RosterEntry {
            ordinal: 1,
            subject: SubjectId::new("s-001").expect("id"),
            display: canary.to_owned(),
            attributes: BTreeMap::from([("age".to_owned(), Value::Int(9))]),
            consent: ConsentState::Unknown,
            prior_status: None,
        }],
    }
}

struct World {
    demo: DemoWorld,
    instrument: Publication,
    authority: DevAuthority<SeededRandom>,
    store: MemoryRegistryStore,
    bundles: MemoryBundleStore,
    idp: MemoryIdentityProvider,
    clock: FixedClock,
    random: SeededRandom,
    engine: BuiltInPolicyEngine,
    log: MemoryDecisionLog,
    verifier: SoftwareAttestationVerifier,
    progress: MemoryReceivedProgress,
    fleet: MemoryFleetRegistry,
    notifier: MemoryNotifier,
    policy: EffectivePolicy,
    config: FactoryConfig,
}

struct Device {
    demo: DemoDevice,
    keys: SoftwareDevice,
}

impl World {
    fn new() -> Self {
        let demo = DemoWorld::new(1, T0).expect("world");
        let doc = cbor::map([
            ("apiVersion", text("fieldseal.dev/v1alpha1")),
            ("kind", text("Instrument")),
            ("metadata", cbor::map([("name", text("health-check")), ("version", text("1.0.0"))])),
            ("spec", cbor::map([("schema", text("^1.0")), ("items", Value::Array(vec![cbor::map([("label", text("Age {$roster.age}")), ("from", text("roster.age"))])]))])),
        ]);
        let instrument = demo.publish(ArtefactKind::Instrument, "health-check", "1.0.0", cbor::encode(&doc).expect("encodes"), Some(Salt::from([0x5a; 32]))).expect("publishes");
        let authority = dev_authority(SeededRandom::new(1), T0, &["fieldseal-simulator"]).expect("authority");
        let config = FactoryConfig {
            factory_url: HTTPS.into(),
            signing_key: *authority.signing.key_id(),
            sealing_key: *authority.sealing.key_id(),
            terms: TenancyTerms {
                record_key: *authority.record.key_id(),
                window: Window { not_before: T0, not_after: AuthorityTime(T0.0 + 90 * AuthorityTime::DAY), grace_ms: 30 * AuthorityTime::DAY },
                cohorts: vec![],
            },
            unattested: UnattestedKeys::AllowNonProduction,
            posture_nonce_ttl_ms: 600_000,
            access_token_ttl_ms: 600_000,
        };
        let idp = MemoryIdentityProvider::new();
        for login in ["alice", "bob"] {
            idp.add(login, &format!("sub-{login}"), &["collector"], &["hwk", "user"], MethodAssurance::FromProvider);
        }
        Self {
            demo,
            instrument,
            authority,
            store: MemoryRegistryStore::new(),
            bundles: MemoryBundleStore::new(),
            idp,
            clock: FixedClock::new(T0),
            random: SeededRandom::new(2),
            engine: BuiltInPolicyEngine,
            log: MemoryDecisionLog::new(),
            verifier: SoftwareAttestationVerifier,
            progress: MemoryReceivedProgress::new(),
            fleet: MemoryFleetRegistry::new(),
            notifier: MemoryNotifier::new(),
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

    /// A device of `login` that registers with the factory, whose bundle the demo authority
    /// builds with `canary` in its roster of `cohort` and stores for delivery.
    fn device(&self, login: &str, cohort: &str, canary: &str) -> Device {
        let keys = device_keys(login);
        let person = self.idp.person(login).expect("person");
        let token = self.factory().issue_token(&person, RegistrationRoute::Online, 1).expect("token");
        let sealed = keys.seal(&self.random, &self.authority.bundle, T0, &keys.body(&token.token, Some(login)), None);
        let pending = self.factory().submit(&sealed, Submission::Online).expect("submit").tenancy;
        assert_eq!(self.factory().confirm(&person.account, &pending.id).expect("confirm").state, TenancyState::Registered);
        let demo = self.demo.register(login, &[(cohort, 1)], true, RuntimeProfile { instrument_schema: DEMO_SCHEMA, localisation_reference: None }).expect("registers");
        assert_eq!(demo.tenancy, keys.tenancy(), "the demo authority and the factory name the same tenancy");
        self.demo.assign_rosters(&demo, vec![roster(cohort, canary)]);
        let built = self.demo.build(&self.demo.built_in_policy(), &BuildRequest::new(demo.tenancy, vec![*self.instrument.address()])).expect("builds");
        self.bundles.put(&built.sealed).expect("put");
        Device { demo, keys }
    }

    fn call(&self, req: &Request) -> Response {
        let factory = self.factory();
        let delivery = BundleDelivery::new(&self.store, &self.bundles);
        FactoryHttp::new(&factory, &self.idp, HttpConfig { public_url: HTTPS.into(), session_ttl_ms: 3_600_000 })
            .with_bundle_routes(BundleRoutes { fetch: &delivery, download: &delivery })
            .handle(req)
    }

    fn get(&self, path: &str, pop: &str) -> Response {
        self.call(&Request::new("GET", path, BTreeMap::from([("fieldseal-pop".to_owned(), pop.to_owned())]), vec![]))
    }
}

impl Device {
    fn pop(&self, url: &str, jti: u8) -> String {
        self.keys.pop_token(self.keys.tenancy(), "GET", url, T0, [jti; 16], None).to_header()
    }

    fn fresh_pop(&self, url: &str) -> String {
        self.pop(url, JTI.fetch_add(1, Ordering::SeqCst))
    }

    fn open(&self, bytes: &[u8]) -> Result<BundleContent, AgreementError> {
        let file = BundleFile::decode(bytes, MAX_BUNDLE_FILE).expect("a bundle file");
        let plain = self.demo.agreement_key().open(&tags::BUNDLE_SEAL, self.demo.tenancy.as_bytes(), &file.sealed)?;
        Ok(BundleContent::decode(&plain).expect("content"))
    }
}

fn error(r: &Response) -> String {
    serde_json::from_slice::<serde_json::Value>(&r.body).ok().and_then(|j| j["error"].as_str().map(str::to_owned)).unwrap_or_default()
}

#[test]
fn dis_021_a_stolen_token_yields_bytes_only_the_device_can_open() {
    let w = World::new();
    let alice = w.device("alice", "cohort-a", CANARIES[0]);
    // Whoever holds a token that was not yet used gets the stored bytes...
    let stolen = alice.fresh_pop(&format!("{HTTPS}/v1/bundle"));
    let r = w.get("/v1/bundle", &stolen);
    assert_eq!(r.status, 200);
    // ...which an attacker's key cannot open, and which show no personal data without it.
    let attacker = SoftwareAgreementKey::new(RecipientSecret::from_bytes(Suite::Fs1P, &[7; 32]).expect("scalar")).expect("key");
    let file = BundleFile::decode(&r.body, MAX_BUNDLE_FILE).expect("file");
    assert!(matches!(attacker.open(&tags::BUNDLE_SEAL, alice.demo.tenancy.as_bytes(), &file.sealed), Err(AgreementError::WrongRecipient)));
    assert_no_canary("the bytes of the bundle", &r.body);
    // The device opens it.
    assert_eq!(alice.open(&r.body).expect("opens").rosters[0].entries[0].display, CANARIES[0]);
}

#[test]
fn dis_040_a_token_for_another_url_is_refused() {
    let w = World::new();
    let alice = w.device("alice", "cohort-a", CANARIES[0]);
    for url in ["https://evil.example/v1/bundle", &format!("{HTTPS}/v1/certificate"), &format!("{HTTPS}/v1/bundle/")] {
        let r = w.get("/v1/bundle", &alice.fresh_pop(url));
        assert_eq!((r.status, error(&r).as_str()), (401, "proof-invalid"), "{url}");
    }
    // A GET token does not serve another method either.
    let post = Request::new("POST", "/v1/bundle", BTreeMap::from([("fieldseal-pop".to_owned(), alice.fresh_pop(&format!("{HTTPS}/v1/bundle")))]), vec![]);
    assert_ne!(w.call(&post).status, 200);
}

#[test]
fn reg_082_a_withheld_tenancy_can_still_upload() {
    // Withholding stops bundles and nothing else: a flagged tenancy is refused the bundle with
    // its reasons, and it still authenticates to the factory's API, which is what lets it
    // report its posture and clear the flag (REG-081). Intake's upload gate does not read the
    // bundle release decision, and neither does it read a policy hold on the stored bundle.
    let w = World::new();
    let alice = w.device("alice", "cohort-a", CANARIES[0]);
    let mut record = w.store.tenancy(&alice.demo.tenancy).expect("store").expect("tenancy");
    record.state = TenancyState::Flagged;
    w.store.put_tenancy(&record).expect("put");
    let r = w.get("/v1/bundle", &alice.fresh_pop(&format!("{HTTPS}/v1/bundle")));
    assert_eq!((r.status, error(&r).as_str()), (403, "withheld"));
    assert_no_canary("the refusal", &r.body);
    // A policy hold on the stored bundle is refused the same way.
    record.state = TenancyState::Registered;
    w.store.put_tenancy(&record).expect("put");
    w.bundles.set_withheld(&alice.demo.tenancy, Some(&["policy-hold".to_owned()])).expect("withheld");
    let r = w.get("/v1/bundle", &alice.fresh_pop(&format!("{HTTPS}/v1/bundle")));
    assert_eq!((r.status, error(&r).as_str()), (403, "withheld"));
    assert_no_canary("the refusal", &r.body);
    record.state = TenancyState::Flagged;
    w.store.put_tenancy(&record).expect("put");
    let api = w.get("/v1/certificate", &alice.fresh_pop(&format!("{HTTPS}/v1/certificate")));
    assert_eq!(api.status, 200);

    // The upload endpoint reads the same registry state (here a file journal holding the same
    // record) and still authenticates the tenancy's token: Flagged is not deny-listed.
    let upload_as = |state: TenancyState, jti: u8| {
        let dir = std::env::temp_dir().join(format!("fieldseal-sec-bundle-delivery-{}-{jti}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let mut record = record.clone();
        record.state = state;
        FileRegistryStore::open(&dir).expect("journal").put_tenancy(&record).expect("put");
        let registry = FileTenancyRegistry::new(&dir);
        let (store, rosters, instruments, platform, ledger) =
            (MemorySubmissionStore::new(), MemoryRosterHistory::new(), MemoryInstrumentSource::new(), MemoryDataPlatform::new(), MemoryPopLedger::new());
        let gate = IntakeService {
            store: &store,
            registry: &registry,
            rosters: &rosters,
            instruments: &instruments,
            platform: &platform,
            custody: &w.authority.custody,
            policy: &w.engine,
            effective: &w.policy,
            random: &w.random,
            trust: &w.authority.bundle,
            revocations: vec![],
            receipt_key: *w.authority.receipt.key_id(),
            caller: "security-tests",
        };
        let urls = [HTTPS.to_owned()];
        let upload = UploadService { intake: &gate, ledger: &ledger, receiver_key: *w.authority.receipt.key_id(), receiver_certificate: &w.authority.receipt, public_urls: &urls };
        let header = alice.keys.pop_token(alice.keys.tenancy(), "POST", &UploadRoute::Tenancy.url(HTTPS), T0, [jti; 16], None).to_header();
        let result = upload.authenticate(Some(&header), "POST", UploadRoute::Tenancy, T0);
        let _ = std::fs::remove_dir_all(&dir);
        result
    };
    assert_eq!(upload_as(TenancyState::Flagged, 0x77), Ok(alice.demo.tenancy), "a flagged tenancy's upload is authenticated");
    // Only a lost tenancy is deny-listed.
    let refused = upload_as(TenancyState::Lost, 0x78);
    assert!(matches!(refused, Err(UploadRefusal::TokenRejected("tenancy revoked"))), "{refused:?}");
}

#[test]
fn dis_020_neither_bundle_bytes_nor_decrypted_contents_contain_the_record_key_secret_or_the_export_pseudonymisation_key() {
    let w = World::new();
    let alice = w.device("alice", "cohort-a", CANARIES[0]);
    let bob = w.device("bob", "cohort-b", CANARIES[1]);
    // The keys never leave their holders; these are the strings a leak of either would put in
    // a bundle, and the record key a bundle does carry is its public identifier only.
    let export_key = [0xE9u8; 32];
    for d in [&alice, &bob] {
        let r = w.get("/v1/bundle", &d.fresh_pop(&format!("{HTTPS}/v1/bundle")));
        let plain = d.open(&r.body).expect("opens");
        let certificate = plain.certificate.as_ref().expect("certificate");
        assert_eq!(certificate.record_key, w.demo.record.id, "the certificate names the record key, it does not hold it");
        let everything = plain.encode().expect("encodes");
        for (name, haystack) in [("the bundle bytes", &r.body), ("the decrypted contents", &everything)] {
            assert!(!haystack.windows(32).any(|win| win == export_key), "{name} hold the export pseudonymisation key");
            assert!(!haystack.windows(5).any(|win| win == b"nsec:"), "{name}");
        }
    }
}

#[test]
fn dis_040_the_replay_ledger_is_shared_with_the_other_pop_routes() {
    let w = World::new();
    let alice = w.device("alice", "cohort-a", CANARIES[0]);
    // The `jti` seen at the certificate route is spent for the bundle route too.
    let jti = 200;
    assert_eq!(w.get("/v1/certificate", &alice.pop(&format!("{HTTPS}/v1/certificate"), jti)).status, 200);
    let r = w.get("/v1/bundle", &alice.pop(&format!("{HTTPS}/v1/bundle"), jti));
    assert_eq!((r.status, error(&r).as_str()), (401, "replay"));
    // And the reverse.
    assert_eq!(w.get("/v1/bundle", &alice.pop(&format!("{HTTPS}/v1/bundle"), 201)).status, 200);
    let r = w.get("/v1/certificate", &alice.pop(&format!("{HTTPS}/v1/certificate"), 201));
    assert_eq!((r.status, error(&r).as_str()), (401, "replay"));
}

#[test]
fn dis_013_neither_account_receives_the_others_cohort_roster() {
    let w = World::new();
    let alice = w.device("alice", "cohort-a", CANARIES[0]);
    let bob = w.device("bob", "cohort-b", CANARIES[1]);
    let from_alice = w.get("/v1/bundle", &alice.fresh_pop(&format!("{HTTPS}/v1/bundle")));
    let from_bob = w.get("/v1/bundle", &bob.fresh_pop(&format!("{HTTPS}/v1/bundle")));
    let cohorts = |d: &Device, r: &Response| d.open(&r.body).expect("opens").rosters.iter().map(|x| x.cohort.as_str().to_owned()).collect::<Vec<_>>();
    assert_eq!(cohorts(&alice, &from_alice), vec!["cohort-a".to_owned()]);
    assert_eq!(cohorts(&bob, &from_bob), vec!["cohort-b".to_owned()]);
    // Each bundle opens only with its own device's key.
    assert!(matches!(bob.open(&from_alice.body), Err(AgreementError::WrongRecipient)));
    assert!(matches!(alice.open(&from_bob.body), Err(AgreementError::WrongRecipient)));
    // A token names its own tenancy: one device cannot ask for the other's bundle.
    assert_ne!(from_alice.body, from_bob.body);
}
