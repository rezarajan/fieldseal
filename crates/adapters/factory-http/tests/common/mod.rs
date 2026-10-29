//! Shared fixture of the operator API tests: the in-memory factory over a stub
//! `BearerVerifier`, with devices that register for real so that certificates can be compared.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use fieldseal_adapters_factory_http::{
    BearerError, BearerVerifier, FactoryHttp, HttpConfig, OperatorEvent, OperatorEvents, ReconcileNotify, Request, Response,
};
use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog};
use fieldseal_adapters_memory::registration::{
    DevAuthority, MemoryFleetRegistry, MemoryIdentityProvider, MemoryNotifier, MemoryReceivedProgress, MemoryRegistryStore, SoftwareDevice,
    dev_authority,
};
use fieldseal_adapters_memory::trust::{FixedClock, SeededRandom, SoftwareAttestationVerifier};
use fieldseal_kernel::id::{CohortId, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, cbor};
use fieldseal_policy::domain::EffectivePolicy;
use fieldseal_policy::fixtures::{DocBuilder, effective};
use fieldseal_registration::application::{Factory, FactoryConfig, FactoryPorts, OperatorPorts, Submission};
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::domain::{AuthenticatedPerson, MethodAssurance, RegistrationRoute, TenancyRecord, TenancyState, TenancyTerms, Window};
use fieldseal_registration::ports::{CohortDirectory, IssueOutcome, RegistryStore, RosterIssuer, SurveyDirectory};

pub const T0: AuthorityTime = AuthorityTime(1_800_000_000_000);
pub const OPERATOR_TOKEN: &str = "operator-token";
pub const HTTPS: &str = "https://factory.example.org";

/// Surveys that exist.
pub struct Surveys(pub BTreeSet<String>);

impl SurveyDirectory for Surveys {
    fn exists(&self, name: &str) -> bool {
        self.0.contains(name)
    }
}

/// Cohorts that exist.
pub struct Cohorts(pub BTreeSet<String>);

impl CohortDirectory for Cohorts {
    fn exists(&self, cohort: &CohortId) -> bool {
        self.0.contains(cohort.as_str())
    }
}

/// A roster issuer that is never asked.
pub struct NoRosters;

impl RosterIssuer for NoRosters {
    fn issue(&self, _: &CohortId, _: &[u8], _: &[String]) -> IssueOutcome {
        IssueOutcome::Invalid("no roster store in this test".into())
    }
}

/// A verifier that knows a few tokens and refuses every other.
pub struct StubBearer(pub BTreeMap<String, Result<AuthenticatedPerson, BearerError>>);

impl BearerVerifier for StubBearer {
    fn verify(&self, token: &str) -> Result<AuthenticatedPerson, BearerError> {
        self.0.get(token).cloned().unwrap_or_else(|| Err(BearerError::Invalid("unknown token".into())))
    }

    /// The in-memory identity provider's rule: the subject is the account id.
    fn account_for_subject(&self, sub: &str) -> fieldseal_registration::domain::AccountId {
        fieldseal_registration::domain::AccountId(sub.into())
    }

    fn subject_of_account(&self, account: &fieldseal_registration::domain::AccountId) -> Option<String> {
        Some(account.0.clone())
    }
}

pub struct World {
    pub authority: DevAuthority<SeededRandom>,
    pub store: MemoryRegistryStore,
    verifier: SoftwareAttestationVerifier,
    engine: BuiltInPolicyEngine,
    log: MemoryDecisionLog,
    pub clock: FixedClock,
    pub random: SeededRandom,
    progress: MemoryReceivedProgress,
    fleet: MemoryFleetRegistry,
    notifier: MemoryNotifier,
    pub idp: MemoryIdentityProvider,
    policy: EffectivePolicy,
    config: FactoryConfig,
    pub surveys: Surveys,
    pub cohorts: Cohorts,
    pub rosters: Box<dyn RosterIssuer>,
}

impl World {
    pub fn new(surveys: &[&str], cohorts: &[&str], rosters: Box<dyn RosterIssuer>) -> Self {
        let authority = dev_authority(SeededRandom::new(1), T0, &["fieldseal-simulator"]).expect("dev authority");
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
        for (login, sub) in [("alice", "sub-alice"), ("bob", "sub-bob"), ("carol", "auth0|abc")] {
            idp.add(login, sub, &["collector"], &["hwk", "user"], MethodAssurance::FromProvider);
        }
        idp.add("ops", "sub-ops", &["operator"], &["hwk", "phr"], MethodAssurance::FromProvider);
        idp.add("weak-ops", "sub-weak", &["operator"], &["pwd"], MethodAssurance::FromProvider);
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
            surveys: Surveys(surveys.iter().map(|s| (*s).to_owned()).collect()),
            cohorts: Cohorts(cohorts.iter().map(|s| (*s).to_owned()).collect()),
            rosters,
        }
    }

    pub fn factory(&self) -> Factory<'_> {
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
        .with_operator_ports(OperatorPorts { rosters: self.rosters.as_ref(), surveys: &self.surveys, cohorts: &self.cohorts })
    }

    pub fn person(&self, login: &str) -> AuthenticatedPerson {
        self.idp.person(login).expect("known person")
    }

    /// Submits a device's request for `login`: the tenancy waits for the fingerprint to be
    /// confirmed.
    pub fn pending_as(&self, login: &str) -> TenancyRecord {
        let device = SoftwareDevice::new(&self.random);
        let token = self.factory().issue_token(&self.person(login), RegistrationRoute::Online, 1).expect("token");
        let body = device.body(&token.token, Some("blue"));
        let sealed = device.seal(&self.random, &self.authority.bundle, T0, &body, None);
        self.factory().submit(&sealed, Submission::Online).expect("submit").tenancy
    }

    /// Registers a device for `login` and confirms it: the tenancy is registered.
    pub fn register_as(&self, login: &str) -> TenancyRecord {
        let submitted = self.pending_as(login);
        let record = self.factory().confirm(&self.person(login).account, &submitted.id).expect("confirm");
        assert_eq!(record.state, TenancyState::Registered);
        record
    }

    pub fn tenancy(&self, id: &TenancyId) -> TenancyRecord {
        self.store.tenancy(id).expect("store").expect("tenancy")
    }
}

/// The world, the stub verifier and what the HTTP adapter reported.
pub struct Fixture {
    pub world: World,
    pub bearer: StubBearer,
    pub notified: Arc<Mutex<Vec<TenancyId>>>,
    pub events: Arc<Mutex<Vec<OperatorEvent>>>,
}

impl Fixture {
    pub fn new(surveys: &[&str], cohorts: &[&str], rosters: Box<dyn RosterIssuer>) -> Self {
        let world = World::new(surveys, cohorts, rosters);
        let mut tokens = BTreeMap::new();
        tokens.insert(OPERATOR_TOKEN.to_owned(), Ok(world.person("ops")));
        tokens.insert("weak-token".to_owned(), Ok(world.person("weak-ops")));
        tokens.insert("collector-token".to_owned(), Ok(world.person("alice")));
        tokens.insert("expired-token".to_owned(), Err(BearerError::Invalid("expired".into())));
        Self { world, bearer: StubBearer(tokens), notified: Arc::default(), events: Arc::default() }
    }

    /// Runs `f` against the HTTP adapter over this fixture.
    pub fn with_http<R>(&self, f: impl FnOnce(&FactoryHttp) -> R) -> R {
        let factory = self.world.factory();
        let notified = self.notified.clone();
        let notify: ReconcileNotify = Arc::new(move |t| notified.lock().expect("lock").push(t));
        let events = self.events.clone();
        let events: OperatorEvents = Arc::new(move |e| events.lock().expect("lock").push(e.clone()));
        let http = FactoryHttp::new(&factory, &self.world.idp, HttpConfig { public_url: HTTPS.into(), session_ttl_ms: 3_600_000 })
            .with_operator_api(&self.bearer, notify, events);
        f(&http)
    }

    pub fn call(&self, req: &Request) -> Response {
        self.with_http(|http| http.handle(req))
    }
}

pub fn request(method: &str, path: &str, token: Option<&str>, body: Vec<u8>) -> Request {
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_owned(), "application/cbor".to_owned());
    if let Some(t) = token {
        headers.insert("authorization".to_owned(), format!("Bearer {t}"));
    }
    Request::new(method, path, headers, body)
}

pub fn assignment_body(account: &str, survey: &str, cohort: &str) -> Vec<u8> {
    cbor::encode(&cbor::map([
        ("account", Value::Text(account.into())),
        ("survey", Value::Text(survey.into())),
        ("cohort", Value::Text(cohort.into())),
    ]))
    .expect("encodable")
}

pub fn json(r: &Response) -> serde_json::Value {
    serde_json::from_slice(&r.body).expect("a JSON body")
}
