//! The operator API of the factory (REG-070a, REG-046, REG-047): every route answers the
//! same refusals, whatever the body, and no credential of the other surface is accepted.
//!
//! The `BearerVerifier` here is a test double that returns the outcomes the OIDC verifier
//! returns. Token-level refusals (signature, issuer, audience, `typ`, `nonce`, client,
//! expiry) are tested in `crates/adapters/oidc/tests/access_token.rs`, because the development
//! IdP crate is an app and cannot be a dependency of another app.

use std::collections::BTreeMap;

use fieldseal_adapters_factory_http::{
    BearerError, BearerVerifier, FactoryHttp, HttpConfig, Request, Response, no_reconcile,
};
use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog};
use fieldseal_adapters_memory::registration::{
    DevAuthority, MemoryFleetRegistry, MemoryIdentityProvider, MemoryNotifier, MemoryReceivedProgress, MemoryRegistryStore, dev_authority,
};
use fieldseal_adapters_memory::trust::{FixedClock, SeededRandom, SoftwareAttestationVerifier};
use fieldseal_kernel::id::CohortId;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, cbor};
use fieldseal_policy::domain::EffectivePolicy;
use fieldseal_policy::fixtures::{DocBuilder, effective};
use fieldseal_registration::application::{Factory, FactoryConfig, FactoryPorts, OperatorPorts};
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::domain::{AuthenticatedPerson, MethodAssurance, TenancyTerms, Window};
use fieldseal_registration::ports::{CohortDirectory, IssueOutcome, RegistryStore, RosterIssuer, SurveyDirectory};

const T0: AuthorityTime = AuthorityTime(1_800_000_000_000);
const HTTPS: &str = "https://factory.example.org";

struct Everything;

impl SurveyDirectory for Everything {
    fn exists(&self, _: &str) -> bool {
        true
    }
}

impl CohortDirectory for Everything {
    fn exists(&self, _: &CohortId) -> bool {
        true
    }
}

/// An issuer that would accept anything, so that only the route's own checks can refuse.
struct AcceptingIssuer;

impl RosterIssuer for AcceptingIssuer {
    fn issue(&self, _: &CohortId, _: &[u8], _: &[String]) -> IssueOutcome {
        IssueOutcome::Issued { version: 1, digest: fieldseal_kernel::id::Digest::from([1; 32]) }
    }
}

/// Knows four tokens; every other token is refused as the OIDC verifier refuses a bad one.
struct Verifier(BTreeMap<&'static str, AuthenticatedPerson>);

impl BearerVerifier for Verifier {
    fn verify(&self, token: &str) -> Result<AuthenticatedPerson, BearerError> {
        self.0.get(token).cloned().ok_or_else(|| BearerError::Invalid("not one of the test tokens".into()))
    }

    fn account_for_subject(&self, sub: &str) -> fieldseal_registration::domain::AccountId {
        fieldseal_registration::domain::AccountId(format!("test-issuer|{sub}"))
    }

    fn subject_of_account(&self, account: &fieldseal_registration::domain::AccountId) -> Option<String> {
        account.0.strip_prefix("test-issuer|").map(str::to_owned)
    }
}

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
    bearer: Verifier,
}

impl World {
    fn new() -> Self {
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
        idp.add("operator", "sub-ops", &["collector", "operator"], &["hwk", "phr"], MethodAssurance::FromProvider);
        idp.add("collector", "sub-coll", &["collector"], &["hwk"], MethodAssurance::FromProvider);
        idp.add("weak", "sub-weak", &["operator"], &["pwd"], MethodAssurance::FromProvider);
        idp.add("asserted", "sub-asserted", &["operator"], &["hwk"], MethodAssurance::Asserted);
        let people = |l: &str| idp.person(l).expect("person");
        let bearer = Verifier(BTreeMap::from([
            ("operator", people("operator")),
            ("collector", people("collector")),
            ("weak", people("weak")),
            ("asserted", people("asserted")),
        ]));
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
            bearer,
        }
    }

    fn call(&self, req: &Request) -> Response {
        self.with_http(|http| http.handle(req))
    }

    /// Runs `f` against one adapter, so that portal sessions last for the whole of `f`.
    fn with_http<R>(&self, f: impl FnOnce(&FactoryHttp) -> R) -> R {
        let factory = Factory::new(
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
        .with_operator_ports(OperatorPorts { rosters: &AcceptingIssuer, surveys: &Everything, cohorts: &Everything });
        let http = FactoryHttp::new(&factory, &self.idp, HttpConfig { public_url: HTTPS.into(), session_ttl_ms: 3_600_000 })
            .with_operator_api(&self.bearer, no_reconcile(), std::sync::Arc::new(|_| {}));
        f(&http)
    }
}

fn request(method: &str, path: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Request {
    let headers: BTreeMap<String, String> = headers.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
    Request::new(method, path, headers, body)
}

fn bearer(token: &str) -> [(&'static str, String); 1] {
    [("authorization", format!("Bearer {token}"))]
}

fn with_bearer(method: &str, path: &str, token: &str, body: Vec<u8>) -> Request {
    let [(k, v)] = bearer(token);
    request(method, path, &[(k, v.as_str())], body)
}

fn assignment() -> Vec<u8> {
    cbor::encode(&cbor::map([
        ("account", Value::Text("sub-target".into())),
        ("survey", Value::Text("survey-a".into())),
        ("cohort", Value::Text("cohort-a".into())),
    ]))
    .expect("encodable")
}

fn roster() -> Vec<u8> {
    cbor::encode(&cbor::map([("cohort", Value::Text("cohort-a".into())), ("version", Value::Int(1)), ("subjects", Value::Array(vec![]))])).expect("encodable")
}

/// Every operator route with a well-formed body.
fn routes() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    vec![("POST", "/v1/assignments", assignment()), ("GET", "/v1/assignments", vec![]), ("POST", "/v1/rosters", roster())]
}

fn error_of(r: &Response) -> String {
    serde_json::from_slice::<serde_json::Value>(&r.body).ok().and_then(|j| j["error"].as_str().map(str::to_owned)).unwrap_or_default()
}

#[test]
fn reg_070a_a_collector_role_account_is_refused_with_403() {
    let w = World::new();
    for (method, path, body) in routes() {
        let r = w.call(&with_bearer(method, path, "collector", body));
        assert_eq!((r.status, error_of(&r).as_str()), (403, "not-authorised"), "{method} {path}");
    }
    assert_eq!(w.store.assignments(), Ok(vec![]));
    assert_eq!(w.store.roster_issues(), Ok(vec![]));
}

#[test]
fn reg_070a_a_weak_sign_in_method_is_refused_with_403() {
    let w = World::new();
    for token in ["weak", "asserted"] {
        for (method, path, body) in routes() {
            let r = w.call(&with_bearer(method, path, token, body));
            assert_eq!((r.status, error_of(&r).as_str()), (403, "authentication-too-weak"), "{token} {method} {path}");
        }
    }
    assert_eq!(w.store.assignments(), Ok(vec![]));
    assert_eq!(w.store.roster_issues(), Ok(vec![]));
}

#[test]
fn reg_070a_a_verifier_refusal_is_401_token_invalid() {
    let w = World::new();
    for (method, path, body) in routes() {
        let r = w.call(&with_bearer(method, path, "expired-or-forged", body));
        assert_eq!((r.status, error_of(&r).as_str()), (401, "token-invalid"), "{method} {path}");
        let text = String::from_utf8_lossy(&r.body).into_owned();
        assert!(!text.contains("test tokens"), "the verifier's reason is not sent to the caller: {text}");
    }
}

#[test]
fn reg_070a_no_authorization_header_is_401_bearer_required() {
    let w = World::new();
    for (method, path, body) in routes() {
        let r = w.call(&request(method, path, &[], body.clone()));
        assert_eq!((r.status, error_of(&r).as_str()), (401, "bearer-required"), "{method} {path}");
        assert!(r.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("www-authenticate") && v.starts_with("Bearer")));
        // Another scheme, or an empty token, is no Bearer token.
        for header in ["Basic b3BlcmF0b3I6eA==", "FieldsealPoP operator", "Bearer ", "bearer operator", "Bearer"] {
            let r = w.call(&request(method, path, &[("authorization", header)], body.clone()));
            assert_eq!((r.status, error_of(&r).as_str()), (401, "bearer-required"), "{header} on {method} {path}");
        }
    }
}

#[test]
fn reg_070a_the_same_refusals_apply_to_post_v1_rosters() {
    let w = World::new();
    let post = |headers: &[(&str, &str)]| w.call(&request("POST", "/v1/rosters", headers, roster()));
    assert_eq!((post(&[]).status, error_of(&post(&[]))), (401, "bearer-required".into()));
    let (k, v) = ("authorization", "Bearer forged");
    assert_eq!((post(&[(k, v)]).status, error_of(&post(&[(k, v)]))), (401, "token-invalid".into()));
    let r = w.call(&with_bearer("POST", "/v1/rosters", "collector", roster()));
    assert_eq!((r.status, error_of(&r)), (403, "not-authorised".into()));
    let r = w.call(&with_bearer("POST", "/v1/rosters", "weak", roster()));
    assert_eq!((r.status, error_of(&r)), (403, "authentication-too-weak".into()));
    // The refusals come before the body is read: a garbage body from a collector is still 403.
    let r = w.call(&with_bearer("POST", "/v1/rosters", "collector", b"not cbor".to_vec()));
    assert_eq!(r.status, 403);
    // And an operator is accepted.
    assert_eq!(w.call(&with_bearer("POST", "/v1/rosters", "operator", roster())).status, 200);
    assert_eq!(w.store.roster_issues().expect("issues").len(), 1);
}

#[test]
fn reg_046_a_portal_session_cookie_is_never_accepted_on_the_assignment_routes() {
    let w = World::new();
    w.idp.set_default(Some("operator"));
    w.with_http(|http| {
        // Sign the operator in at the portal, as a browser would.
        let start = http.handle(&request("GET", "/sign-in", &[], vec![]));
        let location = start.headers.iter().find(|(k, _)| k == "Location").expect("redirect").1.clone();
        let pre_auth = start.headers.iter().find(|(k, _)| k == "Set-Cookie").expect("pre-auth cookie").1.split(';').next().expect("pair").to_owned();
        let done = http.handle(&request("GET", location.strip_prefix(HTTPS).expect("on the public URL"), &[("cookie", &pre_auth)], vec![]));
        assert_eq!(done.status, 303, "{}", String::from_utf8_lossy(&done.body));
        let session = done.headers.iter().find(|(k, _)| k == "Set-Cookie").expect("session cookie").1.split(';').next().expect("pair").to_owned();
        // The session is good for the portal ...
        let home = http.handle(&request("GET", "/", &[("cookie", &session)], vec![]));
        assert!(String::from_utf8_lossy(&home.body).contains("sub-ops"));
        // ... and for nothing on the API.
        for (method, path, body) in routes() {
            let r = http.handle(&request(method, path, &[("cookie", &session)], body));
            assert_eq!((r.status, error_of(&r).as_str()), (401, "bearer-required"), "{method} {path}");
        }
    });
    assert_eq!(w.store.assignments(), Ok(vec![]));
}

#[test]
fn reg_046_a_bearer_token_is_never_accepted_on_the_portal_pages() {
    let w = World::new();
    let [(k, v)] = bearer("operator");
    // The home page shows the sign-in page, not the operator's account.
    let home = w.call(&request("GET", "/", &[(k, v.as_str())], vec![]));
    let page = String::from_utf8_lossy(&home.body).into_owned();
    assert!(page.contains("/sign-in") && !page.contains("sub-ops"), "{page}");
    // A portal action with a Bearer token and a forged CSRF field is not run.
    let form = request("POST", "/tokens", &[(k, v.as_str()), ("content-type", "application/x-www-form-urlencoded")], b"csrf=x&route=online".to_vec());
    assert_eq!(w.call(&form).status, 303, "no session: sent back to the start");
    let download = w.call(&request("GET", "/tenancies/00/certificate.cbor", &[(k, v.as_str())], vec![]));
    assert_eq!(download.status, 303);
}
