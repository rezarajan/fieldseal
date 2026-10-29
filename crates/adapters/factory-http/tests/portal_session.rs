//! Characterises the portal's sign-in, session and CSRF behaviour through
//! `FactoryHttp::handle`, over the in-memory registration ports. It was written against the
//! sessions kept inside this crate and must pass unchanged once they live in
//! `fieldseal-adapters-portal`. `MemoryIdentityProvider` sends no PKCE challenge, so no case
//! asserts one.

use std::collections::BTreeMap;

use fieldseal_adapters_factory_http::{FactoryHttp, HttpConfig, Request, Response, SESSION_COOKIE};
use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog};
use fieldseal_adapters_memory::registration::{
    DevAuthority, MemoryFleetRegistry, MemoryIdentityProvider, MemoryNotifier, MemoryReceivedProgress, MemoryRegistryStore, dev_authority,
};
use fieldseal_adapters_memory::trust::{FixedClock, SeededRandom, SoftwareAttestationVerifier};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::domain::EffectivePolicy;
use fieldseal_policy::fixtures::{DocBuilder, effective};
use fieldseal_registration::application::{Factory, FactoryConfig, FactoryPorts};
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::domain::{MethodAssurance, TenancyTerms, Window};

const T0: AuthorityTime = AuthorityTime(1_800_000_000_000);
const TTL_MS: u64 = 3_600_000;
const HTTPS: &str = "https://factory.example.org";

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
        idp.add("alice", "sub-alice", &["collector"], &["hwk", "user"], MethodAssurance::FromProvider);
        idp.add("bob", "sub-bob", &["collector"], &["hwk"], MethodAssurance::FromProvider);
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
}

fn config(public_url: &str) -> HttpConfig {
    HttpConfig { public_url: public_url.into(), session_ttl_ms: TTL_MS }
}

fn get(path: &str, cookie: Option<&str>) -> Request {
    request("GET", path, cookie, Vec::new())
}

fn post(path: &str, cookie: Option<&str>, csrf: Option<&str>) -> Request {
    let body = csrf.map(|c| format!("csrf={c}&route=online")).unwrap_or_else(|| "route=online".into());
    request("POST", path, cookie, body.into_bytes())
}

fn request(method: &str, target: &str, cookie: Option<&str>, body: Vec<u8>) -> Request {
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_owned(), "application/x-www-form-urlencoded".to_owned());
    if let Some(c) = cookie {
        headers.insert("cookie".to_owned(), c.to_owned());
    }
    Request::new(method, target, headers, body)
}

fn header<'a>(r: &'a Response, name: &str) -> Option<&'a str> {
    r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// Signs in as `login` and returns the `Cookie` header value and the `Set-Cookie` value.
fn sign_in(world: &World, http: &FactoryHttp, public_url: &str, login: &str) -> (String, String) {
    world.idp.set_default(Some(login));
    let start = http.handle(&get("/sign-in", None));
    let location = header(&start, "Location").expect("redirect to the provider").to_owned();
    let callback = location.strip_prefix(public_url).expect("the callback is on the public URL");
    // The browser brings back the pre-auth cookie that the redirect set.
    let pre_auth = header(&start, "Set-Cookie").expect("a pre-auth cookie").split(';').next().expect("name=value").to_owned();
    let done = http.handle(&get(callback, Some(&pre_auth)));
    assert_eq!(done.status, 303);
    let set_cookie = header(&done, "Set-Cookie").expect("a session cookie").to_owned();
    let pair = set_cookie.split(';').next().expect("name=value").to_owned();
    (pair, set_cookie)
}

/// The CSRF token the home page embeds in its forms.
fn csrf_of(http: &FactoryHttp, cookie: &str) -> String {
    let page = String::from_utf8(http.handle(&get("/", Some(cookie))).body).expect("utf-8");
    let marker = "name=\"csrf\" value=\"";
    let start = page.find(marker).expect("a CSRF field") + marker.len();
    let end = start + page[start..].find('"').expect("closing quote");
    page[start..end].to_owned()
}

#[test]
fn reg_002_sign_in_redirects_to_the_provider_with_a_state() {
    let world = World::new();
    let factory = world.factory();
    let http = FactoryHttp::new(&factory, &world.idp, config(HTTPS));
    world.idp.set_default(Some("alice"));
    let r = http.handle(&get("/sign-in", None));
    assert_eq!(r.status, 303);
    let location = header(&r, "Location").expect("Location");
    assert!(location.starts_with("https://factory.example.org/sign-in/callback?state="), "{location}");
}

#[test]
fn reg_002_callback_with_an_unknown_state_is_refused() {
    let world = World::new();
    let factory = world.factory();
    let http = FactoryHttp::new(&factory, &world.idp, config(HTTPS));
    let r = http.handle(&get("/sign-in/callback?state=nope&code=alice", None));
    assert_eq!(r.status, 401);
    assert!(header(&r, "Set-Cookie").is_none());
}

#[test]
fn reg_092_a_session_cookie_is_httponly_samesite_lax_and_secure_on_https() {
    let world = World::new();
    let factory = world.factory();
    let https = FactoryHttp::new(&factory, &world.idp, config(HTTPS));
    let (_, set_cookie) = sign_in(&world, &https, HTTPS, "alice");
    for attribute in ["Path=/", "HttpOnly", "SameSite=Lax", "Secure", "Max-Age=3600"] {
        assert!(set_cookie.contains(attribute), "{attribute} missing from {set_cookie}");
    }
    let http = FactoryHttp::new(&factory, &world.idp, config("http://127.0.0.1:8080"));
    let (_, plain) = sign_in(&world, &http, "http://127.0.0.1:8080", "alice");
    assert!(plain.contains("HttpOnly") && plain.contains("SameSite=Lax"), "{plain}");
    assert!(!plain.contains("Secure"), "{plain}");
}

#[test]
fn reg_092_a_page_without_a_session_redirects_to_sign_in() {
    let world = World::new();
    let factory = world.factory();
    let http = FactoryHttp::new(&factory, &world.idp, config(HTTPS));
    let r = http.handle(&get(&format!("/tenancies/{}/certificate.cbor", "0".repeat(64)), None));
    assert_eq!((r.status, header(&r, "Location")), (303, Some("/")));
    let r = http.handle(&post("/tokens", None, None));
    assert_eq!((r.status, header(&r, "Location")), (303, Some("/")));
    let home = http.handle(&get("/", None));
    assert!(String::from_utf8_lossy(&home.body).contains("href=\"/sign-in\""));
}

#[test]
fn reg_092_a_post_without_the_csrf_token_is_refused() {
    let world = World::new();
    let factory = world.factory();
    let http = FactoryHttp::new(&factory, &world.idp, config(HTTPS));
    let (cookie, _) = sign_in(&world, &http, HTTPS, "alice");
    let r = http.handle(&post("/tokens", Some(&cookie), None));
    assert_eq!(r.status, 403);
    let ok = http.handle(&post("/tokens", Some(&cookie), Some(&csrf_of(&http, &cookie))));
    assert_eq!(ok.status, 200);
}

#[test]
fn reg_092_a_post_with_another_sessions_token_is_refused() {
    let world = World::new();
    let factory = world.factory();
    let http = FactoryHttp::new(&factory, &world.idp, config(HTTPS));
    let (alice, _) = sign_in(&world, &http, HTTPS, "alice");
    let (bob, _) = sign_in(&world, &http, HTTPS, "bob");
    let (alice_csrf, bob_csrf) = (csrf_of(&http, &alice), csrf_of(&http, &bob));
    assert_ne!(alice_csrf, bob_csrf);
    assert_ne!(alice, bob);
    assert_eq!(http.handle(&post("/tokens", Some(&alice), Some(&bob_csrf))).status, 403);
    assert_eq!(http.handle(&post("/tokens", Some(&alice), Some(&alice_csrf))).status, 200);
}

#[test]
fn reg_092_sign_out_ends_the_session() {
    let world = World::new();
    let factory = world.factory();
    let http = FactoryHttp::new(&factory, &world.idp, config(HTTPS));
    let (cookie, _) = sign_in(&world, &http, HTTPS, "alice");
    let csrf = csrf_of(&http, &cookie);
    let out = http.handle(&post("/sign-out", Some(&cookie), Some(&csrf)));
    assert_eq!((out.status, header(&out, "Location")), (303, Some("/")));
    assert!(header(&out, "Set-Cookie").is_some_and(|c| c.contains("Max-Age=0")));
    // The old cookie no longer opens a session.
    let again = http.handle(&post("/tokens", Some(&cookie), Some(&csrf)));
    assert_eq!((again.status, header(&again, "Location")), (303, Some("/")));
    assert!(String::from_utf8_lossy(&http.handle(&get("/", Some(&cookie))).body).contains("href=\"/sign-in\""));
}

#[test]
fn reg_092_the_session_cookie_name_is_fs_session() {
    assert_eq!(SESSION_COOKIE, "fs_session");
    let world = World::new();
    let factory = world.factory();
    let http = FactoryHttp::new(&factory, &world.idp, config(HTTPS));
    let (cookie, set_cookie) = sign_in(&world, &http, HTTPS, "alice");
    assert!(set_cookie.starts_with("fs_session="), "{set_cookie}");
    // A cookie of another name is not a session.
    let renamed = cookie.replacen("fs_session=", "other=", 1);
    let r = http.handle(&post("/tokens", Some(&renamed), None));
    assert_eq!((r.status, header(&r, "Location")), (303, Some("/")));
}
