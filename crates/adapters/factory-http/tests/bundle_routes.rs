//! `GET /v1/bundle` and the portal's bundle download (DIS-040, DIS-041, REG-043) through
//! `FactoryHttp::handle`, over the in-memory registration ports and a bundle store that holds
//! whatever the test puts in it: the routes only serve what is stored.

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};

use fieldseal_adapters_factory_http::{BundleRoutes, FactoryHttp, HttpConfig, Request, Response};
use fieldseal_adapters_memory::distribution::MemoryBundleStore;
use fieldseal_adapters_memory::registration::SoftwareDevice;
use fieldseal_distribution::application::BundleDelivery;
use fieldseal_distribution::domain::{BundleSeq, SealedBundle, file_name};
use fieldseal_distribution::ports::BundleStore;
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::id::TenancyId;
use fieldseal_registration::domain::{RegistrationRoute, TenancyRecord, TenancyState};
use fieldseal_registration::ports::RegistryStore;

use common::{Fixture, HTTPS, NoRosters, T0};

static JTI: AtomicU8 = AtomicU8::new(1);

struct Setup {
    f: Fixture,
    bundles: MemoryBundleStore,
    device: SoftwareDevice,
    record: TenancyRecord,
}

fn header<'a>(r: &'a Response, name: &str) -> Option<&'a str> {
    r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn error(r: &Response) -> String {
    serde_json::from_slice::<serde_json::Value>(&r.body).ok().and_then(|j| j["error"].as_str().map(str::to_owned)).unwrap_or_default()
}

fn setup() -> Setup {
    let f = Fixture::new(&[], &[], Box::new(NoRosters));
    let device = SoftwareDevice::new(&f.world.random);
    let token = f.world.factory().issue_token(&f.world.person("alice"), RegistrationRoute::Online, 1).expect("token");
    let body = device.body(&token.token, Some("blue"));
    let sealed = device.seal(&f.world.random, &f.world.authority.bundle, T0, &body, None);
    let submitted = f.world.factory().submit(&sealed, fieldseal_registration::application::Submission::Online).expect("submit").tenancy;
    let record = f.world.factory().confirm(&f.world.person("alice").account, &submitted.id).expect("confirm");
    Setup { f, bundles: MemoryBundleStore::new(), device, record }
}

impl Setup {
    fn store(&self, seq: u64) -> SealedBundle {
        let bundle = SealedBundle::new(self.record.id, BundleSeq(seq), T0, format!("FSB1 sealed bytes {seq}").into_bytes());
        self.bundles.put(&bundle).expect("put");
        bundle
    }

    fn pop(&self, tenancy: TenancyId, method: &str, url: &str) -> String {
        let jti = [JTI.fetch_add(1, Ordering::SeqCst); 16];
        self.device.pop_token(tenancy, method, url, T0, jti, None).to_header()
    }

    fn get(&self, target: &str, pop: Option<String>) -> Response {
        let mut headers = BTreeMap::new();
        if let Some(p) = pop {
            headers.insert("fieldseal-pop".to_owned(), p);
        }
        self.call(&Request::new("GET", target, headers, vec![]))
    }

    /// A signed request for the bundle, with the token bound to the URL without its query.
    fn fetch(&self, held: Option<u64>) -> Response {
        let target = held.map_or("/v1/bundle".to_owned(), |h| format!("/v1/bundle?held={h}"));
        self.get(&target, Some(self.pop(self.record.id, "GET", &format!("{HTTPS}/v1/bundle"))))
    }

    /// Runs `f` against one adapter, which keeps its sessions between requests.
    fn with_http<R>(&self, f: impl FnOnce(&FactoryHttp) -> R) -> R {
        let factory = self.f.world.factory();
        let delivery = BundleDelivery::new(&self.f.world.store, &self.bundles);
        let http = FactoryHttp::new(&factory, &self.f.world.idp, HttpConfig { public_url: HTTPS.into(), session_ttl_ms: 3_600_000 })
            .with_bundle_routes(BundleRoutes { fetch: &delivery, download: &delivery });
        f(&http)
    }

    fn call(&self, req: &Request) -> Response {
        self.with_http(|http| http.handle(req))
    }

    fn set_state(&self, state: TenancyState) {
        let mut record = self.f.world.tenancy(&self.record.id);
        record.state = state;
        self.f.world.store.put_tenancy(&record).expect("put");
    }
}

#[test]
fn dis_040_a_registered_device_with_a_valid_token_gets_the_stored_bundle() {
    let s = setup();
    let stored = s.store(1);
    let r = s.fetch(None);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, stored.bytes);
    assert_eq!(header(&r, "Fieldseal-Bundle-Sequence"), Some("1"));
    assert_eq!(header(&r, "Content-Type"), Some("application/octet-stream"));
    assert_eq!(header(&r, "Content-Disposition"), Some(format!("attachment; filename=\"{}\"", file_name(T0.0, 1)).as_str()));
}

#[test]
fn dis_040_held_equal_to_latest_gives_304() {
    let s = setup();
    s.store(1);
    s.store(2);
    let r = s.fetch(Some(2));
    assert_eq!((r.status, r.body.len()), (304, 0));
    assert_eq!(s.fetch(Some(1)).status, 200);
}

#[test]
fn dis_040_the_query_is_outside_the_pop_binding() {
    let s = setup();
    s.store(1);
    // A token bound to the URL without the query works with any query, and a token that signed
    // the query is refused: a client MUST NOT sign it.
    assert_eq!(s.fetch(Some(0)).status, 200);
    let signed_query = s.pop(s.record.id, "GET", &format!("{HTTPS}/v1/bundle?held=0"));
    let r = s.get("/v1/bundle?held=0", Some(signed_query));
    assert!(matches!(r.status, 400 | 401), "{}", r.status);
}

#[test]
fn dis_040_a_rewritten_held_gives_a_full_bundle_or_304_and_never_a_forged_one() {
    let s = setup();
    let stored = s.store(3);
    for held in [None, Some(0), Some(2), Some(3), Some(99)] {
        let r = s.fetch(held);
        match r.status {
            200 => assert_eq!(r.body, stored.bytes),
            304 => assert!(r.body.is_empty()),
            other => panic!("held {held:?}: {other}"),
        }
    }
    // A garbled value is ignored, as a dropped one would be.
    let r = s.get("/v1/bundle?held=abc", Some(s.pop(s.record.id, "GET", &format!("{HTTPS}/v1/bundle"))));
    assert_eq!((r.status, r.body), (200, stored.bytes));
}

#[test]
fn dis_040_no_token_gives_pop_required() {
    let s = setup();
    s.store(1);
    let r = s.get("/v1/bundle", None);
    assert_eq!((r.status, error(&r).as_str()), (401, "pop-required"));
}

#[test]
fn dis_040_a_replayed_token_is_refused() {
    let s = setup();
    s.store(1);
    let pop = s.pop(s.record.id, "GET", &format!("{HTTPS}/v1/bundle"));
    assert_eq!(s.get("/v1/bundle", Some(pop.clone())).status, 200);
    let r = s.get("/v1/bundle", Some(pop));
    assert_eq!((r.status, error(&r).as_str()), (401, "replay"));
}

#[test]
fn dis_040_an_unknown_tenancy_is_not_registered() {
    let s = setup();
    let stranger = SoftwareDevice::new(&s.f.world.random);
    let pop = stranger.pop_token(stranger.tenancy(), "GET", &format!("{HTTPS}/v1/bundle"), T0, [9; 16], None).to_header();
    let r = s.get("/v1/bundle", Some(pop));
    assert_eq!((r.status, error(&r).as_str()), (403, "not-registered"));
}

#[test]
fn dis_040_a_lost_closing_closed_or_retired_tenancy_is_revoked() {
    let s = setup();
    s.store(1);
    for state in [TenancyState::Lost, TenancyState::Closing, TenancyState::Closed, TenancyState::Retired] {
        s.set_state(state);
        let r = s.fetch(None);
        assert_eq!((r.status, error(&r).as_str()), (403, "revoked"), "{state:?}");
    }
}

#[test]
fn dis_003_a_withheld_tenancy_gets_403_with_reasons_and_can_still_upload() {
    let s = setup();
    s.store(1);
    s.set_state(TenancyState::Flagged);
    let r = s.fetch(None);
    assert_eq!((r.status, error(&r).as_str()), (403, "withheld"));
    let reasons: serde_json::Value = serde_json::from_slice(&r.body).expect("json");
    assert_eq!(reasons["reasons"], serde_json::json!(["tenancy-flagged"]));
    // A flagged tenancy still authenticates to the factory's API (REG-070). That intake
    // still authenticates its uploads is shown by the security tests (REG-082).
    let cert = s.get("/v1/certificate", Some(s.pop(s.record.id, "GET", &format!("{HTTPS}/v1/certificate"))));
    assert_eq!(cert.status, 200);
}

#[test]
fn dis_040_an_eligible_tenancy_with_no_bundle_yet_gets_no_bundle() {
    let s = setup();
    let r = s.fetch(None);
    assert_eq!((r.status, error(&r).as_str()), (404, "no-bundle"));
}

#[test]
fn dis_040_a_current_held_bundle_gives_304_and_nothing_stored_gives_404_no_bundle() {
    let s = setup();
    assert_eq!(s.fetch(Some(1)).status, 404, "a held bundle does not make an empty store current");
    s.store(1);
    assert_eq!(s.fetch(Some(1)).status, 304);
}

#[test]
fn dis_084_the_route_never_builds() {
    let s = setup();
    // The routes take a store and nothing to build with; a registered, eligible tenancy with
    // an empty store stays empty however often it asks.
    for _ in 0..3 {
        assert_eq!(s.fetch(None).status, 404);
    }
    assert_eq!(s.bundles.latest(&s.record.id), Ok(None));
}

#[test]
fn dis_022_the_answer_reveals_nothing_outside_the_seal() {
    let s = setup();
    let stored = s.store(1);
    let r = s.fetch(None);
    assert_eq!(r.body, stored.bytes, "the body is the stored bytes and nothing else");
    let tenancy = lower_hex(s.record.id.as_bytes());
    let visible = r.headers.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join("\n");
    assert!(!visible.contains(&tenancy) && !visible.contains("cohort"), "{visible}");
    let refused = s.get("/v1/bundle", None);
    assert!(!String::from_utf8_lossy(&refused.body).contains(&tenancy));
}

#[test]
fn dis_040_responses_carry_cache_control_no_store() {
    let s = setup();
    let none = s.fetch(None);
    s.store(1);
    let ok = s.fetch(None);
    let current = s.fetch(Some(1));
    let unsigned = s.get("/v1/bundle", None);
    s.set_state(TenancyState::Flagged);
    let withheld = s.fetch(None);
    for (name, r) in [("404", none), ("200", ok), ("304", current), ("401", unsigned), ("403", withheld)] {
        assert_eq!(header(&r, "Cache-Control"), Some("no-store"), "{name}");
    }
}

/// Signs in as `login` and returns the cookie pair.
fn sign_in(s: &Setup, http: &FactoryHttp, login: &str) -> String {
    s.f.world.idp.set_default(Some(login));
    let start = http.handle(&Request::new("GET", "/sign-in", BTreeMap::new(), vec![]));
    let location = header(&start, "Location").expect("redirect").to_owned();
    let pre = header(&start, "Set-Cookie").expect("pre-auth").split(';').next().expect("pair").to_owned();
    let mut headers = BTreeMap::new();
    headers.insert("cookie".to_owned(), pre);
    let done = http.handle(&Request::new("GET", location.strip_prefix(HTTPS).expect("callback"), headers, vec![]));
    header(&done, "Set-Cookie").expect("session").split(';').next().expect("pair").to_owned()
}

fn download(s: &Setup, http: &FactoryHttp, cookie: Option<&str>) -> Response {
    let mut headers = BTreeMap::new();
    if let Some(c) = cookie {
        headers.insert("cookie".to_owned(), c.to_owned());
    }
    http.handle(&Request::new("GET", &format!("/devices/{}/bundle.fsb", s.record.device.0), headers, vec![]))
}

#[test]
fn dis_041_the_portal_download_needs_a_session() {
    let s = setup();
    s.store(1);
    let r = s.with_http(|http| download(&s, http, None));
    assert_eq!((r.status, header(&r, "Location")), (303, Some("/")));
    assert!(r.body.is_empty());
}

#[test]
fn reg_043_the_portal_download_serves_only_the_collectors_own_device() {
    let s = setup();
    s.with_http(|http| {
    // Nothing stored yet: 404, and only that reason is turned into it.
    let alice = sign_in(&s, http, "alice");
    assert_eq!(download(&s, http, Some(&alice)).status, 404);
    let stored = s.store(1);
    let own = download(&s, http, Some(&alice));
    assert_eq!((own.status, own.body.as_slice()), (200, stored.bytes.as_slice()));
    assert_eq!(header(&own, "Content-Disposition"), Some(format!("attachment; filename=\"{}\"", file_name(T0.0, 1)).as_str()));
    assert_eq!(header(&own, "Cache-Control"), Some("no-store"));
    // Another account's session gets nothing of it.
    let bob = sign_in(&s, http, "bob");
    let other = download(&s, http, Some(&bob));
    assert_eq!(other.status, 403);
    assert!(!other.body.windows(stored.bytes.len()).any(|w| w == stored.bytes.as_slice()));
    // A withheld device gets no file either.
    s.set_state(TenancyState::Flagged);
    assert_eq!(download(&s, http, Some(&alice)).status, 403);
    });
}

#[test]
fn dis_003_a_policy_hold_on_the_stored_bundle_gets_403_with_reasons_until_it_is_cleared() {
    let s = setup();
    let stored = s.store(1);
    assert_eq!(s.fetch(None).status, 200);
    let reasons = vec!["instrument-incompatible".to_owned(), "no-policy".to_owned()];
    s.bundles.set_withheld(&s.record.id, Some(&reasons)).expect("set");
    let r = s.fetch(None);
    assert_eq!((r.status, error(&r).as_str()), (403, "withheld"));
    let body: serde_json::Value = serde_json::from_slice(&r.body).expect("json");
    assert_eq!(body["reasons"], serde_json::json!(["instrument-incompatible", "no-policy"]));
    assert!(!r.body.windows(stored.bytes.len()).any(|w| w == stored.bytes.as_slice()));
    // The held sequence does not make it a 304 either.
    assert_eq!(s.fetch(Some(1)).status, 403);
    s.with_http(|http| {
        let alice = sign_in(&s, http, "alice");
        let d = download(&s, http, Some(&alice));
        assert_eq!(d.status, 403, "the portal download is refused too");
        assert!(String::from_utf8_lossy(&d.body).contains("Bundles are not being released"));
        s.bundles.set_withheld(&s.record.id, None).expect("clear");
        assert_eq!(download(&s, http, Some(&alice)).status, 200);
    });
    assert_eq!(s.fetch(None).status, 200, "clearing the marker restores delivery");
}
