//! The browser device asks the factory for its bundle (`GET /v1/bundle`, DIS-040) through the
//! host's blocking GET, here a stub that records what it is sent and serves bundles built by
//! the demo authority. The bundle is verified in DIS-030 order before anything is held.
#![allow(missing_docs)]

use std::cell::RefCell;
use std::rc::Rc;

use fieldseal_adapters_web::device::{BundleFetch, Host, WebDevice};
use fieldseal_adapters_web_demo::{Demo, DemoConfig};
use fieldseal_kernel::crypto::P256PublicKey;
use fieldseal_kernel::pop::PopToken;
use fieldseal_kernel::sign::verify_message;

const FACTORY: &str = "http://factory.example:8080";

type Answer = (u16, Vec<(String, String)>, Vec<u8>);

/// What the stub saw, and what it answers next.
#[derive(Default)]
struct Stub {
    seen: Vec<(String, Option<String>)>,
    answer: Option<Answer>,
}

fn now_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as f64
}

fn host(stub: Rc<RefCell<Stub>>) -> Host {
    let started = std::time::Instant::now();
    Host {
        now_ms: Rc::new(now_ms),
        elapsed_ms: Rc::new(move || started.elapsed().as_millis() as f64),
        post: Rc::new(|_, _, _| Err("no POST in this test".into())),
        get: Rc::new(move |url, pop| {
            let mut s = stub.borrow_mut();
            s.seen.push((url.to_owned(), pop.map(str::to_owned)));
            s.answer.clone().ok_or_else(|| "no answer set".to_owned())
        }),
    }
}

fn unhex(t: &str) -> Vec<u8> {
    (0..t.len() / 2).map(|i| u8::from_str_radix(&t[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn bundle_answer(bytes: Vec<u8>, sequence: u64) -> Answer {
    (200, vec![("fieldseal-bundle-sequence".into(), sequence.to_string())], bytes)
}

fn refusal(status: u16, body: &str) -> Answer {
    (status, vec![], body.as_bytes().to_vec())
}

/// A registered device, the demo authority it registered with and the stub it asks.
struct World {
    demo: &'static Demo,
    dev: WebDevice,
    stub: Rc<RefCell<Stub>>,
    tenancy: String,
    sign_pub: String,
}

fn world() -> World {
    let mut cfg = DemoConfig::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../examples"));
    cfg.now_ms = now_ms() as u64;
    let demo = Demo::start(cfg).expect("demo authority");
    let stub = Rc::new(RefCell::new(Stub::default()));
    let mut dev = WebDevice::open(&demo.provisioning_json(), vec![], 1, host(stub.clone())).expect("device opens");
    dev.create_tenancy("246810").expect("tenancy and PIN");
    let token = demo.issue_registration_token("alice").expect("token");
    let req = dev.registration_request(&token, "fetch test").expect("request");
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
    let status = agent.post(&format!("{}/v1/registrations", demo.factory_url())).send(&req.file[..]).unwrap().status().as_u16();
    assert_eq!(status, 202);
    demo.confirm_registration(&req.tenancy).expect("confirmed");
    World { demo, dev, stub, tenancy: req.tenancy, sign_pub: req.sign_pub }
}

impl World {
    fn bundle(&self) -> Vec<u8> {
        self.demo.build_bundle_for(&self.tenancy, &["household-water-access"]).expect("bundle").bytes
    }

    fn answer(&self, answer: Answer) {
        self.stub.borrow_mut().answer = Some(answer);
    }

    fn requests(&self) -> Vec<(String, Option<String>)> {
        self.stub.borrow().seen.clone()
    }
}

// covers: DIS-040
#[test]
fn dis_040_the_device_fetches_and_imports_a_bundle() {
    let mut w = world();
    w.answer(bundle_answer(w.bundle(), 1));
    let fetched = w.dev.fetch_bundle(FACTORY, None).expect("fetch");
    let BundleFetch::Imported { sequence, report } = fetched else { panic!("expected a bundle, got {fetched:?}") };
    assert_eq!(sequence, 1);
    assert!(report.contains("publisher signatures verified"), "{report}");
    assert!(w.dev.held_json().expect("held").contains("fingerprint"), "the instrument is held");
    assert_eq!(w.requests()[0].0, format!("{FACTORY}/v1/bundle"), "no `held` query when nothing is held");
}

// covers: DIS-040
#[test]
fn dis_040_a_304_keeps_the_held_bundle() {
    let mut w = world();
    w.answer(bundle_answer(w.bundle(), 1));
    w.dev.fetch_bundle(FACTORY, None).expect("first fetch");
    let held = w.dev.held_json().expect("held");
    w.answer((304, vec![], vec![]));
    assert_eq!(w.dev.fetch_bundle(FACTORY, Some(1)).expect("second fetch"), BundleFetch::Current);
    assert_eq!(w.dev.held_json().expect("still held"), held);
    assert_eq!(w.requests()[1].0, format!("{FACTORY}/v1/bundle?held=1"), "the held sequence is a query");
}

// covers: DIS-040
#[test]
fn dis_040_a_404_no_bundle_is_reported_as_still_preparing() {
    let mut w = world();
    w.answer(refusal(404, "{\"error\":\"no-bundle\"}"));
    assert_eq!(w.dev.fetch_bundle(FACTORY, None).expect("answer"), BundleFetch::Preparing);
    assert!(w.dev.held_json().is_err(), "nothing is held");
    w.answer(refusal(403, "{\"error\":\"withheld\",\"reasons\":[\"not registered\"]}"));
    assert_eq!(
        w.dev.fetch_bundle(FACTORY, None).expect("answer"),
        BundleFetch::Refused { status: 403, code: "withheld".into(), reasons: vec!["not registered".into()] }
    );
    w.answer((502, vec![], vec![]));
    assert!(w.dev.fetch_bundle(FACTORY, None).is_err(), "another status is an error, not a state");
}

// covers: DIS-030
#[test]
fn dis_030_a_bundle_that_fails_verification_is_not_imported() {
    let mut w = world();
    let mut bytes = w.bundle();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    w.answer(bundle_answer(bytes, 1));
    let e = w.dev.fetch_bundle(FACTORY, None).expect_err("a damaged bundle is refused");
    assert!(e.contains("bundle rejected"), "{e}");
    assert!(w.dev.held_json().is_err(), "nothing from the refused bundle is held");
    w.answer((200, vec![], w.bundle()));
    assert!(w.dev.fetch_bundle(FACTORY, None).is_err(), "a bundle without its sequence number is refused");
}

// covers: DIS-040, WIRE-171
#[test]
fn dis_040_the_pop_token_is_bound_to_the_factory_url_not_the_proxy_url() {
    let mut w = world();
    w.answer(refusal(404, "{\"error\":\"no-bundle\"}"));
    w.dev.fetch_bundle(&format!("{FACTORY}/"), Some(4)).expect("answer");
    let (url, pop) = w.requests().remove(0);
    assert_eq!(url, format!("{FACTORY}/v1/bundle?held=4"), "the device addresses the factory itself; the page's worker maps it to its proxy");
    let token = PopToken::from_header(&pop.expect("a PoP header")).expect("a readable token");
    assert_eq!((token.method.as_str(), token.url.as_str()), ("GET", "http://factory.example:8080/v1/bundle"), "the token names the factory, without the query");
    assert_eq!(lower(token.tenancy.as_bytes()), w.tenancy);
    let key = P256PublicKey::from_bytes(&unhex(&w.sign_pub)).expect("key");
    verify_message(&key, &token.message(), &token.signature).expect("signed by the tenancy's signing key");
}

fn lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
