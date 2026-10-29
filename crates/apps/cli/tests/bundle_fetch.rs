//! `bundle fetch` (CLI-049): the device asks the factory for its latest bundle with a
//! proof-of-possession token and stores it whole under its dated name. The factory is a
//! `tiny_http` stand-in on loopback that records the token it is sent.

mod common;

use std::sync::{Arc, Mutex};

use common::{Sandbox, field, text};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::pop::{POP_HEADER, PopToken};
use fieldseal_kernel::sign::SigningKey;

const SIGN_SECRET: [u8; 32] = [7u8; 32];
const AGREE_SECRET: [u8; 32] = [11u8; 32];
const NAME: &str = "fieldseal-bundle-20261029-3.fsb";
const BUNDLE: &[u8] = b"FSB1 a stand-in for a bundle file";

/// A device directory holding fixed keys, as `registration request --device-dir` leaves it.
fn device_dir(sb: &Sandbox) -> String {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    sb.write("device/sign.key", &format!("purpose=sign\nalgorithm=p256\nsecret={}\n", hex(&SIGN_SECRET)));
    sb.write("device/agree.key", &format!("purpose=agree\nalgorithm=p256\nsecret={}\n", hex(&AGREE_SECRET)));
    sb.path("device")
}

/// What the stand-in factory does with `GET /v1/bundle`.
#[derive(Clone, Copy)]
enum Mode {
    /// Serves the bundle (sequence 3), or `304` when `held=3`.
    Serve,
    /// Serves the bundle without a usable `Content-Disposition` name.
    Nameless,
    /// `403 withheld`.
    Withhold,
}

/// A request the stand-in saw: the target (path and query) and the `Fieldseal-PoP` header.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    pop: Option<String>,
}

struct Factory {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Factory {
    fn start(mode: Mode) -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
        let url = format!("http://127.0.0.1:{}", server.server_addr().to_ip().expect("ip").port());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for request in server.incoming_requests() {
                let pop = request.headers().iter().find(|h| h.field.equiv(POP_HEADER)).map(|h| h.value.as_str().to_owned());
                let target = request.url().to_owned();
                log.lock().expect("lock").push(Seen { method: request.method().as_str().to_owned(), target: target.clone(), pop });
                let header = |k: &str, v: &str| tiny_http::Header::from_bytes(k, v).expect("header");
                let _ = match mode {
                    Mode::Withhold => request.respond(tiny_http::Response::from_string("{\"error\":\"withheld\",\"reasons\":[\"not registered\"]}").with_status_code(403)),
                    _ if target.contains("held=3") => request.respond(tiny_http::Response::empty(304)),
                    Mode::Serve => request.respond(
                        tiny_http::Response::from_data(BUNDLE.to_vec())
                            .with_header(header("Fieldseal-Bundle-Sequence", "3"))
                            .with_header(header("Content-Disposition", &format!("attachment; filename=\"{NAME}\""))),
                    ),
                    Mode::Nameless => request.respond(tiny_http::Response::from_data(BUNDLE.to_vec()).with_header(header("Fieldseal-Bundle-Sequence", "3"))),
                };
            }
        });
        Self { url, seen }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("lock").clone()
    }
}

fn fetch(sb: &Sandbox, factory_url: &str, extra: &[&str]) -> (i32, fieldseal_kernel::Value) {
    let device = device_dir(sb);
    let mut args = vec!["bundle", "fetch", "--device-dir", device.as_str(), "--factory-url", factory_url];
    args.extend_from_slice(extra);
    sb.json(&args)
}

#[test]
fn cli_049_fetch_stores_the_bundle_under_its_dated_name() {
    let sb = Sandbox::new("bundle-fetch-stores");
    let factory = Factory::start(Mode::Serve);
    let out = sb.path("bundles");
    std::fs::create_dir_all(&out).unwrap();
    let (code, doc) = fetch(&sb, &factory.url, &["--out", &out]);
    assert_eq!(code, 0, "{doc:?}");
    assert_eq!(text(&doc, "status"), "stored");
    assert_eq!(field(&doc, "sequence").as_int(), Some(3));
    // No trust bundle was given, so the signature was not checked, and the output says so.
    assert_eq!(field(&doc, "signatureVerified"), &fieldseal_kernel::Value::Bool(false));
    let human = sb.run(&["bundle", "fetch", "--device-dir", device_dir(&sb).as_str(), "--factory-url", &factory.url, "--out", &out]);
    let shown = String::from_utf8_lossy(&human.stdout).into_owned() + &String::from_utf8_lossy(&human.stderr);
    assert!(shown.contains("signature not checked"), "{shown}");
    assert_eq!(std::fs::read(std::path::Path::new(&out).join(NAME)).expect("the bundle is stored under its name"), BUNDLE);

    // A path that is not a directory is the exact file name; a trailing slash makes a directory.
    let exact = sb.path("here/my.fsb");
    let (code, _) = fetch(&sb, &factory.url, &["--out", &exact]);
    assert_eq!(code, 0);
    assert_eq!(std::fs::read(&exact).unwrap(), BUNDLE);
    let slash = format!("{}/", sb.path("new-dir"));
    let (code, _) = fetch(&sb, &factory.url, &["--out", &slash]);
    assert_eq!(code, 0);
    assert!(std::path::Path::new(&slash).join(NAME).is_file());

    // An answer with no usable name cannot be stored in a directory.
    let nameless = Factory::start(Mode::Nameless);
    let (code, _) = fetch(&sb, &nameless.url, &["--out", &out]);
    assert_eq!(code, 1);
}

#[test]
fn cli_049_fetch_with_held_current_exits_0_and_writes_nothing() {
    let sb = Sandbox::new("bundle-fetch-current");
    let factory = Factory::start(Mode::Serve);
    let out = sb.path("bundles");
    std::fs::create_dir_all(&out).unwrap();
    let (code, doc) = fetch(&sb, &factory.url, &["--held", "3", "--out", &out]);
    assert_eq!(code, 0, "{doc:?}");
    assert_eq!(text(&doc, "status"), "current");
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    assert!(factory.seen()[0].target.ends_with("/v1/bundle?held=3"));
}

#[test]
fn cli_049_a_refusal_exits_1() {
    let sb = Sandbox::new("bundle-fetch-refused");
    let factory = Factory::start(Mode::Withhold);
    let out = sb.path("bundle.fsb");
    let (code, _) = fetch(&sb, &factory.url, &["--out", &out]);
    assert_eq!(code, 1);
    assert!(!std::path::Path::new(&out).exists());
}

#[test]
fn cli_049_an_unreachable_factory_exits_3() {
    let sb = Sandbox::new("bundle-fetch-unreachable");
    // A port that was just free and has nothing listening.
    let url = {
        let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
        format!("http://127.0.0.1:{}", server.server_addr().to_ip().expect("ip").port())
    };
    let out = sb.path("bundle.fsb");
    let (code, _) = fetch(&sb, &url, &["--out", &out]);
    assert_eq!(code, 3);
    assert!(!std::path::Path::new(&out).exists());
}

#[test]
fn cli_049_the_token_is_bound_to_the_factory_url() {
    let sb = Sandbox::new("bundle-fetch-token");
    let factory = Factory::start(Mode::Serve);
    let out = sb.path("bundle.fsb");
    let (code, _) = fetch(&sb, &factory.url, &["--held", "2", "--out", &out]);
    assert_eq!(code, 0);
    let seen = factory.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "GET");
    let token = PopToken::from_header(seen[0].pop.as_deref().expect("a Fieldseal-PoP header")).expect("a PoP token");
    // The token names the request URL without its query, and the device's own tenancy.
    assert_eq!(token.method, "GET");
    assert_eq!(token.url, format!("{}/v1/bundle", factory.url));
    let key = SigningKey::from_scalar(&SIGN_SECRET).unwrap().public_key();
    assert_eq!(token.tenancy.as_bytes(), sha256(key.as_bytes()).as_bytes());
    token.verify_signature(&key).expect("signed by the device key");
}
