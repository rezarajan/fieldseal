//! Stack mode after the spawn path: the device gets its bundle from the factory through the
//! proxy, the app needs no CLI, and the surveys it names are the published ones the log vouches
//! for. The factory and the log are `tiny_http` stand-ins on loopback.
#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fieldseal_adapters_memory::demo::DemoWorld;
use fieldseal_adapters_translog::{FileLogStore, handle};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_web::http::Request;
use fieldseal_web::routes::dispatch;
use fieldseal_web::state::AppState;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fieldseal-web-stack-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn serve(handler: impl Fn(&tiny_http::Request) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> + Send + 'static) -> String {
    let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
    let url = format!("http://127.0.0.1:{}", server.server_addr().to_ip().expect("ip").port());
    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let response = handler(&request);
            let _ = request.respond(response);
        }
    });
    url
}

/// A request the factory stand-in saw: the target and the `Fieldseal-PoP` header.
type Seen = (String, Option<String>);

fn header(k: &str, v: &str) -> tiny_http::Header {
    tiny_http::Header::from_bytes(k, v).expect("header")
}

#[test]
fn web_153_get_device_bundle_is_gone() {
    for stack in [true, false] {
        let state = AppState { examples_dir: scratch("gone"), stack, ..AppState::default() };
        let r = dispatch(&state, &Request::get("/device/bundle?tenancy=00&instrument=household-water-access"));
        assert_eq!(r.status, 404, "the app builds no bundle (stack: {stack})");
    }
}

#[test]
fn web_153_the_proxy_passes_the_pop_header_and_bundle_headers() {
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let log = seen.clone();
    let factory = serve(move |r| {
        let pop = r.headers().iter().find(|h| h.field.equiv("Fieldseal-PoP")).map(|h| h.value.as_str().to_owned());
        log.lock().unwrap().push((r.url().to_owned(), pop));
        if r.url().contains("held=3") {
            tiny_http::Response::from_data(Vec::new()).with_status_code(304)
        } else {
            tiny_http::Response::from_data(b"FSB1 bundle".to_vec())
                .with_header(header("Fieldseal-Bundle-Sequence", "3"))
                .with_header(header("Content-Disposition", "attachment; filename=\"fieldseal-bundle-20261029-3.fsb\""))
        }
    });
    let state = AppState { examples_dir: scratch("proxy"), stack: true, factory_url: Some(factory), ..AppState::default() };
    let ask = |target: &str| {
        let headers = BTreeMap::from([("fieldseal-pop".to_owned(), "the-token".to_owned())]);
        dispatch(&state, &Request::new("GET", target, headers, Vec::new()))
    };

    let r = ask("/proxy/factory/v1/bundle");
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"FSB1 bundle");
    assert_eq!(r.header("Fieldseal-Bundle-Sequence"), Some("3"));
    assert_eq!(r.header("Content-Disposition"), Some("attachment; filename=\"fieldseal-bundle-20261029-3.fsb\""));

    let r = ask("/proxy/factory/v1/bundle?held=3");
    assert_eq!(r.status, 304, "a 304 passes through unchanged");
    assert!(r.header("Fieldseal-Bundle-Sequence").is_none());

    let seen = seen.lock().unwrap();
    assert_eq!(seen[0], ("/v1/bundle".to_owned(), Some("the-token".to_owned())), "the token reaches the factory");
    assert_eq!(seen[1].0, "/v1/bundle?held=3", "the query is passed on");
}

#[test]
fn web_191_the_stack_mode_needs_no_cli_path() {
    // `FIELDSEAL_WEB_STACK=true` alone is stack mode: the state holds a flag, not an executable.
    let world = DemoWorld::new(1, AuthorityTime(1_800_000_000_000)).expect("world");
    let authority = scratch("authority");
    std::fs::write(authority.join("trust-bundle.bundle"), world.trust.encode().unwrap()).unwrap();
    let state = AppState {
        examples_dir: scratch("stack"),
        stack: true,
        authority_dir: Some(authority),
        factory_url: Some("http://factory.example:8080".into()),
        upload_url: Some("http://intake.example:8480".into()),
        allowed_builders: vec!["https://ci.example.org/builders/a".into()],
        allowed_sources: vec!["https://git.example.org/a".into(), "https://git.example.org/b".into()],
        ..AppState::default()
    };
    let r = dispatch(&state, &Request::get("/device/provisioning"));
    assert_eq!(r.status, 200, "{}", r.body_text());
    let json: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(json["allowedBuilders"], serde_json::json!(["https://ci.example.org/builders/a"]), "the allow-lists come from the environment");
    assert_eq!(json["allowedSources"].as_array().unwrap().len(), 2);
    assert_eq!(json["factoryUrl"], "http://factory.example:8080", "the device names the factory itself, as its token must");
    assert_eq!(json["uploadUrl"], "http://intake.example:8480");
}

#[test]
fn web_191_the_surveys_are_the_published_files_the_log_vouches_for() {
    let world = DemoWorld::new(1, AuthorityTime(1_800_000_000_000)).expect("world");
    let publication = &world.policy.publication;
    let record = publication.log.first().expect("a log record");
    let index = record.inclusion.leaf_index;

    // A log holding the publication's entry at its index, then one holding another there.
    let log_with = |name: &str, genuine: bool| {
        let store = Arc::new(FileLogStore::open(&scratch(name), "stack.example/log", SigningKey::from_scalar(&[9; 32]).unwrap()).unwrap());
        for _ in 0..index {
            store.append_entry(&record.entry).unwrap();
        }
        let mut other = record.entry.clone();
        if !genuine {
            other = fieldseal_publishing::domain::LogEntry::new(
                record.entry.entry_type(),
                fieldseal_kernel::id::Digest::from([1; 32]),
                record.entry.signature().clone(),
                record.entry.public_key().clone(),
            );
        }
        store.append_entry(&other).unwrap();
        serve(move |r| {
            let answer = handle(&store, r.method().as_str(), r.url(), b"", 4096);
            tiny_http::Response::from_data(answer.body).with_status_code(answer.status)
        })
    };

    let published = scratch("published");
    std::fs::write(published.join("water.published"), publication.encode()).unwrap();
    std::fs::write(published.join("deployment-policy.published"), publication.encode()).unwrap();
    std::fs::write(published.join("water.core.layout.published"), publication.encode()).unwrap();
    std::fs::write(published.join("broken.published"), b"not a publication").unwrap();
    let state = |log: String| AppState { stack: true, published_dir: Some(published.clone()), log_url: Some(log), ..AppState::default() };

    assert_eq!(fieldseal_web::stack::surveys(&state(log_with("log-genuine", true))), vec!["water".to_owned()], "the policy, the layout and the unreadable file are not surveys");
    assert!(fieldseal_web::stack::surveys(&state(log_with("log-forged", false))).is_empty(), "a file the log does not vouch for is not listed");
    assert!(fieldseal_web::stack::surveys(&state("http://127.0.0.1:1".into())).is_empty(), "with no log nothing is vouched for");
}
