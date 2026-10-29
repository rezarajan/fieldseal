//! The collector stand-in holds no authority: its pages read the factory, the log and the
//! upload endpoint, verify what they show against the trust bundle, and say plainly when a
//! service is unreachable (WEB-151 to WEB-154). The services are `tiny_http` stand-ins on
//! loopback, and the log is the real log server's handler over a file store.
#![allow(missing_docs)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fieldseal_adapters_memory::demo::DemoWorld;
use fieldseal_adapters_translog::{FileLogStore, handle};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_web::http::Request;
use fieldseal_web::routes::dispatch;
use fieldseal_web::state::AppState;

/// A fresh directory, different on every call, so the tests can run side by side.
fn scratch(name: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!("fieldseal-web-services-{name}-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn examples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../examples")
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

/// The registration endpoint of a factory that knows one tenancy, in state `pending`.
fn factory(known: String) -> String {
    serve(move |r| {
        if r.url() == format!("/v1/registrations/{known}") {
            tiny_http::Response::from_data(b"{\"state\":\"pending\",\"reasons\":[\"awaiting confirmation\"]}".to_vec())
        } else {
            tiny_http::Response::from_data(b"{\"error\":\"not-found\"}".to_vec()).with_status_code(404)
        }
    })
}

/// A log server holding the publication's entry at the index of its record.
fn log_holding(world: &DemoWorld, name: &str) -> String {
    let record = world.policy.publication.log.first().expect("a log record");
    let store = Arc::new(FileLogStore::open(&scratch(name), "services.example/log", SigningKey::from_scalar(&[9; 32]).unwrap()).unwrap());
    for _ in 0..=record.inclusion.leaf_index {
        store.append_entry(&record.entry).unwrap();
    }
    serve(move |r| {
        let answer = handle(&store, r.method().as_str(), r.url(), b"", 4096);
        tiny_http::Response::from_data(answer.body).with_status_code(answer.status)
    })
}

fn world() -> DemoWorld {
    DemoWorld::new(1, AuthorityTime(1_800_000_000_000)).expect("world")
}

/// An app in stack mode on a world's trust bundle and publication.
fn stack_state(world: &DemoWorld, log: Option<String>, factory: Option<String>) -> AppState {
    let authority = scratch("authority");
    std::fs::write(authority.join("trust-bundle.bundle"), world.trust.encode().unwrap()).unwrap();
    let published = scratch("published");
    std::fs::write(published.join("water.published"), world.policy.publication.encode()).unwrap();
    AppState {
        examples_dir: examples(),
        stack: true,
        authority_dir: Some(authority),
        published_dir: Some(published),
        log_url: log,
        factory_url: factory,
        allowed_builders: world.publishing.allowed_builders.clone(),
        allowed_sources: world.publishing.allowed_sources.clone(),
        ..AppState::default()
    }
}

#[test]
fn web_151_the_publishing_page_reads_the_log_and_the_registration_page_reads_the_factory() {
    let world = world();
    let tenancy = "ab".repeat(32);
    let state = stack_state(&world, Some(log_holding(&world, "log-pages")), Some(factory(tenancy.clone())));

    let publishing = dispatch(&state, &Request::get("/publishing"));
    assert_eq!(publishing.status, 200);
    let page = publishing.body_text();
    let artefact = &world.policy.publication.artefact;
    assert!(page.contains(artefact.name()) && page.contains(&fieldseal_kernel::digest::lower_hex(world.policy.publication.address().as_bytes())), "the published artefact is listed");
    assert!(page.contains("<span class=\"ok\">verified</span>"), "its signatures, threshold and provenance verify against the trust bundle: {page}");
    assert!(page.contains("services.example/log"), "the log's own checkpoint is read");
    assert!(page.contains("id=\"entries\""), "the log's entries are read");
    // The stand-in log signs with a key the bundle does not pin: the page must not take its word.
    assert!(page.contains("pinned log key</dt><dd><span class=\"bad\">NO</span>"), "an unpinned log key is not trusted");
    assert!(page.contains("id=\"surveys\""), "the surveys the log vouches for are named");

    let registration = dispatch(&state, &Request::get(&format!("/registration?tenancy={tenancy}")));
    assert_eq!(registration.status, 200);
    let page = registration.body_text();
    assert!(page.contains("<strong>pending</strong>") && page.contains("awaiting confirmation"), "the state is the factory's: {page}");
    assert!(page.contains("Open the factory portal"), "the portal link stays");
    let unknown = dispatch(&state, &Request::get(&format!("/registration?tenancy={}", "cd".repeat(32)))).body_text();
    assert!(unknown.contains("does not know a registration"));
    assert!(!page.contains("Demo shortcuts") && !page.contains("Issue a registration token"), "no token or confirm shortcut");
}

#[test]
fn web_151_a_page_says_plainly_when_its_service_is_unreachable() {
    let world = world();
    let state = stack_state(&world, Some("http://127.0.0.1:1".into()), Some("http://127.0.0.1:1".into()));
    let publishing = dispatch(&state, &Request::get("/publishing")).body_text();
    assert!(publishing.contains("The log could not be read at"), "{publishing}");
    assert!(!publishing.contains("<span class=\"ok\">verified</span>") || publishing.contains("not asked"), "nothing claims the log's inclusion");
    let registration = dispatch(&state, &Request::get(&format!("/registration?tenancy={}", "ab".repeat(32)))).body_text();
    assert!(registration.contains("The factory could not be reached"), "{registration}");
    let unconfigured = AppState { examples_dir: examples(), ..AppState::default() };
    assert!(dispatch(&unconfigured, &Request::get("/publishing")).body_text().contains("No transparency log is configured"));
    assert!(dispatch(&unconfigured, &Request::get("/registration?tenancy=00")).body_text().contains("No factory is configured"));
}

#[test]
fn web_152_the_provisioning_document_carries_the_trust_bundle_and_the_allow_lists_from_the_environment() {
    let world = world();
    let mut state = stack_state(&world, None, Some("http://localhost:8080".into()));
    state.allowed_builders = vec!["https://ci.example.org/builders/a".into()];
    state.allowed_sources = vec!["https://git.example.org/a".into()];
    state.upload_url = Some("http://localhost:8480".into());
    let r = dispatch(&state, &Request::get("/device/provisioning"));
    assert_eq!(r.status, 200, "{}", r.body_text());
    let doc: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(doc["trustBundle"], fieldseal_kernel::base64url::base64url_encode(&world.trust.encode().unwrap()));
    assert_eq!(doc["allowedBuilders"], serde_json::json!(["https://ci.example.org/builders/a"]));
    assert_eq!(doc["allowedSources"], serde_json::json!(["https://git.example.org/a"]));
    assert_eq!(doc["factoryUrl"], "http://localhost:8080");
    assert!(doc.get("seed").is_none() && doc.get("key").is_none(), "no key material of the app's own");
}

#[test]
fn web_154_the_intake_route_is_404_and_no_page_links_to_it() {
    let world = world();
    let mut state = stack_state(&world, Some(log_holding(&world, "log-intake")), Some("http://localhost:8080".into()));
    state.results_url = Some("http://localhost:8481".into());
    for (method, path) in [("GET", "/intake"), ("GET", "/intake/rows.csv"), ("GET", "/intake/contract.json"), ("POST", "/intake/ingest"), ("GET", "/assets/intake.js")] {
        let r = dispatch(&state, &Request::new(method, path, Default::default(), Vec::new()));
        assert_eq!(r.status, 404, "{method} {path}");
    }
    for path in ["/instruments", "/instruments/household-water-access", "/publishing", "/registration", "/device"] {
        let page = dispatch(&state, &Request::get(path)).body_text();
        assert!(!page.contains("href=\"/intake"), "{path} does not link to the removed page");
        assert_eq!(page.matches("<nav class=\"pipeline\"").count(), 1);
        let nav = &page[page.find("<nav class=\"pipeline\"").unwrap()..page.find("</nav>").unwrap()];
        assert_eq!(nav.matches("<a href=").count(), 5, "five destinations in {path}");
        assert!(page.contains("href=\"http://localhost:8481/\""), "the footer points to the results reader on {path}");
    }
    let without = AppState { results_url: None, ..state };
    assert!(!dispatch(&without, &Request::get("/registration")).body_text().contains("Results reader"));
}
