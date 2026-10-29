//! Bundle responses are written off the serving thread (a client that never reads cannot stall
//! the factory), and a `304` carries no sequence header.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use fieldseal_adapters_factory_http::{BundleRoutes, FactoryHttp, HttpConfig, Request};
use fieldseal_adapters_memory::distribution::MemoryBundleStore;
use fieldseal_adapters_memory::registration::SoftwareDevice;
use fieldseal_distribution::application::BundleDelivery;
use fieldseal_distribution::domain::{BundleSeq, SealedBundle};
use fieldseal_distribution::ports::BundleStore;
use fieldseal_registration::domain::RegistrationRoute;

use common::{Fixture, HTTPS, NoRosters, T0};

static JTI: AtomicU8 = AtomicU8::new(100);

// covers: DIS-040
#[test]
fn a_304_has_no_sequence_header() {
    let (f, device, record, bundles) = setup();
    bundles.put(&SealedBundle::new(record.id, BundleSeq(2), T0, b"FSB1".to_vec())).expect("put");
    let delivery = BundleDelivery::new(&f.world.store, &bundles);
    let factory = f.world.factory();
    let http = FactoryHttp::new(&factory, &f.world.idp, HttpConfig { public_url: HTTPS.into(), session_ttl_ms: 3_600_000 })
        .with_bundle_routes(BundleRoutes { fetch: &delivery, download: &delivery });
    let mut headers = std::collections::BTreeMap::new();
    headers.insert("fieldseal-pop".to_owned(), pop(&device, record.id));
    let r = http.handle(&Request::new("GET", "/v1/bundle?held=2", headers, vec![]));
    assert_eq!(r.status, 304);
    assert!(r.headers.iter().all(|(k, _)| !k.eq_ignore_ascii_case("Fieldseal-Bundle-Sequence")), "{:?}", r.headers);
}

// covers: DIS-040
#[test]
fn a_client_that_never_reads_a_bundle_does_not_stop_other_routes() {
    let (f, device, record, bundles) = setup();
    // Far more than the socket buffers on both sides hold.
    bundles.put(&SealedBundle::new(record.id, BundleSeq(1), T0, vec![7u8; 6 * 1024 * 1024])).expect("put");
    let delivery = BundleDelivery::new(&f.world.store, &bundles);
    let factory = f.world.factory();
    let http = FactoryHttp::new(&factory, &f.world.idp, HttpConfig { public_url: HTTPS.into(), session_ttl_ms: 3_600_000 })
        .with_bundle_routes(BundleRoutes { fetch: &delivery, download: &delivery });
    let server = tiny_http::Server::http("127.0.0.1:0").expect("listen");
    let addr = server.server_addr().to_ip().expect("ip");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let header = pop(&device, record.id);
    // The factory is not `Sync`, so it serves on this thread and the clients run on another.
    let stopper = stop.clone();
    let clients = std::thread::spawn(move || {
        let mut stalled = TcpStream::connect(addr).expect("connect");
        let request = format!("GET /v1/bundle HTTP/1.1\r\nHost: x\r\nFieldseal-PoP: {header}\r\n\r\n");
        stalled.write_all(request.as_bytes()).expect("send");
        // Give the factory time to start writing, then ask a cheap route while nothing is read.
        std::thread::sleep(Duration::from_millis(500));
        let mut health = TcpStream::connect(addr).expect("connect");
        health.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        health.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
        let mut answer = String::new();
        let read = health.read_to_string(&mut answer);
        // Closing the stalled client lets its writer end; raising the flag ends `run_until`.
        drop(stalled);
        stopper.store(true, Ordering::SeqCst);
        read.expect("healthz answers while a bundle is unread");
        answer
    });
    http.run_until(&server, &|| stop.load(Ordering::SeqCst), Default::default());
    let answer = clients.join().expect("clients");
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
}

fn setup() -> (Fixture, SoftwareDevice, fieldseal_registration::domain::TenancyRecord, MemoryBundleStore) {
    let f = Fixture::new(&[], &[], Box::new(NoRosters));
    let device = SoftwareDevice::new(&f.world.random);
    let token = f.world.factory().issue_token(&f.world.person("alice"), RegistrationRoute::Online, 1).expect("token");
    let body = device.body(&token.token, Some("blue"));
    let sealed = device.seal(&f.world.random, &f.world.authority.bundle, T0, &body, None);
    let submitted = f.world.factory().submit(&sealed, fieldseal_registration::application::Submission::Online).expect("submit").tenancy;
    let record = f.world.factory().confirm(&f.world.person("alice").account, &submitted.id).expect("confirm");
    (f, device, record, MemoryBundleStore::new())
}

fn pop(device: &SoftwareDevice, tenancy: fieldseal_kernel::id::TenancyId) -> String {
    let jti = [JTI.fetch_add(1, Ordering::SeqCst); 16];
    device.pop_token(tenancy, "GET", &format!("{HTTPS}/v1/bundle"), T0, jti, None).to_header()
}

// covers: DIS-040
#[test]
fn a_stalled_request_body_does_not_stop_other_routes() {
    let (f, _, _, _) = setup();
    let answer = with_clients(&f, |addr| {
        let mut stalled = TcpStream::connect(addr).expect("connect");
        // Promises 2000 bytes and sends 10.
        stalled.write_all(b"POST /v1/registrations HTTP/1.1\r\nHost: x\r\nContent-Length: 2000\r\n\r\n0123456789").expect("send");
        std::thread::sleep(Duration::from_millis(300));
        let answer = healthz(addr);
        drop(stalled);
        answer
    });
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
}

// covers: DIS-040
#[test]
fn a_chunked_body_that_stops_does_not_stop_other_routes() {
    let (f, _, _, _) = setup();
    let answer = with_clients(&f, |addr| {
        let mut stalled = TcpStream::connect(addr).expect("connect");
        stalled.write_all(b"POST /v1/registrations HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n").expect("send");
        std::thread::sleep(Duration::from_millis(300));
        let answer = healthz(addr);
        drop(stalled);
        answer
    });
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
}

// covers: DIS-040
#[test]
fn a_pipelining_client_that_never_reads_does_not_stop_other_routes() {
    let (f, _, _, _) = setup();
    let answer = with_clients(&f, |addr| {
        let mut greedy = TcpStream::connect(addr).expect("connect");
        // Many requests at once, none of the answers read.
        let batch = "GET /readyz HTTP/1.1\r\nHost: x\r\n\r\n".repeat(2000);
        greedy.set_write_timeout(Some(Duration::from_millis(500))).expect("timeout");
        let _ = greedy.write_all(batch.as_bytes());
        std::thread::sleep(Duration::from_millis(300));
        let answer = healthz(addr);
        drop(greedy);
        answer
    });
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
}

/// `GET /healthz` on a new connection, which must answer within 2 s.
fn healthz(addr: std::net::SocketAddr) -> String {
    let mut health = TcpStream::connect(addr).expect("connect");
    health.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    health.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    let mut answer = String::new();
    health.read_to_string(&mut answer).expect("healthz answers in time");
    answer
}

/// Serves a factory on this thread while `clients` runs on another; returns what it returns.
fn with_clients(f: &Fixture, clients: impl FnOnce(std::net::SocketAddr) -> String + Send + 'static) -> String {
    let server = tiny_http::Server::http("127.0.0.1:0").expect("listen");
    let addr = server.server_addr().to_ip().expect("ip");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopper = stop.clone();
    let client = std::thread::spawn(move || {
        let answer = clients(addr);
        stopper.store(true, Ordering::SeqCst);
        answer
    });
    f.with_http(|http| http.run_until(&server, &|| stop.load(Ordering::SeqCst), Default::default()));
    client.join().expect("clients")
}
