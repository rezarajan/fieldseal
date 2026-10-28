//! End to end: a real server on a loopback socket, driven by the HTTP client through the
//! contract suite.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;

use fieldseal_adapters_translog::{FileLogStore, HttpLogTransport, HttpTranslog};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_publishing::contract::{RecordingTransport, transparency_log_contract};
use fieldseal_publishing::ports::TransparencyLog;
use fieldseal_translog::http::Server;

fn temp_dir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("fieldseal-translog-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn raw(addr: std::net::SocketAddr, request: &[u8]) -> String {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.write_all(request).expect("write");
    s.shutdown(std::net::Shutdown::Write).expect("half-close");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn pub_100_104_the_http_client_passes_the_contract_against_a_running_server() {
    let dir = temp_dir("contract");
    let key = SigningKey::from_scalar(&[3; 32]).expect("key");
    let store = Arc::new(FileLogStore::open(&dir, "e2e.example/log", key).expect("open"));
    let pin = store.pin();
    let server = Server::bind("127.0.0.1:0", store.clone(), 4096).expect("bind");
    let addr = server.local_addr().expect("addr");
    let stop = server.shutdown_handle().expect("handle");
    let thread = std::thread::spawn(move || server.run());

    let base = format!("http://{addr}");
    let transport = RecordingTransport::forwarding(HttpLogTransport::new(&base).expect("transport"));
    transparency_log_contract(transport, |t| HttpTranslog::new(t).pinned(pin.clone()), &pin);
    assert_eq!(store.size(), 3, "the server logged exactly the three contract entries");

    // The log is also reachable in-process by the same store, and agrees.
    let cp = HttpTranslog::new(HttpLogTransport::new(&base).expect("transport")).checkpoint().expect("checkpoint");
    assert_eq!(cp, store.checkpoint().expect("direct"));

    // Hostile requests are answered, not crashed on, and log nothing.
    assert!(raw(addr, b"GARBAGE\r\n\r\n").starts_with("HTTP/1.1 400"));
    assert!(raw(addr, b"POST /append HTTP/1.1\r\nContent-Length: 999999\r\n\r\n").starts_with("HTTP/1.1 413"));
    assert!(raw(addr, b"POST /append HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").starts_with("HTTP/1.1 501"));
    assert!(raw(addr, b"POST /append HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort").starts_with("HTTP/1.1 400"));
    assert!(raw(addr, b"GET /inclusion/0/99 HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 404"));
    assert!(raw(addr, b"GET /checkpoint HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 200"));
    assert_eq!(store.size(), 3);

    stop.shutdown();
    thread.join().expect("server thread");
    drop(store);
    let reopened = FileLogStore::open(&dir, "e2e.example/log", SigningKey::from_scalar(&[3; 32]).expect("key")).expect("reopen");
    assert_eq!(reopened.size(), 3, "the entries survive the server");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pub_100_a_client_of_a_stopped_server_reports_unavailable() {
    let dir = temp_dir("stopped");
    let store = Arc::new(FileLogStore::open(&dir, "e2e.example/log", SigningKey::from_scalar(&[4; 32]).expect("key")).expect("open"));
    let server = Server::bind("127.0.0.1:0", store, 4096).expect("bind");
    let addr = server.local_addr().expect("addr");
    drop(server);
    let client = HttpTranslog::new(HttpLogTransport::new(&format!("http://{addr}")).expect("transport"));
    assert!(matches!(client.checkpoint(), Err(fieldseal_publishing::ports::LogError::Unavailable(_))));
    let _ = std::fs::remove_dir_all(&dir);
}
