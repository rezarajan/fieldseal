//! The two listeners are separate surfaces, and a slow client of one never holds up the other
//! (INT-011, INT-089, SR-5).

mod support;

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use fieldseal_intake_app::AppError;
use fieldseal_intake_app::front::BodyLimits;
use support::*;

fn connect(addr: &str) -> TcpStream {
    let s = TcpStream::connect(addr.trim_start_matches("http://")).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s
}

// covers: INT-089
#[test]
fn int_089_portal_routes_are_not_served_on_the_upload_address_and_the_reverse() {
    let d = Dirs::new("surfaces");
    let app = start(&d).expect("starts");
    let on_upload = |method: &str, path: &str| raw_status(&app.upload, &format!("{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", app.upload.trim_start_matches("http://")));
    assert_eq!(on_upload("GET", "/results"), 404);
    assert_eq!(on_upload("GET", "/sign-in"), 404);
    assert_eq!(on_upload("POST", "/sign-out"), 404);
    assert_eq!(on_upload("GET", "/results/exports/3/results.csv"), 404);
    // The portal has no upload route: a POST is refused as a method it does not take.
    let status = portal_request(&app.portal, "POST", "/v1/upload");
    assert!([404, 405].contains(&status), "{status}");
    assert_eq!(portal_request(&app.portal, "POST", "/v1/upload/outbox"), 405);
    assert_eq!(portal_request(&app.portal, "GET", "/healthz"), 404);
    assert_eq!(portal_request(&app.portal, "GET", "/"), 200);
    app.stop();
}

// covers: INT-089
#[test]
fn int_089_the_portal_answers_only_for_the_host_of_its_public_url() {
    let d = Dirs::new("host");
    let app = start(&d).expect("starts");
    let with_host = |host: &str| raw_status(&app.portal, &format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"));
    assert_eq!(with_host("localhost:8481"), 200);
    assert_eq!(with_host("evil.example"), 400);
    assert_eq!(with_host(app.portal.trim_start_matches("http://")), 400, "the bind address is not the public URL");
    app.stop();
}

// covers: INT-089
#[test]
fn int_089_the_development_login_needs_a_loopback_portal() {
    let d = Dirs::new("devlogin");
    for bind in ["0.0.0.0:0", "192.0.2.1:8481", "[::]:0"] {
        match start_with(&d, &[("FIELDSEAL_INTAKE_PORTAL_BIND", bind)], BodyLimits::default()) {
            Err(e @ AppError::Config(_)) => {
                assert_eq!(e.exit_code(), 2);
                assert!(e.to_string().contains("loopback") && e.to_string().contains(bind), "{e}");
            }
            Err(e) => panic!("expected exit 2, got {e}"),
            Ok(_) => panic!("the development login was served on {bind}"),
        }
    }
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        // [::1] may be missing in a sandbox; the refusal is about the address, not the bind.
        if let Ok(app) = start_with(&d, &[("FIELDSEAL_INTAKE_PORTAL_BIND", bind)], BodyLimits::default()) {
            app.stop();
        }
    }
}

// covers: INT-011
#[test]
fn int_011_a_stalled_upload_body_does_not_stop_the_portal_or_the_upload_listener() {
    let d = Dirs::new("stall");
    let app = start(&d).expect("starts");
    // A device that sends a head, promises 1000 bytes, sends 10 and goes quiet.
    let mut stalled = connect(&app.upload);
    stalled.write_all(b"POST /v1/upload/outbox HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n0123456789").expect("send");
    std::thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    assert_eq!(portal_request(&app.portal, "GET", "/"), 200);
    assert!(started.elapsed() < Duration::from_secs(2), "the portal waited on the stalled upload: {:?}", started.elapsed());
    let started = Instant::now();
    assert_eq!(get(&format!("{}/healthz", app.upload)).0, 200);
    assert!(started.elapsed() < Duration::from_secs(2), "the upload listener waited on the stalled upload");
    // And the reverse: a stalled sign-out body on the portal.
    let mut stalled_portal = connect(&app.portal);
    stalled_portal.write_all(b"POST /sign-out HTTP/1.1\r\nHost: localhost:8481\r\nContent-Length: 100000\r\n\r\ncsrf=").expect("send");
    std::thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    assert_eq!(get(&format!("{}/healthz", app.upload)).0, 200);
    assert_eq!(portal_request(&app.portal, "GET", "/"), 200);
    assert!(started.elapsed() < Duration::from_secs(2), "a listener waited on the stalled portal request");
    drop((stalled, stalled_portal));
    app.stop();
}

// covers: INT-011
#[test]
fn int_011_a_body_that_trickles_in_under_the_floor_is_dropped_with_408() {
    let d = Dirs::new("trickle");
    let floor = BodyLimits { grace: Duration::from_millis(300), min_bytes_per_second: 8 * 1024 };
    let app = start_with(&d, &[], floor).expect("starts");
    let mut slow = connect(&app.upload);
    slow.write_all(b"POST /v1/upload/outbox HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n").expect("send");
    // A byte every 200 ms is far under 8 KiB per second, once the grace period has passed.
    for _ in 0..8 {
        std::thread::sleep(Duration::from_millis(200));
        if slow.write_all(b"x").is_err() {
            break;
        }
    }
    let (mut answer, mut buf) = (String::new(), [0u8; 1024]);
    while !answer.contains("\r\n\r\n") {
        match slow.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => answer.push_str(&String::from_utf8_lossy(&buf[..n])),
        }
    }
    assert!(answer.starts_with("HTTP/1.1 408"), "{answer}");
    // The listener was never held up by it.
    assert_eq!(get(&format!("{}/healthz", app.upload)).0, 200);
    app.stop();
}
