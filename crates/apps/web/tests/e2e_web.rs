//! One end-to-end path through the showcase, without a browser: the server's routes and the
//! browser device's native twin (the same Rust the WebAssembly build runs) over the embedded
//! demo authority. Registration, bundle, capture, export, upload, then the Intake and
//! Publishing pages show what happened. WEB-170, PLAT-110..116, WEB-154, WEB-160..162.

use std::collections::BTreeMap;
use std::rc::Rc;

use fieldseal_adapters_web::device::{Host, WebDevice};
use fieldseal_adapters_web_demo::{Demo, DemoConfig};
use fieldseal_web::http::Request;
use fieldseal_web::routes::dispatch;
use fieldseal_web::state::{AppState, DemoHandle};

fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as f64
}

fn host() -> Host {
    Host {
        now_ms: Rc::new(now),
        elapsed_ms: Rc::new(|| 0.0),
        post: Rc::new(|url, pop, body| {
            let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
            let mut r = agent.post(url).header("Content-Type", "application/cbor");
            if let Some(p) = pop {
                r = r.header("Fieldseal-PoP", p);
            }
            let mut resp = r.send(body).map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            Ok((status, resp.body_mut().read_to_vec().map_err(|e| e.to_string())?))
        }),
    }
}

// covers: WEB-156
#[test]
fn web_170_the_whole_path_through_the_routes_and_the_device() {
    let mut cfg = DemoConfig::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../examples"));
    cfg.now_ms = now() as u64;
    let demo = Demo::start(cfg).expect("demo");
    let state = AppState {
        examples_dir: std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../examples")),
        factory_url: Some(demo.factory_url().to_owned()),
        upload_url: Some(demo.upload_url().to_owned()),
        demo: Some(DemoHandle(demo)),
        ..AppState::default()
    };
    let get = |t: &str| dispatch(&state, &Request::get(t));

    // The device page and what it fetches.
    let device_page = get("/device");
    assert_eq!(device_page.status, 200);
    assert!(device_page.body_text().contains("data-step=\"export\""), "the page has its four steps");
    let provisioning = get("/device/provisioning");
    assert_eq!(provisioning.status, 200);
    let mut dev = WebDevice::open(&provisioning.body_text(), vec![], 1, host()).expect("the device starts from the served provisioning");
    dev.create_tenancy("246810").expect("tenancy");

    // Registration through the authority's real factory API, words confirmed by the collector.
    let token = demo.issue_registration_token("alice").expect("token");
    let req = dev.registration_request(&token, "e2e").expect("request");
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
    let answer = agent.post(&format!("{}/v1/registrations", demo.factory_url())).send(&req.file[..]).expect("post");
    assert_eq!(answer.status().as_u16(), 202);
    assert!(get("/registration").body_text().contains("Registration"));
    demo.confirm_registration(&req.tenancy).expect("confirmed");

    // The bundle comes from the page's own route and verifies in the device.
    let bundle = get(&format!("/device/bundle?tenancy={}&instrument=household-water-access", req.tenancy));
    assert_eq!(bundle.status, 200);
    assert_eq!(bundle.header("X-Bundle-Development-Allowance"), Some("true"), "rosters were released under the development allowance");
    assert!(demo.registrations().iter().all(|r| !r.keys_attested), "TRU-061, TRU-063: the web device is never reported as attested");
    let report = dev.import_bundle(&bundle.body).expect("the bundle verifies");
    assert!(report.contains("publisher signatures verified"));

    // Capture, seal, export, upload.
    let held = fieldseal_adapters_web::json::from_json(&dev.held_json().unwrap()).unwrap();
    let subject = held.as_map().unwrap()["rosters"].as_array().unwrap()[0].as_map().unwrap()["subjects"].as_array().unwrap()[0].as_map().unwrap()["subject"].as_text().unwrap().to_owned();
    if dev.start_capture(&subject, "first").is_err() {
        dev.record_consent(&subject, "form-seen", 1).expect("consent");
        dev.start_capture(&subject, "first").expect("capture");
    }
    let view = dev.set_values("{\"household.members\":3}").expect("values");
    let n = fieldseal_adapters_web::json::from_json(&view).unwrap().as_map().unwrap()["view"].as_map().unwrap()["unanswered"].as_array().unwrap().len();
    dev.acknowledge_incomplete(n).unwrap();
    dev.seal().expect("sealed");
    dev.export(true).expect("export");
    let up = dev.upload(demo.upload_url()).expect("upload");
    assert!(up.contains("receiptVerified"));

    // The pages show what happened.
    let intake = get("/intake").body_text();
    assert!(intake.contains("household.members"), "the landed row is on the Intake page");
    let filtered = get("/intake?f_item=household.members").body_text();
    assert!(filtered.contains("1 matching"), "filtering by column keeps the matching row");
    assert!(get("/intake?f_item=no-such-item").body_text().contains("0 matching"));
    let csv = get("/intake/rows.csv");
    assert_eq!(csv.status, 200);
    assert!(csv.body_text().contains("household.members"));
    let publishing = get("/publishing").body_text();
    assert!(publishing.contains("household-water-access"));
    let _: BTreeMap<String, String> = BTreeMap::new();
}
