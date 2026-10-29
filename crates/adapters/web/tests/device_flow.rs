//! The browser device against the demo authority over real HTTP, natively: the same Rust the
//! WebAssembly build runs, with `ureq` standing in for the worker's blocking request.
//! Named after the requirements of the `web` profile (docs/reference/spec/web-app.md).
#![allow(missing_docs)]

use std::cell::RefCell;
use std::rc::Rc;

use fieldseal_adapters_web::device::{Host, WebDevice};
use fieldseal_adapters_web::platform::Namespace;
use fieldseal_adapters_web::workbench::RenderOptions;
use fieldseal_adapters_web_demo::{Demo, DemoConfig};

fn now_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as f64
}

fn host() -> Host {
    let started = std::time::Instant::now();
    Host {
        now_ms: Rc::new(now_ms),
        elapsed_ms: Rc::new(move || started.elapsed().as_millis() as f64),
        post: Rc::new(|url, pop, body| {
            let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
            let mut r = agent.post(url).header("Content-Type", "application/cbor");
            if let Some(p) = pop {
                r = r.header("Fieldseal-PoP", p);
            }
            let mut resp = r.send(body).map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let bytes = resp.body_mut().with_config().limit(8 << 20).read_to_vec().map_err(|e| e.to_string())?;
            Ok((status, bytes))
        }),
        get: Rc::new(|_, _| Err("this test builds its bundle with the demo authority".into())),
    }
}

fn http(method: &str, url: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
    let mut resp = if method == "POST" { agent.post(url).send(body).unwrap() } else { agent.get(url).call().unwrap() };
    (resp.status().as_u16(), resp.body_mut().read_to_vec().unwrap())
}

fn json(text: &str) -> fieldseal_kernel::Value {
    fieldseal_adapters_web::json::from_json(text).expect("json")
}

fn field(v: &fieldseal_kernel::Value, k: &str) -> fieldseal_kernel::Value {
    v.as_map().and_then(|m| m.get(k)).cloned().unwrap_or_else(|| panic!("no {k} in {v:?}"))
}

// covers: PLAT-100, PLAT-105, PLAT-106, PLAT-108, PLAT-111, PLAT-113, PLAT-114, PLAT-115, PLAT-116
#[test]
fn plat_110_web_device_registers_verifies_captures_exports_uploads_and_lands() {
    let mut cfg = DemoConfig::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../examples"));
    cfg.now_ms = now_ms() as u64;
    let demo = Demo::start(cfg).expect("demo authority");
    let mut provisioning = demo.provisioning_json();
    // The device reaches the services at the demo's own URLs here (the page uses same-origin proxies).
    let mut dev = WebDevice::open(&provisioning, vec![], 1, host()).expect("device opens");
    dev.create_tenancy("246810").expect("PLAT-110: tenancy and PIN");
    let state = dev.state_json();
    assert!(state.contains("\"unattested\":true"), "PLAT-100: the device presents itself as unattested");
    assert!(state.contains("\"unknown\""), "PLAT-105: every restriction is reported as unknown, so posture findings list them");

    // Registration: the request is built in the device from its own keys and accepted by the factory.
    let token = demo.issue_registration_token("alice").expect("token");
    let req = dev.registration_request(&token, "native test").expect("PLAT-111: sealed request from a token");
    let (status, body) = http("POST", &format!("{}/v1/registrations", demo.factory_url()), &req.file);
    assert_eq!(status, 202, "the factory accepts the request: {}", String::from_utf8_lossy(&body));
    demo.confirm_registration(&req.tenancy).expect("the collector confirms the four words");
    let (_, st) = http("GET", &format!("{}/v1/registrations/{}", demo.factory_url(), req.tenancy), &[]);
    assert!(String::from_utf8_lossy(&st).contains("registered"));

    // Bundle: verified in WIRE-093 order, then imported.
    let bundle = demo.build_bundle_for(&req.tenancy, &["household-water-access"]).expect("bundle");
    // PLAT-112: a bundle with a flipped byte is refused and nothing in it is used.
    let mut tampered = bundle.bytes.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0xff;
    assert!(dev.import_bundle(&tampered).is_err(), "PLAT-112: a damaged bundle is refused");
    assert!(dev.held_json().is_err(), "nothing from the refused bundle is held");
    let report = dev.import_bundle(&bundle.bytes).expect("PLAT-112: the bundle verifies and opens");
    assert!(report.contains("publisher signatures verified"), "{report}");
    assert!(report.contains("log inclusion"), "{report}");

    // Capture through the real runtime; the core's own rules say what blocks sealing.
    let held = json(&dev.held_json().expect("held"));
    // The device knows which survey is conducted with which cohort, and the survey's title: it
    // shows the survey, not the cohort id (the bundle's assignments, WIRE-094).
    let surveys = field(&held, "surveys");
    let survey = &surveys.as_array().unwrap()[0];
    assert_eq!(field(survey, "survey").as_text(), Some("household-water-access"));
    let water_fp = field(survey, "fingerprint").as_text().expect("a fingerprint").to_owned();
    assert!(field(survey, "title").as_map().unwrap().values().any(|t| t.as_text().is_some_and(|t| !t.is_empty())), "the instrument's title is carried");
    let rosters = field(&held, "rosters");
    assert_eq!(field(survey, "cohort").as_text(), Some("village-a"), "the survey names the cohort whose roster it uses, though the bundle carries every certified roster");
    assert!(rosters.as_array().unwrap().iter().any(|r| field(r, "cohort").as_text() == Some("village-a")));
    let village = rosters.as_array().unwrap().iter().find(|r| field(r, "cohort").as_text() == Some("village-a")).expect("the survey's roster");
    let first = field(village, "subjects");
    let subject = field(&first.as_array().unwrap()[0], "subject").as_text().unwrap().to_owned();
    let mut ok = dev.start_capture(&subject, &water_fp, "first");
    if matches!(&ok, Err(e) if e == "consent_needed") {
        dev.record_consent(&subject, &water_fp, "form-seen", 1).expect("consent");
        ok = dev.start_capture(&subject, &water_fp, "first");
    }
    ok.expect("PLAT-113: capture starts");
    let set = dev.set_values("{\"household.members\":4}").expect("answers set");
    assert!(set.contains("\"unanswered\""), "{set}");
    let view = json(&set);
    let unanswered = field(&field(&view, "view"), "unanswered").as_array().unwrap().len();
    dev.acknowledge_incomplete(unanswered).expect("ack");
    let sealed = dev.seal().expect("PLAT-114: the record seals (dual write)");
    assert!(sealed.contains("seq"));
    let ev = dev.evaluate(&water_fp, &RenderOptions::default(), &Default::default(), &Default::default()).expect("evaluate");
    assert!(ev.contains("blocksSealing"));
    assert!(dev.render(&water_fp, &RenderOptions::default(), None, None).expect("render").contains("<html"));

    // A bundle the factory builds with both example instruments is held whole: each survey has its
    // own title and cohort, and the other survey can be conducted for its own cohort's people.
    let both = demo.build_bundle_for(&req.tenancy, &["household-water-access", "school-meals-baseline"]).expect("a bundle with two instruments");
    dev.import_bundle(&both.bytes).expect("the runtime accepts a bundle with two instruments");
    let held = json(&dev.held_json().expect("held"));
    let surveys = field(&held, "surveys");
    let surveys = surveys.as_array().unwrap();
    assert_eq!(surveys.len(), 2, "both surveys are listed");
    let by = |name: &str| surveys.iter().find(|s| field(s, "survey").as_text() == Some(name)).unwrap_or_else(|| panic!("no survey {name}"));
    let (water, meals) = (by("household-water-access"), by("school-meals-baseline"));
    assert_ne!(field(water, "fingerprint"), field(meals, "fingerprint"));
    let (water_fp, meals_fp) = (field(water, "fingerprint").as_text().unwrap().to_owned(), field(meals, "fingerprint").as_text().unwrap().to_owned());
    assert_ne!(field(water, "title"), field(meals, "title"), "each survey has its own title");
    assert_eq!(field(meals, "cohort").as_text(), Some("cohort-a"));
    let meals_people = field(field(&held, "rosters").as_array().unwrap().iter().find(|r| field(r, "cohort").as_text() == Some("cohort-a")).expect("the meals roster"), "subjects");
    let child = field(&meals_people.as_array().unwrap()[0], "subject").as_text().unwrap().to_owned();
    let started = dev.start_capture(&child, &meals_fp, "first");
    assert!(started.is_ok() || matches!(&started, Err(e) if e == "consent_needed"), "the meals survey starts for its own cohort: {started:?}");
    assert!(dev.start_capture(&child, &water_fp, "first").is_err(), "the water survey is not assigned to that cohort");
    assert!(dev.render(&meals_fp, &RenderOptions::default(), None, None).expect("render").contains("<html"));
    assert!(dev.render("household-water-access", &RenderOptions::default(), None, None).is_err(), "a survey is named by its fingerprint, not its name");
    dev.discard_capture();

    // Export, upload and receipt verification.
    let export = dev.export(true).expect("PLAT-115: export builds and verifies");
    assert!(export.contains("records"), "{export}");
    assert_eq!(dev.take_downloads().len(), 1, "the export is offered as a download");
    let up = dev.upload(demo.upload_url()).expect("PLAT-116: upload with challenge, proof of possession and a verified receipt");
    assert!(up.contains("\"receiptVerified\":true"), "{up}");

    // A receipt that is not the authority's is refused (DEL-064).
    assert!(dev.import_receipt(b"not a receipt").is_err(), "PLAT-116: receipts are verified before they are applied");

    // TRU-061, TRU-063: nothing invented attestation for the device; it is unattested in the registry
    // and its key evidence is software evidence.
    assert!(demo.registrations().iter().all(|r| !r.keys_attested), "the registry never records the web device as attested");
    assert!(req.sign_pub.len() == 130 && !dev.state_json().contains("\"unattested\":false"));

    // What was uploaded landed through the real gate.
    let report = demo.intake().report();
    assert!(!report.rows.is_empty(), "long-format rows landed");

    // Persistence: everything the runtime wrote is in the change log, and a reload resumes.
    let changes = dev.drain_changes();
    assert!(changes.iter().any(|c| c.namespace == Namespace::Keys), "keys are persisted in their own namespace");
    let mut state = std::collections::BTreeMap::new();
    for c in changes {
        match c.bytes {
            Some(b) => {
                state.insert((c.namespace, c.name), b);
            }
            None => {
                state.remove(&(c.namespace, c.name));
            }
        }
    }
    provisioning.push(' ');
    let persisted = state.into_iter().map(|((n, name), b)| (n, name, b)).collect();
    let mut again = WebDevice::open(&provisioning, persisted, 2, host()).expect("reload");
    let s = again.state_json();
    assert!(s.contains("\"state\":\"registered\""), "{s}");
    assert!(again.unlock("246810").is_ok(), "the PIN opens the reloaded tenancy");
    let _ = RefCell::new(0);
}
