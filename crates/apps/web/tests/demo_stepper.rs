//! The guided demo (WEB-195 to WEB-199): eight steps, each naming the production component that
//! does it, a banner that the collector stand-in is not the native app, and a stepper that
//! performs nothing for the authority. The browser run of the eight steps is
//! `tools/browser-tests/demo-e2e.sh`.
#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use fieldseal_web::http::Request;
use fieldseal_web::routes::dispatch;
use fieldseal_web::state::AppState;
use fieldseal_web::ui::{BANNER, NAV};

fn state() -> AppState {
    AppState {
        examples_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../examples"),
        factory_url: Some("http://localhost:8080".into()),
        results_url: Some("http://localhost:8481".into()),
        ..AppState::default()
    }
}

fn page(path: &str) -> String {
    let r = dispatch(&state(), &Request::get(path));
    assert_eq!(r.status, 200, "{path}");
    r.body_text()
}

fn primary_actions(html: &str) -> usize {
    html.matches("btn btn-primary").count() + html.matches("class=\"btn-primary").count()
}

#[test]
fn web_196_the_stepper_holds_no_credential_and_makes_no_non_get_request_to_a_service() {
    let server = include_str!("../src/demo_steps.rs");
    let script = include_str!("../assets/demo.js");
    // The server code reads through the log's transport and the catalogue; it has no client of its
    // own, no request method but GET, no key, session or token.
    for forbidden in ["ureq", ".post(", "Method::Post", "\"POST\"", "\"PUT\"", "\"DELETE\"", "Authorization", "Bearer", "Fieldseal-PoP", "SigningKey", "secret", "Cookie", "session"] {
        let code: String = server.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        assert!(!code.contains(forbidden), "demo_steps.rs mentions {forbidden}");
    }
    // The script only reads: every fetch is a plain GET with no options, and it opens no other channel.
    assert!(script.matches("fetch(").count() >= 1);
    for line in script.lines().filter(|l| l.contains("fetch(")) {
        assert!(!line.contains("method") && !line.contains("body") && !line.contains("headers") && !line.contains("credentials"), "{line}");
    }
    for forbidden in ["XMLHttpRequest", "sendBeacon", "WebSocket", "EventSource", "method:"] {
        assert!(!script.contains(forbidden), "demo.js uses {forbidden}");
    }
    // No route records a confirmation, and nothing but GET reaches the stepper.
    for path in ["/demo", "/demo/1", "/demo/3", "/demo/confirm"] {
        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            let r = dispatch(&state(), &Request::new(method, path, BTreeMap::new(), b"confirmed=1".to_vec()));
            assert_eq!(r.status, 404, "{method} {path}");
        }
    }
    assert_eq!(dispatch(&state(), &Request::get("/demo/confirm")).status, 404);
}

#[test]
fn web_195_each_step_names_its_production_component() {
    let overview = page("/demo");
    for n in 1..=8 {
        assert!(overview.contains(&format!("href=\"/demo/{n}\"")), "/demo links to step {n}");
    }
    let titles = ["Compile the survey", "Publish to the factory", "Register a device", "Load the published bundle", "Manage rosters", "Conduct a survey", "Export", "Read the results"];
    for (i, title) in titles.iter().enumerate() {
        let n = i + 1;
        let html = page(&format!("/demo/{n}"));
        assert!(html.contains(&format!("<h1>{title}</h1>")), "step {n} title");
        assert!(html.contains(&format!("Step {n} of 8")), "step {n} position");
        for part in ["Who does this in production", "In this demo", "How to do it", "<h2 id=\"confirmation-h\">Confirmation</h2>", "<strong>Read from:</strong>"] {
            assert!(html.contains(part), "step {n} lacks {part}");
        }
        assert!(html.contains("class=\"lede\""), "step {n} says what happens");
        assert!(html.contains("Back"), "step {n} has Back");
        assert_eq!(html.contains(">Next</a>"), n < 8, "step {n} Next");
        assert!(overview.contains(title), "/demo table names {title}");
    }
    // The command steps give the exact command; the stepper never runs it.
    assert!(page("/demo/1").contains("fieldseal survey check examples/surveys/"));
    assert!(page("/demo/2").contains("just publish my-visit"));
    assert!(page("/demo/5").contains("fieldseal roster issue --factory-url http://localhost:8080"));
    // Production components are named, and so is the one that stands in.
    assert!(overview.contains("Everything except this collector stand-in is a production component"));
    assert!(page("/demo/3").contains("The factory portal and the factory (production)"));
    assert!(page("/demo/6").contains("It stands in for the Android app."));
}

#[test]
fn web_197_every_confirmation_says_where_it_was_read_and_has_a_check_it_link() {
    for n in 1..=7 {
        let html = page(&format!("/demo/{n}"));
        assert!(html.contains("<h3>Check it</h3>"), "step {n} has a check-it list");
        assert!(html.contains("<ul class=\"checks\">"), "step {n}");
    }
    let script = include_str!("../assets/demo.js");
    assert!(script.contains("the device's own view"), "the script labels the device's view");
    assert!(script.contains("read now from the factory"), "the script labels what the factory reported");
    assert!(page("/demo/3").contains("The state is read now from the factory."));
}

#[test]
fn web_197_step_8_links_to_the_results_reader_and_confirms_nothing() {
    let html = page("/demo/8");
    assert!(html.contains("<a class=\"btn btn-primary\" href=\"http://localhost:8481/\""), "the link to the results reader");
    assert!(html.contains("Nothing is confirmed here."));
    assert!(!html.contains("id=\"facts\""), "no panel the script could fill");
}

#[test]
fn web_198_the_banner_is_on_the_demo_and_device_pages() {
    assert_eq!(BANNER, "This collector stand-in stands in for the native Android and iOS apps, which do not exist yet; only the bindings do.");
    assert!(page("/demo").contains(BANNER));
    assert!(page("/device").contains(BANNER));
}

#[test]
fn web_199_step_3_says_to_retire_the_old_device_before_registering_again() {
    let html = page("/demo/3");
    assert!(html.contains("retire the old device on the factory portal (REG-043)"), "step 3 tells a presenter to retire the old device");
}

#[test]
fn web_199_the_last_page_points_to_acceptance_and_release() {
    let html = page("/demo/8");
    assert!(html.contains("<code>just acceptance</code>"));
    assert!(html.contains("<code>just release</code>"));
}

#[test]
fn web_180_navigation_has_five_destinations_in_pipeline_order() {
    let labels: Vec<&str> = NAV.iter().map(|(label, _)| *label).collect();
    assert_eq!(labels, ["Guided demo", "Instruments", "Publishing", "Registration", "Device"]);
    assert_eq!(NAV[0].1, "/demo");
    for path in ["/demo", "/demo/4", "/instruments", "/publishing", "/registration", "/device"] {
        let html = page(path);
        let mut at = 0;
        for (label, href) in NAV {
            let link = format!("<a href=\"{href}\"");
            let found = html[at..].find(&link).unwrap_or_else(|| panic!("{path} lacks the {label} link in order"));
            at += found + link.len();
        }
    }
    // The stand-in opens on the guided demo.
    let root = dispatch(&state(), &Request::get("/"));
    assert_eq!(root.status, 303);
    assert_eq!(root.header("Location"), Some("/demo"));
    // The demo is the current destination on its pages.
    assert!(page("/demo/5").contains("<a href=\"/demo\" aria-current=\"page\">Guided demo</a>"));
}

#[test]
fn web_181_each_step_has_one_primary_action() {
    for path in ["/demo", "/demo/1", "/demo/2", "/demo/3", "/demo/4", "/demo/5", "/demo/6", "/demo/7", "/demo/8"] {
        assert_eq!(primary_actions(&page(path)), 1, "{path}");
    }
}
