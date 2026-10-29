//! The pages `just web` relies on: the Publishing page lists the CLI's artefact registry, and a
//! survey that stops loading keeps its last good version, shown beside the resolver's error.
#![allow(missing_docs)]

use std::path::{Path, PathBuf};

use fieldseal_adapters_memory::demo::DemoWorld;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_web::http::Request;
use fieldseal_web::routes::dispatch;
use fieldseal_web::state::AppState;

fn examples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../examples")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fieldseal-web-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn web_140_the_publishing_page_lists_the_artefacts_of_the_registry_directory() {
    let registry = scratch("registry");
    let world = DemoWorld::new(1, AuthorityTime(1_800_000_000_000)).expect("world");
    let policy = &world.policy.publication;
    std::fs::write(registry.join("one.publication"), policy.encode()).unwrap();
    std::fs::write(registry.join("broken.publication"), b"not a publication").unwrap();
    // An unreachable log: the artefacts are listed above whatever the log answers.
    let state = AppState {
        examples_dir: examples(),
        stack: Some("fieldseal".into()),
        log_url: Some("http://127.0.0.1:1".into()),
        registry_dir: Some(registry.clone()),
        ..AppState::default()
    };
    let page = dispatch(&state, &Request::get("/publishing")).body_text();
    let at = page.find("id=\"registry\"").expect("the registry section");
    assert!(at < page.find("Transparency log:").expect("the log section"), "the artefacts come above the log");
    for cell in [policy.artefact.name(), policy.artefact.version(), policy.artefact.kind().as_str(), &policy.address().to_text()] {
        assert!(page[at..].contains(cell), "{cell} is listed");
    }
    assert!(page.contains("broken.publication is unreadable"), "a file that does not decode is named");

    let empty = AppState { registry_dir: None, ..state };
    assert!(dispatch(&empty, &Request::get("/publishing")).body_text().contains("No artefact has been published yet"));
    let _ = std::fs::remove_dir_all(registry);
}

#[test]
fn web_111_a_survey_that_stops_loading_keeps_its_last_good_version_beside_the_error() {
    let dir = scratch("last-good");
    copy_dir(&examples().join("surveys"), &dir.join("surveys"));
    copy_dir(&examples().join("rosters"), &dir.join("rosters"));
    let state = AppState { examples_dir: dir.clone(), ..AppState::default() };
    let file = dir.join("surveys/household-water-access/instrument.yaml");
    let original = std::fs::read_to_string(&file).unwrap();
    let get = |t: &str| dispatch(&state, &Request::get(t));

    let first = get("/instruments/household-water-access");
    assert_eq!(first.status, 200);
    assert!(!first.body_text().contains("current-errors"));

    // An edit that does not resolve: the last good version, the error with its position.
    std::fs::write(&file, original.replacen("version:", "versoin:", 1)).unwrap();
    let broken = get("/instruments/household-water-access").body_text();
    assert!(broken.contains("id=\"current-errors\""), "the error is shown");
    assert!(broken.contains("instrument.yaml:"), "with the file and position");
    assert!(broken.contains("id=\"rendered\""), "the last good version is still drawn");
    assert_eq!(get("/instruments/household-water-access/render").status, 200);
    assert!(get("/instruments").body_text().contains("showing the last good version"));

    // Fixed: the error goes.
    std::fs::write(&file, original).unwrap();
    assert!(!get("/instruments/household-water-access").body_text().contains("current-errors"));

    // After a restart (a fresh state) whose first load is invalid, the error stands alone.
    std::fs::write(&file, "not: [valid").unwrap();
    let fresh = AppState { examples_dir: dir.clone(), ..AppState::default() };
    let alone = dispatch(&fresh, &Request::get("/instruments/household-water-access")).body_text();
    assert!(alone.contains("cannot be drawn") && !alone.contains("id=\"rendered\""));
    let _ = std::fs::remove_dir_all(dir);
}
