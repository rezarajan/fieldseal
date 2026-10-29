//! The roster page reads the factory's roster store when `FIELDSEAL_WEB_ROSTER_DIR` is set,
//! showing counts only, and the examples' rosters, also as counts, when it is not.
#![allow(missing_docs)]

use std::path::PathBuf;

use fieldseal_adapters_file::roster_store::RosterStore;
use fieldseal_distribution::domain::{ConsentState, Roster, RosterEntry};
use fieldseal_kernel::id::{CohortId, Generation, SubjectId};
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

fn roster(cohort: &str, version: u64, people: &[(&str, &str, ConsentState)]) -> Roster {
    Roster {
        cohort: CohortId::new(cohort).unwrap(),
        version,
        generation: Generation(1),
        entries: people
            .iter()
            .enumerate()
            .map(|(i, (subject, display, consent))| RosterEntry {
                ordinal: i as u32 + 1,
                subject: SubjectId::new(*subject).unwrap(),
                display: (*display).to_owned(),
                attributes: Default::default(),
                consent: *consent,
                prior_status: None,
            })
            .collect(),
        consent_covers: vec![],
    }
}

fn state(roster_dir: Option<PathBuf>) -> AppState {
    AppState {
        examples_dir: examples(),
        roster_dir,
        ..AppState::default()
    }
}

/// The cohort comes with the request: the device's bundle assigns it to the survey.
const PAGE: &str = "/instruments/school-meals-baseline/roster?cohort=cohort-a";
const NO_COHORT: &str = "/instruments/school-meals-baseline/roster";

#[test]
fn web_110_the_roster_page_reads_the_mounted_roster_store_when_set_and_the_examples_otherwise() {
    let dir = scratch("roster-store");
    let store_dir = dir.join("rosters");

    // The directory does not exist yet: the page shows the state of a survey without a roster,
    // and the stand-in does not create the directory.
    let page = dispatch(&state(Some(store_dir.clone())), &Request::get(PAGE));
    assert_eq!((page.status, page.body_text().as_str()), (200, "{}"));
    assert!(!store_dir.exists(), "the stand-in only reads");

    // The latest stored version of the survey's cohort, as counts.
    let store = RosterStore::open(&store_dir).unwrap();
    store.issue(&roster("cohort-a", 1, &[("s-old", "Old Name", ConsentState::Granted)])).unwrap();
    store
        .issue(&roster(
            "cohort-a",
            2,
            &[("s-ada", "Ada Secret", ConsentState::Granted), ("s-bo", "Bo Secret", ConsentState::Refused), ("s-cy", "Cy Secret", ConsentState::Granted)],
        ))
        .unwrap();
    store.issue(&roster("village-a", 1, &[("s-vi", "Vi Secret", ConsentState::Unknown)])).unwrap();
    let page = dispatch(&state(Some(store_dir.clone())), &Request::get(PAGE));
    assert_eq!(page.status, 200);
    let body = page.body_text();
    assert!(body.contains("\"version\":2") && body.contains("\"subjects\":3"), "{body}");
    assert!(body.contains("\"granted\":2") && body.contains("\"refused\":1") && body.contains("\"unknown\":0"), "{body}");
    for hidden in ["Secret", "Old Name", "s-ada", "s-bo", "p-0001", "Participant"] {
        assert!(!body.contains(hidden), "the page shows counts only, not {hidden}");
    }

    // No cohort named, and a cohort with no roster in the store: the same empty state.
    assert_eq!(dispatch(&state(Some(store_dir.clone())), &Request::get(NO_COHORT)).body_text(), "{}");
    let elsewhere = "/instruments/school-meals-baseline/roster?cohort=no-such-cohort";
    assert_eq!(dispatch(&state(Some(store_dir.clone())), &Request::get(elsewhere)).body_text(), "{}");

    // A store directory that others can reach is refused, as the store itself refuses it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let wide = dir.join("wide");
        std::fs::create_dir(&wide).unwrap();
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(dispatch(&state(Some(wide)), &Request::get(PAGE)).status, 422);
    }

    // Unset: the examples' roster file, also as counts and never as names.
    let page = dispatch(&state(None), &Request::get(PAGE));
    assert_eq!(page.status, 200);
    let body = page.body_text();
    assert!(body.contains("\"cohort\":\"cohort-a\"") && body.contains("\"subjects\":2"), "{body}");
    for hidden in ["p-0001", "Participant", "Hill School"] {
        assert!(!body.contains(hidden), "the examples' roster is shown as counts, not {hidden}");
    }
    assert_eq!(dispatch(&state(None), &Request::get(NO_COHORT)).body_text(), "{}");
    assert_eq!(dispatch(&state(None), &Request::get(elsewhere)).body_text(), "{}");
    let _ = std::fs::remove_dir_all(dir);
}
