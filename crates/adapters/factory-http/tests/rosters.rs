//! `POST /v1/rosters` (REG-047, DIS-063, DIS-080) through `FactoryHttp::handle`, over the
//! in-memory registration ports, a stub `BearerVerifier` and a temporary roster store.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fieldseal_adapters_factory_http::OperatorEvent;
use fieldseal_adapters_file::roster_issuer::FileRosterIssuer;
use fieldseal_adapters_file::roster_store::RosterStore;
use fieldseal_kernel::id::CohortId;
use fieldseal_kernel::{Value, cbor};
use fieldseal_registration::ports::RegistryStore;

use common::{Fixture, OPERATOR_TOKEN, assignment_body, json, request};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A fresh directory that is removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("fieldseal-rosters-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let _ = std::fs::remove_dir_all(&dir);
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Rig {
    f: Fixture,
    store: RosterStore,
    _dir: Scratch,
}

fn rig() -> Rig {
    let dir = Scratch::new();
    let issuer = FileRosterIssuer::new(RosterStore::open(&dir.0).expect("store"));
    let f = Fixture::new(&["survey-a", "survey-b"], &["cohort-a"], Box::new(issuer));
    Rig { f, store: RosterStore::open(&dir.0).expect("store"), _dir: dir }
}

/// A roster body in the issue form: `cohort`, `version` and two subjects whose second `display`
/// is `second`.
fn roster(cohort: &str, version: i128, second: &str) -> Vec<u8> {
    let subject = |id: &str, display: &str| cbor::map([("subject", Value::Text(id.into())), ("display", Value::Text(display.into())), ("consent", Value::Text("granted".into()))]);
    cbor::encode(&cbor::map([
        ("cohort", Value::Text(cohort.into())),
        ("version", Value::Int(version)),
        ("subjects", Value::Array(vec![subject("s-0001", "Amara Okafor"), subject("s-0002", second)])),
    ]))
    .expect("encodable")
}

fn issue(r: &Rig, token: Option<&str>, body: Vec<u8>) -> fieldseal_adapters_factory_http::Response {
    r.f.call(&request("POST", "/v1/rosters", token, body))
}

fn cohort() -> CohortId {
    CohortId::new("cohort-a").expect("cohort")
}

#[test]
fn reg_047_an_operator_can_issue_a_roster_version() {
    let r = rig();
    let done = issue(&r, Some(OPERATOR_TOKEN), roster("cohort-a", 1, "Bo Lindqvist"));
    assert_eq!(done.status, 200);
    let body = json(&done);
    assert_eq!((body["status"].as_str(), body["version"].as_u64(), body["cohort"].as_str()), (Some("issued"), Some(1), Some("cohort-a")));
    assert!(body["digest"].as_str().is_some_and(|d| d.starts_with("sha256:") && d.len() == 7 + 64));
    assert_eq!(r.store.versions(&cohort()).expect("versions"), vec![1]);
}

#[test]
fn reg_047_a_collector_is_not_authorised() {
    let r = rig();
    let refused = issue(&r, Some("collector-token"), roster("cohort-a", 1, "Bo Lindqvist"));
    assert_eq!((refused.status, json(&refused)["error"].as_str().map(str::to_owned)), (403, Some("not-authorised".into())));
    assert_eq!(r.store.versions(&cohort()).expect("versions"), Vec::<u64>::new());
    assert_eq!(r.f.world.store.roster_issues(), Ok(vec![]));
}

#[test]
fn reg_047_a_weak_method_is_refused() {
    let r = rig();
    let refused = issue(&r, Some("weak-token"), roster("cohort-a", 1, "Bo Lindqvist"));
    assert_eq!((refused.status, json(&refused)["error"].as_str().map(str::to_owned)), (403, Some("authentication-too-weak".into())));
    assert_eq!(r.store.versions(&cohort()).expect("versions"), Vec::<u64>::new());
}

#[test]
fn reg_047_an_invalid_roster_is_422_and_stores_nothing() {
    let r = rig();
    // WIRE-198: a generation (or any unknown key) is refused.
    let mut m = match cbor::decode(&roster("cohort-a", 1, "Bo Lindqvist")).expect("decodes") {
        Value::Map(m) => m,
        _ => unreachable!("a roster is a map"),
    };
    m.insert("generation".into(), Value::Int(1));
    let with_generation = cbor::encode(&Value::Map(m)).expect("encodable");
    for body in [with_generation, roster("cohort-a", 0, "Bo Lindqvist"), b"\xff\xff not cbor".to_vec(), b"\xa0".to_vec()] {
        let refused = issue(&r, Some(OPERATOR_TOKEN), body);
        assert_eq!((refused.status, json(&refused)["error"].as_str().map(str::to_owned)), (422, Some("roster-invalid".into())));
    }
    assert_eq!(r.store.versions(&cohort()).expect("versions"), Vec::<u64>::new());
    assert_eq!(r.f.world.store.roster_issues(), Ok(vec![]));
}

#[test]
fn reg_047_a_lower_version_is_not_newer() {
    let r = rig();
    assert_eq!(issue(&r, Some(OPERATOR_TOKEN), roster("cohort-a", 3, "Bo Lindqvist")).status, 200);
    let refused = issue(&r, Some(OPERATOR_TOKEN), roster("cohort-a", 2, "Bo Lindqvist"));
    assert_eq!((refused.status, json(&refused)["error"].as_str().map(str::to_owned)), (409, Some("not-newer".into())));
    assert_eq!(r.store.versions(&cohort()).expect("versions"), vec![3]);
}

#[test]
fn reg_047_different_content_at_an_existing_version_is_version_taken() {
    let r = rig();
    assert_eq!(issue(&r, Some(OPERATOR_TOKEN), roster("cohort-a", 1, "Bo Lindqvist")).status, 200);
    let refused = issue(&r, Some(OPERATOR_TOKEN), roster("cohort-a", 1, "Someone Else"));
    assert_eq!((refused.status, json(&refused)["error"].as_str().map(str::to_owned)), (409, Some("version-taken".into())));
    assert_eq!(r.f.world.store.roster_issues().expect("issues").len(), 1);
}

#[test]
fn reg_047_identical_content_is_unchanged_and_writes_no_record() {
    let r = rig();
    let first = issue(&r, Some(OPERATOR_TOKEN), roster("cohort-a", 1, "Bo Lindqvist"));
    let again = issue(&r, Some(OPERATOR_TOKEN), roster("cohort-a", 1, "Bo Lindqvist"));
    assert_eq!((again.status, json(&again)["status"].as_str().map(str::to_owned)), (200, Some("unchanged".into())));
    assert_eq!(json(&again)["digest"], json(&first)["digest"]);
    assert_eq!(r.f.world.store.roster_issues().expect("issues").len(), 1);
    assert_eq!(r.f.events.lock().expect("lock").len(), 1, "one event for one issue");
}

#[test]
fn reg_047_a_stop_between_the_store_write_and_the_record_heals_on_the_next_issue() {
    let r = rig();
    // The store write happened and the process stopped before the journal record.
    let stored = FileRosterIssuer::new(RosterStore::open(&r._dir.0).expect("store"));
    assert!(matches!(
        fieldseal_registration::ports::RosterIssuer::issue(&stored, &cohort(), &roster("cohort-a", 1, "Bo Lindqvist"), &[]),
        fieldseal_registration::ports::IssueOutcome::Issued { .. }
    ));
    assert_eq!(r.f.world.store.roster_issues(), Ok(vec![]));
    let healed = issue(&r, Some(OPERATOR_TOKEN), roster("cohort-a", 1, "Bo Lindqvist"));
    assert_eq!((healed.status, json(&healed)["status"].as_str().map(str::to_owned)), (200, Some("issued".into())));
    assert_eq!(r.f.world.store.roster_issues().expect("issues").len(), 1, "the missing record is written");
}

#[test]
fn reg_047_each_issue_is_journaled_with_account_roles_methods_time_cohort_version_and_digest() {
    let r = rig();
    let done = issue(&r, Some(OPERATOR_TOKEN), roster("cohort-a", 1, "Bo Lindqvist"));
    let record = r.f.world.store.roster_issues().expect("issues").remove(0);
    assert_eq!((record.cohort.as_str(), record.version), ("cohort-a", 1));
    assert_eq!(format!("sha256:{}", fieldseal_kernel::digest::lower_hex(record.digest.as_bytes())), json(&done)["digest"].as_str().expect("digest"));
    assert_eq!((record.by.0.as_str(), record.roles.as_slice(), record.methods.as_slice()), ("sub-ops", &["operator".to_owned()][..], &["hwk".to_owned(), "phr".to_owned()][..]));
    assert_eq!(record.at, common::T0);
}

#[test]
fn reg_047_the_journal_and_events_hold_no_subject_data() {
    let r = rig();
    assert_eq!(issue(&r, Some(OPERATOR_TOKEN), roster("cohort-a", 1, "Bo Lindqvist")).status, 200);
    let journal = format!("{:?}", r.f.world.store.roster_issues().expect("issues"));
    let events = format!("{:?}", r.f.events.lock().expect("lock"));
    for text in [&journal, &events] {
        assert!(!text.contains("s-0001") && !text.contains("Amara") && !text.contains("Bo Lindqvist"), "no subject id or display name in {text}");
    }
    assert!(matches!(r.f.events.lock().expect("lock").as_slice(), [OperatorEvent::RosterIssued { cohort, version: 1, .. }] if cohort == "cohort-a"));
    // A refusal repeats no value of the body either.
    let refused = issue(&r, Some(OPERATOR_TOKEN), roster("cohort-b", 1, "Bo Lindqvist"));
    let text = String::from_utf8_lossy(&refused.body).into_owned();
    assert!(!text.contains("s-0001") && !text.contains("Bo Lindqvist") && !text.contains("Amara"), "{text}");
}

#[test]
fn reg_047_an_issue_notifies_the_reconciler() {
    let r = rig();
    let tenancy = r.f.world.register_as("alice");
    assert_eq!(r.f.call(&request("POST", "/v1/assignments", Some(OPERATOR_TOKEN), assignment_body("sub-alice", "survey-a", "cohort-a"))).status, 200);
    r.f.notified.lock().expect("lock").clear();
    assert_eq!(issue(&r, Some(OPERATOR_TOKEN), roster("cohort-a", 1, "Bo Lindqvist")).status, 200);
    assert_eq!(r.f.notified.lock().expect("lock").as_slice(), &[tenancy.id], "the tenancy that holds the cohort is rebuilt");
    // An unchanged issue rebuilds nothing.
    r.f.notified.lock().expect("lock").clear();
    assert_eq!(issue(&r, Some(OPERATOR_TOKEN), roster("cohort-a", 1, "Bo Lindqvist")).status, 200);
    assert!(r.f.notified.lock().expect("lock").is_empty());
}

/// The roster body of `roster`, naming the surveys its consent covers.
fn roster_covering(cohort: &str, version: i128, covers: &[&str]) -> Vec<u8> {
    let Value::Map(mut m) = cbor::decode(&roster(cohort, version, "Bo Lindqvist")).expect("decodes") else { unreachable!("a roster is a map") };
    m.insert("consent-covers".into(), Value::Array(covers.iter().map(|c| Value::Text((*c).into())).collect()));
    cbor::encode(&Value::Map(m)).expect("encodable")
}

#[test]
fn reg_047_col_031_a_roster_that_declares_nothing_covers_the_surveys_assigned_to_its_cohort_now() {
    let r = rig();
    let assign = |survey: &str| {
        let done = r.f.call(&request("POST", "/v1/assignments", Some(OPERATOR_TOKEN), assignment_body("sub-alice", survey, "cohort-a")));
        assert_eq!(done.status, 200, "{}", String::from_utf8_lossy(&done.body));
    };
    assign("survey-a");
    assert_eq!(issue(&r, Some(OPERATOR_TOKEN), roster("cohort-a", 1, "Bo Lindqvist")).status, 200);
    assert_eq!(r.store.get(&cohort(), 1).expect("get").expect("stored").consent_covers, ["survey-a"], "the coverage is fixed at issue");

    // A survey assigned afterwards does not change the roster already issued, and the same bytes
    // are still that roster.
    assign("survey-b");
    let again = issue(&r, Some(OPERATOR_TOKEN), roster("cohort-a", 1, "Bo Lindqvist"));
    assert_eq!((again.status, json(&again)["status"].as_str().map(str::to_owned)), (200, Some("unchanged".into())));
    assert_eq!(r.store.get(&cohort(), 1).expect("get").expect("stored").consent_covers, ["survey-a"]);
    // The next version takes the surveys assigned by then.
    assert_eq!(issue(&r, Some(OPERATOR_TOKEN), roster("cohort-a", 2, "Bo Lindqvist")).status, 200);
    assert_eq!(r.store.get(&cohort(), 2).expect("get").expect("stored").consent_covers, ["survey-a", "survey-b"]);
    // A roster that names its surveys keeps them whatever is assigned.
    assert_eq!(issue(&r, Some(OPERATOR_TOKEN), roster_covering("cohort-a", 3, &["survey-b"])).status, 200);
    assert_eq!(r.store.get(&cohort(), 3).expect("get").expect("stored").consent_covers, ["survey-b"]);
}
