//! `POST /v1/assignments` and `GET /v1/assignments` (REG-046, REG-032, REG-085) through
//! `FactoryHttp::handle`, over the in-memory registration ports and a stub `BearerVerifier`.

mod common;

use fieldseal_adapters_factory_http::OperatorEvent;
use fieldseal_kernel::id::{CohortId, Generation};
use fieldseal_registration::domain::AccountId;
use fieldseal_registration::ports::RegistryStore;

use common::{Fixture, NoRosters, OPERATOR_TOKEN, assignment_body, json, request};

fn fixture() -> Fixture {
    Fixture::new(&["survey-a", "survey-b"], &["cohort-a", "cohort-b"], Box::new(NoRosters))
}

fn assign(f: &Fixture, token: Option<&str>, account: &str, survey: &str, cohort: &str) -> fieldseal_adapters_factory_http::Response {
    f.call(&request("POST", "/v1/assignments", token, assignment_body(account, survey, cohort)))
}

fn cohort(name: &str) -> CohortId {
    CohortId::new(name).expect("cohort")
}

#[test]
fn reg_046_an_operator_can_assign_and_list() {
    let f = fixture();
    let made = assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "survey-a", "cohort-a");
    assert_eq!(made.status, 200);
    let body = json(&made);
    assert_eq!(body["status"], "assigned");
    assert_eq!((body["survey"].as_str(), body["cohort"].as_str(), body["generation"].as_u64()), (Some("survey-a"), Some("cohort-a"), Some(1)));
    let listed = f.call(&request("GET", "/v1/assignments", Some(OPERATOR_TOKEN), vec![]));
    assert_eq!(listed.status, 200);
    let rows = &json(&listed)["assignments"];
    assert_eq!(rows.as_array().map(Vec::len), Some(1));
    assert_eq!(rows[0]["account"], "sub-alice");
    assert_eq!(rows[0]["seq"], 1);
}

#[test]
fn reg_046_a_collector_is_not_authorised() {
    let f = fixture();
    let r = assign(&f, Some("collector-token"), "sub-alice", "survey-a", "cohort-a");
    assert_eq!((r.status, json(&r)["error"].as_str().map(str::to_owned)), (403, Some("not-authorised".into())));
    let r = f.call(&request("GET", "/v1/assignments", Some("collector-token"), vec![]));
    assert_eq!(r.status, 403);
    assert_eq!(f.world.store.assignments(), Ok(vec![]));
}

#[test]
fn reg_046_a_weak_method_is_refused() {
    let f = fixture();
    let r = assign(&f, Some("weak-token"), "sub-alice", "survey-a", "cohort-a");
    assert_eq!((r.status, json(&r)["error"].as_str().map(str::to_owned)), (403, Some("authentication-too-weak".into())));
    assert_eq!(f.world.store.assignments(), Ok(vec![]));
}

#[test]
fn reg_046_an_unknown_survey_or_cohort_is_refused() {
    let f = fixture();
    let r = assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "no-such-survey", "cohort-a");
    assert_eq!((r.status, json(&r)["error"].as_str().map(str::to_owned)), (404, Some("unknown-survey".into())));
    let r = assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "survey-a", "no-such-cohort");
    assert_eq!((r.status, json(&r)["error"].as_str().map(str::to_owned)), (404, Some("unknown-cohort".into())));
    assert_eq!(f.world.store.assignments(), Ok(vec![]));
    assert_eq!(f.world.store.account(&AccountId("sub-alice".into())), Ok(None), "a refused assignment creates no account");
}

#[test]
fn reg_046_an_assignment_records_generation_1_for_each_cohort_on_each_tenancy() {
    let f = fixture();
    let first = f.world.register_as("alice");
    assert_eq!(assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "survey-a", "cohort-a").status, 200);
    assert_eq!(assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "survey-b", "cohort-b").status, 200);
    let held = f.world.tenancy(&first.id);
    let cohorts: Vec<(&str, Generation)> = held.cohorts.iter().map(|c| (c.cohort.as_str(), c.generation)).collect();
    assert_eq!(cohorts, vec![("cohort-a", Generation(1)), ("cohort-b", Generation(1))]);
    assert!(f.world.store.assignments().expect("assignments").iter().all(|a| a.generation == Generation(1)));
}

#[test]
fn reg_046_an_assignment_reaches_only_the_target_accounts_tenancies() {
    let f = fixture();
    let alice = f.world.register_as("alice");
    let bob = f.world.register_as("bob");
    let before = f.world.tenancy(&bob.id);
    assert_eq!(assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "survey-a", "cohort-a").status, 200);
    assert_eq!(f.world.tenancy(&alice.id).cohorts.len(), 1);
    assert_eq!(f.world.tenancy(&bob.id), before, "the other account's tenancy is not touched");
    assert_eq!(f.notified.lock().expect("lock").as_slice(), &[alice.id], "only the reached tenancy is reported to the reconciler");
}

#[test]
fn reg_046_an_assignment_applies_to_tenancies_the_account_registers_later() {
    let f = fixture();
    assert_eq!(assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "survey-a", "cohort-a").status, 200);
    let later = f.world.register_as("alice");
    let held = f.world.tenancy(&later.id);
    assert_eq!(held.cohorts.iter().map(|c| c.cohort.as_str()).collect::<Vec<_>>(), vec!["cohort-a"]);
    let certificate = f.world.factory().certificate(&later.id).expect("certificate");
    assert_eq!(certificate.cohorts, held.cohorts, "the first certificate already names the assigned cohort");
    let other = f.world.register_as("bob");
    assert!(f.world.tenancy(&other.id).cohorts.is_empty(), "another account's later tenancy gets nothing");
}

#[test]
fn reg_046_an_assignment_creates_the_account_when_it_does_not_exist() {
    let f = fixture();
    let subject = AccountId("00000000-0000-4000-8000-000000000003".into());
    assert_eq!(f.world.store.account(&subject), Ok(None));
    assert_eq!(assign(&f, Some(OPERATOR_TOKEN), &subject.0, "survey-a", "cohort-a").status, 200);
    let account = f.world.store.account(&subject).expect("store").expect("account created");
    assert_eq!((account.id, account.roles), (subject.clone(), vec![]), "the id is the subject and there are no roles");
    assert_ne!(account.collector, [0; 16], "the collector reference is random");
    assert_ne!(account.collector.to_vec(), subject.0.as_bytes()[..16].to_vec(), "and is not derived from the subject");
}

#[test]
fn reg_046_a_subject_may_hold_a_pipe() {
    let f = fixture();
    let made = assign(&f, Some(OPERATOR_TOKEN), "auth0|abc", "survey-a", "cohort-a");
    assert_eq!(made.status, 200);
    assert_eq!(json(&made)["account"], "auth0|abc");
    let held = f.world.store.assignments().expect("assignments");
    assert_eq!(held[0].account, AccountId("auth0|abc".into()));
    let listed = f.call(&request("GET", "/v1/assignments", Some(OPERATOR_TOKEN), vec![]));
    assert_eq!(json(&listed)["assignments"][0]["account"], "auth0|abc");
    let tenancy = f.world.register_as("carol");
    assert_eq!(tenancy.cohorts.iter().map(|c| c.cohort.as_str()).collect::<Vec<_>>(), vec!["cohort-a"]);
}

#[test]
fn reg_046_the_assignment_names_the_account_by_subject() {
    let f = fixture();
    assert_eq!(assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "survey-a", "cohort-a").status, 200);
    let held = f.world.store.assignments().expect("assignments");
    assert_eq!(held[0].account, AccountId("sub-alice".into()));
    assert_eq!(held[0].cohort, cohort("cohort-a"));
    // A body that names no account, or names extra keys, is malformed and writes nothing.
    let r = f.call(&request("POST", "/v1/assignments", Some(OPERATOR_TOKEN), b"\xa1\x61a\x61b".to_vec()));
    assert_eq!(r.status, 400);
    assert_eq!(f.world.store.assignments().expect("assignments").len(), 1);
}

#[test]
fn reg_046_an_identical_assignment_is_unchanged_and_writes_nothing() {
    let f = fixture();
    f.world.register_as("alice");
    assert_eq!(assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "survey-a", "cohort-a").status, 200);
    let events_before = f.events.lock().expect("lock").len();
    let notified_before = f.notified.lock().expect("lock").len();
    let again = assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "survey-a", "cohort-a");
    assert_eq!((again.status, json(&again)["status"].as_str().map(str::to_owned)), (200, Some("unchanged".into())));
    assert_eq!(f.world.store.assignments().expect("assignments").len(), 1, "no second record");
    assert_eq!(f.events.lock().expect("lock").len(), events_before, "no second event");
    assert_eq!(f.notified.lock().expect("lock").len(), notified_before, "nothing to rebuild");
}

#[test]
fn reg_046_each_assignment_is_journaled_with_account_roles_methods_and_time() {
    let f = fixture();
    assert_eq!(assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "survey-a", "cohort-a").status, 200);
    let record = f.world.store.assignments().expect("assignments").remove(0);
    assert_eq!(record.by, AccountId("sub-ops".into()), "the operator's account, not the target's");
    assert_eq!(record.roles, vec!["operator".to_owned()]);
    assert_eq!(record.methods, vec!["hwk".to_owned(), "phr".to_owned()]);
    assert_eq!(record.at, common::T0);
    assert_eq!((record.survey.as_str(), record.generation), ("survey-a", Generation(1)));
    // The event names the survey, the cohort and the generation, and no account.
    let events = f.events.lock().expect("lock").clone();
    assert_eq!(events, vec![OperatorEvent::AssignmentMade { survey: "survey-a".into(), cohort: "cohort-a".into(), generation: 1 }]);
    assert!(!format!("{events:?}").contains("sub-alice"));
}

#[test]
fn reg_032_an_assignment_change_reissues_the_certificate_with_the_new_cohort_set() {
    let f = fixture();
    let tenancy = f.world.register_as("alice");
    let before = f.world.factory().certificate(&tenancy.id).expect("certificate");
    assert!(before.cohorts.is_empty());
    assert_eq!(assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "survey-a", "cohort-a").status, 200);
    let after = f.world.factory().certificate(&tenancy.id).expect("GetCertificate returns the stored certificate");
    assert_eq!(after.cohorts.iter().map(|c| c.cohort.as_str()).collect::<Vec<_>>(), vec!["cohort-a"]);
    assert_ne!(after.signature, before.signature, "a new certificate is signed");
    assert_eq!(f.world.tenancy(&tenancy.id).certificate.as_ref(), Some(&after), "and stored in the tenancy record");
    assert_eq!((after.tenancy, after.agreement_key.clone()), (before.tenancy, before.agreement_key.clone()), "it names the same tenancy and agreement key");
    assert_eq!(after.serial, before.serial, "the attested device serial is kept");
    // A second survey on the same cohort changes no cohort set: the certificate stays.
    assert_eq!(assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "survey-b", "cohort-a").status, 200);
    assert_eq!(f.world.factory().certificate(&tenancy.id).expect("certificate"), after);
}

#[test]
fn reg_032_a_tenancy_of_another_account_keeps_its_certificate() {
    let f = fixture();
    f.world.register_as("alice");
    let bob = f.world.register_as("bob");
    let before = f.world.factory().certificate(&bob.id).expect("certificate");
    assert_eq!(assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "survey-a", "cohort-a").status, 200);
    assert_eq!(f.world.factory().certificate(&bob.id).expect("certificate"), before);
}

#[test]
fn reg_046_an_account_that_is_empty_too_long_or_holds_a_control_character_is_malformed() {
    let f = fixture();
    let long = "a".repeat(256);
    for bad in ["", "tab\there", "nul\0", long.as_str()] {
        let r = assign(&f, Some(OPERATOR_TOKEN), bad, "survey-a", "cohort-a");
        assert_eq!((r.status, json(&r)["error"].as_str().map(str::to_owned)), (400, Some("malformed".into())), "{bad:?}");
    }
    assert_eq!(f.world.store.assignments(), Ok(vec![]));
    assert_eq!(assign(&f, Some(OPERATOR_TOKEN), &"a".repeat(255), "survey-a", "cohort-a").status, 200, "255 bytes is allowed");
}

#[test]
fn reg_046_the_token_is_checked_before_the_body_is_read() {
    use std::io::{Read as _, Write as _};
    let f = fixture();
    let server = std::sync::Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind"));
    let addr = server.server_addr().to_ip().expect("address");
    let stopper = server.clone();
    // A client that promises a body and never sends it. A server that read the body first
    // would wait for it; this one answers 401 from the headers alone.
    let client = std::thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(addr).expect("connect");
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("timeout");
        let head = "Content-Length: 500000\r\nContent-Type: application/cbor\r\n";
        let mut answers = Vec::new();
        for (path, method) in [("/v1/assignments", "POST"), ("/v1/rosters", "POST"), ("/v1/assignments", "GET")] {
            stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: factory\r\nAuthorization: Bearer nonsense\r\n{head}\r\n").as_bytes()).expect("send");
            let mut buf = [0u8; 512];
            let n = stream.read(&mut buf).unwrap_or(0);
            answers.push(String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or_default().to_owned());
            // Keep the connection honest: a refused request leaves the body unread, so use a new one.
            stream = std::net::TcpStream::connect(addr).expect("connect");
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("timeout");
        }
        stopper.unblock();
        answers
    });
    f.with_http(|http| http.run(&server));
    let answers = client.join().expect("client");
    assert_eq!(answers, vec!["HTTP/1.1 401 Unauthorized"; 3]);
}

#[test]
fn reg_046_a_journaled_assignment_reaches_a_tenancy_that_registers_after_it() {
    // The record was written and the tenancy was not updated: the order `assign_cohort` writes
    // in, seen from a registration that runs in between.
    let f = fixture();
    let pending = f.world.pending_as("alice");
    assert!(pending.cohorts.is_empty());
    f.world.store.put_assignment(&fieldseal_registration::contract::sample_assignment("sub-alice", "survey-a", "cohort-a")).expect("put");
    let registered = f.world.factory().confirm(&f.world.person("alice").account, &pending.id).expect("confirm");
    assert_eq!(registered.cohorts.iter().map(|c| c.cohort.as_str()).collect::<Vec<_>>(), vec!["cohort-a"]);
    assert_eq!(f.world.tenancy(&pending.id).cohorts, registered.cohorts, "stored too");
    let certificate = f.world.factory().certificate(&pending.id).expect("certificate");
    assert_eq!(certificate.cohorts, registered.cohorts, "and the first certificate names it");
}

#[test]
fn reg_046_assigning_again_applies_a_journaled_assignment_to_a_registered_tenancy() {
    // A stop after the record and before the tenancies: the same assignment made again finishes it.
    let f = fixture();
    let alice = f.world.register_as("alice");
    f.world.store.put_assignment(&fieldseal_registration::contract::sample_assignment("sub-alice", "survey-a", "cohort-a")).expect("put");
    assert!(f.world.tenancy(&alice.id).cohorts.is_empty());
    let r = assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "survey-a", "cohort-a");
    assert_eq!((r.status, json(&r)["status"].as_str().map(str::to_owned)), (200, Some("assigned".into())));
    assert_eq!(f.world.store.assignments().expect("assignments").len(), 1, "no second record");
    let held = f.world.tenancy(&alice.id);
    assert_eq!(held.cohorts.iter().map(|c| c.cohort.as_str()).collect::<Vec<_>>(), vec!["cohort-a"]);
    assert_eq!(f.world.factory().certificate(&alice.id).expect("certificate").cohorts, held.cohorts, "with a new certificate");
    let again = assign(&f, Some(OPERATOR_TOKEN), "sub-alice", "survey-a", "cohort-a");
    assert_eq!(json(&again)["status"], "unchanged");
}
