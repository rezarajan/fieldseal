//! `roster issue` (CLI-051): the check runs first, one sign-in serves every file, and the
//! factory's refusals are reported. Stand-ins for the identity provider and the factory, as in
//! `roster_assign.rs`.

mod common;

use std::path::Path;

use common::standin::{Authorize, Factory, Idp, accepting_factory};
use common::{Sandbox, repo};

fn example(name: &str) -> String {
    repo().join("examples").join(name).to_string_lossy().into_owned()
}

fn run(sb: &Sandbox, idp: &Idp, args: &[&str]) -> (i32, String, String) {
    std::fs::create_dir_all(sb.path("home")).expect("home");
    std::fs::create_dir_all(sb.path("tmp")).expect("tmp");
    let (home, tmp) = (sb.path("home"), sb.path("tmp"));
    let o = sb.run_with(args, &[("FIELDSEAL_OIDC_ISSUER", &idp.issuer), ("FIELDSEAL_OIDC_CLIENT_ID", "fieldseal-cli"), ("HOME", &home), ("TMPDIR", &tmp)]);
    (o.status.code().expect("exit code"), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn issue_args<'a>(factory: &'a Factory, files: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec!["roster", "issue", "--factory-url", &factory.url, "--browser", "none", "--login", "presenter"];
    args.extend_from_slice(files);
    args
}

fn files_hold(dir: &Path, needles: &[String]) -> bool {
    std::fs::read_dir(dir).expect("directory").flatten().any(|e| {
        let p = e.path();
        if p.is_dir() {
            files_hold(&p, needles)
        } else {
            let text = String::from_utf8_lossy(&std::fs::read(&p).unwrap_or_default()).into_owned();
            needles.iter().any(|n| !n.is_empty() && text.contains(n.as_str()))
        }
    })
}

#[test]
fn cli_051_issue_runs_check_first_and_sends_nothing_when_it_fails() {
    let sb = Sandbox::new("issue-check-first");
    let idp = Idp::start(Authorize::Auto);
    let factory = accepting_factory();
    let bad = sb.write("bad.yaml", "cohort: village-a\nversion: 0\ngeneration: 1\nsubjects:\n  - {subject: hh-0001, display: One}\n");
    let good = example("rosters/village-a.yaml");
    let (code, _, err) = run(&sb, &idp, &issue_args(&factory, &[&good, &bad]));
    assert_eq!(code, 1, "{err}");
    assert_eq!(idp.requests(), 0, "nobody is signed in for a roster that fails the check");
    assert!(factory.seen().is_empty(), "not even the good file is sent");
    // Against an instrument that reads a field the roster lacks.
    let lacking = sb.write("lacking.yaml", "cohort: village-a\nversion: 1\nsubjects:\n  - {subject: hh-0001, display: One, fields: {village_code: V-1}}\n");
    let survey = example("surveys/household-water-access");
    let mut args = issue_args(&factory, &[&lacking]);
    args.extend(["--instrument", &survey]);
    let (code, _, _) = run(&sb, &idp, &args);
    assert_eq!(code, 1);
    assert!(factory.seen().is_empty() && idp.requests() == 0);
}

#[test]
fn cli_051_issue_signs_in_once_for_several_files() {
    let sb = Sandbox::new("issue-once");
    let idp = Idp::start(Authorize::Auto);
    let factory = accepting_factory();
    let (a, b) = (example("rosters/village-a.yaml"), example("rosters/cohort-a.yaml"));
    let (code, out, err) = run(&sb, &idp, &issue_args(&factory, &[&a, &b]));
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!((idp.authorize_requests().len(), idp.token_requests().len()), (1, 1));
    let posts = factory.seen();
    assert_eq!(posts.len(), 2);
    assert!(posts.iter().all(|p| p.path == "/v1/rosters" && p.authorization == posts[0].authorization && p.authorization.is_some()));
    // The body is the canonical issue form: cohort, version and subjects, and no generation.
    let body = fieldseal_kernel::cbor::decode(&posts[0].body).expect("canonical CBOR");
    let m = body.as_map().expect("a map");
    assert_eq!(m["cohort"].as_text(), Some("village-a"));
    assert!(!m.contains_key("generation") && m.contains_key("subjects"));
    assert!(out.contains("village-a@") && out.contains("cohort-a@") && out.contains("sha256:"), "{out}");
}

#[test]
fn cli_051_issue_refuses_a_version_not_higher_than_the_latest() {
    let sb = Sandbox::new("issue-not-newer");
    let idp = Idp::start(Authorize::Auto);
    let factory = Factory::start(|_| (409, r#"{"error":"not-newer"}"#.to_owned()));
    let (code, _, err) = run(&sb, &idp, &issue_args(&factory, &[&example("rosters/village-a.yaml")]));
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("higher version"), "{err}");
}

#[test]
fn cli_051_issue_accepts_identical_content_at_the_same_version() {
    let sb = Sandbox::new("issue-unchanged");
    let idp = Idp::start(Authorize::Auto);
    let factory = Factory::start(|_| (200, format!(r#"{{"status":"unchanged","version":3,"digest":"sha256:{}"}}"#, "cd".repeat(32))));
    let (code, out, err) = run(&sb, &idp, &issue_args(&factory, &[&example("rosters/village-a.yaml")]));
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("unchanged") && out.contains("village-a@3"), "{out}");
}

#[test]
fn cli_051_issue_refuses_different_content_at_an_existing_version() {
    let sb = Sandbox::new("issue-version-taken");
    let idp = Idp::start(Authorize::Auto);
    let factory = Factory::start(|_| (409, r#"{"error":"version-taken"}"#.to_owned()));
    let (code, _, err) = run(&sb, &idp, &issue_args(&factory, &[&example("rosters/village-a.yaml")]));
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("different roster") && err.contains("village-a"), "{err}");
}

#[test]
fn cli_051_no_token_is_written_to_disk() {
    let sb = Sandbox::new("issue-no-token-on-disk");
    let idp = Idp::start(Authorize::Auto);
    let factory = accepting_factory();
    let (code, out, err) = run(&sb, &idp, &issue_args(&factory, &[&example("rosters/village-a.yaml")]));
    assert_eq!(code, 0, "{out}\n{err}");
    let secrets = idp.secrets();
    assert!(secrets.len() >= 4);
    assert!(!files_hold(&sb.dir, &secrets));
    assert!(secrets.iter().all(|s| !out.contains(s.as_str()) && !err.contains(s.as_str())));
    // Nor does it print a subject or a name from the roster (CLI-008).
    for s in ["hh-000", "Household", "Amina"] {
        assert!(!out.contains(s) && !err.contains(s), "{s}");
    }
}

#[test]
fn cli_051_a_cleartext_factory_url_is_refused_unless_it_is_loopback() {
    let sb = Sandbox::new("issue-cleartext");
    let idp = Idp::start(Authorize::Auto);
    let good = example("rosters/village-a.yaml");
    let args = ["roster", "issue", "--factory-url", "http://factory.example.org", "--browser", "none", "--login", "presenter", good.as_str()];
    let (code, _, err) = run(&sb, &idp, &args);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("https://"), "{err}");
    assert_eq!(idp.requests(), 0, "nobody is signed in");
}
