//! The closed-schema check of a roster issue form (DIS-063).

use fieldseal_distribution::domain::{ConsentState, check_issue_form};
use fieldseal_kernel::Value;
use fieldseal_kernel::cbor;

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn subject(id: &str) -> Value {
    cbor::map([("subject", text(id)), ("display", text(id)), ("fields", cbor::map([("head_name", text("Amina"))]))])
}

fn form(subjects: Vec<Value>) -> Value {
    cbor::map([("cohort", text("village-a")), ("version", Value::Int(4)), ("subjects", Value::Array(subjects))])
}

fn with(mut v: Value, key: &str, to: Value) -> Value {
    if let Value::Map(m) = &mut v {
        m.insert(key.to_owned(), to);
    }
    v
}

fn paths(value: Value) -> Vec<String> {
    check_issue_form(value).expect_err("findings").into_iter().map(|f| f.path).collect()
}

#[test]
fn dis_063_a_well_formed_form_passes_and_has_a_stable_digest() {
    let a = check_issue_form(form(vec![subject("hh-1"), subject("hh-2")])).expect("well formed");
    assert_eq!(a.entries.len(), 2);
    assert_eq!(a.entries[1].ordinal, 2);
    assert_eq!(a.entries[0].consent, ConsentState::Unknown);
    let b = check_issue_form(form(vec![subject("hh-1"), subject("hh-2")])).expect("well formed");
    assert_eq!(a.digest(), b.digest());
    // The canonical form reads back as the same form.
    let again = check_issue_form(cbor::decode(&a.encode()).expect("decodes")).expect("reads back");
    assert_eq!(again, a);
    assert_eq!(again.digest(), a.digest());
    let other = check_issue_form(form(vec![subject("hh-1")])).expect("well formed");
    assert_ne!(other.digest(), a.digest());
}

#[test]
fn dis_063_a_repeated_subject_is_a_finding() {
    assert_eq!(paths(form(vec![subject("hh-1"), subject("hh-1")])), ["subjects[2].subject"]);
}

#[test]
fn dis_063_ordinals_must_strictly_increase() {
    let at = |o: i128| with(subject("x"), "ordinal", Value::Int(o));
    let two = with(at(2), "subject", text("hh-2"));
    let also_two = with(at(2), "subject", text("hh-3"));
    assert_eq!(paths(form(vec![two.clone(), also_two])), ["subjects[2].ordinal"]);
    let one = with(at(1), "subject", text("hh-1"));
    assert_eq!(paths(form(vec![two, one])), ["subjects[2].ordinal"]);
    let first = with(at(5), "subject", text("hh-1"));
    let later = with(at(9), "subject", text("hh-2"));
    check_issue_form(form(vec![first, later])).expect("gaps are allowed");
}

#[test]
fn dis_063_an_unknown_key_is_a_finding() {
    assert_eq!(paths(with(form(vec![subject("hh-1")]), "owner", text("x"))), ["owner"]);
    assert_eq!(paths(form(vec![with(subject("hh-1"), "phone", text("x"))])), ["subjects[1].phone"]);
}

#[test]
fn dis_063_a_generation_key_is_refused_in_the_issue_form() {
    let findings = check_issue_form(with(form(vec![subject("hh-1")]), "generation", Value::Int(1))).expect_err("refused");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "generation");
}

#[test]
fn dis_063_a_consent_state_outside_the_declared_set_is_a_finding() {
    let bad = with(subject("hh-1"), "consent", text("maybe"));
    assert_eq!(paths(form(vec![bad])), ["subjects[1].consent"]);
    for state in ["granted", "refused", "unknown"] {
        check_issue_form(form(vec![with(subject("hh-1"), "consent", text(state))])).expect(state);
    }
}

#[test]
fn dis_063_every_finding_is_reported_not_only_the_first() {
    let value = cbor::map([
        ("cohort", text("")),
        ("version", Value::Int(0)),
        ("generation", Value::Int(1)),
        ("subjects", Value::Array(vec![subject("hh-1"), subject("hh-1"), with(subject("hh-3"), "consent", text("maybe"))])),
    ]);
    let found = paths(value);
    for expected in ["cohort", "version", "generation", "subjects[2].subject", "subjects[3].consent"] {
        assert!(found.iter().any(|p| p == expected), "{expected} in {found:?}");
    }
}
