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

#[test]
fn dis_063_consent_covers_names_the_surveys_a_granted_consent_covers() {
    let none = check_issue_form(form(vec![subject("hh-1")])).expect("well formed");
    assert_eq!(none.consent_covers, None, "a file that says nothing leaves it to the factory");
    let declared = with(form(vec![subject("hh-1")]), "consent-covers", Value::Array(vec![text("water"), text("meals")]));
    let a = check_issue_form(declared.clone()).expect("well formed");
    assert_eq!(a.consent_covers, Some(vec!["meals".to_owned(), "water".to_owned()]), "sorted");
    assert_ne!(a.digest(), none.digest());
    assert_eq!(check_issue_form(cbor::decode(&a.encode()).expect("decodes")).expect("reads back"), a);
    // A declared list wins over what is assigned; an undeclared one takes what is assigned.
    let assigned = vec!["tomorrow".to_owned()];
    assert_eq!(a.clone().into_roster(fieldseal_kernel::id::Generation(1), &assigned).consent_covers, ["meals", "water"]);
    assert_eq!(none.into_roster(fieldseal_kernel::id::Generation(1), &assigned).consent_covers, ["tomorrow"]);
    let empty = check_issue_form(with(form(vec![subject("hh-1")]), "consent-covers", Value::Array(vec![]))).expect("an empty list is a declaration");
    assert_eq!(empty.into_roster(fieldseal_kernel::id::Generation(1), &assigned).consent_covers, Vec::<String>::new());
}

#[test]
fn dis_063_consent_covers_is_checked() {
    let with_covers = |v: Value| with(form(vec![subject("hh-1")]), "consent-covers", v);
    assert_eq!(paths(with_covers(text("water"))), ["consent-covers"]);
    assert_eq!(paths(with_covers(Value::Array(vec![Value::Int(1)]))), ["consent-covers[1]"]);
    assert_eq!(paths(with_covers(Value::Array(vec![text("two words")]))), ["consent-covers[1]"]);
    assert_eq!(paths(with_covers(Value::Array(vec![text("water"), text("water")]))), ["consent-covers[2]"]);
}

#[test]
fn wire_095_a_roster_carries_the_surveys_its_consent_covers() {
    use fieldseal_distribution::domain::Roster;
    let issued = check_issue_form(with(form(vec![subject("hh-1")]), "consent-covers", Value::Array(vec![text("water")]))).expect("well formed");
    let roster = issued.into_roster(fieldseal_kernel::id::Generation(2), &[]);
    let back = Roster::from_value(cbor::decode(&roster.encode()).expect("decodes")).expect("reads back");
    assert_eq!(back, roster);
    assert!(back.covers("water") && !back.covers("meals"));
    // A roster that covers nothing leaves the key out, so it encodes as it did before coverage.
    let none = check_issue_form(form(vec![subject("hh-1")])).expect("well formed").into_roster(fieldseal_kernel::id::Generation(2), &[]);
    let Value::Map(m) = none.to_value() else { unreachable!("a roster is a map") };
    assert!(!m.contains_key("consent_covers"));
    // The reader is strict: an empty, unsorted, repeating or non-text list is refused.
    let wire = |v: Value| Roster::from_value(with(roster.to_value(), "consent_covers", v));
    assert!(wire(Value::Array(vec![])).is_err());
    assert!(wire(Value::Array(vec![text("b"), text("a")])).is_err());
    assert!(wire(Value::Array(vec![text("a"), text("a")])).is_err());
    assert!(wire(Value::Array(vec![Value::Int(1)])).is_err());
    assert!(wire(text("a")).is_err());
}
