//! Instrument checks over the clinic-visit sample (copied from `crates/contexts/instrument/tests/clinic_visit.rs`).

#![allow(dead_code, unused_imports, missing_docs, clippy::all)]


use super::ins_support as support;

use std::collections::BTreeMap;

use fieldseal_instrument::application::{check_instrument, evaluate_field_checks, evaluate_rules, lint_instrument};
use fieldseal_instrument::domain::compiled::QuestionOrigin;
use fieldseal_instrument::domain::evaluation::{Evaluation, RecordInput, Verdict, Visibility};
use fieldseal_instrument::domain::field_checks::RecordView;
use fieldseal_instrument::domain::language::{Direction, lookup};
use fieldseal_instrument::domain::rules::Val;
use fieldseal_instrument::domain::{Compatibility, Control, ControlType, Instrument, LanguageTag, Num, SchemaVersion};
use fieldseal_instrument::ports::ControlCatalogue;
use fieldseal_kernel::Value;
use support::fixtures::clinic_visit;
use support::{valid, values};

fn instrument() -> Instrument {
    valid(&clinic_visit()).instrument
}

fn roster() -> BTreeMap<String, Value> {
    let mut r = BTreeMap::new();
    r.insert("given_name".to_owned(), Value::Text("Ana".into()));
    r
}

fn eval(vals: &str) -> Evaluation {
    let i = instrument();
    evaluate_rules(&i, RecordInput { values: &values(vals), roster: &roster() }).unwrap()
}

fn verdict(e: &Evaluation, id: &str) -> Verdict {
    e.rules.iter().find(|r| r.id == id).unwrap_or_else(|| panic!("no rule {id}")).verdict
}

pub fn ins_087_language_lookup_falls_back_to_the_default() {
    let i = instrument();
    let langs = &i.definition().languages;
    assert_eq!(lookup(&["fr-CA"], &langs.languages, &langs.default).as_str(), "fr");
    assert_eq!(lookup(&["sw-KE"], &langs.languages, &langs.default).as_str(), "en");
    assert_eq!(langs.default.direction(), Direction::Ltr);
}

pub fn ins_137_multi_choice_other_text_is_synthesised_and_shown_with_its_code() {
    let i = instrument();
    let q = i.compiled().question("complaint.symptoms.other").unwrap();
    assert_eq!(q.origin, QuestionOrigin::OtherText { of: "complaint.symptoms".into() });
    let e = eval(r#"{ complaint.symptoms: [cough] }"#);
    assert_eq!(e.visibility_of("complaint.symptoms.other"), Some(Visibility::Hidden));
    let e = eval(r#"{ complaint.symptoms: [cough, other], complaint.symptoms.other: "Headache" }"#);
    assert_eq!(e.visibility_of("complaint.symptoms.other"), Some(Visibility::Visible));
    assert_eq!(e.values["complaint.symptoms.other"], Val::Text("Headache".into()));
    let e = eval(r#"{ complaint.symptoms: [cough, other] }"#);
    assert!(e.unanswered.contains(&"complaint.symptoms.other".to_owned()), "selecting other requires the text (INS-134)");
}

pub fn ins_133_exclusive_code_cannot_be_combined() {
    let e = eval("{ complaint.symptoms: [none, cough] }");
    assert_eq!(e.problems.iter().map(|p| p.requirement).collect::<Vec<_>>(), ["INS-133"]);
    let e = eval("{ complaint.symptoms: [none] }");
    assert!(e.problems.is_empty());
}

pub fn ins_161_inches_convert_to_centimetres_exactly() {
    let e = eval("{ vitals.height: 69.0, vitals.height.unit: \"[in_i]\" }");
    assert!(e.problems.is_empty(), "{:?}", e.problems);
    assert_eq!(e.values["vitals.height"], Val::Num(Num::parse("175.26").unwrap()));
    let e = eval("{ vitals.height: 69.0, vitals.height.unit: m }");
    assert_eq!(e.problems[0].requirement, "INS-161");
    let e = eval("{ vitals.height.unit: cm }");
    assert_eq!(e.problems[0].requirement, "INS-030");
}

pub fn ins_162_zero_decimal_currency() {
    let e = eval("{ visit.fee: 1500 }");
    assert!(e.problems.is_empty());
    let e = eval("{ visit.fee: 1500.5 }");
    assert_eq!(e.problems[0].requirement, "INS-162");
    let e = eval("{ visit.fee: 60000 }");
    assert_eq!(e.problems[0].requirement, "INS-027");
}

pub fn ins_141_refused_is_recorded_and_counts_as_answered() {
    let e = eval(r#"{ visit.fee: { nr: refused } }"#);
    assert!(e.problems.is_empty());
    assert!(!e.unanswered.contains(&"visit.fee".to_owned()));
    assert_eq!(e.nonresponse.len(), 1);
    let e = eval(r#"{ visit.type: { nr: dont-know } }"#);
    assert_eq!(e.problems[0].requirement, "INS-140", "the default offers only refused");
    let e = eval(r#"{ complaint.days: { nr: not-applicable } }"#);
    assert_eq!(e.problems[0].requirement, "INS-142");
}

pub fn ins_089_compatibility_reports_controls_and_languages() {
    struct Small;
    impl ControlCatalogue for Small {
        fn schema_version(&self) -> SchemaVersion {
            SchemaVersion { major: 1, minor: 2, patch: 0 }
        }
        fn controls(&self) -> Vec<ControlType> {
            ControlType::V1.into_iter().filter(|c| *c != ControlType::Money).collect()
        }
        fn renders_language(&self, l: &LanguageTag) -> bool {
            l.as_str() == "fr"
        }
    }
    let report = check_instrument(&Small, &instrument());
    assert_eq!(report.schema, Compatibility::Compatible);
    assert_eq!(report.unsupported_controls, [ControlType::Money]);
    assert_eq!(report.offered_languages().iter().map(|l| l.as_str()).collect::<Vec<_>>(), ["fr"]);
    assert!(!report.is_compatible());
}

struct FullAll;
impl ControlCatalogue for FullAll {
    fn schema_version(&self) -> SchemaVersion {
        SchemaVersion { major: 1, minor: 2, patch: 0 }
    }
    fn controls(&self) -> Vec<ControlType> {
        ControlType::V1.to_vec()
    }
}

pub fn ins_050_field_checks_raise_with_their_records() {
    let i = instrument();
    let r = roster();
    let a = values(r#"{ visit.date: "2026-03-01", vitals.weight: [60.0, 60.0], vitals.height: 170.0, vitals.temperature: 39.5 }"#);
    let b = values(r#"{ visit.date: "2026-03-01", vitals.weight: [60.0, 60.0], vitals.height: 170.0, vitals.temperature: 39.0 }"#);
    let c = values(r#"{ visit.date: "2026-03-02", vitals.temperature: 39.9 }"#);
    let records = [
        RecordView { id: "r1", subject: "s1", values: &a, roster: &r, elapsed_seconds: Some(600) },
        RecordView { id: "r2", subject: "s2", values: &b, roster: &r, elapsed_seconds: Some(45) },
        RecordView { id: "r3", subject: "s3", values: &c, roster: &r, elapsed_seconds: None },
    ];
    let raised = evaluate_field_checks(&i, &records).unwrap();
    let by_id: BTreeMap<&str, Vec<&str>> = raised.iter().map(|r| (r.check.as_str(), r.records.iter().map(String::as_str).collect())).collect();
    assert_eq!(by_id["same-person"], ["r1", "r2"]);
    assert_eq!(by_id["temperatures"], ["r1", "r2", "r3"]);
    assert_eq!(by_id["rushed"], ["r2"]);
    assert_eq!(by_id["thin-vitals"], ["r3"]);
}

pub fn ins_050_drift_raises_on_a_steady_rise_in_the_items_unit() {
    let i = valid(&support::fixtures::spec_example()).instrument;
    let r = BTreeMap::new();
    let series: Vec<BTreeMap<String, Value>> = (0..10).map(|k| values(&format!("{{ about.weight: [{}.0, {}.0] }}", 100 + k, 100 + k))).collect();
    let ids: Vec<String> = (0..10).map(|k| format!("r{k}")).collect();
    let records: Vec<RecordView> = series
        .iter()
        .zip(&ids)
        .map(|(v, id)| RecordView { id, subject: id, values: v, roster: &r, elapsed_seconds: None })
        .collect();
    let raised = evaluate_field_checks(&i, &records).unwrap();
    assert_eq!(raised.len(), 1);
    assert_eq!(raised[0].check, "weight-drift");
    assert_eq!(raised[0].records.len(), 10);
    let raised = evaluate_field_checks(&i, &records[..9]).unwrap();
    assert!(raised.is_empty(), "fewer values than the window");
}
