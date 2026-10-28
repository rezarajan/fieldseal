//! Instrument checks over the specification's section 6.1 example (copied from `crates/contexts/instrument/tests/spec_example.rs`).

#![allow(dead_code, unused_imports, missing_docs, clippy::all)]


use super::ins_support as support;

use std::collections::BTreeMap;

use fieldseal_instrument::application::evaluate_rules;
use fieldseal_instrument::domain::compiled::QuestionOrigin;
use fieldseal_instrument::domain::evaluation::{RecordInput, Verdict, Visibility};
use fieldseal_instrument::domain::rules::Val;
use fieldseal_instrument::domain::{Control, Num};
use fieldseal_kernel::Value;
use support::fixtures::spec_example;
use support::{valid, values};

fn eval(vals: &str) -> fieldseal_instrument::domain::Evaluation {
    let v = valid(&spec_example());
    let values = values(vals);
    let roster = BTreeMap::new();
    evaluate_rules(&v.instrument, RecordInput { values: &values, roster: &roster }).unwrap()
}

pub fn ins_137_other_instance_gets_a_naming_question() {
    let v = valid(&spec_example());
    let q = v.instrument.compiled().question("staples.other.other").unwrap();
    assert_eq!(q.origin, QuestionOrigin::InstanceName);
    assert_eq!(q.data.data_type, fieldseal_instrument::domain::element::DataType::String);
    assert!(matches!(q.control, Some(Control::Text { max_length: Some(40), .. })));
}

pub fn ins_161_entry_units_convert_exactly_before_bounds() {
    // 20 kg is 44.09… lb: within 40..300 lb.
    let e = eval("{ about.weight: [20.1, 20.1], about.weight.unit: kg }");
    assert!(e.problems.is_empty(), "{:?}", e.problems);
    let Val::Num(mean) = &e.values["about.weight"] else { panic!() };
    let expected = Num::parse("20.1").unwrap().div(Num::parse("0.45359237").unwrap()).unwrap();
    assert_eq!(*mean, expected);
    // 15 kg is 33 lb: below min after conversion.
    let e = eval("{ about.weight: [15.0, 15.0], about.weight.unit: kg }");
    assert_eq!(e.problems.iter().map(|p| p.requirement).collect::<Vec<_>>(), ["INS-027", "INS-027"]);
}

pub fn ins_163_stepper_values_lie_on_the_grid() {
    let e = eval("{ staples.bread.freq: d_1, staples.bread.amount: 1.25 }");
    assert_eq!(e.problems[0].requirement, "INS-163");
    let e = eval("{ staples.bread.freq: d_1, staples.bread.amount: 2.5 }");
    assert!(e.problems.is_empty());
}

pub fn ins_162_money_has_at_most_the_currencys_minor_digits() {
    let e = eval("{ about.money_gets: true, about.money_per_day: 20.505 }");
    assert_eq!(e.problems[0].requirement, "INS-162");
    let e = eval("{ about.money_gets: true, about.money_per_day: 20.50 }");
    assert!(e.problems.is_empty());
}

pub fn ins_141_nonresponse_counts_as_answered_and_offers_only_declared_codes() {
    let e = eval(r#"{ about.sex: { nr: dont-know } }"#);
    assert!(!e.unanswered.contains(&"about.sex".to_owned()));
    assert!(e.unanswered.contains(&"about.money_gets".to_owned()));
    let e = eval(r#"{ about.sex: { nr: refused } }"#);
    assert_eq!(e.problems[0].requirement, "INS-140");
}

pub fn ins_048_value_reads_the_code_value() {
    use fieldseal_instrument::domain::rules::{EvalScope, Slot, evaluate, parse_expr};
    // The compiled slot for a scale carries the code's value.
    let e = eval("{ staples.bread.freq: w_1_2 }");
    assert_eq!(e.values["staples.bread.freq"], Val::Text("w_1_2".into()));
    struct S(Slot);
    impl EvalScope for S {
        fn item(&self, _: &str) -> Option<&Slot> {
            Some(&self.0)
        }
        fn roster(&self, _: &str) -> Val {
            Val::Unset
        }
        fn lookup(&self, _: &str, _: &Val) -> Val {
            Val::Unset
        }
    }
    let s = S(Slot { value: Val::Text("w_1_2".into()), nonresponse: None, code_value: Num::parse("0.214") });
    assert_eq!(evaluate(&parse_expr("value($x) * 7").unwrap(), &s).unwrap(), Val::Num(Num::parse("1.498").unwrap()));
}
