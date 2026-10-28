//! The typed JSON form of a kernel `Value`, as the kernel's vectors write it:
//! `{"int": "<decimal>"}`, `{"decimal": {"exponent", "mantissa"}}`, `{"bytes": "<hex>"}`,
//! `{"text": ...}`, `{"bool": ...}`, `{"array": [...]}`, `{"map": {...}}`. Integers are strings
//! because they range over −2⁶⁴..2⁶⁴−1.
//!
//! Shared by the policy vector generator and by every engine adapter's vector test, which
//! include this file with `#[path]`.

#![allow(dead_code, missing_docs)]

use fieldseal_kernel::value::{Decimal, Value};
use serde_json::{Value as J, json};

pub fn to_j(v: &Value) -> J {
    match v {
        Value::Int(i) => json!({"int": i.to_string()}),
        Value::Decimal(d) => json!({"decimal": {"exponent": d.exponent, "mantissa": d.mantissa.to_string()}}),
        Value::Bytes(b) => json!({"bytes": b.iter().map(|x| format!("{x:02x}")).collect::<String>()}),
        Value::Text(t) => json!({"text": t}),
        Value::Bool(b) => json!({"bool": b}),
        Value::Array(a) => json!({"array": a.iter().map(to_j).collect::<Vec<_>>()}),
        Value::Map(m) => json!({"map": m.iter().map(|(k, v)| (k.clone(), to_j(v))).collect::<serde_json::Map<_, _>>()}),
    }
}

pub fn from_j(j: &J) -> Value {
    let (kind, inner) = j.as_object().and_then(|o| o.iter().next()).expect("typed value");
    match kind.as_str() {
        "int" => Value::Int(inner.as_str().unwrap().parse().unwrap()),
        "decimal" => Value::Decimal(Decimal {
            exponent: inner["exponent"].as_i64().unwrap() as i32,
            mantissa: inner["mantissa"].as_str().unwrap().parse().unwrap(),
        }),
        "bytes" => {
            let s = inner.as_str().unwrap();
            Value::Bytes((0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect())
        }
        "text" => Value::Text(inner.as_str().unwrap().to_owned()),
        "bool" => Value::Bool(inner.as_bool().unwrap()),
        "array" => Value::Array(inner.as_array().unwrap().iter().map(from_j).collect()),
        "map" => Value::Map(inner.as_object().unwrap().iter().map(|(k, v)| (k.clone(), from_j(v))).collect()),
        other => panic!("unknown typed value {other}"),
    }
}

/// The facts of a vector case.
pub fn facts_of(j: &J) -> std::collections::BTreeMap<String, Value> {
    j.as_object().unwrap().iter().map(|(k, v)| (k.clone(), from_j(v))).collect()
}

/// Runs `decisions.json` against `engine`: every case must reach its verdict and obligations,
/// and every invalid case must be an error (never a decision). Returns the number of cases run.
pub fn run_decision_vectors<E: fieldseal_policy::ports::PolicyEngine>(engine: &E, decisions: &J) -> usize {
    use fieldseal_policy::domain::{DecisionPoint, Obligation, Verdict};
    use fieldseal_policy::fixtures::effective;
    use fieldseal_policy::ports::PolicyEngineError;

    let stacks: std::collections::BTreeMap<String, Vec<Value>> = decisions["policies"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, layers)| (name.clone(), layers.as_array().unwrap().iter().map(from_j).collect()))
        .collect();
    let point_of = |j: &J| DecisionPoint::parse(j.as_str().unwrap()).expect("a decision point");
    let mut run = 0;
    for c in decisions["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let policy = effective(&stacks[c["policy"].as_str().unwrap()]);
        let d = engine
            .evaluate(point_of(&c["point"]), &policy, &facts_of(&c["facts"]))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let verdict = match c["verdict"].as_str().unwrap() {
            "allow" => Verdict::Allow,
            "deny" => Verdict::Deny,
            "hold" => Verdict::Hold,
            "flag" => Verdict::Flag,
            other => panic!("{other}"),
        };
        let obligations: Vec<Obligation> = c["obligations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| match o.as_str().unwrap() {
                "sample-for-review" => Obligation::SampleForReview,
                "pause-release" => Obligation::PauseRelease,
                "quarantine" => Obligation::Quarantine,
                other => panic!("{other}"),
            })
            .collect();
        assert_eq!(d.verdict, verdict, "{name}: {:?}", d.reasons);
        assert_eq!(d.obligations, obligations, "{name}");
        assert_eq!(d.policy, policy.sources, "{name}: the decision names its policy");
        assert!(verdict == Verdict::Allow || !d.reasons.is_empty(), "{name}: reasons for every non-allow outcome");
        run += 1;
    }
    let default = effective(&stacks["default-deployment"]);
    for c in decisions["invalid"].as_array().unwrap() {
        let r = engine.evaluate(point_of(&c["point"]), &default, &facts_of(&c["facts"]));
        match c["error"].as_str().unwrap() {
            "missing-fact" => assert!(matches!(r, Err(PolicyEngineError::MissingFact(_))), "{c}: {r:?}"),
            "bad-fact" => assert!(matches!(r, Err(PolicyEngineError::BadFact(_))), "{c}: {r:?}"),
            other => panic!("{other}"),
        }
        run += 1;
    }
    run
}
