//! POL-035, POL-032: the built-in engine and the OPA adapter refuse and accept exactly the same facts.
//! Needs the `opa` binary (always present in the dev shell).

use std::process::{Command, Stdio};

use fieldseal_adapters_memory::policy::BuiltInPolicyEngine;
use fieldseal_adapters_opa::{OpaConfig, OpaEngine};
use fieldseal_kernel::value::Value;
use fieldseal_policy::domain::{DecisionPoint, Facts};
use fieldseal_policy::fixtures::{dec, effective_default, facts, int, text, words};
use fieldseal_policy::ports::PolicyEngine;

fn opa_present() -> bool {
    let ok = Command::new("opa").arg("version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    if !ok {
        assert!(std::env::var_os("IN_NIX_SHELL").is_none(), "`opa` is missing from the dev shell");
        eprintln!("SKIPPED: the `opa` binary is not installed");
    }
    ok
}

fn consent(draw: Value) -> Facts {
    facts(&[("hasEvidence", Value::Bool(true)), ("heuristicHits", words(&[])), ("sampleDraw", draw)])
}

fn device(n: Value) -> Facts {
    facts(&[("activeDevices", n)])
}

/// Runs both engines and requires the same result: both accept, or both refuse identically.
fn same(point: DecisionPoint, f: &Facts) -> Result<(), String> {
    let policy = effective_default();
    let a = BuiltInPolicyEngine.evaluate(point, &policy, f);
    let b = OpaEngine::new(OpaConfig::binary()).evaluate(point, &policy, f);
    match (a, b) {
        (Ok(x), Ok(y)) if x.verdict == y.verdict && x.reasons == y.reasons => Ok(()),
        (Err(x), Err(y)) if x == y => Err(format!("{x:?}")),
        (a, b) => panic!("engines disagree on {f:?}: built-in {a:?}, opa {b:?}"),
    }
}

#[test]
fn pol_035_invalid_facts_are_refused_identically_by_both_engines() {
    if !opa_present() {
        return;
    }
    use DecisionPoint::*;
    let mut extra = device(int(1));
    extra.insert("surprise".into(), Value::Bool(true));
    let mut extra_consent = consent(dec("0.5"));
    extra_consent.insert("sampleRate".into(), dec("0.1"));
    let cases: Vec<(&str, DecisionPoint, Facts)> = vec![
        ("unknown fact", DeviceAdd, extra),
        ("unknown fact (consent)", ConsentDecide, extra_consent),
        ("wrong type: text for uint", DeviceAdd, device(text("1"))),
        ("wrong type: bool for uint", DeviceAdd, device(Value::Bool(true))),
        ("negative uint", DeviceAdd, device(int(-1))),
        ("int for decimal", ConsentDecide, consent(int(0))),
        ("text for decimal", ConsentDecide, consent(text("0.5"))),
        ("draw of one", ConsentDecide, consent(dec("1"))),
        ("draw above one", ConsentDecide, consent(dec("1.5"))),
        ("negative draw", ConsentDecide, consent(dec("-0.1"))),
        ("missing fact", DeviceAdd, facts(&[])),
        ("missing fact (consent)", ConsentDecide, facts(&[("hasEvidence", Value::Bool(true)), ("sampleDraw", dec("0.5"))])),
        ("non-text in list", ConsentDecide, facts(&[("hasEvidence", Value::Bool(true)), ("heuristicHits", Value::Array(vec![int(1)])), ("sampleDraw", dec("0.5"))])),
        ("bad enum", RegistrationApprove, facts(&[("fingerprintConfirmed", Value::Bool(true)), ("serialStatus", text("maybe")), ("nonceOnly", Value::Bool(false))])),
        ("bad security level", PostureRecheck, facts(&[("verifiedBoot", Value::Bool(true)), ("bootloaderLocked", Value::Bool(true)), ("securityLevel", text("quantum")), ("osPatchLevel", text("2026-01-01")), ("unknownRestriction", Value::Bool(false))])),
        ("bad date", PostureRecheck, facts(&[("verifiedBoot", Value::Bool(true)), ("bootloaderLocked", Value::Bool(true)), ("securityLevel", text("tee")), ("osPatchLevel", text("yesterday")), ("unknownRestriction", Value::Bool(false))])),
    ];
    for (name, point, f) in cases {
        assert!(same(point, &f).is_err(), "{name}: both engines must refuse");
    }
}

#[test]
fn pol_032_valid_facts_are_accepted_identically_by_both_engines() {
    if !opa_present() {
        return;
    }
    for draw in ["0", "0.0", "0.5", "0.999"] {
        same(DecisionPoint::ConsentDecide, &consent(dec(draw))).unwrap_or_else(|e| panic!("{draw}: {e}"));
    }
    same(DecisionPoint::DeviceAdd, &device(int(1))).expect("valid device facts");
}
