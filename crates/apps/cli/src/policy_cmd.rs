//! `fieldseal policy validate|evaluate|diff|effective` (CLI §5 `policy`, POL): read policy
//! layers from files, call the Policy context, report. These run on a workstation against
//! unpublished files, which POL-004 allows for exactly these commands.

use std::collections::BTreeMap;

use fieldseal_adapters_memory::policy::BuiltInPolicyEngine;
use fieldseal_kernel::Value;
use fieldseal_kernel::id::ContentAddress;
use fieldseal_policy::application::{PolicyValidator, ValidatePolicy};
use fieldseal_policy::domain::merge::describe;
use fieldseal_policy::domain::{
    ChangeDirection, DecisionPoint, EffectivePolicy, Facts, Finding, PolicyDocument, Severity, Verdict, diff_documents, merge_layers,
};
use fieldseal_policy::ports::PolicyEngine;

use crate::args::Args;
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::support::{Res, fail, load_doc, policy_paths, run_command, usage};

/// Runs `policy <verb>`; `None` if the verb is not one of these.
pub fn run(verb: &str, raw: &[String]) -> Option<u8> {
    Some(match verb {
        "validate" => run_command("policy validate", raw, &[], &[], validate),
        "evaluate" => run_command("policy evaluate", raw, &["--decision", "--input"], &[], evaluate),
        "diff" => run_command("policy diff", raw, &[], &[], diff),
        "effective" => run_command("policy effective", raw, &[], &[], effective),
        _ => return None,
    })
}

fn report(out: &mut Outcome, file: &str, findings: &[Finding]) {
    for f in findings {
        let sev = if f.severity == Severity::Error { "error" } else { "warning" };
        out.raw_finding(f.requirement, sev, file, &f.path, &f.message);
    }
}

/// The layer files: positionals, else `FIELDSEAL_POLICY` (comma-separated paths).
fn layer_paths(args: &Args) -> Res<Vec<String>> {
    if !args.positionals.is_empty() {
        return Ok(args.positionals.clone());
    }
    policy_paths(args)
}

/// A layer: its document and the content address of its canonical form (POL-023).
pub struct Layer {
    /// The decoded document.
    pub document: PolicyDocument,
    /// Its address.
    pub address: ContentAddress,
}

/// Loads, validates and returns the layers in `paths`, recording findings. `None` if any
/// file is missing or invalid, or the stack does not merge.
pub fn load_layers(paths: &[String], out: &mut Outcome) -> Res<Option<Vec<Layer>>> {
    let v = PolicyValidator;
    let mut layers = Vec::new();
    let mut ok = true;
    for p in paths {
        let Some(doc) = load_doc(p, out)? else {
            ok = false;
            continue;
        };
        let report_ = v.validate(&doc);
        report(out, p, &report_.findings);
        match report_.document {
            Some(d) if !has_error(&report_.findings) => {
                let address = fieldseal_kernel::cbor::encode(&doc).map(|b| ContentAddress::of(&b)).unwrap_or_else(|_| ContentAddress::of(b""));
                layers.push(Layer { document: d, address });
            }
            _ => ok = false,
        }
    }
    if !ok {
        return Ok(None);
    }
    let refs: Vec<&PolicyDocument> = layers.iter().map(|l| &l.document).collect();
    let (_, merge_findings) = merge_layers(&refs);
    report(out, "(layers)", &merge_findings);
    Ok((!has_error(&merge_findings)).then_some(layers))
}

fn has_error(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity == Severity::Error)
}

/// The effective policy of `layers`.
pub fn effective_of(layers: &[Layer]) -> EffectivePolicy {
    let refs: Vec<&PolicyDocument> = layers.iter().map(|l| &l.document).collect();
    EffectivePolicy { sources: layers.iter().map(|l| l.address).collect(), controls: merge_layers(&refs).0 }
}

fn validate(args: &Args, out: &mut Outcome) -> Res {
    let paths = layer_paths(args)?;
    if paths.is_empty() {
        return Err(usage("missing-file", &[("command", "policy validate")]));
    }
    let v = PolicyValidator;
    let mut docs = Vec::new();
    for p in &paths {
        let Some(doc) = load_doc(p, out)? else { continue };
        let r = v.validate(&doc);
        report(out, p, &r.findings);
        let errs = r.findings.iter().filter(|f| f.severity == Severity::Error).count().to_string();
        let line = if r.is_valid() { msg("valid", &[("file", p)]) } else { msg("invalid", &[("file", p), ("errors", &errs)]) };
        out.lines.push(line);
        docs.push(doc);
    }
    if docs.len() > 1 && out.exit == exit::OK {
        report(out, "(layers)", &v.validate_stack(&docs));
    }
    Ok(())
}

fn evaluate(args: &Args, out: &mut Outcome) -> Res {
    let name = args.required("policy evaluate", "--decision")?;
    let Some(point) = DecisionPoint::parse(name) else {
        return Err(usage("unknown-decision", &[("value", name)]));
    };
    let input = args.required("policy evaluate", "--input")?;
    let value = if input.trim_start().starts_with('{') {
        fieldseal_adapters_authoring::decode(input.as_bytes(), fieldseal_adapters_authoring::Format::Json).map_err(|e| usage("bad-input", &[("reason", &e.message)]))?
    } else {
        let Some(v) = load_doc(input, out)? else { return Ok(()) };
        v
    };
    let Value::Map(facts) = value else {
        return Err(usage("not-a-map", &[("file", input), ("what", "facts")]));
    };
    let facts: Facts = facts;
    let paths = layer_paths(args)?;
    if paths.is_empty() {
        return Err(usage("missing-file", &[("command", "policy evaluate")]));
    }
    let Some(layers) = load_layers(&paths, out)? else { return Ok(()) };
    let policy = effective_of(&layers);
    match BuiltInPolicyEngine.evaluate(point, &policy, &facts) {
        Ok(d) => {
            out.lines.push(msg("decision", &[("decision", point.name()), ("verdict", d.verdict.name())]));
            for r in &d.reasons {
                out.lines.push(msg("decision-reason", &[("reason", r)]));
            }
            out.set("decision", Value::Text(point.name().into()));
            out.set("verdict", Value::Text(d.verdict.name().into()));
            out.set("reasons", Value::Array(d.reasons.iter().cloned().map(Value::Text).collect()));
            out.set("obligations", Value::Array(d.obligations.iter().map(|o| Value::Text(format!("{o:?}"))).collect()));
            out.set("policy", Value::Array(policy.sources.iter().map(|a| Value::Text(a.to_text())).collect()));
            if matches!(d.verdict, Verdict::Deny | Verdict::Hold) {
                out.fail(exit::DENIED);
            }
        }
        Err(e) => fail(out, exit::FAILED, "engine-failed", &[("reason", &e.to_string())]),
    }
    Ok(())
}

/// A policy set: comma-separated layer files, as one document with the set's effective controls.
fn set_document(spec: &str, out: &mut Outcome) -> Res<Option<PolicyDocument>> {
    let paths: Vec<String> = spec.split(',').map(str::to_owned).collect();
    let Some(layers) = load_layers(&paths, out)? else { return Ok(None) };
    let eff = effective_of(&layers);
    let mut doc = layers[0].document.clone();
    doc.controls = eff.controls.as_map().clone();
    Ok(Some(doc))
}

fn diff(args: &Args, out: &mut Outcome) -> Res {
    let [a, b] = args.positionals.as_slice() else {
        return Err(usage("diff-needs-two", &[]));
    };
    let (Some(before), Some(after)) = (set_document(a, out)?, set_document(b, out)?) else { return Ok(()) };
    // Both sets were validated and merged when loaded, so the documents are usable as they are.
    let changes = diff_documents(&before, &after);
    let mut rows = Vec::new();
    for c in &changes {
        let dir = match c.direction {
            ChangeDirection::Tighter => "tighter",
            ChangeDirection::Looser => "looser",
            ChangeDirection::Changed => "changed",
        };
        let show = |v: &Option<fieldseal_policy::domain::ControlValue>| v.as_ref().map_or_else(|| "unset".to_owned(), describe);
        out.lines.push(msg("policy-change", &[("path", &c.path), ("before", &show(&c.before)), ("after", &show(&c.after)), ("direction", dir)]));
        rows.push(Value::Map(BTreeMap::from([
            ("path".to_owned(), Value::Text(c.path.clone())),
            ("before".to_owned(), c.before.as_ref().map_or(Value::Text("unset".into()), |v| v.to_value())),
            ("after".to_owned(), c.after.as_ref().map_or(Value::Text("unset".into()), |v| v.to_value())),
            ("direction".to_owned(), Value::Text(dir.into())),
        ])));
    }
    if changes.is_empty() {
        out.lines.push(msg("policy-same", &[]));
    }
    out.set("changes", Value::Array(rows));
    Ok(())
}

fn effective(args: &Args, out: &mut Outcome) -> Res {
    let paths = layer_paths(args)?;
    if paths.is_empty() {
        return Err(usage("missing-file", &[("command", "policy effective")]));
    }
    let Some(layers) = load_layers(&paths, out)? else { return Ok(()) };
    let eff = effective_of(&layers);
    let mut controls = BTreeMap::new();
    for (path, v) in eff.controls.iter() {
        out.lines.push(format!("{path} = {}", describe(v)));
        controls.insert(path.clone(), v.to_value());
    }
    out.set("controls", Value::Map(controls));
    out.set("sources", Value::Array(eff.sources.iter().map(|a| Value::Text(a.to_text())).collect()));
    Ok(())
}
