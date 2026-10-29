//! `fieldseal conformance run --suite <name>`: the golden vectors and conformance suites the
//! specs' §8 tables name, run in-process and reported per requirement ID (CLI-017, #56).
//!
//! The work is split into *units*: a vector file, or one contract function against one
//! adapter. Each unit runs in its own `fieldseal` process, because a failed contract panics
//! and a release build aborts on panic; a crash is reported as a failure of that unit's
//! requirements, never as a missing result.
//!
//! ```text
//! fieldseal conformance run [--suite <name>[,<name>…]] [--adapter <name>] [--json]
//! fieldseal conformance list
//! fieldseal conformance matrix        # the port → contract → adapters table (Markdown)
//! ```
//!
//! Suites: `wire`, `trust`, `publishing`, `distribution` (alias `dis-verify`), `ins-rules`
//! and `ins-eval`, `policy`, `transparency-log`, `contracts`, one per context for its port
//! contracts, and `all`.

mod col;
mod contracts;
mod dis_release;
mod distribution;
mod harness;
mod ins;
mod ins_clinic;
mod ins_invalid;
mod ins_render;
mod ins_spec;
#[path = "../../../../contexts/instrument/tests/support/mod.rs"]
mod ins_support;
mod publishing;
mod reg;
mod reg_attacks;
mod rules;
mod strict_schema;
mod trust;
mod wire;

use std::collections::{BTreeMap, BTreeSet};
use std::process::{Command, ExitCode};

use serde_json::{Value as J, json};

use crate::outcome::exit;
use harness::{Check, CheckResult, Collector, Status};

pub use contracts::{Location, entries};

enum Kind {
    Vector(fn(&mut Collector)),
    Table(&'static [Check]),
    Contract { requirements: &'static [&'static str], contract: &'static str, run: fn() },
}

/// One independently runnable part of a suite.
pub struct Unit {
    id: String,
    suites: Vec<&'static str>,
    kind: Kind,
}

impl Unit {
    fn new(id: &str, suites: &[&'static str], run: fn(&mut Collector)) -> Self {
        Self { id: id.to_owned(), suites: suites.to_vec(), kind: Kind::Vector(run) }
    }

    /// A unit that runs a table of panicking checks, each naming its requirements.
    fn table(id: &str, suites: &[&'static str], checks: &'static [Check]) -> Self {
        Self { id: id.to_owned(), suites: suites.to_vec(), kind: Kind::Table(checks) }
    }

    fn contract(id: String, suites: Vec<&'static str>, requirements: &'static [&'static str], contract: &'static str, run: fn()) -> Self {
        Self { id, suites, kind: Kind::Contract { requirements, contract, run } }
    }

    fn execute(&self) -> Vec<CheckResult> {
        match &self.kind {
            Kind::Vector(f) => {
                let mut c = Collector::new(&self.id);
                f(&mut c);
                c.results
            }
            Kind::Table(checks) => {
                let mut c = Collector::new(&self.id);
                for check in *checks {
                    c.check(check);
                }
                c.results
            }
            Kind::Contract { requirements, contract, run } => contracts::run_contract(&self.id, requirements, contract, *run).results,
        }
    }

    fn requirements(&self) -> Vec<String> {
        match &self.kind {
            Kind::Vector(_) => Vec::new(),
            Kind::Table(checks) => {
                let ids: BTreeSet<&str> = checks.iter().flat_map(|c| c.reqs.iter().copied()).collect();
                ids.into_iter().map(str::to_owned).collect()
            }
            Kind::Contract { requirements, .. } => requirements.iter().map(|r| (*r).to_owned()).collect(),
        }
    }
}

/// Every unit.
fn units() -> Vec<Unit> {
    let mut all = Vec::new();
    all.extend(wire::units());
    all.extend(trust::units());
    all.extend(publishing::units());
    all.extend(distribution::units());
    all.extend(rules::units());
    all.extend(col::units());
    all.extend(reg::units());
    all.extend(dis_release::units());
    all.extend(ins::units());
    all.extend(reg_attacks::units());
    all.extend(contracts::units());
    all.extend(strict_schema::units());
    all
}

/// The suites that exist, with what they hold.
const SUITES: &[(&str, &str)] = &[
    ("wire", "kernel wire vectors (WIRE §8), plus receipts, time tokens and the receiver challenge"),
    ("trust", "trust vectors and the trust ports' contracts"),
    ("publishing", "publishing vectors and the publishing ports' contracts"),
    ("transparency-log", "the TransparencyLog contract and log-entry vectors (PUB §8)"),
    ("distribution", "the bundle file vector (also `dis-verify`) and the distribution ports' contracts"),
    ("ins-rules", "rule grammar and bounds (also `ins-eval`: unset propagation and verdicts)"),
    ("policy", "the policy engine cases and the policy ports' contracts"),
    ("contracts", "every port contract against every in-process adapter"),
    ("collection", "the collection ports' contracts"),
    ("delivery", "the delivery ports' contracts"),
    ("deployment", "the deployment ports' contracts"),
    ("instrument", "the instrument ports' contracts"),
    ("intake", "the intake ports' contracts"),
    ("registration", "the registration ports' contracts"),
    ("col-lifecycle", "tenancy lifecycle, close certificate, outbox (COL-001..010)"),
    ("col-session", "PIN floor, lockout, idle and background locks (COL-020..027)"),
    ("col-crash", "dual write, crash recovery and fault injection (COL-050..053, 092, 093)"),
    ("reg-token", "token fields, single use, factory-side expiry (REG-002..006)"),
    ("reg-verify", "token trust, request nonce and sealing, verification order, attestation and policy (REG-010..017)"),
    ("reg-revoke", "key roll, mark as lost, close certificates, forgotten PIN (REG-060..065)"),
    ("reg-attacks", "the registration attack table, section 5.9"),
    ("dis-release", "release refused before registration and for flagged tenancies; practice bundles (DIS-001..004)"),
    ("ins-checks", "field checks raise on golden record sets (INS-050..053)"),
    ("ins-locale", "language lookup, locale formatting, native-digit input (INS-087..089)"),
    ("ins-codes", "code lists: exclusive, other, ordered, numeric values (INS-131..136, 048)"),
    ("ins-nonresponse", "nonresponse recorded, cleared and counted as answered (INS-140..143)"),
    ("ins-units", "entry units and money convert exactly (INS-160..163)"),
    ("strict-schema", "the invalid-document corpus (WIRE-213) through every reader"),
    ("all", "everything above"),
];

fn selected<'a>(all: &'a [Unit], suites: &[String]) -> Result<Vec<&'a Unit>, String> {
    let known: BTreeSet<&str> = SUITES.iter().map(|(n, _)| *n).chain(["dis-verify", "ins-eval"]).collect();
    for s in suites {
        if !known.contains(s.as_str()) {
            return Err(format!("unknown suite `{s}`; known suites: {}", SUITES.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")));
        }
    }
    Ok(all
        .iter()
        .filter(|u| suites.is_empty() || suites.iter().any(|s| s == "all" || u.suites.contains(&s.as_str())))
        .collect())
}

/// The parsed arguments of `fieldseal conformance …`.
#[derive(Debug, PartialEq, Eq)]
struct Flags {
    verb: String,
    suites: Vec<String>,
    child: Option<String>,
    adapter: Option<String>,
}

/// Reads `conformance` arguments strictly: only `--json`, `--suite` (repeatable, comma lists),
/// `--child` and `--adapter` (once each, each with a value), the noun and one verb. Anything
/// else is a usage error (CLI-022).
fn parse_flags(args: &[String]) -> Result<Flags, String> {
    let mut flags = Flags { verb: String::new(), suites: Vec::new(), child: None, adapter: None };
    let mut words: Vec<&str> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_owned())),
            _ => (a.as_str(), None),
        };
        let value = |it: &mut std::slice::Iter<'_, String>| match inline.clone() {
            Some(v) => Ok(v),
            None => it.next().filter(|v| !v.starts_with("--")).cloned().ok_or_else(|| format!("`{name}` needs a value")),
        };
        match name {
            "--json" if inline.is_none() => {}
            "--suite" => {
                let v = value(&mut it)?;
                if v.is_empty() || v.split(',').any(str::is_empty) {
                    return Err("`--suite` takes names separated by commas".into());
                }
                flags.suites.extend(v.split(',').map(str::to_owned));
            }
            "--child" | "--adapter" => {
                let slot = if name == "--child" { &mut flags.child } else { &mut flags.adapter };
                if slot.is_some() {
                    return Err(format!("`{name}` was given more than once"));
                }
                *slot = Some(value(&mut it)?);
            }
            n if n.starts_with('-') => return Err(format!("`conformance` doesn't take `{n}`")),
            w => words.push(w),
        }
    }
    match words.as_slice() {
        ["conformance"] => {}
        ["conformance", verb] => flags.verb = (*verb).to_owned(),
        [_, _, extra, ..] => return Err(format!("unexpected argument `{extra}`")),
        _ => return Err("usage: conformance run | list | matrix".into()),
    }
    Ok(flags)
}

/// The entry point for `fieldseal conformance …`.
pub fn run(args: &[String]) -> ExitCode {
    let json_out = args.iter().any(|a| a == "--json");
    let Flags { verb, suites, child, adapter } = match parse_flags(args) {
        Ok(f) => f,
        Err(m) => {
            eprintln!("fieldseal: {m}");
            return ExitCode::from(exit::USAGE);
        }
    };
    let all = units();
    if let Some(id) = child {
        return run_child(&all, &id);
    }
    match verb.as_str() {
        "run" => {
            let units = match selected(&all, &suites) {
                Ok(u) => u,
                Err(m) => {
                    eprintln!("fieldseal: {m}");
                    return ExitCode::from(exit::USAGE);
                }
            };
            let units: Vec<&Unit> = match &adapter {
                Some(a) => units.into_iter().filter(|u| u.id.to_lowercase().ends_with(&format!(":{}", a.to_lowercase()))).collect(),
                None => units,
            };
            if units.is_empty() {
                let external: Vec<String> = entries()
                    .iter()
                    .filter_map(|e| match e.location {
                        Location::CargoTest(how) => Some(format!("{} ({how})", e.adapter)),
                        Location::Here(_) => None,
                    })
                    .collect();
                eprintln!("fieldseal: no in-process unit matches; adapters that run under cargo test: {}", external.join("; "));
                return ExitCode::from(exit::NOT_FOUND);
            }
            let results = execute(&units);
            report(&suites, &results, json_out)
        }
        "list" => {
            for (name, what) in SUITES {
                println!("{name:<17} {what}");
            }
            ExitCode::from(exit::OK)
        }
        "matrix" => {
            print!("{}", matrix());
            ExitCode::from(exit::OK)
        }
        _ => {
            eprintln!("fieldseal: usage: conformance run [--suite <name>[,<name>…]] [--json] | conformance list | conformance matrix");
            ExitCode::from(exit::USAGE)
        }
    }
}

fn run_child(all: &[Unit], id: &str) -> ExitCode {
    let Some(unit) = all.iter().find(|u| u.id == id) else {
        eprintln!("fieldseal: no conformance unit `{id}`");
        return ExitCode::from(exit::NOT_FOUND);
    };
    std::panic::set_hook(Box::new(|info| {
        let msg = info.payload().downcast_ref::<String>().cloned().or_else(|| info.payload().downcast_ref::<&str>().map(|s| (*s).to_owned()));
        eprintln!("panic: {}", msg.unwrap_or_else(|| "a contract assertion failed".into()));
    }));
    let rows: Vec<J> = unit
        .execute()
        .into_iter()
        .map(|r| {
            let (status, message) = match r.status {
                Status::Pass => ("pass", String::new()),
                Status::Fail(m) => ("fail", m),
            };
            json!({"name": r.name, "requirements": r.requirements, "status": status, "message": message})
        })
        .collect();
    println!("{}", J::Array(rows));
    ExitCode::from(exit::OK)
}

fn execute(units: &[&Unit]) -> Vec<CheckResult> {
    let exe = std::env::current_exe().ok();
    let mut out = Vec::new();
    for u in units {
        let crashed = |why: String| CheckResult { unit: u.id.clone(), name: "unit".into(), requirements: u.requirements(), status: Status::Fail(why) };
        let Some(exe) = &exe else {
            out.push(crashed("cannot find the fieldseal executable".into()));
            continue;
        };
        match Command::new(exe).args(["conformance", "run", "--child", &u.id]).output() {
            Ok(o) if o.status.success() => match serde_json::from_slice::<Vec<J>>(&o.stdout) {
                Ok(rows) => {
                    for r in rows {
                        let msg = r["message"].as_str().unwrap_or("").to_owned();
                        out.push(CheckResult {
                            unit: u.id.clone(),
                            name: r["name"].as_str().unwrap_or("").to_owned(),
                            requirements: r["requirements"].as_array().map_or_else(Vec::new, |a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect()),
                            status: if r["status"] == "pass" { Status::Pass } else { Status::Fail(msg) },
                        });
                    }
                }
                Err(e) => out.push(crashed(format!("unreadable result: {e}"))),
            },
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr);
                let line = err.lines().find(|l| l.starts_with("panic:")).unwrap_or("the unit crashed").to_owned();
                out.push(crashed(line));
            }
            Err(e) => out.push(crashed(format!("cannot start: {e}"))),
        }
    }
    out
}

fn report(suites: &[String], results: &[CheckResult], json_out: bool) -> ExitCode {
    // Per requirement: every check that names it must pass.
    let mut by_req: BTreeMap<&str, (usize, Vec<String>)> = BTreeMap::new();
    for r in results {
        for id in &r.requirements {
            let e = by_req.entry(id.as_str()).or_default();
            e.0 += 1;
            if let Status::Fail(m) = &r.status {
                e.1.push(format!("{}: {}: {m}", r.unit, r.name));
            }
        }
    }
    let unnumbered_failures: Vec<&CheckResult> = results.iter().filter(|r| r.requirements.is_empty() && matches!(r.status, Status::Fail(_))).collect();
    let failed_reqs = by_req.values().filter(|(_, f)| !f.is_empty()).count();
    let failed_checks = results.iter().filter(|r| matches!(r.status, Status::Fail(_))).count();
    let external: Vec<J> = entries()
        .iter()
        .filter_map(|e| match e.location {
            Location::CargoTest(how) => Some(json!({"context": e.context, "port": e.port, "adapter": e.adapter, "run": how})),
            Location::Here(_) => None,
        })
        .collect();
    if json_out {
        let reqs: BTreeMap<&str, J> = by_req
            .iter()
            .map(|(id, (n, f))| (*id, json!({"status": if f.is_empty() { "pass" } else { "fail" }, "checks": n, "failures": f})))
            .collect();
        let doc = json!({
            "command": "conformance run",
            "suites": if suites.is_empty() { vec!["all".to_owned()] } else { suites.to_vec() },
            "requirements": reqs,
            "unnumbered_failures": unnumbered_failures.iter().map(|r| json!({"unit": r.unit, "check": r.name, "message": match &r.status { Status::Fail(m) => m.as_str(), Status::Pass => "" }})).collect::<Vec<_>>(),
            "external_contracts": external,
            "summary": {"checks": results.len(), "failed_checks": failed_checks, "requirements": by_req.len(), "failed_requirements": failed_reqs},
        });
        println!("{doc}");
    } else {
        for (id, (n, f)) in &by_req {
            if f.is_empty() {
                println!("PASS {id:<9} {n} check(s)");
            } else {
                println!("FAIL {id:<9} {n} check(s)");
                for m in f {
                    println!("       {m}");
                }
            }
        }
        for r in &unnumbered_failures {
            if let Status::Fail(m) = &r.status {
                println!("FAIL {} {}: {m}", r.unit, r.name);
            }
        }
        println!(
            "\n{} checks, {failed_checks} failed; {} requirements, {failed_reqs} failed; {} adapter contracts run under cargo test (see `conformance matrix`)",
            results.len(),
            by_req.len(),
            external.len()
        );
    }
    ExitCode::from(if failed_checks == 0 { exit::OK } else { exit::FAILED })
}

/// The port → contract → adapters table, as Markdown (docs/reference/conformance.md).
pub fn matrix() -> String {
    let mut rows: BTreeMap<(String, String, String), Vec<(String, bool)>> = BTreeMap::new();
    for e in entries() {
        rows.entry((e.context.to_owned(), e.port.to_owned(), e.contract.to_owned()))
            .or_default()
            .push((e.adapter.to_owned(), matches!(e.location, Location::Here(_))));
    }
    let mut out = String::from(
        "<!-- Generated by `fieldseal conformance matrix`; do not edit by hand. A test keeps it current. -->\n\n\
         | Context | Port | Contract | Adapters that pass it |\n|---|---|---|---|\n",
    );
    for ((ctx, port, contract), adapters) in rows {
        let list: Vec<String> = adapters.iter().map(|(a, here)| if *here { format!("`{a}`") } else { format!("`{a}` (cargo test)") }).collect();
        out.push_str(&format!("| {ctx} | `{port}` | `{contract}` | {} |\n", list.join(", ")));
    }
    out
}
