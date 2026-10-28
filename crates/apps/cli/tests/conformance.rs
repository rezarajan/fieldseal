//! `fieldseal conformance` (#56, #57): the suites pass, every driven port has a contract and
//! an adapter that runs it, and the generated documentation table is current.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

fn fieldseal(args: &[&str]) -> (bool, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_fieldseal")).args(args).output().expect("runs");
    (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

// covers: CLI-017
#[test]
fn cli_017_conformance_run_reports_every_suite_per_requirement_and_passes() {
    let (ok, out, err) = fieldseal(&["conformance", "run", "--json"]);
    assert!(ok, "{out}\n{err}");
    let doc: serde_json::Value = serde_json::from_str(&out).expect("one JSON document");
    assert_eq!(doc["summary"]["failed_checks"], 0, "{out}");
    let reqs = doc["requirements"].as_object().expect("requirements");
    for id in ["WIRE-001", "WIRE-031", "WIRE-109", "TRU-011", "TRU-091", "PUB-104", "PUB-106", "DIS-030", "INS-041", "POL-034", "PLAT-033"] {
        assert_eq!(reqs[id]["status"], "pass", "{id} is reported and passes");
    }
}

#[test]
fn cli_017_a_single_suite_and_unknown_suites() {
    let (ok, out, _) = fieldseal(&["conformance", "run", "--suite", "transparency-log"]);
    assert!(ok, "{out}");
    assert!(out.contains("PASS PUB-104"), "{out}");
    let (ok, _, err) = fieldseal(&["conformance", "run", "--suite", "nonsense"]);
    assert!(!ok && err.contains("unknown suite"), "{err}");
}

/// The driven ports and the adapter types that implement them, read from the source.
fn ports_in_source() -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for ctx in std::fs::read_dir(repo().join("crates/contexts")).expect("contexts").flatten() {
        let Ok(src) = std::fs::read_to_string(ctx.path().join("src/ports.rs")) else { continue };
        for line in src.lines() {
            if let Some(rest) = line.strip_prefix("pub trait ") {
                let name: String = rest.chars().take_while(|c| c.is_alphanumeric()).collect();
                out.insert((ctx.file_name().to_string_lossy().into_owned(), name));
            }
        }
    }
    out
}

// covers: CLI-017
#[test]
fn every_driven_port_has_a_contract_run_against_at_least_one_adapter() {
    let (_, matrix, _) = fieldseal(&["conformance", "matrix"]);
    let covered: BTreeSet<(String, String)> = matrix
        .lines()
        .filter(|l| l.starts_with("| ") && !l.starts_with("| Context") && !l.starts_with("|---"))
        .filter_map(|l| {
            let cells: Vec<&str> = l.split('|').map(str::trim).collect();
            Some((cells.get(1)?.to_string(), cells.get(2)?.trim_matches('`').to_string()))
        })
        .collect();
    // Ports that other contexts' contracts exercise under another context's name.
    let missing: Vec<_> = ports_in_source().into_iter().filter(|p| !covered.contains(p)).collect();
    assert!(missing.is_empty(), "ports without a contract run: {missing:?}");
}

// covers: CLI-017, PLAT-033
#[test]
fn every_adapter_implementing_a_port_is_in_the_matrix() {
    let (_, matrix, _) = fieldseal(&["conformance", "matrix"]);
    let ports: BTreeSet<String> = ports_in_source().into_iter().map(|(_, p)| p).collect();
    // Implementations that are not adapters: test doubles, blanket impls and shims.
    let exempt = ["AcceptAll", "Dyn", "Stub", "Leaky", "LabelCustody", "Fixed", "Opener", "Small", "FullAll", "PracticeAllowed"];
    let mut unlisted = Vec::new();
    let mut stack = vec![repo().join("crates")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("dir").flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if !matches!(name.as_str(), "target" | "tests" | "bindings") {
                    stack.push(path);
                }
            } else if name.ends_with(".rs") {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                let production = text.split("#[cfg(test)]").next().unwrap_or("");
                for line in production.lines() {
                    let line = line.trim_start();
                    let Some(rest) = line.strip_prefix("impl") else { continue };
                    let Some((head, tail)) = rest.split_once(" for ") else { continue };
                    let port: String = head.rsplit("::").next().unwrap_or(head).chars().filter(|c| c.is_alphanumeric()).collect();
                    let adapter: String = tail.trim_start_matches('&').chars().take_while(|c| c.is_alphanumeric()).collect();
                    let port_name = port.trim_start_matches(|c: char| !c.is_alphabetic());
                    if ports.contains(port_name) && !exempt.contains(&adapter.as_str()) && !adapter.is_empty() && !matrix.contains(&format!("`{adapter}`")) && !matrix.contains(&format!("`{adapter} ")) {
                        unlisted.push(format!("{adapter} implements {port_name} ({})", path.display()));
                    }
                }
            }
        }
    }
    assert!(unlisted.is_empty(), "adapters that no contract is registered for: {unlisted:#?}");
}

// covers: CLI-017, PLAT-033
#[test]
fn the_conformance_document_is_generated_from_the_matrix() {
    let (_, matrix, _) = fieldseal(&["conformance", "matrix"]);
    let doc = std::fs::read_to_string(repo().join("docs/reference/conformance.md")).expect("docs/reference/conformance.md");
    assert!(doc.contains(matrix.trim_end()), "docs/reference/conformance.md is stale; regenerate the table with `fieldseal conformance matrix`");
}

// covers: CLI-017
#[test]
fn cli_017_the_context_suites_list_run_and_pass() {
    let suites = ["col-lifecycle", "col-session", "col-crash", "reg-token", "reg-verify", "reg-revoke", "reg-attacks", "dis-release", "ins-checks", "ins-locale", "ins-codes", "ins-nonresponse", "ins-units"];
    let (_, listed, _) = fieldseal(&["conformance", "list"]);
    for s in suites {
        assert!(listed.lines().any(|l| l.starts_with(s)), "{s} is listed");
    }
    let (ok, out, err) = fieldseal(&["conformance", "run", "--json", "--suite", "col-lifecycle,reg-verify,dis-release,ins-codes"]);
    assert!(ok, "{out}\n{err}");
    let doc: serde_json::Value = serde_json::from_str(&out).expect("one JSON document");
    assert_eq!(doc["summary"]["failed_checks"], 0, "{out}");
    let reqs = doc["requirements"].as_object().expect("requirements");
    for id in ["COL-001", "COL-007", "REG-014", "REG-017", "DIS-001", "DIS-004", "INS-133", "INS-137"] {
        assert_eq!(reqs[id]["status"], "pass", "{id} is reported and passes");
    }
}
