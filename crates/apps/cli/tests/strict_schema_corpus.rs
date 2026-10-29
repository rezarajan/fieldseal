//! The `strict-schema` conformance suite (CLI-043, WIRE-213) runs the whole invalid-document
//! corpus, and the corpus embedded in the binary is the corpus on disk.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

fn fieldseal(args: &[&str]) -> (bool, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_fieldseal")).args(args).output().expect("runs");
    (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/schema-corpus")
}

/// Every file of the corpus on disk, as `<kind>/<file>`.
fn on_disk() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for kind in ["survey", "layout"] {
        for entry in std::fs::read_dir(corpus().join(kind)).expect("corpus directory").flatten() {
            out.insert(format!("{kind}/{}", entry.file_name().to_string_lossy()));
        }
    }
    out
}

#[test]
fn wire_213_the_embedded_corpus_lists_every_file() {
    let (ok, out, err) = fieldseal(&["conformance", "run", "--json", "--suite", "strict-schema"]);
    assert!(ok, "{out}\n{err}");
    let doc: serde_json::Value = serde_json::from_str(&out).expect("one JSON document");
    // One check per embedded document: the table is exactly the directory.
    let checks = doc["requirements"]["WIRE-213"]["checks"].as_u64().expect("a count of checks");
    let files = on_disk();
    assert_eq!(usize::try_from(checks).expect("fits"), files.len(), "the embedded table and tests/schema-corpus disagree");
    let table = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/conformance_cmd/strict_schema.rs")).expect("source");
    let embedded: BTreeSet<String> = table
        .lines()
        .filter(|l| l.trim_start().starts_with("(DocKind::"))
        .filter_map(|l| l.split("tests/schema-corpus/").nth(1))
        .filter_map(|rest| rest.split('"').next())
        .map(str::to_owned)
        .collect();
    assert_eq!(embedded, files, "a corpus file is not embedded, or an embedded file is gone");
}

#[test]
fn cli_043_conformance_list_names_strict_schema() {
    let (ok, out, _) = fieldseal(&["conformance", "list"]);
    assert!(ok, "{out}");
    assert!(out.lines().any(|l| l.starts_with("strict-schema")), "{out}");
}

#[test]
fn cli_043_the_strict_schema_suite_rejects_every_corpus_document() {
    let (ok, out, err) = fieldseal(&["conformance", "run", "--json", "--suite", "strict-schema"]);
    assert!(ok, "{out}\n{err}");
    let doc: serde_json::Value = serde_json::from_str(&out).expect("one JSON document");
    assert_eq!(doc["summary"]["failed_checks"], 0, "{out}");
    for id in ["WIRE-210", "WIRE-211", "WIRE-213"] {
        assert_eq!(doc["requirements"][id]["status"], "pass", "{id}: {out}");
    }
}
