//! The decoder and the generated JSON Schema accept and reject the same documents (WIRE-209,
//! WIRE-210, WIRE-213). The schema is generated from the kernel's table; the decoder validates
//! against the table; this test checks that the two stay in step.

use std::path::{Path, PathBuf};

use fieldseal_adapters_authoring::{ErrorKind, Format, decode, decode_path, decode_raw, decode_with_spans};
use fieldseal_kernel::schema::{self, DocKind, Select, ShapeId, Ty};
use fieldseal_kernel::value::Value;
use jsonschema::Validator;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// A kernel value as JSON: integers as numbers (text when they exceed `i64`), decimals as numbers
/// parsed from their canonical text, bytes as lowercase hex text.
fn json(v: &Value) -> serde_json::Value {
    match v {
        Value::Int(i) => i64::try_from(*i).map_or_else(|_| serde_json::Value::String(i.to_string()), |n| serde_json::Value::Number(n.into())),
        Value::Decimal(d) => serde_json::from_str(&d.to_string()).expect("a canonical decimal is a JSON number"),
        Value::Bytes(b) => serde_json::Value::String(fieldseal_kernel::digest::lower_hex(b)),
        Value::Text(s) => serde_json::Value::String(s.clone()),
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Array(a) => serde_json::Value::Array(a.iter().map(json).collect()),
        Value::Map(m) => serde_json::Value::Object(m.iter().map(|(k, v)| (k.clone(), json(v))).collect()),
    }
}

fn validator(kind: DocKind) -> Validator {
    jsonschema::validator_for(&json(&schema::json_schema(kind))).expect("the generated schema is a valid JSON Schema")
}

struct Validators {
    survey: Validator,
    layout: Validator,
    roster: Validator,
}

impl Validators {
    fn new() -> Self {
        Self { survey: validator(DocKind::Survey), layout: validator(DocKind::Layout), roster: validator(DocKind::Roster) }
    }

    fn of(&self, kind: DocKind) -> &Validator {
        match kind {
            DocKind::Survey => &self.survey,
            DocKind::Layout => &self.layout,
            DocKind::Roster => &self.roster,
        }
    }

    /// Whether the JSON Schema accepts the document.
    fn accepts(&self, doc: &Value, kind: DocKind) -> bool {
        self.of(kind).is_valid(&json(doc))
    }
}

/// Every compact document under `examples/`, by path.
fn examples() -> Vec<(PathBuf, Value, DocKind)> {
    let mut out = Vec::new();
    for dir in ["instruments", "layouts", "rosters"] {
        let mut files: Vec<_> = std::fs::read_dir(repo().join("examples").join(dir)).expect("examples").filter_map(Result::ok).map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "yaml")).collect();
        files.sort();
        for path in files {
            let doc = decode_raw(&std::fs::read(&path).expect("readable"), Format::Yaml).expect("an example decodes");
            if let Some(kind) = DocKind::detect(&doc) {
                out.push((path, doc, kind));
            }
        }
    }
    out
}

/// The value at a JSON Pointer.
fn at_mut<'a>(doc: &'a mut Value, pointer: &str) -> &'a mut Value {
    let mut here = doc;
    for segment in pointer.split('/').skip(1) {
        let segment = segment.replace("~1", "/").replace("~0", "~");
        here = match here {
            Value::Map(m) => m.get_mut(&segment).expect("a key on the path"),
            Value::Array(a) => a.get_mut(segment.parse::<usize>().expect("an index")).expect("an item on the path"),
            _ => panic!("{pointer} runs into a scalar"),
        };
    }
    here
}

fn map_at<'a>(doc: &'a mut Value, pointer: &str) -> &'a mut std::collections::BTreeMap<String, Value> {
    match at_mut(doc, pointer) {
        Value::Map(m) => m,
        _ => panic!("{pointer} is not a map"),
    }
}

/// A value of a kind the type does not take, if there is one.
fn wrong_kind(ty: &Ty) -> Option<Value> {
    [Value::Text("zz".into()), Value::Int(7), Value::Bool(true), Value::Array(vec![]), Value::Map(Default::default())].into_iter().find(|v| !schema::accepts_kind(ty, v))
}

/// Each mutation of `doc` that the schema must refuse, from the shapes it is read as.
fn mutations(doc: &Value, kind: DocKind) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for (pointer, shape) in schema::shapes_in(doc, kind) {
        let mut probe = doc.clone();
        let present: Vec<String> = map_at(&mut probe, &pointer).keys().cloned().collect();
        let mut unknown = doc.clone();
        map_at(&mut unknown, &pointer).insert("zz-unknown".into(), Value::Int(1));
        out.push((format!("{pointer}: an unknown sibling key"), unknown));
        for key in schema::keys_of(shape).into_iter().filter(|k| present.iter().any(|p| p == k.name)) {
            if key.required {
                let mut d = doc.clone();
                map_at(&mut d, &pointer).remove(key.name);
                out.push((format!("{pointer}: `{}` dropped", key.name), d));
            }
            if let Some(bad) = wrong_kind(&key.ty) {
                let mut d = doc.clone();
                map_at(&mut d, &pointer).insert(key.name.into(), bad);
                out.push((format!("{pointer}: `{}` of the wrong type", key.name), d));
            }
            if matches!(key.ty, Ty::Enum(_)) {
                let mut d = doc.clone();
                map_at(&mut d, &pointer).insert(key.name.into(), Value::Text("zz-not-an-option".into()));
                out.push((format!("{pointer}: `{}` outside its enum", key.name), d));
            }
        }
    }
    out
}

#[test]
fn wire_210_every_example_is_accepted_by_decoder_and_json_schema() {
    let validators = Validators::new();
    let docs = examples();
    assert!(docs.len() >= 4, "found {} examples", docs.len());
    for kind in [DocKind::Survey, DocKind::Layout] {
        assert!(docs.iter().any(|(_, _, k)| *k == kind), "no example of {kind:?}");
    }
    for (path, raw, kind) in docs {
        let decoded = decode_path(&path);
        assert!(decoded.is_ok(), "{}: the decoder refuses it: {decoded:?}", path.display());
        assert!(schema::check(&raw, kind).is_empty(), "{}: the validator refuses it", path.display());
        assert!(validators.accepts(&raw, kind), "{}: the JSON Schema refuses it:\n{:?}", path.display(), validators.of(kind).iter_errors(&json(&raw)).take(3).map(|e| e.to_string()).collect::<Vec<_>>());
    }
}

/// Every mutation of the kind is refused by the validator and by the JSON Schema.
fn every_mutation_is_refused_by_both(label: &str, wanted: fn(&str) -> bool) {
    let validators = Validators::new();
    let mut tried = 0;
    for (path, raw, kind) in examples() {
        for (what, doc) in mutations(&raw, kind) {
            if !wanted(&what) {
                continue;
            }
            tried += 1;
            let name = path.file_name().expect("a file").to_string_lossy().into_owned();
            assert!(!schema::check(&doc, kind).is_empty(), "{name}, {what}: the validator accepts a {label}");
            assert!(!validators.accepts(&doc, kind), "{name}, {what}: the JSON Schema accepts a {label}");
        }
    }
    assert!(tried >= 20, "only {tried} {label} mutations were tried");
}

#[test]
fn wire_210_a_compact_roster_is_judged_alike_by_decoder_and_json_schema() {
    // No bundled example is a compact roster, so the kind is checked on a small document.
    let validators = Validators::new();
    let good = "roster: {cohort: c1, version: 1}\ncolumns: [subject, display, village]\nrows:\n- [p-1, One, Hill]\n";
    let bad = ["roster: {cohort: c1}\ncolumns: [subject, display]\nrows: []\n", "roster: {cohort: c1, version: 1, extra: 2}\ncolumns: [subject, display]\nrows: []\n", "roster: {cohort: c1, version: 1}\ncolumns: subject\nrows: []\n"];
    let raw = decode_raw(good.as_bytes(), Format::Yaml).expect("decodes");
    assert!(decode(good.as_bytes(), Format::Yaml).is_ok() && validators.accepts(&raw, DocKind::Roster));
    for text in bad {
        let raw = decode_raw(text.as_bytes(), Format::Yaml).expect("decodes");
        assert!(decode(text.as_bytes(), Format::Yaml).is_err(), "{text}");
        assert!(!validators.accepts(&raw, DocKind::Roster), "{text}");
    }
}

#[test]
fn wire_210_dropping_a_required_key_is_rejected_by_both() {
    every_mutation_is_refused_by_both("dropped required key", |w| w.ends_with("dropped"));
}

#[test]
fn wire_210_a_wrong_type_is_rejected_by_both() {
    every_mutation_is_refused_by_both("wrong type", |w| w.ends_with("of the wrong type"));
}

#[test]
fn wire_210_a_value_outside_an_enum_is_rejected_by_both() {
    every_mutation_is_refused_by_both("value outside an enum", |w| w.ends_with("outside its enum"));
}

#[test]
fn wire_210_an_unknown_sibling_key_is_rejected_by_both() {
    every_mutation_is_refused_by_both("unknown sibling key", |w| w.ends_with("an unknown sibling key"));
}

#[test]
fn wire_210_the_decoder_refuses_a_mutated_document_with_findings() {
    // The decoder (not only the validator) reports a mutation, as findings.
    let (_, raw, kind) = examples().into_iter().find(|(_, _, k)| *k == DocKind::Survey).expect("a survey example");
    let (what, doc) = mutations(&raw, kind).into_iter().next().expect("a mutation");
    let text = serde_json::to_string(&json(&doc)).expect("serialises");
    let e = decode(text.as_bytes(), Format::Json).expect_err(&what);
    assert_eq!(e.kind, ErrorKind::Compact, "{what}");
    assert!(!e.findings.is_empty(), "{what}");
    // The JSON text carries positions, so the findings do too.
    assert!(e.findings.iter().all(|f| f.position.line >= 1), "{what}: {:?}", e.findings);
}

#[test]
fn wire_209_json_schema_output_is_deterministic() {
    for kind in [DocKind::Survey, DocKind::Layout, DocKind::Roster] {
        let first = serde_json::to_string_pretty(&json(&schema::json_schema(kind))).expect("serialises");
        let second = serde_json::to_string_pretty(&json(&schema::json_schema(kind))).expect("serialises");
        assert_eq!(first, second);
        // The schema is closed everywhere a shape is a map of declared keys.
        let value: serde_json::Value = serde_json::from_str(&first).expect("parses");
        let defs = value["$defs"].as_object().expect("defs");
        for (name, def) in defs {
            let shape = schema::shape(ShapeId(Box::leak(name.clone().into_boxed_str()))).expect("a declared shape");
            if matches!(shape.select, Select::Closed | Select::Single) {
                assert_eq!(def["additionalProperties"], serde_json::Value::Bool(false), "{name} is not closed");
            }
        }
    }
}

/// The `# expect: <Kind> <pointer>` comment of a corpus document.
fn expectation(text: &str) -> (String, String) {
    let line = text.lines().find_map(|l| l.strip_prefix("# expect:")).expect("an expect comment");
    let (kind, pointer) = line.trim().split_once(' ').expect("kind and pointer");
    (kind.to_owned(), pointer.to_owned())
}

#[test]
fn wire_213_every_document_in_the_schema_corpus_is_rejected_by_both() {
    let validators = Validators::new();
    let mut seen = 0;
    for (dir, kind) in [("survey", DocKind::Survey), ("layout", DocKind::Layout)] {
        let mut files: Vec<_> = std::fs::read_dir(repo().join("tests/schema-corpus").join(dir)).expect("corpus").filter_map(Result::ok).map(|e| e.path()).collect();
        files.sort();
        for path in files {
            let name = format!("{dir}/{}", path.file_name().expect("a file").to_string_lossy());
            let bytes = std::fs::read(&path).expect("readable");
            let (wanted_kind, wanted_pointer) = expectation(&String::from_utf8(bytes.clone()).expect("utf-8"));
            // The decoder refuses it, with the finding the document names.
            let e = decode(&bytes, Format::Yaml).expect_err(&name);
            assert!(e.findings.iter().any(|f| f.kind.name() == wanted_kind && f.pointer == wanted_pointer), "{name}: wanted {wanted_kind} at {wanted_pointer}, got {:?}", e.findings);
            // A repeated key and a refused value never become a document, so only the decoder
            // can refuse them; for every other kind the JSON Schema refuses the document too.
            if !matches!(wanted_kind.as_str(), "DuplicateKey" | "CoercionRefused") {
                let (doc, _) = decode_with_spans(std::str::from_utf8(&bytes).expect("utf-8"), Format::Yaml).expect(&name);
                assert!(!validators.accepts(&doc, kind), "{name}: the JSON Schema accepts it");
                assert!(schema::check(&doc, kind).iter().any(|f| f.kind.name() == wanted_kind && f.pointer == wanted_pointer), "{name}: the validator does not report {wanted_kind} at {wanted_pointer}");
            }
            seen += 1;
        }
    }
    assert!(seen >= 100, "{seen} corpus documents");
}
