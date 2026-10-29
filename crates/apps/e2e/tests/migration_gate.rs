//! The migration gate (Technical Plan §5): every example's expanded documents, content
//! addresses, salted fingerprint and bound layout addresses stay what the golden set in
//! `tests/golden/` says. A change that must not alter a signed byte (a decoder rewrite, a move
//! of the sources) passes only if these tests pass unchanged.
//!
//! `FIELDSEAL_GOLDEN=write cargo test -p fieldseal-e2e --test migration_gate` rewrites the
//! golden set from the current decoder. CI never sets it; a change to the golden set is a
//! reviewed event.

#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use fieldseal_adapters_authoring::{Format, decode_path, decode_raw};
use fieldseal_e2e::{examples, expanded_json, pinned_salt, survey_sources};
use fieldseal_instrument::application::{LayoutBinding, LayoutOptions, validate_instrument, validate_layout_with};
use fieldseal_kernel::Value;
use fieldseal_kernel::cbor;
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::id::{ContentAddress, Fingerprint};
use fieldseal_publishing::domain::{ArtefactKind, artefact_address};

const SURVEYS: [&str; 2] = ["household-water-access", "school-meals-baseline"];

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn writing() -> bool {
    std::env::var("FIELDSEAL_GOLDEN").is_ok_and(|v| v == "write")
}

/// Everything the gate records about one survey.
struct Recorded {
    salt: String,
    instrument_address: ContentAddress,
    fingerprint: Fingerprint,
    /// Window class to (bound layout address, expanded and bound layout text).
    layouts: BTreeMap<&'static str, (ContentAddress, String)>,
    instrument_text: String,
}

fn load(path: &str) -> Value {
    let full = examples().join(path);
    decode_path(&full).unwrap_or_else(|e| panic!("{}: {e}", full.display()))
}

/// Expands, addresses and binds one survey, following `Site::new`.
fn record(name: &str) -> Recorded {
    let sources = survey_sources(name);
    for catalogue in sources.catalogues {
        assert!(examples().join(catalogue).is_file(), "{name}: catalogue {catalogue} is missing");
    }
    let doc = load(sources.instrument);
    let instrument = validate_instrument(&doc).unwrap_or_else(|f| panic!("{name}: {:?}", f.iter().collect::<Vec<_>>())).instrument;
    let bytes = cbor::encode(&doc).expect("encodes");
    let instrument_address = ContentAddress::of(&bytes);
    let salt = pinned_salt(name);
    let fingerprint = Fingerprint::from(*artefact_address(ArtefactKind::Instrument, &bytes, Some(&salt)).expect("a salted instrument address").as_bytes());

    let mut layouts = BTreeMap::new();
    for (window, path) in sources.layouts {
        let mut layout = load(path);
        let Value::Map(root) = &mut layout else { panic!("{name}/{window}: a layout is a map") };
        let Some(Value::Map(spec)) = root.get_mut("spec") else { panic!("{name}/{window}: a layout has a spec") };
        spec.insert("instrument".into(), Value::Bytes(fingerprint.as_bytes().to_vec()));
        let address = ContentAddress::of(&cbor::encode(&layout).expect("encodes"));
        let resolve = |_: &_| None;
        let options = LayoutOptions { binding: Some(LayoutBinding { expected: fingerprint, resolve: &resolve }) };
        validate_layout_with(&layout, &instrument, options).unwrap_or_else(|f| panic!("{name}/{window}: {:?}", f.iter().collect::<Vec<_>>()));
        layouts.insert(*window, (address, expanded_json(&layout)));
    }
    Recorded { salt: lower_hex(salt.as_bytes()), instrument_address, fingerprint, layouts, instrument_text: expanded_json(&doc) }
}

fn address_text(a: &ContentAddress) -> String {
    format!("sha256:{}", lower_hex(a.as_bytes()))
}

fn table(rec: &Recorded) -> Value {
    let text = |t: String| Value::Text(t);
    let layouts = rec.layouts.iter().map(|(w, (a, _))| ((*w).to_owned(), text(address_text(a)))).collect();
    Value::Map(BTreeMap::from([
        ("salt".to_owned(), text(rec.salt.clone())),
        ("instrument_address".to_owned(), text(address_text(&rec.instrument_address))),
        ("instrument_fingerprint".to_owned(), text(lower_hex(rec.fingerprint.as_bytes()))),
        ("layouts".to_owned(), Value::Map(layouts)),
    ]))
}

fn write_golden() {
    let mut all = BTreeMap::new();
    for name in SURVEYS {
        let rec = record(name);
        let dir = golden_dir().join("expanded").join(name);
        std::fs::create_dir_all(&dir).expect("the golden directory");
        std::fs::write(dir.join("instrument.json"), &rec.instrument_text).expect("writes the instrument");
        for (window, (_, text)) in &rec.layouts {
            std::fs::write(dir.join(format!("layout-{window}.json")), text).expect("writes a layout");
        }
        all.insert(name.to_owned(), table(&rec));
    }
    std::fs::write(golden_dir().join("examples.json"), expanded_json(&Value::Map(all))).expect("writes examples.json");
}

/// The golden table, read with the authoring decoder.
fn golden() -> BTreeMap<String, Value> {
    if writing() {
        write_golden();
    }
    let bytes = std::fs::read(golden_dir().join("examples.json")).expect("tests/golden/examples.json");
    match decode_raw(&bytes, Format::Json).expect("the golden table decodes") {
        Value::Map(m) => m,
        _ => panic!("the golden table is a map"),
    }
}

fn field<'a>(entry: &'a Value, name: &str, key: &str) -> &'a Value {
    entry.as_map().and_then(|m| m.get(key)).unwrap_or_else(|| panic!("{name}: the golden set has no `{key}`"))
}

fn assert_same(name: &str, what: &str, golden: &str, actual: &str) {
    assert_eq!(golden, actual, "{name}: {what} changed\n  golden: {golden}\n  actual: {actual}");
}

fn text_diff(name: &str, what: &str, golden: &str, actual: &str) {
    if golden == actual {
        return;
    }
    let mut diff = String::new();
    let (g, a): (Vec<_>, Vec<_>) = (golden.lines().collect(), actual.lines().collect());
    for i in 0..g.len().max(a.len()) {
        let (gl, al) = (g.get(i).copied().unwrap_or(""), a.get(i).copied().unwrap_or(""));
        if gl != al {
            diff.push_str(&format!("  line {}: golden `{gl}`, actual `{al}`\n", i + 1));
        }
    }
    panic!("{name}: {what} changed\n{diff}");
}

#[test]
fn wire_011_every_example_instrument_keeps_its_address() {
    let golden = golden();
    for name in SURVEYS {
        let rec = record(name);
        let g = field(&golden[name], name, "instrument_address").as_text().expect("text");
        assert_same(name, "the instrument address", g, &address_text(&rec.instrument_address));
    }
}

#[test]
fn wire_185_every_example_keeps_its_salted_fingerprint() {
    let golden = golden();
    for name in SURVEYS {
        let rec = record(name);
        assert_same(name, "the salt", field(&golden[name], name, "salt").as_text().expect("text"), &rec.salt);
        assert_same(name, "the salted fingerprint", field(&golden[name], name, "instrument_fingerprint").as_text().expect("text"), &lower_hex(rec.fingerprint.as_bytes()));
    }
}

#[test]
fn ins_200_every_bound_layout_keeps_its_address() {
    let golden = golden();
    for name in SURVEYS {
        let rec = record(name);
        let layouts = field(&golden[name], name, "layouts").as_map().expect("a map");
        assert_eq!(layouts.keys().collect::<Vec<_>>(), rec.layouts.keys().collect::<Vec<_>>(), "{name}: the set of layout windows changed");
        for (window, (address, _)) in &rec.layouts {
            assert_same(&format!("{name}/{window}"), "the bound layout address", layouts[*window].as_text().expect("text"), &address_text(address));
        }
    }
}

#[test]
fn ins_200_expanded_documents_match_the_golden_text() {
    let _ = golden();
    for name in SURVEYS {
        let rec = record(name);
        let dir = golden_dir().join("expanded").join(name);
        let read = |file: &str| std::fs::read_to_string(dir.join(file)).unwrap_or_else(|e| panic!("{name}: {file}: {e}"));
        text_diff(name, "the expanded instrument", &read("instrument.json"), &rec.instrument_text);
        for (window, (_, text)) in &rec.layouts {
            text_diff(&format!("{name}/{window}"), "the expanded and bound layout", &read(&format!("layout-{window}.json")), text);
        }
    }
}
