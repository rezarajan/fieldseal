//! The translation report: missing, orphaned, stale and absent catalogues (INS-259 to INS-261).

use std::path::{Path, PathBuf};

use fieldseal_adapters_authoring::compact::{self, expand_with_entries};
use fieldseal_adapters_authoring::po::EntryCatalogues;
use fieldseal_adapters_authoring::survey::{Finding, FindingKind, ResolveKind};
use fieldseal_adapters_authoring::{Format, SurveyTree, Value, decode_raw};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/surveys")
}

fn report(name: &str) -> Vec<Finding> {
    SurveyTree::open(&fixtures()).expect("open").survey(name).expect("folder").load().expect("loads").translation_report
}

fn of_kind(findings: &[Finding], kind: FindingKind) -> Vec<&Finding> {
    findings.iter().filter(|f| f.kind == kind).collect()
}

#[test]
fn ins_260_missing_entry_is_reported_with_the_source_line() {
    let dir = fixtures().join("valid");
    let text = std::fs::read_to_string(dir.join("i18n/es.po")).expect("po").replace("msgctxt \"instrument/water\"\nmsgid \"Water\"\nmsgstr \"Agua\"\n\n", "");
    let scratch = scratch("missing-entry", &dir, &text);
    let f = SurveyTree::open(scratch.parent().expect("parent")).expect("open").survey("valid").expect("folder").load().expect("loads").translation_report;
    std::fs::remove_dir_all(scratch.parent().expect("parent")).expect("clean up");
    let missing = of_kind(&f, FindingKind::Missing);
    assert_eq!(missing.len(), 1, "{f:?}");
    assert_eq!((missing[0].file.as_str(), missing[0].line, missing[0].msgctxt.as_str(), missing[0].new_text.as_deref()), ("instrument.yaml", 14, "instrument/water", Some("Water")));
}

#[test]
fn ins_260_empty_msgstr_counts_as_missing() {
    let dir = fixtures().join("valid");
    let text = std::fs::read_to_string(dir.join("i18n/es.po")).expect("po").replace("msgstr \"Agua en casa\"", "msgstr \"\"");
    let scratch = scratch("empty-msgstr", &dir, &text);
    let f = SurveyTree::open(scratch.parent().expect("parent")).expect("open").survey("valid").expect("folder").load().expect("loads");
    std::fs::remove_dir_all(scratch.parent().expect("parent")).expect("clean up");
    let missing = of_kind(&f.translation_report, FindingKind::Missing);
    assert_eq!((missing.len(), missing[0].file.as_str(), missing[0].line), (1, "i18n/es.po", 3));
    let title = f.instrument.as_map().and_then(|m| m.get("spec")).and_then(Value::as_map).and_then(|s| s.get("title")).and_then(Value::as_map).expect("title");
    assert!(!title.contains_key("es"), "an empty translation is not applied");
}

#[test]
fn ins_260_a_catalogue_with_every_msgstr_empty_adds_no_language() {
    let dir = fixtures().join("valid");
    let text: String = std::fs::read_to_string(dir.join("i18n/es.po")).expect("po").lines().map(|l| if l.starts_with("msgstr ") { "msgstr \"\"".to_owned() } else { l.to_owned() }).collect::<Vec<_>>().join("\n");
    let scratch = scratch("all-empty", &dir, &text);
    let f = SurveyTree::open(scratch.parent().expect("parent")).expect("open").survey("valid").expect("folder").load().expect("loads");
    std::fs::remove_dir_all(scratch.parent().expect("parent")).expect("clean up");
    let languages = f.instrument.as_map().and_then(|m| m.get("spec")).and_then(Value::as_map).and_then(|s| s.get("languages")).and_then(Value::as_array).expect("languages");
    assert_eq!(languages, [Value::Text("en".to_owned())], "a stub is a to-do list, not a language");
    assert!(!of_kind(&f.translation_report, FindingKind::Missing).is_empty());
    assert!(of_kind(&f.translation_report, FindingKind::NoCatalogue).is_empty());
}

#[test]
fn ins_260_orphaned_entry_after_a_deleted_question() {
    let f = report("stale-and-orphaned");
    let orphans = of_kind(&f, FindingKind::Orphaned);
    assert_eq!(orphans.len(), 1, "{f:?}");
    assert_eq!((orphans[0].msgctxt.as_str(), orphans[0].file.as_str(), orphans[0].line), ("instrument/lists.sources.rain", "i18n/es.po", 15));
}

#[test]
fn ins_260_stale_entry_reports_old_msgid_and_new_text() {
    let f = report("stale-and-orphaned");
    let stale = of_kind(&f, FindingKind::Stale);
    assert_eq!(stale.len(), 1, "{f:?}");
    assert_eq!((stale[0].old_msgid.as_deref(), stale[0].new_text.as_deref()), (Some("Where does the water come from?"), Some("Where does the water come from now?")));
    assert_eq!((stale[0].file.as_str(), stale[0].line, stale[0].msgctxt.as_str()), ("i18n/es.po", 11, "instrument/water.source"));
}

#[test]
fn ins_260_stale_entry_is_not_applied() {
    let loaded = SurveyTree::open(&fixtures()).expect("open").survey("stale-and-orphaned").expect("folder").load().expect("loads");
    let json = format!("{:?}", loaded.instrument);
    assert!(json.contains("Where does the water come from now?"));
    assert!(!json.contains("De dónde viene el agua?"), "the stale translation must not reach the document");
    assert!(json.contains("Agua en casa"), "current entries still apply");
}

#[test]
fn ins_260_a_declared_language_without_a_catalogue_warns() {
    let f = report("no-catalogue");
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!((f[0].kind, f[0].language.as_str(), f[0].file.as_str()), (FindingKind::NoCatalogue, "es", "i18n/es.po"));
}

#[test]
fn ins_259_one_catalogue_serves_instrument_and_layouts() {
    let loaded = SurveyTree::open(&fixtures()).expect("open").survey("valid").expect("folder").load().expect("loads");
    // No orphan: the layout entries are not orphans of the instrument pass.
    assert!(loaded.translation_report.is_empty(), "{:?}", loaded.translation_report);
    let json = format!("{:?}", loaded.layouts[0].1);
    assert!(json.contains("El hogar") && json.contains("Quién vive aquí"), "{json}");
}

#[test]
fn ins_261_layout_ids_never_reach_the_expanded_document() {
    let loaded = SurveyTree::open(&fixtures()).expect("open").survey("valid").expect("folder").load().expect("loads");
    fn has_id(v: &Value) -> bool {
        match v {
            Value::Map(m) => m.contains_key("id") || m.values().any(has_id),
            Value::Array(a) => a.iter().any(has_id),
            _ => false,
        }
    }
    assert!(!has_id(&loaded.layouts[0].1));
    let raw = decode_raw(&std::fs::read(fixtures().join("valid/layouts/compact.yaml")).expect("file"), Format::Yaml).expect("decodes");
    let with = expand_with_entries(raw.clone(), &EntryCatalogues::new()).expect("expands");
    let mut without = raw;
    strip_ids(&mut without);
    assert_eq!(with, compact::expand(without).expect("expands"), "an id changes nothing but the key of the title");
}

fn strip_ids(v: &mut Value) {
    match v {
        Value::Map(m) => {
            m.remove("id");
            m.values_mut().for_each(strip_ids);
        }
        Value::Array(a) => a.iter_mut().for_each(strip_ids),
        _ => {}
    }
}

/// The example catalogues must have no stale, orphaned or missing entry, so treating a stale entry
/// as missing cannot change a signed address.
#[test]
fn ins_260_the_example_catalogues_have_no_stale_entries() {
    let tree = SurveyTree::open(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples/surveys")).expect("open");
    assert_eq!(tree.names().len(), 2, "two example surveys");
    for name in tree.names() {
        let loaded = tree.survey(name).expect("folder").load().unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(loaded.translation_report.is_empty(), "{name}: {:?}", loaded.translation_report);
    }
}

#[test]
fn ins_260_strict_turns_warnings_into_errors() {
    let loaded = SurveyTree::open(&fixtures()).expect("open").survey("stale-and-orphaned").expect("folder").load().expect("loads");
    assert!(!loaded.translation_report.is_empty());
    let errors = loaded.strict().expect_err("findings are errors under strict");
    let kinds: Vec<ResolveKind> = errors.iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&ResolveKind::Translation(FindingKind::Stale)) && kinds.contains(&ResolveKind::Translation(FindingKind::Orphaned)), "{kinds:?}");
    let clean = SurveyTree::open(&fixtures()).expect("open").survey("valid").expect("folder").load().expect("loads");
    assert!(clean.strict().is_ok());
}

/// Copies the `valid` survey to a scratch folder with `es.po` replaced by `po`.
fn scratch(case: &str, from: &Path, po: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("fieldseal-translation-report-{}-{case}", std::process::id()));
    let dir = root.join("valid");
    std::fs::create_dir_all(dir.join("layouts")).expect("mkdir");
    std::fs::create_dir_all(dir.join("i18n")).expect("mkdir");
    for f in ["instrument.yaml", "layouts/compact.yaml"] {
        std::fs::copy(from.join(f), dir.join(f)).expect("copy");
    }
    std::fs::write(dir.join("i18n/es.po"), po).expect("write");
    dir
}
