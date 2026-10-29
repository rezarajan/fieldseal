//! The survey resolver: the folder shape, its rules, and the rosters beside it (INS-258).

use std::path::{Path, PathBuf};

use fieldseal_adapters_authoring::survey::{ResolveKind, RosterSet};
use fieldseal_adapters_authoring::{SurveyTree, Value};
use fieldseal_kernel::schema::SchemaErrorKind;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn load(name: &str) -> Result<fieldseal_adapters_authoring::LoadedSurvey, Vec<fieldseal_adapters_authoring::ResolveError>> {
    SurveyTree::open(&fixtures().join("surveys")).expect("the fixtures open").survey(name).expect("the folder exists").load()
}

fn kinds(e: &[fieldseal_adapters_authoring::ResolveError]) -> Vec<ResolveKind> {
    e.iter().map(|e| e.kind).collect()
}

#[test]
fn ins_258_a_valid_folder_loads() {
    let tree = SurveyTree::open(&fixtures().join("surveys")).expect("open");
    assert!(tree.names().iter().any(|n| n == "valid"));
    let loaded = load("valid").expect("loads");
    assert!(loaded.warnings.is_empty());
    assert!(loaded.translation_report.is_empty(), "{:?}", loaded.translation_report);
    assert_eq!(loaded.layouts.len(), 1);
    assert_eq!(loaded.layouts[0].0, "compact");
    let title = loaded.instrument.as_map().and_then(|m| m.get("spec")).and_then(Value::as_map).and_then(|s| s.get("title")).and_then(Value::as_map).expect("a localised title");
    assert_eq!(title.get("es").and_then(Value::as_text), Some("Agua en casa"));
}

#[test]
fn ins_258_folder_name_must_equal_survey_name() {
    let e = load("name-mismatch").expect_err("the names differ");
    assert_eq!(kinds(&e), [ResolveKind::NameMismatch]);
    assert_eq!((e[0].file.as_str(), e[0].pointer.as_str(), e[0].line), ("instrument.yaml", "/survey/name", 2));
}

#[test]
fn ins_258_layout_stem_must_equal_window() {
    let e = load("window-mismatch").expect_err("the stem differs");
    assert_eq!(kinds(&e), [ResolveKind::WindowMismatch]);
    assert_eq!((e[0].file.as_str(), e[0].pointer.as_str()), ("layouts/expanded.yaml", "/layout/window"));
    assert!(e[0].line > 0 && e[0].column > 0);
}

#[test]
fn ins_258_titled_steps_and_cards_need_unique_ids() {
    let e = load("missing-layout-id").expect_err("no id");
    assert_eq!(kinds(&e), [ResolveKind::MissingLayoutId]);
    assert_eq!((e[0].pointer.as_str(), e[0].line), ("/steps/0", 3));
    let e = load("duplicate-layout-id").expect_err("a repeated id");
    assert_eq!(kinds(&e), [ResolveKind::DuplicateLayoutId]);
    assert_eq!(e[0].pointer, "/steps/0/contents/0/card/id");
}

#[test]
fn ins_258_unknown_files_are_warnings_not_ignored() {
    let loaded = load("stray-file").expect("a stray file does not stop the load");
    assert_eq!(loaded.warnings.len(), 1);
    assert_eq!((loaded.warnings[0].kind, loaded.warnings[0].file.as_str()), (ResolveKind::StrayFile, "instrument.yaml.bak"));
    let strict = loaded.strict().expect_err("strict makes the warning an error");
    assert_eq!(kinds(&strict), [ResolveKind::StrayFile]);
}

#[test]
fn ins_258_a_survey_that_fails_to_load_returns_its_error_with_position() {
    let e = load("unknown-key").expect_err("a misspelled key");
    assert_eq!(kinds(&e), [ResolveKind::Schema(SchemaErrorKind::UnknownField)]);
    let unknown = e.iter().find(|e| e.pointer == "/titel").expect("the misspelled key");
    assert_eq!((unknown.file.as_str(), unknown.line, unknown.column), ("instrument.yaml", 2, 1));
    let tree = SurveyTree::open(&fixtures().join("surveys")).expect("open");
    assert_eq!(tree.survey("no-such-survey").expect_err("no folder").kind, ResolveKind::NoInstrument);
    let unreadable = SurveyTree::open(&fixtures().join("no-such-root")).expect_err("no root");
    assert_eq!((unreadable.kind, unreadable.line, unreadable.column), (ResolveKind::Io, 0, 0));
}

#[test]
fn ins_258_rosters_are_listed_by_cohort_and_version() {
    let set = RosterSet::open(&fixtures().join("rosters")).expect("open");
    assert_eq!(set.cohorts(), ["town-b", "village-a"]);
    let latest = set.latest("village-a").expect("a cohort");
    assert_eq!((latest.version, latest.path.file_name().and_then(|n| n.to_str())), (2, Some("second.yaml")));
    assert_eq!(set.latest("town-b").map(|f| f.version), Some(1));
    assert!(set.latest("nowhere").is_none());
}

#[test]
fn ins_258_a_roster_in_a_subdirectory_is_not_listed() {
    let set = RosterSet::open(&fixtures().join("rosters")).expect("open");
    assert!(set.files().iter().all(|f| f.version != 3));
    assert_eq!(set.files().len(), 3);
}
