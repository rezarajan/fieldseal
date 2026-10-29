//! The authoring commands: `new survey`, `survey check|list` and `schema export|check`
//! (CLI-041, CLI-044 to CLI-046).

mod common;

use common::{Sandbox, field, finding_ids, repo, text};
use fieldseal_kernel::Value;

fn findings(doc: &Value) -> Vec<&std::collections::BTreeMap<String, Value>> {
    field(doc, "findings").as_array().unwrap().iter().map(|f| f.as_map().unwrap()).collect()
}

fn severities(doc: &Value, severity: &str) -> usize {
    findings(doc).iter().filter(|f| f["severity"].as_text() == Some(severity)).count()
}

#[test]
fn cli_044_a_scaffold_passes_survey_check_with_no_errors() {
    let sb = Sandbox::new("scaffold-passes");
    sb.ok(&["new", "survey", "my-survey", "--lang", "es"], &[]);
    let (code, doc) = sb.json(&["survey", "check", "surveys/my-survey", "--roster", "rosters/my-survey-cohort.yaml"]);
    assert_eq!(code, 0, "{doc:?}");
    assert_eq!(severities(&doc, "error"), 0);
    // The catalogue is a to-do list: every English text is listed as missing, and the only other
    // finding is advice.
    assert_eq!(severities(&doc, "warning"), finding_ids(&doc).iter().filter(|id| *id == "INS-260").count(), "{doc:?}");
    // A scaffold with no translation has nothing to warn about, even under --strict.
    sb.ok(&["new", "survey", "plain"], &[]);
    let strict = sb.ok(&["survey", "check", "surveys/plain", "--strict", "--roster", "rosters/plain-cohort.yaml"], &[]);
    assert_eq!(severities(&strict, "error") + severities(&strict, "warning"), 0, "{strict:?}");
    for file in ["surveys/plain/instrument.yaml", "surveys/plain/layouts/compact.yaml", "surveys/plain/README.md", "surveys/.fieldseal/survey.schema.json", "surveys/.fieldseal/layout.schema.json", "rosters/plain-cohort.yaml"] {
        assert!(sb.dir.join(file).is_file(), "{file}");
    }
    assert!(!sb.dir.join("surveys/plain/rosters").exists(), "the roster is outside the publishable folder");
}

#[test]
fn cli_044_a_scaffold_refuses_to_overwrite() {
    let sb = Sandbox::new("scaffold-overwrite");
    sb.ok(&["new", "survey", "my-survey"], &[]);
    let edited = sb.write("surveys/my-survey/instrument.yaml", "edited");
    let (code, _) = sb.json(&["new", "survey", "my-survey"]);
    assert_eq!(code, 1);
    assert_eq!(std::fs::read_to_string(edited).unwrap(), "edited");
}

#[test]
fn cli_044_scaffold_pins_answer_codes() {
    let sb = Sandbox::new("scaffold-codes");
    sb.ok(&["new", "survey", "my-survey"], &[]);
    let instrument = std::fs::read_to_string(sb.dir.join("surveys/my-survey/instrument.yaml")).unwrap();
    let items: Vec<&str> = instrument.lines().filter(|l| l.trim_start().starts_with("- {label:")).collect();
    assert!(!items.is_empty());
    assert!(items.iter().all(|l| l.contains("code:")), "every list item carries an explicit code: {items:?}");
}

#[test]
fn cli_044_the_scaffold_headers_point_at_the_exported_survey_and_layout_schemas() {
    let sb = Sandbox::new("scaffold-headers");
    sb.ok(&["new", "survey", "my-survey"], &[]);
    for (file, kind, header) in [
        ("surveys/my-survey/instrument.yaml", "survey", "# yaml-language-server: $schema=../.fieldseal/survey.schema.json"),
        ("surveys/my-survey/layouts/compact.yaml", "layout", "# yaml-language-server: $schema=../../.fieldseal/layout.schema.json"),
    ] {
        let source = std::fs::read_to_string(sb.dir.join(file)).unwrap();
        assert_eq!(source.lines().next(), Some(header));
        let exported = sb.run(&["schema", "export", "--kind", kind, "--out", &sb.path(&format!("export-{kind}.json"))]);
        assert!(exported.status.success());
        let local = std::fs::read(sb.dir.join(format!("surveys/.fieldseal/{kind}.schema.json"))).unwrap();
        assert_eq!(local, std::fs::read(sb.dir.join(format!("export-{kind}.json"))).unwrap(), "the scaffold's copy is `schema export --out`");
    }
}

#[test]
fn cli_045_survey_check_reports_file_line_and_column() {
    let sb = Sandbox::new("check-position");
    sb.ok(&["new", "survey", "my-survey"], &[]);
    let path = sb.dir.join("surveys/my-survey/instrument.yaml");
    let source = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, source.replace("administration: interviewer", "administration: interviewer\nadministrtion: oops")).unwrap();
    let (code, doc) = sb.json(&["survey", "check", "surveys/my-survey"]);
    assert_eq!(code, 1, "{doc:?}");
    let f = findings(&doc).into_iter().find(|f| f["severity"].as_text() == Some("error")).expect("an error");
    let at = f["where"].as_map().unwrap();
    assert_eq!(at["file"].as_text(), Some("surveys/my-survey/instrument.yaml"));
    let line = source.lines().position(|l| l.starts_with("administration:")).unwrap() as i128 + 2;
    assert_eq!((at["line"].as_int(), at["column"].as_int()), (Some(line), Some(1)), "{f:?}");
    let o = sb.run(&["survey", "check", "surveys/my-survey"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains(&format!("surveys/my-survey/instrument.yaml:{line}:1:")));
}

fn roster_with(sb: &Sandbox, fields: &[&str]) -> String {
    let subject = |n: u32, f: &str| format!("  - subject: s-000{n}\n    display: Subject {n}\n    fields: {{ {f} }}\n");
    sb.write("roster.yaml", &format!("cohort: c\nversion: 1\nsubjects:\n{}{}", subject(1, &fields.join(", ")), subject(2, &fields[..fields.len().min(1)].join(", "))))
}

#[test]
fn cli_045_survey_check_roster_flags_a_missing_field_as_an_error() {
    let sb = Sandbox::new("check-roster-missing");
    let (code, doc) = sb.json(&["survey", "check", &repo().join("examples/surveys/household-water-access").to_string_lossy(), "--roster", &roster_with(&sb, &["village_code: V-1"])]);
    assert_eq!(code, 1, "{doc:?}");
    let missing = findings(&doc).into_iter().filter(|f| f["id"].as_text() == Some("DIS-013") && f["severity"].as_text() == Some("error")).collect::<Vec<_>>();
    assert_eq!(missing.len(), 2, "{doc:?}");
    assert!(missing.iter().all(|f| f["message"].as_text().unwrap().contains("head_name")));
    assert!(missing[1]["message"].as_text().unwrap().contains("subject 2"), "names the ordinal: {missing:?}");
    assert!(!missing.iter().any(|f| f["message"].as_text().unwrap().contains("s-000")), "not the subject id");
}

#[test]
fn cli_045_survey_check_roster_notes_an_unused_field() {
    let sb = Sandbox::new("check-roster-unused");
    let (code, doc) = sb.json(&["survey", "check", &repo().join("examples/surveys/household-water-access").to_string_lossy(), "--roster", &roster_with(&sb, &["head_name: A", "village_code: V-1"])]);
    assert_eq!(code, 0, "{doc:?}");
    let note = findings(&doc).into_iter().find(|f| f["id"].as_text() == Some("DIS-013")).expect("a note");
    assert_eq!(note["severity"].as_text(), Some("advice"));
    assert!(note["message"].as_text().unwrap().contains("village_code"));
}

#[test]
fn cli_045_strict_turns_warnings_into_errors() {
    let sb = Sandbox::new("check-strict");
    sb.ok(&["new", "survey", "my-survey", "--lang", "es"], &[]);
    let lax = sb.json(&["survey", "check", "surveys/my-survey"]);
    assert_eq!(lax.0, 0);
    let (code, doc) = sb.json(&["survey", "check", "surveys/my-survey", "--strict"]);
    assert_eq!(code, 1, "{doc:?}");
    assert_eq!(severities(&doc, "warning"), 0);
    assert!(severities(&doc, "error") > 0);
    // The shipped examples pass --strict (their expanded layouts' lints stay warnings).
    for (survey, roster) in [("household-water-access", "village-a"), ("school-meals-baseline", "cohort-a")] {
        let r = repo();
        let o = sb.run(&["survey", "check", &r.join("examples/surveys").join(survey).to_string_lossy(), "--roster", &r.join("examples/rosters").join(format!("{roster}.yaml")).to_string_lossy(), "--strict"]);
        assert!(o.status.success(), "{survey}: {}", String::from_utf8_lossy(&o.stdout));
    }
}

#[test]
fn ins_210_too_many_questions_on_a_screen_is_an_error_on_a_compact_layout_and_a_warning_otherwise() {
    let sb = Sandbox::new("check-ins-210");
    let source = repo().join("examples/surveys/school-meals-baseline");
    let copy = sb.dir.join("surveys/school-meals-baseline");
    std::fs::create_dir_all(sb.dir.join("surveys")).unwrap();
    assert!(std::process::Command::new("cp").arg("-r").arg(&source).arg(&copy).status().unwrap().success());
    let ins_210 = |doc: &Value, severity: &str| findings(doc).iter().filter(|f| f["id"].as_text() == Some("INS-210") && f["severity"].as_text() == Some(severity)).count();

    // The expanded layout holds up to 24 questions on a screen: warnings, and the check passes.
    let (code, doc) = sb.json(&["survey", "check", "surveys/school-meals-baseline"]);
    assert_eq!((code, ins_210(&doc, "error")), (0, 0), "{doc:?}");
    assert!(ins_210(&doc, "warning") > 0);

    // The same layout declared for a compact window is an error, so the check fails. (The
    // compact layout goes, and the expanded one's titles are translated as compact ones.)
    std::fs::remove_file(copy.join("layouts/compact.yaml")).unwrap();
    let layout = copy.join("layouts/expanded.yaml");
    let text = std::fs::read_to_string(&layout).unwrap().replace("window: expanded", "window: compact");
    std::fs::write(copy.join("layouts/compact.yaml"), text).unwrap();
    std::fs::remove_file(&layout).unwrap();
    let po = copy.join("i18n/es.po");
    let kept: Vec<String> = std::fs::read_to_string(&po).unwrap().split("\n\n").filter(|b| !b.contains("\"layout/compact/")).map(|b| b.replace("layout/expanded/", "layout/compact/")).collect();
    std::fs::write(&po, kept.join("\n\n")).unwrap();
    let (code, doc) = sb.json(&["survey", "check", "surveys/school-meals-baseline"]);
    assert_eq!(code, 1, "{doc:?}");
    assert!(ins_210(&doc, "error") > 0, "{doc:?}");
}

#[test]
fn cli_045_json_output_lists_findings() {
    let sb = Sandbox::new("check-json");
    sb.ok(&["new", "survey", "my-survey", "--lang", "es"], &[]);
    let (_, doc) = sb.json(&["survey", "check", "surveys/my-survey"]);
    assert_eq!(text(&doc, "command"), "survey check");
    let all = findings(&doc);
    assert!(!all.is_empty());
    for f in all {
        assert!(f.contains_key("id") && f.contains_key("severity") && f.contains_key("message"));
        assert!(f["where"].as_map().unwrap().contains_key("file"));
    }
}

#[test]
fn cli_046_survey_list_names_every_example() {
    let sb = Sandbox::new("list");
    let doc = sb.ok(&["survey", "list", "--root", &repo().join("examples/surveys").to_string_lossy()], &[]);
    let surveys = field(&doc, "surveys").as_array().unwrap();
    let names: Vec<&str> = surveys.iter().map(|s| s.as_map().unwrap()["name"].as_text().unwrap()).collect();
    assert_eq!(names, ["household-water-access", "school-meals-baseline"]);
    let water = surveys[0].as_map().unwrap();
    assert_eq!(water["languages"].as_array().unwrap().len(), 2);
    assert_eq!(water["windows"].as_array().unwrap().iter().filter_map(Value::as_text).collect::<Vec<_>>(), ["compact"]);
    assert!(water["version"].as_text().is_some());
}

#[test]
fn cli_041_schema_export_is_deterministic_and_addressed() {
    let sb = Sandbox::new("schema-export");
    for kind in ["survey", "layout"] {
        let first = sb.run(&["schema", "export", "--kind", kind]);
        let second = sb.run(&["schema", "export", "--kind", kind]);
        assert!(first.status.success());
        assert_eq!(first.stdout, second.stdout, "{kind}: identical bytes");
        let out = String::from_utf8(first.stdout).unwrap();
        let (schema, address) = out.rsplit_once("address: ").expect("an address line");
        assert!(schema.ends_with("}\n"), "exactly one final newline");
        // The address is the SHA-256 of the schema text; `--out` writes those same bytes.
        let file = sb.path(&format!("{kind}.json"));
        let written = sb.json(&["schema", "export", "--kind", kind, "--out", &file]).1;
        assert_eq!(std::fs::read_to_string(&file).unwrap(), schema);
        assert_eq!(text(&written, "address"), address.trim());
        let hash = std::process::Command::new("sha256sum").arg(&file).output();
        if let Ok(h) = hash {
            assert_eq!(format!("sha256:{}", String::from_utf8_lossy(&h.stdout).split_whitespace().next().unwrap()), address.trim());
        }
        let both = sb.ok(&["schema", "export", "--kind", kind], &[]);
        assert_eq!(text(&both, "address"), address.trim());
        assert!(field(&both, "schema").as_map().is_some());
    }
    let (code, _) = sb.json(&["schema", "export", "--kind", "survey", "--version", "9.9.9"]);
    assert_eq!(code, 2, "a version the schema does not have is a usage error");
    assert_eq!(sb.json(&["schema", "export", "--kind", "survey", "--version", "1.0.0"]).0, 0);
    assert_eq!(sb.json(&["schema", "export", "--kind", "policy"]).0, 2);
}

#[test]
fn cli_041_schema_check_validates_a_source_file_against_its_schema() {
    let sb = Sandbox::new("schema-check");
    let ok = sb.ok(&["schema", "check", &repo().join("examples/surveys/household-water-access/instrument.yaml").to_string_lossy()], &[]);
    assert_eq!(text(&ok, "kind"), "survey");
    let bad = sb.write("bad.yaml", "survey: {name: x, version: 0.1.0}\nsections: []\nbogus: 1\n");
    let (code, doc) = sb.json(&["schema", "check", &bad]);
    assert_eq!(code, 1, "{doc:?}");
    assert!(findings(&doc).iter().any(|f| f["where"].as_map().unwrap().contains_key("line")));
}

#[test]
fn ins_260_a_stale_translation_is_listed_with_old_and_new_text() {
    let sb = Sandbox::new("stale");
    sb.ok(&["new", "survey", "my-survey", "--lang", "es"], &[]);
    let po = sb.dir.join("surveys/my-survey/i18n/es.po");
    let translated = std::fs::read_to_string(&po).unwrap().replacen("msgid \"My survey\"\nmsgstr \"\"", "msgid \"My survey\"\nmsgstr \"Mi encuesta\"", 1);
    std::fs::write(&po, translated).unwrap();
    let path = sb.dir.join("surveys/my-survey/instrument.yaml");
    let source = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, source.replace("title: My survey", "title: My first survey")).unwrap();
    let (_, doc) = sb.json(&["survey", "check", "surveys/my-survey"]);
    let stale = findings(&doc).into_iter().find(|f| f["message"].as_text().unwrap().contains("was written against")).expect("a stale entry");
    let message = stale["message"].as_text().unwrap();
    assert!(message.contains("My survey") && message.contains("My first survey"), "{message}");
    assert_eq!(stale["id"].as_text(), Some("INS-260"));
    assert_eq!(stale["where"].as_map().unwrap()["file"].as_text(), Some("surveys/my-survey/i18n/es.po"));
}
