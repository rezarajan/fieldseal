//! `roster check|diff|list` (CLI-050, CLI-052, CLI-053, DIS-081).

mod common;

use std::path::Path;

use common::{Sandbox, field, finding_ids, repo};
use fieldseal_adapters_authoring::decode_path;
use fieldseal_adapters_file::roster_store::RosterStore;
use fieldseal_distribution::domain::{ConsentState, Roster, RosterEntry};
use fieldseal_kernel::Value;
use fieldseal_kernel::id::{CohortId, Generation, SubjectId};

/// What no command may print without `--reveal`: the example rosters' ids, names and values.
const SECRETS: &[&str] = &["hh-000", "Household", "Amina", "Tomas", "Lucia", "Nadia", "Omar", "V-17"];

fn example(name: &str) -> String {
    repo().join("examples").join(name).to_string_lossy().into_owned()
}

fn survey(name: &str) -> String {
    example(&format!("surveys/{name}"))
}

/// The roster in a YAML file as the factory would hold it (generation 1).
fn roster(path: &str) -> Roster {
    let doc = decode_path(Path::new(path)).expect("the example decodes");
    let m = doc.as_map().expect("a map");
    let entries = m["subjects"]
        .as_array()
        .expect("subjects")
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let s = s.as_map().expect("a subject");
            RosterEntry {
                ordinal: i as u32 + 1,
                subject: SubjectId::new(s["subject"].as_text().unwrap()).unwrap(),
                display: s["display"].as_text().unwrap().to_owned(),
                attributes: s["fields"].as_map().cloned().unwrap_or_default(),
                consent: ConsentState::parse(s["consent"].as_text().unwrap_or("unknown")).unwrap(),
                prior_status: s.get("prior_status").and_then(Value::as_text).map(str::to_owned),
            }
        })
        .collect();
    Roster {
        cohort: CohortId::new(m["cohort"].as_text().unwrap()).unwrap(),
        version: u64::try_from(m["version"].as_int().unwrap()).unwrap(),
        generation: Generation(1),
        entries,
    }
}

/// A store holding `village-a@3` and `cohort-a@1`, issued through the store as the factory does.
fn store(sb: &Sandbox) -> String {
    let dir = sb.path("store");
    let store = RosterStore::open(&dir).expect("store opens");
    for name in ["rosters/village-a.yaml", "rosters/cohort-a.yaml"] {
        store.issue(&roster(&example(name))).expect("issues");
    }
    dir
}

fn output(sb: &Sandbox, args: &[&str]) -> (i32, String, String) {
    let o = sb.run(args);
    (o.status.code().unwrap(), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn assert_no_secrets(what: &str, text: &str) {
    for s in SECRETS {
        assert!(!text.contains(s), "{what} printed `{s}`:\n{text}");
    }
}

fn files_under(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(files_under(&p));
        } else {
            out.push((p.to_string_lossy().into_owned(), std::fs::read(&p).unwrap()));
        }
    }
    out.sort();
    out
}

#[test]
fn cli_050_check_fails_on_a_field_the_instrument_reads_and_a_subject_lacks() {
    let sb = Sandbox::new("roster-check-lacks");
    let ok = sb.ok(&["roster", "check", &example("rosters/village-a.yaml"), "--instrument", &survey("household-water-access")], &[]);
    assert_eq!(field(&ok, "subjects").as_int(), Some(3));
    let lacking = sb.write("lacking.yaml", "cohort: village-a\nversion: 1\nsubjects:\n  - {subject: hh-0001, display: One, fields: {head_name: A}}\n  - {subject: hh-0002, display: Two, fields: {village_code: V-1}}\n");
    let (code, doc) = sb.json(&["roster", "check", &lacking, "--instrument", &survey("household-water-access")]);
    assert_eq!(code, 1, "{doc:?}");
    let errors: Vec<_> = field(&doc, "findings").as_array().unwrap().iter().map(|f| f.as_map().unwrap()).filter(|f| f["severity"].as_text() == Some("error")).collect();
    assert_eq!(errors.len(), 1, "{doc:?}");
    let message = errors[0]["message"].as_text().unwrap();
    assert!(message.contains("head_name") && message.contains("subject 2"), "{message}");
    assert!(!message.contains("hh-0002"), "the finding names the ordinal, not the ID: {message}");
    // The closed schema is checked first, and every finding is reported.
    let bad = sb.write("bad.yaml", "cohort: village-a\nversion: 0\ngeneration: 1\nsubjects:\n  - {subject: hh-0001, display: One}\n  - {subject: hh-0001, display: Two, consent: maybe}\n");
    let (code, doc) = sb.json(&["roster", "check", &bad, "--instrument", &survey("household-water-access")]);
    assert_eq!(code, 1);
    assert_eq!(finding_ids(&doc), ["DIS-063"; 4]);
}

#[test]
fn cli_050_check_requires_a_survey_folder() {
    let sb = Sandbox::new("roster-check-usage");
    let file = example("rosters/village-a.yaml");
    let (code, _, err) = output(&sb, &["roster", "check", &file]);
    assert_eq!(code, 2, "{err}");
    let (code, _, err) = output(&sb, &["roster", "check", &file, "--instrument", &example("rosters/cohort-a.yaml")]);
    assert_eq!(code, 2, "{err}");
    let (code, _, _) = output(&sb, &["roster", "check", &file, "--instrument", "sha256:abc"]);
    assert_eq!(code, 2);
}

#[test]
fn cli_050_check_writes_nothing() {
    let sb = Sandbox::new("roster-check-writes-nothing");
    let file = sb.write("roster.yaml", &std::fs::read_to_string(example("rosters/village-a.yaml")).unwrap());
    let before = files_under(&sb.dir);
    sb.ok(&["roster", "check", &file, "--instrument", &survey("household-water-access")], &[]);
    sb.json(&["roster", "check", &sb.write("lacking.yaml", "cohort: c\nversion: 1\nsubjects: []\n"), "--instrument", &survey("household-water-access")]);
    let after = files_under(&sb.dir);
    let expected: Vec<_> = before.iter().cloned().chain([(sb.path("lacking.yaml"), std::fs::read(sb.path("lacking.yaml")).unwrap())]).collect();
    let mut expected = expected;
    expected.sort();
    assert_eq!(after, expected);
}

#[test]
fn cli_050_check_notes_a_field_no_instrument_reads() {
    let sb = Sandbox::new("roster-check-notes");
    let doc = sb.ok(&["roster", "check", &example("rosters/village-a.yaml"), "--instrument", &survey("household-water-access")], &[]);
    let notes: Vec<_> = field(&doc, "findings").as_array().unwrap().iter().map(|f| f.as_map().unwrap()).collect();
    assert_eq!(notes.len(), 1, "{doc:?}");
    assert_eq!(notes[0]["severity"].as_text(), Some("advice"));
    assert!(notes[0]["message"].as_text().unwrap().contains("village_code"));
    // A field another instrument reads is not a note.
    let both = sb.ok(&["roster", "check", &example("rosters/cohort-a.yaml"), "--instrument", &survey("school-meals-baseline"), "--instrument", &survey("school-meals-baseline")], &[]);
    assert_eq!(field(&both, "findings").as_array().unwrap().len(), 1, "{both:?}");
}

#[test]
fn cli_052_diff_reads_a_stored_version_named_cohort_at_version() {
    let sb = Sandbox::new("roster-diff-stored");
    let store = store(&sb);
    let next = example("rosters/next/village-a.yaml");
    let doc = sb.ok(&["roster", "diff", "village-a@3", &next, "--store", &store], &[]);
    assert_eq!(field(&doc, "added").as_int(), Some(2));
    assert_eq!(field(&doc, "removed").as_int(), Some(0));
    assert_eq!(field(&doc, "kept").as_int(), Some(3));
    assert_eq!(field(&doc, "changedFields").as_array().unwrap(), &[Value::Text("head_name".into())]);
    assert_eq!(field(&doc, "consentChanges").as_array().unwrap().len(), 1);
    // The same counts from the file itself.
    let from_file = sb.ok(&["roster", "diff", &example("rosters/village-a.yaml"), &next], &[]);
    assert_eq!(field(&from_file, "added"), field(&doc, "added"));
    // A version that was never issued, a store that is not there, and a stored name without a store.
    let (code, _, _) = output(&sb, &["roster", "diff", "village-a@9", &next, "--store", &store]);
    assert_eq!(code, 4);
    let (code, _, _) = output(&sb, &["roster", "diff", "village-a@3", &next, "--store", &sb.path("nowhere")]);
    assert_eq!(code, 4);
    assert!(!sb.dir.join("nowhere").exists(), "diff does not create a store");
    let (code, _, _) = output(&sb, &["roster", "diff", "village-a@3", &next]);
    assert_eq!(code, 2);
    let (code, _, _) = output(&sb, &["roster", "diff", "village-a@3", &example("rosters/next/cohort-a.yaml"), "--store", &store]);
    assert_eq!(code, 2, "rosters of different cohorts");
}

#[test]
fn cli_052_diff_prints_counts_only() {
    let sb = Sandbox::new("roster-diff-counts");
    let store = store(&sb);
    let next = example("rosters/next/village-a.yaml");
    for args in [vec!["roster", "diff", "village-a@3", &next, "--store", &store], vec!["roster", "diff", "village-a@3", &next, "--store", &store, "--json"]] {
        let (code, out, err) = output(&sb, &args);
        assert_eq!(code, 0);
        assert_no_secrets("roster diff", &out);
        assert_no_secrets("roster diff", &err);
        assert!(!err.contains("--reveal"), "no warning without --reveal: {err}");
    }
}

#[test]
fn cli_052_diff_with_reveal_warns_on_stderr() {
    let sb = Sandbox::new("roster-diff-reveal");
    let store = store(&sb);
    let (code, out, err) = output(&sb, &["roster", "diff", "village-a@3", &example("rosters/next/village-a.yaml"), "--store", &store, "--reveal"]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("--reveal") && err.contains("warning"), "{err}");
    assert!(out.contains("hh-0004") && out.contains("hh-0001: unknown -> granted") && out.contains("Tomas") && out.contains("Tomasz"), "{out}");
    assert_no_secrets("the warning", &err);
}

#[test]
fn cli_053_list_prints_no_subject_ids() {
    let sb = Sandbox::new("roster-list");
    let store = store(&sb);
    let (code, out, err) = output(&sb, &["roster", "list", "--store", &store]);
    assert_eq!(code, 0, "{err}");
    assert_no_secrets("roster list", &out);
    assert_no_secrets("roster list", &err);
    let village = out.lines().find(|l| l.starts_with("village-a@3")).expect("village-a@3 is listed");
    assert!(village.contains("sha256:") && village.contains("3 subjects") && village.contains("granted 1, refused 1, unknown 1"), "{village}");
    let doc = sb.ok(&["roster", "list", "--store", &store, "--cohort", "cohort-a"], &[]);
    let rows = field(&doc, "rosters").as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].as_map().unwrap()["name"].as_text(), Some("cohort-a@1"));
    // The digest is the stored checksum.
    let sum = std::fs::read_to_string(Path::new(&store).join("village-a/v3.sha256")).unwrap();
    assert!(village.contains(sum.trim()), "{village} vs {sum}");
    let (code, _, _) = output(&sb, &["roster", "list", "--store", &store, "--cohort", "nobody"]);
    assert_eq!(code, 4);
    let (code, _, _) = output(&sb, &["roster", "list"]);
    assert_eq!(code, 2);
}

#[test]
fn dis_081_a_diff_is_computable_without_exposing_a_subject() {
    let sb = Sandbox::new("roster-diff-private");
    let store = store(&sb);
    let next = example("rosters/next/cohort-a.yaml");
    let (code, out, err) = output(&sb, &["roster", "diff", "cohort-a@1", &next, "--store", &store]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("subjects added: 1") && out.contains("consent changes: unknown -> granted: 1") && out.contains("changed fields: class"), "{out}");
    for s in ["p-000", "Participant", "Hill School", "3A"] {
        assert!(!out.contains(s) && !err.contains(s), "`{s}` leaked:\n{out}\n{err}");
    }
}
