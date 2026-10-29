//! What the results export keeps out of its files (INT-086, INT-087).

mod support;

use std::collections::BTreeSet;

use fieldseal_adapters_landing_files::export::{ExportKey, IdentitySubject, KeyedSubject, SubjectMapper, key_id, write_export};
use fieldseal_kernel::Value;
use fieldseal_kernel::digest::lower_hex;
use support::*;

fn keyed(byte: u8) -> KeyedSubject {
    KeyedSubject::new(ExportKey::from_bytes([byte; 32]))
}

/// Every file under `dir`, with its path relative to it.
fn files(dir: &std::path::Path) -> Vec<(String, String)> {
    fn walk(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<(String, String)>) {
        for e in std::fs::read_dir(dir).expect("dir") {
            let path = e.expect("entry").path();
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                out.push((path.strip_prefix(base).expect("under base").display().to_string(), String::from_utf8(std::fs::read(&path).expect("file")).expect("text")));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out
}

/// The subject ids of the bundled rosters.
fn roster_subjects() -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for e in std::fs::read_dir(repo().join("examples/rosters")).expect("rosters") {
        let doc = fieldseal_adapters_authoring::decode_path(&e.expect("entry").path()).expect("roster decodes");
        let Some(Value::Array(subjects)) = doc.as_map().and_then(|m| m.get("subjects")) else { panic!("a roster lists subjects") };
        for s in subjects {
            ids.insert(s.as_map().and_then(|m| m.get("subject")).and_then(Value::as_text).expect("subject id").to_owned());
        }
    }
    assert!(ids.len() >= 3, "the bundled rosters name subjects");
    ids
}

// covers: INT-086
#[test]
fn int_086_excluded_rows_appear_in_no_file_and_are_counted() {
    let out = scratch("excluded");
    let mut rows = table_rows("s-1");
    let mut second = value(6, "x.marker", "integer", fieldseal_intake::domain::ObservedValue::Int(424_242));
    second.excluded = Some("consent refused".into());
    rows.push(second);
    write_export(&table(rows, &IdentitySubject), &both(), &out).expect("export");
    for (name, text) in files(&out) {
        assert!(!text.contains("424242") && !text.contains("d.integer") && !text.contains("x.marker"), "{name} holds an excluded row");
        assert!(!text.contains("consent-pending") && !text.contains("consent refused"), "{name} holds an exclusion reason");
    }
    let manifest = parse_json(&read(&out, "manifest.json"));
    assert_eq!(manifest.get("rows_omitted_excluded"), &J::Num("2".into()));
    assert_eq!(manifest.get("landing_mark"), &J::Num("16".into()), "the mark still counts them");
    let _ = std::fs::remove_dir_all(out);
}

// covers: INT-087
#[test]
fn int_087_no_roster_subject_id_appears_in_any_file_in_readable_or_hex_form() {
    let subjects = roster_subjects();
    let mut rows = Vec::new();
    for (n, id) in subjects.iter().enumerate() {
        // Intake lands the subject as the hex of the roster id's bytes in the demo; a readable
        // id is scanned for too.
        for (k, subject) in [lower_hex(id.as_bytes()), id.clone()].into_iter().enumerate() {
            let mut r = value((n * 2 + k) as u8 + 1, "a.integer", "integer", fieldseal_intake::domain::ObservedValue::Int(1));
            r.observation.subject = fieldseal_kernel::id::SubjectId::new(subject).expect("subject");
            rows.push(r);
        }
    }
    let out = scratch("privacy");
    write_export(&table(rows, &keyed(9)), &fieldseal_adapters_landing_files::export::ExportOptions { subject: Box::new(keyed(9)), ..both() }, &out).expect("export");
    let all = files(&out);
    assert!(all.len() == 7, "JSON Lines, CSV, free text, contract, codebook and manifest were all written: {all:?}");
    for id in &subjects {
        for form in [id.clone(), lower_hex(id.as_bytes()), lower_hex(id.as_bytes()).to_uppercase()] {
            for (name, text) in &all {
                assert!(!text.contains(&form), "{name} holds the subject {form}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(out);
}

// covers: INT-087
#[test]
fn int_087_the_same_key_gives_the_same_pseudonym() {
    let (a, b) = (keyed(1), keyed(1));
    assert_eq!(a.map("686830303031"), b.map("686830303031"));
    assert_ne!(a.map("686830303031"), a.map("686830303032"), "different subjects stay different");
    assert_eq!(a.map("x").len(), 64);
    let (one, two) = (export_with("same-a", 1), export_with("same-b", 1));
    assert_eq!(read(&one, "results.jsonl"), read(&two, "results.jsonl"));
    let _ = (std::fs::remove_dir_all(one), std::fs::remove_dir_all(two));
}

fn export_with(name: &str, key: u8) -> std::path::PathBuf {
    let out = scratch(name);
    let options = fieldseal_adapters_landing_files::export::ExportOptions { subject: Box::new(keyed(key)), ..both() };
    write_export(&table(table_rows("686830303031"), &keyed(key)), &options, &out).expect("export");
    out
}

// covers: INT-087
#[test]
fn int_087_another_key_gives_different_pseudonyms() {
    assert_ne!(keyed(1).map("686830303031"), keyed(2).map("686830303031"));
    let (one, two) = (export_with("other-a", 1), export_with("other-b", 2));
    let subject = |dir: &std::path::Path| jsonl_rows(&read(dir, "results.jsonl"))[0].get("subject").cell();
    assert_ne!(subject(&one), subject(&two));
    let _ = (std::fs::remove_dir_all(one), std::fs::remove_dir_all(two));
}

// covers: INT-087
#[test]
fn int_087_the_pseudonym_is_the_hmac_of_the_subject_text() {
    // The vector was made with Python's `hmac` for the key 0x01 * 32 and the text "hh-0001".
    let got = keyed(1).map("hh-0001");
    assert_eq!(got.len(), 64);
    assert!(got.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    assert_eq!(got, "54dea962e52094c631a20a4fd9a9a5a4ff97f3a191052a30dc86107a7a241bc6".to_owned(), "HMAC-SHA-256(0x01*32, \"hh-0001\")");
}

// covers: INT-087
#[test]
fn int_087_the_manifest_records_the_key_id_not_the_key() {
    let key = ExportKey::from_bytes([0x5c; 32]);
    let id = key_id(&key);
    assert_eq!(id.len(), 32);
    let out = scratch("keyid");
    let options = fieldseal_adapters_landing_files::export::ExportOptions { subject: Box::new(keyed(0x5c)), ..both() };
    write_export(&table(table_rows("s-1"), &keyed(0x5c)), &options, &out).expect("export");
    let manifest = parse_json(&read(&out, "manifest.json"));
    assert_eq!(manifest.get("pseudonymisation_key_id"), &J::Str(id.clone()));
    for (name, text) in files(&out) {
        assert!(!text.contains(&lower_hex(&[0x5c; 32])), "{name} holds the key");
    }
    let want = lower_hex(fieldseal_kernel::digest::sha256(&[b"fieldseal.dev/export-key-id".as_slice(), &[0x5c; 32]].concat()).as_bytes());
    assert_eq!(id, want[..32], "the id is the first 32 hex digits of SHA-256(domain || key)");
    let _ = std::fs::remove_dir_all(out);
}

// covers: INT-087
#[test]
fn int_087_an_absent_or_wrong_key_file_is_refused_and_never_created() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = scratch("keyfile");
    assert!(ExportKey::load(&dir).is_err(), "an absent key is refused");
    assert!(!dir.join("export.key").exists(), "and not created");
    let path = dir.join("short.key");
    std::fs::write(&path, [1u8; 31]).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    assert!(ExportKey::load_file(&path).is_err(), "31 bytes are refused");
    std::fs::write(&path, [1u8; 33]).expect("write");
    assert!(ExportKey::load_file(&path).is_err(), "33 bytes are refused");
    std::fs::write(&path, [1u8; 32]).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("mode");
    assert!(ExportKey::load_file(&path).is_err(), "a mode wider than 0600 is refused");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    assert!(ExportKey::load_file(&path).is_ok(), "32 bytes at 0600 are accepted");
    std::fs::copy(&path, dir.join("export.key")).expect("copy");
    std::fs::set_permissions(dir.join("export.key"), std::fs::Permissions::from_mode(0o400)).expect("mode");
    assert!(ExportKey::load(&dir).is_ok(), "load reads <dir>/export.key; 0400 is no wider than 0600");
    let mut names: Vec<_> = std::fs::read_dir(&dir).expect("dir").map(|e| e.expect("entry").file_name()).collect();
    names.sort();
    assert_eq!(names, ["export.key", "short.key"], "nothing was created");
    let _ = std::fs::remove_dir_all(dir);
}
