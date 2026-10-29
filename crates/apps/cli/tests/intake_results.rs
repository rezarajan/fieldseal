//! `fieldseal intake results`: the results export of a landing directory (CLI-048, INT-085 to
//! INT-088). The publications are the local demo's real ones, verified against its trust bundle.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fieldseal_adapters_landing_files::FileDataPlatform;
use fieldseal_adapters_landing_files::export::{ExportKey, KeyedSubject, SubjectMapper};
use fieldseal_intake::contract::sample_observation;
use fieldseal_intake::domain::{ObservedValue, Reading};
use fieldseal_intake::ports::{DataPlatform, LandingBatch};
use fieldseal_kernel::id::{Fingerprint, ItemPath, RecordId, SubjectId};

const FS: &str = env!("CARGO_BIN_EXE_fieldseal");

struct World {
    dir: PathBuf,
    published: PathBuf,
    bundle: PathBuf,
    landing: PathBuf,
    fingerprint: Fingerprint,
}

fn path(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

/// The demo's authority and its published water survey, and a landing directory with rows
/// under the survey's fingerprint.
fn world(name: &str) -> World {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let dir = std::env::temp_dir().join(format!("fieldseal-intake-results-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let work = dir.join("work");
    let demo = Command::new("bash").arg(repo.join("tools/demo-pipeline.sh")).arg(&work).env("FIELDSEAL_BIN", FS).output().expect("the demo runs");
    assert!(demo.status.success(), "{}", String::from_utf8_lossy(&demo.stderr));
    let published = dir.join("published");
    std::fs::create_dir_all(&published).expect("published directory");
    std::fs::copy(work.join("water.published"), published.join("water.published")).expect("the publication");
    let bundle = work.join("trust-bundle.bundle");
    let fetched = Command::new(FS).args(["registry", "fetch", "household-water-access", "--dir", path(&published), "--trust-bundle", path(&bundle), "--out", path(&dir.join("got.published")), "--json"]).output().expect("fetch");
    let json = String::from_utf8_lossy(&fetched.stdout).to_string();
    let hex = json.split("\"address\":\"sha256:").nth(1).and_then(|r| r.split('"').next()).expect("the address").to_owned();
    let bytes: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex")).collect();
    let fingerprint = Fingerprint::from_bytes(&bytes).expect("a fingerprint");
    let landing = dir.join("landing");
    land(&landing, fingerprint, "hh-0001");
    World { dir, published, bundle, landing, fingerprint }
}

fn row(fingerprint: Fingerprint, record: u8, subject: &str, item: &str, value_type: &'static str, reading: Reading) -> fieldseal_intake::domain::Observation {
    let mut o = sample_observation(1, record);
    o.instrument = fingerprint;
    o.subject = SubjectId::new(subject).expect("subject");
    o.item = ItemPath::new(item).expect("item");
    o.value_type = value_type;
    o.reading = reading;
    o.unit = None;
    o
}

fn land(dir: &Path, fingerprint: Fingerprint, subject: &str) {
    let platform = FileDataPlatform::new(dir).expect("landing directory");
    let value = |r, item, t, v| row(fingerprint, r, subject, item, t, Reading::Value(v));
    let observations = vec![
        value(1, "water.liters", "integer", ObservedValue::Int(-5)),
        value(1, "water.source", "code", ObservedValue::Code("=SUM(A1)".into())),
        value(1, "water.notes", "string", ObservedValue::Text("fetches water, twice a day".into())),
        value(2, "water.liters", "integer", ObservedValue::Int(40)),
        value(3, "water.liters", "integer", ObservedValue::Int(41)),
    ];
    platform.land(&LandingBatch { observations, exclusions: vec![(RecordId::from([3; 16]), "consent refused".into())], ..LandingBatch::default() }).expect("land");
}

fn key_file(dir: &Path, name: &str, byte: u8) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, [byte; 32]).expect("key");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).expect("mode");
    p
}

fn run(w: &World, key: Option<&Path>, out: &str, extra: &[&str]) -> Output {
    let mut args = vec!["intake", "results", "--landing", path(&w.landing), "--published", path(&w.published), "--trust-bundle", path(&w.bundle), "--out", out];
    if let Some(k) = key {
        args.extend(["--export-key", path(k)]);
    }
    args.extend(extra);
    Command::new(FS).args(&args).output().expect("fieldseal runs")
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn ok(o: &Output) {
    assert!(o.status.success(), "{}", text(o));
}

fn read(dir: &Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

// covers: CLI-048
#[test]
fn cli_048_results_from_a_landing_directory_writes_every_file_and_prints_the_manifest_digest() {
    let w = world("all");
    let key = key_file(&w.dir, "export.key", 3);
    let out = w.dir.join("export");
    let o = run(&w, Some(&key), path(&out), &[]);
    ok(&o);
    let hex = fieldseal_kernel::digest::lower_hex(w.fingerprint.as_bytes());
    for name in ["manifest.json", "results.jsonl", "results.csv", "free_text.jsonl", "free_text.csv", "codebook.csv"] {
        assert!(out.join(name).is_file(), "{name}");
    }
    assert!(out.join(format!("contracts/{hex}.json")).is_file());
    let digest = fieldseal_kernel::digest::lower_hex(fieldseal_kernel::digest::sha256(&std::fs::read(out.join("manifest.json")).expect("manifest")).as_bytes());
    let stdout = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(stdout.contains(&digest), "the manifest digest is printed\n{stdout}");
    assert!(stdout.contains("results.jsonl") && stdout.contains("free_text.csv"), "the file list is printed\n{stdout}");
    let jsonl = read(&out, "results.jsonl");
    assert_eq!(jsonl.lines().count(), 4, "the excluded record is left out");
    assert!(!jsonl.contains("hh-0001"), "the subject is a keyed hash");
    let mapped = KeyedSubject::new(ExportKey::from_bytes([3; 32])).map("hh-0001");
    assert!(jsonl.contains(&mapped), "the subject is HMAC-SHA-256 under the key file");
    let _ = std::fs::remove_dir_all(w.dir);
}

// covers: CLI-048
#[test]
fn cli_048_the_unprotected_data_statement_is_printed() {
    let w = world("statement");
    let key = key_file(&w.dir, "export.key", 3);
    let o = run(&w, Some(&key), path(&w.dir.join("export")), &[]);
    ok(&o);
    assert!(String::from_utf8_lossy(&o.stdout).contains("outside Fieldseal's protection"), "{}", text(&o));
    let json = run(&w, Some(&key), path(&w.dir.join("export-json")), &["--json"]);
    ok(&json);
    let stdout = String::from_utf8_lossy(&json.stdout).to_string();
    assert!(stdout.trim_start().starts_with('{') && stdout.trim_end().ends_with('}') && stdout.lines().count() == 1, "stdout is one JSON document\n{stdout}");
    assert!(String::from_utf8_lossy(&json.stderr).contains("outside Fieldseal's protection"), "the statement goes to stderr with --json");
    let _ = std::fs::remove_dir_all(w.dir);
}

// covers: CLI-048
#[test]
fn cli_048_the_csv_guard_prefixes_text_and_never_numbers() {
    let w = world("guard");
    let key = key_file(&w.dir, "export.key", 3);
    let out = w.dir.join("export");
    ok(&run(&w, Some(&key), path(&out), &[]));
    let csv = read(&out, "results.csv");
    assert!(csv.contains(",'=SUM(A1),"), "text that starts with a formula character is prefixed\n{csv}");
    assert!(csv.contains(",-5,"), "a number is not\n{csv}");
    assert!(!csv.contains("'-5"));
    let jsonl = read(&out, "results.jsonl");
    assert!(jsonl.contains("\"value_text\":\"=SUM(A1)\""), "JSON Lines is not guarded");
    assert!(!csv.contains("twice a day") && !jsonl.contains("twice a day"), "free text stays out of the results files");
    assert!(read(&out, "free_text.csv").contains("\"fetches water, twice a day\""));
    let _ = std::fs::remove_dir_all(w.dir);
}

// covers: CLI-048
#[test]
fn cli_048_the_manifest_records_the_landing_mark_of_the_snapshot() {
    let w = world("mark");
    let key = key_file(&w.dir, "export.key", 3);
    let out = w.dir.join("export");
    ok(&run(&w, Some(&key), path(&out), &[]));
    let manifest = read(&out, "manifest.json");
    assert!(manifest.contains("\"landing_mark\":5"), "five rows, one of them excluded\n{manifest}");
    assert!(manifest.contains("\"rows_omitted_excluded\":1"));
    let _ = std::fs::remove_dir_all(w.dir);
}

// covers: CLI-048
#[test]
fn cli_048_a_second_export_key_changes_pseudonyms() {
    let w = world("keys");
    let (a, b) = (key_file(&w.dir, "a.key", 3), key_file(&w.dir, "b.key", 4));
    let (one, two, again) = (w.dir.join("one"), w.dir.join("two"), w.dir.join("again"));
    ok(&run(&w, Some(&a), path(&one), &[]));
    ok(&run(&w, Some(&b), path(&two), &[]));
    ok(&run(&w, Some(&a), path(&again), &[]));
    assert_ne!(read(&one, "results.jsonl"), read(&two, "results.jsonl"));
    assert_eq!(read(&one, "results.jsonl"), read(&again, "results.jsonl"), "the same key gives the same files");
    assert_eq!(read(&one, "manifest.json"), read(&again, "manifest.json"));
    assert_ne!(read(&one, "manifest.json"), read(&two, "manifest.json"), "the key id differs");
    let _ = std::fs::remove_dir_all(w.dir);
}

// covers: CLI-048
#[test]
fn cli_048_the_export_key_is_required() {
    let w = world("nokey");
    let out = w.dir.join("export");
    let o = run(&w, None, path(&out), &[]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("--export-key"));
    assert!(!out.exists(), "nothing is written");
    let _ = std::fs::remove_dir_all(w.dir);
}

// covers: CLI-048
#[test]
fn cli_048_published_is_required() {
    let w = world("nopublished");
    let key = key_file(&w.dir, "export.key", 3);
    let o = Command::new(FS)
        .args(["intake", "results", "--landing", path(&w.landing), "--export-key", path(&key), "--trust-bundle", path(&w.bundle), "--out", path(&w.dir.join("export"))])
        .output()
        .expect("fieldseal runs");
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("--published"));
    let _ = std::fs::remove_dir_all(w.dir);
}

// covers: CLI-048
#[test]
fn cli_048_trust_bundle_is_required() {
    let w = world("nobundle");
    let key = key_file(&w.dir, "export.key", 3);
    let o = Command::new(FS)
        .args(["intake", "results", "--landing", path(&w.landing), "--published", path(&w.published), "--export-key", path(&key), "--out", path(&w.dir.join("export"))])
        .env("FIELDSEAL_TRUST_BUNDLE", path(&w.bundle))
        .output()
        .expect("fieldseal runs");
    assert_eq!(o.status.code(), Some(2), "the environment does not stand in for the flag\n{}", text(&o));
    assert!(text(&o).contains("--trust-bundle"));
    let _ = std::fs::remove_dir_all(w.dir);
}

// covers: CLI-048
#[test]
fn cli_048_a_key_file_of_the_wrong_length_or_mode_is_refused() {
    let w = world("badkey");
    let out = w.dir.join("export");
    let short = w.dir.join("short.key");
    std::fs::write(&short, [1u8; 16]).expect("key");
    std::fs::set_permissions(&short, std::fs::Permissions::from_mode(0o600)).expect("mode");
    let wide = key_file(&w.dir, "wide.key", 1);
    std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o644)).expect("mode");
    let missing = w.dir.join("missing.key");
    for (key, why) in [(&short, "32 bytes"), (&wide, "0600"), (&missing, "missing")] {
        let o = run(&w, Some(key), path(&out), &[]);
        assert_eq!(o.status.code(), Some(2), "{why}: {}", text(&o));
        assert!(text(&o).contains("export key"), "{why}: {}", text(&o));
        assert!(!out.exists(), "{why}: nothing is written");
    }
    assert!(!missing.exists(), "a missing key is never created");
    let _ = std::fs::remove_dir_all(w.dir);
}

// covers: CLI-048
#[test]
fn cli_048_contract_files_are_named_by_fingerprint_hex() {
    let w = world("names");
    let key = key_file(&w.dir, "export.key", 3);
    let out = w.dir.join("export");
    ok(&run(&w, Some(&key), path(&out), &[]));
    let names: Vec<String> = std::fs::read_dir(out.join("contracts")).expect("contracts").map(|e| e.expect("entry").file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(names, [format!("{}.json", fieldseal_kernel::digest::lower_hex(w.fingerprint.as_bytes()))], "64 lower-case hex digits and .json");
    let contract = read(&out.join("contracts"), &names[0]);
    assert!(contract.contains("\"exportSchemaVersion\":\"1.0.0\""));
    let _ = std::fs::remove_dir_all(w.dir);
}

// covers: CLI-048
#[test]
fn cli_048_an_instrument_with_no_verified_publication_is_refused() {
    let w = world("unpublished");
    let key = key_file(&w.dir, "export.key", 3);
    land(&w.dir.join("other"), Fingerprint::from([9; 32]), "hh-0001");
    let out = w.dir.join("export");
    let o = Command::new(FS)
        .args(["intake", "results", "--landing", path(&w.dir.join("other")), "--published", path(&w.published), "--export-key", path(&key), "--trust-bundle", path(&w.bundle), "--out", path(&out)])
        .output()
        .expect("fieldseal runs");
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("no verified publication"));
    assert!(!out.exists());
    let _ = std::fs::remove_dir_all(w.dir);
}
