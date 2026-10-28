//! The local demo (`tools/demo-pipeline.sh`) runs end to end against the built binary.
//! Guards the connected flow against spec tightenings (for example PUB-072) landing without
//! the demo being updated.

use std::path::PathBuf;
use std::process::Command;

// covers: CLI-006
#[test]
fn cli_006_demo_pipeline_runs_end_to_end_and_exits_zero() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let work = std::env::temp_dir().join(format!("fieldseal-demo-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let o = Command::new("bash")
        .arg(repo.join("tools/demo-pipeline.sh"))
        .arg(&work)
        .env("FIELDSEAL_BIN", env!("CARGO_BIN_EXE_fieldseal"))
        .output()
        .expect("bash runs the demo");
    let out = String::from_utf8_lossy(&o.stdout);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "demo failed ({:?})\n{out}\n{err}", o.status);
    assert!(out.contains("== Summary"), "the demo reaches its summary\n{out}");
    cli_032_the_register_resolves_names_and_addresses_and_refuses_ambiguity(&work);
    let _ = std::fs::remove_dir_all(&work);
}

/// CLI-032, on the demo's real publication and trust bundle: a unique name and an address both
/// fetch; a name two artefacts share is refused with both listed.
fn cli_032_the_register_resolves_names_and_addresses_and_refuses_ambiguity(work: &std::path::Path) {
    let fs = env!("CARGO_BIN_EXE_fieldseal");
    let register = work.join("register");
    std::fs::create_dir_all(&register).unwrap();
    std::fs::copy(work.join("water.published"), register.join("a.published")).expect("the demo's publication");
    let run = |args: &[&str]| Command::new(fs).args(args).current_dir(work).output().expect("fieldseal runs");
    let common = ["--dir", "register", "--trust-bundle", "trust-bundle.bundle"];
    let by_name = run(&[&["registry", "fetch", "household-water-access", "--out", "got.published", "--json"][..], &common[..]].concat());
    let json = String::from_utf8_lossy(&by_name.stdout).to_string();
    assert!(by_name.status.success(), "a unique name fetches\n{json}{}", String::from_utf8_lossy(&by_name.stderr));
    let address = json.split("\"address\":\"").nth(1).and_then(|r| r.split('"').next()).expect("the fetched address").to_owned();
    assert!(address.starts_with("sha256:"));
    assert!(json.contains("\"name\":\"household-water-access\""), "the JSON names what was fetched\n{json}");
    let by_address = run(&[&["registry", "fetch", address.as_str(), "--out", "got2.published"][..], &common[..]].concat());
    assert!(by_address.status.success(), "an address fetches");
    assert_eq!(std::fs::read(work.join("got.published")).unwrap(), std::fs::read(work.join("got2.published")).unwrap());
    // A second artefact under the same name: the name no longer identifies one.
    std::fs::copy(work.join("water.published"), register.join("b.published")).unwrap();
    let ambiguous = run(&[&["registry", "fetch", "household-water-access", "--out", "never.published"][..], &common[..]].concat());
    let text = format!("{}{}", String::from_utf8_lossy(&ambiguous.stdout), String::from_utf8_lossy(&ambiguous.stderr));
    assert_eq!(ambiguous.status.code(), Some(2), "an ambiguous name is refused with exit 2\n{text}");
    assert_eq!(text.matches(address.as_str()).count(), 2, "both matches are listed with their address\n{text}");
    assert!(!work.join("never.published").exists(), "nothing is written for an ambiguous name");
}
