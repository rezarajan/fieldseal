//! The development IdP refuses to start outside development, and is in no image or manifest.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// Runs the binary with the given flags and `FIELDSEAL_ENVIRONMENT` (none when `None`). The
/// client secrets are set, so a refusal is about the thing under test and nothing else.
fn run(args: &[&str], environment: Option<&str>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fieldseal-dev-idp"));
    cmd.args(args)
        .arg("--config")
        .arg(root().join("examples/deployments/dev-idp.yaml"))
        .env_clear()
        .env("FIELDSEAL_SECRET_FACTORY_OIDC_CLIENT_SECRET", "a")
        .env("FIELDSEAL_SECRET_INTAKE_OIDC_CLIENT_SECRET", "b");
    if let Some(e) = environment {
        cmd.env("FIELDSEAL_ENVIRONMENT", e);
    }
    cmd.output().unwrap()
}

fn refused(out: &Output, mentions: &str) {
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(mentions), "{stderr}");
}

#[test]
fn dep_023_exits_2_without_development_tool() {
    refused(&run(&["--bind", "127.0.0.1:0"], Some("development")), "--development-tool");
}

#[test]
fn dep_023_exits_2_in_production() {
    for environment in [Some("production"), Some("staging"), Some(""), None] {
        refused(&run(&["--development-tool", "--bind", "127.0.0.1:0"], environment), "FIELDSEAL_ENVIRONMENT");
    }
}

#[test]
fn dep_023_exits_2_on_a_non_loopback_bind() {
    for bind in ["0.0.0.0:8180", "192.168.1.5:8180", "example.com:8180"] {
        refused(&run(&["--development-tool", "--bind", bind], Some("development")), "loopback");
    }
}

#[test]
fn dep_023_it_appears_in_no_image_compose_file_or_manifest() {
    let mut files = vec![root().join("flake.nix"), root().join("deploy/local/compose.yaml")];
    for entry in std::fs::read_dir(root().join("examples/deployments")).unwrap() {
        let path = entry.unwrap().path();
        // dev-idp.yaml is the tool's own configuration, not a manifest.
        if path.extension().is_some_and(|e| e == "yaml") && path.file_name().unwrap() != "dev-idp.yaml" {
            files.push(path);
        }
    }
    assert!(files.len() > 3, "the manifests were found");
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(!text.contains("fieldseal-dev-idp"), "{} names the development IdP", file.display());
    }
}
