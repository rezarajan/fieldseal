//! The web app as a service of the compose stack (`FIELDSEAL_WEB_STACK=true`): the browser
//! device is provisioned from the stack's trust bundle, chooses among the surveys published
//! through the stack's log, and gets its bundles from the stack's authority. Bundles are built by
//! the stack's own `fieldseal bundle build --stack --tenancy …`, with every roster, so every
//! cohort the factory assigned is carried. The mount points are the stack's (deploy/local).

use std::path::Path;
use std::process::Command;

use fieldseal_trust::domain::{AuthorityPublicKey, TrustBundle};

use crate::state::AppState;

const AUTHORITY: &str = "/authority";
const PUBLISHED: &str = "/published";
const FACTORY_STATE: &str = "/factory-state";
const CLI_STATE: &str = "/clistate";
const ROSTERS: &str = "/opt/fieldseal/examples/rosters";
/// The provenance the stack's publishing policy allows (tools/stack-demo.sh).
const BUILDER: &str = "https://ci.example.org/builders/fieldseal-publish";
const SOURCE: &str = "https://git.example.org/authority/artefacts";

/// The surveys published in the stack: every `*.published` but the deployment policy.
#[must_use]
pub fn surveys() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(PUBLISHED)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".published")).map(str::to_owned))
        .filter(|n| n != "deployment-policy")
        .collect();
    names.sort();
    names
}

/// The provisioning document, from the stack's trust bundle.
///
/// # Errors
///
/// The trust bundle cannot be read or has no record key.
pub fn provisioning(_state: &AppState) -> Result<String, String> {
    let bytes = std::fs::read(Path::new(AUTHORITY).join("trust-bundle.bundle")).map_err(|e| format!("{AUTHORITY}/trust-bundle.bundle: {e}"))?;
    let bundle = TrustBundle::decode(&bytes).map_err(|e| e.to_string())?;
    let record = bundle
        .certificates()
        .iter()
        .find_map(|c| match (c.purpose(), c.public_key()) {
            (Some(fieldseal_kernel::crypto::Purpose::Record), AuthorityPublicKey::X25519(k)) => Some(*k),
            _ => None,
        })
        .ok_or("the stack's trust bundle has no record key")?;
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    Ok(serde_json::json!({
        "authority": bundle.name(),
        "environment": "development",
        "trustBundle": fieldseal_kernel::base64url::base64url_encode(&bytes),
        "allowedBuilders": [BUILDER],
        "allowedSources": [SOURCE],
        "provisionalRecordKey": hex(&record),
        "buildAnchor": hex(&[0xbb; 32]),
        "schema": "1.0.0",
        "unattested": true,
    })
    .to_string())
}

/// A bundle of `survey` for the registered `tenancy`, built by the stack's authority.
///
/// # Errors
///
/// The survey is not published, or the CLI refuses (an unknown tenancy among other reasons).
pub fn bundle(cli: &str, tenancy: &str, survey: &str) -> Result<Vec<u8>, String> {
    if !tenancy.chars().all(|c| c.is_ascii_hexdigit()) || tenancy.len() != 64 {
        return Err("tenancy: expected 64 hexadecimal digits".into());
    }
    if !surveys().iter().any(|s| s == survey) {
        return Err(format!("{survey}: not a published survey"));
    }
    let out = std::env::temp_dir().join(format!("fieldseal-web-bundle-{tenancy}"));
    let _ = std::fs::remove_dir_all(&out);
    let mut cmd = Command::new(cli);
    cmd.args(["bundle", "build", "--stack", "--tenancy", tenancy])
        .args(["--trust-bundle", &format!("{AUTHORITY}/trust-bundle.bundle"), "--custody", &format!("{AUTHORITY}/online")])
        .args(["--publication", &format!("{PUBLISHED}/{survey}.published"), "--policy-publication", &format!("{PUBLISHED}/deployment-policy.published")])
        .args(["--tenancy-dir", FACTORY_STATE, "--state", CLI_STATE, "--issued-dir", &format!("{PUBLISHED}/rosters")])
        .args(["--allow-unattested", "--out-dir"])
        .arg(&out);
    for roster in std::fs::read_dir(ROSTERS).map_err(|e| format!("{ROSTERS}: {e}"))?.flatten() {
        cmd.arg("--roster").arg(roster.path());
    }
    let run = cmd.output().map_err(|e| format!("{cli}: {e}"))?;
    if !run.status.success() {
        return Err(format!("{}{}", String::from_utf8_lossy(&run.stdout), String::from_utf8_lossy(&run.stderr)).trim().to_owned());
    }
    let file = std::fs::read_dir(&out).map_err(|e| e.to_string())?.flatten().map(|e| e.path()).find(|p| p.extension().is_some_and(|x| x == "fsb")).ok_or("no bundle was written")?;
    std::fs::read(file).map_err(|e| e.to_string())
}
