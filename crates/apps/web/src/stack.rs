//! The web app as a service of the compose stack (`FIELDSEAL_WEB_STACK=true`): the browser
//! device is provisioned from the stack's trust bundle, and its page names the surveys
//! published through the stack's log. The device gets its bundle from the factory
//! (`GET /v1/bundle`), through this app's proxy; nothing here builds one. The mount points are
//! the stack's (deploy/local); `just web` runs the same code natively and points the app at
//! its own directories with `FIELDSEAL_WEB_AUTHORITY_DIR`, `FIELDSEAL_WEB_PUBLISHED_DIR` and
//! `FIELDSEAL_WEB_REGISTRY_DIR`.

use fieldseal_adapters_translog::{HttpLogTransport, HttpTranslog};
use fieldseal_publishing::domain::Publication;
use fieldseal_trust::domain::{AuthorityPublicKey, TrustBundle};

use crate::state::AppState;

/// The surveys published in the stack: the `*.published` files of the published directory
/// (not the deployment policy, not the layouts `<survey>.<window>.layout.published`) whose
/// publication the log vouches for. The log's entries hold digests, not names (WIRE-191), so
/// the names come from the files; a file is kept only when the entry at the index of its first
/// log record, read with `GET /entries/{from}/{to}`, is the entry the file carries.
#[must_use]
pub fn surveys(state: &AppState) -> Vec<String> {
    let Some(log) = state.log_url.as_deref().and_then(|url| HttpLogTransport::new(url).ok()).map(HttpTranslog::new) else { return Vec::new() };
    let mut names: Vec<String> = std::fs::read_dir(state.published())
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str()?.strip_suffix(".published")?.to_owned();
            if name == "deployment-policy" || name.ends_with(".layout") {
                return None;
            }
            let publication = Publication::decode(&std::fs::read(e.path()).ok()?).ok()?;
            let record = publication.log.first()?;
            let index = record.inclusion.leaf_index;
            (log.entries(index, index + 1).ok()?.first() == Some(&record.entry)).then_some(name)
        })
        .collect();
    names.sort();
    names
}

/// The provisioning document, from the stack's trust bundle.
///
/// # Errors
///
/// The trust bundle cannot be read or has no record key.
pub fn provisioning(state: &AppState) -> Result<String, String> {
    let path = state.authority().join("trust-bundle.bundle");
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
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
        "allowedBuilders": state.allowed_builders,
        "allowedSources": state.allowed_sources,
        "factoryUrl": state.factory_url,
        "uploadUrl": state.upload_url,
        "provisionalRecordKey": hex(&record),
        "buildAnchor": hex(&[0xbb; 32]),
        "schema": "1.0.0",
        "unattested": true,
    })
    .to_string())
}
