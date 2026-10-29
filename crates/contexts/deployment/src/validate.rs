//! Manifest validation (DEP-001–006, DEP-023, DEP-024): schema, adapters per context,
//! secrets only by reference, and the floors a production environment may not go below.

use fieldseal_kernel::Value;
use fieldseal_policy::domain::{Layer, Severity, PolicyDocument, merge_layers};

use crate::application::ManifestFinding;
use crate::domain::Component;
use crate::manifest::{ConfigValue, Manifest, decode_manifest};

/// Adapters for development and tests: never allowed in production (DEP-023, REG-017). `web` is the browser platform profile (PLAT-107).
pub const DEVELOPMENT_ADAPTERS: &[&str] = &["memory", "memory-dev", "file-dev", "software", "dev", "web"];

/// Ports a component must bind (DEP-002), with the adapters known for each.
pub fn ports(component: Component) -> &'static [(&'static str, &'static [&'static str])] {
    match component {
        Component::Factory => &[
            ("IdentityProvider", &["oidc", "memory-dev"]),
            ("Signer", &["pkcs11-hsm", "file-dev", "memory"]),
            ("AttestationVerifier", &["android-key-attestation", "software", "memory"]),
            ("PolicyEngine", &["opa", "built-in"]),
            ("TenancyRegistry", &["postgres", "file-dev", "memory"]),
            // The operator API reads the artefact registry and writes the roster store (REG-046, REG-047).
            ("ArtefactRegistry", &["file-dev"]),
            ("RosterSource", &["file-dev"]),
            // The factory stores the bundles it builds and reads the runtime profile reported at registration (DIS-082, DIS-012).
            ("BundleStore", &["file-dev"]),
            ("RuntimeProfiles", &["file-dev"]),
        ],
        Component::Intake => &[
            ("RecordKeyUnsealer", &["pkcs11-hsm", "file-dev", "memory"]),
            ("SubmissionStore", &["s3", "file-dev", "memory"]),
            ("DataPlatform", &["lakehouse-delta", "landing-files", "memory"]),
            ("PolicyEngine", &["opa", "built-in"]),
            ("TenancyRegistry", &["postgres", "file-dev", "memory"]),
            ("IdentityProvider", &["oidc", "memory-dev"]),
            ("RosterHistory", &["file-dev"]),
            ("InstrumentSource", &["file-dev"]),
        ],
        Component::Publishing => &[("TransparencyLog", &["trillian", "rekor", "translog", "memory"]), ("Signer", &["pkcs11-hsm", "file-dev", "memory"])],
        Component::Runtime | Component::Cli => &[],
    }
}

/// Words that mark a configuration key as holding a secret.
const SECRET_WORDS: &[&str] = &["password", "passwd", "secret", "token", "pin", "credentials", "credential", "apikey", "passphrase"];

fn words(key: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    for c in key.chars() {
        if c.is_ascii_uppercase() {
            out.push(c.to_ascii_lowercase().to_string());
        } else if c == '_' || c == '-' || c == '.' {
            out.push(String::new());
        } else {
            out.last_mut().expect("non-empty").push(c);
        }
    }
    out
}

/// Whether a configuration key names a secret.
pub fn key_names_secret(key: &str) -> bool {
    let w = words(key);
    if w.windows(2).any(|p| matches!((p[0].as_str(), p[1].as_str()), ("api" | "private" | "access" | "secret", "key"))) {
        return true;
    }
    w.iter().any(|x| SECRET_WORDS.contains(&x.as_str()))
}

/// Whether a text value looks like a key, password or token (DEP-004).
pub fn looks_like_secret(s: &str) -> bool {
    if s.contains("-----BEGIN") {
        return true;
    }
    if ["sk-", "ghp_", "gho_", "github_pat_", "xoxb-", "xoxp-", "AKIA", "eyJ"].iter().any(|p| s.starts_with(p)) && s.len() >= 20 {
        return true;
    }
    if let Some((_, rest)) = s.split_once("://") {
        if let Some((userinfo, _)) = rest.split('/').next().unwrap_or("").rsplit_once('@') {
            return userinfo.contains(':');
        }
        return false;
    }
    s.len() >= 32
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b))
        && !s.starts_with('/')
        && s.bytes().any(|b| b.is_ascii_digit())
        && s.bytes().any(|b| b.is_ascii_alphabetic())
}

fn check_value(key: &str, v: &ConfigValue, path: &str, out: &mut Vec<ManifestFinding>) {
    if let ConfigValue::Text(t) = v {
        if key_names_secret(key) && !t.is_empty() {
            out.push(ManifestFinding::InlineSecret(format!("{path}: `{key}` holds a secret and must be `{{ secretRef: … }}` (DEP-004)")));
        } else if looks_like_secret(t) {
            out.push(ManifestFinding::InlineSecret(format!("{path}: the value looks like a key, password or token; use a secretRef (DEP-004)")));
        }
    }
}

/// Whether `url` is plain `http` to a loopback host: `127.0.0.1`, `localhost` or `[::1]`
/// (a browser only allows passkeys on `localhost`, never on an IP address, so the local
/// stack needs `localhost`).
fn loopback_http(url: &str) -> bool {
    url.strip_prefix("http://").is_some_and(|rest| {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = authority.rsplit_once(':').map_or(authority, |(h, p)| if p.bytes().all(|b| b.is_ascii_digit()) { h } else { authority });
        matches!(host, "127.0.0.1" | "localhost" | "[::1]")
    })
}

/// Findings for a decoded manifest in its base form (adapters, secrets, platforms).
pub fn check_manifest(m: &Manifest) -> Vec<ManifestFinding> {
    let mut out = vec![];
    for component in Component::SERVICES {
        let Some(spec) = m.components.get(&component) else {
            out.push(ManifestFinding::SchemaError(format!("spec.components.{}: the component is missing (DEP-040)", component.name())));
            continue;
        };
        let known = ports(component);
        for (port, _) in known {
            if !spec.adapters.contains_key(*port) {
                out.push(ManifestFinding::SchemaError(format!("spec.components.{}.adapters.{port}: no adapter declared (DEP-002)", component.name())));
            }
        }
        for (port, binding) in &spec.adapters {
            let path = format!("spec.components.{}.adapters.{port}", component.name());
            match known.iter().find(|(p, _)| p == port) {
                None => out.push(ManifestFinding::UnknownAdapter(format!("{path}: `{port}` is not a port of {}", component.name()))),
                Some((_, adapters)) if !adapters.contains(&binding.adapter.as_str()) => out.push(ManifestFinding::UnknownAdapter(format!(
                    "{path}.adapter: `{}` is not an adapter of {port} (known: {})",
                    binding.adapter,
                    adapters.join(", ")
                ))),
                Some(_) => {}
            }
            for (k, v) in &binding.config {
                check_value(k, v, &format!("{path}.config.{k}"), &mut out);
            }
        }
    }
    for (plat, p) in &m.provisioning.platforms {
        for (k, v) in &p.settings {
            check_value(k, v, &format!("spec.runtime.provisioning.platforms.{plat}.{k}"), &mut out);
        }
    }
    for (env, e) in &m.environments {
        for (k, v) in &e.overrides {
            let leaf = k.rsplit('.').next().unwrap_or(k);
            check_value(leaf, v, &format!("spec.environments.{env}.overrides.{k}"), &mut out);
        }
    }
    let url = &m.provisioning.factory_url;
    if !(url.is_empty() || url.starts_with("https://") || loopback_http(url)) {
        out.push(ManifestFinding::SchemaError("spec.runtime.provisioning.factoryUrl: must be https (http only for a loopback host)".into()));
    }
    out
}

/// The development adapters a manifest binds, as (component, port, adapter), in component and
/// port order (DEP-076). `fieldseal deployment validate` prints them, and `tools/dev-web.sh
/// --check` compares them with the `development-adapters` event of each service (DEP-051).
pub fn development_adapters_in_use(m: &Manifest) -> Vec<(Component, String, String)> {
    let mut out: Vec<(Component, String, String)> = m
        .components
        .iter()
        .flat_map(|(component, spec)| {
            spec.adapters.iter().filter(|(_, b)| DEVELOPMENT_ADAPTERS.contains(&b.adapter.as_str())).map(|(port, b)| (*component, port.clone(), b.adapter.clone()))
        })
        .collect();
    // The export pseudonymisation key is a file the manifest names, not an adapter port, but the
    // intake app counts it among its development adapters (`ExportKey`).
    for (component, spec) in &m.components {
        if *component == Component::Intake && spec.dirs.export_key.is_some() {
            out.push((*component, "ExportKey".to_owned(), "file-dev".to_owned()));
        }
    }
    out.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    out
}

/// Findings for one environment: its overrides stay within DEP-006 and, in production, no
/// development adapter or unattested-key acceptance is in force (DEP-023).
pub fn check_environment(m: &Manifest, environment: &str) -> Vec<ManifestFinding> {
    let resolved = match m.resolve(environment) {
        Ok(r) => r,
        Err(f) => return f,
    };
    let mut out = vec![];
    // Outside development the factory verifies its release policy against a pinned content
    // address; one that verified itself would let a publisher key lower its own threshold.
    if matches!(environment, "staging" | "production") {
        for (component, spec) in &resolved.components {
            if component.name() == "factory" && !spec.adapters.get("PolicyEngine").is_some_and(|b| b.config.contains_key("policyDigest")) {
                out.push(ManifestFinding::PolicyFloorViolation(format!(
                    "spec.components.factory.adapters.PolicyEngine.config.policyDigest: required in {environment}: the content address of the deployment-policy the factory trusts"
                )));
            }
        }
    }
    if environment == "production" {
        for (component, spec) in &resolved.components {
            for (port, b) in &spec.adapters {
                if DEVELOPMENT_ADAPTERS.contains(&b.adapter.as_str()) {
                    out.push(ManifestFinding::PolicyFloorViolation(format!(
                        "spec.components.{}.adapters.{port}: the development adapter `{}` is not allowed in production (DEP-023)",
                        component.name(),
                        b.adapter
                    )));
                }
            }
        }
    }
    out
}

/// Validates a manifest value: schema, adapters, secrets, and every environment (DEP-001–006).
pub fn validate_manifest(value: &Value) -> Vec<ManifestFinding> {
    match decode_manifest(value) {
        Err(f) => f,
        Ok(m) => {
            let mut out = check_manifest(&m);
            for env in m.environments.keys() {
                out.extend(check_environment(&m, env));
                out.extend(crate::custody::check_custody(&m, env, None));
            }
            out
        }
    }
}

/// Merges the supplied policy layers and reports any floor or tightening violation as a
/// [`ManifestFinding::PolicyFloorViolation`] (DEP-003, POL-010, POL-021).
pub fn check_policy_layers(layers: &[&PolicyDocument]) -> Vec<ManifestFinding> {
    let (_, findings) = merge_layers(layers);
    findings
        .into_iter()
        .filter(|f| f.severity == Severity::Error)
        .map(|f| ManifestFinding::PolicyFloorViolation(format!("{}: {} ({})", f.path, f.message, f.requirement)))
        .collect()
}

/// Whether `layer` is the deployment layer.
pub fn is_deployment_layer(doc: &PolicyDocument) -> bool {
    doc.layer == Layer::Deployment
}
