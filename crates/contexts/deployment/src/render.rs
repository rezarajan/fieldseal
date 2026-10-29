//! Rendering a manifest into the twelve-factor environment of each service and the device
//! provisioning configuration (DEP-012, DEP-020, DEP-021, DEP-024). Secrets render as
//! references only; the output is a pure function of the manifest and environment name.

use std::collections::BTreeMap;

use fieldseal_kernel::Value;

use crate::application::EnvironmentSet;
use crate::domain::{Component, EnvironmentName};
use crate::manifest::{ArtefactRef, ConfigValue, Manifest};

/// The result of rendering one environment.
#[derive(Clone, PartialEq, Debug)]
pub struct Rendered {
    /// Environment variables per service component.
    pub environments: EnvironmentSet,
    /// The device provisioning configuration (DEP-020), as a canonical value.
    pub provisioning: Value,
}

/// `UPPER_SNAKE` of a camel-case or hyphenated name.
pub fn snake_upper(name: &str) -> String {
    let mut out = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            if c.is_ascii_uppercase() && prev_lower {
                out.push('_');
            }
            out.push(c.to_ascii_uppercase());
            prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        } else {
            if !out.ends_with('_') {
                out.push('_');
            }
            prev_lower = false;
        }
    }
    out
}

fn put(env: &mut BTreeMap<String, String>, key: &str, v: &ConfigValue) {
    match v {
        ConfigValue::Secret(r) => {
            env.insert(format!("{key}_REF"), r.0.clone());
        }
        other => {
            env.insert(key.to_owned(), other.display());
        }
    }
}

fn artefact_value(a: &ArtefactRef) -> Value {
    let mut m = BTreeMap::from([("ref".to_owned(), Value::Text(a.name.clone()))]);
    if let Some(d) = &a.digest {
        m.insert("digest".into(), Value::Text(d.to_text()));
    }
    if let Some(c) = &a.channel {
        m.insert("channel".into(), Value::Text(c.clone()));
    }
    if let Some(r) = &a.registry {
        m.insert("registry".into(), Value::Text(r.clone()));
    }
    Value::Map(m)
}

fn config_value(v: &ConfigValue) -> Value {
    match v {
        ConfigValue::Text(t) => Value::Text(t.clone()),
        ConfigValue::Number(n) => Value::Int(*n),
        ConfigValue::Bool(b) => Value::Bool(*b),
        ConfigValue::Secret(r) => Value::Map(BTreeMap::from([("secretRef".to_owned(), Value::Text(r.0.clone()))])),
    }
}

/// The device provisioning configuration (DEP-020, DEP-024).
pub fn provisioning_configuration(m: &Manifest, environment: &str) -> Value {
    let mut platforms = BTreeMap::new();
    for (name, p) in &m.provisioning.platforms {
        let mut pm: BTreeMap<String, Value> = p.settings.iter().map(|(k, v)| (k.clone(), config_value(v))).collect();
        pm.insert("management".into(), Value::Text(p.management.as_str().into()));
        platforms.insert(name.clone(), Value::Map(pm));
    }
    let mut hints = BTreeMap::from([("factoryUrl".to_owned(), Value::Text(m.provisioning.factory_url.clone()))]);
    if let Some(d) = &m.provisioning.destination_url {
        hints.insert("destinationUrl".into(), Value::Text(d.clone()));
    }
    Value::Map(BTreeMap::from([
        ("deployment".to_owned(), Value::Text(m.name.clone())),
        ("environment".to_owned(), Value::Text(environment.to_owned())),
        ("trustBundle".to_owned(), artefact_value(&m.trust_bundle)),
        ("addressHints".to_owned(), Value::Map(hints)),
        ("initialRuntimePolicy".to_owned(), Value::Array(m.policy_layers.iter().map(artefact_value).collect())),
        ("platforms".to_owned(), Value::Map(platforms)),
    ]))
}

/// Renders `environment` of `manifest` (DEP-012). Errors name the references that cannot be
/// resolved.
pub fn render_environment(manifest: &Manifest, environment: &EnvironmentName) -> Result<Rendered, Vec<String>> {
    let m = manifest.resolve(&environment.0).map_err(|f| f.iter().map(|x| x.message().to_owned()).collect::<Vec<_>>())?;
    let missing: Vec<String> = m
        .policy_layers
        .iter()
        .chain(&m.instruments)
        .chain(std::iter::once(&m.trust_bundle))
        .filter(|a| a.registry.as_deref().is_some_and(|r| r != "artefacts"))
        .map(|a| format!("{}: registry `{}` is not declared in spec.registries", a.name, a.registry.clone().unwrap_or_default()))
        .collect();
    if !missing.is_empty() {
        return Err(missing);
    }
    let mut set = EnvironmentSet::new();
    for (component, spec) in &m.components {
        let mut env = BTreeMap::new();
        env.insert("FIELDSEAL_ENVIRONMENT".to_owned(), environment.0.clone());
        env.insert("FIELDSEAL_DEPLOYMENT".to_owned(), m.name.clone());
        env.insert("FIELDSEAL_COMPONENT".to_owned(), component.name().into());
        env.insert("FIELDSEAL_LOG_FORMAT".to_owned(), "json".into());
        env.insert("FIELDSEAL_ARTEFACT_REGISTRY".to_owned(), m.artefact_registry.clone());
        env.insert("FIELDSEAL_TRANSPARENCY_LOG".to_owned(), m.transparency_log.clone());
        env.insert("FIELDSEAL_TRUST_BUNDLE_REF".to_owned(), m.trust_bundle.label());
        env.insert("FIELDSEAL_POLICY_LAYERS".to_owned(), m.policy_layers.iter().map(ArtefactRef::label).collect::<Vec<_>>().join(","));
        env.insert("FIELDSEAL_TIER".to_owned(), crate::custody::tier_of(&environment.0, m.environments.get(&environment.0).and_then(|e| e.tier)).as_str().to_owned());
        for (purpose, b) in &m.custody {
            env.insert(crate::custody::env_name(purpose), format!("{}:{}", b.assurance.as_str(), b.mode.as_str()));
        }
        for (k, v) in &spec.scaling {
            env.insert(format!("FIELDSEAL_SCALING_{}", snake_upper(k)), v.to_string());
        }
        for (port, b) in &spec.adapters {
            let p = snake_upper(port);
            env.insert(format!("FIELDSEAL_ADAPTER_{p}"), b.adapter.clone());
            for (k, v) in &b.config {
                put(&mut env, &format!("FIELDSEAL_{p}_{}", snake_upper(k)), v);
            }
        }
        match component {
            Component::Factory => factory_aliases(&mut env, spec, &m),
            Component::Intake => intake_aliases(&mut env, spec, &m),
            Component::Publishing => translog_aliases(&mut env, spec),
            Component::Runtime | Component::Cli => {}
        }
        set.insert(*component, env);
    }
    Ok(Rendered { environments: set, provisioning: provisioning_configuration(&m, &environment.0) })
}

/// The variables the factory service reads (`crates/apps/factory`), derived from its adapters.
fn factory_aliases(env: &mut BTreeMap<String, String>, spec: &crate::manifest::ComponentSpec, m: &Manifest) {
    env.insert("FIELDSEAL_FACTORY_BIND".into(), spec.bind.clone().unwrap_or_else(|| "0.0.0.0:8080".into()));
    env.insert("FIELDSEAL_FACTORY_URL".into(), m.provisioning.factory_url.clone());
    if let Some(idp) = spec.adapters.get("IdentityProvider") {
        identity_vars(env, idp, true);
    }
    if let Some(signer) = spec.adapters.get("Signer") {
        let custody = if signer.adapter == "memory" { "memory-dev" } else { signer.adapter.as_str() };
        env.insert("FIELDSEAL_CUSTODY".into(), custody.into());
        // `memory` writes its generated bundle out; `file-dev` reads the authority's bundle.
        for (key, var) in [("trustBundleOut", "FIELDSEAL_TRUST_BUNDLE"), ("trustBundle", "FIELDSEAL_TRUST_BUNDLE"), ("dir", "FIELDSEAL_CUSTODY_DIR")] {
            if let Some(v) = signer.config.get(key) {
                put(env, var, v);
            }
        }
    }
    // The file-backed state store (development): the journal directory.
    if let Some(v) = spec.adapters.get("TenancyRegistry").filter(|a| a.adapter == "file-dev").and_then(|a| a.config.get("dir")) {
        put(env, "FIELDSEAL_STATE_DIR", v);
    }
    // The artefact registry directory the factory reads and the roster store it writes.
    for (port, var) in [("ArtefactRegistry", "FIELDSEAL_FACTORY_REGISTRY_DIR"), ("RosterSource", "FIELDSEAL_ROSTER_DIR")] {
        if let Some(v) = spec.adapters.get(port).filter(|a| a.adapter == "file-dev").and_then(|a| a.config.get("dir")) {
            put(env, var, v);
        }
    }
    if spec.adapters.get("AttestationVerifier").is_some_and(|a| a.adapter == "software" || a.adapter == "memory") {
        env.insert("FIELDSEAL_ALLOW_UNATTESTED".into(), "true".into());
    }
}

/// The variables the intake app reads (`crates/apps/intake`, Technical Plan 7.6), derived from
/// its adapters and the named keys of its component.
fn intake_aliases(env: &mut BTreeMap<String, String>, spec: &crate::manifest::ComponentSpec, m: &Manifest) {
    if let Some(bind) = &spec.bind {
        env.insert("FIELDSEAL_INTAKE_BIND".into(), bind.clone());
    }
    // The base URLs device tokens may be bound to: `publicUrl`, else the provisioned destination.
    if let Some(url) = spec.public_url.as_ref().or(m.provisioning.destination_url.as_ref()) {
        env.insert("FIELDSEAL_INTAKE_PUBLIC_URLS".into(), url.clone());
    }
    if let Some(n) = spec.max_body_bytes {
        env.insert("FIELDSEAL_INTAKE_MAX_BODY".into(), n.to_string());
    }
    if let Some(v) = &spec.portal.bind {
        env.insert("FIELDSEAL_INTAKE_PORTAL_BIND".into(), v.clone());
    }
    if let Some(v) = &spec.portal.public_url {
        env.insert("FIELDSEAL_INTAKE_PORTAL_URL".into(), v.clone());
    }
    if let Some(idp) = spec.adapters.get("IdentityProvider") {
        identity_vars(env, idp, false);
    }
    // The authority's keys: a key directory and the trust bundle (development custody), or
    // keys generated in memory.
    if let Some(unsealer) = spec.adapters.get("RecordKeyUnsealer") {
        let custody = if unsealer.adapter == "memory" { "memory-dev" } else { unsealer.adapter.as_str() };
        env.insert("FIELDSEAL_CUSTODY".into(), custody.into());
        for (key, var) in [("dir", "FIELDSEAL_CUSTODY_DIR"), ("trustBundle", "FIELDSEAL_TRUST_BUNDLE")] {
            if let Some(v) = unsealer.config.get(key) {
                put(env, var, v);
            }
        }
    }
    // The factory's registered tenancies, read from its file-backed state (read-only).
    if let Some(v) = spec.adapters.get("TenancyRegistry").filter(|a| a.adapter == "file-dev").and_then(|a| a.config.get("dir")) {
        put(env, "FIELDSEAL_TENANCY_DIR", v);
    }
    // Where long-format files land (DEP-057): `dirs.landing`, else the `DataPlatform` directory.
    let landing = spec.dirs.landing.clone().or_else(|| {
        spec.adapters.get("DataPlatform").filter(|a| a.adapter == "landing-files").and_then(|a| a.config.get("dir")).map(ConfigValue::display)
    });
    if let Some(v) = landing {
        env.insert("FIELDSEAL_LANDING_DIR".into(), v);
    }
    let binding_dir = |port: &str| spec.adapters.get(port).filter(|a| a.adapter == "file-dev").and_then(|a| a.config.get("dir")).map(ConfigValue::display);
    if let Some(v) = binding_dir("SubmissionStore") {
        env.insert("FIELDSEAL_INTAKE_SUBMISSIONS_DIR".into(), v);
    }
    if let Some(v) = spec.dirs.published.clone().or_else(|| binding_dir("InstrumentSource")) {
        env.insert("FIELDSEAL_INTAKE_PUBLISHED_DIR".into(), v);
    }
    if let Some(v) = spec.dirs.roster_history.clone().or_else(|| binding_dir("RosterHistory")) {
        env.insert("FIELDSEAL_INTAKE_ROSTERS_DIR".into(), v);
    }
    if let Some(v) = &spec.dirs.export_key {
        env.insert("FIELDSEAL_EXPORT_KEY_DIR".into(), v.clone());
    }
    // The publishing policy instruments are verified under (comma-separated lists).
    if let Some(engine) = spec.adapters.get("PolicyEngine") {
        for (key, var) in [("allowedBuilders", "FIELDSEAL_INTAKE_ALLOWED_BUILDERS"), ("allowedSources", "FIELDSEAL_INTAKE_ALLOWED_SOURCES")] {
            if let Some(v) = engine.config.get(key) {
                put(env, var, v);
            }
        }
    }
}

/// The variables the self-hosted transparency-log server reads (`fieldseal-translog`),
/// from the `translog` adapter's configuration.
fn translog_aliases(env: &mut BTreeMap<String, String>, spec: &crate::manifest::ComponentSpec) {
    let Some(log) = spec.adapters.get("TransparencyLog").filter(|b| b.adapter == "translog") else { return };
    for (key, var) in [
        ("dir", "FIELDSEAL_TRANSLOG_DIR"),
        ("origin", "FIELDSEAL_TRANSLOG_ORIGIN"),
        ("keyFile", "FIELDSEAL_TRANSLOG_KEY_FILE"),
        ("generateKey", "FIELDSEAL_TRANSLOG_GENERATE_KEY"),
        ("maxBody", "FIELDSEAL_TRANSLOG_MAX_BODY"),
    ] {
        if let Some(v) = log.config.get(key) {
            put(env, var, v);
        }
    }
    if let Some(bind) = &spec.bind {
        env.insert("FIELDSEAL_TRANSLOG_BIND".into(), bind.clone());
    }
}

/// An environment as a `.env` file: sorted `KEY=value` lines. Values never hold secrets.
pub fn env_file(env: &BTreeMap<String, String>) -> String {
    env.iter().map(|(k, v)| format!("{k}={v}\n")).collect()
}

/// The identity variables of a service that signs people in. `memory-dev` renders
/// `FIELDSEAL_IDENTITY=dev`, with its users only for the factory (the intake app signs in as
/// one fixed login).
fn identity_vars(env: &mut BTreeMap<String, String>, idp: &crate::manifest::AdapterBinding, with_users: bool) {
    match idp.adapter.as_str() {
        "oidc" => {
            env.insert("FIELDSEAL_IDENTITY".into(), "oidc".into());
            // The operator API's access tokens (REG-070a); only the factory verifies them.
            if with_users {
                for (key, var) in [("apiAudience", "FIELDSEAL_OIDC_API_AUDIENCE"), ("cliClientId", "FIELDSEAL_OIDC_CLI_CLIENT_ID"), ("acceptTypJwt", "FIELDSEAL_OIDC_ACCEPT_TYP_JWT")] {
                    if let Some(v) = idp.config.get(key) {
                        put(env, var, v);
                    }
                }
            }
            for (key, var) in [
                ("issuer", "FIELDSEAL_OIDC_ISSUER"),
                ("clientId", "FIELDSEAL_OIDC_CLIENT_ID"),
                ("clientSecret", "FIELDSEAL_OIDC_CLIENT_SECRET"),
                ("scopes", "FIELDSEAL_OIDC_SCOPES"),
                ("rolesClaim", "FIELDSEAL_OIDC_ROLES_CLAIM"),
                ("acrValues", "FIELDSEAL_OIDC_ACR_VALUES"),
                ("assertedMethods", "FIELDSEAL_OIDC_ASSERTED_METHODS"),
                ("phishingResistantAmr", "FIELDSEAL_OIDC_PHISHING_RESISTANT_AMR"),
                ("phishingResistantAcr", "FIELDSEAL_OIDC_PHISHING_RESISTANT_ACR"),
            ] {
                if let Some(v) = idp.config.get(key) {
                    put(env, var, v);
                }
            }
        }
        "memory-dev" => {
            env.insert("FIELDSEAL_IDENTITY".into(), "dev".into());
            if let Some(v) = idp.config.get("users").filter(|_| with_users) {
                put(env, "FIELDSEAL_DEV_USERS", v);
            }
        }
        _ => {}
    }
}
