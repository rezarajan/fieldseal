//! The Intake component: its required ports, its rendered environment and the development
//! adapters that production refuses (DEP-002, DEP-012, DEP-023, DEP-057).

use fieldseal_deployment::domain::{Component, EnvironmentName};
use fieldseal_deployment::events::development_adapters_event;
use fieldseal_deployment::manifest::decode_manifest;
use fieldseal_deployment::render::render_environment;
use fieldseal_deployment::validate::validate_manifest;
use fieldseal_kernel::Value;
use fieldseal_kernel::cbor::map;

fn t(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn binding(adapter: &str, config: Vec<(&str, Value)>) -> Value {
    map([("adapter", t(adapter)), ("config", map(config))])
}

/// A manifest whose intake component binds `intake_adapters`.
fn manifest(intake_adapters: Vec<(&str, Value)>, production: bool) -> Value {
    let simple = |ports: &[(&str, &str)]| map(ports.iter().map(|(p, a)| (*p, binding(a, vec![]))).collect::<Vec<_>>());
    let factory = map([(
        "adapters",
        simple(&[("IdentityProvider", "memory-dev"), ("Signer", "file-dev"), ("AttestationVerifier", "software"), ("PolicyEngine", "built-in"), ("TenancyRegistry", "file-dev"), ("ArtefactRegistry", "file-dev"), ("RosterSource", "file-dev")]),
    )]);
    let intake = map([
        ("bind", t("127.0.0.1:8480")),
        ("publicUrl", t("http://localhost:8480")),
        ("maxBodyBytes", Value::Int(1000)),
        ("portal", map([("bind", t("127.0.0.1:8481")), ("publicUrl", t("http://localhost:8481"))])),
        ("dirs", map([("landing", t("/landing")), ("published", t("/published")), ("exportKey", t("/authority/export-key")), ("rosterHistory", t("/published/rosters"))])),
        ("adapters", map(intake_adapters)),
    ]);
    let publishing = map([("adapters", simple(&[("TransparencyLog", "memory"), ("Signer", "memory")]))]);
    let digest = format!("sha256:{}", "ab".repeat(32));
    map([
        ("apiVersion", t("fieldseal.dev/v1alpha1")),
        ("kind", t("Deployment")),
        ("metadata", map([("name", t("t")), ("schemaVersion", t("1.0.0"))])),
        (
            "spec",
            map([
                ("authority", map([("displayName", t("T")), ("trustBundle", map([("ref", t("trust/x")), ("channel", t("c"))]))])),
                ("registries", map([("artefacts", map([("url", t("http://a")), ("transparencyLog", t("http://l"))]))])),
                ("policies", map([("layers", Value::Array(vec![map([("ref", t("policy/x")), ("digest", t(&digest))])]))])),
                ("components", map([("factory", factory), ("intake", intake), ("publishing", publishing)])),
                ("runtime", map([("provisioning", map([("factoryUrl", t("http://localhost:8080")), ("platforms", map([("android", map([("management", t("self-managed"))]))]))]))])),
                ("environments", map([(if production { "production" } else { "development" }, map([]))])),
            ]),
        ),
    ])
}

fn all_ports(identity: &str, store: &str, unsealer: &str) -> Vec<(&'static str, Value)> {
    vec![
        ("RecordKeyUnsealer", binding(unsealer, vec![("dir", t("/k")), ("trustBundle", t("/b"))])),
        ("SubmissionStore", binding(store, vec![("dir", t("/submissions"))])),
        ("DataPlatform", binding("landing-files", vec![("dir", t("/landing"))])),
        ("PolicyEngine", binding("built-in", vec![("allowedBuilders", t("https://b.example/x")), ("allowedSources", t("https://s.example/y"))])),
        ("TenancyRegistry", binding("file-dev", vec![("dir", t("/factory-state"))])),
        ("IdentityProvider", binding(identity, vec![("issuer", t("http://localhost:8180/realms/f")), ("clientId", t("fieldseal-intake"))])),
        ("RosterHistory", binding("file-dev", vec![("dir", t("/published/rosters"))])),
        ("InstrumentSource", binding("file-dev", vec![("dir", t("/published"))])),
    ]
}

fn findings(v: &Value) -> Vec<String> {
    validate_manifest(v).iter().map(|f| f.message().to_owned()).collect()
}

fn without(mut ports: Vec<(&'static str, Value)>, port: &str) -> Vec<(&'static str, Value)> {
    ports.retain(|(p, _)| *p != port);
    ports
}

// covers: DEP-057
#[test]
fn dep_057_the_intake_component_renders_the_listed_variables() {
    let m = decode_manifest(&manifest(all_ports("oidc", "file-dev", "file-dev"), false)).expect("decodes");
    let env = &render_environment(&m, &EnvironmentName("development".into())).expect("renders").environments[&Component::Intake];
    for (k, v) in [
        ("FIELDSEAL_INTAKE_BIND", "127.0.0.1:8480"),
        ("FIELDSEAL_INTAKE_PUBLIC_URLS", "http://localhost:8480"),
        ("FIELDSEAL_INTAKE_MAX_BODY", "1000"),
        ("FIELDSEAL_INTAKE_PORTAL_BIND", "127.0.0.1:8481"),
        ("FIELDSEAL_INTAKE_PORTAL_URL", "http://localhost:8481"),
        ("FIELDSEAL_IDENTITY", "oidc"),
        ("FIELDSEAL_OIDC_CLIENT_ID", "fieldseal-intake"),
        ("FIELDSEAL_INTAKE_SUBMISSIONS_DIR", "/submissions"),
        ("FIELDSEAL_INTAKE_ALLOWED_BUILDERS", "https://b.example/x"),
        ("FIELDSEAL_INTAKE_ALLOWED_SOURCES", "https://s.example/y"),
        ("FIELDSEAL_LANDING_DIR", "/landing"),
        ("FIELDSEAL_TENANCY_DIR", "/factory-state"),
    ] {
        assert_eq!(env.get(k).map(String::as_str), Some(v), "{k}");
    }
    assert!(!env.contains_key("FIELDSEAL_UPLOAD_AUTHORITY"), "the intake app has no authority switch");
    assert!(!env.contains_key("FIELDSEAL_UPLOAD_LISTEN"));
}

// covers: DEP-057
#[test]
fn dep_057_a_file_submission_store_is_a_development_adapter() {
    assert!(fieldseal_deployment::validate::DEVELOPMENT_ADAPTERS.contains(&"file-dev"));
    assert!(!fieldseal_deployment::validate::DEVELOPMENT_ADAPTERS.contains(&"landing-files"));
}

// covers: DEP-023
#[test]
fn dep_023_validate_refuses_intake_development_adapters_in_production() {
    let f = findings(&manifest(all_ports("memory-dev", "file-dev", "file-dev"), true));
    for needle in ["IdentityProvider", "SubmissionStore", "RosterHistory", "InstrumentSource"] {
        assert!(f.iter().any(|m| m.contains(needle) && m.contains("production")), "{needle} is refused: {f:?}");
    }
}

// covers: DEP-023
#[test]
fn dep_023_validate_does_not_refuse_landing_files_in_production() {
    let f = findings(&manifest(all_ports("oidc", "s3", "pkcs11-hsm"), true));
    assert!(!f.iter().any(|m| m.contains("DataPlatform")), "{f:?}");
}

// covers: DEP-002
#[test]
fn dep_002_a_manifest_without_the_new_intake_ports_is_refused() {
    for port in ["IdentityProvider", "RosterHistory", "InstrumentSource"] {
        let f = findings(&manifest(without(all_ports("oidc", "file-dev", "file-dev"), port), false));
        assert!(f.iter().any(|m| m.contains(port) && m.contains("DEP-002")), "{port}: {f:?}");
    }
}

// covers: DEP-012
#[test]
fn dep_012_the_rendered_environment_carries_the_directories_the_intake_app_reads() {
    let m = decode_manifest(&manifest(all_ports("oidc", "file-dev", "file-dev"), false)).expect("decodes");
    let env = &render_environment(&m, &EnvironmentName("development".into())).expect("renders").environments[&Component::Intake];
    assert_eq!(env["FIELDSEAL_INTAKE_PUBLISHED_DIR"], "/published");
    assert_eq!(env["FIELDSEAL_INTAKE_ROSTERS_DIR"], "/published/rosters");
    assert_eq!(env["FIELDSEAL_EXPORT_KEY_DIR"], "/authority/export-key");
    assert_eq!(env["FIELDSEAL_CUSTODY"], "file-dev");
}

// covers: DEP-012
#[test]
fn dep_012_an_unknown_key_under_portal_or_dirs_is_refused() {
    let mut v = manifest(all_ports("oidc", "file-dev", "file-dev"), false);
    let Value::Map(root) = &mut v else { panic!() };
    let spec = root.get_mut("spec").and_then(|s| if let Value::Map(m) = s { Some(m) } else { None }).expect("spec");
    let Some(Value::Map(components)) = spec.get_mut("components") else { panic!() };
    let Some(Value::Map(intake)) = components.get_mut("intake") else { panic!() };
    intake.insert("portal".into(), map([("bind", t("x:1")), ("bogus", t("y"))]));
    assert!(findings(&v).iter().any(|m| m.contains("portal.bogus")));
}

// covers: DEP-051
#[test]
fn dep_051_the_development_adapters_event_has_one_shape() {
    let e = development_adapters_event("fieldseal-intake", &[("SubmissionStore", "file-dev"), ("IdentityProvider", "dev")]);
    assert_eq!(
        e,
        "{\"event\":\"development-adapters\",\"service\":\"fieldseal-intake\",\"adapters\":[{\"port\":\"SubmissionStore\",\"adapter\":\"file-dev\"},{\"port\":\"IdentityProvider\",\"adapter\":\"dev\"}]}"
    );
}
