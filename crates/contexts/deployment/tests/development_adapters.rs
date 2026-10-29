//! The development adapters a manifest uses: `validate` lists them per component, production
//! refuses them, and every service writes the same `development-adapters` event (DEP-023,
//! DEP-051, DEP-076). The comparison of the two example manifests is in the CLI's tests
//! (`crates/apps/cli/tests/deployment_manifests.rs`), which can read YAML.

use fieldseal_deployment::events::development_adapters_event;
use fieldseal_deployment::manifest::decode_manifest;
use fieldseal_deployment::validate::{development_adapters_in_use, validate_manifest};
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
        simple(&[("IdentityProvider", "memory-dev"), ("Signer", "file-dev"), ("AttestationVerifier", "software"), ("PolicyEngine", "built-in"), ("TenancyRegistry", "file-dev"), ("ArtefactRegistry", "file-dev"), ("RosterSource", "file-dev"), ("BundleStore", "file-dev"), ("RuntimeProfiles", "file-dev")]),
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


/// The intake component's ports with development adapters for the identity provider, the
/// submission store and the key unsealer, and production ones for the rest.
fn intake_ports() -> Vec<(&'static str, Value)> {
    vec![
        ("RecordKeyUnsealer", binding("file-dev", vec![("dir", t("/k")), ("trustBundle", t("/b"))])),
        ("SubmissionStore", binding("file-dev", vec![("dir", t("/submissions"))])),
        ("DataPlatform", binding("landing-files", vec![("dir", t("/landing"))])),
        ("PolicyEngine", binding("built-in", vec![("allowedBuilders", t("https://b.example/x")), ("allowedSources", t("https://s.example/y"))])),
        ("TenancyRegistry", binding("postgres", vec![])),
        ("IdentityProvider", binding("oidc", vec![("issuer", t("http://localhost:8180/realms/f")), ("clientId", t("fieldseal-intake"))])),
        ("RosterHistory", binding("file-dev", vec![("dir", t("/published/rosters"))])),
        ("InstrumentSource", binding("file-dev", vec![("dir", t("/published"))])),
    ]
}

fn findings(v: &Value) -> Vec<String> {
    validate_manifest(v).iter().map(|f| f.message().to_owned()).collect()
}

// covers: DEP-076
#[test]
fn dep_023_validate_lists_the_development_adapters_per_component() {
    let m = decode_manifest(&manifest(intake_ports(), false)).expect("decodes");
    let in_use: Vec<(&str, String, String)> = development_adapters_in_use(&m).into_iter().map(|(c, p, a)| (c.name(), p, a)).collect();
    // Components in manifest order, ports in name order; `landing-files`, `oidc`, `postgres`, `built-in` and `translog` are not development adapters.
    let expect = |c: &'static str, p: &str, a: &str| (c, p.to_owned(), a.to_owned());
    assert_eq!(
        in_use,
        vec![
            expect("factory", "ArtefactRegistry", "file-dev"),
            expect("factory", "AttestationVerifier", "software"),
            expect("factory", "BundleStore", "file-dev"),
            expect("factory", "IdentityProvider", "memory-dev"),
            expect("factory", "RosterSource", "file-dev"),
            expect("factory", "RuntimeProfiles", "file-dev"),
            expect("factory", "Signer", "file-dev"),
            expect("factory", "TenancyRegistry", "file-dev"),
            // The export key is a file the manifest names (`dirs.exportKey`), counted as a port as the intake app does.
            expect("intake", "ExportKey", "file-dev"),
            expect("intake", "InstrumentSource", "file-dev"),
            expect("intake", "RecordKeyUnsealer", "file-dev"),
            expect("intake", "RosterHistory", "file-dev"),
            expect("intake", "SubmissionStore", "file-dev"),
            expect("publishing", "Signer", "memory"),
            expect("publishing", "TransparencyLog", "memory"),
        ]
    );
}

// covers: DEP-023
#[test]
fn dep_023_validate_refuses_them_in_production() {
    let f = findings(&manifest(intake_ports(), true));
    for needle in ["Signer", "SubmissionStore", "RecordKeyUnsealer", "RosterHistory", "InstrumentSource", "TenancyRegistry"] {
        assert!(f.iter().any(|m| m.contains(needle) && m.contains("production") && m.contains("DEP-023")), "{needle} is refused: {f:?}");
    }
}

// covers: DEP-051
#[test]
fn dep_051_the_development_adapters_event_has_the_same_shape_in_every_service() {
    for service in ["fieldseal-factory", "fieldseal-intake", "fieldseal-translog"] {
        let e = development_adapters_event(service, &[("Signer", "file-dev")]);
        assert_eq!(e, format!("{{\"event\":\"development-adapters\",\"service\":\"{service}\",\"adapters\":[{{\"port\":\"Signer\",\"adapter\":\"file-dev\"}}]}}"));
        assert!(!e.contains('\n'), "one line");
    }
    assert!(development_adapters_event("fieldseal-translog", &[]).ends_with("\"adapters\":[]}"));
}
