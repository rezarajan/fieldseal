//! The Factory component: the ports the operator API needs, the variables it renders and the
//! `cohorts` key that is no longer read (DEP-002, DEP-012, DEP-023).

use fieldseal_deployment::domain::{Component, EnvironmentName};
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

/// The factory's ports as `local-stack.yaml` binds them, with `tenancy_config` for the
/// tenancy registry.
fn factory_ports(tenancy_config: Vec<(&str, Value)>) -> Vec<(&'static str, Value)> {
    vec![
        (
            "IdentityProvider",
            binding(
                "oidc",
                vec![
                    ("issuer", t("http://localhost:8180/realms/fieldseal")),
                    ("clientId", t("fieldseal-factory")),
                    ("apiAudience", t("fieldseal-factory-api")),
                    ("cliClientId", t("fieldseal-cli")),
                    ("acceptTypJwt", Value::Bool(true)),
                ],
            ),
        ),
        ("Signer", binding("file-dev", vec![("dir", t("/authority/online")), ("trustBundle", t("/authority/trust-bundle.bundle"))])),
        ("AttestationVerifier", binding("software", vec![])),
        ("PolicyEngine", binding("built-in", vec![])),
        ("TenancyRegistry", binding("file-dev", tenancy_config)),
        ("ArtefactRegistry", binding("file-dev", vec![("dir", t("/clistate/registry"))])),
        ("RosterSource", binding("file-dev", vec![("dir", t("/rosters"))])),
    ]
}

fn manifest(factory_ports: Vec<(&str, Value)>, production: bool) -> Value {
    let simple = |ports: &[(&str, &str)]| map(ports.iter().map(|(p, a)| (*p, binding(a, vec![]))).collect::<Vec<_>>());
    let intake = map([(
        "adapters",
        simple(&[
            ("RecordKeyUnsealer", "file-dev"),
            ("SubmissionStore", "file-dev"),
            ("DataPlatform", "landing-files"),
            ("PolicyEngine", "built-in"),
            ("TenancyRegistry", "file-dev"),
            ("IdentityProvider", "oidc"),
            ("RosterHistory", "file-dev"),
            ("InstrumentSource", "file-dev"),
        ]),
    )]);
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
                ("components", map([("factory", map([("bind", t("127.0.0.1:8080")), ("adapters", map(factory_ports))])), ("intake", intake), ("publishing", publishing)])),
                ("runtime", map([("provisioning", map([("factoryUrl", t("http://localhost:8080")), ("platforms", map([("android", map([("management", t("self-managed"))]))]))]))])),
                ("environments", map([(if production { "production" } else { "development" }, map([]))])),
            ]),
        ),
    ])
}

fn findings(v: &Value) -> Vec<String> {
    validate_manifest(v).iter().map(|f| f.message().to_owned()).collect()
}

fn factory_env(m: &Value) -> std::collections::BTreeMap<String, String> {
    let m = decode_manifest(m).expect("decodes");
    render_environment(&m, &EnvironmentName("development".into())).expect("renders").environments[&Component::Factory].clone()
}

// covers: DEP-012
#[test]
fn dep_012_a_cohorts_key_in_the_tenancy_registry_config_is_no_longer_rendered() {
    let m = manifest(factory_ports(vec![("dir", t("/state/factory")), ("cohorts", t("cohort-a:1,village-a:1"))]), false);
    assert!(findings(&m).is_empty(), "an unknown adapter config key is not refused (DEP-007 is open): {:?}", findings(&m));
    let env = factory_env(&m);
    assert!(!env.contains_key("FIELDSEAL_COHORTS"), "the variable is gone");
    assert_eq!(env.get("FIELDSEAL_STATE_DIR").map(String::as_str), Some("/state/factory"));
}

// covers: DEP-012
#[test]
fn dep_012_the_factory_component_renders_the_new_variables() {
    let env = factory_env(&manifest(factory_ports(vec![("dir", t("/state/factory"))]), false));
    for (k, v) in [
        ("FIELDSEAL_OIDC_API_AUDIENCE", "fieldseal-factory-api"),
        ("FIELDSEAL_OIDC_CLI_CLIENT_ID", "fieldseal-cli"),
        ("FIELDSEAL_OIDC_ACCEPT_TYP_JWT", "true"),
        ("FIELDSEAL_FACTORY_REGISTRY_DIR", "/clistate/registry"),
        ("FIELDSEAL_ROSTER_DIR", "/rosters"),
        ("FIELDSEAL_OIDC_CLIENT_ID", "fieldseal-factory"),
    ] {
        assert_eq!(env.get(k).map(String::as_str), Some(v), "{k}");
    }
}

// covers: DEP-002
#[test]
fn dep_002_a_manifest_without_the_new_factory_ports_is_refused() {
    for port in ["ArtefactRegistry", "RosterSource"] {
        let mut ports = factory_ports(vec![("dir", t("/state/factory"))]);
        ports.retain(|(p, _)| *p != port);
        let f = findings(&manifest(ports, false));
        assert!(f.iter().any(|m| m.contains(port) && m.contains("DEP-002")), "{port}: {f:?}");
    }
}

// covers: DEP-002
#[test]
fn dep_002_the_example_manifests_bind_the_new_factory_ports() {
    for file in ["local-stack.yaml", "dev-web.yaml", "sample.yaml"] {
        let path = format!("{}/../../../examples/deployments/{file}", env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(&path).expect("example manifest");
        for port in ["ArtefactRegistry", "RosterSource"] {
            assert!(text.lines().any(|l| l.trim_start().starts_with(&format!("{port}: {{ adapter: file-dev"))), "{file} binds {port}");
        }
        assert!(!text.contains("cohorts:"), "{file} carries no cohorts string");
    }
}

// covers: DEP-023
#[test]
fn dep_023_validate_refuses_the_factory_file_adapters_in_production() {
    let f = findings(&manifest(factory_ports(vec![("dir", t("/state/factory"))]), true));
    for needle in ["ArtefactRegistry", "RosterSource"] {
        assert!(f.iter().any(|m| m.contains(needle) && m.contains("production")), "{needle} is refused: {f:?}");
    }
}
