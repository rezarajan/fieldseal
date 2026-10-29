//! The two example manifests that run the whole system, `just web` (`dev-web.yaml`) and the
//! compose stack (`local-stack.yaml`), use the same adapters (DEP-012).

mod common;

use std::path::Path;

use common::{Sandbox, repo};
use fieldseal_adapters_authoring::decode_path;
use fieldseal_deployment::manifest::{Manifest, decode_manifest};

fn load(name: &str) -> Manifest {
    let path = repo().join("examples/deployments").join(name);
    decode_manifest(&decode_path(Path::new(&path)).expect("the manifest decodes")).expect("the manifest is valid")
}

/// Settings that are a place on disk or a network address: the only things the two may differ in.
fn is_directory_or_address(key: &str) -> bool {
    matches!(key, "dir" | "trustBundle" | "keyFile" | "exportKey" | "issuedRostersDir" | "bind")
}

// covers: DEP-012
#[test]
fn dep_012_dev_web_and_local_stack_differ_only_in_directories() {
    let (web, stack) = (load("dev-web.yaml"), load("local-stack.yaml"));
    assert_eq!(web.components.keys().collect::<Vec<_>>(), stack.components.keys().collect::<Vec<_>>());
    for (component, w) in &web.components {
        let s = &stack.components[component];
        assert_eq!(w.adapters.keys().collect::<Vec<_>>(), s.adapters.keys().collect::<Vec<_>>(), "{}: the same ports", component.name());
        for (port, wb) in &w.adapters {
            let sb = &s.adapters[port];
            assert_eq!(wb.adapter, sb.adapter, "{} {port}: the same adapter", component.name());
            // `acceptTypJwt` is the one real difference: Keycloak's access tokens carry the header type JWT, the development IdP's carry at+jwt.
            let keys = |b: &fieldseal_deployment::manifest::AdapterBinding| b.config.keys().filter(|k| *k != "acceptTypJwt").cloned().collect::<Vec<_>>();
            assert_eq!(keys(wb), keys(sb), "{} {port}: the same settings", component.name());
            for (key, value) in wb.config.iter().filter(|(k, _)| !is_directory_or_address(k) && *k != "acceptTypJwt") {
                assert_eq!(Some(value), sb.config.get(key), "{} {port} {key}", component.name());
            }
        }
    }
}

// covers: DEP-076
#[test]
fn dep_076_deployment_validate_prints_the_development_adapters_per_component() {
    let sb = Sandbox::new("validate-dev-adapters");
    let manifest = repo().join("examples/deployments/dev-web.yaml");
    let (code, doc) = sb.json(&["deployment", "validate", &manifest.to_string_lossy()]);
    assert_eq!(code, 0);
    let adapters = doc.as_map().expect("an object")["developmentAdapters"].as_map().expect("developmentAdapters");
    let port = |component: &str, port: &str| adapters[component].as_map().expect("a component")[port].as_text().map(str::to_owned);
    assert_eq!(port("factory", "Signer").as_deref(), Some("file-dev"));
    assert_eq!(port("intake", "SubmissionStore").as_deref(), Some("file-dev"));
    assert_eq!(port("publishing", "Signer").as_deref(), Some("file-dev"));
    assert!(adapters["factory"].as_map().expect("a component").get("IdentityProvider").is_none(), "oidc is not a development adapter");
    let text = sb.run(&["deployment", "validate", &manifest.to_string_lossy()]);
    assert!(String::from_utf8_lossy(&text.stdout).contains("development adapter: publishing Signer file-dev"));
}
