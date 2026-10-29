//! The factory's build settings (Technical Plan section 7.6): defaults, ranges, and the file
//! adapters that production refuses.

use std::collections::BTreeMap;

use fieldseal_factory::config::{Config, PolicyTrust};

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000001";

fn env(extra: &[(&str, &str)]) -> BTreeMap<String, String> {
    let mut m: BTreeMap<String, String> = [
        ("FIELDSEAL_ENVIRONMENT", "development"),
        ("FIELDSEAL_FACTORY_BIND", "127.0.0.1:8080"),
        ("FIELDSEAL_FACTORY_URL", "http://127.0.0.1:8080"),
        ("FIELDSEAL_IDENTITY", "dev"),
        ("FIELDSEAL_DEV_USERS", "ops=operator:phr"),
        ("FIELDSEAL_CUSTODY", "memory-dev"),
        ("FIELDSEAL_STATE_DIR", "/state"),
        ("FIELDSEAL_FACTORY_REGISTRY_DIR", "/registry"),
        ("FIELDSEAL_ROSTER_DIR", "/rosters"),
        ("FIELDSEAL_BUNDLE_DIR", "/bundles"),
        ("FIELDSEAL_ISSUED_ROSTERS_DIR", "/issued"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    m.extend(extra.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())));
    m
}

fn load(m: &BTreeMap<String, String>) -> Result<Config, String> {
    Config::from_lookup(|k| m.get(k).cloned())
}

#[test]
fn dep_012_the_build_settings_have_their_defaults() {
    let c = load(&env(&[])).expect("valid");
    assert_eq!((c.build_interval_s, c.max_anchor_age_s), (5, 86_400));
    assert_eq!((c.bundle_dir.as_str(), c.issued_rosters_dir.as_str()), ("/bundles", "/issued"));
    let staging = load(&env(&[("FIELDSEAL_ENVIRONMENT", "staging"), ("FIELDSEAL_FACTORY_POLICY_DIGEST", DIGEST)])).expect("valid");
    assert_eq!(staging.build_interval_s, 60);
}

#[test]
fn dep_012_an_out_of_range_build_setting_is_refused() {
    for (name, value) in [
        ("FIELDSEAL_FACTORY_BUILD_INTERVAL_S", "0"),
        ("FIELDSEAL_FACTORY_BUILD_INTERVAL_S", "3601"),
        ("FIELDSEAL_FACTORY_BUILD_INTERVAL_S", "soon"),
        ("FIELDSEAL_FACTORY_MAX_ANCHOR_AGE_S", "59"),
        ("FIELDSEAL_FACTORY_MAX_ANCHOR_AGE_S", "604801"),
    ] {
        let e = load(&env(&[(name, value)])).expect_err(value);
        assert!(e.contains(name), "{e}");
    }
    assert!(load(&env(&[("FIELDSEAL_FACTORY_BUILD_INTERVAL_S", "3600"), ("FIELDSEAL_FACTORY_MAX_ANCHOR_AGE_S", "60")])).is_ok());
}

#[test]
fn dep_023_production_refuses_the_development_adapters_the_factory_is_configured_with() {
    // There is no production custody, state store, artefact registry, roster store or bundle
    // store yet, so a production environment cannot be configured at all.
    let e = load(&env(&[("FIELDSEAL_ENVIRONMENT", "production")])).expect_err("production");
    assert!(e.contains("production"), "{e}");
}

#[test]
fn dep_012_the_new_directories_are_required() {
    for name in ["FIELDSEAL_BUNDLE_DIR", "FIELDSEAL_ISSUED_ROSTERS_DIR", "FIELDSEAL_STATE_DIR"] {
        let mut m = env(&[]);
        m.remove(name);
        let e = load(&m).expect_err(name);
        assert!(e.contains(name), "{e}");
    }
}

// covers: DEP-012
#[test]
fn sr3_b1_outside_development_the_release_policy_must_be_pinned() {
    let e = load(&env(&[("FIELDSEAL_ENVIRONMENT", "staging")])).expect_err("staging without a digest");
    assert!(e.contains("FIELDSEAL_FACTORY_POLICY_DIGEST"), "{e}");
    for bad in ["sha256:ab", "0000000000000000000000000000000000000000000000000000000000000001", "sha256:0000000000000000000000000000000000000000000000000000000000000G01"] {
        let e = load(&env(&[("FIELDSEAL_ENVIRONMENT", "staging"), ("FIELDSEAL_FACTORY_POLICY_DIGEST", bad)])).expect_err(bad);
        assert!(e.contains("FIELDSEAL_FACTORY_POLICY_DIGEST"), "{e}");
    }
    let c = load(&env(&[("FIELDSEAL_ENVIRONMENT", "staging"), ("FIELDSEAL_FACTORY_POLICY_DIGEST", DIGEST)])).expect("pinned");
    assert!(matches!(c.policy_trust, PolicyTrust::Pinned(_)));
}

// covers: DEP-012
#[test]
fn sr3_b1_development_verifies_the_release_policy_under_the_configured_allow_lists() {
    let c = load(&env(&[("FIELDSEAL_FACTORY_ALLOWED_BUILDERS", "https://b.example/x,https://b.example/y"), ("FIELDSEAL_FACTORY_ALLOWED_SOURCES", "https://s.example/z")])).expect("valid");
    assert_eq!(c.policy_trust, PolicyTrust::Allowlists { builders: vec!["https://b.example/x".into(), "https://b.example/y".into()], sources: vec!["https://s.example/z".into()] });
    assert_eq!(load(&env(&[])).expect("valid").policy_trust, PolicyTrust::Allowlists { builders: vec![], sources: vec![] });
}
