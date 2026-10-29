//! The intake app's configuration (DEP-012, INT-089): environment only, strict.

mod support;

use std::collections::BTreeMap;

use fieldseal_intake_app::config::{Config, Custody, Identity};
use fieldseal_intake_app::{AppError, IntakeApp};
use support::*;

fn lookup(m: &BTreeMap<String, String>) -> Result<Config, String> {
    Config::from_lookup(|k| m.get(k).cloned())
}

// covers: DEP-012
#[test]
fn dep_012_every_variable_is_read_from_the_environment_only() {
    let d = Dirs::new("env");
    let c = d.config(&[("FIELDSEAL_INTAKE_PUBLIC_URLS", "http://localhost:8480,http://intake:8480"), ("FIELDSEAL_INTAKE_MAX_BODY", "1000"), ("FIELDSEAL_INTAKE_READER_ROLE", "analyst")]);
    assert_eq!(c.public_urls, vec!["http://localhost:8480", "http://intake:8480"]);
    assert_eq!(c.max_body, Some(1000));
    assert_eq!(c.reader_role, "analyst");
    assert_eq!(c.identity, Identity::Dev);
    assert_eq!(c.custody, Custody::MemoryDev);
    // No flags, no files: an empty lookup is a missing-variable error, not a default authority.
    assert!(lookup(&BTreeMap::new()).is_err());
}

// covers: DEP-012
#[test]
fn dep_012_an_empty_or_untrimmed_value_is_unusable_configuration() {
    let d = Dirs::new("trim");
    for (k, v) in [("FIELDSEAL_INTAKE_BIND", ""), ("FIELDSEAL_LANDING_DIR", " /x"), ("FIELDSEAL_INTAKE_PUBLIC_URLS", "a, b"), ("FIELDSEAL_INTAKE_MAX_BODY", "0"), ("FIELDSEAL_INTAKE_BIND", "nonsense")] {
        assert!(lookup(&d.env(&[(k, v)])).is_err(), "{k}={v:?}");
    }
}

// covers: DEP-012
#[test]
fn dep_012_flags_are_true_or_false() {
    let d = Dirs::new("flags");
    let oidc = [("FIELDSEAL_IDENTITY", "oidc"), ("FIELDSEAL_OIDC_ISSUER", "http://localhost:8180/realms/f"), ("FIELDSEAL_OIDC_CLIENT_ID", "fieldseal-intake")];
    let ok = [&oidc[..], &[("FIELDSEAL_OIDC_ASSERTED_METHODS", "true")]].concat();
    assert!(lookup(&d.env(&ok)).is_ok());
    let bad = [&oidc[..], &[("FIELDSEAL_OIDC_ASSERTED_METHODS", "yes")]].concat();
    assert!(lookup(&d.env(&bad)).is_err());
}

// covers: DEP-012
#[test]
fn dep_012_missing_required_variables_exit_2() {
    let d = Dirs::new("missing");
    for k in ["FIELDSEAL_ENVIRONMENT", "FIELDSEAL_IDENTITY", "FIELDSEAL_CUSTODY", "FIELDSEAL_TENANCY_DIR", "FIELDSEAL_LANDING_DIR", "FIELDSEAL_INTAKE_PUBLISHED_DIR", "FIELDSEAL_EXPORT_KEY_DIR", "FIELDSEAL_INTAKE_PORTAL_URL"] {
        let mut env = d.env(&[]);
        env.remove(k);
        let e = lookup(&env).expect_err(k);
        assert!(e.contains(k), "{e}");
    }
    let e = AppError::Config(String::new());
    assert_eq!(e.exit_code(), 2);
    assert_eq!(AppError::Failed(String::new()).exit_code(), 1);
}

// covers: INT-089
#[test]
fn int_089_the_results_reader_role_defaults_to_results_reader() {
    assert_eq!(Dirs::new("role").config(&[]).reader_role, "results-reader");
}

// covers: DEP-012
#[test]
fn dep_012_a_missing_wrong_length_or_wrong_mode_export_key_exits_2_and_is_never_created() {
    use std::os::unix::fs::PermissionsExt as _;
    let d = Dirs::new("key");
    let key = d.root.join("export-key/export.key");
    let attempt = |d: &Dirs| match build(d) {
        Err(e) => e,
        Ok(_) => panic!("the app started with a bad key"),
    };
    std::fs::write(&key, [1u8; 31]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(attempt(&d).exit_code(), 2);
    std::fs::write(&key, [1u8; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(attempt(&d).exit_code(), 2);
    std::fs::remove_file(&key).unwrap();
    assert_eq!(attempt(&d).exit_code(), 2);
    assert!(!exists(&key), "the app never creates the key");
    let _ = IntakeApp::build; // the app is the only code under test here
}
