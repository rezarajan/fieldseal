//! Development adapters never reach production (DEP-023, DEP-051, Technical Plan 10.1): each
//! one makes the intake app refuse to start, with exit `2`. `landing-files` is not one.

mod support;

use fieldseal_intake_app::config::Config;
use fieldseal_intake_app::dev_adapters;
use fieldseal_intake_app::{AppError, IntakeApp};
use support::*;

/// Builds the app under `production` with `extra` configuration and returns the refusal.
fn refused(name: &str, extra: &[(&str, &str)]) -> String {
    let d = Dirs::new(name);
    let mut vars = vec![("FIELDSEAL_ENVIRONMENT", "production")];
    vars.extend_from_slice(extra);
    let config = d.config(&vars);
    match IntakeApp::build(config) {
        Err(e @ AppError::Config(_)) => {
            assert_eq!(e.exit_code(), 2);
            e.to_string()
        }
        Err(e) => panic!("expected exit 2, got {e}"),
        Ok(_) => panic!("the app started in production with a development adapter"),
    }
}

// covers: DEP-023
#[test]
fn dep_023_production_refuses_file_dev_custody() {
    let d = Dirs::new("fcust");
    let bundle = d.p("bundle");
    let msg = refused("fcust2", &[("FIELDSEAL_CUSTODY", "file-dev"), ("FIELDSEAL_CUSTODY_DIR", &d.p("custody")), ("FIELDSEAL_TRUST_BUNDLE", &bundle)]);
    assert!(msg.contains("RecordKeyUnsealer=file-dev"), "{msg}");
}

// covers: DEP-023
#[test]
fn dep_023_production_refuses_memory_dev_custody() {
    assert!(refused("mcust", &[]).contains("RecordKeyUnsealer=memory-dev"));
}

// covers: DEP-023
#[test]
fn dep_023_production_refuses_a_file_submission_store() {
    assert!(refused("fsub", &[]).contains("SubmissionStore=file-dev"));
}

// covers: DEP-023
#[test]
fn dep_023_production_refuses_a_memory_submission_store() {
    let d = Dirs::new("msub");
    let mut env = d.env(&[("FIELDSEAL_ENVIRONMENT", "production")]);
    env.remove("FIELDSEAL_INTAKE_SUBMISSIONS_DIR");
    let config = Config::from_lookup(|k| env.get(k).cloned()).expect("valid");
    let e = IntakeApp::build(config).err().expect("refused");
    assert_eq!(e.exit_code(), 2);
    assert!(e.to_string().contains("SubmissionStore=memory"));
}

// covers: DEP-023
#[test]
fn dep_023_production_refuses_a_file_roster_history() {
    assert!(refused("froster", &[]).contains("RosterHistory=file-dev"));
}

// covers: DEP-023
#[test]
fn dep_023_production_refuses_a_file_instrument_source() {
    assert!(refused("finst", &[]).contains("InstrumentSource=file-dev"));
}

// covers: DEP-023
#[test]
fn dep_023_production_refuses_a_file_tenancy_registry() {
    assert!(refused("ften", &[]).contains("TenancyRegistry=file-dev"));
}

// covers: DEP-023
#[test]
fn dep_023_production_refuses_the_dev_identity() {
    assert!(refused("dev", &[("FIELDSEAL_IDENTITY", "dev")]).contains("IdentityProvider=dev"));
}

// covers: DEP-023
#[test]
fn dep_023_production_refuses_a_file_export_key() {
    assert!(refused("fkey", &[]).contains("ExportKey=file-dev"));
}

// covers: DEP-023
#[test]
fn dep_023_the_landing_files_adapter_is_not_a_development_adapter() {
    let d = Dirs::new("landing");
    let list = dev_adapters::list(&d.config(&[]));
    assert!(!list.iter().any(|(p, a)| *p == "DataPlatform" || *a == "landing-files"), "{list:?}");
}

// covers: DEP-023
#[test]
fn dep_023_development_starts_with_every_one_of_them() {
    let d = Dirs::new("devok");
    assert!(build(&d).is_ok());
}

// covers: DEP-051
#[test]
fn dep_051_the_development_adapters_event_lists_every_development_port() {
    let d = Dirs::new("event");
    let event = dev_adapters::event(&d.config(&[("FIELDSEAL_IDENTITY", "dev")]));
    for needle in ["\"service\":\"fieldseal-intake\"", "RecordKeyUnsealer", "SubmissionStore", "RosterHistory", "InstrumentSource", "TenancyRegistry", "IdentityProvider", "ExportKey"] {
        assert!(event.contains(needle), "{needle} in {event}");
    }
    assert!(!event.contains("DataPlatform"));
}
