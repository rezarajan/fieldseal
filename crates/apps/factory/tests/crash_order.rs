//! The write order of a build (Technical Plan section 7.3): issued rosters, bundle, digest.
//! A hook stops the build after each step, as a crash would, and a new reconciler starts on the
//! same directories.

mod common;

use fieldseal_distribution::domain::BundleSeq;
use fieldseal_factory::reconciler::{BuildWriteHook, Outcome, WriteStep};
use fieldseal_kernel::id::TenancyId;

use common::{Env, SCHEMA_1_0, roster};

/// Fails after `step`.
struct FailAfter(WriteStep);

impl BuildWriteHook for FailAfter {
    fn after(&self, _: &TenancyId, step: WriteStep) -> Result<(), String> {
        if step == self.0 { Err("crash".into()) } else { Ok(()) }
    }
}

/// A device with a bundle at sequence 1 and a newer roster version waiting to be built.
fn world(name: &str) -> (Env, fieldseal_adapters_memory::demo::DemoDevice) {
    let env = Env::new(name);
    env.instrument("survey-a", "1.0.0", "^1.0");
    let device = env.device("a", &[("cohort-a", 1)], SCHEMA_1_0);
    env.assign("a", "survey-a", "cohort-a", 1);
    env.world.assign_rosters(&device, vec![roster("cohort-a", 1, 1)]);
    assert!(matches!(env.reconciler().run_once()[0].1, Outcome::Built(BundleSeq(1))));
    env.world.assign_rosters(&device, vec![roster("cohort-a", 2, 1)]);
    (env, device)
}

fn digest(env: &Env, device: &fieldseal_adapters_memory::demo::DemoDevice) -> String {
    std::fs::read_to_string(env.digest_file(device)).expect("digest")
}

/// Every bundle file in the tenancy's directory is whole (has its metadata) and nothing
/// temporary is left.
fn assert_no_partial_file(env: &Env, device: &fieldseal_adapters_memory::demo::DemoDevice) {
    let dir = env.digest_file(device).parent().expect("dir").to_path_buf();
    for entry in std::fs::read_dir(&dir).expect("dir").map(|e| e.expect("entry").path()) {
        let name = entry.file_name().expect("name").to_string_lossy().into_owned();
        assert!(!name.starts_with('.') && !name.ends_with(".tmp"), "a temporary file remains: {name}");
        if name.ends_with(".fsb") {
            assert!(entry.with_extension("meta").is_file(), "{name} has no metadata");
        }
    }
}

#[test]
fn dis_083_a_crash_after_record_issued_leaves_the_previous_bundle_and_the_next_pass_rebuilds() {
    let (env, device) = world("crash-issued");
    let before = digest(&env, &device);
    let crashed = env.reconciler_with(Some(Box::new(FailAfter(WriteStep::IssuedRosters)))).run_once();
    assert_eq!(crashed[0].1, Outcome::Stopped(WriteStep::IssuedRosters));
    assert_eq!(env.latest(&device).expect("stored").seq, BundleSeq(1));
    assert_eq!(digest(&env, &device), before);
    assert_eq!(env.reconciler().run_once()[0].1, Outcome::Built(BundleSeq(2)));
    assert_eq!(std::fs::read_to_string(env.issued_file(&device)).expect("recorded").matches("roster cohort-a 2 ").count(), 1, "the second pass does not record it again");
    assert_no_partial_file(&env, &device);
}

#[test]
fn dis_083_a_crash_after_the_bundle_rename_leaves_a_digest_that_does_not_claim_the_new_inputs() {
    let (env, device) = world("crash-bundle");
    let before = digest(&env, &device);
    let crashed = env.reconciler_with(Some(Box::new(FailAfter(WriteStep::Bundle)))).run_once();
    assert_eq!(crashed[0].1, Outcome::Stopped(WriteStep::Bundle));
    assert_eq!(env.latest(&device).expect("stored").seq, BundleSeq(2));
    assert_eq!(digest(&env, &device), before, "the digest still names the inputs of the bundle before");
    // The next pass sees the digest differ and builds again: no input is ever claimed without a bundle.
    assert_eq!(env.reconciler().run_once()[0].1, Outcome::Built(BundleSeq(3)));
    assert_ne!(digest(&env, &device), before);
    assert_no_partial_file(&env, &device);
}

#[test]
fn dis_083_a_crash_after_the_digest_rename_leaves_a_consistent_store() {
    let (env, device) = world("crash-digest");
    let before = digest(&env, &device);
    let crashed = env.reconciler_with(Some(Box::new(FailAfter(WriteStep::Digest)))).run_once();
    assert_eq!(crashed[0].1, Outcome::Stopped(WriteStep::Digest));
    assert_eq!(env.latest(&device).expect("stored").seq, BundleSeq(2));
    assert_ne!(digest(&env, &device), before);
    assert_eq!(env.reconciler().run_once()[0].1, Outcome::Unchanged, "bundle and digest agree: nothing is rebuilt");
    assert_no_partial_file(&env, &device);
}

#[test]
fn dis_083_no_crash_point_leaves_a_partial_bundle_file_in_the_store() {
    for step in [WriteStep::IssuedRosters, WriteStep::Bundle, WriteStep::Digest] {
        let (env, device) = world(&format!("partial-{step:?}"));
        env.reconciler_with(Some(Box::new(FailAfter(step)))).run_once();
        assert_no_partial_file(&env, &device);
        // Whatever is stored is a whole bundle that opens.
        env.open(&device, &env.latest(&device).expect("stored"));
    }
}
