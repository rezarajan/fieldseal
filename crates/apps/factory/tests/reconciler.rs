//! The reconciler (Technical Plan section 7.3) over the in-memory demo authority, with file
//! stores for bundles and issued rosters in a scratch directory.

mod common;

use fieldseal_distribution::domain::{BundleAssignment, BundleContent, BundleSeq};
use fieldseal_distribution::ports::BundleStore as _;
use fieldseal_registration::ports::RegistryStore as _;
use fieldseal_factory::reconciler::{Outcome, ReconcileEvent};
use fieldseal_instrument::domain::SchemaVersion;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_registration::domain::TenancyState;

use common::{Env, HOUR, SCHEMA_1_0, roster};

/// One device in `cohort-a` assigned `survey-a`, with a published instrument and a roster.
fn basic(name: &str) -> (Env, fieldseal_adapters_memory::demo::DemoDevice, fieldseal_publishing::domain::Publication) {
    let env = Env::new(name);
    let instrument = env.instrument("survey-a", "1.0.0", "^1.0");
    let device = env.device("a", &[("cohort-a", 1)], SCHEMA_1_0);
    env.assign("a", "survey-a", "cohort-a", 1);
    env.world.assign_rosters(&device, vec![roster("cohort-a", 1, 1)]);
    (env, device, instrument)
}

fn built(outcomes: &[(fieldseal_kernel::id::TenancyId, Outcome)]) -> Vec<u64> {
    outcomes.iter().filter_map(|(_, o)| if let Outcome::Built(s) = o { Some(s.0) } else { None }).collect()
}

#[test]
fn dis_082_registration_builds_sequence_one() {
    let (env, device, instrument) = basic("seq1");
    let r = env.reconciler();
    assert_eq!(built(&r.run_once()), vec![1]);
    let bundle = env.latest(&device).expect("stored");
    let content = env.open(&device, &bundle);
    assert_eq!(content.instruments.iter().map(|p| *p.address()).collect::<Vec<_>>(), vec![*instrument.address()]);
    assert!(env.digest_file(&device).is_file());
    assert!(env.events().iter().any(|e| matches!(e, ReconcileEvent::Built { seq: 1, .. })));
}

#[test]
fn wire_094_the_bundle_carries_the_assignments_of_the_journal() {
    let (env, device, instrument) = basic("assignments");
    let r = env.reconciler();
    r.run_once();
    let cohort = fieldseal_kernel::id::CohortId::new("cohort-a").expect("id");
    let first = BundleAssignment { survey: "survey-a".into(), instrument: *instrument.address(), cohort: cohort.clone(), generation: fieldseal_kernel::id::Generation(1) };
    let content = env.open(&device, &env.latest(&device).expect("stored"));
    assert_eq!(content.assignments, vec![first.clone()], "the survey is linked to the cohort the journal says");
    assert_eq!(BundleContent::decode(&content.encode().expect("encodes")).expect("decodes"), content, "the assignments round-trip");

    // A second survey for the same cohort is a second assignment, in survey order.
    let second = env.instrument("survey-b", "1.0.0", "^1.0");
    env.assign("a", "survey-b", "cohort-a", 1);
    assert_eq!(built(&r.reconcile_all(&[device.tenancy])), vec![2]);
    let content = env.open(&device, &env.latest(&device).expect("stored"));
    let b = BundleAssignment { survey: "survey-b".into(), instrument: *second.address(), cohort, generation: fieldseal_kernel::id::Generation(1) };
    assert_eq!(content.assignments, vec![first, b]);
    assert_eq!(content.manifest().assignments, content.assignments, "the manifest lists them too");

    // An assignment to a cohort the bundle holds no roster for is not a bundle.
    let mut bad = content;
    bad.assignments[0].cohort = fieldseal_kernel::id::CohortId::new("elsewhere").expect("id");
    assert!(BundleContent::decode(&bad.encode().expect("encodes")).is_err());
}

#[test]
fn dis_018_a_survey_assigned_to_two_cohorts_carries_both_assignments() {
    let env = Env::new("two-cohorts");
    let instrument = env.instrument("survey-a", "1.0.0", "^1.0");
    let device = env.device("a", &[("cohort-a", 1), ("cohort-b", 1)], SCHEMA_1_0);
    env.assign("a", "survey-a", "cohort-a", 1);
    env.assign("a", "survey-a", "cohort-b", 1);
    env.world.assign_rosters(&device, vec![roster("cohort-a", 1, 1), roster("cohort-b", 1, 1)]);
    env.reconciler().run_once();
    let content = env.open(&device, &env.latest(&device).expect("stored"));
    let cohorts: Vec<_> = content.assignments.iter().map(|a| (a.survey.as_str(), a.cohort.as_str(), a.instrument)).collect();
    assert_eq!(cohorts, vec![("survey-a", "cohort-a", *instrument.address()), ("survey-a", "cohort-b", *instrument.address())]);
}

#[test]
fn dis_018_an_assignment_without_a_roster_is_left_out_of_the_bundle() {
    let (env, device, instrument) = basic("no-roster");
    // The journal is ahead of the tenancy: cohort-b has no roster in this build.
    env.assign("a", "survey-a", "cohort-b", 1);
    env.reconciler().run_once();
    let content = env.open(&device, &env.latest(&device).expect("stored"));
    assert_eq!(content.assignments.len(), 1);
    assert_eq!(content.assignments[0].cohort.as_str(), "cohort-a");
    assert_eq!(content.assignments[0].instrument, *instrument.address());
}

#[test]
fn dis_018_an_instrument_whose_assignments_were_all_left_out_is_not_carried() {
    let (env, device, instrument) = basic("dropped-instrument");
    // survey-b is published and assigned, but only to a cohort this build holds no roster for.
    env.instrument("survey-b", "1.0.0", "^1.0");
    env.assign("a", "survey-b", "cohort-b", 1);
    env.reconciler().run_once();
    let content = env.open(&device, &env.latest(&device).expect("stored"));
    assert_eq!(content.instruments.iter().map(|p| *p.address()).collect::<Vec<_>>(), vec![*instrument.address()], "survey-b is not carried, so a device can't conduct it");
    assert_eq!(content.assignments.len(), 1);
}

#[test]
fn dis_018_when_no_assignment_survives_the_bundle_carries_no_instrument() {
    let env = Env::new("none-survive");
    env.instrument("survey-a", "1.0.0", "^1.0");
    let device = env.device("a", &[("cohort-a", 1)], SCHEMA_1_0);
    // The only assignment is to a cohort the tenancy holds no roster for.
    env.assign("a", "survey-a", "cohort-b", 1);
    env.world.assign_rosters(&device, vec![roster("cohort-a", 1, 1)]);
    env.reconciler().run_once();
    let content = env.open(&device, &env.latest(&device).expect("stored"));
    assert!(content.instruments.is_empty(), "nothing is left to conduct, and an empty list of assignments must not mean everything");
    assert!(content.assignments.is_empty());
    assert_eq!(content.rosters.len(), 1);
    assert_eq!(BundleContent::decode(&content.encode().expect("encodes")).expect("decodes"), content);
}

#[test]
fn dis_082_a_new_publication_builds_the_next_sequence() {
    let (env, device, _) = basic("newpub");
    let r = env.reconciler();
    r.run_once();
    let v2 = env.instrument("survey-a", "1.1.0", "^1.0");
    assert_eq!(built(&r.run_once()), vec![2]);
    assert_eq!(env.open(&device, &env.latest(&device).expect("stored")).instruments[0].address(), v2.address());
}

#[test]
fn dis_082_a_new_roster_version_builds_the_next_sequence() {
    let (env, device, _) = basic("newroster");
    let r = env.reconciler();
    r.run_once();
    env.world.assign_rosters(&device, vec![roster("cohort-a", 2, 1)]);
    assert_eq!(built(&r.run_once()), vec![2]);
    assert_eq!(env.open(&device, &env.latest(&device).expect("stored")).rosters[0].version, 2);
}

#[test]
fn dis_082_an_assignment_rebuilds_without_a_restart() {
    let (env, device, _) = basic("assign");
    let r = env.reconciler();
    r.run_once();
    env.instrument("survey-b", "1.0.0", "^1.0");
    env.assign("a", "survey-b", "cohort-a", 1);
    // A notification, not the scan, triggers it.
    assert_eq!(built(&r.reconcile_all(&[device.tenancy])), vec![2]);
    assert_eq!(env.open(&device, &env.latest(&device).expect("stored")).instruments.len(), 2);
}

#[test]
fn dis_082_a_roster_issue_rebuilds_without_a_restart() {
    let (env, device, _) = basic("issue");
    let r = env.reconciler();
    r.run_once();
    env.world.assign_rosters(&device, vec![roster("cohort-a", 4, 1)]);
    assert_eq!(built(&r.reconcile_all(&[device.tenancy])), vec![2]);
}

#[test]
fn dis_082_an_assignment_that_changes_the_cohort_set_brings_the_reissued_certificate_in_the_next_bundle() {
    let (env, device, _) = basic("cert");
    let r = env.reconciler();
    r.run_once();
    let before = env.open(&device, &env.latest(&device).expect("stored")).certificate.expect("certificate");
    // The registration use case reissues the certificate with the new cohort set; here the
    // record is changed the way it does.
    let mut record = env.world.registry.tenancy(&device.tenancy).expect("store").expect("tenancy");
    record.cohorts.push(fieldseal_registration::domain::CohortAssignment { cohort: fieldseal_kernel::id::CohortId::new("cohort-b").expect("id"), generation: fieldseal_kernel::id::Generation(1) });
    let mut cert = record.certificate.clone().expect("certificate");
    cert.cohorts = record.cohorts.clone();
    cert.issued_at = AuthorityTime(cert.issued_at.0 + 1);
    record.certificate = Some(cert);
    env.world.registry.put_tenancy(&record).expect("put");
    env.instrument("survey-b", "1.0.0", "^1.0");
    env.assign("a", "survey-b", "cohort-b", 1);
    env.world.assign_rosters(&device, vec![roster("cohort-a", 1, 1), roster("cohort-b", 1, 1)]);
    assert_eq!(built(&r.reconcile_all(&[device.tenancy])), vec![2]);
    let after = env.open(&device, &env.latest(&device).expect("stored")).certificate.expect("certificate");
    assert_eq!((before.cohorts.len(), after.cohorts.len()), (1, 2));
}

#[test]
fn dis_083_an_unchanged_input_digest_builds_nothing() {
    let (env, device, _) = basic("idempotent");
    let r = env.reconciler();
    r.run_once();
    assert_eq!(r.run_once().iter().map(|(_, o)| o.clone()).collect::<Vec<_>>(), vec![Outcome::Unchanged]);
    assert_eq!(env.latest(&device).expect("stored").seq, BundleSeq(1));
}

#[test]
fn dis_083_a_restart_builds_nothing_new() {
    let (env, device, _) = basic("restart");
    env.reconciler().run_once();
    let restarted = env.reconciler();
    assert_eq!(restarted.run_once().into_iter().map(|(_, o)| o).collect::<Vec<_>>(), vec![Outcome::Unchanged]);
    assert_eq!(env.latest(&device).expect("stored").seq, BundleSeq(1));
}

#[test]
fn dis_010_a_bundle_whose_anchor_is_older_than_the_maximum_age_is_rebuilt_with_the_next_sequence() {
    let (env, device, _) = basic("stale");
    let r = env.reconciler();
    r.run_once();
    env.clock.advance(25 * HOUR);
    assert_eq!(built(&r.run_once()), vec![2]);
    let bundle = env.latest(&device).expect("stored");
    assert!(bundle.issued.0 > 24 * HOUR + common::T0.0 + 24 * HOUR, "the new anchor is the current time");
}

#[test]
fn dis_010_a_fresh_anchor_with_an_unchanged_digest_builds_nothing() {
    let (env, device, _) = basic("fresh");
    let r = env.reconciler();
    r.run_once();
    env.clock.advance(23 * HOUR);
    assert_eq!(built(&r.run_once()), Vec::<u64>::new());
    assert_eq!(env.latest(&device).expect("stored").seq, BundleSeq(1));
}

#[test]
fn dis_013_two_accounts_get_only_their_own_cohorts() {
    let (env, a, _) = basic("accounts");
    let b = env.device("b", &[("cohort-b", 1)], SCHEMA_1_0);
    env.assign("b", "survey-a", "cohort-b", 1);
    env.world.assign_rosters(&b, vec![roster("cohort-b", 1, 1)]);
    env.reconciler().run_once();
    let cohorts = |d| env.open(d, &env.latest(d).expect("stored")).rosters.iter().map(|r| r.cohort.as_str().to_owned()).collect::<Vec<_>>();
    assert_eq!((cohorts(&a), cohorts(&b)), (vec!["cohort-a".to_owned()], vec!["cohort-b".to_owned()]));
}

#[test]
fn reg_041_a_retired_tenancy_frees_the_cohort_slot_for_the_accounts_new_device() {
    let (env, old, _) = basic("retired");
    let r = env.reconciler();
    r.run_once();
    env.world.set_state(&old.tenancy, TenancyState::Retired).expect("state");
    env.world.assign_rosters(&old, vec![]);
    // The account's new device registers in the cohort the old one held.
    let new = env.world.register("a2", &[("cohort-a", 1)], true, common::profile(SCHEMA_1_0)).expect("registers");
    let mut record = env.world.registry.tenancy(&new.tenancy).expect("store").expect("tenancy");
    record.account = Env::account("a");
    env.world.registry.put_tenancy(&record).expect("put");
    env.world.assign_rosters(&new, vec![roster("cohort-a", 1, 1)]);
    let outcomes = r.run_once();
    assert!(outcomes.iter().any(|(t, o)| *t == new.tenancy && matches!(o, Outcome::Built(_))), "{outcomes:?}");
    assert!(outcomes.iter().any(|(t, o)| *t == old.tenancy && matches!(o, Outcome::Withheld(_))));
}

#[test]
fn reg_041_a_second_active_tenancy_of_one_cohort_is_held_by_the_cohort_limit() {
    // The release policy allows one other active tenancy per cohort at most: with two in
    // `cohort-a`, `bundle.release` holds both back until one is retired.
    let (env, first, _) = basic("limit");
    let second = env.device("a2", &[("cohort-a", 1)], SCHEMA_1_0);
    env.assign("a2", "survey-a", "cohort-a", 1);
    env.world.assign_rosters(&second, vec![roster("cohort-a", 1, 1)]);
    let outcomes = env.reconciler().run_once();
    assert!(outcomes.iter().all(|(_, o)| matches!(o, Outcome::Withheld(r) if r.contains("cohort"))), "{outcomes:?}");
    assert!(env.latest(&first).is_none() && env.latest(&second).is_none());
}

#[test]
fn dis_083_a_failed_build_keeps_the_previous_bundle() {
    let (env, device, _) = basic("failed");
    let r = env.reconciler();
    r.run_once();
    // The roster of a cohort the tenancy does not hold fails the build (DIS-014).
    env.world.assign_rosters(&device, vec![roster("cohort-a", 2, 7)]);
    let outcomes = r.run_once();
    assert!(matches!(outcomes[0].1, Outcome::Failed(_)), "{outcomes:?}");
    assert_eq!(env.latest(&device).expect("stored").seq, BundleSeq(1));
    assert!(env.events().iter().any(|e| matches!(e, ReconcileEvent::Failed { .. })));
}

#[test]
fn dis_003_a_lost_retired_or_flagged_tenancy_gets_no_new_bundle() {
    for state in [TenancyState::Lost, TenancyState::Retired, TenancyState::Flagged] {
        let (env, device, _) = basic(&format!("state-{}", state.as_str()));
        let r = env.reconciler();
        r.run_once();
        env.world.set_state(&device.tenancy, state).expect("state");
        env.world.assign_rosters(&device, vec![roster("cohort-a", 2, 1)]);
        let outcomes = r.run_once();
        assert!(matches!(outcomes[0].1, Outcome::Withheld(_)), "{state:?}: {outcomes:?}");
        assert_eq!(env.latest(&device).expect("stored").seq, BundleSeq(1));
        assert!(env.events().iter().any(|e| matches!(e, ReconcileEvent::Withheld { reason, .. } if reason.starts_with("tenancy-"))));
    }
}

#[test]
fn dis_075_a_build_with_an_unpublished_artefact_releases_nothing() {
    let (env, device, _) = basic("unpublished");
    // A layout that is published but whose instrument is not in the bundle cannot be released:
    // an instrument version missing from the registry makes the build fail, not pass.
    let ghost = fieldseal_kernel::id::ContentAddress::of(b"not published");
    let mut request = fieldseal_distribution::application::BuildRequest::new(device.tenancy, vec![ghost]);
    request.layouts = vec![];
    assert!(env.world.build(&env.world.built_in_policy(), &request).is_err());
    assert!(env.latest(&device).is_none());
}

#[test]
fn dis_002_with_no_published_policy_nothing_is_built_and_no_policy_is_recorded() {
    let env = Env::new("nopolicy");
    // A world with no deployment policy: withdraw the one the helper published.
    env.world.withdraw(&env.policy, "test").expect("withdraws");
    env.instrument("survey-a", "1.0.0", "^1.0");
    let device = env.device("a", &[("cohort-a", 1)], SCHEMA_1_0);
    env.assign("a", "survey-a", "cohort-a", 1);
    env.world.assign_rosters(&device, vec![roster("cohort-a", 1, 1)]);
    let outcomes = env.reconciler().run_once();
    assert_eq!(outcomes[0].1, Outcome::Withheld("no-policy".into()));
    assert!(env.latest(&device).is_none());
    assert!(!env.issued_file(&device).exists());
    // Once a policy is published the next pass builds.
    env.publish_policy("2.0.0", None);
    assert_eq!(built(&env.reconciler().run_once()), vec![1]);
}

#[test]
fn dis_012_the_highest_non_withdrawn_version_the_runtime_can_run_is_bundled() {
    let (env, device, _) = basic("highest");
    env.instrument("survey-a", "1.2.0", "^1.0");
    let v3 = env.instrument("survey-a", "2.0.0", "^1.0");
    env.instrument("survey-a", "1.10.0", "^1.0");
    env.reconciler().run_once();
    let content = env.open(&device, &env.latest(&device).expect("stored"));
    assert_eq!(content.instruments[0].address(), v3.address(), "2.0.0 outranks 1.10.0 and 1.2.0");
}

#[test]
fn dis_012_a_withdrawn_version_is_never_bundled() {
    let (env, device, v1) = basic("withdrawn");
    let v2 = env.instrument("survey-a", "2.0.0", "^1.0");
    env.world.withdraw(&v2, "mistake").expect("withdraws");
    env.reconciler().run_once();
    let content = env.open(&device, &env.latest(&device).expect("stored"));
    assert_eq!(content.instruments[0].address(), v1.address());
}

#[test]
fn dis_012_a_tenancy_whose_runtime_reported_an_older_schema_gets_no_instrument_it_cannot_run() {
    let env = Env::new("older");
    env.instrument("survey-a", "1.0.0", "^1.1");
    let device = env.device("a", &[("cohort-a", 1)], SchemaVersion { major: 1, minor: 0, patch: 0 });
    env.assign("a", "survey-a", "cohort-a", 1);
    env.world.assign_rosters(&device, vec![roster("cohort-a", 1, 1)]);
    let outcomes = env.reconciler().run_once();
    assert_eq!(outcomes[0].1, Outcome::Withheld("instrument-incompatible".into()));
    assert!(env.latest(&device).is_none());
    // The runtime that reports 1.1 gets it.
    let newer = env.device("b", &[("cohort-b", 1)], SchemaVersion { major: 1, minor: 1, patch: 0 });
    env.assign("b", "survey-a", "cohort-b", 1);
    env.world.assign_rosters(&newer, vec![roster("cohort-b", 1, 1)]);
    assert_eq!(built(&env.reconciler().run_once()), vec![1]);
}

#[test]
fn dis_077_the_profile_used_is_the_one_recorded_at_registration() {
    let env = Env::new("profile");
    env.instrument("survey-a", "1.0.0", "^1.0");
    let device = env.device("a", &[("cohort-a", 1)], SCHEMA_1_0);
    env.assign("a", "survey-a", "cohort-a", 1);
    env.world.assign_rosters(&device, vec![roster("cohort-a", 1, 1)]);
    // A tenancy with no recorded profile is withheld, never given a default.
    let ghost = env.world.register("ghost", &[("cohort-g", 1)], true, common::profile(SCHEMA_1_0)).expect("registers");
    env.world.profiles.forget(&ghost.tenancy);
    env.assign("ghost", "survey-a", "cohort-g", 1);
    env.world.assign_rosters(&ghost, vec![roster("cohort-g", 1, 1)]);
    let outcomes = env.reconciler().run_once();
    let of = |t| outcomes.iter().find(|(x, _)| *x == t).map(|(_, o)| o.clone());
    assert!(matches!(of(device.tenancy), Some(Outcome::Built(_))));
    assert_eq!(of(ghost.tenancy), Some(Outcome::Withheld("runtime-profile-unknown".into())));
}

fn layouts_of(env: &Env, device: &fieldseal_adapters_memory::demo::DemoDevice) -> Vec<String> {
    let mut names: Vec<String> = env.open(device, &env.latest(device).expect("stored")).layouts.iter().map(|l| format!("{}@{}", l.artefact.name(), l.artefact.version())).collect();
    names.sort();
    names
}

#[test]
fn dis_016_the_default_bundles_every_bound_layout_newest_per_window_class() {
    let (env, device, v1) = basic("layouts");
    env.layout("survey-a", "compact", "1.0.0", &v1);
    env.layout("survey-a", "compact", "1.1.0", &v1);
    env.layout("survey-a", "medium", "1.0.0", &v1);
    env.reconciler().run_once();
    assert_eq!(layouts_of(&env, &device), vec!["survey-a-compact@1.1.0", "survey-a-medium@1.0.0"]);
}

#[test]
fn ins_207_at_most_one_layout_per_window_class() {
    let (env, device, v1) = basic("oneclass");
    for v in ["1.0.0", "1.0.1", "1.0.2"] {
        env.layout("survey-a", "expanded", v, &v1);
    }
    env.reconciler().run_once();
    assert_eq!(layouts_of(&env, &device), vec!["survey-a-expanded@1.0.2"]);
}

#[test]
fn dis_016_an_explicit_none_bundles_no_layout() {
    let env = Env::with_layouts("nolayouts", Some("none"));
    let v1 = env.instrument("survey-a", "1.0.0", "^1.0");
    env.layout("survey-a", "compact", "1.0.0", &v1);
    let device = env.device("a", &[("cohort-a", 1)], SCHEMA_1_0);
    env.assign("a", "survey-a", "cohort-a", 1);
    env.world.assign_rosters(&device, vec![roster("cohort-a", 1, 1)]);
    env.reconciler().run_once();
    assert!(layouts_of(&env, &device).is_empty());
}

#[test]
fn dis_016_a_layout_bound_to_another_fingerprint_is_never_included() {
    let (env, device, v1) = basic("otherfp");
    let v2 = env.instrument("survey-a", "2.0.0", "^1.0");
    // Bound to the older version; the bundle carries 2.0.0.
    env.layout("survey-a", "compact", "1.0.0", &v1);
    env.reconciler().run_once();
    assert!(layouts_of(&env, &device).is_empty());
    assert_eq!(env.open(&device, &env.latest(&device).expect("stored")).instruments[0].address(), v2.address());
}

#[test]
fn dis_016_layouts_are_found_by_the_name_survey_hyphen_window() {
    let (env, device, v1) = basic("named");
    // A layout under another survey's name is not this survey's.
    env.world.publish(fieldseal_publishing::domain::ArtefactKind::Layout, "other-compact", "0.9.0", common::layout_bytes(v1.address(), "compact", "0.9.0"), None).expect("publishes");
    env.layout("survey-a", "compact", "1.0.0", &v1);
    env.reconciler().run_once();
    assert_eq!(layouts_of(&env, &device), vec!["survey-a-compact@1.0.0"]);
}

#[test]
fn dis_002_the_bundle_release_decision_gates_roster_release() {
    // An unattested key gets no roster unless the factory allows it; the decision is asked
    // before the roster is recorded as issued.
    let env = Env::new("gate");
    env.instrument("survey-a", "1.0.0", "^1.0");
    let device = env.world.register("soft", &[("cohort-a", 1)], false, common::profile(SCHEMA_1_0)).expect("registers");
    env.assign("soft", "survey-a", "cohort-a", 1);
    env.world.assign_rosters(&device, vec![roster("cohort-a", 1, 1)]);
    let strict = env.reconciler_strict();
    let outcomes = strict.run_once();
    assert!(matches!(outcomes[0].1, Outcome::Withheld(_)), "{outcomes:?}");
    assert!(env.latest(&device).is_none());
    assert!(!env.issued_file(&device).exists(), "a withheld bundle records no issued roster");
}

#[test]
fn dep_051_build_events_carry_no_subject_data() {
    let (env, device, _) = basic("events");
    env.reconciler().run_once();
    env.world.set_state(&device.tenancy, TenancyState::Lost).expect("state");
    env.reconciler().run_once();
    let text = format!("{:?}", env.events());
    for needle in ["s-001", "s-002", "Person", "account-a", "North"] {
        assert!(!text.contains(needle), "{needle} in {text}");
    }
}

#[test]
fn int_040_issued_rosters_are_recorded_for_intake_with_restricted_fields() {
    let (env, device, _) = basic("issued");
    env.reconciler().run_once();
    let recorded = std::fs::read_to_string(env.issued_file(&device)).expect("recorded");
    assert!(recorded.contains("roster cohort-a 1 "), "{recorded}");
    // Subjects as intake names them: the hex of the roster identifier's bytes (INT-051).
    assert!(recorded.contains("consent 732d303031=granted") && recorded.contains("consent 732d303032=unknown"), "{recorded}");
    // The address is that of the roster as the bundle carries it: only the fields the
    // instrument reads (`age`, not `district`).
    let bundle = env.open(&device, &env.latest(&device).expect("stored"));
    let carried = &bundle.rosters[0];
    assert!(carried.entries.iter().all(|e| e.attributes.contains_key("age") && !e.attributes.contains_key("district")));
    let address = fieldseal_kernel::digest::lower_hex(fieldseal_kernel::id::ContentAddress::of(&carried.encode()).as_bytes());
    assert!(recorded.contains(&address));
    // The surveys the roster's consent covers travel in the bundle and are recorded for intake (INT-031).
    assert_eq!(carried.consent_covers, ["survey-a"]);
    assert!(recorded.contains("covers survey-a\n"), "{recorded}");
    // A rebuild for the same roster does not record it twice.
    env.clock.advance(25 * HOUR);
    env.reconciler().run_once();
    assert_eq!(std::fs::read_to_string(env.issued_file(&device)).expect("recorded").matches("roster cohort-a 1 ").count(), 1);
}

// --- The release policy is verified against what the factory trusts (SR-3 B1, M2, M3) ---

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fieldseal_adapters_memory::demo::DemoWorld;
use fieldseal_factory::reconciler::{BuildWriteHook, WriteStep};
use fieldseal_policy::domain::Threshold;
use fieldseal_publishing::domain::ArtefactKind;
use fieldseal_publishing::ports::ArtefactRegistry as _;
use fieldseal_trust::ports::KeyCustody as _;

/// A publishing policy that one publisher key satisfies: what a key that writes its own release
/// policy would set.
fn lowered(world: &DemoWorld) -> fieldseal_policy::domain::PublishingPolicy {
    let mut p = world.publishing.clone();
    for k in p.kinds.values_mut() {
        k.publisher_threshold = Threshold { m: 1, n: 2 };
        k.withdrawal_threshold = Threshold { m: 1, n: 2 };
    }
    p
}

fn forged_policy(env: &Env, version: &str) {
    let doc = fieldseal_policy::fixtures::DocBuilder::deployment("deployment-policy", version);
    let bytes = fieldseal_kernel::cbor::encode(&doc.build()).expect("encodes");
    env.world
        .publish_under(&lowered(&env.world), &env.world.publishers[..1], ArtefactKind::Policy, "deployment-policy", version, bytes, None)
        .expect("a lowered threshold lets one key publish");
}

// covers: DIS-002
#[test]
fn sr3_b1_a_policy_signed_by_one_key_that_lowers_its_own_threshold_is_refused() {
    let (env, device, _) = basic("forged-policy");
    forged_policy(&env, "99.0.0");
    let r = env.reconciler();
    assert_eq!(built(&r.run_once()), vec![1], "the genuine 1.0.0 policy is used, not the forged 99.0.0");
    assert!(env.events().iter().any(|e| matches!(e, ReconcileEvent::Skipped { kind, version, .. } if kind == "Policy" && version == "99.0.0")), "{:?}", env.events());
    assert!(env.latest(&device).is_some());
}

// covers: DIS-002
#[test]
fn sr3_b1_with_only_a_forged_policy_nothing_is_built() {
    let (env, device, _) = basic("only-forged-policy");
    env.world.withdraw(&env.policy, "test").expect("withdraws");
    forged_policy(&env, "99.0.0");
    let outcomes = env.reconciler().run_once();
    assert_eq!(outcomes[0].1, Outcome::Failed("policy-unverified".into()));
    assert!(env.latest(&device).is_none());
}

// covers: DIS-002
#[test]
fn sr3_b1_a_pinned_policy_is_the_only_one_read() {
    use fieldseal_factory::config::PolicyTrust;
    let (env, device, _) = basic("pinned");
    let newer = env.publish_policy("2.0.0", Some("none"));
    let mut r = env.reconciler();
    r.set_policy_trust(PolicyTrust::Pinned(*env.policy.address()));
    assert_eq!(built(&r.run_once()), vec![1]);
    assert!(!env.open(&device, &env.latest(&device).expect("stored")).policy.iter().any(|p| p.address() == newer.address()));
    r.set_policy_trust(PolicyTrust::Pinned(fieldseal_kernel::id::ContentAddress::of(b"another policy")));
    env.clock.advance(25 * HOUR);
    assert_eq!(r.run_once()[0].1, Outcome::Withheld("no-policy".into()));
}

fn other_authority_withdrawal(publication: &fieldseal_publishing::domain::Publication) -> fieldseal_publishing::domain::Withdrawal {
    // Another world signs a withdrawal of the same artefact: its keys are not in this trust bundle.
    let other = DemoWorld::new(2, common::T0).expect("world");
    let copy = other
        .publish(ArtefactKind::Instrument, publication.artefact.name(), publication.artefact.version(), publication.artefact.canonical_bytes().to_vec(), Some(DemoWorld::salt_for(publication.artefact.name())))
        .expect("publishes");
    other.withdraw(&copy, "forged").expect("withdraws")
}

// covers: DIS-011
#[test]
fn sr3_m2_a_forged_withdrawal_withdraws_nothing() {
    let (env, device, _) = basic("forged-withdrawal");
    let v2 = env.instrument("survey-a", "2.0.0", "^1.0");
    let forged = other_authority_withdrawal(&v2);
    assert_eq!(forged.address(), v2.address());
    env.world.artefacts.withdraw(&forged).expect("recorded");
    env.reconciler().run_once();
    assert_eq!(env.open(&device, &env.latest(&device).expect("stored")).instruments[0].address(), v2.address());
}

// covers: DIS-011
#[test]
fn sr3_m3_a_forged_higher_version_is_skipped_and_the_next_is_built() {
    let (env, device, v1) = basic("forged-instrument");
    let bytes = common::instrument_bytes("survey-a", "9.0.0", "^1.0");
    env.world
        .publish_under(&lowered(&env.world), &env.world.publishers[..1], ArtefactKind::Instrument, "survey-a", "9.0.0", bytes, Some(DemoWorld::salt_for("survey-a")))
        .expect("publishes under a lowered threshold");
    assert_eq!(built(&env.reconciler().run_once()), vec![1]);
    assert_eq!(env.open(&device, &env.latest(&device).expect("stored")).instruments[0].address(), v1.address());
    assert!(env.events().iter().any(|e| matches!(e, ReconcileEvent::Skipped { kind, name, version, .. } if kind == "Instrument" && name == "survey-a" && version == "9.0.0")));
}

// --- Failures, holds and polling (SR-3 m7, SR2-M2, m11) ---

struct Counting(Arc<AtomicUsize>);

impl BuildWriteHook for Counting {
    fn after(&self, _: &fieldseal_kernel::id::TenancyId, step: WriteStep) -> Result<(), String> {
        if step == WriteStep::IssuedRosters {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

// covers: DIS-083
#[test]
fn sr3_m7_a_failed_build_is_retried_only_after_a_backoff_or_when_its_inputs_change() {
    let (env, device, _) = basic("backoff");
    let attempts = Arc::new(AtomicUsize::new(0));
    let r = env.reconciler_with(Some(Box::new(Counting(attempts.clone()))));
    r.run_once();
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    // A roster of a generation the tenancy does not hold fails every build.
    env.world.assign_rosters(&device, vec![roster("cohort-a", 2, 7)]);
    assert!(matches!(r.run_once()[0].1, Outcome::Failed(_)));
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(matches!(r.run_once()[0].1, Outcome::Failed(_)));
    assert_eq!(attempts.load(Ordering::SeqCst), 2, "the same inputs are not built again at once");
    env.clock.advance(5_001);
    r.run_once();
    assert_eq!(attempts.load(Ordering::SeqCst), 3, "the first backoff is 5 s");
    env.clock.advance(5_001);
    r.run_once();
    assert_eq!(attempts.load(Ordering::SeqCst), 3, "the second backoff is 10 s");
    env.clock.advance(5_000);
    r.run_once();
    assert_eq!(attempts.load(Ordering::SeqCst), 4);
    env.world.assign_rosters(&device, vec![roster("cohort-a", 3, 8)]);
    r.run_once();
    assert_eq!(attempts.load(Ordering::SeqCst), 5, "new inputs are tried at once");
}

// covers: DIS-003
#[test]
fn sr2_m2_a_policy_hold_leaves_a_marker_that_the_next_build_clears() {
    use fieldseal_distribution::ports::BundleStore as _;
    let env = Env::new("hold");
    env.instrument("survey-a", "1.0.0", "^1.0");
    let device = env.world.register("soft", &[("cohort-a", 1)], false, common::profile(SCHEMA_1_0)).expect("registers");
    env.assign("soft", "survey-a", "cohort-a", 1);
    env.world.assign_rosters(&device, vec![roster("cohort-a", 1, 1)]);
    assert_eq!(built(&env.reconciler().run_once()), vec![1]);
    assert_eq!(env.bundles.withheld(&device.tenancy).expect("store"), None);
    // The next roster version meets a factory that does not allow unattested keys.
    env.world.assign_rosters(&device, vec![roster("cohort-a", 2, 1)]);
    assert!(matches!(env.reconciler_strict().run_once()[0].1, Outcome::Withheld(_)));
    assert!(env.bundles.withheld(&device.tenancy).expect("store").is_some(), "the stored bundle is no longer delivered");
    assert_eq!(built(&env.reconciler().run_once()), vec![2]);
    assert_eq!(env.bundles.withheld(&device.tenancy).expect("store"), None);
}

// covers: DIS-003
#[test]
fn sr2_m2_a_hold_that_appears_after_a_build_stops_the_stored_bundle_though_the_inputs_are_unchanged() {
    use fieldseal_distribution::application::{BundleDelivery, FetchBundle as _};
    use fieldseal_distribution::domain::DistributionError;
    let (env, first, _) = basic("late-hold");
    let r = env.reconciler();
    assert_eq!(built(&r.run_once()), vec![1]);
    let delivery = BundleDelivery::new(&env.world.registry, &env.bundles);
    assert!(delivery.fetch(&first.tenancy, None).is_ok());
    // A second tenancy becomes active in the cohort: nothing the first one's digest covers changed.
    let second = env.device("a2", &[("cohort-a", 1)], SCHEMA_1_0);
    env.world.assign_rosters(&second, vec![roster("cohort-a", 1, 1)]);
    let outcomes = r.reconcile_all(&[first.tenancy]);
    assert!(matches!(&outcomes[0].1, Outcome::Withheld(why) if why.contains("cohort-tenancy-limit")), "{outcomes:?}");
    let marker = env.bundles.withheld(&first.tenancy).expect("store").expect("marked");
    assert!(marker.iter().any(|m| m == "cohort-tenancy-limit"), "{marker:?}");
    assert!(matches!(delivery.fetch(&first.tenancy, None), Err(DistributionError::Withheld(r)) if r.iter().any(|m| m == "cohort-tenancy-limit")));
}

// covers: DIS-003
#[test]
fn sr2_m2_a_policy_fault_withholds_every_tenancy_the_pass_covers() {
    let (env, device, _) = basic("policy-fault");
    let r = env.reconciler();
    assert_eq!(built(&r.run_once()), vec![1]);
    assert_eq!(env.bundles.withheld(&device.tenancy).expect("store"), None);
    // No policy can be read any more.
    env.world.withdraw(&env.policy, "test").expect("withdraws");
    env.clock.advance(25 * HOUR);
    assert_eq!(r.run_once()[0].1, Outcome::Withheld("no-policy".into()));
    assert_eq!(env.bundles.withheld(&device.tenancy).expect("store"), Some(vec!["no-policy".to_owned()]));
    // A policy that cannot be verified is a failed pass, and it holds the tenancy as well.
    let (env, device, _) = basic("policy-unverified");
    let r = env.reconciler();
    assert_eq!(built(&r.run_once()), vec![1]);
    env.world.withdraw(&env.policy, "test").expect("withdraws");
    forged_policy(&env, "99.0.0");
    env.clock.advance(25 * HOUR);
    assert_eq!(r.run_once()[0].1, Outcome::Failed("policy-unverified".into()));
    assert_eq!(env.bundles.withheld(&device.tenancy).expect("store"), Some(vec!["policy-unverified".to_owned()]));
}

// covers: DIS-083
#[test]
fn sr3_m11_nothing_is_read_while_the_watched_paths_are_unchanged() {
    let (mut env, device, _) = basic("quiet");
    let watched = env.dir.join("watched");
    std::fs::write(&watched, b"1").expect("write");
    env.watch = vec![watched.clone()];
    let r = env.reconciler();
    assert_eq!(built(&r.run_once()), vec![1]);
    assert_eq!(r.run_once()[0].1, Outcome::Unchanged);
    // A new publication nobody told the reconciler about: the watched paths did not change.
    env.instrument("survey-a", "1.1.0", "^1.0");
    assert_eq!(r.run_once()[0].1, Outcome::Unchanged);
    std::thread::sleep(std::time::Duration::from_millis(30));
    std::fs::write(&watched, b"2").expect("write");
    assert_eq!(built(&r.run_once()), vec![2]);
    // A stale anchor is rebuilt although nothing changed.
    env.clock.advance(25 * HOUR);
    assert_eq!(built(&r.run_once()), vec![3]);
    assert!(env.latest(&device).is_some());
}

// covers: DIS-075
#[test]
fn sr3_m7_a_bundle_over_the_size_limit_is_refused_before_it_is_signed() {
    use fieldseal_distribution::application::BuildRequest;
    use fieldseal_distribution::domain::DistributionError;
    let (env, device, instrument) = basic("toolarge");
    // The anchor's time token is signed by the receipt key before the bundle; count the factory key.
    let signed = |env: &Env| env.world.custody.usage_log().iter().filter(|u| u.key == env.world.identity().signer).count();
    let before = signed(&env);
    let request = BuildRequest::new(device.tenancy, vec![*instrument.address()]);
    let result = env.world.build_sized(&env.world.built_in_policy(), &request, fieldseal_registration::domain::checks::UnattestedKeys::AllowNonProduction, 200);
    assert!(matches!(result, Err(DistributionError::TooLarge { .. })), "{result:?}");
    assert_eq!(signed(&env), before, "a refused bundle costs no signature");
    assert!(env.latest(&device).is_none());
}
