//! The connected flow (issue #61), named by the requirement each step proves: root
//! ceremony, publishing with threshold signatures and the transparency log, a portal token,
//! device registration with confirmed fingerprint words, a bundle sealed to the device,
//! capture, background upload to an authorised intake, landing in long format, the receipt
//! and the device clearing. In process; software keys, unattested.

#![allow(missing_docs)]

use fieldseal_adapters_memory::delivery::LoopbackTransport;
use fieldseal_collection::application::CaptureMode;
use fieldseal_collection::domain::{DeliveryState, RuntimePin, TenancyState};
use fieldseal_delivery::domain::{AddressHint, DeliveryLabel, HintSource};
use fieldseal_distribution::domain::ConsentState;
use fieldseal_e2e::{Couriers, Enrolled, Intake, Opener, PIN, Phone, Site, delivery, household_answers, now, roster};
use fieldseal_intake::domain::{ObservedValue, Reading};
use fieldseal_intake::ports::DataPlatform;
use fieldseal_kernel::Value;
use fieldseal_kernel::id::{ItemPath, SubjectId};
use fieldseal_policy::domain::RuntimeEvaluator;
use fieldseal_policy::fixtures::effective_default;
use fieldseal_publishing::application::VerifyPublication;
use fieldseal_trust::domain::TrustStore;

fn path(p: &str) -> ItemPath {
    ItemPath::new(p).expect("path")
}

fn subject(s: &str) -> SubjectId {
    SubjectId::new(s).expect("subject")
}

#[test]
fn del_002_int_050_the_connected_flow_lands_what_was_captured_and_the_device_clears() {
    // -- TRU-002, TRU-010: the root ceremony and the purpose keys are the site's own. -----
    let mut site = Site::new(11, 2);
    site.set_cohorts(&[("village-a", 1)]);
    assert!(site.world.trust.certificates().len() >= 8, "factory, registration (two), receipt, builder, two publishers, record and receiver keys are certified");

    // -- PUB-040, PUB-100: two publisher signatures, one log record each, a checkpoint that
    // verifies against the pinned log. ------------------------------------------------------
    assert_eq!(site.instrument.signatures.len(), 2, "the threshold of publisher signatures");
    assert_eq!(site.instrument.log.len(), 2, "PUB-103: one log record per signature");
    VerifyPublication::new(TrustStore::new(&site.world.trust), &site.world.publishing).verify(&site.instrument, &[]).expect("the publication verifies offline");

    // -- REG-004..021: portal token, request from the runtime's keys, words confirmed. ----
    let phone = Phone::new(21);
    let opener = Opener::new(&site, &phone.device);
    let mut rt = phone.runtime(&site, &opener);
    rt.create_tenancy(&RuntimePin::new(PIN).expect("pin")).expect("create tenancy");
    let tenancy = rt.tenancy().expect("tenancy");
    opener.tenancy.set(Some(tenancy));
    assert_eq!(rt.state(), Some(TenancyState::Local), "COL-003: not registered yet");
    let record = site.register_online(&phone, &rt, "alice", "blue phone");
    assert_eq!(record.id, tenancy, "the tenancy is the hash of the runtime's signing key (WIRE-140)");
    assert!(record.certificate.is_some(), "REG-032: a tenancy certificate");

    // -- DIS-010..030: a bundle sealed to this device, verified, opened and imported. -----
    site.assign(tenancy, vec![roster("village-a", 1, 1, &[("h-001", ConsentState::Unknown), ("h-002", ConsentState::Granted), ("h-003", ConsentState::Refused), ("h-004", ConsentState::Granted)])]);
    let bundle = site.build_bundle(tenancy).expect("the bundle builds");
    rt.import_bundle(&bundle).expect("the device verifies and imports it");
    assert_eq!(rt.state(), Some(TenancyState::Registered), "COL-005: the certificate registers the tenancy");
    let held = rt.held().expect("held");
    assert_eq!(held.fingerprint, site.fingerprint(), "DIS-062: named by fingerprint");
    assert_eq!(held.rosters[0].subjects.len(), 4);
    assert!(!held.rosters[0].subjects[0].fields().contains_key("internal_note"), "DIS-013: only referenced roster fields travel");
    let held_rosters = held.rosters.clone();

    // -- COL-030..043: capture. h-003 refused consent, so nothing may be recorded for them.
    assert!(rt.start_capture(&subject("h-003"), CaptureMode::First).is_err(), "COL-030");
    // h-002: roster consent. First visit in Spanish, with a nonresponse; then a resurvey.
    rt.set_languages(&["es"]).expect("language");
    let first = fieldseal_e2e::capture_household(&mut rt, "h-002", 5);
    rt.start_capture(&subject("h-002"), CaptureMode::Resurvey).expect("resurvey");
    rt.set_value(&path("household.members"), Value::Int(6)).expect("changed");
    let resurvey = rt.seal().expect("seal");
    // h-001: consent unknown on the roster, attested by the collector (COL-031, COL-040).
    rt.set_languages(&["en"]).expect("language");
    assert!(rt.start_capture(&subject("h-001"), CaptureMode::First).is_err(), "COL-031: consent first");
    rt.record_consent(&subject("h-001"), &fieldseal_collection::application::ConsentInput { basis: "form-seen".into(), statement_version: 1, capture_evidence: true }).expect("attestation");
    let attested = fieldseal_e2e::capture_household(&mut rt, "h-001", 2);
    // h-004: not at home.
    rt.record_status(&subject("h-004"), fieldseal_collection::application::StatusOutcome::Absent).expect("status");
    assert!(attested > resurvey && resurvey > first);

    // -- DEL-002..008, INT-001..014, INT-050..051: upload, gate, landing, receipt. ---------
    let intake = Intake::new(&site, &[Enrolled { tenancy, keys: rt.key_history(), rosters: held_rosters, predecessor: None }]);
    let gate = intake.gate(&site);
    let upload = intake.upload(&site, &gate);
    let loopback = LoopbackTransport::new(&upload, now);
    let couriers = Couriers::new();
    let policy = RuntimeEvaluator::from_effective(&effective_default()).expect("policy");
    delivery!(site, phone, couriers, &couriers.removable, policy, &loopback, svc);
    let hints = vec![AddressHint { address: "http://intake.loopback".into(), source: HintSource::DeviceConfiguration }];
    assert!(!svc.outstanding(&rt).expect("outstanding").is_empty(), "DEL-001: nothing delivered yet");
    let result = svc.upload(&mut rt, &hints).expect("background upload to the authorised receiver");
    assert_eq!(result.attempt.label, DeliveryLabel::Received, "DEL-026");
    assert!(result.covered_through >= attested, "the receipt covers everything sealed");
    assert_eq!(rt.delivery_state(attested), DeliveryState::Received);

    // The landed observations match what was captured (INT-051, INT-071).
    let rows = intake.platform.observations(&site.fingerprint()).expect("observations");
    let of = |s: &str, item: &str| -> Vec<_> { rows.iter().filter(|r| r.observation.subject == fieldseal_e2e::intake_subject(s) && r.observation.item == path(item)).map(|r| &r.observation).collect() };
    for (item, _) in household_answers(5) {
        assert!(!of("h-002", item).is_empty(), "h-002 {item} landed");
        assert!(!of("h-001", item).is_empty(), "h-001 {item} landed");
    }
    let members = of("h-002", "household.members");
    assert_eq!(members.len(), 2, "the first visit and the resurvey are both rows");
    assert_eq!(members[0].reading, Reading::Value(ObservedValue::Int(5)));
    assert_eq!(members[1].reading, Reading::Value(ObservedValue::Int(6)), "INT-053: the resurvey's value is later");
    assert!(members[0].seq < members[1].seq);
    assert_eq!(of("h-002", "water.source")[0].reading, Reading::Value(ObservedValue::Code("standpipe".into())));
    assert_eq!(of("h-002", "water.monthly_cost")[0].reading, Reading::Nonresponse(fieldseal_intake::domain::Nonresponse::Refused), "INS-072: a nonresponse is a state, not a value");
    assert_eq!(of("h-002", "household.members")[0].lang, vec!["es".to_owned()], "INT-071: the language the record was administered in");
    assert_eq!(of("h-001", "household.members")[0].lang, vec!["en".to_owned()]);
    assert_eq!(of("h-001", "household.members")[0].reading, Reading::Value(ObservedValue::Int(2)));
    assert_eq!(of("h-001", "household.members")[0].consent_basis, "attestation:form-seen", "INT-032: the collector's attestation is the basis");
    assert_eq!(of("h-002", "household.members")[0].consent_basis, "roster:1", "INT-031: the roster version is the basis");
    let case = intake.platform.consent_case(&tenancy, &fieldseal_e2e::intake_subject("h-001"), &site.fingerprint()).expect("platform").expect("a consent case");
    assert_eq!(case.decision, fieldseal_intake::domain::ConsentDecision::AutoAccepted, "INT-035: evidence present, every rule passes");
    assert!(rows.iter().all(|r| r.observation.tenancy == tenancy), "INT-051: every row names its tenancy");
    assert!(rows.iter().all(|r| r.excluded.is_none()), "nothing was excluded: {:?}", rows.iter().filter_map(|r| r.excluded.clone()).collect::<Vec<_>>());
    assert!(intake.platform.losses().expect("losses").is_empty(), "INT-020: nothing was lost");
    assert!(of("h-004", "household.members").is_empty(), "INT-052: a status record has no observations");
    assert!(of("h-003", "household.members").is_empty(), "nothing about a subject who refused");

    // -- INT-014, DEL-007, COL-103, COL-104: the receipt is back; the device clears. ------
    assert_eq!(result.receipt.offer_clear_through, Some(result.covered_through), "a clear is offered");
    let pin = RuntimePin::new(PIN).expect("pin");
    let preview = rt.clear_preview(result.covered_through).expect("preview");
    assert_eq!(preview.not_received, 0, "everything to be cleared was received (COL-102)");
    rt.clear(result.covered_through, &pin, &pin, Some(&result.coverage)).expect("the PIN twice clears the local copies");
    assert!(rt.review(&fieldseal_collection::application::ReviewFilter::default()).expect("review").subjects.is_empty(), "the readable copy is gone");
    assert_eq!(rt.clear_offer(), None);
    assert!(svc.outstanding(&rt).expect("outstanding").iter().all(|s| *s > result.covered_through), "only what was sealed after the clear is outstanding");
}
