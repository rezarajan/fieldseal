//! Multi-device (ADR 0014, issue #61): one collector, two devices within the policy limit of
//! two, a third refused; each device has its own sealed bundle that the other cannot open;
//! intake keeps their records apart and orders observations correctly (INT-053, INT-054).

#![allow(missing_docs)]

use fieldseal_adapters_memory::delivery::LoopbackTransport;
use fieldseal_collection::application::CollectionError;
use fieldseal_collection::domain::{RuntimePin, TenancyState};
use fieldseal_delivery::application::DeliveryError;
use fieldseal_delivery::domain::{AddressHint, DeliveryLabel, HintSource};
use fieldseal_e2e::{Couriers, Enrolled, Intake, Opener, PIN, Phone, Site, capture_household, delivery, intake_subject, now, village_a};
use fieldseal_delivery::ports::PrivateStorage;
use fieldseal_intake::application::QuerySubjectState;
use fieldseal_intake::domain::{ObservedValue, Reading, SubmissionSource};
use fieldseal_intake::landing::ItemState;
use fieldseal_intake::ports::DataPlatform;
use fieldseal_kernel::id::ItemPath;
use fieldseal_policy::domain::RuntimeEvaluator;
use fieldseal_policy::fixtures::effective_default;
use fieldseal_registration::application::{RegistrationError, Submission};
use fieldseal_registration::domain::RegistrationRoute;

fn members() -> ItemPath {
    ItemPath::new("household.members").expect("path")
}

fn hints() -> Vec<AddressHint> {
    vec![AddressHint { address: "http://intake.loopback".into(), source: HintSource::DeviceConfiguration }]
}

#[test]
fn reg_042_dis_042_int_054_two_devices_are_registered_apart_and_intake_orders_their_records() {
    let mut site = Site::new(51, 2);
    site.set_cohorts(&[("village-a", 1)]);
    let (phone_a, phone_b) = (Phone::new(61), Phone::new(62));
    let (opener_a, opener_b) = (Opener::new(&site, &phone_a.device), Opener::new(&site, &phone_b.device));

    // REG-042: two devices of one collector are within the limit.
    let mut rt_a = site.enrol(&phone_a, &opener_a, "alice", "phone A", vec![village_a()]);
    let mut rt_b = site.enrol(&phone_b, &opener_b, "alice", "phone B", vec![village_a()]);
    let (a, b) = (rt_a.tenancy().expect("a"), rt_b.tenancy().expect("b"));
    assert_ne!(a, b, "ADR 0014: each device has its own tenancy, keys and bundle");
    assert_ne!(site.record(&a).device, site.record(&b).device);
    assert_eq!(site.record(&a).account, site.record(&b).account, "one collector");
    assert_eq!(site.factory().list_devices(&site.person("alice").account).expect("devices").len(), 2);
    // ...and a third is refused: the portal won't issue the token.
    assert_eq!(site.token("alice", RegistrationRoute::Online).unwrap_err(), RegistrationError::DeviceLimitReached, "REG-042");
    // Another collector is unaffected.
    assert!(site.token("bob", RegistrationRoute::Online).is_ok());

    // DIS-042: a bundle is sealed to one device. A's bundle can't be opened on B, and the
    // refusal leaves what B holds untouched (DIS-031).
    let bundle_a = site.build_bundle(a).expect("a's bundle");
    let bundle_b = site.build_bundle(b).expect("b's bundle");
    assert_ne!(bundle_a, bundle_b);
    let held_before = rt_b.held().expect("held").clone();
    for (rt, foreign) in [(&mut rt_b, &bundle_a), (&mut rt_a, &bundle_b)] {
        match rt.import_bundle(foreign) {
            Err(CollectionError::BundleRejected(_)) => {}
            other => panic!("another device's bundle must be refused, got {other:?}"),
        }
    }
    assert_eq!(rt_b.held().expect("held").fingerprint, held_before.fingerprint);
    assert_eq!(rt_b.state(), Some(TenancyState::Registered));
    rt_a.import_bundle(&bundle_a).expect("a's own newer bundle imports");
    rt_b.import_bundle(&bundle_b).expect("b's own newer bundle imports");

    // Capture. h-002 is visited by both devices with different answers; h-004 by A only.
    // B has sealed more records by the time it sees h-002, so its record has the later seq.
    capture_household(&mut rt_a, "h-002", 3);
    capture_household(&mut rt_a, "h-004", 5);
    capture_household(&mut rt_b, "h-004", 6);
    let seq_b = capture_household(&mut rt_b, "h-002", 4);

    // The same records as files, kept to be ingested again below.
    let (couriers_a, couriers_b) = (Couriers::new(), Couriers::new());
    let policy = RuntimeEvaluator::from_effective(&effective_default()).expect("policy");
    let intake = Intake::new(&site, &[Enrolled::of(&rt_a), Enrolled::of(&rt_b)]);
    let gate = intake.gate(&site);
    let upload = intake.upload(&site, &gate);
    let loopback = LoopbackTransport::new(&upload, now);
    delivery!(site, phone_a, couriers_a, &couriers_a.removable, policy, &loopback, svc_a);
    delivery!(site, phone_b, couriers_b, &couriers_b.removable, policy, &loopback, svc_b);
    let export_a = svc_a.build_export(&mut rt_a, None).expect("export a");
    let export_b = svc_b.build_export(&mut rt_b, None).expect("export b");
    let (file_a, file_b) = (couriers_a.storage.get(&export_a.id).expect("get").expect("a"), couriers_b.storage.get(&export_b.id).expect("get").expect("b"));
    assert_ne!(file_a, file_b);

    // Upload both to one intake.
    let done_a = svc_a.upload(&mut rt_a, &hints()).expect("a uploads");
    let done_b = svc_b.upload(&mut rt_b, &hints()).expect("b uploads");
    assert_eq!(done_a.attempt.label, DeliveryLabel::Received);
    assert_eq!(done_b.attempt.label, DeliveryLabel::Received);

    // DEL-007, INT-014: a receipt is bound to its tenancy. B's receipt means nothing to A.
    let b_receipt = gate.ingest(&file_b, SubmissionSource::File, now()).expect("ingest").receipts[0].bytes.clone();
    assert!(matches!(svc_a.import_receipt(&mut rt_a, &b_receipt), Err(DeliveryError::ReceiptRejected(_))), "another tenancy's receipt is refused");
    svc_b.import_receipt(&mut rt_b, &b_receipt).expect("and B's own is accepted");

    // Records stay apart: envelopes per tenancy, disjoint, ascending seq (INT-050).
    let (env_a, env_b) = (intake.platform.envelopes(&a).expect("a"), intake.platform.envelopes(&b).expect("b"));
    assert!(!env_a.is_empty() && !env_b.is_empty());
    assert!(env_a.iter().all(|e| e.tenancy == a) && env_b.iter().all(|e| e.tenancy == b));
    assert!(env_a.iter().all(|x| env_b.iter().all(|y| x.record != y.record)), "no record is in both");
    assert!(env_a.windows(2).all(|w| w[0].seq < w[1].seq) && env_b.windows(2).all(|w| w[0].seq < w[1].seq));

    // Observations carry their own tenancy and (generation, seq) (INT-051).
    let rows = intake.platform.observations(&site.fingerprint()).expect("rows");
    let of = |t, s: &str| rows.iter().filter(move |r| r.observation.tenancy == t && r.observation.subject == intake_subject(s) && r.observation.item == members()).collect::<Vec<_>>();
    assert_eq!(of(a, "h-002").len(), 1);
    assert_eq!(of(b, "h-002").len(), 1);
    assert_eq!(of(a, "h-002")[0].observation.reading, Reading::Value(ObservedValue::Int(3)));
    assert_eq!(of(b, "h-002")[0].observation.reading, Reading::Value(ObservedValue::Int(4)));
    assert_eq!(of(b, "h-002")[0].observation.seq, seq_b);
    assert_eq!(of(a, "h-002")[0].observation.generation.0, 1);

    // INT-054: two tenancies with no succession are never ordered against each other; both
    // saw h-002 and h-004 and said different things, so both are flagged for a custodian.
    let state = gate.subject_state(&intake_subject("h-002"), &site.fingerprint()).expect("state");
    assert_eq!(state.conflicts(), vec![&members()], "h-002 was recorded differently by two unrelated devices");
    let h4 = gate.subject_state(&intake_subject("h-004"), &site.fingerprint()).expect("state");
    assert!(matches!(&h4.items[&members()], ItemState::Conflict(c) if c.len() == 2));

    // INT-053: once B is declared A's successor (a replaced device), they are ordered; the
    // later (generation, seq) wins and keeps its source record. The same exports, as files.
    let mut b_after_a = Enrolled::of(&rt_b);
    b_after_a.predecessor = Some(a);
    let ordered = Intake::new(&site, &[Enrolled::of(&rt_a), b_after_a]);
    let ordered_gate = ordered.gate(&site);
    for file in [&file_a, &file_b] {
        let report = ordered_gate.ingest(file, SubmissionSource::File, now()).expect("ingest");
        assert!(report.submission.rejection().is_none(), "{:?}", report.submission.rejection());
    }
    let state = ordered_gate.subject_state(&intake_subject("h-002"), &site.fingerprint()).expect("state");
    assert!(state.conflicts().is_empty());
    let ItemState::Current(c) = &state.items[&members()] else { panic!("one current value") };
    assert_eq!((c.tenancy, c.seq), (b, seq_b), "B's record is later in (generation, seq)");
    assert_eq!(c.reading, Reading::Value(ObservedValue::Int(4)));
    assert_eq!(c.source, of(b, "h-002")[0].observation.source);
}

#[test]
fn reg_042_the_device_limit_is_checked_again_when_the_words_are_confirmed() {
    // Three tokens are issued while no device is registered; the third device is refused when
    // its collector confirms, because the limit counts devices registered by then.
    let mut site = Site::new(52, 2);
    site.set_cohorts(&[("village-a", 1)]);
    let phones: Vec<Phone> = (0..3).map(|i| Phone::new(70 + i)).collect();
    let openers: Vec<Opener<'_>> = phones.iter().map(|p| Opener::new(&site, &p.device)).collect();
    let mut rts: Vec<_> = phones.iter().zip(&openers).map(|(p, o)| p.runtime(&site, o)).collect();
    let person = site.person("alice");
    let mut pending = Vec::new();
    for (i, rt) in rts.iter_mut().enumerate() {
        rt.create_tenancy(&RuntimePin::new(PIN).expect("pin")).expect("create");
        let token = site.token("alice", RegistrationRoute::Online).expect("a token while below the limit");
        let (sealed, _) = phones[i].registration_request(&site, rt, &token.token, &format!("phone {i}")).expect("request");
        pending.push(site.factory().submit(&sealed, Submission::Online).expect("pending").tenancy.id);
    }
    assert!(site.factory().confirm(&person.account, &pending[0]).is_ok());
    assert!(site.factory().confirm(&person.account, &pending[1]).is_ok());
    assert_eq!(site.factory().confirm(&person.account, &pending[2]).unwrap_err(), RegistrationError::DeviceLimitReached);
    assert_eq!(site.record(&pending[2]).state, fieldseal_registration::domain::TenancyState::Pending, "the third stays unregistered");
}
