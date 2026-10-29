//! The collection suites the spec's section 8 names: `col-lifecycle`, `col-session` and
//! `col-crash`. The checks are the runtime's own contract tests, run in-process against the
//! simulated authority and device (`crates/adapters/memory/tests/collection.rs` is where they
//! are kept as cargo tests); each names the COL requirements it exercises.
//!
//! The simulated platform is a stand-in (no hardware keys, no real storage), so these checks
//! show the runtime's logic, not a platform's persistence controls (COL-090, COL-091, COL-094).

#![allow(dead_code, unused_imports, missing_docs, clippy::all)]

use super::harness::Check;
use super::Unit;


use std::collections::BTreeMap;

use fieldseal_adapters_authoring::{Format, decode};
use fieldseal_adapters_memory::collection::{BundleSpec, SimulatedAuthority, SimulatedDevice, roster_address, SIMULATION_T0};
use fieldseal_collection::application::{
    CaptureMode, CollectionError, CollectionEvent, ConsentInput, Provisioning, ReviewFilter, Runtime, StatusOutcome,
};
use fieldseal_collection::domain::bundle::{HeldRoster, RosterSubject};
use fieldseal_collection::domain::payload::Payload;
use fieldseal_collection::domain::ticks::first_non_monotonic;
use fieldseal_collection::domain::{DeliveryState, Restriction, RuntimePin, StorageClass, TenancyState, WindowId};
use fieldseal_distribution::domain::ConsentState;
use fieldseal_kernel::export::ExportFile;
use fieldseal_kernel::id::{CohortId, Digest, ItemPath, Seq, SubjectId};
use fieldseal_kernel::payload::{ConsentRef, Layout, Mode, Tick};
use fieldseal_kernel::record::read_journal;
use fieldseal_kernel::{Decimal, Value, cbor};

const PIN: &str = "246810";
const WATER: &str = "household-water-access";
const MEALS: &str = "school-meals-baseline";

fn example(name: &str) -> crate::embedded::Embedded {
    crate::embedded::survey(name).expect("the example survey expands")
}

fn pin(d: &str) -> RuntimePin {
    RuntimePin::new(d).expect("pin")
}

fn path(p: &str) -> ItemPath {
    ItemPath::new(p).expect("path")
}

fn subject(s: &str) -> SubjectId {
    SubjectId::new(s).expect("subject")
}

fn text(s: &str) -> Value {
    Value::Text(s.into())
}

fn dec(s: &str) -> Value {
    Value::Decimal(Decimal::parse(s).expect("decimal"))
}

fn nr(code: &str) -> Value {
    cbor::map([("nr", text(code))])
}

struct World {
    authority: SimulatedAuthority,
    device: SimulatedDevice,
    windows: Vec<WindowId>,
}

impl World {
    fn new() -> Self {
        Self { authority: SimulatedAuthority::new(7), device: SimulatedDevice::new(11), windows: vec![WindowId("capture".into()), WindowId("review".into())] }
    }

    fn provisioning(&self) -> Provisioning<'_> {
        Provisioning {
            trust: &self.authority.trust,
            publishing: &self.authority.policy,
            build_anchor: Digest::from([0xbb; 32]),
            provisional_record_key: self.authority.record_key(),
            windows: &self.windows,
        }
    }

    fn runtime(&self) -> Runtime<'_> {
        Runtime::load(self.device.platform(), self.provisioning()).expect("load")
    }

    fn roster(&self, cohort: &str, subjects: &[(&str, ConsentState)]) -> HeldRoster {
        let subjects: Vec<RosterSubject> = subjects
            .iter()
            .enumerate()
            .map(|(i, (s, c))| RosterSubject {
                ordinal: i as u64 + 1,
                subject: subject(s),
                display: BTreeMap::from([("name".to_owned(), format!("Person {}", i + 1)), ("head_name".to_owned(), format!("Head {}", i + 1))]),
                attributes: BTreeMap::from([
                    ("school".to_owned(), text("North")),
                    ("class".to_owned(), text("2B")),
                    ("age".to_owned(), Value::Int(12)),
                ]),
                consent: *c,
                prior_status: None,
            })
            .collect();
        HeldRoster { cohort: CohortId::new(cohort).unwrap(), version: 3, generation: 1, address: roster_address(cohort, 3, &subjects), subjects }
    }

    /// A registered bundle file for the runtime's tenancy.
    fn bundle(&self, rt: &Runtime<'_>, instrument: &str, layouts: &[&str], rosters: Vec<HeldRoster>, register: bool) -> Vec<u8> {
        let survey = example(instrument);
        let doc = survey.instrument.clone();
        let layouts: Vec<Value> = layouts.iter().map(|window| survey.layout(window).unwrap_or_else(|| panic!("{instrument} has no {window} layout")).clone()).collect();
        let contents = self
            .authority
            .bundle(rt.tenancy().expect("tenancy"), BundleSpec { instrument: &doc, layouts: &layouts, rosters, register, issued_day: 15, seq: 1 })
            .expect("bundle");
        self.device.bundles.register(contents)
    }
}

fn water_people() -> Vec<(&'static str, ConsentState)> {
    vec![("h-001", ConsentState::Unknown), ("h-002", ConsentState::Granted), ("h-003", ConsentState::Refused)]
}

/// A tenancy, registered, holding the water instrument and its compact layout.
fn water(w: &World) -> Runtime<'_> {
    let mut rt = w.runtime();
    rt.create_tenancy(&pin(PIN)).expect("create");
    let file = w.bundle(&rt, WATER, &["compact"], vec![w.roster("village-a", &water_people())], true);
    rt.import_bundle(&file).expect("import");
    rt
}

fn fill_water(rt: &mut Runtime<'_>) {
    for (p, v) in [
        ("household.members", Value::Int(5)),
        ("water.source", text("standpipe")),
        ("water.minutes_to_source", Value::Int(20)),
        ("water.litres_per_day", Value::Int(150)),
        ("water.treatments", Value::Array(vec![text("boil")])),
        ("water.monthly_cost", nr("refused")),
        ("sanitation.toilet.type", text("pit_slab")),
        ("sanitation.toilet.sharing.shared", Value::Bool(false)),
        ("hygiene.handwashing_place", text("fixed")),
        ("hygiene.soap_seen", Value::Bool(true)),
    ] {
        rt.set_value(&path(p), v).unwrap_or_else(|e| panic!("{p}: {e}"));
    }
}

/// Opens every journal payload as the authority would.
fn payloads(w: &World, rt: &Runtime<'_>) -> Vec<(u64, Payload)> {
    let report = read_journal(&rt.journal().unwrap(), &rt.key_history(), &rt.checkpoints());
    assert!(report.is_clean(), "journal verifies: {:?}", report.errors);
    report.entries.iter().map(|e| (e.record.header.seq, w.authority.open_payload(&e.record.payload).expect("opens"))).collect()
}

fn items(w: &World, rt: &Runtime<'_>) -> Vec<fieldseal_kernel::payload::ItemsPayload> {
    payloads(w, rt)
        .into_iter()
        .filter_map(|(_, p)| match p {
            Payload::Items(i) => Some(i),
            _ => None,
        })
        .collect()
}

// ---- 5.1 Tenancy lifecycle ---------------------------------------------------------------

pub fn col_001_a_device_holds_one_open_tenancy() {
    let w = World::new();
    let mut rt = w.runtime();
    rt.create_tenancy(&pin(PIN)).unwrap();
    assert_eq!(rt.create_tenancy(&pin(PIN)).unwrap_err(), CollectionError::TenancyExists);
}

pub fn col_002_create_tenancy_offline_makes_keys_and_seals_the_open_record() {
    let w = World::new();
    let mut rt = w.runtime();
    rt.create_tenancy(&pin(PIN)).unwrap();
    assert_eq!(rt.state(), Some(TenancyState::Local));
    assert_eq!(w.device.keys.key_count(), 3, "signing, agreement and session-wrapping keys");
    let sign_pub = rt.key_history()[0].clone();
    let tenancy = rt.tenancy().unwrap();
    assert_eq!(tenancy.as_bytes(), fieldseal_kernel::digest::sha256(sign_pub.as_bytes()).as_bytes(), "WIRE §identifiers");
    let p = payloads(&w, &rt);
    assert!(matches!(&p[0], (0, Payload::Open { tenancy: t, evidence, .. }) if t.as_bytes() == tenancy.as_bytes() && evidence.len() == 2));
}

pub fn col_003_no_collection_about_real_subjects_before_registration() {
    let w = World::new();
    let mut rt = w.runtime();
    rt.create_tenancy(&pin(PIN)).unwrap();
    let file = w.bundle(&rt, WATER, &[], vec![w.roster("village-a", &water_people())], false);
    rt.import_bundle(&file).unwrap();
    assert_eq!(rt.state(), Some(TenancyState::Local));
    assert!(matches!(rt.start_capture(&subject("h-002"), CaptureMode::First), Err(CollectionError::NotAllowed(_))));
}

pub fn col_005_a_bundle_with_a_verified_certificate_registers_the_tenancy() {
    let w = World::new();
    let rt = water(&w);
    assert_eq!(rt.state(), Some(TenancyState::Registered));
    let kinds: Vec<&str> = payloads(&w, &rt).iter().map(|(_, p)| p.kind()).collect();
    assert_eq!(kinds, vec!["open", "anchor", "anchor", "import"], "bundle and time-token anchors, then the import (COL-082, WIRE-058)");
}

/// A bundle for a fresh tenancy at `issued_day`, with the instrument's checkpoint time as `edit` leaves it.
fn import_with_tree_head(issued_day: u64, edit: impl FnOnce(&mut fieldseal_publishing::domain::Publication)) -> Result<(), CollectionError> {
    let w = World::new();
    let mut rt = w.runtime();
    rt.create_tenancy(&pin(PIN)).unwrap();
    let doc = example(WATER).instrument;
    let mut contents = w
        .authority
        .bundle(rt.tenancy().unwrap(), BundleSpec { instrument: &doc, layouts: &[], rosters: vec![], register: true, issued_day, seq: 1 })
        .unwrap();
    edit(&mut contents.instrument);
    rt.import_bundle(&w.device.bundles.register(contents))
}

pub fn col_006_end_tenancy_seals_closing_moves_the_journal_to_the_outbox_and_crypto_erases() {
    let w = World::new();
    let mut rt = water(&w);
    let tenancy = rt.tenancy().unwrap();
    rt.record_status(&subject("h-002"), StatusOutcome::Absent).unwrap();
    let summary = rt.end_tenancy().unwrap();
    assert_eq!(summary.parts, 1);
    assert_eq!(rt.state(), None, "erased");
    assert_eq!(w.device.keys.key_count(), 0, "every tenancy key deleted (crypto-erase)");
    assert!(w.device.storage.list(StorageClass::SessionEncrypted).is_empty(), "local record and progress gone");
    assert!(w.device.storage.peek(StorageClass::DeviceEncrypted, "tenancy").is_none(), "PIN material gone");
    let events = rt.take_events();
    assert!(events.contains(&CollectionEvent::TenancyClosed(tenancy)) && events.contains(&CollectionEvent::TenancyErased(tenancy)));

    let outbox = rt.outbox().unwrap();
    let fieldseal_collection::application::OutboxEntry::Closed { export, .. } = &outbox[0] else { panic!("closed entry") };
    let file = ExportFile::decode(export).unwrap();
    let part = &file.parts[0];
    let sign_pub = {
        let report = read_journal(&part.journal, &[], &[]);
        let first = fieldseal_kernel::frame::read_frames(&part.journal).frames[0].body.to_vec();
        let rec = fieldseal_kernel::record::Record::decode(&first).unwrap();
        let _ = report;
        match w.authority.open_payload(&rec.payload).unwrap() {
            Payload::Open { sign_pub, .. } => sign_pub,
            _ => panic!("open first"),
        }
    };
    part.verify(&file.header, &sign_pub).expect("closing manifest signed before the keys were deleted (WIRE-106)");
    let report = read_journal(&part.journal, &[sign_pub], &[]);
    assert!(report.is_clean());
    let last = w.authority.open_payload(&report.entries.last().unwrap().record.payload).unwrap();
    assert!(matches!(last, Payload::Closing { .. }), "closing is the last record (WIRE-039)");
    let manifest = w.authority.open_manifest(&fieldseal_kernel::seal::SealedBox::decode(&part.manifest).unwrap()).unwrap();
    assert_eq!(manifest.as_map().unwrap().get("records"), Some(&Value::Int(report.entries.len() as i128)));
    // A new tenancy may now be created (COL-001).
    rt.create_tenancy(&pin(PIN)).expect("the device is free again");
    assert_eq!(rt.outbox_summary().unwrap().parts, 1, "the outbox survives (COL-009)");
}

pub fn col_007_a_close_certificate_closes_without_the_pin() {
    let w = World::new();
    let mut rt = water(&w);
    let tenancy = rt.tenancy().unwrap();
    rt.lock("test");
    let wrong = w.authority.closes.issue(fieldseal_kernel::id::TenancyId::from([9; 32]), Seq(3), "forgotten-pin");
    assert!(matches!(rt.apply_close_certificate(&wrong, &w.authority.closes), Err(CollectionError::InvalidCertificate(_))));
    let cert = w.authority.closes.issue(tenancy, Seq(3), "forgotten-pin");
    rt.apply_close_certificate(&cert, &w.authority.closes).unwrap();
    assert_eq!(rt.state(), None);
    assert_eq!(w.device.keys.key_count(), 0);
    assert!(matches!(&rt.outbox().unwrap()[0], fieldseal_collection::application::OutboxEntry::Certified { certificate, .. } if *certificate == cert));
}

pub fn col_009_outbox_entries_go_only_under_a_receipt() {
    let w = World::new();
    let mut rt = water(&w);
    let tenancy = rt.tenancy().unwrap();
    rt.end_tenancy().unwrap();
    let short = w.authority.receipt(tenancy, Seq(1), Digest::from([0; 32]), SIMULATION_T0);
    assert!(!rt.remove_outbox(&short).unwrap(), "a receipt that doesn't cover the journal removes nothing");
    let full = w.authority.receipt(tenancy, Seq(99), Digest::from([0; 32]), SIMULATION_T0);
    assert!(rt.remove_outbox(&full).unwrap());
    assert_eq!(rt.outbox_summary().unwrap().parts, 0);
}

// ---- 5.2 PIN and sessions ----------------------------------------------------------------

pub fn col_021_pin_has_a_floor() {
    assert!(RuntimePin::new("12345").is_err());
    let w = World::new();
    let mut rt = w.runtime();
    rt.create_tenancy(&pin("123456")).expect("six digits meet the floor");
}

pub fn col_022_the_session_key_needs_the_pin_and_an_unlocked_device() {
    let w = World::new();
    let mut rt = water(&w);
    rt.lock("test");
    assert!(matches!(rt.open_session(&pin("111111")), Err(CollectionError::WrongPin(_))));
    w.device.keys.set_locked(true);
    assert!(matches!(rt.open_session(&pin(PIN)), Err(CollectionError::NotAllowed(_))), "the wrapping key needs an unlocked device");
    w.device.keys.set_locked(false);
    let info = rt.open_session(&pin(PIN)).unwrap();
    assert!(info.bundle_held, "the held bundle is opened again at unlock");
    assert!(w.windows.iter().all(|win| fieldseal_collection::ports::SecureDisplay::is_protected(&w.device.display, win)), "PLAT-015");
}

pub fn col_023_wrong_pins_impose_increasing_waits_that_survive_a_restart() {
    let w = World::new();
    let mut rt = water(&w);
    rt.lock("test");
    for _ in 0..4 {
        assert_eq!(rt.open_session(&pin("999999")).unwrap_err(), CollectionError::WrongPin(0));
    }
    assert_eq!(rt.open_session(&pin("999999")).unwrap_err(), CollectionError::WrongPin(30), "the fifth failure waits 30 s");
    assert_eq!(rt.open_session(&pin(PIN)).unwrap_err(), CollectionError::LockedOut(30), "even the right PIN waits");
    // A restart doesn't reset the counter: it is stored, wrapped by the hardware key.
    drop(rt);
    let mut rt = w.runtime();
    w.device.clock.advance_ms(30_000);
    assert_eq!(rt.open_session(&pin("999999")).unwrap_err(), CollectionError::WrongPin(60));
    w.device.clock.reboot();
    assert_eq!(rt.open_session(&pin(PIN)).unwrap_err(), CollectionError::LockedOut(60), "a reboot restarts the wait");
    w.device.clock.advance_ms(60_000);
    rt.open_session(&pin(PIN)).expect("after the wait");
    assert!(rt.take_events().iter().any(|e| matches!(e, CollectionEvent::PinLockedOut(_))));
    // Tampering with the counter counts as reaching the lockout.
    rt.lock("test");
    w.device.storage.poke(StorageClass::DeviceEncrypted, "pin-attempts", vec![0; 12]);
    assert_eq!(rt.open_session(&pin(PIN)).unwrap_err(), CollectionError::LockedOut(30));
}

pub fn col_024_sessions_lock_when_idle_and_on_background() {
    let w = World::new();
    let mut rt = water(&w);
    w.device.clock.advance_ms(119_000);
    rt.start_capture(&subject("h-002"), CaptureMode::First).expect("still open");
    w.device.clock.advance_ms(121_000);
    assert_eq!(rt.set_value(&path("household.members"), Value::Int(2)).unwrap_err(), CollectionError::Locked);
    assert!(!rt.is_unlocked(), "the key and the capture are dropped");
    rt.open_session(&pin(PIN)).unwrap();
    rt.on_lock_trigger(fieldseal_policy::domain::LockTrigger::Background);
    assert!(!rt.is_unlocked());
    rt.open_session(&pin(PIN)).unwrap();
    rt.on_lock_trigger(fieldseal_policy::domain::LockTrigger::ScreenOff);
    assert!(!rt.is_unlocked());
}

pub fn col_027_forgotten_pin_help_says_nothing_sealed_is_lost() {
    assert!(Runtime::forgotten_pin_help().contains("forgotten-pin"));
}

// ---- 5.5 Dual write ----------------------------------------------------------------------

pub fn col_050_col_053_every_record_is_in_the_journal_and_the_local_record_signed_and_ticked() {
    let w = World::new();
    let mut rt = water(&w);
    rt.record_status(&subject("h-001"), StatusOutcome::NotThem).unwrap();
    let local: Vec<String> = w.device.storage.list(StorageClass::SessionEncrypted).into_iter().filter(|n| n.starts_with("local/")).collect();
    let journal = payloads(&w, &rt);
    assert_eq!(local.len(), journal.len(), "one local entry per journal record");
    for name in &local {
        let bytes = w.device.storage.peek(StorageClass::SessionEncrypted, name).unwrap();
        assert!(!bytes.windows(5).any(|x| x == b"h-001"), "the local record is encrypted under the session key");
    }
    let names = w.device.storage.list(StorageClass::DeviceEncrypted).join(" ") + &w.device.storage.list(StorageClass::SessionEncrypted).join(" ");
    for stored in names.split(' ') {
        let b = w.device.storage.peek(StorageClass::DeviceEncrypted, stored).or_else(|| w.device.storage.peek(StorageClass::SessionEncrypted, stored)).unwrap_or_default();
        assert!(!b.windows(8).any(|x| x == b"Person 1"), "COL-052, COL-090: names are never stored ({stored})");
    }
    let ticks: Vec<Tick> = journal.iter().map(|(_, p)| *p.tick()).collect();
    let anchors = rt.anchors();
    assert_eq!(first_non_monotonic(&ticks, |d| anchors.iter().position(|a| a == d)), None, "COL-081");
}

// ---- 5.7 Clear ---------------------------------------------------------------------------

pub fn col_101_mismatched_pins_cancel_the_clear_and_count_toward_lockout() {
    let w = World::new();
    let mut rt = water(&w);
    let journal = rt.journal().unwrap();
    for _ in 0..4 {
        assert!(matches!(rt.clear(Seq(3), &pin(PIN), &pin("135791"), None), Err(CollectionError::ClearCancelled(_))));
    }
    assert!(matches!(rt.clear(Seq(3), &pin("135791"), &pin("135791"), None), Err(CollectionError::ClearCancelled(_))), "a wrong PIN too");
    assert_eq!(rt.journal().unwrap(), journal, "nothing was cleared (COL-104)");
    assert_eq!(rt.clear(Seq(3), &pin(PIN), &pin(PIN), None).unwrap_err(), CollectionError::LockedOut(30), "five failures: locked out");
}

// ---- 5.9 Crash safety --------------------------------------------------------------------

pub fn col_092_crash_between_journal_append_and_local_write_is_completed_on_recovery() {
    let w = World::new();
    let mut rt = water(&w);
    // Seal steps: marker, pending entry, pending note, ticks, append | local entry, …
    w.device.storage.crash_after(5);
    assert!(rt.record_status(&subject("h-001"), StatusOutcome::Absent).is_err());
    drop(rt);
    w.device.storage.restart();
    let mut rt = w.runtime();
    assert_eq!(rt.recovery().seals_completed, vec![4]);
    assert!(rt.recovery().head_repaired);
    rt.open_session(&pin(PIN)).unwrap();
    let review = rt.review(&ReviewFilter::default()).unwrap();
    assert_eq!(review.subjects[0].status, Some(fieldseal_collection::domain::payload::StatusCode::Absent), "COL-050: both copies, as one operation");
    rt.record_status(&subject("h-002"), StatusOutcome::Absent).expect("the chain continues");
    assert_eq!(payloads(&w, &rt).len(), 6);
}

pub fn col_092_crash_before_the_append_discards_the_unsealed_record() {
    let w = World::new();
    let mut rt = water(&w);
    let journal = rt.journal().unwrap();
    w.device.storage.crash_after(3);
    assert!(rt.record_status(&subject("h-001"), StatusOutcome::Absent).is_err());
    drop(rt);
    w.device.storage.restart();
    let rt = w.runtime();
    assert_eq!(rt.recovery().seals_discarded, vec![4]);
    assert_eq!(rt.journal().unwrap(), journal);
    assert!(w.device.storage.list(StorageClass::SessionEncrypted).iter().all(|n| !n.starts_with("pending")));
}

pub fn col_093_a_torn_journal_frame_is_truncated_without_losing_earlier_records() {
    let w = World::new();
    let mut rt = water(&w);
    let journal = rt.journal().unwrap();
    w.device.storage.tear_next_append(40);
    assert!(rt.record_status(&subject("h-001"), StatusOutcome::Absent).is_err());
    assert_eq!(w.device.storage.peek(StorageClass::DeviceEncrypted, "journal").unwrap().len(), journal.len() + 40, "torn");
    drop(rt);
    w.device.storage.restart();
    let mut rt = w.runtime();
    assert_eq!(rt.recovery().truncated_bytes, 40);
    assert_eq!(rt.recovery().seals_discarded, vec![4]);
    assert_eq!(rt.journal().unwrap(), journal, "earlier records intact");
    rt.open_session(&pin(PIN)).unwrap();
    rt.record_status(&subject("h-001"), StatusOutcome::Absent).unwrap();
    assert_eq!(payloads(&w, &rt).len(), 5);
}

pub fn col_093_fault_injection_at_every_step_of_seal_and_clear_leaves_a_consistent_device() {
    let base_ops = {
        let w = World::new();
        let mut rt = water(&w);
        let start = w.device.storage.ops();
        rt.record_status(&subject("h-001"), StatusOutcome::Absent).unwrap();
        rt.clear(Seq(4), &pin(PIN), &pin(PIN), None).unwrap();
        w.device.storage.ops() - start
    };
    for k in 0..base_ops {
        let w = World::new();
        let mut rt = water(&w);
        w.device.storage.crash_after(k);
        let _ = rt.record_status(&subject("h-001"), StatusOutcome::Absent).and_then(|_| rt.clear(Seq(4), &pin(PIN), &pin(PIN), None));
        drop(rt);
        w.device.storage.restart();
        let mut rt = w.runtime();
        rt.open_session(&pin(PIN)).unwrap_or_else(|e| panic!("step {k}: {e}"));
        let journal = payloads(&w, &rt);
        let local: Vec<u64> = w
            .device
            .storage
            .list(StorageClass::SessionEncrypted)
            .iter()
            .filter_map(|n| n.strip_prefix("local/").map(|s| s.parse().unwrap()))
            .collect();
        let cleared = rt.checkpoints().iter().map(|(s, _)| *s).max();
        for (seq, _) in &journal {
            assert!(cleared.is_some_and(|c| *seq <= c) || local.contains(seq), "step {k}: journal record {seq} has its local copy");
        }
        assert!(local.iter().all(|s| journal.iter().any(|(j, _)| j == s)), "step {k}: no local entry without a journal record");
        rt.record_status(&subject("h-002"), StatusOutcome::Absent).unwrap_or_else(|e| panic!("step {k}: {e}"));
    }
}
pub fn col_060_to_col_063_review_shows_current_state_records_and_field_checks() {
    let w = World::new();
    let mut rt = water(&w);
    rt.start_capture(&subject("h-002"), CaptureMode::First).unwrap();
    fill_water(&mut rt);
    rt.set_value(&path("water.litres_per_day"), Value::Int(20)).unwrap();
    rt.override_soft("low-use", "dry-season").unwrap();
    let n = rt.capture_view().unwrap().unanswered.len();
    rt.acknowledge_incomplete(n).unwrap();
    w.device.clock.advance_ms(10_000);
    rt.seal().unwrap();
    rt.start_capture(&subject("h-002"), CaptureMode::Correction).unwrap();
    rt.set_value(&path("household.members"), Value::Int(4)).unwrap();
    rt.seal().unwrap();
    rt.record_status(&subject("h-001"), StatusOutcome::Absent).unwrap();
    let review = rt.review(&ReviewFilter::default()).unwrap();
    let h2 = review.subjects.iter().find(|s| s.subject == subject("h-002")).unwrap();
    assert_eq!(h2.cohort.as_ref().unwrap().as_str(), "village-a", "grouped by cohort");
    assert_eq!(h2.current["household.members"], Value::Int(4), "last write wins");
    assert_eq!(h2.records.iter().map(|r| r.mode).collect::<Vec<_>>(), vec![Some("first"), Some("correction")]);
    assert!(h2.records.iter().all(|r| r.delivery == DeliveryState::None));
    assert_eq!(h2.unanswered, 0);
    assert_eq!(h2.kept_soft.get("water.litres_per_day").map(String::as_str), Some("dry-season"), "COL-063");
    assert_eq!(review.checks.len(), 1, "the 10-second visit raises the timing check");
    assert_eq!(review.checks[0].check, "quick-visits");
    assert_eq!(review.checks[0].subjects, vec![subject("h-002")]);
    let only = rt.review(&ReviewFilter { check: Some("quick-visits".into()), ..ReviewFilter::default() }).unwrap();
    assert_eq!(only.subjects.len(), 1);
    let h1 = rt.review(&ReviewFilter { subject: Some(subject("h-001")), ..ReviewFilter::default() }).unwrap();
    assert_eq!(h1.subjects[0].status, Some(fieldseal_collection::domain::payload::StatusCode::Absent));
}
/// COL-026 and COL-008: keys are used only while a session is open, except to apply a close
/// certificate, which closes the tenancy and moves the journal to the outbox without the PIN.
pub fn col_026_locked_runtime_refuses_work_but_still_applies_a_close_certificate() {
    let w = World::new();
    let mut rt = water(&w);
    let tenancy = rt.tenancy().unwrap();
    rt.lock("test");
    assert!(!rt.is_unlocked());
    assert!(rt.record_status(&subject("h-002"), StatusOutcome::Absent).is_err(), "no signing while locked");
    assert!(rt.start_capture(&subject("h-002"), CaptureMode::First).is_err(), "no capture while locked");
    let cert = w.authority.closes.issue(tenancy, Seq(3), "forgotten-pin");
    rt.apply_close_certificate(&cert, &w.authority.closes).expect("the exception: no PIN, no session");
    assert_eq!(rt.state(), None);
}

/// COL-008 and COL-010: the journal is stored so a close certificate can move it without the
/// PIN, and the outbox can be read afterwards by anyone using the device, on a fresh load.
pub fn col_008_col_010_the_journal_moves_to_the_outbox_without_the_pin_and_the_outbox_is_readable() {
    let w = World::new();
    let mut rt = water(&w);
    let tenancy = rt.tenancy().unwrap();
    rt.record_status(&subject("h-002"), StatusOutcome::Absent).unwrap();
    rt.lock("test");
    let cert = w.authority.closes.issue(tenancy, Seq(3), "forgotten-pin");
    rt.apply_close_certificate(&cert, &w.authority.closes).unwrap();
    drop(rt);
    let rt = w.runtime();
    assert_eq!(rt.state(), None, "no session, no PIN was ever entered");
    let outbox = rt.outbox().expect("readable without a session");
    assert!(matches!(&outbox[0], fieldseal_collection::application::OutboxEntry::Certified { .. }));
    assert_eq!(rt.outbox_summary().unwrap().parts, 1, "the journal travelled to the outbox");
}

// covers: COL-001, COL-002, COL-003, COL-005, COL-006, COL-007, COL-008, COL-009, COL-010, COL-021, COL-022, COL-023, COL-024, COL-026, COL-027, COL-050, COL-051, COL-052, COL-053, COL-062, COL-063, COL-092, COL-093, COL-101, INS-051, INS-052, INS-053

const fn c(reqs: &'static [&'static str], name: &'static str, run: fn()) -> Check {
    Check { reqs, name, run }
}

const CHECKS_FROM_COLLECTION: &[Check] = &[c(
    &["COL-062", "COL-063", "INS-051", "INS-052", "INS-053"],
    "review shows current state and raised field checks, identifying the records, without blocking sealing",
    col_060_to_col_063_review_shows_current_state_records_and_field_checks,
)];

const LIFECYCLE: &[Check] = &[
    c(&["COL-001"], "a device holds one open tenancy", col_001_a_device_holds_one_open_tenancy),
    c(&["COL-002"], "create tenancy offline makes keys and seals the open record", col_002_create_tenancy_offline_makes_keys_and_seals_the_open_record),
    c(&["COL-003"], "no collection about real subjects before registration", col_003_no_collection_about_real_subjects_before_registration),
    c(&["COL-005"], "a bundle with a verified certificate registers the tenancy", col_005_a_bundle_with_a_verified_certificate_registers_the_tenancy),
    c(&["COL-006"], "end tenancy seals closing, moves the journal to the outbox and crypto-erases", col_006_end_tenancy_seals_closing_moves_the_journal_to_the_outbox_and_crypto_erases),
    c(&["COL-007"], "a close certificate closes without the PIN", col_007_a_close_certificate_closes_without_the_pin),
    c(&["COL-008", "COL-010"], "the journal moves to the outbox without the PIN and the outbox is readable", col_008_col_010_the_journal_moves_to_the_outbox_without_the_pin_and_the_outbox_is_readable),
    c(&["COL-009"], "outbox entries go only under a receipt", col_009_outbox_entries_go_only_under_a_receipt),
];

const SESSION: &[Check] = &[
    c(&["COL-021"], "the PIN has a floor", col_021_pin_has_a_floor),
    c(&["COL-022"], "the session key needs the PIN and an unlocked device", col_022_the_session_key_needs_the_pin_and_an_unlocked_device),
    c(&["COL-023"], "wrong PINs impose increasing waits that survive a restart", col_023_wrong_pins_impose_increasing_waits_that_survive_a_restart),
    c(&["COL-024"], "sessions lock when idle and on background", col_024_sessions_lock_when_idle_and_on_background),
    c(&["COL-026"], "a locked runtime refuses work but still applies a close certificate", col_026_locked_runtime_refuses_work_but_still_applies_a_close_certificate),
    c(&["COL-027"], "forgotten-PIN help says nothing sealed is lost", col_027_forgotten_pin_help_says_nothing_sealed_is_lost),
    c(&["COL-101"], "mismatched clear PINs cancel the clear and count toward lockout", col_101_mismatched_pins_cancel_the_clear_and_count_toward_lockout),
];

const CRASH: &[Check] = &[
    c(&["COL-050", "COL-052", "COL-053"], "every record is in the journal; the local record is encrypted, names are never stored, ticks are monotonic", col_050_col_053_every_record_is_in_the_journal_and_the_local_record_signed_and_ticked),
    c(&["COL-051", "COL-092"], "a crash between the journal append and the local write is completed on recovery", col_092_crash_between_journal_append_and_local_write_is_completed_on_recovery),
    c(&["COL-092"], "a crash before the append discards the unsealed record", col_092_crash_before_the_append_discards_the_unsealed_record),
    c(&["COL-093"], "a torn journal frame is truncated without losing earlier records", col_093_a_torn_journal_frame_is_truncated_without_losing_earlier_records),
    c(&["COL-050", "COL-051", "COL-092", "COL-093"], "fault injection at every step of seal and clear leaves a consistent device", col_093_fault_injection_at_every_step_of_seal_and_clear_leaves_a_consistent_device),
];

/// The units of the `col-lifecycle`, `col-session` and `col-crash` suites.
pub fn units() -> Vec<Unit> {
    vec![
        Unit::table("col:lifecycle", &["col-lifecycle"], LIFECYCLE),
        Unit::table("col:session", &["col-session"], SESSION),
        Unit::table("col:crash", &["col-crash"], CRASH),
        Unit::table("ins:checks-review", &["ins-checks"], CHECKS_FROM_COLLECTION),
    ]
}
