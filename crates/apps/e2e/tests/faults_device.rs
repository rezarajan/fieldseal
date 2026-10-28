//! Fault injection on the device (issue #58): power cuts mid-seal, mid-clear, mid-close and
//! mid-export, and a clock reset with a reboot. After each fault the device is restarted
//! over the same storage, then everything it holds is uploaded to the real gate: nothing
//! the device acknowledged may be missing at intake, and nothing may land twice.

#![allow(missing_docs)]

use std::cell::Cell;

use fieldseal_adapters_memory::delivery::{LoopbackTransport, MemoryPrivateStorage};
use fieldseal_collection::application::StatusOutcome;
use fieldseal_collection::domain::{DeliveryState, RuntimePin};
use fieldseal_delivery::application::DeliveryError;
use fieldseal_delivery::domain::{AddressHint, DeliveryLabel, ExportId, HintSource};
use fieldseal_delivery::ports::{PrivateStorage, PrivateStorageError};
use fieldseal_e2e::{Couriers, Enrolled, Intake, PIN, Site, capture_household, delivery, device, intake_subject, now};
use fieldseal_intake::domain::{FindingKind, Reading, ObservedValue};
use fieldseal_intake::ports::DataPlatform;
use fieldseal_kernel::frame::read_frames;
use fieldseal_kernel::id::{ItemPath, Seq, SubjectId};
use fieldseal_policy::domain::RuntimeEvaluator;
use fieldseal_policy::fixtures::effective_default;

fn hints() -> Vec<AddressHint> {
    vec![AddressHint { address: "http://intake.loopback".into(), source: HintSource::DeviceConfiguration }]
}

fn pin() -> RuntimePin {
    RuntimePin::new(PIN).expect("pin")
}

fn subject(s: &str) -> SubjectId {
    SubjectId::new(s).expect("subject")
}

fn policy() -> RuntimeEvaluator {
    RuntimeEvaluator::from_effective(&effective_default()).expect("policy")
}

fn frames(rt: &fieldseal_collection::application::Runtime<'_>) -> usize {
    read_frames(&rt.journal().expect("journal")).frames.len()
}

fn members_rows(intake: &Intake, site: &Site, who: &str) -> Vec<Reading> {
    intake
        .platform
        .observations(&site.fingerprint())
        .expect("rows")
        .into_iter()
        .filter(|r| r.observation.subject == intake_subject(who) && r.observation.item == ItemPath::new("household.members").expect("path"))
        .map(|r| r.observation.reading)
        .collect()
}

/// One power cut, at the `cut`th mutating storage operation after the first capture (or
/// none, to count the operations): a status record is sealed and the sealed records are
/// then cleared. The device restarts and uploads. Returns the operations the section took.
fn seal_then_clear(seed: u64, cut: Option<u64>) -> u64 {
    device!(seed => site, phone, opener, rt);
    let first = capture_household(&mut rt, "h-002", 3);
    let started = phone.device.storage.ops();
    if let Some(k) = cut {
        phone.device.storage.crash_after(k);
    }
    let sealed = rt.record_status(&subject("h-004"), StatusOutcome::Absent);
    let through = sealed.as_ref().map_or(first, |s| *s);
    let cleared = sealed.as_ref().ok().map(|_| rt.clear(through, &pin(), &pin(), None));
    let used = phone.device.storage.ops() - started;
    if cut.is_none() {
        assert!(matches!(cleared, Some(Ok(_))));
        return used;
    }
    let cut = cut.unwrap_or_default();
    drop(rt);
    phone.device.storage.restart();

    // Restart: the runtime loads over the same storage and recovers (COL-092, COL-093).
    let mut rt = phone.runtime(&site, &opener);
    let recovery = rt.recovery().clone();
    rt.open_session(&pin()).unwrap_or_else(|e| panic!("cut {cut}: {e}"));
    let n = frames(&rt);
    if sealed.is_ok() {
        assert!(n >= 5, "cut {cut}: a record the device acknowledged is in the journal ({recovery:?})");
    }
    // The chain continues after recovery.
    rt.record_status(&subject("h-001"), StatusOutcome::Absent).unwrap_or_else(|e| panic!("cut {cut}: the chain continues: {e}"));

    // Everything the device holds reaches intake: no gap, no loss, no duplicate.
    let intake_after = Intake::new(&site, &[Enrolled::of(&rt)]);
    let gate = intake_after.gate(&site);
    let upload = intake_after.upload(&site, &gate);
    let loopback = LoopbackTransport::new(&upload, now);
    let couriers = Couriers::new();
    let policy = policy();
    delivery!(site, phone, couriers, &couriers.removable, policy, &loopback, svc);
    let sent = frames(&rt);
    let done = svc.upload(&mut rt, &hints()).unwrap_or_else(|e| panic!("cut {cut}: upload: {e:?}"));
    assert_eq!(done.attempt.label, DeliveryLabel::Received, "cut {cut}");
    let tenancy = rt.tenancy().expect("tenancy");
    let landed = intake_after.platform.envelopes(&tenancy).expect("envelopes");
    assert_eq!(landed.len(), sent, "cut {cut}: every record the journal held landed");
    assert!(landed.windows(2).all(|w| w[1].seq.0 == w[0].seq.0 + 1), "cut {cut}: continuous seq");
    assert!(intake_after.platform.losses().expect("losses").is_empty(), "cut {cut}: nothing lost");
    assert!(
        !intake_after.platform.findings().expect("findings").iter().any(|(_, f)| f.kind == FindingKind::Loss || f.kind == FindingKind::Rejection),
        "cut {cut}: no loss or rejection finding"
    );
    assert_eq!(members_rows(&intake_after, &site, "h-002"), vec![Reading::Value(ObservedValue::Int(3))], "cut {cut}: the capture sealed before the cut landed exactly once");
    used
}

#[test]
fn col_092_093_a_power_cut_at_every_step_of_seal_and_clear_loses_nothing() {
    let steps = seal_then_clear(90, None);
    assert!(steps > 8, "a seal and a clear take several storage operations ({steps})");
    fieldseal_e2e::every_cut(steps, |k| {
        seal_then_clear(90, Some(k));
    });
}

/// The torn append: the power goes mid-write and only part of the frame reaches the
/// journal (COL-093).
#[test]
fn col_093_a_torn_journal_frame_is_truncated_and_everything_before_it_lands() {
    device!(91 => site, phone, opener, rt);
    capture_household(&mut rt, "h-002", 3);
    let before = rt.journal().expect("journal");
    phone.device.storage.tear_next_append(40);
    assert!(rt.record_status(&subject("h-004"), StatusOutcome::Absent).is_err());
    drop(rt);
    phone.device.storage.restart();
    let mut rt = phone.runtime(&site, &opener);
    assert_eq!(rt.recovery().truncated_bytes, 40);
    assert_eq!(rt.journal().expect("journal"), before, "the torn frame is gone, earlier records intact");
    rt.open_session(&pin()).expect("open");
    rt.record_status(&subject("h-004"), StatusOutcome::Absent).expect("the chain continues");
    let intake = Intake::new(&site, &[Enrolled::of(&rt)]);
    let gate = intake.gate(&site);
    let upload = intake.upload(&site, &gate);
    let loopback = LoopbackTransport::new(&upload, now);
    let couriers = Couriers::new();
    let policy = policy();
    delivery!(site, phone, couriers, &couriers.removable, policy, &loopback, svc);
    let sent = frames(&rt);
    svc.upload(&mut rt, &hints()).expect("upload");
    assert_eq!(intake.platform.envelopes(&rt.tenancy().expect("tenancy")).expect("envelopes").len(), sent);
    assert!(intake.platform.losses().expect("losses").is_empty());
}

#[test]
fn col_006_col_092_a_power_cut_at_every_step_of_closing_the_tenancy_loses_nothing() {
    fn run(cut: Option<u64>) -> u64 {
        device!(92 => site, phone, opener, rt);
        capture_household(&mut rt, "h-002", 3);
        capture_household(&mut rt, "h-004", 4);
        let intake = Intake::new(&site, &[Enrolled::of(&rt)]);
        let started = phone.device.storage.ops();
        if let Some(k) = cut {
            phone.device.storage.crash_after(k);
        }
        let closed = rt.end_tenancy();
        let used = phone.device.storage.ops() - started;
        let Some(k) = cut else {
            closed.expect("closes");
            return used;
        };
        drop(rt);
        phone.device.storage.restart();
        let mut rt = phone.runtime(&site, &opener);
        // A close the cut interrupted completes: at load when its outbox entry exists, else
        // at the next unlock (COL recovery); the tenancy never stays half closed.
        if rt.state().is_some() {
            rt.open_session(&pin()).unwrap_or_else(|e| panic!("cut {k}: {e}"));
            if rt.state().is_some() {
                rt.end_tenancy().unwrap_or_else(|e| panic!("cut {k}: closing again: {e}"));
            }
        }
        assert_eq!(rt.state(), None, "cut {k}: closed");
        assert_eq!(phone.device.keys.key_count(), 0, "cut {k}: every key erased (crypto-erase)");
        assert_eq!(rt.outbox().expect("outbox").len(), 1, "cut {k}: the journal is in the outbox");

        // The outbox goes to intake on its own route, and every sealed record is there.
        let gate = intake.gate(&site);
        let upload = intake.upload(&site, &gate);
        let loopback = LoopbackTransport::new(&upload, now);
        let couriers = Couriers::new();
        let policy = policy();
        delivery!(site, phone, couriers, &couriers.removable, policy, &loopback, svc);
        let results = svc.upload_outbox(&mut rt, &hints()).unwrap_or_else(|e| panic!("cut {k}: {e:?}"));
        assert_eq!(results[0].attempt.label, DeliveryLabel::Received);
        assert!(rt.outbox().expect("outbox").is_empty(), "cut {k}: a receipt removes the part");
        assert!(intake.platform.losses().expect("losses").is_empty());
        assert_eq!(members_rows(&intake, &site, "h-002"), vec![Reading::Value(ObservedValue::Int(3))], "cut {k}");
        assert_eq!(members_rows(&intake, &site, "h-004"), vec![Reading::Value(ObservedValue::Int(4))], "cut {k}");
        used
    }
    let steps = run(None);
    assert!(steps >= 3, "closing takes several storage operations ({steps})");
    fieldseal_e2e::every_cut(steps, |k| {
        run(Some(k));
    });
}

/// A private storage that loses power in the middle of writing an export: half the bytes
/// are written, then the call fails.
struct PowerCut<'a> {
    inner: &'a MemoryPrivateStorage,
    armed: Cell<bool>,
}

impl PrivateStorage for PowerCut<'_> {
    fn put(&self, id: &ExportId, bytes: &[u8]) -> Result<(), PrivateStorageError> {
        if self.armed.replace(false) {
            self.inner.put(id, &bytes[..bytes.len() / 2])?;
            return Err(PrivateStorageError::Backend("power lost".into()));
        }
        self.inner.put(id, bytes)
    }

    fn get(&self, id: &ExportId) -> Result<Option<Vec<u8>>, PrivateStorageError> {
        self.inner.get(id)
    }

    fn delete(&self, id: &ExportId) -> Result<(), PrivateStorageError> {
        self.inner.delete(id)
    }

    fn put_marker(&self, name: &str, bytes: &[u8]) -> Result<(), PrivateStorageError> {
        self.inner.put_marker(name, bytes)
    }

    fn get_marker(&self, name: &str) -> Result<Option<Vec<u8>>, PrivateStorageError> {
        self.inner.get_marker(name)
    }
}

#[test]
fn del_010_del_012_a_power_cut_while_an_export_is_written_offers_nothing_and_loses_nothing() {
    device!(93 => site, phone, opener, rt);
    capture_household(&mut rt, "h-002", 3);
    capture_household(&mut rt, "h-004", 4);
    let journal = rt.journal().expect("journal");
    let intake = Intake::new(&site, &[Enrolled::of(&rt)]);
    let gate = intake.gate(&site);
    let upload = intake.upload(&site, &gate);
    let loopback = LoopbackTransport::new(&upload, now);
    let couriers = Couriers::new();
    let policy = policy();
    let cut = PowerCut { inner: &couriers.storage, armed: Cell::new(true) };

    // First attempt: the app's private storage fails half way through the file.
    let receiver = fieldseal_delivery::checks::TrustReceiverCheck::new(fieldseal_trust::domain::TrustStore::new(&site.world.trust), now());
    let receipts = fieldseal_delivery::checks::TrustReceiptCheck::new(fieldseal_trust::domain::TrustStore::new(&site.world.trust));
    let mut broken = fieldseal_delivery::application::DeliveryService::new(
        fieldseal_delivery::application::Ports {
            keys: &phone.device.keys,
            random: &phone.device.random,
            wall: &phone.device.wall,
            transport: &loopback,
            receiver: &receiver,
            receipts: &receipts,
            files: &couriers.removable,
            share: &couriers.share,
            storage: &cut,
            records: &couriers.records,
        },
        &policy,
    );
    let err = broken.build_export(&mut rt, None).expect_err("the cut export is not offered");
    assert_eq!(err, DeliveryError::BuildFailed("power lost".into()));
    assert_eq!(rt.journal().expect("journal"), journal, "the journal was only read: nothing is lost");
    assert_eq!(rt.delivery_state(Seq(1)), DeliveryState::None);

    // The next attempt builds a whole, verified export, and the records arrive.
    delivery!(site, phone, couriers, &couriers.removable, policy, &loopback, svc);
    let export = svc.build_export(&mut rt, None).expect("a clean export");
    let bytes = couriers.storage.get(&export.id).expect("get").expect("stored");
    assert!(fieldseal_delivery::export::verify(&bytes, &[]).ok());
    let sent = frames(&rt);
    let done = svc.upload(&mut rt, &hints()).expect("upload");
    assert_eq!(done.attempt.label, DeliveryLabel::Received);
    assert_eq!(intake.platform.envelopes(&rt.tenancy().expect("tenancy")).expect("envelopes").len(), sent);

    // A cut while copying to a removable disk: the copy fails and does not count (DEL-023).
    use fieldseal_delivery::ports::FileAccess;
    couriers.removable.fail_writes(true);
    let disk = couriers.removable.pick_destination().expect("disk");
    assert!(svc.deliver_file(&mut rt, &export, &disk).is_err());
    assert_eq!(svc.attempts().last().expect("attempt").label, DeliveryLabel::Failed);
    couriers.removable.fail_writes(false);
    assert_eq!(svc.deliver_file(&mut rt, &export, &disk).map(|a| a.label), Ok(DeliveryLabel::SavedAndChecked), "retrying works");
}

#[test]
fn col_080_081_int_010_a_clock_reset_and_a_reboot_leave_ticks_that_intake_accepts() {
    device!(94 => site, phone, opener, rt);
    capture_household(&mut rt, "h-002", 3);
    // The collector's phone loses its clock: elapsed time restarts at the reboot, and the
    // wall clock jumps back a year, then becomes unknown altogether.
    phone.device.clock.advance_ms(120_000);
    rt.open_session(&pin()).expect("the idle session is unlocked again");
    capture_household(&mut rt, "h-004", 4);
    phone.device.clock.reboot();
    phone.device.wall.set(Some(now().0 - 365 * fieldseal_kernel::time::AuthorityTime::DAY));
    drop(rt);
    let mut rt = phone.runtime(&site, &opener);
    let info = rt.open_session(&pin()).expect("the session opens");
    assert!(info.outside_window, "COL-083: the runtime only warns outside the window");
    capture_household_again(&mut rt, "h-002", 5);
    phone.device.wall.set(None);
    phone.device.clock.reboot();
    drop(rt);
    let mut rt = phone.runtime(&site, &opener);
    rt.open_session(&pin()).expect("and again with no wall clock");
    rt.record_status(&subject("h-004"), StatusOutcome::Absent).expect("sealing is not blocked by device time");

    // Intake sees ticks that never go back (WIRE-071, WIRE-072, INT-010): no flag, no loss.
    phone.device.wall.set(Some(now().0));
    let intake = Intake::new(&site, &[Enrolled::of(&rt)]);
    let gate = intake.gate(&site);
    let upload = intake.upload(&site, &gate);
    let loopback = LoopbackTransport::new(&upload, now);
    let couriers = Couriers::new();
    let policy = policy();
    delivery!(site, phone, couriers, &couriers.removable, policy, &loopback, svc);
    let sent = frames(&rt);
    let done = svc.upload(&mut rt, &hints()).expect("upload");
    assert_eq!(done.attempt.label, DeliveryLabel::Received);
    assert_eq!(intake.platform.envelopes(&rt.tenancy().expect("tenancy")).expect("envelopes").len(), sent);
    let findings = intake.platform.findings().expect("findings");
    assert!(!findings.iter().any(|(_, f)| f.rule == "INT-010" || f.rule == "WIRE-071"), "no tick finding: {findings:?}");
    assert!(intake.platform.losses().expect("losses").is_empty());
    assert_eq!(members_rows(&intake, &site, "h-002").len(), 2, "both visits to h-002 landed in order");
}

/// A second visit, as a resurvey with a changed answer.
fn capture_household_again(rt: &mut fieldseal_collection::application::Runtime<'_>, who: &str, members: i128) {
    rt.start_capture(&subject(who), fieldseal_collection::application::CaptureMode::Resurvey).expect("resurvey");
    rt.set_value(&ItemPath::new("household.members").expect("path"), fieldseal_kernel::Value::Int(members)).expect("set");
    rt.seal().expect("seal");
}
