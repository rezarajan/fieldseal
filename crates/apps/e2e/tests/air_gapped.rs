//! The air-gapped flow (ADR 0014, issue #61): every exchange is a file or a code. The token
//! is text, the registration request is a file, the bundle is a file, the export is a file
//! carried on a removable disk to intake, and the receipt comes back as `FS1R:` text. The
//! upload transport is present but nothing may ever call it.

#![allow(missing_docs)]

use std::cell::Cell;

use fieldseal_adapters_memory::delivery::MemoryQrScanner;
use fieldseal_collection::domain::{DeliveryState, RuntimePin, TenancyState};
use fieldseal_delivery::checks::receipt_qr_text;
use fieldseal_delivery::domain::{AuthorisedDestination, DeliveryLabel, ReceiverChallenge, ReceiverProof, UploadRequest};
use fieldseal_delivery::ports::{FileAccess, UploadError, UploadTransport};
use fieldseal_e2e::{Couriers, Enrolled, Intake, Opener, PIN, Phone, Scratch, Site, capture_household, delivery, intake_subject, now, village_a};
use fieldseal_intake::domain::{GateState, SubmissionSource};
use fieldseal_intake::ports::DataPlatform;
use fieldseal_policy::domain::RuntimeEvaluator;
use fieldseal_policy::fixtures::effective_default;
use fieldseal_registration::application::Submission;
use fieldseal_registration::domain::wire::{decode_request_file, encode_request_file};
use fieldseal_registration::domain::{RegistrationRoute, RegistrationToken, TenancyState as RegState};

/// A network that must never be touched.
#[derive(Default)]
struct NoNetwork {
    calls: Cell<usize>,
}

impl UploadTransport for NoNetwork {
    fn challenge(&self, _: &fieldseal_delivery::domain::AddressHint, _: &ReceiverChallenge) -> Result<ReceiverProof, UploadError> {
        self.calls.set(self.calls.get() + 1);
        Err(UploadError::Unreachable)
    }

    fn upload(&self, _: &AuthorisedDestination, _: &UploadRequest) -> Result<Vec<fieldseal_collection::domain::ReceiptClaim>, UploadError> {
        self.calls.set(self.calls.get() + 1);
        Err(UploadError::Unreachable)
    }
}

#[test]
fn reg_006_dis_030_del_042_the_air_gapped_flow_moves_only_files_and_codes() {
    let mut site = Site::new(31, 2);
    site.set_cohorts(&[("village-a", 1)]);
    let files = Scratch::new("air-gapped");
    let phone = Phone::new(41);
    let opener = Opener::new(&site, &phone.device);
    let mut rt = phone.runtime(&site, &opener);
    rt.create_tenancy(&RuntimePin::new(PIN).expect("pin")).expect("create");
    let tenancy = rt.tenancy().expect("tenancy");
    opener.tenancy.set(Some(tenancy));

    // REG-004, WIRE-122: the portal shows the token as a code; the device types or scans the text.
    let person = site.person("alice");
    let issued = site.factory().issue_token(&person, RegistrationRoute::AirGapped, 1).expect("an air-gapped token");
    let token_text = issued.token.to_text().expect("text");
    assert!(token_text.starts_with("FS1T:"));
    files.write("token.txt", token_text.as_bytes());
    let token = RegistrationToken::from_text(String::from_utf8(files.read("token.txt")).expect("utf8").trim()).expect("the device reads the token");

    // WIRE-136: the request is a file the collector carries to the portal and uploads there
    // (REG-007). The device shows the four words; the portal shows them again.
    let (sealed, device_words) = phone.registration_request(&site, &rt, &token, "no-signal phone").expect("request");
    files.write("registration.request", &encode_request_file(&sealed));
    let uploaded = decode_request_file(&files.read("registration.request")).expect("the portal reads the file");
    let submitted = site.factory().submit(&uploaded, Submission::Upload(person.account.clone())).expect("the portal accepts the uploaded request");
    assert_eq!(submitted.words, device_words, "REG-020: the words on the portal match the words on the device");
    assert_eq!(submitted.tenancy.state, RegState::Pending);
    let record = site.factory().confirm(&person.account, &submitted.tenancy.id).expect("confirmed");
    assert_eq!(record.state, RegState::Registered);
    site.simulate_attestation(&tenancy);

    // DIS-023: the bundle is a file with a neutral name, carried back on the same disk.
    site.assign(tenancy, vec![village_a()]);
    files.write("bundle.fieldseal", &site.build_bundle(tenancy).expect("builds"));
    rt.import_bundle(&files.read("bundle.fieldseal")).expect("the device imports the file");
    assert_eq!(rt.state(), Some(TenancyState::Registered));

    capture_household(&mut rt, "h-002", 4);
    let last = capture_household(&mut rt, "h-004", 7);

    // DEL-020..022: the export is a file on a removable disk, read back and hashed; that is
    // all the device knows ("Saved and checked"), and it is not a delivery (DEL-033).
    let intake = Intake::new(&site, &[Enrolled::of(&rt)]);
    let gate = intake.gate(&site);
    let network = NoNetwork::default();
    let couriers = Couriers::new();
    let policy = RuntimeEvaluator::from_effective(&effective_default()).expect("policy");
    delivery!(site, phone, couriers, &couriers.removable, policy, &network, svc);
    let export = svc.build_export(&mut rt, None).expect("export");
    let disk = couriers.removable.pick_destination().expect("a disk");
    let attempt = svc.deliver_file(&mut rt, &export, &disk).expect("saved");
    assert_eq!(attempt.label, DeliveryLabel::SavedAndChecked);
    assert_eq!(rt.delivery_state(last), DeliveryState::SavedAndChecked);
    assert_eq!(rt.clear_offer(), None, "DEL-033: a saved file is not a receipt, so no clear is offered");
    files.write("export.fieldseal", &couriers.removable.stored(&disk).expect("the file on the disk"));

    // INT-001: the file is carried to intake and gated like any upload.
    let report = gate.ingest(&files.read("export.fieldseal"), SubmissionSource::File, now()).expect("ingest");
    assert!(matches!(report.submission.state(), GateState::Landed | GateState::Flagged), "{:?}", report.submission.rejection());
    assert_eq!(report.receipts.len(), 1, "INT-014");

    // WIRE-144, DEL-042: the receipt is shown as a code and scanned (or typed) at the device.
    let code = receipt_qr_text(&report.receipts[0].bytes).expect("a receipt fits one code");
    assert!(code.starts_with("FS1R:"));
    let scanner = MemoryQrScanner::default();
    scanner.queue(code.into_bytes());
    let outcome = svc.import_receipt_scan(&mut rt, &scanner).expect("the receipt verifies like one from an upload");
    assert_eq!(outcome.offer_clear_through, Some(last), "COL-103: the receipt offers a clear");
    assert_eq!(rt.delivery_state(last), DeliveryState::Received);
    let pin = RuntimePin::new(PIN).expect("pin");
    rt.clear(last, &pin, &pin, None).expect("clear");

    // The records landed as captured.
    let rows = intake.platform.observations(&site.fingerprint()).expect("rows");
    assert!(rows.iter().any(|r| r.observation.subject == intake_subject("h-004") && r.observation.reading == fieldseal_intake::domain::Reading::Value(fieldseal_intake::domain::ObservedValue::Int(7))));
    assert!(rows.iter().any(|r| r.observation.subject == intake_subject("h-002") && r.observation.reading == fieldseal_intake::domain::Reading::Value(fieldseal_intake::domain::ObservedValue::Int(4))));

    // ADR 0014: no step needed a network.
    assert_eq!(network.calls.get(), 0, "no request was ever made to the network");
}
