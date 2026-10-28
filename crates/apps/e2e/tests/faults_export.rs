//! Fault injection on exports and uploads (issue #58): damaged and truncated exports,
//! reordered, duplicated and missing journal frames, a replayed upload token. Each fault is
//! injected into a real export from a registered device and the real gate must refuse it, or
//! recover from it, as the spec says.

#![allow(missing_docs)]

use fieldseal_adapters_memory::delivery::LoopbackTransport;
use fieldseal_delivery::domain::{AddressHint, HintSource, PopToken, UploadRoute};
use fieldseal_delivery::export::{self, assemble};
use fieldseal_delivery::ports::ManifestAttachments;
use fieldseal_kernel::frame::{frame, read_frames};
use fieldseal_delivery::ports::PrivateStorage;
use fieldseal_e2e::{Couriers, Enrolled, Intake, capture_household, delivery, device, now};
use fieldseal_trust::ports::SecureKeyStore;
use fieldseal_intake::domain::{FindingKind, GateState, SubmissionSource};
use fieldseal_intake::gate::IngestReport;
use fieldseal_intake::ports::DataPlatform;
use fieldseal_policy::domain::RuntimeEvaluator;
use fieldseal_policy::fixtures::effective_default;


/// The offset and length of a section's body in an export file (type byte, length, CRC).
fn section_body(bytes: &[u8], kind: u8) -> (usize, usize) {
    let mut pos = 4;
    while pos < bytes.len() {
        let len = u32::from_be_bytes([bytes[pos + 1], bytes[pos + 2], bytes[pos + 3], bytes[pos + 4]]) as usize;
        if bytes[pos] == kind {
            return (pos + 9, len);
        }
        pos += 9 + len;
    }
    panic!("no section of type {kind:#x}");
}

/// The journal section (type 3).
fn journal_body(bytes: &[u8]) -> (usize, usize) {
    section_body(bytes, 0x03)
}

/// The sealed manifest section (type 2).
fn manifest_body(bytes: &[u8]) -> (usize, usize) {
    section_body(bytes, 0x02)
}

fn landed(r: &IngestReport) -> bool {
    matches!(r.submission.state(), GateState::Landed | GateState::Flagged)
}

#[test]
fn wire_109_int_005_four_damaged_shards_are_repaired_from_parity_and_five_are_not() {
    device!(81 => site, phone, opener, rt);
    for (s, n) in [("h-002", 3), ("h-004", 4), ("h-002", 5)] {
        capture_household(&mut rt, s, n);
    }
    let intake = Intake::new(&site, &[Enrolled::of(&rt)]);
    let gate = intake.gate(&site);
    let (couriers, policy) = (Couriers::new(), RuntimeEvaluator::from_effective(&effective_default()).expect("policy"));
    let upload = intake.upload(&site, &gate);
    let loopback = LoopbackTransport::new(&upload, now);
    delivery!(site, phone, couriers, &couriers.removable, policy, &loopback, svc);
    let export = svc.build_export(&mut rt, Some(true)).expect("export with parity");
    let original = couriers.storage.get(&export.id).expect("get").expect("stored");
    let (start, len) = journal_body(&original);
    let shard = original.len() / 10;
    assert!(len > 5 * shard, "the journal spans several shards");
    let damage = |bytes: &mut Vec<u8>, shards: usize| {
        for i in 0..shards {
            bytes[start + i * shard + 1] ^= 0xff;
        }
    };

    // Four damaged shards: the most the parity rebuilds, byte for byte.
    let mut four = original.clone();
    damage(&mut four, 4);
    assert!(export::verify(&four, &[]).findings.iter().any(|f| f.code == "E_CRC"), "the damage is detected");
    let repaired = export::repair(&four).expect("repair");
    assert_eq!((repaired.shards_rebuilt, repaired.damaged.len()), (4, 4), "CLI-016: which shards were rebuilt");
    assert_eq!(repaired.bytes, original);
    let report = gate.ingest(&four, SubmissionSource::File, now()).expect("ingest");
    assert!(landed(&report), "{:?}", report.submission.rejection());
    assert!(report.submission.findings().iter().any(|f| f.kind == FindingKind::Repair && f.rule == "INT-005"), "the repair is reported");
    assert!(report.losses.is_empty(), "nothing was lost");
    assert!(report.summary.landed >= 7, "every record landed");

    // Five damaged shards: beyond the parity.
    let mut five = original.clone();
    damage(&mut five, 5);
    assert_eq!(export::repair(&five).expect_err("beyond parity").code.to_string(), "E_PARITY");
    assert!(!fieldseal_kernel::export::salvage_frames(&five).is_empty(), "intact frames can still be salvaged");
    // INT-020: the gate lands every intact record, verifying each one by itself, and writes
    // what it could not land to the loss ledger. It invents nothing.
    let fresh = Intake::new(&site, &[Enrolled::of(&rt)]);
    let fresh_gate = fresh.gate(&site);
    let tenancy = rt.tenancy().expect("tenancy");
    let report = fresh_gate.ingest(&five, SubmissionSource::File, now()).expect("ingest");
    assert_eq!(report.submission.state(), GateState::Flagged, "{:?}", report.submission.rejection());
    assert!(report.submission.findings().iter().any(|f| f.rule == "INT-005" && f.detail.contains("E_PARITY")));
    let kept: Vec<u64> = fresh.platform.envelopes(&tenancy).expect("envelopes").iter().map(|e| e.seq.0).collect();
    let lost: Vec<u64> = report.losses.iter().flat_map(|l| l.from.0..=l.through.0).collect();
    assert!(!lost.is_empty() && !kept.is_empty(), "some records were lost and some survived");
    assert!(kept.iter().all(|k| !lost.contains(k)), "a record is landed or lost, never both");
    assert_eq!((kept.len() + lost.len()) as u64, export.records, "every record is accounted for");
    // INT-021: the ledger is never edited; an intact export later supplies the missing records.
    let ledger = fresh.platform.losses().expect("losses").len();
    let again = fresh_gate.ingest(&original, SubmissionSource::File, now()).expect("ingest");
    assert!(landed(&again), "{:?}", again.submission.rejection());
    assert_eq!(fresh.platform.envelopes(&tenancy).expect("envelopes").len() as u64, export.records);
    assert_eq!(fresh.platform.losses().expect("losses").len(), ledger, "INT-021: the ledger entry stays");
    assert_eq!(again.receipts[0].receipt.last_seq, export.through.0, "INT-014: the receipt now covers everything");
}

#[test]
fn int_020_a_truncated_export_lands_its_intact_prefix_and_the_next_export_completes_it() {
    device!(82 => site, phone, opener, rt);
    for (s, n) in [("h-002", 3), ("h-004", 4)] {
        capture_household(&mut rt, s, n);
    }
    let intake = Intake::new(&site, &[Enrolled::of(&rt)]);
    let gate = intake.gate(&site);
    let (couriers, policy) = (Couriers::new(), RuntimeEvaluator::from_effective(&effective_default()).expect("policy"));
    let upload = intake.upload(&site, &gate);
    let loopback = LoopbackTransport::new(&upload, now);
    delivery!(site, phone, couriers, &couriers.removable, policy, &loopback, svc);
    let export = svc.build_export(&mut rt, Some(false)).expect("export");
    let full = couriers.storage.get(&export.id).expect("get").expect("stored");
    let tenancy = rt.tenancy().expect("tenancy");

    // Cut the file in the middle of the last record: the signature at the end is gone.
    let (start, len) = journal_body(&full);
    let cut = start + len - 40;
    let report = gate.ingest(&full[..cut], SubmissionSource::File, now()).expect("ingest");
    assert!(report.submission.rejection().is_none(), "{:?}", report.submission.rejection());
    let first = intake.platform.envelopes(&tenancy).expect("envelopes").len();
    assert!(first > 0 && (first as u64) < export.records, "the intact prefix landed, the cut record did not");
    let covered = report.receipts[0].receipt.last_seq;
    assert!(covered < export.through.0, "INT-014: the receipt covers only the contiguous run that arrived");

    // The device was not told it was delivered (it holds the older receipt claim only), so
    // the intact file later completes it: INT-013 deduplicates, the missing record lands.
    let again = gate.ingest(&full, SubmissionSource::File, now()).expect("ingest");
    assert!(landed(&again), "{:?}", again.submission.rejection());
    let after = intake.platform.envelopes(&tenancy).expect("envelopes");
    assert_eq!(after.len() as u64, export.records, "every record, once");
    assert_eq!(again.receipts[0].receipt.last_seq, export.through.0);
    let mut ids: Vec<_> = after.iter().map(|e| e.record).collect();
    ids.sort_by_key(|r| *r.as_bytes());
    ids.dedup();
    assert_eq!(ids.len(), after.len(), "INT-013: no record twice");
}

#[test]
fn wire_106_int_020_a_bit_flip_in_the_header_manifest_or_signature_is_not_trusted() {
    device!(83 => site, phone, opener, rt);
    capture_household(&mut rt, "h-002", 3);
    let intake = Intake::new(&site, &[Enrolled::of(&rt)]);
    let gate = intake.gate(&site);
    let (couriers, policy) = (Couriers::new(), RuntimeEvaluator::from_effective(&effective_default()).expect("policy"));
    let upload = intake.upload(&site, &gate);
    let loopback = LoopbackTransport::new(&upload, now);
    delivery!(site, phone, couriers, &couriers.removable, policy, &loopback, svc);
    let export = svc.build_export(&mut rt, Some(false)).expect("export");
    let original = couriers.storage.get(&export.id).expect("get").expect("stored");
    let tenancy = rt.tenancy().expect("tenancy");

    // A flipped bit in the signature section: the file's signature cannot be trusted, so the
    // gate says so, and lands only records that each verify by themselves.
    let mut bad_signature = original.clone();
    let (sig_start, _) = section_body(&original, 0x05);
    bad_signature[sig_start + 5] ^= 0x01;
    assert!(!export::verify(&bad_signature, &[]).ok());
    let report = gate.ingest(&bad_signature, SubmissionSource::File, now()).expect("ingest");
    assert_eq!(report.submission.state(), GateState::Flagged);
    assert!(report.submission.findings().iter().any(|f| f.rule == "INT-020" && f.detail.contains("signature and certificate were not checked")));
    let landed_here = intake.platform.envelopes(&tenancy).expect("envelopes").len() as u64;
    assert!(landed_here <= export.records);

    // A flipped bit in the sealed manifest, with no parity to repair it, is the same case: the
    // file-level checks are skipped and each record stands on its own signature and chain.
    let mut bad_manifest = original.clone();
    let (m_start, m_len) = manifest_body(&original);
    bad_manifest[m_start + m_len / 2] ^= 0x01;
    let fresh = Intake::new(&site, &[Enrolled::of(&rt)]);
    let report = fresh.gate(&site).ingest(&bad_manifest, SubmissionSource::File, now()).expect("ingest");
    assert_eq!(report.submission.state(), GateState::Flagged, "{:?}", report.submission.rejection());
    assert!(report.submission.findings().iter().any(|f| f.rule == "INT-005" && f.detail.contains("no parity")), "INT-005: repair was tried, there was nothing to repair from");
    assert!(report.submission.findings().iter().any(|f| f.rule == "INT-020" && f.detail.contains("signature and certificate were not checked")));
    assert!(fresh.platform.envelopes(&tenancy).expect("envelopes").len() as u64 <= export.records);

    // A flipped bit in the header names a different tenancy handle: refused at framing,
    // before anything is decrypted (INT-001), and nothing lands.
    let mut bad_header = original.clone();
    let (h_start, _) = section_body(&original, 0x01);
    bad_header[h_start + 2] ^= 0x01;
    let strict = Intake::new(&site, &[Enrolled::of(&rt)]);
    let report = strict.gate(&site).ingest(&bad_header, SubmissionSource::File, now()).expect("ingest");
    let rejection = report.submission.rejection().expect("a damaged header is refused");
    assert_eq!(report.submission.state(), GateState::Rejected);
    assert_eq!(rejection.stage, fieldseal_intake::domain::Stage::Framing);
    assert!(strict.platform.envelopes(&tenancy).expect("envelopes").is_empty());

    // The undamaged file still lands afterwards: a refusal leaves no mark on the tenancy.
    let ok = strict.gate(&site).ingest(&original, SubmissionSource::File, now()).expect("ingest");
    assert!(landed(&ok), "{:?}", ok.submission.rejection());
    assert_eq!(strict.platform.envelopes(&tenancy).expect("envelopes").len() as u64, export.records);
}

/// An export the device's key signs over a journal whose frames were changed by `mutate`:
/// what a buggy or hostile runtime could send. The file signature is genuine; the records
/// inside are not in the order the chain says.
fn forged_export(rt: &mut fieldseal_collection::application::Runtime<'_>, phone: &fieldseal_e2e::Phone, mutate: impl FnOnce(&mut Vec<Vec<u8>>)) -> Vec<u8> {
    let mut source = rt.export_source(false).expect("source");
    let mut frames: Vec<Vec<u8>> = read_frames(&source.journal).frames.iter().map(|f| f.body.to_vec()).collect();
    mutate(&mut frames);
    source.journal = frames.iter().flat_map(|b| frame(b).expect("frames")).collect();
    assemble(&source, &ManifestAttachments::default(), &phone.device.keys, &phone.device.random, false).expect("assembles").bytes
}

#[test]
fn wire_030_036_int_008_reordered_duplicated_and_missing_frames_are_refused_at_the_chain() {
    device!(84 => site, phone, opener, rt);
    for (s, n) in [("h-002", 3), ("h-004", 4)] {
        capture_household(&mut rt, s, n);
    }
    let tenancy = rt.tenancy().expect("tenancy");
    let clean = forged_export(&mut rt, &phone, |_| {});
    use fieldseal_intake::domain::Stage;
    let cases: Vec<(&str, Vec<u8>, Stage, &str)> = vec![
        ("reordered", forged_export(&mut rt, &phone, |f| f.swap(2, 3)), Stage::Chain, "seq repeated or out of order"),
        ("duplicated", forged_export(&mut rt, &phone, |f| f.insert(3, f[2].clone())), Stage::Chain, "seq repeated or out of order"),
        ("missing", forged_export(&mut rt, &phone, |f| {
            f.remove(2);
        }), Stage::Payload, "INT-009"),
    ];
    let intake = Intake::new(&site, &[Enrolled::of(&rt)]);
    let gate = intake.gate(&site);
    for (name, bytes, stage, why) in &cases {
        let report = gate.ingest(bytes, SubmissionSource::File, now()).expect("ingest");
        let rejection = report.submission.rejection().unwrap_or_else(|| panic!("{name}: a journal out of order must be refused"));
        assert_eq!((rejection.stage, report.submission.state()), (*stage, GateState::Rejected), "{name}");
        assert!(rejection.detail.contains(why), "{name}: {}", rejection.detail);
        assert_eq!(report.summary.landed, 0, "{name}: nothing from a refused submission lands");
        assert!(intake.platform.envelopes(&tenancy).expect("envelopes").is_empty(), "{name}");
    }
    // The raw submissions are kept even when refused (INT-002), and the genuine journal
    // still lands afterwards.
    let report = gate.ingest(&clean, SubmissionSource::File, now()).expect("ingest");
    assert!(landed(&report), "the unmodified journal is accepted: {:?}", report.submission.rejection());
    assert_eq!(intake.platform.envelopes(&tenancy).expect("envelopes").len() as u64, report.summary.landed as u64);
}

#[test]
fn int_013_sending_the_same_records_twice_changes_nothing_that_landed() {
    device!(85 => site, phone, opener, rt);
    capture_household(&mut rt, "h-002", 3);
    let tenancy = rt.tenancy().expect("tenancy");
    let intake = Intake::new(&site, &[Enrolled::of(&rt)]);
    let gate = intake.gate(&site);
    let file = forged_export(&mut rt, &phone, |_| {});
    let first = gate.ingest(&file, SubmissionSource::File, now()).expect("ingest");
    let rows = intake.platform.observations(&site.fingerprint()).expect("rows");
    let envelopes = intake.platform.envelopes(&tenancy).expect("envelopes");
    let second = gate.ingest(&file, SubmissionSource::File, now()).expect("ingest");
    assert!(landed(&first) && landed(&second));
    assert_eq!(intake.platform.observations(&site.fingerprint()).expect("rows"), rows, "no observation was added or changed");
    assert_eq!(intake.platform.envelopes(&tenancy).expect("envelopes"), envelopes);
    assert_eq!(second.receipts[0].receipt.last_seq, first.receipts[0].receipt.last_seq, "the same receipt coverage");
}

fn pop(phone: &fieldseal_e2e::Phone, rt: &fieldseal_collection::application::Runtime<'_>, jti: u8, iat: u64) -> PopToken {
    let handle = phone.device.keys.signing_handle(&rt.key_history()[0]).expect("signing key");
    let mut t = PopToken {
        tenancy: rt.tenancy().expect("tenancy"),
        method: "POST".into(),
        url: UploadRoute::Tenancy.url("http://intake.loopback"),
        iat: fieldseal_kernel::time::AuthorityTime(iat),
        jti: [jti; 16],
        ath: None,
        signature: fieldseal_kernel::crypto::Signature(vec![0; 64]),
    };
    t.signature = phone.device.keys.sign(&handle, &t.message()).expect("signs");
    t
}

#[test]
fn del_003_a_replayed_upload_token_is_refused_but_the_records_can_be_sent_again_with_a_fresh_one() {
    use fieldseal_intake::upload::UploadRefusal::TokenRejected;
    device!(86 => site, phone, opener, rt);
    capture_household(&mut rt, "h-002", 3);
    let tenancy = rt.tenancy().expect("tenancy");
    let intake = Intake::new(&site, &[Enrolled::of(&rt)]);
    let gate = intake.gate(&site);
    let upload = intake.upload(&site, &gate);
    let t0 = now();

    // A token authenticates one request, once.
    let token = pop(&phone, &rt, 1, t0.0).to_header();
    assert_eq!(upload.authenticate(Some(&token), "POST", UploadRoute::Tenancy, t0), Ok(tenancy));
    assert_eq!(upload.authenticate(Some(&token), "POST", UploadRoute::Tenancy, t0), Err(TokenRejected("token replayed")), "the same jti twice");
    // Nor later: once its window has passed it is expired as well.
    assert_eq!(upload.authenticate(Some(&token), "POST", UploadRoute::Tenancy, fieldseal_kernel::time::AuthorityTime(t0.0 + 301_000)), Err(TokenRejected("token expired")));

    // A whole captured request (body and token) replayed through the transport is refused
    // and lands nothing.
    let source = rt.export_source(false).expect("source");
    let body = assemble(&source, &ManifestAttachments::default(), &phone.device.keys, &phone.device.random, false).expect("assembles").bytes;
    let request = |jti| fieldseal_delivery::domain::UploadRequest { route: UploadRoute::Tenancy, body: body.clone(), pop: Some(pop(&phone, &rt, jti, t0.0)) };
    let loopback = LoopbackTransport::new(&upload, now);
    let receiver = fieldseal_delivery::checks::TrustReceiverCheck::new(fieldseal_trust::domain::TrustStore::new(&site.world.trust), now());
    use fieldseal_delivery::ports::{ReceiverCheck, UploadTransport};
    let challenge = fieldseal_delivery::contract::challenge(7, site.record(&tenancy).handle);
    let address = AddressHint { address: "http://intake.loopback".into(), source: HintSource::DeviceConfiguration };
    let proof = loopback.challenge(&address, &challenge).expect("the receiver answers");
    receiver.verify(&challenge, &proof).expect("an authorised receiver");
    let destination = fieldseal_delivery::domain::AuthorisedDestination::authorise(address, &challenge, &proof, &receiver).expect("authorised");
    let captured = request(2);
    let first = loopback.upload(&destination, &captured).expect("accepted once");
    assert_eq!(first.len(), 1);
    let before = intake.platform.observations(&site.fingerprint()).expect("rows");
    assert!(loopback.upload(&destination, &captured).is_err(), "the captured request is refused the second time");
    // Fresh token, same records: accepted, and INT-013 leaves landed data as it was.
    loopback.upload(&destination, &request(3)).expect("a fresh token is fine");
    assert_eq!(intake.platform.observations(&site.fingerprint()).expect("rows"), before);
}
