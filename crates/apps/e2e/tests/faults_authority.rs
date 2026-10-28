//! Fault injection on the authority's side of the flow (issue #58): an expired registration
//! token, a bundle for another tenancy or damaged in transit, an artefact withdrawn after a
//! bundle was built, and a tampered transparency-log checkpoint.

#![allow(missing_docs)]

use fieldseal_collection::application::CollectionError;
use fieldseal_collection::domain::{RuntimePin, TenancyState};
use fieldseal_distribution::domain::DistributionError;
use fieldseal_e2e::{Opener, PIN, Phone, Site, capture_household, device, village_a};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_publishing::application::VerifyPublication;
use fieldseal_publishing::domain::{CheckpointBody, PublishingError, SignedCheckpoint};
use fieldseal_registration::application::{RegistrationError, Submission};
use fieldseal_registration::domain::RegistrationRoute;
use fieldseal_registration::ports::TokenError;
use fieldseal_trust::domain::TrustStore;

const MINUTE: u64 = 60 * AuthorityTime::SECOND;

#[test]
fn reg_006_an_expired_registration_token_is_refused_by_the_factory_and_registers_nothing() {
    // ADR 0014: the factory, not the device, checks token expiry. The device has no trusted
    // clock and happily builds a request from a token that is past its time.
    for (route, lifetime) in [(RegistrationRoute::Online, 10 * MINUTE), (RegistrationRoute::AirGapped, 24 * 60 * MINUTE)] {
        let mut site = Site::new(101, 2);
        site.set_cohorts(&[("village-a", 1)]);
        let phone = Phone::new(111);
        let opener = Opener::new(&site, &phone.device);
        let mut rt = phone.runtime(&site, &opener);
        rt.create_tenancy(&RuntimePin::new(PIN).expect("pin")).expect("create");
        opener.tenancy.set(rt.tenancy());
        let person = site.person("alice");
        let issued = site.factory().issue_token(&person, route, 1).expect("token");
        assert_eq!(issued.expires_at, AuthorityTime(site.world.now.0 + lifetime), "REG-006: {route:?}");
        let (sealed, _) = phone.registration_request(&site, &rt, &issued.token, "late").expect("the device builds the request: it does not judge expiry");
        site.clock.advance(lifetime + 1);
        let via = if route == RegistrationRoute::AirGapped { Submission::Upload(person.account.clone()) } else { Submission::Online };
        assert_eq!(site.factory().submit(&sealed, via).unwrap_err(), RegistrationError::Token(TokenError::Expired), "{route:?}");

        // Nothing registered: no tenancy in the registry, no bundle for it, nothing to import.
        let tenancy = rt.tenancy().expect("tenancy");
        assert!(fieldseal_registration::ports::RegistryStore::tenancy(&site.world.registry, &tenancy).expect("registry").is_none());
        assert!(matches!(site.build_bundle(tenancy), Err(DistributionError::NotRegistered)));
        assert_eq!(rt.state(), Some(TenancyState::Local));
        // A fresh token on a fresh request works (the expired one is simply spent).
        let again = site.factory().issue_token(&person, route, 1).expect("a new token");
        let (sealed, _) = phone.registration_request(&site, &rt, &again.token, "on time").expect("request");
        let via = if route == RegistrationRoute::AirGapped { Submission::Upload(person.account.clone()) } else { Submission::Online };
        site.factory().submit(&sealed, via).expect("accepted before its expiry");
    }
}

#[test]
fn dis_030_dis_042_a_bundle_for_another_tenancy_or_damaged_in_transit_is_refused_and_changes_nothing() {
    let mut site = Site::new(102, 2);
    site.set_cohorts(&[("village-a", 1)]);
    let (phone_a, phone_b) = (Phone::new(121), Phone::new(122));
    let (opener_a, opener_b) = (Opener::new(&site, &phone_a.device), Opener::new(&site, &phone_b.device));
    let mut rt_a = site.enrol(&phone_a, &opener_a, "alice", "a", vec![village_a()]);
    let rt_b = site.enrol(&phone_b, &opener_b, "alice", "b", vec![village_a()]);
    let held = rt_a.held().expect("held").fingerprint;
    let (a, b) = (rt_a.tenancy().expect("a"), rt_b.tenancy().expect("b"));

    let for_b = site.build_bundle(b).expect("b's bundle");
    match rt_a.import_bundle(&for_b) {
        Err(CollectionError::BundleRejected(why)) => assert!(!why.is_empty()),
        other => panic!("DIS-042: a bundle sealed to another device must be refused, got {other:?}"),
    }
    let for_a = site.build_bundle(a).expect("a's bundle");
    // Damaged in transit: one flipped bit anywhere fails the signature or the AEAD; a short
    // file fails the framing. Each is refused before anything is used (DIS-030, DIS-031).
    let mut flipped = for_a.clone();
    let mid = flipped.len() / 2;
    flipped[mid] ^= 0x01;
    let truncated = for_a[..for_a.len() / 2].to_vec();
    for (name, bad) in [("bit-flipped", flipped), ("truncated", truncated), ("empty", Vec::new())] {
        assert!(matches!(rt_a.import_bundle(&bad), Err(CollectionError::BundleRejected(_))), "{name}");
    }
    assert_eq!(rt_a.held().expect("still held").fingerprint, held, "DIS-031: what was held is still held");
    assert_eq!(rt_a.state(), Some(TenancyState::Registered));
    capture_household(&mut rt_a, "h-002", 3);
    // And the undamaged file imports, so the refusals above left nothing behind.
    rt_a.import_bundle(&for_a).expect("the real bundle imports");
}

#[test]
fn pub_080_dis_011_an_artefact_withdrawn_after_the_bundle_was_built_does_not_reach_the_device() {
    device!(103 => site, phone, opener, rt);
    capture_household(&mut rt, "h-002", 3);
    let tenancy = rt.tenancy().expect("tenancy");
    let held = rt.held().expect("held").fingerprint;
    // A bundle is built while the instrument is good...
    let built_before = site.build_bundle(tenancy).expect("built before the withdrawal");
    // ...then the publishers withdraw it.
    let withdrawal = site.world.withdraw(&site.instrument, "found wrong").expect("both publishers withdraw it");

    // DIS-011: the factory builds nothing more from it.
    match site.build_bundle(tenancy) {
        Err(DistributionError::ArtefactNotPublished { address, reason }) => {
            assert_eq!(&address, site.instrument.address());
            assert_eq!(reason, "withdrawn");
        },
        other => panic!("a withdrawn instrument must not be released: {other:?}"),
    }
    // PUB-080, DIS-030 step 6: the bundle built before is not trusted once the device learns
    // of the withdrawal (any later bundle carries the current list): it is refused whole.
    opener.extra_withdrawals.borrow_mut().push(withdrawal);
    match rt.import_bundle(&built_before) {
        Err(CollectionError::BundleRejected(why)) => assert!(why.to_lowercase().contains("withdrawn"), "{why}"),
        other => panic!("a bundle for a withdrawn instrument must be refused, got {other:?}"),
    }
    assert_eq!(rt.held().expect("held").fingerprint, held, "the previously held bundle is untouched (DIS-031)");
}

fn tampered(checkpoint: &SignedCheckpoint, edit: impl Fn(&str) -> String) -> SignedCheckpoint {
    let note = String::from_utf8(checkpoint.note().to_vec()).expect("a checkpoint note is text");
    SignedCheckpoint::parse(edit(&note).as_bytes()).expect("the edit keeps the note well formed")
}

#[test]
fn pub_106_a_tampered_transparency_log_checkpoint_fails_verification_everywhere() {
    device!(104 => site, phone, opener, rt);
    let verifier = VerifyPublication::new(TrustStore::new(&site.world.trust), &site.world.publishing);
    verifier.verify(&site.instrument, &[]).expect("the genuine publication verifies offline");
    let genuine = site.instrument.checkpoint.clone();
    let lines: Vec<String> = String::from_utf8(genuine.note().to_vec()).expect("text").lines().map(str::to_owned).collect();

    // A changed root hash (the log tells a different story), a changed size (a rollback or
    // fork), and a note the pinned key never signed are each refused.
    let root = |note: &str| {
        let mut l: Vec<String> = note.lines().map(str::to_owned).collect();
        let r = &mut l[2];
        let first = r.remove(0);
        r.insert(0, if first == 'A' { 'B' } else { 'A' });
        l.join("\n") + "\n"
    };
    let size = |note: &str| {
        let mut l: Vec<String> = note.lines().map(str::to_owned).collect();
        l[1] = (genuine.size() + 1).to_string();
        l.join("\n") + "\n"
    };
    assert!(lines.len() >= 4, "origin, size, root, blank line, signature");
    for (name, edit) in [("root", Box::new(root) as Box<dyn Fn(&str) -> String>), ("size", Box::new(size))] {
        let mut p = site.instrument.clone();
        p.checkpoint = tampered(&genuine, &*edit);
        match verifier.verify(&p, &[]) {
            Err(PublishingError::Checkpoint(_)) => {}
            other => panic!("{name}: a tampered checkpoint must fail verification, got {other:?}"),
        }
    }
    // A checkpoint for the same origin signed by a key the trust bundle does not pin.
    let rogue = fieldseal_kernel::sign::SigningKey::from_scalar(&[0x42; 32]).expect("key");
    let forged = SignedCheckpoint::sign(CheckpointBody { origin: genuine.origin().to_owned(), size: genuine.size(), root: *genuine.root(), extensions: vec![] }, genuine.origin(), &rogue);
    let mut p = site.instrument.clone();
    p.checkpoint = forged;
    assert!(matches!(verifier.verify(&p, &[]), Err(PublishingError::Checkpoint(_))), "PUB-106: only a pinned log key counts");

    // The device verifies the same way when a bundle arrives: a tampered publication inside an
    // otherwise valid bundle is refused, and the runtime keeps what it holds.
    let held = rt.held().expect("held").fingerprint;
    let tenancy = rt.tenancy().expect("tenancy");
    let bundle = site.build_bundle(tenancy).expect("a newer bundle");
    let bad = tampered(&genuine, |n| size(n));
    *opener.tamper.borrow_mut() = Some(Box::new(move |b| b.instrument.checkpoint = bad.clone()));
    assert!(matches!(rt.import_bundle(&bundle), Err(CollectionError::BundleRejected(_))));
    assert_eq!(rt.held().expect("held").fingerprint, held);
    *opener.tamper.borrow_mut() = None;
    rt.import_bundle(&bundle).expect("untampered, the same bundle imports");
}
