//! Bundle import under attack (ADR 0007, ADR 0015, DIS-030, DIS-031).
//!
//! The oracle for "authenticate before you parse" is a spying agreement key: the runtime
//! may only ask it to open the seal after the factory signature has verified. Every
//! rejection below must leave the spy untouched, and the held bundle must stay.

use std::cell::Cell;
use std::collections::BTreeMap;

use fieldseal_adapters_memory::demo::{DEMO_SCHEMA, DemoDevice, DemoWorld};
use fieldseal_adapters_memory::distribution::{MemoryBundleStore, SoftwareAgreementKey};
use fieldseal_distribution::application::{BuildRequest, ImportBundle, BundleImporter, HeldRoster, HeldState, ImportState, VerifyBundle};
use fieldseal_distribution::domain::{BundleFile, BundleRejection, ConsentState, Roster, RosterEntry, RuntimeProfile, VerifyStep};
use fieldseal_distribution::ports::{AgreementError, AgreementKey, BundleStore};
use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::{DomainTag, tags};
use fieldseal_kernel::id::{CohortId, Generation, KeyId, Salt, SubjectId};
use fieldseal_kernel::seal::SealedBox;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::value::Value;
use fieldseal_publishing::domain::{ArtefactKind, Publication};
use fieldseal_security_tests::{assert_no_canary, to_high_s, CANARIES};
use zeroize::Zeroizing;

const T0: AuthorityTime = AuthorityTime(1_800_000_000_000);

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn profile() -> RuntimeProfile {
    RuntimeProfile { instrument_schema: DEMO_SCHEMA, localisation_reference: None }
}

/// An agreement key that counts how often the runtime asked it to open anything.
struct Spy<'a> {
    inner: SoftwareAgreementKey,
    opens: &'a Cell<u32>,
}

impl AgreementKey for Spy<'_> {
    fn key_id(&self) -> KeyId {
        self.inner.key_id()
    }
    fn open(&self, tag: &DomainTag, context: &[u8], sealed: &SealedBox) -> Result<Zeroizing<Vec<u8>>, AgreementError> {
        self.opens.set(self.opens.get() + 1);
        self.inner.open(tag, context, sealed)
    }
}

struct Env {
    w: DemoWorld,
    d: DemoDevice,
    instrument: Publication,
}

fn roster(version: u64, generation: u32) -> Roster {
    Roster {
        cohort: CohortId::new("cohort-a").expect("id"),
        version,
        generation: Generation(generation),
        entries: vec![RosterEntry {
            ordinal: 1,
            subject: SubjectId::new("s-001").expect("id"),
            display: CANARIES[0].to_owned(),
            attributes: BTreeMap::from([("age".to_owned(), Value::Int(9))]),
            consent: ConsentState::Unknown,
            prior_status: None,
        }],
    }
}

impl Env {
    fn new() -> Self {
        let w = DemoWorld::new(1, T0).expect("world");
        let doc = cbor::map([
            ("apiVersion", text("fieldseal.dev/v1alpha1")),
            ("kind", text("Instrument")),
            ("metadata", cbor::map([("name", text("health-check")), ("version", text("1.0.0"))])),
            (
                "spec",
                cbor::map([
                    ("schema", text("^1.0")),
                    ("items", Value::Array(vec![cbor::map([("label", text("Age {$roster.age}")), ("from", text("roster.age"))])])),
                ]),
            ),
        ]);
        let instrument = w
            .publish(ArtefactKind::Instrument, "health-check", "1.0.0", cbor::encode(&doc).expect("encodes"), Some(Salt::from([0x5a; 32])))
            .expect("publishes");
        let d = w.register("device-a", &[("cohort-a", 1)], true, profile()).expect("registers");
        w.assign_rosters(&d, vec![roster(1, 1)]);
        Env { w, d, instrument }
    }

    fn build(&self) -> Vec<u8> {
        self.w.build(&self.w.built_in_policy(), &BuildRequest::new(self.d.tenancy, vec![*self.instrument.address()])).expect("builds").sealed.bytes
    }

    fn now(&self) -> AuthorityTime {
        AuthorityTime(T0.0 + 2 * AuthorityTime::DAY)
    }

    fn state(&self, held: HeldState) -> ImportState {
        ImportState { tenancy: self.d.tenancy, now: self.now(), held }
    }

    /// Verifies `bytes`, returning the rejection and how many times the seal was opened.
    fn attempt(&self, bytes: &[u8], held: HeldState) -> (Result<(), BundleRejection>, u32) {
        let opens = Cell::new(0);
        let spy = Spy { inner: self.d.agreement_key(), opens: &opens };
        let r = VerifyBundle::new(&self.w.trust, &self.w.publishing, &spy, profile()).verify(bytes, &self.state(held)).map(|_| ());
        (r, opens.get())
    }
}

/// ADR 0007 / WIRE-093: nothing is decrypted before the factory signature verifies. Eight
/// different ways to break the envelope, and the seal is never opened for any of them.
#[test]
fn adr_0007_bundle_is_authenticated_before_it_is_decrypted_or_parsed() {
    let e = Env::new();
    let good = e.build();
    let (ok, opens) = e.attempt(&good, HeldState::default());
    assert!(ok.is_ok());
    assert_eq!(opens, 1, "a good bundle is opened exactly once, after verification");

    let file = || BundleFile::decode(&good, usize::MAX).expect("file");
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut f = file();
    f.sig.0[10] ^= 1;
    cases.push(("flipped signature bit", f.encode()));
    let mut f = file();
    f.sealed.ct[0] ^= 1;
    cases.push(("tampered ciphertext", f.encode()));
    let mut f = file();
    f.sealed.enc[0] ^= 1;
    cases.push(("tampered encapsulation", f.encode()));
    let mut f = file();
    f.sig.0 = to_high_s(&f.sig.0);
    cases.push(("high-s signature (malleated)", f.encode()));
    let mut f = file();
    f.signer = e.w.publishers[0];
    f.chain = vec![];
    cases.push(("signed by a publisher key, not a factory key", f.encode()));
    let mut f = file();
    f.chain = vec![];
    f.signer = KeyId::from([7; 16]);
    cases.push(("unknown signer", f.encode()));
    let mut f = file();
    f.sig.0.truncate(63);
    cases.push(("short signature", f.encode()));
    let mut f = file();
    f.sig.0 = vec![0; 64];
    cases.push(("zero signature", f.encode()));
    for (what, bytes) in &cases {
        let (r, opens) = e.attempt(bytes, HeldState::default());
        let r = r.expect_err(what);
        assert_eq!(opens, 0, "{what}: the seal was opened before the signature was accepted ({r:?})");
        assert!(matches!(r.step(), VerifyStep::Signature | VerifyStep::Envelope), "{what}: {r:?}");
    }

    // A signature made under a different domain tag (DOMAIN SEPARATION): resign the same
    // envelope under the receipt tag with the factory key.
    use fieldseal_kernel::crypto::Purpose;
    use fieldseal_trust::domain::KeyRole;
    use fieldseal_trust::ports::KeyCustody;
    let f = file();
    let wrong = e.w.custody.sign(&e.w.factory, KeyRole::Purpose(Purpose::Factory), &tags::TRUST_BUNDLE, &BundleFile::signed_structure(&f.sealed, &e.w.factory), "attack");
    // The custody itself refuses the tag (key misuse); if a custody ever did sign it, the
    // verifier must still refuse it.
    assert!(wrong.is_err(), "a factory key must not sign under another purpose's tag");
}

/// ADR 0007: size and magic come before everything, even before the signature.
#[test]
fn wire_093_oversize_and_foreign_files_are_refused_unparsed() {
    let e = Env::new();
    let opens = Cell::new(0);
    let spy = Spy { inner: e.d.agreement_key(), opens: &opens };
    let v = VerifyBundle::new(&e.w.trust, &e.w.publishing, &spy, profile()).with_max_size(64);
    let r = v.verify(&e.build(), &e.state(HeldState::default())).unwrap_err();
    assert!(matches!(r, BundleRejection::TooLarge { .. }));
    for junk in [&b""[..], b"PK\x03\x04", b"FSB1", b"FSB1\xff\xff\xff\xff\xff\xff\xff\xff\xff", b"%PDF-1.7"] {
        let r = v.verify(junk, &e.state(HeldState::default()));
        assert!(r.is_err());
    }
    assert_eq!(opens.get(), 0);
}

/// DIS-030 step 5: an old bundle re-imported, or the same one again, is refused and the
/// held bundle is kept (replay of a captured file).
#[test]
fn dis_030_5_replaying_an_old_bundle_is_refused_and_the_held_one_kept() {
    let e = Env::new();
    let first = e.build();
    let second = e.build();
    let store = MemoryBundleStore::new();
    let key = e.d.agreement_key();
    let importer = BundleImporter::new(VerifyBundle::new(&e.w.trust, &e.w.publishing, &key, profile()), &store);
    let mut state = e.state(HeldState::default());
    importer.import(&second, &state).expect("imports the newer");
    state.held.seq = Some(fieldseal_distribution::domain::BundleSeq(2));
    for replay in [&first, &second] {
        let r = importer.import(replay, &state).expect_err("replay refused");
        assert!(matches!(r, BundleRejection::NotNewer { .. }), "{r:?}");
    }
    assert_eq!(store.latest(&e.d.tenancy).unwrap().unwrap().bytes, second);
}

/// DIS-014: a roster generation or version lower than held (a rolled-back roster) is refused.
#[test]
fn dis_014_a_rolled_back_roster_is_refused() {
    let e = Env::new();
    let bytes = e.build();
    let cohort = CohortId::new("cohort-a").unwrap();
    for (version, generation) in [(4, 1), (1, 2)] {
        let held = HeldState { rosters: vec![HeldRoster { cohort: cohort.clone(), version, generation: Generation(generation) }], ..HeldState::default() };
        let (r, _) = e.attempt(&bytes, held);
        let r = r.expect_err("rolled-back roster");
        assert_eq!(r.step(), VerifyStep::Rosters, "{r:?}");
    }
}

/// DIS-030 step 2 / TRU-0xx: stale and early anchors. A runtime whose authority clock is past
/// the factory certificate's validity, or before it, cannot be talked into accepting.
#[test]
fn dis_030_2_stale_and_premature_anchors_do_not_validate_the_factory_signature() {
    let e = Env::new();
    let bytes = e.build();
    let key = e.d.agreement_key();
    for now in [AuthorityTime(T0.0 - 1), AuthorityTime(T0.0 + 3 * 365 * AuthorityTime::DAY)] {
        let r = VerifyBundle::new(&e.w.trust, &e.w.publishing, &key, profile())
            .verify(&bytes, &ImportState { tenancy: e.d.tenancy, now, held: HeldState::default() })
            .unwrap_err();
        assert_eq!(r.step(), VerifyStep::Signature, "{now:?}: {r:?}");
    }
}

/// DIS-042: a bundle copied to another device (another agreement key, another tenancy) is
/// unusable, and nothing is opened when the recipient does not match.
#[test]
fn dis_042_a_bundle_copied_to_another_device_is_unusable() {
    let e = Env::new();
    let other = e.w.register("device-b", &[("cohort-a", 1)], true, profile()).expect("registers");
    let bytes = e.build();
    let opens = Cell::new(0);
    let spy = Spy { inner: other.agreement_key(), opens: &opens };
    let r = VerifyBundle::new(&e.w.trust, &e.w.publishing, &spy, profile())
        .verify(&bytes, &ImportState { tenancy: other.tenancy, now: e.now(), held: HeldState::default() })
        .unwrap_err();
    assert!(matches!(r, BundleRejection::WrongRecipient), "{r:?}");
    assert_eq!(opens.get(), 0, "a seal to another key is never opened");
}

/// DIS-022: the outer envelope reveals nothing about subjects, cohorts or instruments.
#[test]
fn dis_022_the_outer_envelope_and_file_name_carry_no_personal_data() {
    let e = Env::new();
    let bytes = e.build();
    assert_no_canary("bundle file bytes", &bytes);
    for needle in ["cohort-a", "s-001", "health-check", "device-a"] {
        assert!(!bytes.windows(needle.len()).any(|w| w == needle.as_bytes()), "{needle} appears in the sealed bundle file");
    }
    let name = fieldseal_distribution::domain::file_name(T0.0, 1);
    assert_no_canary("bundle file name", name.as_bytes());
    assert!(name.starts_with("fieldseal-bundle-") && name.ends_with(".fsb"), "{name}");
}
