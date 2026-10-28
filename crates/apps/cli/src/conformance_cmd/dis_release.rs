//! The `dis-release` suite: release is refused before registration and for flagged
//! tenancies, names the policy and is logged, and a practice bundle needs policy to allow it
//! (DIS-001..DIS-004; the same cases as `crates/adapters/memory/tests/distribution.rs`).

#![allow(dead_code, unused_imports, missing_docs, clippy::all)]

use super::harness::Check;
use super::Unit;


use std::collections::BTreeMap;

use fieldseal_adapters_memory::demo::{DEMO_SCHEMA, DemoDevice, DemoWorld};
use fieldseal_adapters_memory::distribution::{MemoryBundleStore, SoftwareAgreementKey};
use fieldseal_distribution::application::{
    BuildRequest, BundleDelivery, BundleImporter, DownloadBundle, FetchBundle, HeldRoster, HeldState, ImportBundle, ImportState,
    VerifyBundle, VerifiedBundle, release_facts,
};
use fieldseal_distribution::domain::{
    BundleContent, BundleFile, BundleRejection, BundleSeq, CollectorReason, CompositionError, ConsentState, DistributionError,
    ReleaseDecision, Roster, RosterEntry, RuntimeProfile, VerifyStep, file_name,
};
use fieldseal_distribution::ports::{AgreementKey, BundleStore};
use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::{Purpose, tags};
use fieldseal_kernel::error::ErrorCode;
use fieldseal_kernel::id::{CohortId, ContentAddress, Generation, Salt, SubjectId};
use fieldseal_kernel::seal::{RecipientKey, seal_with_context};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::value::Value;
use fieldseal_policy::domain::{Decision, DecisionPoint, EffectivePolicy, Facts, Verdict};
use fieldseal_policy::ports::{PolicyEngine, PolicyEngineError};
use fieldseal_publishing::domain::{ArtefactKind, Publication};
use fieldseal_publishing::ports::ArtefactRegistry;
use fieldseal_registration::domain::{KeyState, TenancyState};
use fieldseal_registration::ports::RegistryStore;
use fieldseal_trust::domain::{DeviceKeyKind, KeyRole};
use fieldseal_trust::ports::{KeyCustody, SourceRng};

const T0: AuthorityTime = AuthorityTime(1_800_000_000_000);

fn salt() -> Salt {
    Salt::from([0x5a; 32])
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// A minimal instrument document: a schema range and a label that reads a roster field.
fn instrument_bytes(schema: &str, label: &str) -> Vec<u8> {
    let doc = cbor::map([
        ("apiVersion", text("fieldseal.dev/v1alpha1")),
        ("kind", text("Instrument")),
        ("metadata", cbor::map([("name", text("health-check")), ("version", text("1.0.0"))])),
        (
            "spec",
            cbor::map([
                ("schema", text(schema)),
                ("items", Value::Array(vec![cbor::map([("label", text(label)), ("from", text("roster.age"))])])),
            ]),
        ),
    ]);
    cbor::encode(&doc).expect("encodes")
}

fn layout_bytes(name: &str, instrument: &ContentAddress, class: Option<&str>) -> Vec<u8> {
    let mut spec = vec![("instrument", Value::Bytes(instrument.as_bytes().to_vec())), ("schema", text("^1.0"))];
    if let Some(c) = class {
        spec.push(("windowClass", text(c)));
    }
    cbor::encode(&cbor::map([("kind", text("Layout")), ("metadata", cbor::map([("name", text(name))])), ("spec", cbor::map(spec))])).expect("encodes")
}

fn localisation_bytes(reference: &str) -> Vec<u8> {
    cbor::encode(&cbor::map([("kind", text("Localisation")), ("spec", cbor::map([("reference", text(reference)), ("language", text("es"))]))])).expect("encodes")
}

fn profile() -> RuntimeProfile {
    RuntimeProfile { instrument_schema: DEMO_SCHEMA, localisation_reference: Some("ref-1".into()) }
}

fn roster(cohort: &str, version: u64, generation: u32) -> Roster {
    let entry = |ordinal: u32, subject: &str, prior: Option<&str>| RosterEntry {
        ordinal,
        subject: SubjectId::new(subject).expect("id"),
        display: format!("Subject {ordinal}"),
        attributes: BTreeMap::from([
            ("age".to_owned(), Value::Int(9)),
            ("district".to_owned(), text("North")), // no instrument references it
        ]),
        consent: ConsentState::Unknown,
        prior_status: prior.map(str::to_owned),
    };
    Roster {
        cohort: CohortId::new(cohort).expect("id"),
        version,
        generation: Generation(generation),
        entries: vec![entry(1, "s-001", None), entry(2, "s-002", Some("carried"))],
    }
}

struct Env {
    w: DemoWorld,
    d: DemoDevice,
    instrument: Publication,
}

impl Env {
    fn new() -> Self {
        let w = DemoWorld::new(1, T0).expect("world");
        let instrument = w.publish(ArtefactKind::Instrument, "health-check", "1.0.0", instrument_bytes("^1.0", "Age {$roster.age}"), Some(salt())).expect("publishes");
        let d = w.register("device-a", &[("cohort-a", 1)], true, profile()).expect("registers");
        w.assign_rosters(&d, vec![roster("cohort-a", 1, 1)]);
        Env { w, d, instrument }
    }

    fn request(&self) -> BuildRequest {
        BuildRequest::new(self.d.tenancy, vec![*self.instrument.address()])
    }

    fn build(&self) -> Result<fieldseal_distribution::application::BuiltBundle, DistributionError> {
        self.w.build(&self.w.built_in_policy(), &self.request())
    }

    fn now(&self) -> AuthorityTime {
        AuthorityTime(T0.0 + 2 * AuthorityTime::DAY)
    }

    fn verify_with(&self, key: &SoftwareAgreementKey, profile: RuntimeProfile, bytes: &[u8], held: HeldState) -> Result<VerifiedBundle, BundleRejection> {
        VerifyBundle::new(&self.w.trust, &self.w.publishing, key, profile).verify(bytes, &ImportState { tenancy: self.d.tenancy, now: self.now(), held })
    }

    fn verify(&self, bytes: &[u8]) -> Result<VerifiedBundle, BundleRejection> {
        self.verify_with(&self.d.agreement_key(), profile(), bytes, HeldState::default())
    }

    /// The content of a built bundle, opened with the device's key.
    fn content(&self, bytes: &[u8]) -> BundleContent {
        let file = BundleFile::decode(bytes, usize::MAX).expect("file");
        let plaintext = self.d.agreement_key().open(&tags::BUNDLE_SEAL, self.d.tenancy.as_bytes(), &file.sealed).expect("opens");
        BundleContent::decode(&plaintext).expect("content")
    }

    /// Seals and signs `content` for the device as the factory would.
    fn pack(&self, content: &BundleContent) -> Vec<u8> {
        self.pack_for(&self.d.agreement_public, self.d.tenancy.as_bytes(), content)
    }

    fn pack_for(&self, to: &fieldseal_kernel::crypto::P256PublicKey, context: &[u8], content: &BundleContent) -> Vec<u8> {
        let plaintext = content.encode().expect("encodes");
        let sealed = seal_with_context(&mut SourceRng(&self.w.random), &RecipientKey::P256(to.clone()), &tags::BUNDLE_SEAL, context, &plaintext).expect("seals");
        let sig = self
            .w
            .custody
            .sign(&self.w.factory, KeyRole::Purpose(Purpose::Factory), &tags::BUNDLE, &BundleFile::signed_structure(&sealed, &self.w.factory), "test")
            .expect("signs");
        BundleFile { sealed, signer: self.w.factory, chain: vec![self.w.factory_certificate.clone()], sig }.encode()
    }
}

fn rejection(r: Result<VerifiedBundle, BundleRejection>) -> BundleRejection {
    r.expect_err("the bundle must be rejected")
}

// ---- Release (DIS-001–DIS-004) -------------------------------------------------------------

pub fn dis_001_no_bundle_before_registration() {
    let e = Env::new();
    for state in [TenancyState::Pending, TenancyState::Held, TenancyState::Rejected] {
        e.w.set_state(&e.d.tenancy, state).expect("state");
        assert_eq!(e.build().unwrap_err(), DistributionError::NotRegistered, "{state:?}");
    }
    let unknown = BuildRequest::new(fieldseal_kernel::id::TenancyId::from([9; 32]), vec![*e.instrument.address()]);
    assert_eq!(e.w.build(&e.w.built_in_policy(), &unknown).unwrap_err(), DistributionError::NotRegistered);
}

pub fn dis_003_flagged_lost_closing_closed_and_retired_tenancies_are_withheld() {
    let e = Env::new();
    for state in [TenancyState::Flagged, TenancyState::Lost, TenancyState::Closing, TenancyState::Closed, TenancyState::Retired] {
        e.w.set_state(&e.d.tenancy, state).expect("state");
        assert!(matches!(e.build(), Err(DistributionError::Withheld(_))), "{state:?}");
    }
    e.w.set_state(&e.d.tenancy, TenancyState::Registered).expect("state");
    e.build().expect("registered again");
}

pub fn dis_002_release_names_the_policy_and_is_logged() {
    let e = Env::new();
    let policy = e.w.built_in_policy();
    let built = e.w.build(&policy, &e.request()).expect("builds");
    let ReleaseDecision::Release { policy: layers } = &built.decision else { panic!("released") };
    assert_eq!(layers, &[e.w.policy.address], "the decision records the policy content address");
    let content = e.content(&built.sealed.bytes);
    assert_eq!(content.policy.iter().map(|p| *p.address()).collect::<Vec<_>>(), *layers, "POL-050: the layer is in the bundle");
    assert_eq!(built.event, fieldseal_distribution::domain::DistributionEvent::BundleReleased { tenancy: e.d.tenancy, bundle: built.sealed.address, policy: layers.clone() });
}

pub fn dis_002_a_roster_for_unattested_keys_is_withheld_by_policy() {
    let w = DemoWorld::new(1, T0).expect("world");
    let ins = w.publish(ArtefactKind::Instrument, "health-check", "1.0.0", instrument_bytes("^1.0", "x"), Some(salt())).expect("publishes");
    let d = w.register("software-device", &[("cohort-a", 1)], false, profile()).expect("registers");
    w.assign_rosters(&d, vec![roster("cohort-a", 1, 1)]);
    let err = w.build(&w.built_in_policy(), &BuildRequest::new(d.tenancy, vec![*ins.address()])).unwrap_err();
    assert!(matches!(&err, DistributionError::Withheld(r) if r.iter().any(|x| x == "unattested-key-roster")), "{err:?}");
}

/// A policy engine that releases bundles without rosters (DIS-004) and otherwise decides like
/// the built-in one.
struct PracticeAllowed;
impl PolicyEngine for PracticeAllowed {
    fn evaluate(&self, point: DecisionPoint, policy: &EffectivePolicy, facts: &Facts) -> Result<Decision, PolicyEngineError> {
        if point == DecisionPoint::BundleRelease && facts.get("containsRoster") == Some(&Value::Bool(false)) {
            return Ok(Decision { point, verdict: Verdict::Allow, reasons: vec![], obligations: vec![], policy: policy.sources.clone() });
        }
        fieldseal_adapters_memory::policy::BuiltInPolicyEngine.evaluate(point, policy, facts)
    }
}

pub fn dis_004_a_practice_bundle_has_no_rosters_and_needs_policy_to_allow() {
    let e = Env::new();
    e.w.set_state(&e.d.tenancy, TenancyState::Pending).expect("state");
    let mut request = e.request();
    request.practice = true;
    // The built-in policy never releases to an unregistered tenancy.
    assert!(matches!(e.w.build(&e.w.built_in_policy(), &request), Err(DistributionError::Withheld(r)) if r.contains(&"tenancy-not-registered".to_owned())));
    // A policy that allows it releases a bundle with no rosters and no certificate.
    let built = e.w.build(&e.w.policy_service(PracticeAllowed), &request).expect("practice bundle");
    let content = e.content(&built.sealed.bytes);
    assert!(content.rosters.is_empty() && content.certificate.is_none());
    e.verify(&built.sealed.bytes).expect("a practice bundle verifies");
    // Rosters still can't go to an unregistered tenancy, whatever the policy says.
    request.practice = false;
    assert_eq!(e.w.build(&e.w.policy_service(PracticeAllowed), &request).unwrap_err(), DistributionError::NotRegistered);
}

fn other_key() -> SoftwareAgreementKey {
    let secret = fieldseal_kernel::seal::RecipientSecret::from_bytes(fieldseal_kernel::seal::Suite::Fs1P, &[0x42; 32]).expect("key");
    SoftwareAgreementKey::new(secret).expect("key")
}

fn seal_and_sign(e: &Env, plaintext: &[u8]) -> Vec<u8> {
    let sealed = seal_with_context(&mut SourceRng(&e.w.random), &RecipientKey::P256(e.d.agreement_public.clone()), &tags::BUNDLE_SEAL, e.d.tenancy.as_bytes(), plaintext).expect("seals");
    let sig = e
        .w
        .custody
        .sign(&e.w.factory, KeyRole::Purpose(Purpose::Factory), &tags::BUNDLE, &BundleFile::signed_structure(&sealed, &e.w.factory), "test")
        .expect("signs");
    BundleFile { sealed, signer: e.w.factory, chain: vec![], sig }.encode()
}

fn other_pub() -> fieldseal_kernel::crypto::P256PublicKey {
    let RecipientKey::P256(p) = fieldseal_kernel::seal::RecipientSecret::from_bytes(fieldseal_kernel::seal::Suite::Fs1P, &[0x42; 32]).unwrap().public().unwrap() else { panic!() };
    p
}

// ---- Tree-head age (PUB-072) -------------------------------------------------------------------

mod pub_072 {
    use super::*;
    use fieldseal_adapters_memory::distribution::sign_time_token;
    use fieldseal_publishing::domain::PublishingError;

    const MAX_AGE: u64 = 90 * AuthorityTime::DAY;

    fn artefact_error(r: Result<VerifiedBundle, BundleRejection>) -> PublishingError {
        match rejection(r) {
            BundleRejection::Artefact { error, .. } => error,
            other => panic!("expected an artefact rejection, found {other:?}"),
        }
    }

    /// Re-dates the bundle to `bundle_time` (a fresh, validly signed time token) and gives the
    /// instrument a tree-head token stating `tree_head_time`, then verifies at `bundle_time`.
    fn verify_dated(e: &Env, tree_head_time: Option<AuthorityTime>, bundle_time: AuthorityTime) -> Result<VerifiedBundle, BundleRejection> {
        let built = e.build().expect("builds");
        let mut content = e.content(&built.sealed.bytes);
        let token = sign_time_token(&e.w.custody, &e.w.receipt, bundle_time).expect("token");
        content.issued = bundle_time;
        content.time_token = token;
        content.instruments[0].checkpoint_time =
            tree_head_time.map(|t| sign_time_token(&e.w.custody, &e.w.receipt, t).expect("token").encode());
        let state = ImportState { tenancy: e.d.tenancy, now: bundle_time, held: HeldState::default() };
        VerifyBundle::new(&e.w.trust, &e.w.publishing, &e.d.agreement_key(), profile()).verify(&e.pack(&content), &state)
    }

    #[test]
    fn pub_072_a_bundle_whose_tree_heads_are_dated_and_recent_verifies() {
        let e = Env::new();
        let built = e.build().expect("builds");
        e.verify(&built.sealed.bytes).expect("the demo factory dates its tree heads");
    }

    #[test]
    fn pub_072_a_tree_head_with_no_time_token_is_too_old() {
        let e = Env::new();
        let bundle_time = AuthorityTime(T0.0 + 2 * AuthorityTime::DAY);
        assert_eq!(artefact_error(verify_dated(&e, None, bundle_time)), PublishingError::TreeHeadTooOld { age_ms: None, max_ms: MAX_AGE });
    }

    #[test]
    fn pub_072_age_is_measured_from_the_checkpoints_token_to_the_bundles_time_token() {
        let e = Env::new();
        let token = AuthorityTime(T0.0 + 3_600_000); // when the demo factory dated its other tree heads
        // Exactly the limit is accepted; a millisecond more is too old.
        verify_dated(&e, Some(token), AuthorityTime(token.0 + MAX_AGE)).expect("at the limit");
        let r = artefact_error(verify_dated(&e, Some(token), AuthorityTime(token.0 + MAX_AGE + 1)));
        assert_eq!(r, PublishingError::TreeHeadTooOld { age_ms: Some(MAX_AGE + 1), max_ms: MAX_AGE });
    }

    #[test]
    fn pub_072_a_forged_or_unreadable_checkpoint_token_is_refused() {
        let e = Env::new();
        let built = e.build().expect("builds");
        let bundle_time = AuthorityTime(T0.0 + 2 * AuthorityTime::DAY);
        for tamper in [|b: &mut Vec<u8>| *b.last_mut().expect("bytes") ^= 1, |b: &mut Vec<u8>| b.truncate(3)] {
            let mut content = e.content(&built.sealed.bytes);
            let mut bytes = content.instruments[0].checkpoint_time.clone().expect("dated");
            tamper(&mut bytes);
            content.instruments[0].checkpoint_time = Some(bytes);
            let state = ImportState { tenancy: e.d.tenancy, now: bundle_time, held: HeldState::default() };
            let r = VerifyBundle::new(&e.w.trust, &e.w.publishing, &e.d.agreement_key(), profile()).verify(&e.pack(&content), &state);
            assert!(matches!(artefact_error(r), PublishingError::CheckpointTime(_)));
        }
    }
}
// covers: DIS-001, DIS-002, DIS-003, DIS-004

const RELEASE: &[Check] = &[
    Check { reqs: &["DIS-001"], name: "no bundle before registration", run: dis_001_no_bundle_before_registration },
    Check { reqs: &["DIS-002"], name: "release names the policy and is logged", run: dis_002_release_names_the_policy_and_is_logged },
    Check { reqs: &["DIS-002"], name: "a roster for unattested keys is withheld by policy", run: dis_002_a_roster_for_unattested_keys_is_withheld_by_policy },
    Check { reqs: &["DIS-003"], name: "flagged, lost, closing, closed and retired tenancies are withheld", run: dis_003_flagged_lost_closing_closed_and_retired_tenancies_are_withheld },
    Check { reqs: &["DIS-004"], name: "a practice bundle has no rosters and needs policy to allow", run: dis_004_a_practice_bundle_has_no_rosters_and_needs_policy_to_allow },
];

/// The unit of the `dis-release` suite.
pub fn units() -> Vec<Unit> {
    vec![Unit::table("dis:release", &["dis-release"], RELEASE)]
}
