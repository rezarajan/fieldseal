//! Contract tests for adapters of the Policy context's driven ports. An adapter's own test
//! module calls these with a constructor for the adapter.

use fieldseal_kernel::id::{ContentAddress, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::value::Value;

use crate::domain::{
    ChangeDirection, Decision, DecisionPoint, DecisionRecord, Facts, Layer, LayerSelector, Obligation,
    Subject, Verdict,
};
use crate::fixtures::{DocBuilder, dec, effective, effective_default, facts, int, text, words};
use crate::ports::{DecisionLog, DecisionLogError, PolicyEngine, PolicyEngineError, PolicySource};

/// One conformance case for a [`PolicyEngine`]: facts at a decision point under the default
/// deployment policy ([`crate::fixtures::default_deployment_policy`]) and the outcome every
/// adapter must reach.
#[derive(Clone, Debug)]
pub struct EngineCase {
    /// A name for failure messages.
    pub name: &'static str,
    /// The decision point.
    pub point: DecisionPoint,
    /// The input facts.
    pub facts: Facts,
    /// The required verdict.
    pub verdict: Verdict,
    /// The required obligations.
    pub obligations: Vec<Obligation>,
}

fn case(name: &'static str, point: DecisionPoint, f: Facts, verdict: Verdict, obligations: &[Obligation]) -> EngineCase {
    EngineCase { name, point, facts: f, verdict, obligations: obligations.to_vec() }
}

fn b(v: bool) -> Value {
    Value::Bool(v)
}

/// Cases covering every decision point (POL §6.2) under the default deployment policy, in
/// both the allowing and the refusing direction where the point has both.
pub fn engine_cases() -> Vec<EngineCase> {
    use DecisionPoint::*;
    use Verdict::*;
    let token = |ttl: i128, batch: bool, role: &str, phishing: bool| {
        facts(&[
            ("batch", b(batch)),
            ("airGapped", b(false)),
            ("requestedTtlSeconds", int(ttl)),
            ("role", text(role)),
            ("phishingResistantAuth", b(phishing)),
        ])
    };
    let approve = |confirmed: bool, serial: &str, nonce: bool| {
        facts(&[("fingerprintConfirmed", b(confirmed)), ("serialStatus", text(serial)), ("nonceOnly", b(nonce))])
    };
    let release_with = |registered: bool, roster: bool, attested: bool, allowed: bool, active: i128, paused: bool| {
        facts(&[
            ("tenancyRegistered", b(registered)),
            ("containsRoster", b(roster)),
            ("keyAttested", b(attested)),
            ("unattestedAllowed", b(allowed)),
            ("activeTenanciesInCohort", int(active)),
            ("paused", b(paused)),
        ])
    };
    let release = |registered: bool, roster: bool, attested: bool, active: i128, paused: bool| release_with(registered, roster, attested, false, active, paused);
    let posture = |boot: bool, locked: bool, unknown: bool| {
        facts(&[
            ("verifiedBoot", b(boot)),
            ("bootloaderLocked", b(locked)),
            ("securityLevel", text("strongbox")),
            ("osPatchLevel", text("2026-07-01")),
            ("unknownRestriction", b(unknown)),
        ])
    };
    let publish = |approvals: i128, sigs: i128, builder: &str, proof: bool| {
        facts(&[
            ("kind", text("Instrument")),
            ("approvals", int(approvals)),
            ("authorIsApprover", b(false)),
            ("publisherSignatures", int(sigs)),
            ("builder", text(builder)),
            ("source", text("https://git.example.org/authority/artefacts")),
            ("inclusionProof", b(proof)),
            ("witnessCosignatures", int(0)),
        ])
    };
    let builder = "https://ci.example.org/builders/fieldseal-publish";
    let consent = |evidence: bool, draw: &str, hits: &[&str]| {
        facts(&[("hasEvidence", b(evidence)), ("heuristicHits", words(hits)), ("sampleDraw", dec(draw))])
    };
    let late = |secs: i128, provable: bool, fast: bool| {
        facts(&[("lateSeconds", int(secs)), ("provablyLate", b(provable)), ("fastRunning", b(fast))])
    };
    let issue = |purpose: &str, assurance: &str, mode: &str, threshold: bool| {
        facts(&[("purpose", text(purpose)), ("assurance", text(assurance)), ("mode", text(mode)), ("thresholdMet", b(threshold))])
    };
    let day = 86_400;
    vec![
        case("token within ttl", RegistrationTokenIssue, token(600, false, "collector", true), Allow, &[]),
        case("token over ttl", RegistrationTokenIssue, token(601, false, "collector", true), Deny, &[]),
        case("token without phishing-resistant auth", RegistrationTokenIssue, token(60, false, "collector", false), Deny, &[]),
        case("batch token for a listed role", RegistrationTokenIssue, token(3600, true, "device-preparation", true), Allow, &[]),
        case("batch token for a collector", RegistrationTokenIssue, token(60, true, "collector", true), Deny, &[]),
        case("approve clean", RegistrationApprove, approve(true, "matched", false), Allow, &[]),
        case("approve unconfirmed fingerprint", RegistrationApprove, approve(false, "matched", false), Hold, &[]),
        case("approve nonce-only registration", RegistrationApprove, approve(true, "matched", true), Flag, &[]),
        case("device below the limit", DeviceAdd, facts(&[("activeDevices", int(1))]), Allow, &[]),
        case("device at the limit", DeviceAdd, facts(&[("activeDevices", int(2))]), Deny, &[]),
        case("key roll with good posture", KeyRoll, facts(&[("postureOk", b(true))]), Allow, &[]),
        case("key roll with bad posture", KeyRoll, facts(&[("postureOk", b(false))]), Hold, &[]),
        case("release to a registered tenancy", BundleRelease, release(true, true, true, 0, false), Allow, &[]),
        case("release to an unregistered tenancy", BundleRelease, release(false, false, true, 0, false), Deny, &[]),
        case("roster to an unattested key", BundleRelease, release(true, true, false, 0, false), Deny, &[]),
        case("roster to an unattested key under the development allowance (REG-017)", BundleRelease, release_with(true, true, false, true, 0, false), Flag, &[]),
        case("release when the cohort is full", BundleRelease, release(true, false, true, 1, false), Hold, &[]),
        case("release while paused", BundleRelease, release(true, false, true, 0, true), Hold, &[]),
        case("posture ok", PostureRecheck, posture(true, true, false), Allow, &[]),
        case("posture bootloader unlocked", PostureRecheck, posture(true, false, false), Flag, &[Obligation::PauseRelease]),
        case("publish with approvals", ArtefactPublish, publish(2, 2, builder, true), Allow, &[]),
        case("publish below approvals", ArtefactPublish, publish(1, 2, builder, true), Deny, &[]),
        case("publish below threshold", ArtefactPublish, publish(2, 1, builder, true), Deny, &[]),
        case("publish from an unknown builder", ArtefactPublish, publish(2, 2, "https://evil.example/b", true), Deny, &[]),
        case("publish without inclusion proof", ArtefactPublish, publish(2, 2, builder, false), Deny, &[]),
        case("intake small clean", IntakeAccept, facts(&[("sizeBytes", int(1024)), ("qualityFailures", int(0))]), Allow, &[]),
        case("intake too large", IntakeAccept, facts(&[("sizeBytes", int(600 * 1024 * 1024)), ("qualityFailures", int(0))]), Deny, &[]),
        case("intake quality failure", IntakeAccept, facts(&[("sizeBytes", int(1024)), ("qualityFailures", int(2))]), Flag, &[]),
        case("consent with evidence, not sampled", ConsentDecide, consent(true, "0.50", &[]), Allow, &[]),
        case("consent with evidence, sampled", ConsentDecide, consent(true, "0.01", &[]), Allow, &[Obligation::SampleForReview]),
        case("consent without evidence", ConsentDecide, consent(false, "0.50", &[]), Hold, &[]),
        case("root issued cold, custody-bound, threshold met", KeyIssue, issue("root", "custody-bound", "cold", true), Allow, &[]),
        case("root issued cold without its threshold", KeyIssue, issue("root", "attested", "cold", false), Hold, &[]),
        case("root issued hot", KeyIssue, issue("root", "attested", "hot", true), Deny, &[]),
        case("development key", KeyIssue, issue("registration", "development", "hot", true), Deny, &[]),
        case("registration key hot and attested", KeyIssue, issue("registration", "attested", "hot", true), Allow, &[]),
        case("registration key cold", KeyIssue, issue("registration", "custody-bound", "cold", true), Allow, &[]),
        case("tenancy within grace", TenancyLate, late(10 * day, true, false), Allow, &[]),
        case("tenancy provably late", TenancyLate, late(40 * day, true, false), Flag, &[]),
        case("tenancy clock running fast", TenancyLate, late(day, false, true), Flag, &[]),
    ]
}

/// [`PolicyEngine`]: deterministic, explains non-`Allow` outcomes, names its policy, reaches
/// the outcomes of [`engine_cases`], and fails rather than allows when facts are missing
/// (POL-032, POL-033, POL-034).
pub fn policy_engine_contract<E: PolicyEngine>(make: impl Fn() -> E) {
    let engine = make();
    let policy = effective_default();
    for c in engine_cases() {
        let a = engine
            .evaluate(c.point, &policy, &c.facts)
            .unwrap_or_else(|e| panic!("{}: {e}", c.name));
        let again = engine.evaluate(c.point, &policy, &c.facts).expect("evaluate");
        assert_eq!(a, again, "{}: evaluation must be deterministic", c.name);
        assert_eq!(a.verdict, c.verdict, "{}: wrong verdict ({:?})", c.name, a.reasons);
        assert_eq!(a.obligations, c.obligations, "{}: wrong obligations", c.name);
        assert_eq!(a.point, c.point, "{}: the decision must name its point", c.name);
        assert_eq!(a.policy, policy.sources, "{}: the decision must name the policy's sources", c.name);
        if a.verdict != Verdict::Allow {
            assert!(!a.reasons.is_empty(), "{}: a non-allow outcome needs reasons", c.name);
        }
    }
    for point in DecisionPoint::ALL {
        let outcome = engine.evaluate(point, &policy, &Facts::new());
        assert!(
            matches!(outcome, Err(PolicyEngineError::MissingFact(_) | PolicyEngineError::BadFact(_))),
            "{}: missing facts must be an error, never a decision: {outcome:?}",
            point.name()
        );
    }
    // Policy changes the outcome: a programme layer with a smaller device limit.
    let tighter = effective(&[
        crate::fixtures::default_deployment_policy(),
        DocBuilder::programme("one-device", "1.0.0", "one-device")
            .set("factory.registration.maxDevicesPerAccount", int(1))
            .build(),
    ]);
    let d = engine
        .evaluate(DecisionPoint::DeviceAdd, &tighter, &facts(&[("activeDevices", int(1))]))
        .expect("evaluate");
    assert_eq!(d.verdict, Verdict::Deny, "the engine must read the effective policy");
    assert_eq!(d.policy.len(), 2, "both layers are named");
}

/// [`PolicySource`]: returns layers outermost first and only those in scope.
///
/// `make` receives the published policies to serve, in any order.
pub fn policy_source_contract<S: PolicySource>(make: impl Fn(Vec<crate::domain::PublishedPolicy>) -> S) {
    let publish = |value: &Value, byte: u8| crate::domain::PublishedPolicy {
        address: ContentAddress::from([byte; 32]),
        document: crate::domain::decode_document(value).document.expect("valid fixture"),
    };
    let deployment = publish(&crate::fixtures::default_deployment_policy(), 1);
    let programme = publish(&crate::fixtures::programme_a_policy(), 2);
    let other = publish(
        &DocBuilder::programme("programme-b", "1.0.0", "programme-b").build(),
        3,
    );
    let source = make(vec![other, programme.clone(), deployment.clone()]);
    let docs = source
        .policies(&LayerSelector { programme: Some("programme-a".into()), instrument: None })
        .expect("policies");
    assert_eq!(docs, vec![deployment.clone(), programme], "deployment first, then the programme in scope only");
    assert_eq!(docs[0].document.layer, Layer::Deployment);
    let alone = source.policies(&LayerSelector::default()).expect("policies");
    assert_eq!(alone, vec![deployment], "no programme selected means the deployment layer alone");
}

/// [`DecisionLog`]: append-only, reads back unchanged.
pub fn decision_log_contract<L: DecisionLog>(make: impl Fn() -> L) {
    let log = make();
    assert!(log.is_empty(), "a new log is empty");
    let first_record = DecisionRecord {
        decision: Decision {
            point: DecisionPoint::DeviceAdd,
            verdict: Verdict::Deny,
            reasons: vec!["device-limit-reached".into()],
            obligations: vec![],
            policy: vec![ContentAddress::from([1; 32])],
        },
        input_digest: crate::domain::facts_digest(DecisionPoint::DeviceAdd, &Facts::new()),
        subject: Subject::Tenancy(TenancyId::from([4; 32])),
        at: AuthorityTime(1_000),
        resolves: None,
    };
    let first = log.append(&first_record).expect("append");
    let mut second_record = first_record.clone();
    second_record.decision.verdict = Verdict::Allow;
    second_record.decision.reasons.clear();
    second_record.at = AuthorityTime(2_000);
    second_record.resolves = Some(first);
    let second = log.append(&second_record).expect("append");
    assert_eq!(second, first + 1, "indices must increase by one");
    assert_eq!(log.read(first).expect("read"), first_record, "entries must read back unchanged");
    assert_eq!(log.read(second).expect("read"), second_record, "entries must read back unchanged");
    assert_eq!(log.len(), 2, "length counts entries");
    assert_eq!(log.read(99), Err(DecisionLogError::NotFound), "missing entries are not found");
}

/// Checks the direction marks a diff gives for a known pair of documents; shared by tests of
/// any `DiffPolicies` implementation.
pub fn diff_marks_tighter_and_looser<D: crate::application::DiffPolicies>(diff: &D) {
    let before = crate::fixtures::default_deployment_policy();
    let after = DocBuilder::deployment("authority-baseline", "3.2.0")
        .set("factory.registration.maxDevicesPerAccount", int(1))
        .set("runtime.session.idleLock", text("10m"))
        .set("runtime.retention.remindAfter", text("3d"))
        .build();
    let changes = diff.diff(&before, &after).expect("valid documents");
    let direction = |path: &str| changes.iter().find(|c| c.path == path).map(|c| c.direction);
    assert_eq!(direction("factory.registration.maxDevicesPerAccount"), Some(ChangeDirection::Tighter));
    assert_eq!(direction("runtime.session.idleLock"), Some(ChangeDirection::Looser));
    assert_eq!(direction("runtime.retention.remindAfter"), Some(ChangeDirection::Changed));
}
