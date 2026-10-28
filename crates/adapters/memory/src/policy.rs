//! In-memory adapters for the Policy context's driven ports: the built-in policy engine, a
//! fixed policy source and an append-only decision log.

use std::cmp::Ordering;
use std::sync::Mutex;

use fieldseal_kernel::value::{Decimal, Value};
use fieldseal_policy::domain::{
    ARTEFACT_KINDS, ConsentWithoutEvidence, Date, Decision, DecisionPoint, DecisionRecord,
    Disposition, EffectivePolicy, Escalation, Facts, Layer, LayerSelector, Obligation,
    Assurance, CustodyMode, PostureFailure, PublishedPolicy, QualityFailure, SecurityLevel, SerialCheck, UnknownRestriction,
    Verdict,
};
use fieldseal_policy::ports::{
    DecisionLog, DecisionLogError, PolicyEngine, PolicyEngineError, PolicySource, PolicySourceError,
};

/// Collects what a rule found: reasons, the strongest verdict and obligations.
struct Outcome {
    verdict: Verdict,
    reasons: Vec<String>,
    obligations: Vec<Obligation>,
}

impl Outcome {
    fn new() -> Self {
        Self { verdict: Verdict::Allow, reasons: vec![], obligations: vec![] }
    }

    /// Records `reason` with `verdict`; the strongest verdict wins (deny, then hold, then flag).
    fn raise(&mut self, verdict: Verdict, reason: &str) {
        let rank = |v: Verdict| match v {
            Verdict::Allow => 0,
            Verdict::Flag => 1,
            Verdict::Hold => 2,
            Verdict::Deny => 3,
        };
        if rank(verdict) > rank(self.verdict) {
            self.verdict = verdict;
        }
        self.reasons.push(reason.to_owned());
    }
}

/// Typed access to facts, failing with the fact's name.
struct FactReader<'a>(&'a Facts);

impl FactReader<'_> {
    fn get(&self, name: &str) -> Result<&Value, PolicyEngineError> {
        self.0.get(name).ok_or_else(|| PolicyEngineError::MissingFact(name.to_owned()))
    }

    fn bool_(&self, name: &str) -> Result<bool, PolicyEngineError> {
        self.get(name)?.as_bool().ok_or_else(|| PolicyEngineError::BadFact(name.to_owned()))
    }

    fn uint(&self, name: &str) -> Result<u64, PolicyEngineError> {
        let i = self.get(name)?.as_int().ok_or_else(|| PolicyEngineError::BadFact(name.to_owned()))?;
        u64::try_from(i).map_err(|_| PolicyEngineError::BadFact(name.to_owned()))
    }

    fn text(&self, name: &str) -> Result<&str, PolicyEngineError> {
        self.get(name)?.as_text().ok_or_else(|| PolicyEngineError::BadFact(name.to_owned()))
    }

    fn texts(&self, name: &str) -> Result<Vec<&str>, PolicyEngineError> {
        self.get(name)?
            .as_array()
            .ok_or_else(|| PolicyEngineError::BadFact(name.to_owned()))?
            .iter()
            .map(|v| v.as_text().ok_or_else(|| PolicyEngineError::BadFact(name.to_owned())))
            .collect()
    }

    /// Exactly a decimal: an integer is not widened (as the OPA adapter).
    fn decimal(&self, name: &str) -> Result<Decimal, PolicyEngineError> {
        match self.get(name)? {
            Value::Decimal(d) => Ok(*d),
            _ => Err(PolicyEngineError::BadFact(name.to_owned())),
        }
    }
}

/// The reference [`PolicyEngine`]: evaluates every decision point directly from the typed
/// effective policy. Deterministic, side-effect free and instantaneous, so it never times out.
/// Other engines (for example Open Policy Agent) must reach the same outcomes, which the
/// contract tests check.
#[derive(Clone, Copy, Default, Debug)]
pub struct BuiltInPolicyEngine;

impl PolicyEngine for BuiltInPolicyEngine {
    fn evaluate(
        &self,
        point: DecisionPoint,
        policy: &EffectivePolicy,
        facts: &Facts,
    ) -> Result<Decision, PolicyEngineError> {
        check_facts(point, facts)?;
        let f = FactReader(facts);
        let mut out = Outcome::new();
        match point {
            DecisionPoint::RegistrationTokenIssue => token_issue(policy, &f, &mut out)?,
            DecisionPoint::RegistrationApprove => approve(policy, &f, &mut out)?,
            DecisionPoint::DeviceAdd => {
                let max = policy.factory().registration.max_devices_per_account;
                if f.uint("activeDevices")? >= max {
                    out.raise(Verdict::Deny, "device-limit-reached");
                }
            }
            DecisionPoint::KeyRoll => {
                if !f.bool_("postureOk")? {
                    out.raise(Verdict::Hold, "posture-not-ok");
                }
            }
            DecisionPoint::BundleRelease => release(policy, &f, &mut out)?,
            DecisionPoint::PostureRecheck => posture(policy, &f, &mut out)?,
            DecisionPoint::ArtefactPublish => publish(policy, &f, &mut out)?,
            DecisionPoint::IntakeAccept => accept(policy, &f, &mut out)?,
            DecisionPoint::ConsentDecide => consent(policy, &f, &mut out)?,
            DecisionPoint::TenancyLate => late(policy, &f, &mut out)?,
            DecisionPoint::KeyIssue => key_issue(policy, &f, &mut out)?,
        }
        Ok(Decision {
            point,
            verdict: out.verdict,
            reasons: out.reasons,
            obligations: out.obligations,
            policy: policy.sources.clone(),
        })
    }
}

/// `key.issue` (POL-067): the key's assurance and mode against the purpose's minimums, and a
/// cold root or publisher issuance against its custodian threshold.
fn key_issue(policy: &EffectivePolicy, f: &FactReader, out: &mut Outcome) -> Result<(), PolicyEngineError> {
    let custody = policy.factory().custody;
    let purpose = f.text("purpose")?;
    let assurance = Assurance::parse(f.text("assurance")?).ok_or_else(|| PolicyEngineError::BadFact("assurance".to_owned()))?;
    let mode = CustodyMode::parse(f.text("mode")?).ok_or_else(|| PolicyEngineError::BadFact("mode".to_owned()))?;
    let thresholds_met = f.bool_("thresholdMet")?;
    let (Some(min_assurance), Some(min_mode)) = (custody.min_assurance.get(purpose), custody.min_mode.get(purpose)) else {
        return Err(PolicyEngineError::BadFact("purpose".to_owned()));
    };
    if assurance < *min_assurance {
        out.raise(Verdict::Deny, "assurance-below-minimum");
    }
    if mode < *min_mode {
        out.raise(Verdict::Deny, "mode-below-minimum");
    }
    if mode == CustodyMode::Cold && matches!(purpose, "root" | "publisher") && !thresholds_met {
        out.raise(Verdict::Hold, "custodian-threshold-pending");
    }
    Ok(())
}

/// The type of a fact; the table below mirrors the OPA adapter's, rule for rule, so both
/// engines refuse the same inputs (the parity tests in `fieldseal-adapters-opa` check it).
#[derive(Clone, Copy)]
enum Kind {
    Bool,
    Uint,
    Text,
    Texts,
    Draw,
    OneOf(&'static [&'static str]),
    Artefact,
    Level,
    Day,
}

fn fact_types(point: DecisionPoint) -> &'static [(&'static str, Kind)] {
    use DecisionPoint::*;
    use Kind::*;
    match point {
        RegistrationTokenIssue => &[
            ("batch", Bool),
            ("airGapped", Bool),
            ("requestedTtlSeconds", Uint),
            ("role", Text),
            ("phishingResistantAuth", Bool),
        ],
        RegistrationApprove => &[
            ("fingerprintConfirmed", Bool),
            ("serialStatus", OneOf(&["matched", "unmatched", "absent"])),
            ("nonceOnly", Bool),
        ],
        DeviceAdd => &[("activeDevices", Uint)],
        KeyRoll => &[("postureOk", Bool)],
        BundleRelease => &[
            ("tenancyRegistered", Bool),
            ("containsRoster", Bool),
            ("keyAttested", Bool),
            ("activeTenanciesInCohort", Uint),
            ("paused", Bool),
            ("unattestedAllowed", Bool),
        ],
        PostureRecheck => &[
            ("verifiedBoot", Bool),
            ("bootloaderLocked", Bool),
            ("securityLevel", Level),
            ("osPatchLevel", Day),
            ("unknownRestriction", Bool),
        ],
        ArtefactPublish => &[
            ("kind", Artefact),
            ("approvals", Uint),
            ("authorIsApprover", Bool),
            ("publisherSignatures", Uint),
            ("builder", Text),
            ("source", Text),
            ("inclusionProof", Bool),
            ("witnessCosignatures", Uint),
        ],
        IntakeAccept => &[("sizeBytes", Uint), ("qualityFailures", Uint)],
        ConsentDecide => &[("hasEvidence", Bool), ("heuristicHits", Texts), ("sampleDraw", Draw)],
        TenancyLate => &[("lateSeconds", Uint), ("provablyLate", Bool), ("fastRunning", Bool)],
        KeyIssue => &[
            ("purpose", OneOf(&["root", "factory", "registration", "publisher", "builder", "receipt", "receiver", "record"])),
            ("assurance", OneOf(&["development", "custody-bound", "attested"])),
            ("mode", OneOf(&["hot", "cold"])),
            ("thresholdMet", Bool),
        ],
    }
}

fn fact_ok(kind: Kind, value: &Value) -> bool {
    match kind {
        Kind::Bool => value.as_bool().is_some(),
        Kind::Uint => value.as_int().is_some_and(|i| u64::try_from(i).is_ok()),
        Kind::Text => value.as_text().is_some(),
        Kind::Texts => value.as_array().is_some_and(|a| a.iter().all(|v| v.as_text().is_some())),
        Kind::Draw => {
            let Value::Decimal(d) = value else { return false };
            let (zero, one) = (Decimal { mantissa: 0, exponent: 0 }, Decimal { mantissa: 1, exponent: 0 });
            d.numeric_cmp(zero).is_some_and(|o| o.is_ge()) && d.numeric_cmp(one).is_some_and(|o| o.is_lt())
        }
        Kind::OneOf(words) => value.as_text().is_some_and(|t| words.contains(&t)),
        Kind::Artefact => value.as_text().is_some_and(|t| ARTEFACT_KINDS.contains(&t)),
        Kind::Level => value.as_text().and_then(SecurityLevel::parse).is_some(),
        Kind::Day => value.as_text().is_some_and(|t| Date::parse(t).is_ok()),
    }
}

/// Refuses facts that are not exactly those of `point`: an unknown fact, a missing one or one of
/// the wrong type or outside its range is an error, never a decision.
fn check_facts(point: DecisionPoint, facts: &Facts) -> Result<(), PolicyEngineError> {
    let known = fact_types(point);
    if let Some(unknown) = facts.keys().find(|k| !known.iter().any(|(name, _)| name == k)) {
        return Err(PolicyEngineError::BadFact(format!("{unknown} (not a fact of {})", point.name())));
    }
    for (name, kind) in known {
        let value = facts.get(*name).ok_or_else(|| PolicyEngineError::MissingFact((*name).to_owned()))?;
        if !fact_ok(*kind, value) {
            return Err(PolicyEngineError::BadFact((*name).to_owned()));
        }
    }
    Ok(())
}

fn token_issue(policy: &EffectivePolicy, f: &FactReader, out: &mut Outcome) -> Result<(), PolicyEngineError> {
    let reg = policy.factory().registration;
    let (batch, air_gapped) = (f.bool_("batch")?, f.bool_("airGapped")?);
    let requested = f.uint("requestedTtlSeconds")?;
    let role = f.text("role")?;
    let phishing_resistant = f.bool_("phishingResistantAuth")?;
    if reg.require_phishing_resistant_auth && !phishing_resistant {
        out.raise(Verdict::Deny, "phishing-resistant-auth-required");
    }
    let limit = if batch {
        if !reg.batch_tokens.allowed {
            out.raise(Verdict::Deny, "batch-tokens-not-allowed");
        } else if !reg.batch_tokens.roles.iter().any(|r| r == role) {
            out.raise(Verdict::Deny, "batch-role-not-allowed");
        }
        reg.batch_tokens.ttl
    } else if air_gapped {
        reg.air_gapped_token_ttl
    } else {
        reg.token_ttl
    };
    if requested > limit.as_secs() {
        out.raise(Verdict::Deny, "ttl-exceeds-policy");
    }
    Ok(())
}

fn approve(policy: &EffectivePolicy, f: &FactReader, out: &mut Outcome) -> Result<(), PolicyEngineError> {
    let reg = policy.factory().registration;
    let confirmed = f.bool_("fingerprintConfirmed")?;
    let serial = f.text("serialStatus")?;
    let nonce_only = f.bool_("nonceOnly")?;
    if !["matched", "unmatched", "absent"].contains(&serial) {
        return Err(PolicyEngineError::BadFact("serialStatus".to_owned()));
    }
    if reg.require_fingerprint_confirmation && !confirmed {
        out.raise(Verdict::Hold, "fingerprint-unconfirmed");
    }
    match (reg.serial_check, serial) {
        (SerialCheck::Off, _) | (_, "matched") => {}
        (SerialCheck::Required, "unmatched") => out.raise(Verdict::Deny, "serial-mismatch"),
        (SerialCheck::Required, _) => out.raise(Verdict::Hold, "serial-missing"),
        (SerialCheck::Optional, "unmatched") => out.raise(Verdict::Hold, "serial-mismatch-review"),
        (SerialCheck::Optional, _) => {}
    }
    if nonce_only {
        match reg.device_nonce_registrations {
            Disposition::Allow => {}
            Disposition::Flag => out.raise(Verdict::Flag, "device-nonce-registration"),
            Disposition::Deny => out.raise(Verdict::Deny, "device-nonce-registration-denied"),
        }
    }
    Ok(())
}

fn release(policy: &EffectivePolicy, f: &FactReader, out: &mut Outcome) -> Result<(), PolicyEngineError> {
    let factory = policy.factory();
    let registered = f.bool_("tenancyRegistered")?;
    let roster = f.bool_("containsRoster")?;
    let attested = f.bool_("keyAttested")?;
    let active = f.uint("activeTenanciesInCohort")?;
    let paused = f.bool_("paused")?;
    if factory.require_registered_tenancy && !registered {
        out.raise(Verdict::Deny, "tenancy-not-registered");
    }
    // Configuration of the factory, not a fact about the device: the non-production allowance
    // for unattested keys (REG-017). Absent means refused.
    let allowed = f.get("unattestedAllowed").ok().and_then(Value::as_bool).unwrap_or(false);
    if roster && !attested {
        if allowed {
            // Development only: released with a flag, so the decision log says why.
            out.raise(Verdict::Flag, "unattested-key-roster-development-allowance");
        } else {
            // INV-10: bundles with rosters are never released to unattested keys.
            out.raise(Verdict::Deny, "unattested-key-roster");
        }
    }
    if active >= factory.max_active_tenancies_per_cohort {
        out.raise(Verdict::Hold, "cohort-tenancy-limit");
    }
    if paused {
        out.raise(Verdict::Hold, "release-paused");
    }
    Ok(())
}

fn posture(policy: &EffectivePolicy, f: &FactReader, out: &mut Outcome) -> Result<(), PolicyEngineError> {
    let factory = policy.factory();
    let att = &factory.attestation;
    let level = SecurityLevel::parse(f.text("securityLevel")?)
        .ok_or_else(|| PolicyEngineError::BadFact("securityLevel".to_owned()))?;
    let patch = Date::parse(f.text("osPatchLevel")?).map_err(|_| PolicyEngineError::BadFact("osPatchLevel".to_owned()))?;
    let mut failed = false;
    let mut fail = |out: &mut Outcome, reason: &str| {
        failed = true;
        out.reasons.push(reason.to_owned());
    };
    if att.require_verified_boot && !f.bool_("verifiedBoot")? {
        fail(out, "verified-boot-failed");
    }
    if att.require_bootloader_locked && !f.bool_("bootloaderLocked")? {
        fail(out, "bootloader-unlocked");
    }
    if level < att.min_security_level {
        fail(out, "security-level-too-low");
    }
    if att.min_os_patch_level.is_some_and(|min| patch < min) {
        fail(out, "os-patch-level-too-old");
    }
    if failed {
        out.verdict = Verdict::Flag;
        if factory.posture.on_failure == PostureFailure::PauseRelease {
            out.obligations.push(Obligation::PauseRelease);
        }
    }
    if f.bool_("unknownRestriction")? && factory.posture.unknown_restriction == UnknownRestriction::Flag {
        out.raise(Verdict::Flag, "unknown-restriction");
    }
    Ok(())
}

fn publish(policy: &EffectivePolicy, f: &FactReader, out: &mut Outcome) -> Result<(), PolicyEngineError> {
    let publishing = policy.publishing();
    let kind = f.text("kind")?;
    let kind_policy = publishing
        .kinds
        .get(kind)
        .filter(|_| ARTEFACT_KINDS.contains(&kind))
        .ok_or_else(|| PolicyEngineError::BadFact("kind".to_owned()))?;
    if f.bool_("authorIsApprover")? && !publishing.author_may_approve {
        out.raise(Verdict::Deny, "author-approval-not-allowed");
    }
    if f.uint("approvals")? < kind_policy.required_approvals {
        out.raise(Verdict::Deny, "insufficient-approvals");
    }
    if f.uint("publisherSignatures")? < kind_policy.publisher_threshold.m {
        out.raise(Verdict::Deny, "insufficient-publisher-signatures");
    }
    let (builder, source) = (f.text("builder")?, f.text("source")?);
    if !publishing.allowed_builders.iter().any(|b| b == builder) {
        out.raise(Verdict::Deny, "builder-not-allowed");
    }
    if !publishing.allowed_sources.iter().any(|s| s == source) {
        out.raise(Verdict::Deny, "source-not-allowed");
    }
    if publishing.require_transparency_log && !f.bool_("inclusionProof")? {
        out.raise(Verdict::Deny, "no-inclusion-proof");
    }
    if f.uint("witnessCosignatures")? < publishing.required_witness_cosignatures {
        out.raise(Verdict::Deny, "insufficient-witness-cosignatures");
    }
    Ok(())
}

fn accept(policy: &EffectivePolicy, f: &FactReader, out: &mut Outcome) -> Result<(), PolicyEngineError> {
    let intake = policy.intake();
    if f.uint("sizeBytes")? > intake.max_submission_size.as_bytes() {
        out.raise(Verdict::Deny, "submission-too-large");
    }
    if f.uint("qualityFailures")? > 0 {
        out.raise(Verdict::Flag, "data-quality-failure");
        if intake.data_quality_on_failure == QualityFailure::Quarantine {
            out.obligations.push(Obligation::Quarantine);
        }
    }
    Ok(())
}

fn consent(policy: &EffectivePolicy, f: &FactReader, out: &mut Outcome) -> Result<(), PolicyEngineError> {
    let c = policy.intake().consent;
    let has_evidence = f.bool_("hasEvidence")?;
    let hits = f.texts("heuristicHits")?;
    let draw = f.decimal("sampleDraw")?;
    let zero = Decimal { mantissa: 0, exponent: 0 };
    let one = Decimal { mantissa: 1, exponent: 0 };
    if draw.numeric_cmp(zero).is_none_or(|o| o == Ordering::Less) || draw.numeric_cmp(one).is_none_or(|o| o != Ordering::Less) {
        return Err(PolicyEngineError::BadFact("sampleDraw".to_owned()));
    }
    if hits.iter().any(|h| c.heuristics.iter().any(|x| x == h)) {
        out.raise(Verdict::Hold, "heuristic-hit");
    }
    if has_evidence {
        if !c.auto_accept_with_evidence {
            out.raise(Verdict::Hold, "evidence-needs-review");
        } else if out.verdict == Verdict::Allow && draw.numeric_cmp(c.sample_rate) == Some(Ordering::Less) {
            out.obligations.push(Obligation::SampleForReview);
        }
    } else {
        match c.without_evidence {
            ConsentWithoutEvidence::Accept => {}
            ConsentWithoutEvidence::Review => out.raise(Verdict::Hold, "no-evidence"),
            ConsentWithoutEvidence::Deny => out.raise(Verdict::Deny, "no-evidence-denied"),
        }
    }
    Ok(())
}

fn late(policy: &EffectivePolicy, f: &FactReader, out: &mut Outcome) -> Result<(), PolicyEngineError> {
    let intake = policy.intake();
    let (late, provable, fast) = (f.uint("lateSeconds")?, f.bool_("provablyLate")?, f.bool_("fastRunning")?);
    let verdict_for = |e: Escalation| if e == Escalation::Deny { Verdict::Deny } else { Verdict::Flag };
    if fast {
        out.raise(verdict_for(intake.fast_running), "clock-running-fast");
    }
    if late > intake.time_grace.as_secs() {
        if provable {
            out.raise(verdict_for(intake.provably_late), "provably-late");
        } else {
            out.raise(Verdict::Flag, "late-beyond-grace");
        }
    }
    Ok(())
}

/// An in-memory [`PolicySource`] serving fixed policies, deployment layer first.
#[derive(Default)]
pub struct MemoryPolicySource {
    policies: Mutex<Vec<PublishedPolicy>>,
}

impl MemoryPolicySource {
    /// A source serving `policies`, which it orders deployment layer first.
    pub fn new(mut policies: Vec<PublishedPolicy>) -> Self {
        policies.sort_by_key(|p| p.document.layer.rank());
        Self { policies: Mutex::new(policies) }
    }
}

impl PolicySource for MemoryPolicySource {
    fn policies(&self, selector: &LayerSelector) -> Result<Vec<PublishedPolicy>, PolicySourceError> {
        Ok(self
            .policies
            .lock()
            .expect("lock")
            .iter()
            .filter(|p| match &p.document.layer {
                Layer::Deployment => true,
                Layer::Programme(name) => selector.programme.as_deref() == Some(name.as_str()),
                Layer::Instrument(r) => selector.instrument.as_ref() == Some(r),
            })
            .cloned()
            .collect())
    }
}

/// An in-memory, append-only [`DecisionLog`].
#[derive(Default)]
pub struct MemoryDecisionLog {
    entries: Mutex<Vec<DecisionRecord>>,
}

impl MemoryDecisionLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }
}

impl DecisionLog for MemoryDecisionLog {
    fn append(&self, record: &DecisionRecord) -> Result<u64, DecisionLogError> {
        let mut entries = self.entries.lock().expect("lock");
        entries.push(record.clone());
        Ok(entries.len() as u64 - 1)
    }

    fn read(&self, index: u64) -> Result<DecisionRecord, DecisionLogError> {
        self.entries
            .lock()
            .expect("lock")
            .get(index as usize)
            .cloned()
            .ok_or(DecisionLogError::NotFound)
    }

    fn len(&self) -> u64 {
        self.entries.lock().expect("lock").len() as u64
    }
}
