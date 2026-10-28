//! Open Policy Agent adapter for the Policy context's [`PolicyEngine`] port
//! (`docs/reference/spec/policy.md` §4; ADR 0011).
//!
//! The decision logic is Rego, in `policy/policy.rego`, written to mirror the reference engine
//! (`BuiltInPolicyEngine` in `fieldseal-adapters-memory`) rule for rule. This crate:
//!
//! 1. checks the facts for the decision point (missing or mistyped facts are errors, never
//!    decisions, as for every engine) and turns the effective policy into the JSON document the
//!    Rego reads (durations in seconds, sizes in bytes);
//! 2. runs OPA, either as `opa eval` ([`OpaConfig::Binary`]) or against OPA's REST API
//!    ([`OpaConfig::Rest`]), chosen by configuration;
//! 3. reads the answer back as a [`Decision`].
//!
//! **Failing closed (POL-034).** Anything that goes wrong with OPA (it cannot be started, it
//! times out, it exits non-zero, it prints something unreadable, the answer is undefined or
//! carries an unknown verdict) is a [`PolicyEngineError`]. Callers turn that into `hold` or
//! `flag`; this adapter never produces `allow` from a failure. A timeout kills the `opa`
//! process, so evaluation cannot hang (POL §4).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fieldseal_kernel::value::{Decimal, Value};
use fieldseal_policy::domain::{
    ARTEFACT_KINDS, Date, Decision, DecisionPoint, EffectivePolicy, Facts, Obligation, SecurityLevel, Verdict,
};
use fieldseal_policy::ports::{PolicyEngine, PolicyEngineError};
use serde_json::{Map, Value as Json, json};

/// The Rego source of the bundled policy, for deployments that ship it themselves.
pub const REGO: &str = include_str!("../policy/policy.rego");

/// The directory holding the bundled Rego, as laid out in this repository.
pub fn bundled_policy_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("policy")
}

/// The query both modes evaluate.
const QUERY: &str = "data.fieldseal.policy.decision";

/// How to reach OPA.
#[derive(Clone, Debug)]
pub enum OpaConfig {
    /// Run `opa eval` once per decision.
    Binary {
        /// The `opa` executable (a name found on `PATH`, or a path).
        program: PathBuf,
        /// A directory of `.rego` files (or one file) holding the decision rules.
        policy: PathBuf,
        /// How long one evaluation may take before the process is killed.
        timeout: Duration,
    },
    /// Ask a running OPA server (`opa run --server`) that has the same Rego loaded.
    Rest {
        /// The server's base URL, for example `http://127.0.0.1:8181`.
        url: String,
        /// How long one request may take.
        timeout: Duration,
    },
}

impl OpaConfig {
    /// `opa eval` with `opa` from `PATH` and the bundled Rego, with a ten-second limit.
    pub fn binary() -> Self {
        Self::Binary { program: "opa".into(), policy: bundled_policy_dir(), timeout: Duration::from_secs(10) }
    }

    /// OPA's REST API at `url`, with a ten-second limit.
    pub fn rest(url: impl Into<String>) -> Self {
        Self::Rest { url: url.into(), timeout: Duration::from_secs(10) }
    }

    /// Chooses the mode from a setting: `http://…` or `https://…` is the REST API at that URL;
    /// anything else is the path of the `opa` executable (`opa` for the one on `PATH`).
    pub fn from_setting(setting: &str) -> Self {
        if setting.starts_with("http://") || setting.starts_with("https://") {
            Self::rest(setting)
        } else {
            Self::Binary { program: setting.into(), policy: bundled_policy_dir(), timeout: Duration::from_secs(10) }
        }
    }

    /// The same configuration with another time limit.
    #[must_use]
    pub fn with_timeout(mut self, limit: Duration) -> Self {
        match &mut self {
            Self::Binary { timeout, .. } | Self::Rest { timeout, .. } => *timeout = limit,
        }
        self
    }
}

/// The OPA-backed [`PolicyEngine`].
#[derive(Clone, Debug)]
pub struct OpaEngine {
    config: OpaConfig,
}

impl OpaEngine {
    /// An engine reaching OPA as `config` says.
    pub fn new(config: OpaConfig) -> Self {
        Self { config }
    }
}

impl PolicyEngine for OpaEngine {
    fn evaluate(&self, point: DecisionPoint, policy: &EffectivePolicy, facts: &Facts) -> Result<Decision, PolicyEngineError> {
        let input = build_input(point, policy, facts)?;
        let answer = match &self.config {
            OpaConfig::Binary { program, policy, timeout } => run_binary(program, policy, &input, *timeout)?,
            OpaConfig::Rest { url, timeout } => ask_server(url, &input, *timeout)?,
        };
        read_decision(point, policy, &answer)
    }
}

// ---- facts -------------------------------------------------------------------------------

fn missing(name: &str) -> PolicyEngineError {
    PolicyEngineError::MissingFact(name.to_owned())
}

fn bad(name: &str) -> PolicyEngineError {
    PolicyEngineError::BadFact(name.to_owned())
}

/// The type of a fact.
#[derive(Clone, Copy)]
enum Kind {
    Bool,
    Uint,
    Text,
    Texts,
    /// A decimal in [0, 1), passed to Rego as a string so it compares exactly.
    Draw,
    /// One of the given words.
    OneOf(&'static [&'static str]),
    /// A name from [`ARTEFACT_KINDS`].
    Artefact,
    /// A [`SecurityLevel`] word.
    Level,
    /// A calendar date, normalised to `YYYY-MM-DD`.
    Day,
}

/// The facts each decision point reads, with their types (see `fieldseal_policy::domain::decision`).
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
            ("unattestedAllowed", Bool),
            ("activeTenanciesInCohort", Uint),
            ("paused", Bool),
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

fn check_fact(name: &str, kind: Kind, value: &Value) -> Result<Json, PolicyEngineError> {
    match kind {
        Kind::Bool => value.as_bool().map(Json::Bool).ok_or_else(|| bad(name)),
        Kind::Uint => {
            let n = value.as_int().and_then(|i| u64::try_from(i).ok()).ok_or_else(|| bad(name))?;
            Ok(Json::Number(n.into()))
        }
        Kind::Text => value.as_text().map(|t| json!(t)).ok_or_else(|| bad(name)),
        Kind::Texts => {
            let items = value.as_array().ok_or_else(|| bad(name))?;
            items.iter().map(|v| v.as_text().map(|t| json!(t)).ok_or_else(|| bad(name))).collect::<Result<Vec<_>, _>>().map(Json::Array)
        }
        Kind::Draw => {
            // Exactly a decimal: an integer is not silently widened.
            let Value::Decimal(d) = value else { return Err(bad(name)) };
            let d = *d;
            let (zero, one) = (Decimal { mantissa: 0, exponent: 0 }, Decimal { mantissa: 1, exponent: 0 });
            let in_range = d.numeric_cmp(zero).is_some_and(|o| o.is_ge()) && d.numeric_cmp(one).is_some_and(|o| o.is_lt());
            if !in_range {
                return Err(bad(name));
            }
            Ok(json!(d.to_string()))
        }
        Kind::OneOf(words) => match value.as_text() {
            Some(t) if words.contains(&t) => Ok(json!(t)),
            _ => Err(bad(name)),
        },
        Kind::Artefact => match value.as_text() {
            Some(t) if ARTEFACT_KINDS.contains(&t) => Ok(json!(t)),
            _ => Err(bad(name)),
        },
        Kind::Level => match value.as_text().and_then(SecurityLevel::parse) {
            Some(level) => Ok(json!(level.as_str())),
            None => Err(bad(name)),
        },
        Kind::Day => match value.as_text().map(Date::parse) {
            Some(Ok(date)) => Ok(json!(date.to_string())),
            _ => Err(bad(name)),
        },
    }
}

/// Checks the facts for `point`: every fact its rules read is present and of the exact type,
/// and no other fact is supplied. Returns the facts as JSON.
fn checked_facts(point: DecisionPoint, facts: &Facts) -> Result<Json, PolicyEngineError> {
    let known = fact_types(point);
    if let Some(unknown) = facts.keys().find(|k| !known.iter().any(|(name, _)| name == k)) {
        return Err(PolicyEngineError::BadFact(format!("{unknown} (not a fact of {})", point.name())));
    }
    let mut out = Map::new();
    for (name, kind) in fact_types(point) {
        let value = facts.get(*name).ok_or_else(|| missing(name))?;
        out.insert((*name).to_owned(), check_fact(name, *kind, value)?);
    }
    Ok(Json::Object(out))
}

// ---- the effective policy as OPA input ---------------------------------------------------

fn secs(d: fieldseal_policy::domain::Duration) -> Json {
    Json::Number(d.as_secs().into())
}

fn words(items: &[String]) -> Json {
    json!(items)
}

/// The controls the Rego reads, from the typed sections (so defaults are already filled in).
fn policy_json(policy: &EffectivePolicy) -> Json {
    let factory = policy.factory();
    let intake = policy.intake();
    let publishing = policy.publishing();
    let reg = &factory.registration;
    let att = &factory.attestation;
    let mut attestation = json!({
        "minSecurityLevel": att.min_security_level.as_str(),
        "requireVerifiedBoot": att.require_verified_boot,
        "requireBootloaderLocked": att.require_bootloader_locked,
    });
    // Absent when unconstrained: a `null` would read as true in Rego.
    if let Some(date) = att.min_os_patch_level {
        attestation["minOsPatchLevel"] = json!(date.to_string());
    }
    let kinds: Map<String, Json> = publishing
        .kinds
        .iter()
        .map(|(name, k)| (name.clone(), json!({"requiredApprovals": k.required_approvals, "publisherThresholdM": k.publisher_threshold.m})))
        .collect();
    json!({
        "factory": {
            "registration": {
                "maxDevicesPerAccount": reg.max_devices_per_account,
                "tokenTtl": secs(reg.token_ttl),
                "airGappedTokenTtl": secs(reg.air_gapped_token_ttl),
                "requireFingerprintConfirmation": reg.require_fingerprint_confirmation,
                "serialCheck": reg.serial_check.as_str(),
                "requirePhishingResistantAuth": reg.require_phishing_resistant_auth,
                "deviceNonceRegistrations": reg.device_nonce_registrations.as_str(),
                "batchTokens": {
                    "allowed": reg.batch_tokens.allowed,
                    "roles": words(&reg.batch_tokens.roles),
                    "ttl": secs(reg.batch_tokens.ttl),
                },
            },
            "attestation": attestation,
            "custody": {
                "minAssurance": factory.custody.min_assurance.iter().map(|(k, v)| (k.clone(), json!(v.as_str()))).collect::<Map<String, Json>>(),
                "minMode": factory.custody.min_mode.iter().map(|(k, v)| (k.clone(), json!(v.as_str()))).collect::<Map<String, Json>>(),
            },
            "maxActiveTenanciesPerCohort": factory.max_active_tenancies_per_cohort,
            "posture": {
                "onFailure": factory.posture.on_failure.as_str(),
                "unknownRestriction": factory.posture.unknown_restriction.as_str(),
            },
            "requireRegisteredTenancy": factory.require_registered_tenancy,
        },
        "intake": {
            "consent": {
                "autoAcceptWithEvidence": intake.consent.auto_accept_with_evidence,
                "sampleRate": intake.consent.sample_rate.to_string(),
                "withoutEvidence": intake.consent.without_evidence.as_str(),
                "heuristics": words(&intake.consent.heuristics),
            },
            "timeGrace": secs(intake.time_grace),
            "provablyLate": intake.provably_late.as_str(),
            "fastRunning": intake.fast_running.as_str(),
            "maxSubmissionSize": intake.max_submission_size.as_bytes(),
            "dataQualityOnFailure": intake.data_quality_on_failure.as_str(),
        },
        "publishing": {
            "kinds": kinds,
            "authorMayApprove": publishing.author_may_approve,
            "allowedBuilders": words(&publishing.allowed_builders),
            "allowedSources": words(&publishing.allowed_sources),
            "requireTransparencyLog": publishing.require_transparency_log,
            "requiredWitnessCosignatures": publishing.required_witness_cosignatures,
        },
    })
}

fn build_input(point: DecisionPoint, policy: &EffectivePolicy, facts: &Facts) -> Result<String, PolicyEngineError> {
    let input = json!({"point": point.name(), "facts": checked_facts(point, facts)?, "policy": policy_json(policy)});
    serde_json::to_string(&input).map_err(|e| PolicyEngineError::Backend(e.to_string()))
}

// ---- running OPA -------------------------------------------------------------------------

fn backend(what: impl std::fmt::Display) -> PolicyEngineError {
    PolicyEngineError::Backend(format!("opa: {what}"))
}

fn drain<R: Read + Send + 'static>(mut from: R) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = from.read_to_end(&mut bytes);
        bytes
    })
}

/// Runs `opa eval` with the input on stdin and returns the decision object.
fn run_binary(program: &Path, policy: &Path, input: &str, timeout: Duration) -> Result<Json, PolicyEngineError> {
    let mut child = Command::new(program)
        .args(["eval", "--format", "json", "--stdin-input", "--data"])
        .arg(policy)
        .arg(QUERY)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| backend(format!("cannot run `{}`: {e}", program.display())))?;
    let stdout = child.stdout.take().map(drain);
    let stderr = child.stderr.take().map(drain);
    if let Some(mut stdin) = child.stdin.take() {
        // A write error surfaces as a non-zero exit below.
        let _ = stdin.write_all(input.as_bytes());
    }
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(PolicyEngineError::Timeout);
            }
            Ok(None) => thread::sleep(Duration::from_millis(2)),
            Err(e) => return Err(backend(e)),
        }
    };
    let out = stdout.map(|h| h.join().unwrap_or_default()).unwrap_or_default();
    let err = stderr.map(|h| h.join().unwrap_or_default()).unwrap_or_default();
    if !status.success() {
        return Err(backend(format!("exited with {status}: {}", String::from_utf8_lossy(&err).trim())));
    }
    let parsed: Json = serde_json::from_slice(&out).map_err(|e| backend(format!("unreadable output: {e}")))?;
    parsed
        .pointer("/result/0/expressions/0/value")
        .cloned()
        .ok_or_else(|| backend("the decision is undefined"))
}

/// Asks a running OPA server for the decision.
fn ask_server(url: &str, input: &str, timeout: Duration) -> Result<Json, PolicyEngineError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .max_redirects(0)
        .build()
        .into();
    let endpoint = format!("{}/v1/data/fieldseal/policy/decision", url.trim_end_matches('/'));
    let body = format!("{{\"input\":{input}}}");
    let mut response = agent
        .post(&endpoint)
        .header("Content-Type", "application/json")
        .send(body.as_bytes())
        .map_err(|e| match e {
            ureq::Error::Timeout(_) => PolicyEngineError::Timeout,
            e => backend(e),
        })?;
    let status = response.status().as_u16();
    let bytes = response
        .body_mut()
        .with_config()
        .limit(1 << 20)
        .read_to_vec()
        .map_err(|e| match e {
            ureq::Error::Timeout(_) => PolicyEngineError::Timeout,
            e => backend(e),
        })?;
    if status != 200 {
        return Err(backend(format!("HTTP {status}")));
    }
    let parsed: Json = serde_json::from_slice(&bytes).map_err(|e| backend(format!("unreadable response: {e}")))?;
    parsed.get("result").cloned().ok_or_else(|| backend("the decision is undefined"))
}

// ---- reading the answer ------------------------------------------------------------------

fn read_decision(point: DecisionPoint, policy: &EffectivePolicy, answer: &Json) -> Result<Decision, PolicyEngineError> {
    // The decision object is closed: exactly `verdict`, `reasons` and `obligations`.
    let Some(object) = answer.as_object() else { return Err(backend("the decision is not an object")) };
    if let Some(extra) = object.keys().find(|k| !["verdict", "reasons", "obligations"].contains(&k.as_str())) {
        return Err(backend(format!("unknown field `{extra}` in the decision")));
    }
    let verdict = match answer.get("verdict").and_then(Json::as_str) {
        Some("allow") => Verdict::Allow,
        Some("deny") => Verdict::Deny,
        Some("hold") => Verdict::Hold,
        Some("flag") => Verdict::Flag,
        other => return Err(backend(format!("unknown verdict {other:?}"))),
    };
    let strings = |key: &str| -> Result<Vec<String>, PolicyEngineError> {
        answer
            .get(key)
            .and_then(Json::as_array)
            .ok_or_else(|| backend(format!("no `{key}` in the decision")))?
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or_else(|| backend(format!("`{key}` holds a non-string"))))
            .collect()
    };
    let reasons = strings("reasons")?;
    if verdict != Verdict::Allow && reasons.is_empty() {
        // The port requires reasons for every non-allow outcome; an answer without them is a
        // broken policy, not a decision.
        return Err(backend("a non-allow decision without reasons"));
    }
    let obligations = strings("obligations")?
        .iter()
        .map(|o| match o.as_str() {
            "sample-for-review" => Ok(Obligation::SampleForReview),
            "pause-release" => Ok(Obligation::PauseRelease),
            "quarantine" => Ok(Obligation::Quarantine),
            other => Err(backend(format!("unknown obligation `{other}`"))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Decision { point, verdict, reasons, obligations, policy: policy.sources.clone() })
}
