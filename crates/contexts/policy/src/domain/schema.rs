//! The policy schema, `schemaVersion: 1.0.0` (POL §6.3): every control, its type, default and
//! merge rule. Decoding, merging, diffing and the typed views all read this table, so a
//! control that is not here does not exist (POL-002, POL-011).

use std::collections::BTreeMap;
use std::sync::LazyLock;

use super::choice::*;
use super::control::{
    Argon2Params, ControlValue, Direction, Kind, Merge, SetItems, TextShape, Threshold,
};
use super::units::{ByteSize, Duration};

/// The only schema version this crate understands. A new major version needs an ADR (POL-012).
pub const SCHEMA_VERSION_MAJOR: u64 = 1;

/// The sections of `spec` that hold controls.
pub const SECTIONS: &[&str] = &["factory", "runtime", "intake", "publishing"];

/// One control's schema entry.
#[derive(Clone, Debug)]
pub struct ControlSpec {
    /// The path from `spec`, for example `runtime.pin.minLength`. Per-kind controls end in the
    /// artefact kind, for example `publishing.requiredApprovals.Instrument`.
    pub path: String,
    /// Its type.
    pub kind: Kind,
    /// The value used when no layer sets it (POL-022). `None` means "unset".
    pub default: Option<ControlValue>,
    /// How layers combine.
    pub merge: Merge,
}

const TIGHTER_LOW: Merge = Merge::Tighten(Direction::Lower);
const TIGHTER_HIGH: Merge = Merge::Tighten(Direction::Higher);

fn spec(path: &str, kind: Kind, default: Option<ControlValue>, merge: Merge) -> ControlSpec {
    ControlSpec { path: path.to_owned(), kind, default, merge }
}

fn int(min: u64, max: u64) -> Kind {
    Kind::Int { min, max }
}

fn dur(text: &str) -> Option<ControlValue> {
    Some(ControlValue::Duration(Duration::parse(text).expect("schema default")))
}

fn durs(texts: &[&str]) -> Option<ControlValue> {
    Some(ControlValue::Durations(
        texts.iter().map(|t| Duration::parse(t).expect("schema default")).collect(),
    ))
}

fn set(words: &[&str]) -> Option<ControlValue> {
    let mut v: Vec<String> = words.iter().map(|w| (*w).to_owned()).collect();
    v.sort();
    Some(ControlValue::Set(v))
}

fn choice(word: &str) -> Option<ControlValue> {
    Some(ControlValue::Choice(word.to_owned()))
}

fn flag(b: bool) -> Option<ControlValue> {
    Some(ControlValue::Bool(b))
}

fn count(n: u64) -> Option<ControlValue> {
    Some(ControlValue::Int(n))
}

const POS: u64 = u64::MAX;

fn build() -> Vec<ControlSpec> {
    let mut s = vec![
        // factory
        spec("factory.registration.maxDevicesPerAccount", int(1, POS), count(2), TIGHTER_LOW),
        spec("factory.registration.tokenTtl", Kind::Duration, dur("10m"), TIGHTER_LOW),
        spec("factory.registration.airGappedTokenTtl", Kind::Duration, dur("24h"), TIGHTER_LOW),
        spec("factory.registration.requireFingerprintConfirmation", Kind::Bool, flag(true), TIGHTER_HIGH),
        spec("factory.registration.serialCheck", Kind::Choice(SerialCheck::NAMES), choice("optional"), TIGHTER_HIGH),
        spec("factory.registration.requirePhishingResistantAuth", Kind::Bool, flag(true), TIGHTER_HIGH),
        // REG-002a: methods an identity broker could not pass through unchanged.
        spec("factory.registration.acceptAssertedAuthMethods", Kind::Bool, flag(false), TIGHTER_LOW),
        spec("factory.registration.deviceNonceRegistrations", Kind::Choice(Disposition::NAMES), choice("flag"), TIGHTER_HIGH),
        spec("factory.registration.batchTokens.allowed", Kind::Bool, flag(false), TIGHTER_LOW),
        spec("factory.registration.batchTokens.roles", Kind::Set(SetItems::Token), set(&[]), Merge::Intersect),
        spec("factory.registration.batchTokens.maxUses", int(1, POS), count(50), TIGHTER_LOW),
        spec("factory.registration.batchTokens.ttl", Kind::Duration, dur("4h"), TIGHTER_LOW),
        spec(
            "factory.attestation.acceptedFormats",
            Kind::Set(SetItems::Token),
            set(&["android-key-attestation", "apple-app-attest", "tpm2-quote"]),
            Merge::Intersect,
        ),
        spec("factory.attestation.minSecurityLevel", Kind::Choice(SecurityLevel::NAMES), choice("tee"), TIGHTER_HIGH),
        spec("factory.attestation.minOsPatchLevel", Kind::Date, None, TIGHTER_HIGH),
        spec("factory.attestation.requireVerifiedBoot", Kind::Bool, flag(true), TIGHTER_HIGH),
        spec("factory.attestation.requireBootloaderLocked", Kind::Bool, flag(true), TIGHTER_HIGH),
        spec("factory.attestation.acceptedRuntimeVersions", Kind::Set(SetItems::Range), None, Merge::Intersect),
        spec("factory.cohorts.maxActiveTenanciesPerCohort", int(1, POS), count(1), TIGHTER_LOW),
        spec("factory.posture.recheckInterval", Kind::Duration, dur("7d"), TIGHTER_LOW),
        spec("factory.posture.onFailure", Kind::Choice(PostureFailure::NAMES), choice("pause-release"), TIGHTER_HIGH),
        spec("factory.posture.unknownRestriction", Kind::Choice(UnknownRestriction::NAMES), choice("flag"), TIGHTER_HIGH),
        spec("factory.release.requireRegisteredTenancy", Kind::Bool, flag(true), TIGHTER_HIGH),
        // runtime
        spec("runtime.pin.minLength", int(1, 64), count(6), TIGHTER_HIGH),
        spec("runtime.pin.lockoutSteps", Kind::Durations, durs(&["30s", "1m", "5m", "15m", "1h"]), TIGHTER_HIGH),
        spec("runtime.pin.failuresBeforeLockout", int(1, 1_000), count(5), TIGHTER_LOW),
        spec(
            "runtime.pin.argon2",
            Kind::Argon2,
            Some(ControlValue::Argon2(Argon2Params { memory: ByteSize::mib(64), iterations: 3, parallelism: 1 })),
            TIGHTER_HIGH,
        ),
        spec("runtime.session.idleLock", Kind::Duration, dur("2m"), TIGHTER_LOW),
        spec("runtime.session.lockOnBackground", Kind::Bool, flag(true), TIGHTER_HIGH),
        spec("runtime.session.lockOnScreenOff", Kind::Bool, flag(true), TIGHTER_HIGH),
        spec("runtime.export.parityDefault", Kind::Choice(Toggle::NAMES), choice("on"), Merge::Override),
        spec("runtime.export.allowParityOff", Kind::Bool, flag(true), TIGHTER_LOW),
        spec(
            "runtime.export.destinations",
            Kind::Set(SetItems::Words(ExportDestination::NAMES)),
            set(ExportDestination::NAMES),
            Merge::Intersect,
        ),
        spec("runtime.export.filePrefix", Kind::Text(TextShape::FilePrefix), Some(ControlValue::Text("Fieldseal".into())), Merge::Override),
        spec("runtime.export.fileExtension", Kind::Text(TextShape::FileExtension), Some(ControlValue::Text("fieldseal".into())), Merge::Override),
        spec("runtime.upload.background", Kind::Bool, flag(true), Merge::Override),
        spec("runtime.upload.retryBackoff", Kind::Durations, durs(&["1m", "5m", "30m", "2h"]), Merge::Override),
        spec("runtime.retention.offerClearOnReceipt", Kind::Bool, flag(true), Merge::Override),
        spec("runtime.retention.remindAfter", Kind::Duration, dur("7d"), Merge::Override),
        spec("runtime.time.warnOutsideWindow", Kind::Bool, flag(true), Merge::Override),
        spec("runtime.device.kiosk", Kind::Bool, flag(false), Merge::Override),
        spec(
            "runtime.device.requiredRestrictions",
            Kind::Set(SetItems::Words(Restriction::NAMES)),
            set(Restriction::NAMES),
            Merge::Union,
        ),
        spec("runtime.publishing.maxTreeHeadAge", Kind::Duration, dur("90d"), TIGHTER_LOW),
        spec("runtime.evidence.maxImageEdge", int(1, 65_535), count(2000), TIGHTER_LOW),
        // intake
        spec("intake.consent.autoAcceptWithEvidence", Kind::Bool, flag(true), Merge::Override),
        spec(
            "intake.consent.sampleRate",
            Kind::Ratio,
            Some(ControlValue::Ratio(fieldseal_kernel::value::Decimal { mantissa: 5, exponent: -2 })),
            Merge::Override,
        ),
        spec("intake.consent.withoutEvidence", Kind::Choice(ConsentWithoutEvidence::NAMES), choice("review"), TIGHTER_HIGH),
        spec("intake.consent.heuristics", Kind::Set(SetItems::Token), set(&[]), Merge::Union),
        spec("intake.consent.excludePendingFromAnalysis", Kind::Bool, flag(true), TIGHTER_HIGH),
        spec("intake.time.grace", Kind::Duration, dur("30d"), TIGHTER_LOW),
        spec("intake.time.provablyLate", Kind::Choice(Escalation::NAMES), choice("flag"), TIGHTER_HIGH),
        spec("intake.ticks.fastRunning", Kind::Choice(Escalation::NAMES), choice("flag"), TIGHTER_HIGH),
        spec("intake.parity.repair", Kind::Bool, flag(true), Merge::Override),
        spec("intake.denyList.cutoffMode", Kind::Choice(CutoffMode::NAMES), choice("highest-received"), TIGHTER_HIGH),
        spec(
            "intake.limits.maxSubmissionSize",
            Kind::Size,
            Some(ControlValue::Size(ByteSize::mib(512))),
            TIGHTER_LOW,
        ),
        spec("intake.dataQuality.onFailure", Kind::Choice(QualityFailure::NAMES), choice("finding"), TIGHTER_HIGH),
        // publishing (per-kind controls are expanded below)
        spec("publishing.authorMayApprove", Kind::Bool, flag(false), TIGHTER_LOW),
        spec("publishing.allowedBuilders", Kind::Set(SetItems::Opaque), set(&[]), Merge::Intersect),
        spec("publishing.allowedSources", Kind::Set(SetItems::Opaque), set(&[]), Merge::Intersect),
        spec("publishing.requireTransparencyLog", Kind::Bool, flag(true), TIGHTER_HIGH),
        spec("publishing.requiredWitnessCosignatures", int(0, POS), count(0), TIGHTER_HIGH),
        spec("publishing.layoutLint.maxDecisionsPerScreen", int(1, POS), count(7), TIGHTER_LOW),
        spec("publishing.layoutLint.maxVisibleOptions", int(1, POS), count(9), TIGHTER_LOW),
        spec("publishing.layoutLint.maxScaleStepsCompact", int(2, POS), count(7), TIGHTER_LOW),
        spec("publishing.layoutLint.blocking", Kind::Set(SetItems::Words(LayoutLint::NAMES)), set(&[]), Merge::Union),
    ];
    for kind in ARTEFACT_KINDS {
        s.push(spec(&format!("publishing.requiredApprovals.{kind}"), int(1, POS), count(2), TIGHTER_HIGH));
        s.push(spec(
            &format!("publishing.publisherThreshold.{kind}"),
            Kind::Threshold,
            Some(ControlValue::Threshold(Threshold { m: 2, n: 3 })),
            TIGHTER_HIGH,
        ));
        s.push(spec(&format!("publishing.withdrawalThreshold.{kind}"), Kind::Threshold, None, TIGHTER_HIGH));
    }
    // Authority key custody (TRU §6.7, POL-065, POL-066): a minimum on each of two axes per
    // purpose. A deployment layer may set a lower assurance only for a non-production tier,
    // which deployment validation checks (INV-15).
    for purpose in CUSTODY_PURPOSES {
        s.push(spec(&format!("factory.custody.minAssurance.{purpose}"), Kind::Choice(Assurance::NAMES), choice("custody-bound"), TIGHTER_HIGH));
        let mode = if matches!(*purpose, "root" | "publisher") { "cold" } else { "hot" };
        s.push(spec(&format!("factory.custody.minMode.{purpose}"), Kind::Choice(CustodyMode::NAMES), choice(mode), TIGHTER_HIGH));
    }
    s.push(spec("factory.custody.hotKey.maxValidity", Kind::Duration, dur("180d"), TIGHTER_LOW));
    s.push(spec("factory.custody.hotKey.rotateBefore", Kind::Duration, dur("30d"), TIGHTER_HIGH));
    s
}

/// The authority purposes a custody minimum is set for: the roles of TRU §6.1, and the root.
pub const CUSTODY_PURPOSES: &[&str] = &["root", "factory", "registration", "publisher", "builder", "receipt", "receiver", "record"];

static SCHEMA: LazyLock<Vec<ControlSpec>> = LazyLock::new(build);
static INDEX: LazyLock<BTreeMap<&'static str, &'static ControlSpec>> =
    LazyLock::new(|| SCHEMA.iter().map(|s| (s.path.as_str(), s)).collect());

/// Every control in the schema.
pub fn schema() -> &'static [ControlSpec] {
    &SCHEMA
}

/// The schema entry for the control at `path`.
pub fn control_spec(path: &str) -> Option<&'static ControlSpec> {
    INDEX.get(path).copied()
}

/// Whether `prefix` (such as `runtime.pin`) names a group of controls.
pub fn is_group(prefix: &str) -> bool {
    let dotted = format!("{prefix}.");
    SCHEMA.iter().any(|s| s.path.starts_with(&dotted))
}

/// The names directly under group `prefix`.
pub fn children(prefix: &str) -> Vec<&'static str> {
    let dotted = format!("{prefix}.");
    let names: std::collections::BTreeSet<&'static str> = SCHEMA
        .iter()
        .filter_map(|s| s.path.strip_prefix(&dotted))
        .map(|rest| rest.split('.').next().unwrap_or(rest))
        .collect();
    names.into_iter().collect()
}

/// Groups whose children are artefact kinds, and which also accept one value for all kinds.
pub const PER_KIND_GROUPS: &[&str] = &[
    "publishing.requiredApprovals",
    "publishing.publisherThreshold",
    "publishing.withdrawalThreshold",
];
