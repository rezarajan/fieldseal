//! Invariant floors (POL §6.1). They live in code (POL-011): no policy field can disable
//! one, and the schema has no control that could. Changing one needs an ADR and a new
//! schema major version (POL-012).

use std::collections::BTreeMap;

use super::control::ControlValue;
use super::finding::Finding;
use super::units::{ByteSize, Duration};

/// The shortest PIN a runtime accepts (INV-4).
pub const MIN_PIN_LENGTH: u64 = 6;
/// The most PIN failures allowed before the first lockout (INV-5).
pub const MAX_FAILURES_BEFORE_LOCKOUT: u64 = 5;
/// The shortest first lockout delay (INV-5).
pub const MIN_FIRST_LOCKOUT: Duration = Duration::from_secs(30);
/// The longest idle time before a session locks (INV-6).
pub const MAX_IDLE_LOCK: Duration = Duration::from_mins(15);
/// The least Argon2id memory for the session key (INV-9).
pub const MIN_ARGON2_MEMORY: ByteSize = ByteSize::mib(64);
/// The fewest Argon2id iterations (INV-9).
pub const MIN_ARGON2_ITERATIONS: u64 = 3;
/// The least Argon2id parallelism (INV-9).
pub const MIN_ARGON2_PARALLELISM: u64 = 1;
/// The fewest publisher signatures ever required (INV-12).
pub const MIN_PUBLISHER_THRESHOLD: u64 = 2;
/// The attestation format that stands for an unattested, software-held key (INV-10).
pub const SOFTWARE_ATTESTATION_FORMAT: &str = "software";

/// A floor in code. Some are numeric limits on a control; the rest are properties of the code
/// that no control exists for.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Invariant {
    /// INV-1: records and export manifests are sealed to an authority key.
    SealToAuthority,
    /// INV-2: inbound artefacts: minimal parse, authenticate, decrypt, strict decode.
    InboundOrdering,
    /// INV-3: secure display on every runtime screen.
    SecureDisplay,
    /// INV-4: runtime PIN length of at least 6 digits.
    PinLength,
    /// INV-5: escalating PIN lockout, first delay of at least 30 s after at most 5 failures.
    PinLockout,
    /// INV-6: session idle lock of at most 15 minutes.
    IdleLock,
    /// INV-7: identity never stored in plaintext.
    NoPlaintextIdentity,
    /// INV-8: no biometric-only unlock.
    NoBiometricOnly,
    /// INV-9: Argon2id parameters of at least m 64 MiB, t 3, p 1.
    Argon2,
    /// INV-10: unattested (software) keys never registered in production.
    NoSoftwareKeys,
    /// INV-11: transparency-log inclusion required.
    TransparencyLog,
    /// INV-12: publisher threshold m of at least 2.
    PublisherThreshold,
    /// INV-13: no clear without the twice-entered PIN; no deleting sealed records before a receipt.
    ClearWithConfirmation,
    /// INV-14: no inbound network services on devices.
    NoInboundServices,
    /// INV-15: no `development` authority key in an environment of tier `production`. Checked
    /// by deployment validation and by issuance, not by a policy control (TRU-109, DEP-074).
    NoDevelopmentAuthorityKeys,
}

impl Invariant {
    /// Every invariant, in order.
    pub const ALL: [Invariant; 15] = [
        Self::SealToAuthority,
        Self::InboundOrdering,
        Self::SecureDisplay,
        Self::PinLength,
        Self::PinLockout,
        Self::IdleLock,
        Self::NoPlaintextIdentity,
        Self::NoBiometricOnly,
        Self::Argon2,
        Self::NoSoftwareKeys,
        Self::TransparencyLog,
        Self::PublisherThreshold,
        Self::ClearWithConfirmation,
        Self::NoInboundServices,
        Self::NoDevelopmentAuthorityKeys,
    ];

    /// The invariant's identifier, `INV-1` to `INV-15`.
    pub fn id(self) -> &'static str {
        match self {
            Self::SealToAuthority => "INV-1",
            Self::InboundOrdering => "INV-2",
            Self::SecureDisplay => "INV-3",
            Self::PinLength => "INV-4",
            Self::PinLockout => "INV-5",
            Self::IdleLock => "INV-6",
            Self::NoPlaintextIdentity => "INV-7",
            Self::NoBiometricOnly => "INV-8",
            Self::Argon2 => "INV-9",
            Self::NoSoftwareKeys => "INV-10",
            Self::TransparencyLog => "INV-11",
            Self::PublisherThreshold => "INV-12",
            Self::ClearWithConfirmation => "INV-13",
            Self::NoInboundServices => "INV-14",
            Self::NoDevelopmentAuthorityKeys => "INV-15",
        }
    }

    /// Whether a control carries a numeric or boolean floor that a policy value can breach.
    /// The others are properties of the code with no control at all.
    pub fn has_control(self) -> bool {
        matches!(
            self,
            Self::PinLength
                | Self::PinLockout
                | Self::IdleLock
                | Self::Argon2
                | Self::NoSoftwareKeys
                | Self::TransparencyLog
                | Self::PublisherThreshold
        )
    }
}

/// Checks the floors that apply to the controls in `controls` (a layer's own controls, or an
/// effective set). Absent controls are not checked: the schema defaults satisfy every floor
/// (POL-022), which a test proves. `at` prefixes the reported path (`spec.` for a document,
/// empty for an effective policy).
pub fn check_floors(controls: &BTreeMap<String, ControlValue>, at: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let breach = |inv: Invariant, path: &str, msg: String| {
        Finding::error(inv.id(), format!("{at}{path}"), format!("{msg} (invariant {})", inv.id()))
    };
    for (path, value) in controls {
        match (path.as_str(), value) {
            ("runtime.pin.minLength", ControlValue::Int(n)) if *n < MIN_PIN_LENGTH => {
                out.push(breach(Invariant::PinLength, path, format!("PIN length {n} is below the floor of {MIN_PIN_LENGTH}")));
            }
            ("runtime.pin.failuresBeforeLockout", ControlValue::Int(n)) if *n > MAX_FAILURES_BEFORE_LOCKOUT => {
                out.push(breach(
                    Invariant::PinLockout,
                    path,
                    format!("lockout after {n} failures is above the ceiling of {MAX_FAILURES_BEFORE_LOCKOUT}"),
                ));
            }
            ("runtime.pin.lockoutSteps", ControlValue::Durations(steps)) => {
                if steps.first().is_some_and(|d| *d < MIN_FIRST_LOCKOUT) {
                    out.push(breach(
                        Invariant::PinLockout,
                        path,
                        format!("first lockout delay {} is below the floor of {MIN_FIRST_LOCKOUT}", steps[0]),
                    ));
                }
                if steps.windows(2).any(|w| w[1] <= w[0]) {
                    out.push(breach(Invariant::PinLockout, path, "lockout delays must escalate strictly".to_owned()));
                }
            }
            ("runtime.session.idleLock", ControlValue::Duration(d)) if *d > MAX_IDLE_LOCK => {
                out.push(breach(Invariant::IdleLock, path, format!("idle lock {d} is above the ceiling of {MAX_IDLE_LOCK}")));
            }
            ("runtime.pin.argon2", ControlValue::Argon2(a)) => {
                if a.memory < MIN_ARGON2_MEMORY {
                    out.push(breach(Invariant::Argon2, path, format!("memory {} is below the floor of {MIN_ARGON2_MEMORY}", a.memory)));
                }
                if a.iterations < MIN_ARGON2_ITERATIONS {
                    out.push(breach(
                        Invariant::Argon2,
                        path,
                        format!("iterations {} are below the floor of {MIN_ARGON2_ITERATIONS}", a.iterations),
                    ));
                }
                if a.parallelism < MIN_ARGON2_PARALLELISM {
                    out.push(breach(
                        Invariant::Argon2,
                        path,
                        format!("parallelism {} is below the floor of {MIN_ARGON2_PARALLELISM}", a.parallelism),
                    ));
                }
            }
            ("factory.attestation.acceptedFormats", ControlValue::Set(formats))
                if formats.iter().any(|f| f == SOFTWARE_ATTESTATION_FORMAT) =>
            {
                out.push(breach(
                    Invariant::NoSoftwareKeys,
                    path,
                    "software (unattested) keys cannot be accepted in production".to_owned(),
                ));
            }
            ("publishing.requireTransparencyLog", ControlValue::Bool(false)) => {
                out.push(breach(Invariant::TransparencyLog, path, "transparency-log inclusion is required".to_owned()));
            }
            (p, ControlValue::Threshold(t)) if p.starts_with("publishing.publisherThreshold.") && t.m < MIN_PUBLISHER_THRESHOLD => {
                out.push(breach(
                    Invariant::PublisherThreshold,
                    path,
                    format!("publisher threshold m={} is below the floor of {MIN_PUBLISHER_THRESHOLD}", t.m),
                ));
            }
            ("factory.release.requireRegisteredTenancy", ControlValue::Bool(false)) => {
                out.push(Finding::error(
                    "POL-010",
                    format!("{at}{path}"),
                    "bundle release without a registered tenancy is never allowed (this control MUST be true)",
                ));
            }
            _ => {}
        }
    }
    out
}
