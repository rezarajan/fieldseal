//! Pure verification rules: whether verified attestation claims are sufficient under factory
//! policy (REG-015, REG-017, TRU-065), and whether the runtime build is one the trust
//! bundle accepts (TRU-030).
//!
//! Every rule fails closed: a fact the claims don't establish counts as not meeting the
//! requirement (TRU-063).

use fieldseal_kernel::id::Nonce;
use fieldseal_policy::domain::{AttestationPolicy, Date, SecurityLevel as PolicyLevel, Version};
use fieldseal_trust::domain::{AttestationClaims, BootState, DeviceKeyKind, SecurityLevel, TrustBundle};

/// Whether the factory may register keys without hardware attestation (REG-017).
///
/// Policy can't express this (INV-10 forbids `software` in `attestation.acceptedFormats`),
/// so it is the factory's deployment setting, and only a non-production environment may
/// set [`UnattestedKeys::AllowNonProduction`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum UnattestedKeys {
    /// Refuse every unattested key (the default, and the only choice in production).
    #[default]
    Refuse,
    /// Accept software keys from `fieldseal device simulate` in development and testing.
    AllowNonProduction,
}

fn policy_level(level: SecurityLevel) -> Option<PolicyLevel> {
    match level {
        SecurityLevel::Software => None,
        SecurityLevel::Tee => Some(PolicyLevel::Tee),
        SecurityLevel::StrongBox => Some(PolicyLevel::Strongbox),
        SecurityLevel::SecureElement => Some(PolicyLevel::SecureElement),
        SecurityLevel::Tpm => Some(PolicyLevel::Tpm),
    }
}

/// Whether `version` satisfies every comparator in `range` (for example `>=1.0.0 <2.0.0`).
/// Anything that doesn't parse fails.
pub fn version_satisfies(range: &str, version: &str) -> bool {
    let Ok(v) = Version::parse(version) else { return false };
    let comparators: Vec<&str> = range.split_whitespace().map(|c| c.trim_end_matches(',')).collect();
    !comparators.is_empty()
        && comparators.iter().all(|c| {
            let (op, rest) = [">=", "<=", ">", "<", "="]
                .iter()
                .find_map(|op| c.strip_prefix(op).map(|r| (*op, r)))
                .unwrap_or(("=", c));
            match Version::parse(rest) {
                Ok(bound) => match op {
                    ">=" => v >= bound,
                    "<=" => v <= bound,
                    ">" => v > bound,
                    "<" => v < bound,
                    _ => v == bound,
                },
                Err(_) => false,
            }
        })
}

/// Whether the trust bundle accepts the runtime build the claims name (TRU-030): some
/// accepted build has the attested `app_id`. The signing digest is part of the platform's
/// app identity and is checked by its attestation verifier.
pub fn build_accepted(bundle: &TrustBundle, claims: &AttestationClaims) -> bool {
    bundle.contents().runtime_builds.iter().any(|b| claims.app_id.as_deref() == Some(b.app_id.as_str()))
}

/// Reasons the claims for one key fall short of policy, as kebab-case codes (empty when
/// sufficient). `format` is the evidence format; `kind` the key it was presented for;
/// `challenge` the nonce it must bind (REG-011).
pub fn attestation_findings(
    policy: &AttestationPolicy,
    bundle: &TrustBundle,
    unattested: UnattestedKeys,
    format: &str,
    kind: DeviceKeyKind,
    challenge: &Nonce,
    claims: &AttestationClaims,
) -> Vec<String> {
    let mut out: Vec<&str> = Vec::new();
    if claims.challenge != *challenge {
        out.push("challenge-mismatch");
    }
    if claims.kind != kind {
        out.push("wrong-key-purpose");
    }
    if !claims.origin_generated {
        out.push("key-not-generated-in-store");
    }
    if !build_accepted(bundle, claims) {
        out.push("runtime-build-not-accepted");
    }
    match policy_level(claims.security_level) {
        None => {
            // REG-017: software keys only where a non-production deployment allows them.
            if unattested != UnattestedKeys::AllowNonProduction {
                out.push("unattested-key");
            }
        }
        Some(level) => {
            if !policy.accepted_formats.iter().any(|f| f == format) {
                out.push("evidence-format-not-accepted");
            }
            if level < policy.min_security_level {
                out.push("security-level-too-low");
            }
            if policy.require_verified_boot && claims.boot_state != Some(BootState::Verified) {
                out.push("boot-not-verified");
            }
            if policy.require_bootloader_locked && claims.bootloader_locked != Some(true) {
                out.push("bootloader-unlocked");
            }
            if let Some(min) = policy.min_os_patch_level {
                match claims.os_patch_level.as_deref().map(Date::parse) {
                    Some(Ok(patch)) if patch >= min => {}
                    Some(Ok(_)) => out.push("os-patch-level-too-old"),
                    _ => out.push("os-patch-level-unknown"),
                }
            }
        }
    }
    if let Some(ranges) = &policy.accepted_runtime_versions
        && !ranges.iter().all(|r| claims.app_version.as_deref().is_some_and(|v| version_satisfies(r, v)))
    {
        out.push("runtime-version-not-accepted");
    }
    out.into_iter().map(str::to_owned).collect()
}
