//! Authority key custody in a deployment (DEP-073 to DEP-075, TRU-112, [ADR 0038]): each
//! environment has a tier, and each authority purpose is bound to a key custody adapter with a
//! declared assurance and mode. Validation refuses a binding below the policy minimum, a
//! `development` binding in a `production` environment (INV-15), a software adapter that
//! claims hardware assurance, and a `cold` binding that is not offline.
//!
//! The declaration is an assertion. The issuance record is the proof, and `fieldseal trust
//! verify --audit` compares the two (TRU-117).
//!
//! [ADR 0038]: ../../../../docs/explanation/adr/0038-authority-key-custody-classes.md

use std::collections::BTreeMap;

use fieldseal_policy::domain::{Assurance, CUSTODY_PURPOSES, CustodyMode, CustodyPolicy};

use crate::application::ManifestFinding;
use crate::manifest::Manifest;

/// The tier of an environment (DEP-073).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    /// Development: software keys are allowed here, and only here.
    Development,
    /// Staging: production rules.
    Staging,
    /// Production.
    Production,
}

impl Tier {
    /// The manifest spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }

    /// Parses the manifest spelling.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "development" => Some(Self::Development),
            "staging" => Some(Self::Staging),
            "production" => Some(Self::Production),
            _ => None,
        }
    }

    /// Whether this tier refuses a `development` assurance (INV-15).
    pub fn refuses_development(self) -> bool {
        self != Self::Development
    }
}

/// The tier of `environment`: what it declares, else the tier its own name spells, else
/// `production` (fail closed: an environment that says nothing and is not named for a tier is
/// held to the strictest rules).
pub fn tier_of(environment: &str, declared: Option<Tier>) -> Tier {
    declared.or_else(|| Tier::parse(environment)).unwrap_or(Tier::Production)
}

/// A `KeyCustody` adapter bound to an authority purpose (DEP-074).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CustodyBinding {
    /// The adapter's name.
    pub adapter: String,
    /// The assurance the binding declares.
    pub assurance: Assurance,
    /// The mode the binding declares.
    pub mode: CustodyMode,
    /// Whether the adapter has no network path; required for `cold` (TRU-116).
    pub offline: bool,
}

/// `KeyCustody` adapters, and whether each is hardware-backed (a software adapter can only be
/// `development`, TRU-112).
pub const KEY_CUSTODY_ADAPTERS: &[(&str, bool)] =
    &[("pkcs11-hsm", true), ("cloud-kms", true), ("software", false), ("memory", false), ("memory-dev", false), ("dev", false)];

fn is_hardware(adapter: &str) -> Option<bool> {
    KEY_CUSTODY_ADAPTERS.iter().find(|(n, _)| *n == adapter).map(|(_, h)| *h)
}

/// The bindings that are in force in `environment`: the manifest's, overridden by the
/// environment's own.
pub fn bindings(m: &Manifest, environment: &str) -> BTreeMap<String, CustodyBinding> {
    let mut out = m.custody.clone();
    if let Some(e) = m.environments.get(environment) {
        out.extend(e.custody.clone());
    }
    out
}

fn violation(path: &str, msg: String) -> ManifestFinding {
    ManifestFinding::PolicyFloorViolation(format!("{path}: {msg}"))
}

/// Findings for the custody bindings of one environment (DEP-074). With `minimums` (the
/// effective policy's `factory.custody`), every purpose must be bound and meet the minimums on
/// both axes; without it, only the checks that need no policy are made.
pub fn check_custody(m: &Manifest, environment: &str, minimums: Option<&CustodyPolicy>) -> Vec<ManifestFinding> {
    let mut out = vec![];
    let tier = tier_of(environment, m.environments.get(environment).and_then(|e| e.tier));
    let bound = bindings(m, environment);
    for (purpose, b) in &bound {
        let path = format!("spec.custody.{purpose}");
        if !CUSTODY_PURPOSES.contains(&purpose.as_str()) {
            out.push(ManifestFinding::SchemaError(format!("{path}: `{purpose}` is not an authority purpose")));
            continue;
        }
        match is_hardware(&b.adapter) {
            None => out.push(ManifestFinding::UnknownAdapter(format!(
                "{path}.adapter: `{}` is not a KeyCustody adapter (known: {})",
                b.adapter,
                KEY_CUSTODY_ADAPTERS.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
            ))),
            Some(false) if b.assurance != Assurance::Development => out.push(violation(
                &path,
                format!("the software adapter `{}` can only be `development`, not `{}` (TRU-112)", b.adapter, b.assurance.as_str()),
            )),
            Some(true) if b.assurance == Assurance::Development => {
                out.push(violation(&path, format!("the hardware adapter `{}` is declared `development`; declare `custody-bound` or `attested` (DEP-074)", b.adapter)));
            }
            Some(_) => {}
        }
        if b.mode == CustodyMode::Cold && !b.offline {
            out.push(violation(&path, "a `cold` binding must be `offline: true` (TRU-116, DEP-074)".into()));
        }
        if b.mode == CustodyMode::Hot && b.offline {
            out.push(ManifestFinding::SchemaError(format!("{path}.offline: only a `cold` binding is offline")));
        }
        if b.assurance == Assurance::Development && tier.refuses_development() {
            out.push(violation(
                &path,
                format!("a `development` key cannot be bound in {environment} (tier {}): INV-15, DEP-073", tier.as_str()),
            ));
        }
    }
    if let Some(min) = minimums {
        for purpose in CUSTODY_PURPOSES {
            let path = format!("spec.custody.{purpose}");
            let Some(b) = bound.get(*purpose) else {
                out.push(violation(&path, format!("no custody binding for `{purpose}` in {environment} (DEP-074)")));
                continue;
            };
            if let Some(least) = min.min_assurance.get(*purpose).filter(|least| b.assurance < **least) {
                out.push(violation(
                    &path,
                    format!("assurance `{}` is below the policy minimum `{}` in {environment} (POL-065)", b.assurance.as_str(), least.as_str()),
                ));
            }
            if let Some(least) = min.min_mode.get(*purpose).filter(|least| b.mode < **least) {
                out.push(violation(&path, format!("mode `{}` is below the policy minimum `{}` in {environment} (POL-065)", b.mode.as_str(), least.as_str())));
            }
        }
    }
    out
}

/// The variable a service reads its declared custody from (DEP-074): `FIELDSEAL_CUSTODY_<PURPOSE>`
/// holding `<assurance>:<mode>`.
pub fn env_name(purpose: &str) -> String {
    format!("FIELDSEAL_CUSTODY_{}", purpose.to_ascii_uppercase())
}

/// The refusals of a service's start-up check: every declared custody must meet the effective
/// policy's minimums, and `development` is refused in a production tier (DEP-074, INV-15).
/// `lookup` reads the service's environment; a purpose it declares nothing for is skipped, since
/// a service holds only the keys it uses.
pub fn startup_check(lookup: &dyn Fn(&str) -> Option<String>, tier: Tier, minimums: &CustodyPolicy) -> Result<(), Vec<String>> {
    let mut why = vec![];
    for purpose in CUSTODY_PURPOSES {
        let Some(declared) = lookup(&env_name(purpose)) else { continue };
        let parsed = declared.split_once(':').and_then(|(a, m)| Some((Assurance::parse(a)?, CustodyMode::parse(m)?)));
        let Some((assurance, mode)) = parsed else {
            why.push(format!("{}: `{declared}` is not `<assurance>:<mode>`", env_name(purpose)));
            continue;
        };
        if assurance == Assurance::Development && tier.refuses_development() {
            why.push(format!("{purpose}: a development key in tier {} (INV-15)", tier.as_str()));
        }
        if minimums.min_assurance.get(*purpose).is_some_and(|least| assurance < *least) {
            why.push(format!("{purpose}: assurance {} is below the policy minimum", assurance.as_str()));
        }
        if minimums.min_mode.get(*purpose).is_some_and(|least| mode < *least) {
            why.push(format!("{purpose}: mode {} is below the policy minimum", mode.as_str()));
        }
    }
    if why.is_empty() { Ok(()) } else { Err(why) }
}
