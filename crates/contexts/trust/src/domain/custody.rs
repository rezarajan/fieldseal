//! Authority key custody (TRU §5.10, §6.7, [ADR 0038]): an operating **mode** and an
//! **assurance**, fixed at issuance and kept in the authority's private issuance record.
//!
//! Nothing here is encoded in a certificate, a request or a trust bundle (TRU-107): those
//! structures are closed (WIRE-005). The functions are pure rules over values the caller has
//! already established: the issuing command knows which of the three means (TRU-108) a request
//! came by, a policy decision (`key.issue`, POL-067) has already judged it against the
//! minimums, and these rules check what only the Trust context can: a development key never
//! reaches a production root, a development key is never promoted, and an auditor can compare
//! a trust bundle's keys with their records.
//!
//! [ADR 0038]: ../../../../docs/explanation/adr/0038-authority-key-custody-classes.md

use std::collections::BTreeSet;

use fieldseal_kernel::id::{ContentAddress, Digest, KeyId};
use fieldseal_kernel::time::AuthorityTime;

use super::certificate::KeyCertificate;
use super::error::TrustError;
use super::purpose::{KeyRole, ValidityLimit, validity_limit};

/// How a key is used (TRU §6.7). `Hot` < `Cold`: offline is the stricter mode.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Mode {
    /// Online, by a running service through `KeyCustody`.
    Hot,
    /// Offline only, in a recorded ceremony.
    Cold,
}

impl Mode {
    /// The written form, `hot` or `cold`.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Hot => "hot",
            Mode::Cold => "cold",
        }
    }

    /// Parses `hot` or `cold`.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "hot" => Some(Mode::Hot),
            "cold" => Some(Mode::Cold),
            _ => None,
        }
    }
}

/// What is known about how a key was made (TRU §6.7): `Development` < `CustodyBound` < `Attested`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Assurance {
    /// A software key; refused in production (INV-15).
    Development,
    /// Generated inside a hardware custody the deployment binds to the purpose.
    CustodyBound,
    /// Custody-bound, with key-attestation evidence a verifier accepted.
    Attested,
}

impl Assurance {
    /// The written form.
    pub fn as_str(self) -> &'static str {
        match self {
            Assurance::Development => "development",
            Assurance::CustodyBound => "custody-bound",
            Assurance::Attested => "attested",
        }
    }

    /// Parses a written form.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "development" => Some(Assurance::Development),
            "custody-bound" => Some(Assurance::CustodyBound),
            "attested" => Some(Assurance::Attested),
            _ => None,
        }
    }
}

/// The three means by which an issuer establishes assurance (TRU-108); there is no fourth.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Means {
    /// The request came from a software custody adapter.
    Software,
    /// A hardware custody adapter the manifest binds to the purpose generated the key in the
    /// issuing ceremony, and the key proved possession (TRU-016).
    BoundGeneration,
    /// Evidence in a registered authority-evidence format verified (TRU-110).
    VerifiedEvidence,
}

/// A key's custody: assurance and mode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Custody {
    /// What is known about how the key was made.
    pub assurance: Assurance,
    /// How the key is used.
    pub mode: Mode,
}

/// The least custody a purpose may have (POL-065).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CustodyMinimum {
    /// The least assurance.
    pub assurance: Assurance,
    /// The least mode.
    pub mode: Mode,
}

impl Custody {
    /// Whether this custody is at least `minimum` on both axes.
    pub fn meets(self, minimum: CustodyMinimum) -> bool {
        self.assurance >= minimum.assurance && self.mode >= minimum.mode
    }

    /// Checks `self` against `minimum`, naming the axis that falls short (TRU-112).
    pub fn check(self, minimum: CustodyMinimum) -> Result<(), TrustError> {
        if self.assurance < minimum.assurance {
            return Err(TrustError::BelowMinimum { what: "assurance", actual: self.assurance.as_str(), minimum: minimum.assurance.as_str() });
        }
        if self.mode < minimum.mode {
            return Err(TrustError::BelowMinimum { what: "mode", actual: self.mode.as_str(), minimum: minimum.mode.as_str() });
        }
        Ok(())
    }
}

/// The custody the `means` establishes, in the `mode` the purpose's binding declares
/// (TRU-108): software is `development`, bound generation `custody-bound`, verified evidence
/// `attested`.
pub fn establish(means: Means, mode: Mode) -> Custody {
    let assurance = match means {
        Means::Software => Assurance::Development,
        Means::BoundGeneration => Assurance::CustodyBound,
        Means::VerifiedEvidence => Assurance::Attested,
    };
    Custody { assurance, mode }
}

/// The tier of the environment a root certifies for (DEP-073).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RootTier {
    /// A development root, listed only in development trust bundles (TRU-109).
    Development,
    /// A root that certifies keys for staging or production.
    Production,
}

impl RootTier {
    /// The written form.
    pub fn as_str(self) -> &'static str {
        match self {
            RootTier::Development => "development",
            RootTier::Production => "production",
        }
    }

    /// Parses a written form.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "development" => Some(RootTier::Development),
            "production" => Some(RootTier::Production),
            _ => None,
        }
    }
}

/// The authority-private record of one issuance (TRU-111). It holds no name (TRU-090): the
/// key is its ID, and any evidence only by digest.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IssuanceRecord {
    /// The certified key.
    pub key_id: KeyId,
    /// The role it was certified for.
    pub role: KeyRole,
    /// Its custody.
    pub custody: Custody,
    /// The tier of the root that certified it.
    pub tier: RootTier,
    /// SHA-256 of the evidence, when assurance is `attested`.
    pub evidence_sha256: Option<Digest>,
    /// The policy layers behind the `key.issue` decision.
    pub policy_layers: Vec<ContentAddress>,
    /// The certificate's serial.
    pub serial: u64,
    /// When it was issued.
    pub issued: AuthorityTime,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

impl IssuanceRecord {
    /// The record as `name=value` lines, the form the authority's private store keeps.
    pub fn to_text(&self) -> String {
        let mut s = format!(
            "key={}\nrole={}\nassurance={}\nmode={}\ntier={}\nserial={}\nissued={}\n",
            hex(self.key_id.as_bytes()),
            self.role.as_str(),
            self.custody.assurance.as_str(),
            self.custody.mode.as_str(),
            self.tier.as_str(),
            self.serial,
            self.issued.0,
        );
        if let Some(d) = &self.evidence_sha256 {
            s.push_str(&format!("evidence={}\n", hex(d.as_bytes())));
        }
        for l in &self.policy_layers {
            s.push_str(&format!("policy={}\n", l.to_text()));
        }
        s
    }

    /// Reads [`IssuanceRecord::to_text`]. Unknown lines are refused (strict, WIRE-196).
    pub fn from_text(text: &str) -> Result<Self, TrustError> {
        let bad = TrustError::BadIssuanceRecord;
        let (mut key, mut role, mut assurance, mut mode, mut tier, mut serial, mut issued) = (None, None, None, None, None, None, None);
        let (mut evidence, mut layers) = (None, Vec::new());
        for line in text.lines().filter(|l| !l.is_empty()) {
            let (name, value) = line.split_once('=').ok_or_else(|| bad("a line is not name=value"))?;
            match name {
                "key" => key = Some(KeyId::from_bytes(&unhex(value).ok_or_else(|| bad("key is not hexadecimal"))?).map_err(|_| bad("key has the wrong length"))?),
                "role" => role = Some(KeyRole::parse(value).ok_or_else(|| bad("unknown role"))?),
                "assurance" => assurance = Some(Assurance::parse(value).ok_or_else(|| bad("unknown assurance"))?),
                "mode" => mode = Some(Mode::parse(value).ok_or_else(|| bad("unknown mode"))?),
                "tier" => tier = Some(RootTier::parse(value).ok_or_else(|| bad("unknown tier"))?),
                "serial" => serial = Some(value.parse::<u64>().map_err(|_| bad("serial is not a number"))?),
                "issued" => issued = Some(AuthorityTime(value.parse::<u64>().map_err(|_| bad("issued is not a number"))?)),
                "evidence" => {
                    evidence = Some(Digest::from_bytes(&unhex(value).ok_or_else(|| bad("evidence is not hexadecimal"))?).map_err(|_| bad("evidence has the wrong length"))?);
                }
                "policy" => layers.push(ContentAddress::parse_text(value).map_err(|_| bad("policy is not a content address"))?),
                _ => return Err(bad("unknown field")),
            }
        }
        let missing = || bad("a required field is missing");
        let custody = Custody { assurance: assurance.ok_or_else(missing)?, mode: mode.ok_or_else(missing)? };
        if (custody.assurance == Assurance::Attested) != evidence.is_some() {
            return Err(bad("evidence is present exactly when the assurance is attested"));
        }
        Ok(Self {
            key_id: key.ok_or_else(missing)?,
            role: role.ok_or_else(missing)?,
            custody,
            tier: tier.ok_or_else(missing)?,
            evidence_sha256: evidence,
            policy_layers: layers,
            serial: serial.ok_or_else(missing)?,
            issued: issued.ok_or_else(missing)?,
        })
    }
}

/// Whether a root of `tier` may certify `key` with `custody`, given the issuance records so far
/// (TRU-109, TRU-114): a production root refuses a `development` request, and refuses any key
/// ever recorded as `development`, because promotion is a new key.
pub fn admit(tier: RootTier, custody: Custody, key: &KeyId, prior: &[IssuanceRecord]) -> Result<(), TrustError> {
    if tier == RootTier::Production {
        if custody.assurance == Assurance::Development {
            return Err(TrustError::DevelopmentKeyInProduction);
        }
        if prior.iter().any(|r| &r.key_id == key && r.custody.assurance == Assurance::Development) {
            return Err(TrustError::PromotionRefused(*key));
        }
    }
    Ok(())
}

/// Checks a hot key's requested validity against policy's maximum and the TRU §6.1 limit
/// (TRU-113, POL-066).
pub fn check_hot_key_terms(role: KeyRole, validity_ms: u64, policy_max_ms: u64) -> Result<(), TrustError> {
    let cap = match validity_limit(role) {
        ValidityLimit::AtMost(limit) => limit.min(policy_max_ms),
        ValidityLimit::PeriodPlusRetention => policy_max_ms,
    };
    if validity_ms > cap {
        return Err(TrustError::HotKeyTooLong { max_ms: cap });
    }
    Ok(())
}

/// Checks a rotation: the successor must meet the minimum and must not be lower than the
/// predecessor's assurance (TRU-113).
pub fn check_rotation(predecessor: &IssuanceRecord, successor: Custody, minimum: CustodyMinimum) -> Result<(), TrustError> {
    successor.check(minimum)?;
    if successor.assurance < predecessor.custody.assurance {
        return Err(TrustError::RotationLowersAssurance);
    }
    Ok(())
}

/// One finding of `trust verify --audit` (TRU-117, TRU-114).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuditFinding {
    /// The key concerned.
    pub key_id: KeyId,
    /// What is wrong.
    pub issue: AuditIssue,
}

/// What an audit found wrong with one key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AuditIssue {
    /// The certificate has no issuance record.
    MissingRecord,
    /// The record's custody is below the policy minimum.
    BelowMinimum(&'static str),
    /// The key is `development` in a bundle that is not a development bundle (INV-15).
    DevelopmentInProduction,
    /// The key appears under both a development and a production root (TRU-114).
    BothTiers,
    /// The record's role or serial differs from the certificate's.
    Mismatch,
}

/// Compares every certificate in a trust bundle (`certificates`) with its record in `records`
/// (TRU-117), under the minimums policy sets (`minimum`) and the bundle's tier. Findings are in
/// certificate order, then in the order found.
pub fn audit(
    certificates: &[&KeyCertificate],
    records: &[IssuanceRecord],
    bundle_tier: RootTier,
    minimum: impl Fn(KeyRole) -> CustodyMinimum,
) -> Vec<AuditFinding> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for cert in certificates {
        let id = *cert.key_id();
        if !seen.insert(id) {
            continue;
        }
        let mine: Vec<&IssuanceRecord> = records.iter().filter(|r| r.key_id == id).collect();
        let Some(record) = mine.iter().find(|r| r.serial == cert.serial()).copied() else {
            out.push(AuditFinding { key_id: id, issue: AuditIssue::MissingRecord });
            continue;
        };
        if record.role != cert.role() {
            out.push(AuditFinding { key_id: id, issue: AuditIssue::Mismatch });
        }
        if let Err(TrustError::BelowMinimum { what, .. }) = record.custody.check(minimum(cert.role())) {
            out.push(AuditFinding { key_id: id, issue: AuditIssue::BelowMinimum(what) });
        }
        if bundle_tier == RootTier::Production && record.custody.assurance == Assurance::Development {
            out.push(AuditFinding { key_id: id, issue: AuditIssue::DevelopmentInProduction });
        }
        if mine.iter().any(|r| r.tier == RootTier::Development) && mine.iter().any(|r| r.tier == RootTier::Production) {
            out.push(AuditFinding { key_id: id, issue: AuditIssue::BothTiers });
        }
    }
    out
}
