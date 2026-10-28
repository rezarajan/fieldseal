//! Key roles, the tags each may sign or open, and validity limits (TRU §6.1, TRU-003,
//! TRU-010, TRU-011).

use fieldseal_kernel::crypto::{DomainTag, Purpose, tags};
use fieldseal_kernel::time::AuthorityTime;

/// What an authority key is for: the root, or exactly one purpose (TRU-010).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum KeyRole {
    /// The authority's offline root. It signs only key certificates, trust bundles and
    /// revocations (TRU-003).
    Root,
    /// An online key certified for one purpose.
    Purpose(Purpose),
}

impl KeyRole {
    /// The name written in a key certificate's `purpose` field: `root` or a TRU §6.1 purpose.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyRole::Root => "root",
            KeyRole::Purpose(p) => p.as_str(),
        }
    }

    /// Parses a role name; `None` for any other text.
    pub fn parse(text: &str) -> Option<Self> {
        if text == "root" { Some(KeyRole::Root) } else { Purpose::parse(text).map(KeyRole::Purpose) }
    }

    /// The purpose, if this is not the root.
    pub fn purpose(self) -> Option<Purpose> {
        match self {
            KeyRole::Root => None,
            KeyRole::Purpose(p) => Some(p),
        }
    }

    /// The key algorithms a key in this role may have (WIRE-009, WIRE-023). Roots and
    /// signing purposes are P-256; `record` keys are X25519 (TRU-020); `registration` keys
    /// both sign (tokens and certificates) and open requests, so either.
    pub fn allows(self, algorithm: KeyAlgorithm) -> bool {
        match self {
            KeyRole::Purpose(Purpose::Record) => algorithm == KeyAlgorithm::X25519,
            KeyRole::Purpose(Purpose::Registration) => true,
            _ => algorithm == KeyAlgorithm::P256,
        }
    }
}

impl core::fmt::Display for KeyRole {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The two key algorithms of authority keys (WIRE-009).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum KeyAlgorithm {
    /// ECDSA / ECDH over P-256, 65-byte uncompressed SEC1 public keys.
    P256,
    /// X25519 for HPKE suite `fs1-x`, 32-byte public keys.
    X25519,
}

/// The authority role that signs structures under `tag`, or `None` if no authority key
/// does (device tags such as `record/v1`, and the log's own `tree-head/v1`).
///
/// This is the purpose ↔ domain-tag mapping TRU-011 checks: a signature under `tag` is
/// trusted only from a key certified for this role.
pub fn signer_role(tag: &DomainTag) -> Option<KeyRole> {
    let t = tag.as_str();
    let is = |other: &DomainTag| other.as_str() == t;
    if is(&tags::KEY_CERTIFICATE) || is(&tags::TRUST_BUNDLE) || is(&tags::REVOCATION) {
        Some(KeyRole::Root)
    } else if is(&tags::BUNDLE) {
        Some(KeyRole::Purpose(Purpose::Factory))
    } else if is(&tags::REGISTRATION_TOKEN)
        || is(&tags::TENANCY_CERTIFICATE)
        || is(&tags::CLOSE_CERTIFICATE)
        || is(&tags::RESET_CERTIFICATE)
    {
        Some(KeyRole::Purpose(Purpose::Registration))
    } else if is(&tags::ARTEFACT) || is(&tags::PUBLICATION) || is(&tags::WITHDRAWAL) {
        Some(KeyRole::Purpose(Purpose::Publisher))
    } else if is(&tags::PROVENANCE) {
        Some(KeyRole::Purpose(Purpose::Builder))
    } else if is(&tags::RECEIPT) || is(&tags::TIME_TOKEN) {
        Some(KeyRole::Purpose(Purpose::Receipt))
    } else if is(&tags::RECEIVER_CHALLENGE) {
        Some(KeyRole::Purpose(Purpose::Receiver))
    } else {
        None
    }
}

/// Whether a key held for `role` may sign under `tag`: the tags of its role
/// ([`signer_role`]), and, for any P-256 authority key, its own certificate request's proof
/// of possession (`fieldseal.dev/csr/v1`, TRU-016).
pub fn may_sign(role: KeyRole, tag: &DomainTag) -> bool {
    signer_role(tag) == Some(role) || tag.as_str() == tags::CSR.as_str()
}

/// Whether a key of `purpose` may open seals under `tag` (TRU §6.1, WIRE-038, WIRE-103,
/// WIRE-134): `record` keys open record payloads and export manifests, `registration` keys
/// open registration requests and an unregistered tenancy's export manifest.
pub fn may_open(purpose: Purpose, tag: &DomainTag) -> bool {
    let t = tag.as_str();
    match purpose {
        Purpose::Record => t == tags::RECORD_SEAL.as_str() || t == tags::EXPORT_MANIFEST_SEAL.as_str(),
        Purpose::Registration => {
            t == tags::REGISTRATION_SEAL.as_str() || t == tags::EXPORT_MANIFEST_SEAL.as_str()
        }
        _ => false,
    }
}

/// One year, as used for validity limits: 365 days (the strict reading of TRU §6.1).
pub const YEAR_MS: u64 = 365 * AuthorityTime::DAY;

/// The longest validity a root may have: 10 years (TRU-004).
pub const ROOT_MAX_VALIDITY_MS: u64 = 10 * YEAR_MS;

/// How long a key in a role may be valid (TRU §6.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValidityLimit {
    /// At most this many milliseconds from `not_before` to `not_after`.
    AtMost(u64),
    /// Until the end of the collection period plus the deployment's retention (`record`).
    PeriodPlusRetention,
}

/// The validity limit for `role` (TRU-004, TRU-012, TRU §6.1).
pub fn validity_limit(role: KeyRole) -> ValidityLimit {
    match role {
        KeyRole::Root => ValidityLimit::AtMost(ROOT_MAX_VALIDITY_MS),
        KeyRole::Purpose(Purpose::Publisher) => ValidityLimit::AtMost(2 * YEAR_MS),
        KeyRole::Purpose(Purpose::Record) => ValidityLimit::PeriodPlusRetention,
        KeyRole::Purpose(_) => ValidityLimit::AtMost(YEAR_MS),
    }
}
