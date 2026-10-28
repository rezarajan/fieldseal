//! The `Artefact` aggregate: one version of one artefact, its canonical bytes and its
//! identity (PUB §2, PUB-001, PUB-020–022, PUB-090–092, ADR 0027).

use fieldseal_kernel::digest::{instrument_fingerprint, sha256};
use fieldseal_kernel::id::{ContentAddress, Digest, Fingerprint, Salt};
use fieldseal_trust::ports::RandomSource;

use super::error::PublishingError;

/// The kinds of artefact published through this context (PUB §1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum ArtefactKind {
    /// `kind: Instrument`
    Instrument,
    /// `kind: Layout` (ADR 0033)
    Layout,
    /// `kind: Localisation` (ADR 0034)
    Localisation,
    /// `kind: Policy`
    Policy,
    /// `kind: TrustBundle`
    TrustBundle,
    /// `kind: Deployment`
    Deployment,
}

impl ArtefactKind {
    /// Every kind, in the order of PUB §1.
    pub const ALL: [ArtefactKind; 6] = [
        Self::Instrument,
        Self::Layout,
        Self::Localisation,
        Self::Policy,
        Self::TrustBundle,
        Self::Deployment,
    ];

    /// The `kind` as written in an artefact and in the trust bundle's `publishers` map.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Instrument => "Instrument",
            Self::Layout => "Layout",
            Self::Localisation => "Localisation",
            Self::Policy => "Policy",
            Self::TrustBundle => "TrustBundle",
            Self::Deployment => "Deployment",
        }
    }

    /// Parses a `kind`.
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == text)
    }
}

impl core::fmt::Display for ArtefactKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether `name` is a valid `metadata.name`: lower-case ASCII letters and digits in
/// hyphen-separated words, at most 63 characters (PUB §6.2).
pub fn is_valid_name(name: &str) -> bool {
    name.len() <= 63
        && !name.is_empty()
        && name.split('-').all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
}

fn numeric(part: &str) -> bool {
    !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()) && (part == "0" || !part.starts_with('0'))
}

fn identifiers(part: &str, numeric_rule: bool) -> bool {
    !part.is_empty()
        && part.split('.').all(|id| {
            !id.is_empty()
                && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && (!numeric_rule || !id.bytes().all(|b| b.is_ascii_digit()) || numeric(id))
        })
}

/// Whether `version` is a Semantic Versioning 2.0.0 version (PUB-001), at most 64
/// characters.
pub fn is_valid_version(version: &str) -> bool {
    if version.len() > 64 {
        return false;
    }
    let (rest, build) = match version.split_once('+') {
        Some((r, b)) => (r, Some(b)),
        None => (version, None),
    };
    let (core, pre) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| numeric(p))
        && pre.is_none_or(|p| identifiers(p, true))
        && build.is_none_or(|b| identifiers(b, false))
}

/// A new 32-byte instrument salt from the random source (PUB-090). Generated once, when an
/// instrument version is first built, and kept for that version.
pub fn new_salt(random: &(impl RandomSource + ?Sized)) -> Salt {
    let mut bytes = [0u8; Salt::LEN];
    random.fill(&mut bytes);
    Salt::from(bytes)
}

/// The identity of an artefact's canonical bytes (`fieldseal instrument hash` and its
/// equivalents, PUB-022): for an instrument, its salted fingerprint (PUB-092, WIRE-185);
/// for any other kind, the SHA-256 content address (PUB-021). An instrument needs a salt
/// and no other kind may have one.
pub fn artefact_address(kind: ArtefactKind, canonical: &[u8], salt: Option<&Salt>) -> Result<ContentAddress, PublishingError> {
    match (kind, salt) {
        (ArtefactKind::Instrument, Some(salt)) => {
            Ok(ContentAddress::from(*instrument_fingerprint(salt, canonical).as_bytes()))
        }
        (ArtefactKind::Instrument, None) => Err(PublishingError::InvalidArtefact("an instrument needs a salt")),
        (_, Some(_)) => Err(PublishingError::InvalidArtefact("only instruments have a salt")),
        (_, None) => Ok(ContentAddress::of(canonical)),
    }
}

/// One version of one artefact: kind, name, semantic version, canonical bytes and the
/// identity derived from them. The identity is computed, never supplied, so it can't
/// disagree with the bytes; any change is a new version.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Artefact {
    kind: ArtefactKind,
    name: String,
    version: String,
    canonical: Vec<u8>,
    salt: Option<Salt>,
    address: ContentAddress,
}

impl Artefact {
    /// Builds an artefact version, checking the name and version (PUB-001, PUB §6.2) and
    /// that a salt is present exactly for instruments (PUB-090).
    pub fn new(
        kind: ArtefactKind,
        name: &str,
        version: &str,
        canonical: Vec<u8>,
        salt: Option<Salt>,
    ) -> Result<Self, PublishingError> {
        if !is_valid_name(name) {
            return Err(PublishingError::InvalidArtefact("name must be lower-case hyphenated words"));
        }
        if !is_valid_version(version) {
            return Err(PublishingError::InvalidArtefact("version must be a semantic version"));
        }
        let address = artefact_address(kind, &canonical, salt.as_ref())?;
        Ok(Self { kind, name: name.to_owned(), version: version.to_owned(), canonical, salt, address })
    }

    /// The kind.
    pub fn kind(&self) -> ArtefactKind {
        self.kind
    }

    /// `metadata.name`: a human label, never an identifier (ADR 0027).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `metadata.version`.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The canonical bytes (PUB-020).
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// The instrument salt, for instruments.
    pub fn salt(&self) -> Option<&Salt> {
        self.salt.as_ref()
    }

    /// The artefact's identity: the fingerprint for an instrument, else the content address.
    pub fn address(&self) -> &ContentAddress {
        &self.address
    }

    /// The fingerprint, for an instrument.
    pub fn fingerprint(&self) -> Option<Fingerprint> {
        self.salt.map(|_| Fingerprint::from(*self.address.as_bytes()))
    }

    /// SHA-256 of the canonical bytes (for an instrument this differs from its address).
    pub fn sha256(&self) -> Digest {
        sha256(&self.canonical)
    }
}
