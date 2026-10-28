//! Published instrument versions and their labels (ADR 0027, INS §5.10a).

use fieldseal_kernel::id::{Fingerprint, Salt};

use super::version::SchemaVersion;

/// A human label for an instrument. Labels never identify an instrument (ADR 0027, INS-101).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct InstrumentLabel {
    /// The author's chosen name.
    pub name: String,
    /// The author's version of the content.
    pub version: SchemaVersion,
}

/// A published instrument version: its salted fingerprint, its salt and canonical bytes
/// (ADR 0027). Constructed only by verifying the fingerprint against the bytes, which is
/// format-core work (issue #42); until then the parts are kept together read-only.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublishedInstrument {
    fingerprint: Fingerprint,
    salt: Salt,
    canonical_bytes: Vec<u8>,
}

impl PublishedInstrument {
    /// Keeps the three parts together. `verify` is the format core's fingerprint check
    /// (WIRE-185); an instrument whose fingerprint doesn't match is refused (INS-103).
    pub fn new(
        fingerprint: Fingerprint,
        salt: Salt,
        canonical_bytes: Vec<u8>,
        verify: impl Fn(&Salt, &[u8]) -> Fingerprint,
    ) -> Result<Self, FingerprintMismatch> {
        if verify(&salt, &canonical_bytes) != fingerprint {
            return Err(FingerprintMismatch);
        }
        Ok(Self { fingerprint, salt, canonical_bytes })
    }

    /// The instrument's identity.
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// The salt the fingerprint was computed with.
    pub fn salt(&self) -> &Salt {
        &self.salt
    }

    /// The canonical bytes.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// An instrument's fingerprint didn't match its salt and bytes (INS-103).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("instrument fingerprint does not match its contents")]
pub struct FingerprintMismatch;
