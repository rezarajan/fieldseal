//! Intake's [`InstrumentSource`] over a directory of published instruments: every
//! `*.published` file there is a `Publication` that `artefact publish` wrote. A publication
//! counts only if it verifies against the trust bundle and the publishing policy (PUB, INT-070);
//! one that does not is skipped. The directory is read on each lookup, so an instrument
//! published a moment ago is known at once.

use std::path::PathBuf;

use fieldseal_instrument::application::validate_instrument;
use fieldseal_intake::ports::{InstrumentSource, InstrumentSourceError};
use fieldseal_kernel::cbor;
use fieldseal_kernel::id::Fingerprint;
use fieldseal_policy::domain::PublishingPolicy;
use fieldseal_publishing::application::VerifyPublication;
use fieldseal_publishing::domain::{ArtefactKind, Publication};
use fieldseal_trust::domain::{TrustBundle, TrustStore};

/// The instruments published into a directory.
pub struct PublishedInstruments {
    dir: PathBuf,
    trust: TrustBundle,
    policy: PublishingPolicy,
}

impl PublishedInstruments {
    /// The instruments in `dir`, verified against `trust` and `policy`.
    pub fn new(dir: impl Into<PathBuf>, trust: TrustBundle, policy: PublishingPolicy) -> Self {
        Self { dir: dir.into(), trust, policy }
    }
}

impl InstrumentSource for PublishedInstruments {
    fn instrument(&self, fingerprint: &Fingerprint) -> Result<Option<fieldseal_instrument::domain::Instrument>, InstrumentSourceError> {
        let Ok(rd) = std::fs::read_dir(&self.dir) else { return Ok(None) };
        let verifier = VerifyPublication::new(TrustStore::new(&self.trust), &self.policy);
        for entry in rd.filter_map(Result::ok).filter(|e| e.path().extension().is_some_and(|x| x == "published")) {
            let Ok(bytes) = std::fs::read(entry.path()) else { continue };
            let Ok(publication) = Publication::decode(&bytes) else { continue };
            let artefact = &publication.artefact;
            if artefact.kind() != ArtefactKind::Instrument || artefact.fingerprint().as_ref() != Some(fingerprint) {
                continue;
            }
            if verifier.verify(&publication, &[]).is_err() {
                continue;
            }
            let value = cbor::decode(artefact.canonical_bytes()).map_err(|e| InstrumentSourceError::Unavailable(e.to_string()))?;
            return Ok(validate_instrument(&value).ok().map(|v| v.instrument));
        }
        Ok(None)
    }
}
