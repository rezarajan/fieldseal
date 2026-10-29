//! What the results export reads: a landing snapshot, through the landing-files
//! [`DataPlatform`] adapter, and a published directory, verified against a trust bundle.
//!
//! The CLI and the results reader both come through here, so they read the same way.

use std::collections::BTreeMap;
use std::path::Path;

use fieldseal_instrument::application::validate_instrument;
use fieldseal_instrument::domain::Instrument;
use fieldseal_intake::data_contract::generate_data_contract;
use fieldseal_intake::ports::DataPlatform;
use fieldseal_kernel::cbor;
use fieldseal_kernel::id::{ContentAddress, Fingerprint};
use fieldseal_policy::domain::PublishingPolicy;
use fieldseal_publishing::application::VerifyPublication;
use fieldseal_publishing::domain::{ArtefactKind, Publication};
use fieldseal_trust::domain::{TrustBundle, TrustStore};

use super::{ExportError, ExportTable, SubjectMapper};
use crate::FileDataPlatform;

/// The verified publications of a published directory that an export needs.
pub struct Published {
    instruments: BTreeMap<Fingerprint, (ContentAddress, Instrument)>,
    layouts: Vec<(Fingerprint, ContentAddress)>,
}

impl Published {
    /// Reads every `*.published` file in `dir` and keeps the instruments and layouts whose
    /// publication verifies against `trust` and `policy`. A file that does not decode or
    /// verify is skipped, as the intake gate's instrument source skips it. Withdrawals are not
    /// kept in the directory, so none applies (replay treats the directory as append-only).
    pub fn read(dir: &Path, trust: &TrustBundle, policy: &PublishingPolicy) -> Result<Self, ExportError> {
        let rd = std::fs::read_dir(dir).map_err(|e| ExportError::Io(format!("{}: {e}", dir.display())))?;
        let mut paths: Vec<_> = rd.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "published")).collect();
        paths.sort();
        let verifier = VerifyPublication::new(TrustStore::new(trust), policy);
        let (mut instruments, mut layouts) = (BTreeMap::new(), Vec::new());
        for path in paths {
            let bytes = std::fs::read(&path).map_err(|e| ExportError::Io(format!("{}: {e}", path.display())))?;
            let Ok(publication) = Publication::decode(&bytes) else { continue };
            let artefact = &publication.artefact;
            match artefact.kind() {
                ArtefactKind::Instrument | ArtefactKind::Layout if verifier.verify(&publication, &[]).is_err() => {}
                ArtefactKind::Instrument => {
                    let Some(fingerprint) = artefact.fingerprint() else { continue };
                    let Ok(value) = cbor::decode(artefact.canonical_bytes()) else { continue };
                    if let Ok(valid) = validate_instrument(&value) {
                        instruments.insert(fingerprint, (*artefact.address(), valid.instrument));
                    }
                }
                ArtefactKind::Layout => {
                    if let Ok(facts) = fieldseal_distribution::domain::layout_facts(artefact) {
                        layouts.push((facts.instrument, *artefact.address()));
                    }
                }
                _ => {}
            }
        }
        Ok(Self { instruments, layouts })
    }

    /// The published instrument under `fingerprint`.
    pub fn instrument(&self, fingerprint: &Fingerprint) -> Option<&Instrument> {
        self.instruments.get(fingerprint).map(|(_, i)| i)
    }
}

/// The export table of a landing snapshot: every row of every instrument, each instrument's
/// contract rendered from its publication, and the manifest's instruments and layouts from
/// `published`. An instrument with landed rows and no verified publication is an error.
pub fn export_table(snapshot: &FileDataPlatform, published: &Published, mapper: &dyn SubjectMapper) -> Result<ExportTable, ExportError> {
    let mut rows = Vec::new();
    let (mut contracts, mut addresses) = (BTreeMap::new(), BTreeMap::new());
    let fingerprints = snapshot.instruments()?;
    for fp in &fingerprints {
        rows.extend(snapshot.observations(fp)?);
        if let Some((address, instrument)) = published.instruments.get(fp) {
            contracts.insert(*fp, generate_data_contract(*fp, instrument));
            addresses.insert(*fp, *address);
        }
    }
    let layouts: Vec<ContentAddress> = published.layouts.iter().filter(|(fp, _)| fingerprints.contains(fp)).map(|(_, a)| *a).collect();
    Ok(ExportTable::from_observations(rows, contracts, mapper)?.with_publications(addresses, layouts))
}
