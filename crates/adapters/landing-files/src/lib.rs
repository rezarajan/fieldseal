//! A file-based [`DataPlatform`] for Intake: the generic long format as CSV, findings and
//! losses as CSV, and each instrument's data contract as JSON.
//!
//! CSV is chosen over Parquet for this first adapter because it needs no dependency beyond
//! the standard library, opens in every analysis tool, and is trivially diffable in review;
//! a lakehouse adapter (Parquet/Delta) is a drop-in replacement behind the same port. State
//! is held by an in-memory platform for the life of the process and the files are rewritten
//! from it after every write, so the files always show the full current state, with
//! exclusions as flags and nothing deleted. Values are landed locale-free (ADR 0034). Every
//! file is written with the atomic-write helper, so a reader never sees a torn file.
//!
//! [`FileDataPlatform::open_read_only`] opens a landing directory as a snapshot, and the
//! [`export`] module turns a snapshot into the results export.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use fieldseal_adapters_file::atomic::write_atomic;
use fieldseal_adapters_memory::intake::MemoryDataPlatform;
use fieldseal_intake::data_contract::DataContract;
use fieldseal_intake::domain::{ConsentCase, Finding, LandedEnvelope, LandedObservation, LossLedgerEntry, SubmissionId};
use fieldseal_intake::ports::{DataPlatform, DataPlatformError, LandingBatch};
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::id::{Digest, Fingerprint, RecordId, SubjectId, TenancyId};

pub mod export;

pub use export::writers::{csv_field, json, long_header, long_row};

fn io(e: std::io::Error) -> DataPlatformError {
    DataPlatformError::Backend(e.to_string())
}

/// A [`DataPlatform`] that keeps the landed data in a directory: `observations.csv`,
/// `findings.csv`, `losses.csv`, and `contracts/<instrument>.json`.
pub struct FileDataPlatform {
    dir: PathBuf,
    inner: MemoryDataPlatform,
    instruments: std::sync::Mutex<BTreeSet<Fingerprint>>,
    read_only: bool,
}

impl FileDataPlatform {
    /// Writes into `dir`, which is created if absent.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, DataPlatformError> {
        let dir = dir.into();
        std::fs::create_dir_all(dir.join("contracts")).map_err(io)?;
        Ok(Self { dir, inner: MemoryDataPlatform::new(), instruments: Default::default(), read_only: false })
    }

    /// Opens a landing directory as a snapshot: reads `observations.csv` once into memory and
    /// answers the read side of [`DataPlatform`] from those rows. Nothing is written, and the
    /// directory is not created. Only observations are in the snapshot, so reading envelopes,
    /// evidence, consent cases, losses or findings is an error.
    pub fn open_read_only(dir: impl Into<PathBuf>) -> Result<Self, DataPlatformError> {
        let dir = dir.into();
        let path = dir.join("observations.csv");
        let text = std::fs::read_to_string(&path).map_err(|e| DataPlatformError::Backend(format!("{}: {e}", path.display())))?;
        let rows = snapshot::parse(&text).map_err(|e| DataPlatformError::Backend(format!("{}: {e}", path.display())))?;
        let inner = MemoryDataPlatform::new();
        let instruments = rows.iter().map(|r| r.observation.instrument).collect();
        let exclusions: BTreeSet<(RecordId, String)> = rows.iter().filter_map(|r| r.excluded.clone().map(|why| (r.observation.source, why))).collect();
        let observations = rows.into_iter().map(|r| r.observation).collect();
        inner.land(&LandingBatch { observations, exclusions: exclusions.into_iter().collect(), ..LandingBatch::default() })?;
        Ok(Self { dir, inner, instruments: std::sync::Mutex::new(instruments), read_only: true })
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The landing mark: the number of observation rows held, excluded rows included. For a
    /// snapshot it is the number of rows in `observations.csv` when it was read.
    pub fn landing_mark(&self) -> Result<u64, DataPlatformError> {
        let fps: Vec<Fingerprint> = self.instruments.lock().expect("lock").iter().copied().collect();
        let mut n = 0;
        for fp in fps {
            n += self.inner.observations(&fp)?.len() as u64;
        }
        Ok(n)
    }

    /// Writes an instrument's data contract as JSON (INT-056) and returns its path.
    pub fn write_contract(&self, contract: &DataContract) -> Result<PathBuf, DataPlatformError> {
        let path = self.dir.join("contracts").join(format!("{}.json", lower_hex(contract.instrument.as_bytes())));
        write_atomic(&path, json(&contract.to_value()).as_bytes()).map_err(io)?;
        Ok(path)
    }

    fn writable(&self) -> Result<(), DataPlatformError> {
        if self.read_only { Err(DataPlatformError::Backend("the landing directory is open read-only".into())) } else { Ok(()) }
    }

    fn snapshot_only(&self) -> Result<(), DataPlatformError> {
        if self.read_only { Err(DataPlatformError::Backend("a read-only snapshot holds observations only".into())) } else { Ok(()) }
    }

    fn rewrite(&self) -> Result<(), DataPlatformError> {
        let mut obs = long_header();
        obs.push('\n');
        for fp in self.instruments()? {
            for r in self.inner.observations(&fp)? {
                obs.push_str(&long_row(&r));
                obs.push('\n');
            }
        }
        write_atomic(&self.dir.join("observations.csv"), obs.as_bytes()).map_err(io)?;
        let mut f = String::from("submission,kind,rule,detail\n");
        for (id, x) in self.inner.findings()? {
            let _ = writeln!(f, "{},{:?},{},{}", lower_hex(id.0.as_bytes()), x.kind, csv_field(&x.rule), csv_field(&x.detail));
        }
        write_atomic(&self.dir.join("findings.csv"), f.as_bytes()).map_err(io)?;
        let mut l = String::from("tenancy,from_seq,through_seq,reason\n");
        for x in self.inner.losses()? {
            let _ = writeln!(l, "{},{},{},{}", lower_hex(x.tenancy.as_bytes()), x.from.0, x.through.0, csv_field(&x.reason));
        }
        write_atomic(&self.dir.join("losses.csv"), l.as_bytes()).map_err(io)
    }
}

impl DataPlatform for FileDataPlatform {
    fn land(&self, batch: &LandingBatch) -> Result<(), DataPlatformError> {
        self.writable()?;
        self.inner.land(batch)?;
        self.instruments.lock().expect("lock").extend(batch.observations.iter().map(|o| o.instrument));
        self.rewrite()
    }

    fn exclude(&self, sources: &[RecordId], reason: &str) -> Result<(), DataPlatformError> {
        self.writable()?;
        self.inner.exclude(sources, reason)?;
        self.rewrite()
    }

    fn reinstate(&self, sources: &[RecordId]) -> Result<(), DataPlatformError> {
        self.writable()?;
        self.inner.reinstate(sources)?;
        self.rewrite()
    }

    fn instruments(&self) -> Result<Vec<Fingerprint>, DataPlatformError> {
        Ok(self.instruments.lock().expect("lock").iter().copied().collect())
    }

    fn observations(&self, instrument: &Fingerprint) -> Result<Vec<LandedObservation>, DataPlatformError> {
        self.inner.observations(instrument)
    }

    fn envelopes(&self, tenancy: &TenancyId) -> Result<Vec<LandedEnvelope>, DataPlatformError> {
        self.snapshot_only()?;
        self.inner.envelopes(tenancy)
    }

    fn evidence(&self, blob_id: &[u8; 16]) -> Result<Option<Digest>, DataPlatformError> {
        self.snapshot_only()?;
        self.inner.evidence(blob_id)
    }

    fn consent_case(&self, t: &TenancyId, s: &SubjectId, i: &Fingerprint) -> Result<Option<ConsentCase>, DataPlatformError> {
        self.snapshot_only()?;
        self.inner.consent_case(t, s, i)
    }

    fn consent_cases(&self) -> Result<Vec<ConsentCase>, DataPlatformError> {
        self.snapshot_only()?;
        self.inner.consent_cases()
    }

    fn losses(&self) -> Result<Vec<LossLedgerEntry>, DataPlatformError> {
        self.snapshot_only()?;
        self.inner.losses()
    }

    fn findings(&self) -> Result<Vec<(SubmissionId, Finding)>, DataPlatformError> {
        self.snapshot_only()?;
        self.inner.findings()
    }
}

mod snapshot;
