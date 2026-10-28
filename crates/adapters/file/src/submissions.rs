//! A file-backed [`SubmissionStore`]: raw submissions, write-once and addressed by their
//! SHA-256, one file each, plus an `index` of the order and time they arrived. Because the
//! store keeps every submission, the intake gate's state (what has landed, so what is a
//! duplicate, INT-013) can be rebuilt after a restart by running the stored submissions
//! through the gate again ([`FileSubmissionStore::stored`]).
//!
//! Development only: no encryption at rest beyond the submissions' own sealing.

use std::io::Write as _;
use std::path::PathBuf;

use fieldseal_intake::domain::SubmissionId;
use fieldseal_intake::ports::{SubmissionStore, SubmissionStoreError};
use fieldseal_kernel::digest::{lower_hex, sha256};
use std::sync::Mutex;

/// The store in a directory.
pub struct FileSubmissionStore {
    dir: PathBuf,
    now: Box<dyn Fn() -> u64 + Send + Sync>,
    lock: Mutex<()>,
}

fn backend(e: impl std::fmt::Display) -> SubmissionStoreError {
    SubmissionStoreError::Backend(e.to_string())
}

impl FileSubmissionStore {
    /// A store in `dir` (created if absent); `now` gives the arrival time in milliseconds.
    pub fn open(dir: impl Into<PathBuf>, now: impl Fn() -> u64 + Send + Sync + 'static) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, now: Box::new(now), lock: Mutex::new(()) })
    }

    fn path(&self, id: &SubmissionId) -> PathBuf {
        self.dir.join(format!("{}.submission", lower_hex(id.0.as_bytes())))
    }

    /// Every stored submission with the time it arrived, in the order it arrived.
    pub fn stored(&self) -> Vec<(u64, Vec<u8>)> {
        let Ok(index) = std::fs::read_to_string(self.dir.join("index")) else { return Vec::new() };
        index
            .lines()
            .filter_map(|l| {
                let (hex, ms) = l.split_once(' ')?;
                let bytes = std::fs::read(self.dir.join(format!("{hex}.submission"))).ok()?;
                Some((ms.parse().ok()?, bytes))
            })
            .collect()
    }
}

impl SubmissionStore for FileSubmissionStore {
    fn put(&self, bytes: &[u8]) -> Result<SubmissionId, SubmissionStoreError> {
        let id = SubmissionId(sha256(bytes));
        let _guard = self.lock.lock().expect("lock");
        let path = self.path(&id);
        if !path.exists() {
            let tmp = self.dir.join(format!("{}.tmp", lower_hex(id.0.as_bytes())));
            std::fs::write(&tmp, bytes).map_err(backend)?;
            std::fs::rename(&tmp, &path).map_err(backend)?;
            let mut index = std::fs::OpenOptions::new().create(true).append(true).open(self.dir.join("index")).map_err(backend)?;
            writeln!(index, "{} {}", lower_hex(id.0.as_bytes()), (self.now)()).map_err(backend)?;
        }
        Ok(id)
    }

    fn get(&self, id: &SubmissionId) -> Result<Option<Vec<u8>>, SubmissionStoreError> {
        match std::fs::read(self.path(id)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(backend(e)),
        }
    }
}
