//! A file-backed store of the rosters the authority issues, and the [`RosterSource`] over it.
//!
//! ```text
//! <dir>/<cohort>/v<version>.roster   the roster in canonical closed form (DIS-063)
//! <dir>/<cohort>/v<version>.sha256   SHA-256 of that file, in lower-case hex
//! ```
//!
//! A roster holds display names and consent, so the directories are `0700` and the files
//! `0600` on Unix. A version, once issued, never changes (DIS-080). The factory writes the
//! store from `IssueRoster`; no command line tool does.
//!
//! **Development adapter.**

use std::path::{Path, PathBuf};

use fieldseal_distribution::domain::Roster;
use fieldseal_distribution::ports::{RosterSource, RosterSourceError};
use fieldseal_kernel::cbor;
use fieldseal_kernel::digest::{lower_hex, sha256};
use fieldseal_kernel::id::{CohortId, TenancyId};
use fieldseal_registration::ports::RegistryStore;

use crate::atomic::{write_atomic_mode, write_new_atomic_mode};
use crate::store::FileRegistryStore;

/// The permission bits of a roster file and its checksum.
const FILE_MODE: u32 = 0o600;

/// The largest roster file read back.
const MAX_ROSTER_FILE: usize = 16 * 1024 * 1024;

/// What [`RosterStore::issue`] did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IssueOutcome {
    /// The roster was stored.
    Stored,
    /// The same content was already stored at this version; nothing changed.
    Unchanged,
}

/// Why a roster store call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RosterStoreError {
    /// A different roster is already stored at this version (DIS-080).
    #[error("cohort {cohort} already has a different roster at version {version}")]
    VersionTaken {
        /// The cohort.
        cohort: String,
        /// The version.
        version: u64,
    },
    /// The version is lower than the latest stored.
    #[error("version {offered} is not newer than {held}")]
    NotNewer {
        /// The latest version stored.
        held: u64,
        /// The version offered.
        offered: u64,
    },
    /// The cohort name can't be a directory name here.
    #[error("cohort name {0:?} can't be stored")]
    Cohort(String),
    /// The store failed, or holds a file that does not read back.
    #[error("roster store: {0}")]
    Backend(String),
}

fn backend(e: impl std::fmt::Display) -> RosterStoreError {
    RosterStoreError::Backend(e.to_string())
}

/// Rosters kept in a directory, one subdirectory per cohort.
pub struct RosterStore {
    dir: PathBuf,
}

/// Whether `name` can be a directory name: letters, digits, `-`, `_` and inner dots.
fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[cfg(unix)]
fn private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

#[cfg(not(unix))]
fn private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

/// Refuses a directory that group or others can reach. A roster holds display names and
/// consent, and silently narrowing a directory someone else set up could break what they
/// rely on (a shared mount, a backup job), so the store reports it and leaves the choice to
/// the operator.
#[cfg(unix)]
fn require_private(path: &Path) -> Result<(), RosterStoreError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path)
        .map_err(backend)?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(backend(format!(
            "{} has mode {mode:03o}; rosters need 700 or narrower",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private(_path: &Path) -> Result<(), RosterStoreError> {
    Ok(())
}

impl RosterStore {
    /// Opens (creating if needed) the store in `dir`.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, RosterStoreError> {
        let dir = dir.into();
        private_dir(&dir).map_err(backend)?;
        require_private(&dir)?;
        Ok(Self { dir })
    }

    fn cohort_dir(&self, cohort: &CohortId) -> Result<PathBuf, RosterStoreError> {
        safe_name(cohort.as_str())
            .then(|| self.dir.join(cohort.as_str()))
            .ok_or_else(|| RosterStoreError::Cohort(cohort.as_str().to_owned()))
    }

    /// The versions stored for a cohort, lowest first.
    pub fn versions(&self, cohort: &CohortId) -> Result<Vec<u64>, RosterStoreError> {
        let dir = self.cohort_dir(cohort)?;
        let mut out: Vec<u64> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd
                .filter_map(Result::ok)
                .filter_map(|e| {
                    e.file_name()
                        .to_str()?
                        .strip_prefix('v')?
                        .strip_suffix(".sha256")?
                        .parse()
                        .ok()
                })
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(backend(e)),
        };
        out.sort_unstable();
        Ok(out)
    }

    /// Stores `roster` at its version. The same content at the same version is `Unchanged`;
    /// different content is `VersionTaken`; a version lower than the latest is `NotNewer`.
    pub fn issue(&self, roster: &Roster) -> Result<IssueOutcome, RosterStoreError> {
        let dir = self.cohort_dir(&roster.cohort)?;
        let versions = self.versions(&roster.cohort)?;
        let bytes = roster.encode();
        if versions.contains(&roster.version) {
            let held =
                std::fs::read(dir.join(format!("v{}.roster", roster.version))).map_err(backend)?;
            return if held == bytes {
                Ok(IssueOutcome::Unchanged)
            } else {
                Err(RosterStoreError::VersionTaken {
                    cohort: roster.cohort.as_str().to_owned(),
                    version: roster.version,
                })
            };
        }
        if let Some(latest) = versions.last().filter(|v| **v > roster.version) {
            return Err(RosterStoreError::NotNewer {
                held: *latest,
                offered: roster.version,
            });
        }
        private_dir(&dir).map_err(backend)?;
        require_private(&dir)?;
        // The roster is published with no-clobber semantics, so of two writers racing for one
        // version exactly one stores it and the other sees what the first wrote.
        let roster_path = dir.join(format!("v{}.roster", roster.version));
        match write_new_atomic_mode(&roster_path, &bytes, FILE_MODE) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let held = std::fs::read(&roster_path).map_err(backend)?;
                if held != bytes {
                    return Err(RosterStoreError::VersionTaken {
                        cohort: roster.cohort.as_str().to_owned(),
                        version: roster.version,
                    });
                }
                // The same bytes: either a finished issue (nothing to do) or one that was
                // interrupted before its checksum, which this call completes.
                if dir.join(format!("v{}.sha256", roster.version)).exists() {
                    return Ok(IssueOutcome::Unchanged);
                }
            }
            Err(e) => return Err(backend(e)),
        }
        // The checksum is written last: a roster without one was interrupted and is not stored.
        let sum = format!("{}\n", lower_hex(sha256(&bytes).as_bytes()));
        write_atomic_mode(
            &dir.join(format!("v{}.sha256", roster.version)),
            sum.as_bytes(),
            FILE_MODE,
        )
        .map_err(backend)?;
        Ok(IssueOutcome::Stored)
    }

    /// The roster of `cohort` at `version`, checked against its checksum.
    pub fn get(&self, cohort: &CohortId, version: u64) -> Result<Option<Roster>, RosterStoreError> {
        if !self.versions(cohort)?.contains(&version) {
            return Ok(None);
        }
        let dir = self.cohort_dir(cohort)?;
        let bytes = std::fs::read(dir.join(format!("v{version}.roster"))).map_err(backend)?;
        let sum =
            std::fs::read_to_string(dir.join(format!("v{version}.sha256"))).map_err(backend)?;
        if sum.trim() != lower_hex(sha256(&bytes).as_bytes()) {
            return Err(backend(format!(
                "{} v{version} does not match its checksum",
                cohort.as_str()
            )));
        }
        let roster = cbor::decode_limited(&bytes, MAX_ROSTER_FILE)
            .and_then(Roster::from_value)
            .map_err(backend)?;
        if roster.cohort != *cohort || roster.version != version {
            return Err(backend(format!(
                "{} v{version} holds another cohort or version",
                cohort.as_str()
            )));
        }
        Ok(Some(roster))
    }

    /// The highest version stored for `cohort`.
    pub fn latest(&self, cohort: &CohortId) -> Result<Option<Roster>, RosterStoreError> {
        match self.versions(cohort)?.last() {
            Some(v) => self.get(cohort, *v),
            None => Ok(None),
        }
    }

    /// Every cohort with at least one roster, in name order.
    pub fn cohorts(&self) -> Result<Vec<CohortId>, RosterStoreError> {
        let mut out: Vec<CohortId> = std::fs::read_dir(&self.dir)
            .map_err(backend)?
            .filter_map(Result::ok)
            .filter(|e| e.path().is_dir())
            .filter_map(|e| CohortId::new(e.file_name().to_str()?).ok())
            .filter(|c| self.versions(c).is_ok_and(|v| !v.is_empty()))
            .collect();
        out.sort();
        Ok(out)
    }
}

/// A [`RosterSource`] over a [`RosterStore`] and the tenancy registry journal: the latest
/// roster of each cohort a tenancy is assigned, at the tenancy's generation (DIS-014).
pub struct FileRosterSource {
    store: RosterStore,
    tenancy_registry_dir: PathBuf,
}

impl FileRosterSource {
    /// Rosters from `store`, assignments from the tenancy registry journal in
    /// `tenancy_registry_dir`.
    pub fn new(store: RosterStore, tenancy_registry_dir: impl Into<PathBuf>) -> Self {
        Self {
            store,
            tenancy_registry_dir: tenancy_registry_dir.into(),
        }
    }

    /// The roster store this source reads.
    pub fn store(&self) -> &RosterStore {
        &self.store
    }
}

fn unavailable(e: impl std::fmt::Display) -> RosterSourceError {
    RosterSourceError::Unavailable(e.to_string())
}

impl RosterSource for FileRosterSource {
    fn current_rosters(&self, tenancy: &TenancyId) -> Result<Vec<Roster>, RosterSourceError> {
        let registry =
            FileRegistryStore::snapshot(&self.tenancy_registry_dir).map_err(unavailable)?;
        let record = registry
            .tenancy(tenancy)
            .map_err(unavailable)?
            .ok_or(RosterSourceError::UnknownTenancy)?;
        let mut out = Vec::new();
        for assignment in &record.cohorts {
            if let Some(mut roster) = self.store.latest(&assignment.cohort).map_err(unavailable)? {
                roster.generation = assignment.generation;
                out.push(roster);
            }
        }
        Ok(out)
    }

    fn active_tenancies(
        &self,
        cohort: &CohortId,
        except: &TenancyId,
    ) -> Result<u64, RosterSourceError> {
        let registry =
            FileRegistryStore::snapshot(&self.tenancy_registry_dir).map_err(unavailable)?;
        let count = registry
            .all_tenancies()
            .iter()
            .filter(|t| {
                t.id != *except
                    && t.state.is_active()
                    && t.cohorts.iter().any(|c| &c.cohort == cohort)
            })
            .count();
        Ok(count as u64)
    }
}
