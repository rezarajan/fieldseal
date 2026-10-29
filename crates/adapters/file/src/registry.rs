//! An immutable, file-backed artefact registry: one `*.publication` file per publication and a
//! `withdrawals/` directory, in the layout `artefact publish` writes under `<state>/registry`
//! when `FIELDSEAL_ADAPTERS=files`. The factory reads this directory, not the `*.published`
//! copies that intake reads.
//!
//! **Development adapter.**

use std::path::PathBuf;

use fieldseal_kernel::digest::{lower_hex, sha256};
use fieldseal_kernel::id::ContentAddress;
use fieldseal_publishing::domain::{ArtefactKind, Publication, Withdrawal};
use fieldseal_publishing::ports::{ArtefactRegistry, RegistryError};

use crate::atomic::write_atomic;

/// An immutable, file-backed artefact registry.
pub struct FileRegistry {
    dir: PathBuf,
}

fn backend(e: impl std::fmt::Display) -> RegistryError {
    RegistryError::Backend(e.to_string())
}

/// The files in `dir` with the extension `ext`, in name order. A missing directory holds
/// none; any other failure to list it is an error, so a permission problem is not read as an
/// empty registry. A temporary file of an atomic write in progress is not one.
fn files_with_extension(dir: &std::path::Path, ext: &str) -> Result<Vec<PathBuf>, RegistryError> {
    let mut paths: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .map(|e| e.map(|e| e.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(backend)?
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == ext))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(backend(e)),
    };
    paths.sort();
    Ok(paths)
}

impl FileRegistry {
    /// The registry in `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn all(&self) -> Result<Vec<Publication>, RegistryError> {
        let paths = files_with_extension(&self.dir, "publication")?;
        paths
            .iter()
            .map(|p| Publication::decode(&std::fs::read(p).map_err(backend)?).map_err(backend))
            .collect()
    }
}

impl ArtefactRegistry for FileRegistry {
    fn put(&self, publication: &Publication) -> Result<(), RegistryError> {
        let all = self.all()?;
        if let Some(existing) = all.iter().find(|p| p.address() == publication.address()) {
            return if existing == publication {
                Ok(())
            } else {
                Err(RegistryError::Conflict)
            };
        }
        let a = &publication.artefact;
        if all.iter().any(|p| {
            p.artefact.kind() == a.kind()
                && p.artefact.name() == a.name()
                && p.artefact.version() == a.version()
        }) {
            return Err(RegistryError::VersionTaken);
        }
        std::fs::create_dir_all(&self.dir).map_err(backend)?;
        write_atomic(
            &self.dir.join(format!(
                "{}.publication",
                lower_hex(publication.address().as_bytes())
            )),
            &publication.encode(),
        )
        .map_err(backend)
    }

    fn get(&self, address: &ContentAddress) -> Result<Option<Publication>, RegistryError> {
        Ok(self.all()?.into_iter().find(|p| p.address() == address))
    }

    fn list(
        &self,
        kind: ArtefactKind,
        name: &str,
    ) -> Result<Vec<(String, ContentAddress)>, RegistryError> {
        Ok(self
            .all()?
            .iter()
            .filter(|p| p.artefact.kind() == kind && p.artefact.name() == name)
            .map(|p| (p.artefact.version().to_owned(), *p.address()))
            .collect())
    }

    fn withdraw(&self, withdrawal: &Withdrawal) -> Result<(), RegistryError> {
        if self.withdrawals()?.contains(withdrawal) {
            return Ok(());
        }
        let dir = self.dir.join("withdrawals");
        std::fs::create_dir_all(&dir).map_err(backend)?;
        // Named by content, so the same withdrawal always lands in the same file and two
        // writers cannot collide on a count. Files from older versions are named by count and
        // are still read.
        let bytes = withdrawal.encode();
        write_atomic(
            &dir.join(format!(
                "{}.withdrawal",
                lower_hex(sha256(&bytes).as_bytes())
            )),
            &bytes,
        )
        .map_err(backend)
    }

    fn withdrawals(&self) -> Result<Vec<Withdrawal>, RegistryError> {
        let paths = files_with_extension(&self.dir.join("withdrawals"), "withdrawal")?;
        paths
            .iter()
            .map(|p| Withdrawal::decode(&std::fs::read(p).map_err(backend)?).map_err(backend))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::files_with_extension;
    use fieldseal_publishing::ports::RegistryError;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fieldseal-registry-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    // covers: PUB-062
    #[test]
    fn a_missing_directory_holds_no_files() {
        let dir = scratch("missing");
        assert_eq!(
            files_with_extension(&dir.join("absent"), "publication"),
            Ok(Vec::new())
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    // covers: PUB-062
    #[test]
    fn a_directory_that_cannot_be_listed_is_a_backend_error() {
        let dir = scratch("unlistable");
        // A file where a directory is expected fails with something other than NotFound.
        let file = dir.join("f");
        std::fs::write(&file, b"x").expect("file");
        assert!(matches!(
            files_with_extension(&file, "publication"),
            Err(RegistryError::Backend(_))
        ));
        let _ = std::fs::remove_dir_all(dir);
    }
}
