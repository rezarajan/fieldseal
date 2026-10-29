//! An immutable, file-backed artefact registry: one `*.publication` file per publication and a
//! `withdrawals/` directory, in the layout `artefact publish` writes under `<state>/registry`
//! when `FIELDSEAL_ADAPTERS=files`. The factory reads this directory, not the `*.published`
//! copies that intake reads.
//!
//! **Development adapter.**

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fieldseal_kernel::digest::{lower_hex, sha256};
use fieldseal_kernel::id::ContentAddress;
use fieldseal_publishing::domain::publication::MAX_PUBLICATION;
use fieldseal_publishing::domain::{ArtefactKind, Publication, Withdrawal};
use fieldseal_publishing::ports::{ArtefactRegistry, RegistryError};

use crate::atomic::write_atomic;

/// An immutable, file-backed artefact registry.
pub struct FileRegistry {
    dir: PathBuf,
    skipped: Mutex<Vec<PathBuf>>,
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

/// Reads the regular file at `path`, at most `max` bytes. A symlink, a FIFO, a device or a
/// directory is refused without being opened (opening a FIFO would wait for a writer), the
/// opened handle is checked again in case the name was swapped in between, and a file over
/// `max` is refused before it is read.
fn read_regular(path: &Path, max: usize) -> std::io::Result<Vec<u8>> {
    let refuse = |why| std::io::Error::new(std::io::ErrorKind::InvalidData, why);
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(refuse("not a regular file"));
    }
    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(refuse("not a regular file"));
    }
    if meta.len() > max as u64 {
        return Err(refuse("file too large"));
    }
    // The length can grow after the check, so the read is capped too.
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(refuse("file too large"));
    }
    Ok(bytes)
}

impl FileRegistry {
    /// The registry in `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into(), skipped: Mutex::new(Vec::new()) }
    }

    /// The publication files the last read skipped because they were not regular files, were
    /// too large or did not decode. Paths only; nothing from inside a file.
    pub fn skipped(&self) -> Vec<PathBuf> {
        self.skipped.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Every publication that reads back. A bad file is skipped and listed in
    /// [`skipped`](Self::skipped), so one bad file cannot stop the rest being served.
    fn all(&self) -> Result<Vec<Publication>, RegistryError> {
        let mut out = Vec::new();
        let mut skipped = Vec::new();
        for p in files_with_extension(&self.dir, "publication")? {
            match read_regular(&p, MAX_PUBLICATION).ok().and_then(|b| Publication::decode(&b).ok()) {
                Some(publication) => out.push(publication),
                None => skipped.push(p),
            }
        }
        if let Ok(mut s) = self.skipped.lock() {
            *s = skipped;
        }
        Ok(out)
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
            // Unlike a publication, a withdrawal that cannot be read is an error: skipping it
            // would put a withdrawn artefact back in service.
            .map(|p| Withdrawal::decode(&read_regular(p, MAX_PUBLICATION).map_err(backend)?).map_err(backend))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{FileRegistry, files_with_extension};
    use fieldseal_publishing::ports::ArtefactRegistry as _;
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

    // covers: PUB-062
    #[test]
    fn a_garbage_publication_is_skipped_and_reported() {
        let dir = scratch("garbage");
        std::fs::write(dir.join("bad.publication"), b"not cbor").expect("file");
        let registry = FileRegistry::new(&dir);
        assert_eq!(registry.list(fieldseal_publishing::domain::ArtefactKind::Instrument, "x"), Ok(Vec::new()));
        assert_eq!(registry.skipped(), vec![dir.join("bad.publication")]);
        let _ = std::fs::remove_dir_all(dir);
    }

    // covers: PUB-062
    #[test]
    fn an_oversize_publication_is_skipped_unread() {
        let dir = scratch("oversize");
        // Sparse: the file claims one byte over the limit and holds nothing.
        let f = std::fs::File::create(dir.join("big.publication")).expect("file");
        f.set_len(super::MAX_PUBLICATION as u64 + 1).expect("length");
        let registry = FileRegistry::new(&dir);
        assert_eq!(registry.list(fieldseal_publishing::domain::ArtefactKind::Instrument, "x"), Ok(Vec::new()));
        assert_eq!(registry.skipped(), vec![dir.join("big.publication")]);
        assert!(super::read_regular(&dir.join("big.publication"), super::MAX_PUBLICATION).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    // covers: PUB-062
    #[cfg(unix)]
    #[test]
    fn a_fifo_is_skipped_without_waiting_for_a_writer() {
        let dir = scratch("fifo");
        let fifo = dir.join("pipe.publication");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status().expect("mkfifo runs");
        assert!(made.success());
        let registry = FileRegistry::new(&dir);
        assert_eq!(registry.list(fieldseal_publishing::domain::ArtefactKind::Instrument, "x"), Ok(Vec::new()));
        assert_eq!(registry.skipped(), vec![fifo]);
        let _ = std::fs::remove_dir_all(dir);
    }

    // covers: PUB-062
    #[cfg(unix)]
    #[test]
    fn a_symlink_is_skipped_even_to_a_readable_file() {
        let dir = scratch("symlink");
        std::fs::write(dir.join("target"), b"x").expect("file");
        let link = dir.join("link.publication");
        std::os::unix::fs::symlink(dir.join("target"), &link).expect("symlink");
        let registry = FileRegistry::new(&dir);
        assert_eq!(registry.list(fieldseal_publishing::domain::ArtefactKind::Instrument, "x"), Ok(Vec::new()));
        assert_eq!(registry.skipped(), vec![link]);
        let _ = std::fs::remove_dir_all(dir);
    }
}
