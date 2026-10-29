//! Atomic file writes: a reader sees the old file or the new one, never a torn file.

use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Writes `bytes` to a temporary file in the directory of `path`, syncs it, renames it over
/// `path` and syncs the directory. A failed write leaves `path` as it was and removes the
/// temporary file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_with(path, bytes, None, false)
}

/// As [`write_atomic`], but the temporary file is created with permission bits `mode` on
/// Unix, so it is never wider than the file it becomes. Elsewhere `mode` is ignored.
pub fn write_atomic_mode(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    write_with(path, bytes, Some(mode), false)
}

/// As [`write_atomic_mode`], but never replaces: if `path` exists the write fails with
/// [`std::io::ErrorKind::AlreadyExists`] and `path` is untouched. The file appears whole or
/// not at all, and of two writers racing for one name exactly one succeeds.
pub fn write_new_atomic_mode(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    write_with(path, bytes, Some(mode), true)
}

fn write_with(
    path: &Path,
    bytes: &[u8],
    mode: Option<u32>,
    no_clobber: bool,
) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = path.file_name().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?;
    let tmp = dir.join(format!(".{}.{}-{}.tmp", name.to_string_lossy(), std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    let written = (|| {
        let mut f = create_tmp(&tmp, mode)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        if no_clobber {
            // A hard link fails if the name exists, unlike a rename.
            std::fs::hard_link(&tmp, path)?;
            std::fs::remove_file(&tmp)
        } else {
            std::fs::rename(&tmp, path)
        }
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // Opening a directory to sync it is a Unix feature; elsewhere the rename stands alone.
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn create_tmp(tmp: &Path, mode: Option<u32>) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    if let Some(mode) = mode {
        options.mode(mode);
    }
    options.open(tmp)
}

#[cfg(not(unix))]
fn create_tmp(tmp: &Path, _mode: Option<u32>) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)
}

#[cfg(test)]
mod tests {
    use super::{write_atomic, write_atomic_mode, write_new_atomic_mode};

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fieldseal-atomic-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    fn entries(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir).expect("dir").map(|e| e.expect("entry").file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    // covers: INT-085
    #[test]
    fn the_new_bytes_replace_the_old() {
        let dir = scratch("replace");
        let path = dir.join("f");
        write_atomic(&path, b"old").expect("first");
        write_atomic(&path, b"new bytes").expect("second");
        assert_eq!(std::fs::read(&path).expect("read"), b"new bytes");
        let _ = std::fs::remove_dir_all(dir);
    }

    // covers: INT-085
    #[test]
    fn a_failed_write_leaves_the_old_file_in_place() {
        let dir = scratch("failed");
        let path = dir.join("f");
        write_atomic(&path, b"old").expect("first");
        // A rename cannot replace a directory, so naming one as the target makes the write fail.
        let target = dir.join("d");
        std::fs::create_dir(&target).expect("dir");
        assert!(write_atomic(&target, b"new").is_err());
        assert!(target.is_dir());
        assert_eq!(std::fs::read(&path).expect("read"), b"old");
        let _ = std::fs::remove_dir_all(dir);
    }

    // covers: INT-085
    #[test]
    fn no_temporary_file_remains() {
        let dir = scratch("tmp");
        let path = dir.join("f");
        write_atomic(&path, b"one").expect("write");
        assert_eq!(entries(&dir), vec!["f".to_owned()]);
        let target = dir.join("d");
        std::fs::create_dir(&target).expect("dir");
        assert!(write_atomic(&target, b"two").is_err());
        assert_eq!(entries(&dir), vec!["d".to_owned(), "f".to_owned()], "a failed write cleans up after itself");
        let _ = std::fs::remove_dir_all(dir);
    }

    // covers: INT-085
    #[cfg(unix)]
    #[test]
    fn the_mode_applies_to_the_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch("mode");
        let path = dir.join("f");
        write_atomic_mode(&path, b"secret", 0o600).expect("write");
        assert_eq!(
            std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    // covers: INT-085
    #[test]
    fn a_new_write_never_replaces() {
        let dir = scratch("new");
        let path = dir.join("f");
        write_new_atomic_mode(&path, b"first", 0o600).expect("first");
        let err = write_new_atomic_mode(&path, b"second", 0o600).expect_err("second");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).expect("read"), b"first");
        assert_eq!(
            entries(&dir),
            vec!["f".to_owned()],
            "the loser leaves no temporary file"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
