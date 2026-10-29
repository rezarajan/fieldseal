//! Atomic file writes: a reader sees the old file or the new one, never a torn file.

use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Writes `bytes` to a temporary file in the directory of `path`, syncs it, renames it over
/// `path` and syncs the directory. A failed write leaves `path` as it was and removes the
/// temporary file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = path.file_name().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?;
    let tmp = dir.join(format!(".{}.{}-{}.tmp", name.to_string_lossy(), std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    let written = (|| {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
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

#[cfg(test)]
mod tests {
    use super::write_atomic;

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
}
