//! A file-backed [`BundleStore`] for the factory: one directory per tenancy (its hex ID), a
//! bundle file named `fieldseal-bundle-<date>-<sequence>.fsb` (DIS-023) and, beside it, a
//! `.meta` file holding the content address and issue time, which the neutral file name does
//! not carry. The `.meta` file is written last, so a bundle without one was interrupted and is
//! not yet stored.
//!
//! **Development adapter.**

use std::path::{Path, PathBuf};

use fieldseal_distribution::domain::{BundleSeq, SealedBundle, file_name};
use fieldseal_distribution::ports::{BundleStore, BundleStoreError};
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::id::{ContentAddress, TenancyId};
use fieldseal_kernel::time::AuthorityTime;

use crate::atomic::{write_atomic, write_atomic_mode};

/// The marker file of a withheld tenancy, beside its bundles. One reason per line.
const WITHHELD: &str = "withheld";
/// The most a marker may hold; a larger one is garbled.
const WITHHELD_MAX: u64 = 64 * 1024;
/// Read as the reason when the marker can't be read: withheld, failing closed.
const WITHHELD_UNREADABLE: &str = "withheld-unreadable";

/// Bundles kept in a directory, one subdirectory per tenancy.
pub struct FileBundleStore {
    dir: PathBuf,
}

fn backend(e: impl std::fmt::Display) -> BundleStoreError {
    BundleStoreError::Backend(e.to_string())
}

impl FileBundleStore {
    /// The store in `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn tenancy_dir(&self, tenancy: &TenancyId) -> PathBuf {
        self.dir.join(lower_hex(tenancy.as_bytes()))
    }
}

/// The sequence number a bundle file name carries, if it is one.
fn sequence_of(name: &str) -> Option<u64> {
    name.strip_prefix("fieldseal-bundle-")?
        .strip_suffix(".fsb")?
        .split_once('-')?
        .1
        .parse()
        .ok()
}

/// The stored bundles of a tenancy directory, as `(sequence, file path)`, lowest first. Only
/// bundles whose `.meta` file exists count.
fn stored(dir: &Path) -> Vec<(u64, PathBuf)> {
    let mut out: Vec<(u64, PathBuf)> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| Some((sequence_of(e.file_name().to_str()?)?, e.path())))
                .filter(|(_, p)| p.with_extension("meta").is_file())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

fn meta_text(bundle: &SealedBundle) -> String {
    format!(
        "address {}\nissued {}\n",
        lower_hex(bundle.address.as_bytes()),
        bundle.issued.0
    )
}

fn read_bundle(
    tenancy: &TenancyId,
    seq: u64,
    path: &Path,
) -> Result<SealedBundle, BundleStoreError> {
    let bytes = std::fs::read(path).map_err(backend)?;
    let meta = std::fs::read_to_string(path.with_extension("meta")).map_err(backend)?;
    let malformed = || backend(format!("malformed bundle metadata for sequence {seq}"));
    let mut lines = meta.lines();
    let address = lines
        .next()
        .and_then(|l| l.strip_prefix("address "))
        .ok_or_else(malformed)?;
    let issued = lines
        .next()
        .and_then(|l| l.strip_prefix("issued "))
        .and_then(|t| t.parse().ok())
        .ok_or_else(malformed)?;
    let raw: Vec<u8> = (0..address.len() / 2)
        .map(|i| {
            address
                .get(2 * i..2 * i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
        .collect::<Option<_>>()
        .ok_or_else(malformed)?;
    let address = ContentAddress::from_bytes(&raw).map_err(|_| malformed())?;
    Ok(SealedBundle {
        address,
        tenancy: *tenancy,
        seq: BundleSeq(seq),
        issued: AuthorityTime(issued),
        bytes,
    })
}

impl BundleStore for FileBundleStore {
    fn put(&self, bundle: &SealedBundle) -> Result<(), BundleStoreError> {
        let dir = self.tenancy_dir(&bundle.tenancy);
        if let Some((held, _)) = stored(&dir).last()
            && *held >= bundle.seq.0
        {
            return Err(BundleStoreError::NotNewer {
                held: BundleSeq(*held),
                offered: bundle.seq,
            });
        }
        std::fs::create_dir_all(&dir).map_err(backend)?;
        let path = dir.join(file_name(bundle.issued.0, bundle.seq.0));
        write_atomic(&path, &bundle.bytes).map_err(backend)?;
        write_atomic(&path.with_extension("meta"), meta_text(bundle).as_bytes()).map_err(backend)
    }

    fn latest(&self, tenancy: &TenancyId) -> Result<Option<SealedBundle>, BundleStoreError> {
        match stored(&self.tenancy_dir(tenancy)).pop() {
            Some((seq, path)) => read_bundle(tenancy, seq, &path).map(Some),
            None => Ok(None),
        }
    }

    fn withheld(&self, tenancy: &TenancyId) -> Result<Option<Vec<String>>, BundleStoreError> {
        use std::io::Read as _;
        let path = self.tenancy_dir(tenancy).join(WITHHELD);
        let unreadable = || Ok(Some(vec![WITHHELD_UNREADABLE.to_owned()]));
        // Neither a symlink nor anything but a regular file is a marker we wrote.
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return unreadable(),
            Ok(m) if !m.is_file() || m.len() > WITHHELD_MAX => return unreadable(),
            Ok(_) => {}
        }
        let mut text = String::new();
        let read = std::fs::File::open(&path).and_then(|f| f.take(WITHHELD_MAX + 1).read_to_string(&mut text));
        let reasons: Vec<String> = text.lines().filter(|l| !l.is_empty()).map(str::to_owned).collect();
        if read.is_err() || text.len() as u64 > WITHHELD_MAX || reasons.is_empty() {
            return unreadable();
        }
        Ok(Some(reasons))
    }

    fn set_withheld(&self, tenancy: &TenancyId, reasons: Option<&[String]>) -> Result<(), BundleStoreError> {
        let dir = self.tenancy_dir(tenancy);
        let path = dir.join(WITHHELD);
        match reasons {
            Some(reasons) => {
                // A reason is one line; an empty list would read back as garbled.
                let clean: Vec<String> = reasons.iter().map(|r| r.replace(['\n', '\r'], " ")).filter(|r| !r.is_empty()).collect();
                let clean = if clean.is_empty() { vec![WITHHELD.to_owned()] } else { clean };
                std::fs::create_dir_all(&dir).map_err(backend)?;
                write_atomic_mode(&path, (clean.join("\n") + "\n").as_bytes(), 0o600).map_err(backend)
            }
            None => match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(backend(e)),
                _ => Ok(()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (FileBundleStore, PathBuf) {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("fieldseal-bundles-{}-{}", std::process::id(), NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        let _ = std::fs::remove_dir_all(&dir);
        (FileBundleStore::new(&dir), dir)
    }

    fn unreadable() -> Result<Option<Vec<String>>, BundleStoreError> {
        Ok(Some(vec!["withheld-unreadable".to_owned()]))
    }

    #[test]
    fn dis_003_a_garbled_or_oversized_or_non_file_withheld_marker_reads_as_withheld() {
        let (store, dir) = store();
        let t = TenancyId::from([3; 32]);
        let marker = store.tenancy_dir(&t).join("withheld");
        std::fs::create_dir_all(store.tenancy_dir(&t)).expect("dir");
        std::fs::write(&marker, b"").expect("empty");
        assert_eq!(store.withheld(&t), unreadable(), "empty");
        std::fs::write(&marker, [0xff, 0xfe, 0x00]).expect("garbled");
        assert_eq!(store.withheld(&t), unreadable(), "not UTF-8");
        std::fs::write(&marker, vec![b'a'; 70_000]).expect("big");
        assert_eq!(store.withheld(&t), unreadable(), "too large");
        std::fs::remove_file(&marker).expect("rm");
        std::fs::create_dir(&marker).expect("dir marker");
        assert_eq!(store.withheld(&t), unreadable(), "a directory");
        std::fs::remove_dir(&marker).expect("rm");
        assert_eq!(store.withheld(&t), Ok(None));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn dis_003_the_withheld_marker_is_owner_only_and_a_symlink_is_not_followed() {
        use std::os::unix::fs::PermissionsExt as _;
        let (store, dir) = store();
        let t = TenancyId::from([4; 32]);
        store.set_withheld(&t, Some(&["policy-hold".to_owned()])).expect("set");
        let marker = store.tenancy_dir(&t).join("withheld");
        assert_eq!(std::fs::metadata(&marker).expect("meta").permissions().mode() & 0o777, 0o600);
        std::fs::remove_file(&marker).expect("rm");
        let target = dir.join("elsewhere");
        std::fs::write(&target, b"policy-hold\n").expect("target");
        std::os::unix::fs::symlink(&target, &marker).expect("link");
        assert_eq!(store.withheld(&t), unreadable());
        store.set_withheld(&t, None).expect("clear removes the link, not the target");
        assert!(target.exists());
        assert_eq!(store.withheld(&t), Ok(None));
        let _ = std::fs::remove_dir_all(dir);
    }
}
