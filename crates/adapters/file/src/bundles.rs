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

use crate::atomic::write_atomic;

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
}
