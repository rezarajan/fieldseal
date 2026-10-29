//! The subject column of the results export: a keyed hash of the subject, so the files hold no
//! roster identifier (INT-087). The key is the export pseudonymisation key.

use std::io::Read as _;
use std::path::Path;

use fieldseal_kernel::digest::{lower_hex, sha256_parts};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use zeroize::Zeroizing;

/// The file in the key directory.
pub const KEY_FILE: &str = "export.key";

/// The bytes of an export key.
const KEY_LEN: usize = 32;

/// Why an export key was refused. Nothing creates a key; the authority's set-up step does.
#[derive(Debug, thiserror::Error)]
pub enum ExportKeyError {
    /// There is no key file.
    #[error("{0}: the export key file is missing; the authority's set-up step creates it")]
    Absent(String),
    /// The file cannot be read.
    #[error("{0}: {1}")]
    Unreadable(String, String),
    /// The file is not 32 bytes.
    #[error("{0}: the export key must be exactly 32 bytes")]
    Length(String),
    /// The file can be read by others than its owner.
    #[error("{0}: the export key file must have mode 0600")]
    Mode(String),
}

/// The 32-byte export pseudonymisation key.
#[derive(Clone)]
pub struct ExportKey(Zeroizing<[u8; KEY_LEN]>);

impl ExportKey {
    /// Reads `<dir>/export.key` (the file store, a development adapter). Never writes it.
    pub fn load(dir: &Path) -> Result<Self, ExportKeyError> {
        Self::load_file(&dir.join(KEY_FILE))
    }

    /// Reads one key file: exactly 32 raw bytes, and on Unix a mode no wider than 0600. Never
    /// writes it.
    pub fn load_file(path: &Path) -> Result<Self, ExportKeyError> {
        let name = path.display().to_string();
        let mut file = std::fs::File::open(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => ExportKeyError::Absent(name.clone()),
            _ => ExportKeyError::Unreadable(name.clone(), e.to_string()),
        })?;
        let meta = file.metadata().map_err(|e| ExportKeyError::Unreadable(name.clone(), e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if meta.permissions().mode() & 0o177 != 0 {
                return Err(ExportKeyError::Mode(name));
            }
        }
        if meta.len() != KEY_LEN as u64 {
            return Err(ExportKeyError::Length(name));
        }
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        file.read_exact(&mut *bytes).map_err(|e| ExportKeyError::Unreadable(name.clone(), e.to_string()))?;
        Ok(Self(bytes))
    }

    /// A key from its bytes, for tests and for the authority's set-up step.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// The key's identifier: the first 32 hex digits of `lower_hex(SHA-256("fieldseal.dev/export-key-id"
/// followed by the key bytes))`. The manifest records it, never the key.
pub fn key_id(key: &ExportKey) -> String {
    lower_hex(sha256_parts(&[b"fieldseal.dev/export-key-id", &key.0[..]]).as_bytes())[..32].to_owned()
}

/// Maps the subject of a landed row to the subject column of an export.
pub trait SubjectMapper {
    /// The subject as it is written.
    fn map(&self, subject: &str) -> String;
    /// The key id for the manifest, if the mapping uses a key.
    fn key_id(&self) -> Option<String>;
}

/// `lower_hex(HMAC-SHA-256(export_key, subject))`, the subject being the UTF-8 bytes of the
/// column text as intake lands it.
#[derive(Clone)]
pub struct KeyedSubject(ExportKey);

impl KeyedSubject {
    /// A mapper under `key`.
    pub fn new(key: ExportKey) -> Self {
        Self(key)
    }
}

impl SubjectMapper for KeyedSubject {
    fn map(&self, subject: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0.0[..]).expect("HMAC accepts a key of any length");
        mac.update(subject.as_bytes());
        lower_hex(&mac.finalize().into_bytes())
    }

    fn key_id(&self) -> Option<String> {
        Some(key_id(&self.0))
    }
}

/// The subject as intake lands it, for the authority's own landing directory, which stays
/// inside the authority.
pub struct IdentitySubject;

impl SubjectMapper for IdentitySubject {
    fn map(&self, subject: &str) -> String {
        subject.to_owned()
    }

    fn key_id(&self) -> Option<String> {
        None
    }
}
