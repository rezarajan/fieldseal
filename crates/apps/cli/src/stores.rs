//! Local, file-backed stores for the publishing commands, selected by `FIELDSEAL_ADAPTERS=files`
//! (the in-memory set is the default and lives for one invocation only).
//!
//! * [`FileLog`]: a crash-safe, append-only transparency log in a directory (the
//!   `fieldseal-adapters-translog` store). The log key is derived from the origin, so
//!   checkpoints are the same across invocations. It is a development log, never a public one:
//!   it signs its own checkpoints with a key anyone can derive. `FIELDSEAL_REKOR_URL`, when set,
//!   replaces it with the Rekor adapter, and `FIELDSEAL_TRANSLOG_URL` with a self-hosted
//!   `fieldseal-translog` server (whose key is its operator's); nothing in this build contacts
//!   a public log otherwise.
//!
//! The artefact registry `FileRegistry` is in `fieldseal-adapters-file`.

use std::path::{Path, PathBuf};

use fieldseal_adapters_translog::{FileLogStore, HttpLogTransport, HttpTranslog};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::sign::SigningKey;
use fieldseal_publishing::domain::{ConsistencyProof, InclusionProof, LogEntry, SignedCheckpoint};
use fieldseal_publishing::ports::{LogError, LoggedEntry, TransparencyLog};

/// The origin of the local development log.
pub const LOCAL_LOG_ORIGIN: &str = "fieldseal-local-log";

/// The environment variable naming a self-hosted log server (`fieldseal-translog`); when set,
/// the log is that server instead of the local one. `FIELDSEAL_REKOR_URL` takes precedence.
pub const TRANSLOG_URL_VAR: &str = "FIELDSEAL_TRANSLOG_URL";

/// The self-hosted log server named by [`TRANSLOG_URL_VAR`], if it is set.
pub fn remote_translog() -> Option<Result<Box<dyn TransparencyLog>, String>> {
    let url = std::env::var(TRANSLOG_URL_VAR).ok().filter(|v| !v.is_empty())?;
    Some(translog_at(&url))
}

/// The log server at `url`, chosen by the URL's scheme like every service client (CLI-021):
/// `http://` and `https://` are built in; `grpc://` and `grpcs://` are refused (CLI-023).
pub fn translog_at(url: &str) -> Result<Box<dyn TransparencyLog>, String> {
    use crate::messages::msg;
    match crate::clients::scheme(url) {
        Some("http" | "https") => {}
        Some(s @ ("grpc" | "grpcs")) => return Err(msg("transport-not-built", &[("url", url), ("scheme", s)])),
        _ => return Err(msg("bad-scheme", &[("url", url)])),
    }
    {
        HttpLogTransport::new(url).map(|t| Box::new(HttpTranslog::new(t)) as Box<dyn TransparencyLog>).map_err(|e| format!("{TRANSLOG_URL_VAR}: {e}"))
    }
}

/// The store behind [`FileLog`]: a [`FileLogStore`] in `dir` signed with the key derived
/// from `origin`. Exposed so conformance can run the log contract over it.
pub fn file_log_store(origin: &str, dir: &Path) -> Result<FileLogStore, LogError> {
    let scalar = sha256(format!("fieldseal.dev/memory/transparency-log/{origin}").as_bytes());
    let key = SigningKey::from_scalar(scalar.as_bytes()).expect("a SHA-256 output is a valid scalar");
    Ok(FileLogStore::open(dir, origin, key)?)
}

/// A file-backed development transparency log: a [`FileLogStore`] whose signing key is
/// derived from the origin, so every invocation (and anyone) produces the same checkpoints.
pub struct FileLog {
    inner: FileLogStore,
}

impl FileLog {
    /// Opens the log in `dir`. Entries from the earlier layout (`NNNNNNNN.entry` files) are
    /// imported, in order, the first time an empty log is opened over them.
    pub fn open(origin: &str, dir: &Path) -> Result<Self, LogError> {
        let inner = file_log_store(origin, dir)?;
        if inner.size() == 0 {
            let mut names: Vec<PathBuf> = std::fs::read_dir(dir)
                .map(|rd| rd.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "entry")).collect())
                .unwrap_or_default();
            names.sort();
            for p in names {
                let bytes = std::fs::read(&p).map_err(|e| LogError::Unavailable(e.to_string()))?;
                let entry = LogEntry::decode(&bytes).map_err(|e| LogError::Malformed(e.to_string()))?;
                inner.append(&entry)?;
            }
        }
        Ok(Self { inner })
    }
}

impl TransparencyLog for FileLog {
    fn append(&self, entry: &LogEntry) -> Result<LoggedEntry, LogError> {
        self.inner.append(entry)
    }

    fn checkpoint(&self) -> Result<SignedCheckpoint, LogError> {
        self.inner.checkpoint()
    }

    fn prove_inclusion(&self, leaf_index: u64, checkpoint: &SignedCheckpoint) -> Result<InclusionProof, LogError> {
        self.inner.prove_inclusion(leaf_index, checkpoint)
    }

    fn prove_consistency(&self, old_size: u64, checkpoint: &SignedCheckpoint) -> Result<ConsistencyProof, LogError> {
        self.inner.prove_consistency(old_size, checkpoint)
    }
}
