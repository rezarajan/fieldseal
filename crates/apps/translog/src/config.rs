//! Configuration, from the environment only (twelve-factor III), as pure functions.

use std::path::{Path, PathBuf};

use fieldseal_kernel::sign::SigningKey;
use fieldseal_publishing::domain::encoding::hex_decode;

/// The data directory (required).
pub const DIR_VAR: &str = "FIELDSEAL_TRANSLOG_DIR";
/// The log's origin line (required).
pub const ORIGIN_VAR: &str = "FIELDSEAL_TRANSLOG_ORIGIN";
/// The file holding the 32-byte P-256 private scalar as hex (required).
pub const KEY_FILE_VAR: &str = "FIELDSEAL_TRANSLOG_KEY_FILE";
/// `1` creates the key file once, from OS randomness, if it doesn't exist.
pub const GENERATE_VAR: &str = "FIELDSEAL_TRANSLOG_GENERATE_KEY";
/// The address to listen on (default [`DEFAULT_BIND`]).
pub const BIND_VAR: &str = "FIELDSEAL_TRANSLOG_BIND";
/// The largest request body in bytes (default [`DEFAULT_MAX_BODY`]).
pub const MAX_BODY_VAR: &str = "FIELDSEAL_TRANSLOG_MAX_BODY";

/// The default listen address.
pub const DEFAULT_BIND: &str = "127.0.0.1:8080";
/// The default largest request body: 4 KiB.
pub const DEFAULT_MAX_BODY: usize = 4096;
/// The largest `FIELDSEAL_TRANSLOG_MAX_BODY` accepted: 1 MiB.
pub const MAX_BODY_LIMIT: usize = 1024 * 1024;

/// Why the configuration is unusable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A required variable is unset or empty.
    #[error("{0} is not set")]
    Missing(&'static str),
    /// A variable has an unusable value.
    #[error("{0}: {1}")]
    Invalid(&'static str, String),
    /// The key file is absent and key generation is not enabled, or it can't be used.
    #[error("key file: {0}")]
    Key(String),
}

/// The server's configuration.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Config {
    /// The log's data directory.
    pub dir: PathBuf,
    /// The log's origin.
    pub origin: String,
    /// The key file.
    pub key_file: PathBuf,
    /// Whether to create the key file if it is missing.
    pub generate_key: bool,
    /// The listen address.
    pub bind: String,
    /// The largest request body in bytes.
    pub max_body: usize,
}

impl Config {
    /// Reads the configuration through `get` (the environment, in the binary). A variable that
    /// is set but empty, or has leading or trailing whitespace, is refused, not treated as
    /// unset (CLI-030); unknown `FIELDSEAL_TRANSLOG_*` names are refused by [`check_names`].
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let var = |name: &'static str| -> Result<Option<String>, ConfigError> {
            match get(name) {
                None => Ok(None),
                Some(v) if v.is_empty() => Err(ConfigError::Invalid(name, "is set but empty; give it a value or unset it".into())),
                Some(v) if v.trim() != v => Err(ConfigError::Invalid(name, "has leading or trailing whitespace".into())),
                Some(v) => Ok(Some(v)),
            }
        };
        let required = |name: &'static str| var(name)?.ok_or(ConfigError::Missing(name));
        let generate_key = match var(GENERATE_VAR)?.as_deref() {
            None | Some("0") => false,
            Some("1") => true,
            Some(other) => return Err(ConfigError::Invalid(GENERATE_VAR, format!("expected 0 or 1, got `{other}`"))),
        };
        let max_body = match var(MAX_BODY_VAR)? {
            None => DEFAULT_MAX_BODY,
            Some(v) => match v.parse::<usize>() {
                Ok(n) if v.bytes().all(|b| b.is_ascii_digit()) && (1..=MAX_BODY_LIMIT).contains(&n) => n,
                _ => return Err(ConfigError::Invalid(MAX_BODY_VAR, format!("expected 1 to {MAX_BODY_LIMIT}, got `{v}`"))),
            },
        };
        let origin = required(ORIGIN_VAR)?;
        if origin.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(ConfigError::Invalid(ORIGIN_VAR, "an origin is one line without whitespace".into()));
        }
        let bind = var(BIND_VAR)?.unwrap_or_else(|| DEFAULT_BIND.into());
        if bind.parse::<std::net::SocketAddr>().is_err() {
            return Err(ConfigError::Invalid(BIND_VAR, format!("expected an `address:port` such as {DEFAULT_BIND}, got `{bind}`")));
        }
        Ok(Self {
            dir: PathBuf::from(required(DIR_VAR)?),
            origin,
            key_file: PathBuf::from(required(KEY_FILE_VAR)?),
            generate_key,
            bind,
            max_body,
        })
    }
}

/// Every environment variable the server reads (CLI-030).
pub const KNOWN_VARS: &[&str] = &[DIR_VAR, ORIGIN_VAR, KEY_FILE_VAR, GENERATE_VAR, BIND_VAR, MAX_BODY_VAR];

/// The prefix the server owns: any variable under it that is not in [`KNOWN_VARS`] is a typo
/// or a stale setting, and is refused.
pub const OWN_PREFIX: &str = "FIELDSEAL_TRANSLOG_";

/// Refuses the first name under [`OWN_PREFIX`] that is not in [`KNOWN_VARS`].
pub fn check_names(names: impl IntoIterator<Item = String>) -> Result<(), ConfigError> {
    let mut unknown: Vec<String> = names.into_iter().filter(|n| n.starts_with(OWN_PREFIX) && !KNOWN_VARS.contains(&n.as_str())).collect();
    unknown.sort();
    match unknown.first() {
        None => Ok(()),
        Some(n) => Err(ConfigError::Invalid("environment", format!("unknown variable {n} (known: {})", KNOWN_VARS.join(", ")))),
    }
}

/// Parses a key file's text: 64 hex digits and an optional final newline, a valid P-256
/// scalar.
pub fn parse_key(text: &str) -> Result<SigningKey, ConfigError> {
    // The file is the hex and one optional final newline, nothing else.
    let bytes = hex_decode(text.strip_suffix('\n').unwrap_or(text)).filter(|b| b.len() == 32).ok_or_else(|| ConfigError::Key("expected 64 hex digits".into()))?;
    SigningKey::from_scalar(&bytes).map_err(|_| ConfigError::Key("not a valid P-256 private scalar".into()))
}

/// Loads the signing key from `path`. If the file doesn't exist and `generate` is set,
/// creates it (exclusively, readable by the owner only) from `random`, which fills a buffer
/// with cryptographically secure random bytes. Without `generate` a missing file is an
/// error: the server never derives its key.
pub fn load_key(path: &Path, generate: bool, random: impl Fn(&mut [u8])) -> Result<SigningKey, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_key(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && generate => {
            let key = loop {
                let mut scalar = [0u8; 32];
                random(&mut scalar);
                if let Ok(k) = SigningKey::from_scalar(&scalar) {
                    write_new(path, &scalar)?;
                    break k;
                }
            };
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(ConfigError::Key(format!("{} does not exist (set {GENERATE_VAR}=1 to create it once)", path.display())))
        }
        Err(e) => Err(ConfigError::Key(format!("{}: {e}", path.display()))),
    }
}

fn write_new(path: &Path, scalar: &[u8; 32]) -> Result<(), ConfigError> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| ConfigError::Key(e.to_string()))?;
    }
    let text = format!("{}\n", fieldseal_kernel::digest::lower_hex(scalar));
    let mut file = options.open(path).map_err(|e| ConfigError::Key(format!("{}: {e}", path.display())))?;
    file.write_all(text.as_bytes()).and_then(|()| file.sync_all()).map_err(|e| ConfigError::Key(e.to_string()))
}

