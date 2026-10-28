//! Development key custody: software authority keys in a local key directory.
//!
//! **Development custody only.** The private keys here are files readable by the owner, not
//! keys behind a hardware boundary; a root or purpose key held this way offers none of the
//! protection `docs/how-to/set-up-the-trust-hierarchy.md` asks for (TRU-001, TRU-013). It
//! implements the same [`KeyCustody`] port as an HSM or KMS adapter, which production
//! deployments use instead; the commands do not change. Every key it holds is unattested
//! (CLI-007), and `fieldseal trust root-init` says so in its output.
//!
//! Layout: `<dir>/<key id, hex>.key` holds `role`, `algorithm` and `secret` lines; each use of
//! a key is appended to `<dir>/usage.log` as `key role operation caller`.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use fieldseal_kernel::Value;
use fieldseal_kernel::crypto::{DomainTag, Purpose, Signature};
use fieldseal_kernel::id::KeyId;
use fieldseal_kernel::seal::{self, RecipientKey, RecipientSecret, SealedBox, Suite};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_trust::domain::{AuthorityPublicKey, CustodyKey, KeyAlgorithm, KeyOperation, KeyRole, KeyUse, may_open, may_sign};
use fieldseal_trust::ports::{CustodyError, KeyCustody};
use zeroize::Zeroizing;


/// The software custody in a key directory.
pub struct DirCustody {
    dir: PathBuf,
}

struct Held {
    role: KeyRole,
    algorithm: KeyAlgorithm,
    secret: Zeroizing<Vec<u8>>,
}

fn backend(e: impl std::fmt::Display) -> CustodyError {
    CustodyError::Backend(e.to_string())
}

impl DirCustody {
    /// The custody in `dir` (created when the first key is generated).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The key directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn file(&self, id: &KeyId) -> PathBuf {
        self.dir.join(format!("{}.key", hex(id.as_bytes())))
    }

    fn load(&self, id: &KeyId) -> Result<Held, CustodyError> {
        let text = std::fs::read_to_string(self.file(id)).map_err(|_| CustodyError::UnknownKey)?;
        let field = |name: &str| text.lines().find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix('='))).ok_or_else(|| backend("key file is malformed"));
        let role = KeyRole::parse(field("role")?).ok_or_else(|| backend("unknown role"))?;
        let algorithm = match field("algorithm")? {
            "p256" => KeyAlgorithm::P256,
            "x25519" => KeyAlgorithm::X25519,
            _ => return Err(backend("unknown algorithm")),
        };
        let secret = unhex(field("secret")?).ok_or_else(|| backend("secret is not hexadecimal"))?;
        Ok(Held { role, algorithm, secret: Zeroizing::new(secret) })
    }

    fn public_of(held: &Held) -> Result<AuthorityPublicKey, CustodyError> {
        match held.algorithm {
            KeyAlgorithm::P256 => Ok(AuthorityPublicKey::P256(SigningKey::from_scalar(&held.secret).map_err(backend)?.public_key())),
            KeyAlgorithm::X25519 => {
                match RecipientSecret::from_bytes(Suite::Fs1X, &held.secret).map_err(backend)?.public().map_err(backend)? {
                    RecipientKey::X25519(p) => Ok(AuthorityPublicKey::X25519(p)),
                    _ => Err(backend("not an X25519 key")),
                }
            }
        }
    }

    fn record(&self, key: &KeyId, role: KeyRole, op: KeyOperation, caller: &str) {
        let op = match op {
            KeyOperation::Sign => "sign",
            KeyOperation::Open => "open",
        };
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(self.dir.join("usage.log")) {
            let _ = writeln!(f, "{} {} {op} {caller}", hex(key.as_bytes()), role.as_str());
        }
    }

    /// Every key in the directory with its role, oldest name first.
    pub fn keys(&self) -> Vec<CustodyKey> {
        let Ok(rd) = std::fs::read_dir(&self.dir) else { return Vec::new() };
        let mut ids: Vec<KeyId> = rd
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".key")).and_then(unhex))
            .filter_map(|b| KeyId::from_bytes(&b).ok())
            .collect();
        ids.sort();
        ids.iter().filter_map(|id| self.public_key(id).ok()).collect()
    }

    /// Whether the directory holds `id`.
    pub fn holds(&self, id: &KeyId) -> bool {
        self.file(id).is_file()
    }

    /// The one key held for `role`, if exactly one is.
    pub fn sole_key(&self, role: KeyRole) -> Option<KeyId> {
        let mut it = self.keys().into_iter().filter(|k| k.role == role);
        let first = it.next()?;
        it.next().is_none().then_some(first.id)
    }
}

/// 32 bytes from the operating system's generator.
fn os_random() -> Result<[u8; 32], CustodyError> {
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut b)).map_err(backend)?;
    Ok(b)
}

impl KeyCustody for DirCustody {
    fn generate(&self, role: KeyRole, algorithm: KeyAlgorithm) -> Result<CustodyKey, CustodyError> {
        if !role.allows(algorithm) {
            return Err(CustodyError::Unsupported);
        }
        let secret = Zeroizing::new(os_random()?);
        let public_key = match algorithm {
            KeyAlgorithm::P256 => AuthorityPublicKey::P256(SigningKey::from_scalar(&secret[..]).map_err(backend)?.public_key()),
            KeyAlgorithm::X25519 => Self::public_of(&Held { role, algorithm, secret: Zeroizing::new(secret.to_vec()) })?,
        };
        let key = CustodyKey { id: public_key.key_id(), public_key, role };
        let alg = if algorithm == KeyAlgorithm::P256 { "p256" } else { "x25519" };
        std::fs::create_dir_all(&self.dir).map_err(backend)?;
        let body = format!("role={}\nalgorithm={alg}\nsecret={}\n", role.as_str(), hex(&secret[..]));
        let path = self.file(&key.id);
        std::fs::write(&path, body).map_err(backend)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(backend)?;
        }
        Ok(key)
    }

    fn sign(&self, key: &KeyId, role: KeyRole, tag: &DomainTag, structure: &Value, caller: &str) -> Result<Signature, CustodyError> {
        let held = self.load(key)?;
        if held.role != role {
            return Err(CustodyError::WrongPurpose { held: held.role, requested: role });
        }
        if !may_sign(role, tag) {
            return Err(CustodyError::TagNotAllowed { role, tag: tag.as_str() });
        }
        if held.algorithm != KeyAlgorithm::P256 {
            return Err(CustodyError::Unsupported);
        }
        let sig = SigningKey::from_scalar(&held.secret).map_err(backend)?.sign(tag, structure).map_err(backend)?;
        self.record(key, role, KeyOperation::Sign, caller);
        Ok(sig)
    }

    fn open(&self, key: &KeyId, purpose: Purpose, tag: &DomainTag, sealed: &SealedBox, caller: &str) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
        let held = self.load(key)?;
        let role = KeyRole::Purpose(purpose);
        if held.role != role {
            return Err(CustodyError::WrongPurpose { held: held.role, requested: role });
        }
        if !may_open(purpose, tag) {
            return Err(CustodyError::TagNotAllowed { role, tag: tag.as_str() });
        }
        if held.algorithm != KeyAlgorithm::X25519 {
            return Err(CustodyError::Unsupported);
        }
        let sk = RecipientSecret::from_bytes(Suite::Fs1X, &held.secret).map_err(backend)?;
        self.record(key, role, KeyOperation::Open, caller);
        seal::open(&sk, tag, sealed).map_err(CustodyError::Open)
    }

    fn public_key(&self, key: &KeyId) -> Result<CustodyKey, CustodyError> {
        let held = self.load(key)?;
        Ok(CustodyKey { id: *key, public_key: Self::public_of(&held)?, role: held.role })
    }

    fn usage_log(&self) -> Vec<KeyUse> {
        // Each line is `key role operation caller`; a caller may contain spaces.
        let Ok(text) = std::fs::read_to_string(self.dir.join("usage.log")) else { return Vec::new() };
        text.lines()
            .filter_map(|line| {
                let mut parts = line.splitn(4, ' ');
                let key = KeyId::from_bytes(&unhex(parts.next()?)?).ok()?;
                let role = KeyRole::parse(parts.next()?)?;
                let operation = match parts.next()? {
                    "sign" => KeyOperation::Sign,
                    "open" => KeyOperation::Open,
                    _ => return None,
                };
                Some(KeyUse { key, role, operation, caller: parts.next().unwrap_or("").to_owned() })
            })
            .collect()
    }
}


fn hex(bytes: &[u8]) -> String {
    fieldseal_kernel::digest::lower_hex(bytes)
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len() / 2).map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()).collect()
}
