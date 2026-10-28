//! Device-style software keys for `fieldseal keys generate --purpose sign|agree`, `keys roll`
//! and `bundle open --key` (CLI §5 `keys`, REG local keys).
//!
//! **Development keys only.** A key file holds a private scalar in a file readable by its
//! owner, so the key is unattested (CLI-007) and the output of every command that uses one
//! says so. A handle is the path of the key file.
//!
//! Layout of a key file: `purpose`, `algorithm` and `secret` lines. A `sign` key is a P-256
//! signing key; an `agree` key is a P-256 agreement key (suite `fs1-p`), the kind a bundle is
//! sealed to (DIS-020).

use fieldseal_kernel::crypto::Signature;
use fieldseal_kernel::digest::key_id;
use fieldseal_kernel::id::KeyId;
use fieldseal_kernel::seal::{RecipientKey, RecipientSecret, Suite};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_trust::ports::RandomSource;
use zeroize::Zeroizing;

use crate::support::{hex, unhex};

/// What a device key is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DevicePurpose {
    /// Signs records and proofs of possession.
    Sign,
    /// Opens what is sealed to the device (bundles, receipts of agreement).
    Agree,
}

impl DevicePurpose {
    /// `sign` or `agree`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Agree => "agree",
        }
    }

    /// Parses `sign` or `agree`.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "sign" => Some(Self::Sign),
            "agree" => Some(Self::Agree),
            _ => None,
        }
    }
}

/// A software device key.
pub struct DeviceKey {
    /// What it is for.
    pub purpose: DevicePurpose,
    secret: Zeroizing<Vec<u8>>,
}

impl DeviceKey {
    /// A fresh key from `random`; a scalar the curve rejects (vanishingly rare) is redrawn.
    pub fn generate(purpose: DevicePurpose, random: &dyn RandomSource) -> Self {
        loop {
            let mut b = Zeroizing::new(vec![0u8; 32]);
            random.fill(&mut b);
            let valid = match purpose {
                DevicePurpose::Sign => SigningKey::from_scalar(&b).is_ok(),
                DevicePurpose::Agree => RecipientSecret::from_bytes(Suite::Fs1P, &b).and_then(|s| s.public()).is_ok(),
            };
            if valid {
                return Self { purpose, secret: b };
            }
        }
    }

    /// The signing key; `None` for an agreement key.
    pub fn signing(&self) -> Option<SigningKey> {
        (self.purpose == DevicePurpose::Sign).then(|| SigningKey::from_scalar(&self.secret).ok()).flatten()
    }

    /// The agreement secret; `None` for a signing key.
    pub fn agreement(&self) -> Option<RecipientSecret> {
        (self.purpose == DevicePurpose::Agree).then(|| RecipientSecret::from_bytes(Suite::Fs1P, &self.secret).ok()).flatten()
    }

    /// The public key in uncompressed SEC1 form (WIRE-009).
    pub fn public(&self) -> Vec<u8> {
        match self.purpose {
            DevicePurpose::Sign => self.signing().map(|k| k.public_key().as_bytes().to_vec()).unwrap_or_default(),
            DevicePurpose::Agree => self.agreement().and_then(|s| s.public().ok()).map(|k: RecipientKey| k.encoded().to_vec()).unwrap_or_default(),
        }
    }

    /// The private scalar (a bundle's device file records it so the device can open the bundle).
    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret
    }

    /// The key's identifier (WIRE-010).
    pub fn id(&self) -> KeyId {
        key_id(&self.public())
    }

    /// Signs `message`; `None` for an agreement key.
    pub fn sign_message(&self, message: &[u8]) -> Option<Signature> {
        self.signing().map(|k| k.sign_message(message))
    }

    /// The key file's text.
    pub fn to_file(&self) -> String {
        format!(
            "# A fieldseal software device key (development only; unattested).\npurpose={}\nalgorithm=p256\nsecret={}\n",
            self.purpose.as_str(),
            hex(&self.secret)
        )
    }

    /// Reads a key file; also reads the `agreement-key = ` line of a device file written by
    /// `bundle build`, so a simulated device's key opens its bundle.
    pub fn from_file(text: &str) -> Result<Self, String> {
        let field = |name: &str| text.lines().find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix('=')));
        if let (Some(p), Some(s)) = (field("purpose"), field("secret")) {
            let purpose = DevicePurpose::parse(p).ok_or("the key file names an unknown purpose")?;
            let secret = unhex(s).ok_or("the secret is not hexadecimal")?;
            let key = Self { purpose, secret: Zeroizing::new(secret) };
            return if key.public().is_empty() { Err("the key file holds an invalid key".into()) } else { Ok(key) };
        }
        if let Some(s) = text.lines().find_map(|l| l.strip_prefix("agreement-key = ")).and_then(unhex) {
            let key = Self { purpose: DevicePurpose::Agree, secret: Zeroizing::new(s) };
            return if key.public().is_empty() { Err("the device file holds an invalid key".into()) } else { Ok(key) };
        }
        Err("not a key file written by `keys generate` or a device file".into())
    }
}

/// The message a key roll's endorsement covers: a fixed prefix (so the signature is good for
/// nothing else), the purpose, and the old and new public keys.
pub fn roll_message(purpose: DevicePurpose, old: &[u8], new: &[u8]) -> Vec<u8> {
    let mut m = b"fieldseal.dev/key-roll/v1\0".to_vec();
    m.extend_from_slice(purpose.as_str().as_bytes());
    m.push(0);
    m.extend_from_slice(old);
    m.extend_from_slice(new);
    m
}
