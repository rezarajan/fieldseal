//! The session key (TRU-070, WIRE §session-key) and the local record envelope
//! (WIRE-080..082).
//!
//! The session key is `HKDF-SHA256(ikm = unwrap(wrapped_secret) ‖ Argon2id(PIN, salt), info =
//! "fieldseal.dev/session-key/v1" ‖ tenancy_id)`. The unwrapping and the memory-hard hash
//! happen outside the kernel (through the key-store and hash ports); the kernel only combines
//! their outputs.
//!
//! A local record entry is `{seq, nonce, ct}`: the plaintext record payload encrypted with
//! AES-256-GCM under the session key, with a 12-byte random nonce, and the additional data
//! `["fieldseal.dev/local-record/v1", tenancy_id, seq]` (canonical CBOR). The kernel reads
//! no randomness: the caller supplies the nonce from its random source.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::cbor;
use crate::crypto::tags;
use crate::error::{ErrorCode, WireError};
use crate::id::TenancyId;
use crate::structure::Fields;
use crate::value::Value;

/// The HKDF `info` prefix for the session key (TRU-070).
pub const SESSION_KEY_INFO: &[u8] = b"fieldseal.dev/session-key/v1";

/// The length of a local record nonce (WIRE-080).
pub const NONCE_LEN: usize = 12;

/// The length of the AES-GCM authentication tag every `ct` ends with.
const GCM_TAG_LEN: usize = 16;

/// Encryptions allowed under one session storage key before it must be rotated (WIRE-082).
pub const MAX_ENCRYPTIONS: u64 = 1 << 32;

/// A session key: 32 bytes, zeroised when dropped. Its `Debug` output is redacted.
pub struct SessionKey(Zeroizing<[u8; 32]>);

impl SessionKey {
    /// The key bytes, for the AEAD only.
    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionKey(<redacted>)")
    }
}

/// Derives the session key from the unwrapped secret and the PIN's memory-hard hash
/// (TRU-070). Both inputs are the caller's to zeroise; the concatenation made here is.
pub fn derive_session_key(unwrapped_secret: &[u8], pin_hash: &[u8; 32], tenancy: &TenancyId) -> SessionKey {
    let mut ikm = Zeroizing::new(Vec::with_capacity(unwrapped_secret.len() + pin_hash.len()));
    ikm.extend_from_slice(unwrapped_secret);
    ikm.extend_from_slice(pin_hash);
    let mut info = SESSION_KEY_INFO.to_vec();
    info.extend_from_slice(tenancy.as_bytes());
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, okm.as_mut()).expect("32 bytes is a valid HKDF-SHA256 output length");
    SessionKey(okm)
}

/// One local record entry (WIRE-080).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LocalEntry {
    /// The record's `seq`.
    pub seq: u64,
    /// The AES-GCM nonce.
    pub nonce: [u8; NONCE_LEN],
    /// The ciphertext with its tag.
    pub ct: Vec<u8>,
}

/// The additional data for an entry (WIRE-081).
pub fn local_record_aad(tenancy: &TenancyId, seq: u64) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::Text(tags::LOCAL_RECORD.as_str().to_owned()),
        Value::Bytes(tenancy.as_bytes().to_vec()),
        Value::Int(i128::from(seq)),
    ]))
    .expect("the additional data is always encodable")
}

impl LocalEntry {
    /// Encrypts `plaintext` (a canonical record payload) for `seq` (WIRE-080, WIRE-081). The
    /// nonce must come from the caller's random source and never repeat under `key`
    /// (WIRE-082).
    pub fn seal(key: &SessionKey, tenancy: &TenancyId, seq: u64, nonce: [u8; NONCE_LEN], plaintext: &[u8]) -> Self {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key.bytes()));
        let aad = local_record_aad(tenancy, seq);
        let ct = cipher
            .encrypt(&Nonce::from(nonce), Payload { msg: plaintext, aad: &aad })
            .expect("AES-GCM encryption of a bounded message does not fail");
        Self { seq, nonce, ct }
    }

    /// Decrypts the entry. A wrong key, tenancy, `seq` or a modified entry is `E_DECRYPT`.
    pub fn open(&self, key: &SessionKey, tenancy: &TenancyId) -> Result<Zeroizing<Vec<u8>>, WireError> {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key.bytes()));
        let aad = local_record_aad(tenancy, self.seq);
        cipher
            .decrypt(&Nonce::from(self.nonce), Payload { msg: &self.ct, aad: &aad })
            .map(Zeroizing::new)
            .map_err(|_| WireError::new(ErrorCode::Decrypt, 0, "local record entry does not decrypt"))
    }

    /// The entry as a value.
    pub fn to_value(&self) -> Value {
        cbor::map([
            ("seq", Value::Int(i128::from(self.seq))),
            ("nonce", Value::Bytes(self.nonce.to_vec())),
            ("ct", Value::Bytes(self.ct.clone())),
        ])
    }

    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("a local entry is always encodable")
    }

    /// Decodes canonical CBOR; any other field is `E_UNKNOWN_FIELD`.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut f = Fields::new(cbor::decode(bytes)?)?;
        let entry = Self { seq: f.uint("seq")?, nonce: f.bytes_n::<NONCE_LEN>("nonce")?, ct: f.bytes("ct")? };
        f.finish()?;
        if entry.ct.len() < GCM_TAG_LEN {
            return Err(WireError::new(ErrorCode::UnknownField, 0, "ct is shorter than the AES-GCM tag"));
        }
        Ok(entry)
    }
}
