//! Domain-tagged ECDSA P-256 signatures (WIRE-020..022).
//!
//! The signed message for structure `S` under tag `t` is the canonical CBOR array `[t, S]`;
//! the signature is ECDSA P-256 with SHA-256 over it, encoded as 64 bytes `r ‖ s` with `s` in
//! low form. Signing is deterministic (RFC 6979), so the same key, tag and structure always
//! give the same signature.

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::elliptic_curve::Generate as _;
use rand_core::CryptoRng;

use crate::cbor;
use crate::crypto::{DomainTag, P256PublicKey, Signature, TagUsage};
use crate::error::{ErrorCode, KernelError, WireError};
use crate::value::Value;

/// The length of an encoded signature (WIRE-022).
pub const SIGNATURE_LEN: usize = 64;

/// The signed message `[t, S]` for structure `S` under tag `t` (WIRE-021). `S` must already
/// lack its signature field.
pub fn signed_message(tag: &DomainTag, structure: &Value) -> Result<Vec<u8>, WireError> {
    cbor::encode(&Value::Array(vec![Value::Text(tag.as_str().to_owned()), structure.clone()]))
}

/// A P-256 signing key held in software. The scalar is zeroised when the key is dropped.
///
/// Keys held by a platform key store never become a `SigningKey`; their signatures are made
/// through the Trust ports over [`signed_message`] and checked with [`verify`].
pub struct SigningKey(p256::ecdsa::SigningKey);

impl SigningKey {
    /// Imports a 32-byte big-endian private scalar (nonzero, below the group order).
    pub fn from_scalar(bytes: &[u8]) -> Result<Self, KernelError> {
        p256::ecdsa::SigningKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| KernelError::Malformed { kind: "SigningKey", reason: "not a valid P-256 scalar" })
    }

    /// Generates a key from the caller's cryptographically secure random source.
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        Self(p256::ecdsa::SigningKey::generate_from_rng(rng))
    }

    /// The public key, in uncompressed SEC1 form (WIRE-009).
    pub fn public_key(&self) -> P256PublicKey {
        let point = self.0.verifying_key().to_sec1_point(false);
        P256PublicKey::from_bytes(point.as_bytes()).expect("uncompressed SEC1 point is 65 bytes")
    }

    /// Signs structure `S` under `tag` (WIRE-021). The tag must be a known signature tag.
    pub fn sign(&self, tag: &DomainTag, structure: &Value) -> Result<Signature, WireError> {
        tag.expect(TagUsage::Signature)?;
        Ok(self.sign_message(&signed_message(tag, structure)?))
    }

    /// Signs an already-built message with SHA-256 and RFC 6979, normalising `s` to low form.
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        let sig: p256::ecdsa::Signature = self.0.sign(message);
        Signature(sig.normalize_s().to_bytes().to_vec())
    }
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKey(…)")
    }
}

/// Verifies `signature` over structure `S` under `tag`. The tag is checked first and an
/// unknown or non-signature tag is refused with `E_TAG` (WIRE-020); a wrong length, high `s`
/// (WIRE-022) or failed check is `E_SIG`.
pub fn verify(public: &P256PublicKey, tag: &DomainTag, structure: &Value, signature: &Signature) -> Result<(), WireError> {
    tag.expect(TagUsage::Signature)?;
    verify_message(public, &signed_message(tag, structure)?, signature)
}

/// Verifies a signature over an already-built message.
pub fn verify_message(public: &P256PublicKey, message: &[u8], signature: &Signature) -> Result<(), WireError> {
    let bad = |detail| WireError::new(ErrorCode::Sig, 0, detail);
    if signature.0.len() != SIGNATURE_LEN {
        return Err(bad("signature is not 64 bytes"));
    }
    let sig = p256::ecdsa::Signature::from_slice(&signature.0).map_err(|_| bad("r or s out of range"))?;
    if sig.normalize_s() != sig {
        return Err(bad("high-s signature"));
    }
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public.as_bytes()).map_err(|_| bad("public key not on the curve"))?;
    key.verify(message, &sig).map_err(|_| bad("signature does not verify"))
}
