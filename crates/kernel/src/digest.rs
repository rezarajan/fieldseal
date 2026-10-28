//! Hashes and identifiers derived from them (WIRE §5.1, §5.16): SHA-256, content
//! addresses, key identifiers and salted instrument fingerprints.

use sha2::{Digest as _, Sha256};

use crate::error::{ErrorCode, WireError};
use crate::id::{ContentAddress, Digest, Fingerprint, Salt, KeyId};

/// The prefix of a content address's text form (WIRE-011).
pub const CONTENT_ADDRESS_PREFIX: &str = "sha256:";

/// The domain prefix of an instrument fingerprint (WIRE-185).
pub const FINGERPRINT_DOMAIN: &str = "fieldseal.dev/instrument-fingerprint/v1";

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> Digest {
    Digest::from(<[u8; 32]>::from(Sha256::digest(bytes)))
}

/// SHA-256 over the concatenation of `parts`.
pub fn sha256_parts(parts: &[&[u8]]) -> Digest {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    Digest::from(<[u8; 32]>::from(h.finalize()))
}

/// A key identifier: the first 16 bytes of SHA-256 over the encoded public key (WIRE-010),
/// where the encoding is that of WIRE-009 (65-byte uncompressed SEC1 for P-256, 32 raw bytes
/// for X25519), not a CBOR byte string.
pub fn key_id(encoded_public_key: &[u8]) -> KeyId {
    let d = sha256(encoded_public_key);
    let mut id = [0u8; 16];
    id.copy_from_slice(&d.as_bytes()[..16]);
    KeyId::from(id)
}

/// An instrument's fingerprint:
/// `SHA-256("fieldseal.dev/instrument-fingerprint/v1" ‖ salt ‖ canonical bytes)` (WIRE-185).
pub fn instrument_fingerprint(salt: &Salt, canonical: &[u8]) -> Fingerprint {
    let d = sha256_parts(&[FINGERPRINT_DOMAIN.as_bytes(), salt.as_bytes(), canonical]);
    Fingerprint::from(*d.as_bytes())
}

impl Fingerprint {
    /// The display short form: the first 8 bytes in Crockford base32, 13 characters (WIRE-187).
    pub fn short_form(&self) -> String {
        crockford_base32(&self.as_bytes()[..8])
    }
}

impl ContentAddress {
    /// The content address of an object's canonical bytes (WIRE-011).
    pub fn of(canonical: &[u8]) -> Self {
        Self::from(*sha256(canonical).as_bytes())
    }

    /// The text form, `sha256:` and 64 lowercase hex digits (WIRE-011).
    pub fn to_text(&self) -> String {
        let mut s = String::with_capacity(CONTENT_ADDRESS_PREFIX.len() + 64);
        s.push_str(CONTENT_ADDRESS_PREFIX);
        s.push_str(&lower_hex(self.as_bytes()));
        s
    }

    /// Parses the text form. Upper-case hex, a missing prefix or a wrong length is refused
    /// with `E_HASH`, since a content address has exactly one text form.
    pub fn parse_text(text: &str) -> Result<Self, WireError> {
        let bad = |offset| WireError::new(ErrorCode::Hash, offset, "not sha256: and 64 lowercase hex digits");
        let hex = text.strip_prefix(CONTENT_ADDRESS_PREFIX).ok_or(bad(0))?;
        if hex.len() != 64 {
            return Err(bad(CONTENT_ADDRESS_PREFIX.len()));
        }
        let mut out = [0u8; 32];
        for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
            let nibble = |c: u8| match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                _ => None,
            };
            let (hi, lo) = (nibble(pair[0]), nibble(pair[1]));
            out[i] = match (hi, lo) {
                (Some(h), Some(l)) => (h << 4) | l,
                _ => return Err(bad(CONTENT_ADDRESS_PREFIX.len() + 2 * i)),
            };
        }
        Ok(Self::from(out))
    }
}

/// Lowercase hexadecimal.
pub fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    s
}

/// Crockford base32 (alphabet `0-9 A-Z` without `I L O U`), most significant bit first,
/// unpadded; a final partial group is padded with zero bits.
pub fn crockford_base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}
