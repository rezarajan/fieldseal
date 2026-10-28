//! Typed text forms for small signed objects (WIRE-122, WIRE-144): a prefix such as
//! `FS1T:`, the Crockford base32 of the object's canonical CBOR, and a two-character check
//! value (CRC-10 over the CBOR bytes, as 10 bits in base32).
//!
//! The CRC is CRC-10/ATM (also called CRC-10/I-610): polynomial `0x233`, initial value 0,
//! no reflection, no final XOR; its check value over `"123456789"` is `0x199`. The text
//! form is upper case, so it fits a QR code's alphanumeric mode.

use crate::digest::crockford_base32;
use crate::error::{ErrorCode, WireError};

/// The text-form prefix of a registration token (WIRE-122).
pub const TOKEN_PREFIX: &str = "FS1T:";
/// The text-form prefix of a close or reset certificate (WIRE-144).
pub const CLOSE_PREFIX: &str = "FS1C:";
/// The text-form prefix of a receipt (WIRE-144).
pub const RECEIPT_PREFIX: &str = "FS1R:";
/// The text-form prefix of a time token (WIRE-144).
pub const TIME_TOKEN_PREFIX: &str = "FS1N:";

/// The largest canonical CBOR a QR-sized object may have (WIRE-123, WIRE-144).
pub const MAX_QR_OBJECT: usize = 300;

const CRC10_POLY: u16 = 0x233;
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// CRC-10/ATM over `bytes` (a 10-bit value).
pub fn crc10(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in bytes {
        crc ^= u16::from(b) << 2;
        for _ in 0..8 {
            crc = if crc & 0x200 != 0 { ((crc << 1) ^ CRC10_POLY) & 0x3ff } else { (crc << 1) & 0x3ff };
        }
    }
    crc
}

/// The value of one Crockford base32 character. Decoding is case-insensitive and maps the
/// look-alikes `I` and `L` to 1 and `O` to 0, as Crockford's alphabet specifies.
fn symbol(c: u8) -> Option<u8> {
    let c = c.to_ascii_uppercase();
    let c = match c {
        b'I' | b'L' => b'1',
        b'O' => b'0',
        other => other,
    };
    ALPHABET.iter().position(|a| *a == c).map(|p| p as u8)
}

/// Decodes Crockford base32 as produced by [`crockford_base32`]. The padding bits of a final
/// partial group must be zero, so every byte string has exactly one encoding.
pub fn crockford_base32_decode(text: &str) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for (i, c) in text.bytes().enumerate() {
        let v = symbol(c).ok_or(WireError::new(ErrorCode::FrameMagic, i, "not a Crockford base32 character"))?;
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if bits >= 5 || acc != 0 {
        return Err(WireError::new(ErrorCode::FrameLength, text.len(), "base32 padding is not zero"));
    }
    Ok(out)
}

/// The check value's two characters: the CRC's 10 bits, most significant first.
fn check_chars(cbor: &[u8]) -> [char; 2] {
    let crc = crc10(cbor);
    [ALPHABET[usize::from(crc >> 5)] as char, ALPHABET[usize::from(crc & 0x1f)] as char]
}

/// The text form of `cbor` under `prefix` (WIRE-122).
pub fn encode(prefix: &str, cbor: &[u8]) -> String {
    let mut s = String::with_capacity(prefix.len() + cbor.len() * 8 / 5 + 4);
    s.push_str(prefix);
    s.push_str(&crockford_base32(cbor));
    s.extend(check_chars(cbor));
    s
}

/// Reads a text form under `prefix`, returning the CBOR bytes. A wrong prefix is
/// `E_FRAME_MAGIC`, a bad character or padding `E_FRAME_MAGIC`/`E_FRAME_LENGTH`, and a check
/// value that doesn't match `E_CRC`. Leading and trailing whitespace is ignored; the prefix
/// is matched case-insensitively, since scanners and people may change case.
pub fn decode(prefix: &str, text: &str) -> Result<Vec<u8>, WireError> {
    let text = text.trim();
    // Work on bytes: the input is untrusted and may hold multi-byte characters anywhere, where
    // slicing the `str` would panic. Every valid text form is ASCII, so a non-ASCII byte is
    // simply "not a Crockford character" below.
    let bytes = text.as_bytes();
    if bytes.len() < prefix.len() + 2 || !bytes[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes()) {
        return Err(WireError::new(ErrorCode::FrameMagic, 0, "wrong text-form prefix"));
    }
    let body = &bytes[prefix.len()..];
    let (data, check) = body.split_at(body.len() - 2);
    let data = std::str::from_utf8(data).map_err(|_| WireError::new(ErrorCode::FrameMagic, prefix.len(), "not a Crockford base32 character"))?;
    let cbor = crockford_base32_decode(data).map_err(|e| e.shifted(prefix.len()))?;
    let expected = check_chars(&cbor);
    let got: Vec<u8> = check.iter().copied().map(|c| symbol(c).map(|v| ALPHABET[usize::from(v)]).unwrap_or(0)).collect();
    if got != [expected[0] as u8, expected[1] as u8] {
        return Err(WireError::new(ErrorCode::Crc, text.len() - 2, "text-form check value does not match"));
    }
    Ok(cbor)
}
