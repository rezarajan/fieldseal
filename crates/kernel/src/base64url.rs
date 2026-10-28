//! base64url without padding (RFC 4648 §5), the encoding of the `Fieldseal-PoP` header
//! (WIRE-172) and of the identity-provider tokens the adapters read.

use crate::error::{ErrorCode, WireError};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding (RFC 4648 §5).
pub fn base64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(B64[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

/// Decodes base64url without padding; padding characters and non-zero trailing bits are
/// refused, so each byte string has one encoding.
pub fn base64url_decode(input: &str) -> Result<Vec<u8>, WireError> {
    let bad = |i| WireError::new(ErrorCode::UnknownField, i, "not base64url");
    if input.len() % 4 == 1 {
        return Err(bad(input.len()));
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for (i, c) in input.bytes().enumerate() {
        let v = B64.iter().position(|b| *b == c).ok_or(bad(i))? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return Err(bad(input.len()));
    }
    Ok(out)
}
