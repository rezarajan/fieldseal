//! Small, exact encoders the log formats need: base64 (RFC 4648 §4, padded), ECDSA
//! signatures in ASN.1 DER, and P-256 public keys as X.509 `SubjectPublicKeyInfo` (DER and
//! PEM).
//!
//! These exist so that a device can verify a transparency-log checkpoint and recompute a
//! log leaf offline, with no dependency beyond the kernel. Every decoder is strict: one
//! value has one accepted encoding.

use fieldseal_kernel::crypto::P256PublicKey;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (RFC 4648 §4).
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes standard, padded base64. Refuses any other character, missing or misplaced
/// padding, and non-zero trailing bits, so that every value has exactly one encoding.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| ALPHABET.iter().position(|&a| a == c).map(|p| p as u32);
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let quads = bytes.len() / 4;
    for (q, quad) in bytes.chunks(4).enumerate() {
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && q + 1 != quads) {
            return None;
        }
        let mut n = 0u32;
        for &c in &quad[..4 - pad] {
            n = (n << 6) | value(c)?;
        }
        n <<= 6 * pad as u32;
        let full = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let keep = 3 - pad;
        if full[keep..].iter().any(|&b| b != 0) {
            return None;
        }
        out.extend_from_slice(&full[..keep]);
    }
    Some(out)
}

/// Parses lowercase hexadecimal.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    bytes.chunks(2).map(|p| Some((nibble(p[0])? << 4) | nibble(p[1])?)).collect()
}

/// The P-256 group order `n`, big-endian.
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// `n / 2`, rounded down: a signature's `s` is low when `s ≤` this (WIRE-022).
const P256_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// Replaces a high `s` with `n − s`. ECDSA accepts both; the kernel's verifier accepts only
/// the low form (WIRE-022). Used only for signatures made outside Fieldseal (a public log's
/// checkpoint key), where the low form is not guaranteed.
pub fn normalize_s(raw: [u8; 64]) -> [u8; 64] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&raw[32..]);
    if s <= P256_HALF_ORDER {
        return raw;
    }
    let mut out = raw;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(P256_ORDER[i]) - i16::from(s[i]) - borrow;
        borrow = 0;
        if d < 0 {
            d += 256;
            borrow = 1;
        }
        out[32 + i] = d as u8;
    }
    out
}

fn der_integer(value: &[u8; 32], out: &mut Vec<u8>) {
    let start = value.iter().position(|&b| b != 0).unwrap_or(31);
    let digits = &value[start..];
    let pad = digits[0] & 0x80 != 0;
    out.push(0x02);
    out.push((digits.len() + usize::from(pad)) as u8);
    if pad {
        out.push(0);
    }
    out.extend_from_slice(digits);
}

/// An ECDSA signature `r ‖ s` (64 bytes) as ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`.
pub fn ecdsa_der_from_raw(raw: &[u8; 64]) -> Vec<u8> {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&raw[..32]);
    s.copy_from_slice(&raw[32..]);
    let mut body = Vec::with_capacity(70);
    der_integer(&r, &mut body);
    der_integer(&s, &mut body);
    let mut out = vec![0x30, body.len() as u8];
    out.extend_from_slice(&body);
    out
}

fn read_der_integer(input: &[u8]) -> Option<([u8; 32], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&len, rest) = rest.split_first()?;
    let len = usize::from(len);
    if tag != 0x02 || len == 0 || len > 33 || rest.len() < len {
        return None;
    }
    let (digits, rest) = rest.split_at(len);
    // Minimal and non-negative: no leading 0x00 unless the next byte has its top bit set.
    if digits[0] & 0x80 != 0 || (digits.len() > 1 && digits[0] == 0 && digits[1] & 0x80 == 0) {
        return None;
    }
    let digits = if digits[0] == 0 && digits.len() > 1 { &digits[1..] } else { digits };
    if digits.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - digits.len()..].copy_from_slice(digits);
    Some((out, rest))
}

/// Parses a strict DER ECDSA signature into `r ‖ s`. Refuses long-form lengths (a P-256
/// signature never needs them), non-minimal integers and trailing bytes.
pub fn ecdsa_raw_from_der(der: &[u8]) -> Option<[u8; 64]> {
    let (&tag, rest) = der.split_first()?;
    let (&len, rest) = rest.split_first()?;
    if tag != 0x30 || len & 0x80 != 0 || usize::from(len) != rest.len() {
        return None;
    }
    let (r, rest) = read_der_integer(rest)?;
    let (s, rest) = read_der_integer(rest)?;
    if !rest.is_empty() {
        return None;
    }
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r);
    out[32..].copy_from_slice(&s);
    Some(out)
}

/// The fixed DER prefix of a P-256 `SubjectPublicKeyInfo` (id-ecPublicKey, prime256v1),
/// followed by the 65-byte uncompressed point.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// A P-256 public key as DER `SubjectPublicKeyInfo` (91 bytes).
pub fn p256_spki_der(key: &P256PublicKey) -> Vec<u8> {
    let mut out = P256_SPKI_PREFIX.to_vec();
    out.extend_from_slice(key.as_bytes());
    out
}

/// Reads a P-256 `SubjectPublicKeyInfo` back into the key.
pub fn p256_from_spki_der(der: &[u8]) -> Option<P256PublicKey> {
    let point = der.strip_prefix(&P256_SPKI_PREFIX[..])?;
    P256PublicKey::from_bytes(point).ok()
}

/// A P-256 public key as PEM (`-----BEGIN PUBLIC KEY-----`, base64 in 64-column lines,
/// each line and the footer ending in `\n`), the form Rekor stores for `hashedrekord`.
pub fn p256_pem(key: &P256PublicKey) -> String {
    let b64 = base64_encode(&p256_spki_der(key));
    let mut out = String::from("-----BEGIN PUBLIC KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END PUBLIC KEY-----\n");
    out
}
