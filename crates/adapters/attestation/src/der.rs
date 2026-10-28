//! A minimal, strict DER reader for the X.509 certificates in attestation chains: just enough
//! to read the issuer, subject, validity, serial and P-256 public key, and to verify the
//! certificate's ECDSA-with-SHA256 signature. Anything else is refused, never skipped
//! silently (a certificate with an unexpected shape is not trusted).

use fieldseal_kernel::time::AuthorityTime;
use p256::ecdsa::signature::Verifier as _;
use sha2::{Digest as _, Sha256};

/// One DER element: its tag, its content, and the whole encoding.
#[derive(Clone, Copy)]
pub struct Tlv<'a> {
    /// The tag byte.
    pub tag: u8,
    /// The content octets.
    pub content: &'a [u8],
    /// Tag, length and content.
    pub raw: &'a [u8],
}

/// Reads one element from the front of `buf`, returning it and the rest. Only definite lengths
/// of up to four octets, in shortest form, and single-octet tags are accepted.
pub fn read(buf: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *buf.first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *buf.get(1)?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let bytes = buf.get(2..2 + n)?;
        if bytes[0] == 0 {
            return None;
        }
        let len = bytes.iter().fold(0usize, |a, b| (a << 8) | usize::from(*b));
        if len < 0x80 {
            return None;
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    let content = buf.get(header..end)?;
    Some((Tlv { tag, content, raw: &buf[..end] }, &buf[end..]))
}

/// Reads one element and requires `tag`.
pub fn expect(buf: &[u8], tag: u8) -> Option<(Tlv<'_>, &[u8])> {
    let (t, rest) = read(buf)?;
    (t.tag == tag).then_some((t, rest))
}

/// `id-ecPublicKey`, 1.2.840.10045.2.1.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `prime256v1`, 1.2.840.10045.3.1.7.
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2.
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/// What the verifier needs from one certificate.
#[derive(Clone, Debug)]
pub struct Certificate {
    /// The whole certificate, as presented.
    pub der: Vec<u8>,
    tbs: Vec<u8>,
    /// The issuer name, as encoded.
    pub issuer: Vec<u8>,
    /// The subject name, as encoded.
    pub subject: Vec<u8>,
    /// The serial number octets.
    pub serial: Vec<u8>,
    /// Start of validity.
    pub not_before: AuthorityTime,
    /// End of validity.
    pub not_after: AuthorityTime,
    /// The subject's P-256 key, uncompressed SEC1.
    pub public_key: [u8; 65],
    signature: Vec<u8>,
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn time(t: Tlv<'_>) -> Option<AuthorityTime> {
    let s = std::str::from_utf8(t.content).ok()?;
    let (year, rest) = match t.tag {
        0x17 if s.len() == 13 => {
            let yy: i64 = s.get(0..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, s.get(2..)?)
        }
        0x18 if s.len() == 15 => (s.get(0..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    if !rest.ends_with('Z') {
        return None;
    }
    let n = |a: usize| -> Option<i64> { rest.get(a..a + 2)?.parse().ok() };
    let (mo, d, h, mi, se) = (n(0)?, n(2)?, n(4)?, n(6)?, n(8)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    let secs = days_from_civil(year, mo, d) * 86_400 + h * 3600 + mi * 60 + se;
    u64::try_from(secs).ok().map(|s| AuthorityTime(s * 1000))
}

fn integer_to_32(t: Tlv<'_>) -> Option<[u8; 32]> {
    if t.tag != 0x02 {
        return None;
    }
    let mut c = t.content;
    while c.len() > 32 && c.first() == Some(&0) {
        c = &c[1..];
    }
    if c.is_empty() || c.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - c.len()..].copy_from_slice(c);
    Some(out)
}

/// Reads a DER `ECDSA-Sig-Value` as `r ‖ s`.
pub fn ecdsa_signature(der: &[u8]) -> Option<[u8; 64]> {
    let (seq, rest) = expect(der, 0x30)?;
    if !rest.is_empty() {
        return None;
    }
    let (r, rest) = read(seq.content)?;
    let (s, rest) = read(rest)?;
    if !rest.is_empty() {
        return None;
    }
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&integer_to_32(r)?);
    out[32..].copy_from_slice(&integer_to_32(s)?);
    Some(out)
}

/// Verifies ECDSA P-256 with SHA-256 of `message` by `public` (uncompressed SEC1), signature
/// `r ‖ s`. A high `s` is accepted: TPMs and certificate authorities do not normalise it.
pub fn verify_ecdsa(public: &[u8], message: &[u8], rs: &[u8; 64]) -> bool {
    let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(public) else { return false };
    let Ok(sig) = p256::ecdsa::Signature::from_slice(rs) else { return false };
    key.verify(message, &sig).is_ok()
}

/// The SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

impl Certificate {
    /// Parses a DER X.509 certificate with a P-256 key and an ECDSA-with-SHA256 signature.
    pub fn parse(der: &[u8]) -> Option<Self> {
        let (cert, rest) = expect(der, 0x30)?;
        if !rest.is_empty() {
            return None;
        }
        let (tbs, rest) = expect(cert.content, 0x30)?;
        let (alg, rest) = expect(rest, 0x30)?;
        let (sig, rest) = expect(rest, 0x03)?;
        if !rest.is_empty() || sig.content.first() != Some(&0) {
            return None;
        }
        let (oid, params) = expect(alg.content, 0x06)?;
        if oid.content != OID_ECDSA_SHA256 || !params.is_empty() {
            return None;
        }
        let mut body = tbs.content;
        if body.first() == Some(&0xa0) {
            let (_version, rest) = read(body)?;
            body = rest;
        }
        let (serial, body) = expect(body, 0x02)?;
        let (tbs_alg, body) = expect(body, 0x30)?;
        if tbs_alg.content != alg.content {
            return None;
        }
        let (issuer, body) = expect(body, 0x30)?;
        let (validity, body) = expect(body, 0x30)?;
        let (nb, v) = read(validity.content)?;
        let (na, v) = read(v)?;
        if !v.is_empty() {
            return None;
        }
        let (subject, body) = expect(body, 0x30)?;
        let (spki, _extensions) = expect(body, 0x30)?;
        let (key_alg, k) = expect(spki.content, 0x30)?;
        let (key_oid, k_params) = expect(key_alg.content, 0x06)?;
        let (curve, k_rest) = expect(k_params, 0x06)?;
        if key_oid.content != OID_EC_PUBLIC_KEY || curve.content != OID_P256 || !k_rest.is_empty() {
            return None;
        }
        let (bits, k) = expect(k, 0x03)?;
        if !k.is_empty() || bits.content.len() != 66 || bits.content[0] != 0 || bits.content[1] != 0x04 {
            return None;
        }
        let mut public_key = [0u8; 65];
        public_key.copy_from_slice(&bits.content[1..]);
        Some(Self {
            der: der.to_vec(),
            tbs: tbs.raw.to_vec(),
            issuer: issuer.raw.to_vec(),
            subject: subject.raw.to_vec(),
            serial: serial.content.to_vec(),
            not_before: time(nb)?,
            not_after: time(na)?,
            public_key,
            signature: sig.content[1..].to_vec(),
        })
    }

    /// Whether `issuer`'s key signed this certificate and names it as issuer.
    pub fn signed_by(&self, issuer: &Certificate) -> bool {
        self.issuer == issuer.subject
            && ecdsa_signature(&self.signature).is_some_and(|rs| verify_ecdsa(&issuer.public_key, &self.tbs, &rs))
    }

    /// Whether `at` lies within the certificate's validity.
    pub fn valid_at(&self, at: AuthorityTime) -> bool {
        self.not_before <= at && at <= self.not_after
    }
}
