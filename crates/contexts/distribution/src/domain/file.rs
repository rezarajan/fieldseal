//! The bundle file (WIRE-090–093, DIS-020–023): magic `FSB1`, then the canonical CBOR
//! `{"sealed", "signer", "chain", "sig"}`.
//!
//! Everything outside `sealed` is what the verifier reads before opening it, so it carries
//! nothing about the bundle's contents (DIS-022): the seal names only the recipient key, and
//! the signer, certificate chain and signature say who made it.

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::Signature;
use fieldseal_kernel::error::{ErrorCode, WireError};
use fieldseal_kernel::id::KeyId;
use fieldseal_kernel::seal::SealedBox;
use fieldseal_kernel::structure::Fields;
use fieldseal_kernel::value::Value;
use fieldseal_trust::domain::KeyCertificate;

/// The first four bytes of a bundle file: "FSB1" (WIRE-090).
pub const MAGIC: [u8; 4] = *b"FSB1";

/// The largest bundle file (WIRE-093, WIRE §6.7): 64 MiB.
pub const MAX_BUNDLE_FILE: usize = 64 * 1024 * 1024;

/// The most certificates a bundle file may present: the signer's own (TRU-014).
pub const MAX_CHAIN: usize = 1;

/// A bundle file: the sealed content, the factory key that signed it, and its signature.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BundleFile {
    /// The sealed `BundleContent` (WIRE-091).
    pub sealed: SealedBox,
    /// The factory signing key.
    pub signer: KeyId,
    /// The signer's certificate, or none when the recipient's trust bundle pins it.
    pub chain: Vec<KeyCertificate>,
    /// The signature over [`BundleFile::signed_structure`] under `fieldseal.dev/bundle/v1`.
    pub sig: Signature,
}

impl BundleFile {
    /// What the factory signs (DIS-021): the sealed envelope and the signer, never the
    /// plaintext.
    pub fn signed_structure(sealed: &SealedBox, signer: &KeyId) -> Value {
        cbor::map([("sealed", sealed.to_value()), ("signer", Value::Bytes(signer.as_bytes().to_vec()))])
    }

    /// The structure this file's signature is over.
    pub fn structure(&self) -> Value {
        Self::signed_structure(&self.sealed, &self.signer)
    }

    /// The file's bytes: magic, then canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let body = cbor::map([
            ("sealed", self.sealed.to_value()),
            ("signer", Value::Bytes(self.signer.as_bytes().to_vec())),
            ("chain", Value::Array(self.chain.iter().map(KeyCertificate::to_value).collect())),
            ("sig", Value::Bytes(self.sig.0.clone())),
        ]);
        let mut out = MAGIC.to_vec();
        out.extend(cbor::encode(&body).expect("a bundle file is encodable"));
        out
    }

    /// Reads a bundle file, checking in this order: the size against `max_size` (`E_SIZE`,
    /// before anything else is read, WIRE-093), the magic (`E_FRAME_MAGIC`), then the
    /// canonical CBOR and its fields (`E_CBOR_*`, `E_UNKNOWN_FIELD`).
    pub fn decode(bytes: &[u8], max_size: usize) -> Result<Self, WireError> {
        if bytes.len() > max_size.min(MAX_BUNDLE_FILE) {
            return Err(WireError::new(ErrorCode::Size, 0, "bundle file exceeds its size limit"));
        }
        let body = bytes
            .strip_prefix(&MAGIC)
            .ok_or(WireError::new(ErrorCode::FrameMagic, 0, "not a bundle file"))?;
        let mut f = Fields::new(cbor::decode(body).map_err(|e| e.shifted(MAGIC.len()))?)?;
        let sealed = SealedBox::from_value(f.take("sealed")?)?;
        let signer = KeyId::from(f.bytes_n::<16>("signer")?);
        let chain_values = f.array("chain")?;
        if chain_values.len() > MAX_CHAIN {
            return Err(WireError::new(ErrorCode::Sig, 0, "certificate chain is longer than the signer's own"));
        }
        let chain = chain_values.into_iter().map(KeyCertificate::from_value).collect::<Result<Vec<_>, _>>()?;
        let sig = Signature(f.bytes("sig")?);
        f.finish()?;
        Ok(Self { sealed, signer, chain, sig })
    }
}

/// The neutral file name of a bundle (DIS-023): `fieldseal-bundle-<date>-<sequence>.fsb`.
pub fn file_name(issued_millis: u64, sequence: u64) -> String {
    let (y, m, d) = civil_date(issued_millis / 86_400_000);
    format!("fieldseal-bundle-{y:04}{m:02}{d:02}-{sequence}.fsb")
}

/// The proleptic Gregorian date of a day count since 1970-01-01 (Hinnant's algorithm).
fn civil_date(days: u64) -> (i64, u32, u32) {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}
