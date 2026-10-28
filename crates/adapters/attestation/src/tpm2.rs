//! `tpm2-quote` for authority keys (TRU §6.2, TRU-110): TPM 2.0 key certification, verified
//! offline.
//!
//! The evidence is a canonical CBOR map `{"v": 1, "attest": bstr, "signature": bstr,
//! "public": bstr, "chain": [+ bstr]}`, where:
//! - `attest` is the `TPMS_ATTEST` a `TPM2_Certify` returned (TCG TPM 2.0 Library Part 2,
//!   §10.12): magic `TPM_GENERATED_VALUE`, type `TPM_ST_ATTEST_CERTIFY`, the challenge as
//!   `extraData`, and the certified object's `name`;
//! - `signature` is the `TPMT_SIGNATURE` over it (ECDSA, SHA-256) made by the attestation key;
//! - `public` is the certified key's `TPMT_PUBLIC`, whose SHA-256 must be the attested `name`;
//! - `chain` is the attestation key's X.509 certificate followed by its issuers, DER.
//!
//! Verified, in order: the chain to one of the trust bundle's attestation roots (each
//! certificate valid at the verifier's time, signed by the next, not revoked); the signature of
//! `attest` by the leaf's key; that `attest` is a certify attestation whose `extraData` is the
//! expected challenge; that its `name` is the digest of `public`; that `public` is a P-256 key
//! equal to the presented key; and that the key is `fixedTPM`, `fixedParent` and
//! `sensitiveDataOrigin`, which is what "generated inside the module and not exportable" means
//! for a TPM object. Only then are claims returned, and only those facts: nothing a TPM does
//! not attest about a runtime is invented (TRU-063, TRU-118).

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::P256PublicKey;
use fieldseal_kernel::id::Nonce;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::value::Value;
use fieldseal_trust::domain::{AttestationClaims, AttestationEvidence, DeviceKeyKind, SecurityLevel};
use fieldseal_trust::ports::{AttestationVerifier, RevocationSource, VerificationError};

use crate::der::{self, Certificate};

/// The evidence format this verifier handles.
pub const FORMAT: &str = "tpm2-quote";

const TPM_GENERATED: u32 = 0xff54_4347;
const ST_ATTEST_CERTIFY: u16 = 0x8017;
const ALG_ECC: u16 = 0x0023;
const ALG_SHA256: u16 = 0x000b;
const ALG_ECDSA: u16 = 0x0018;
const ALG_NULL: u16 = 0x0010;
const CURVE_P256: u16 = 0x0003;
const FIXED_TPM: u32 = 1 << 1;
const FIXED_PARENT: u32 = 1 << 4;
const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
const DECRYPT: u32 = 1 << 17;
const SIGN: u32 = 1 << 18;
/// The longest certificate chain accepted.
const MAX_CHAIN: usize = 5;

fn invalid(why: &str) -> VerificationError {
    VerificationError::Invalid(why.to_owned())
}

/// A cursor over TPM big-endian structures.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], VerificationError> {
        if self.0.len() < n {
            return Err(invalid("a TPM structure is cut short"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }

    fn u16(&mut self) -> Result<u16, VerificationError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| invalid("u16"))?))
    }

    fn u32(&mut self) -> Result<u32, VerificationError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| invalid("u32"))?))
    }

    fn sized(&mut self) -> Result<&'a [u8], VerificationError> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }

    fn done(&self) -> Result<(), VerificationError> {
        if self.0.is_empty() { Ok(()) } else { Err(invalid("trailing bytes after a TPM structure")) }
    }
}

struct Evidence {
    attest: Vec<u8>,
    signature: Vec<u8>,
    public: Vec<u8>,
    chain: Vec<Vec<u8>>,
}

fn decode(data: &[u8]) -> Result<Evidence, VerificationError> {
    let Value::Map(mut m) = cbor::decode(data).map_err(|e| invalid(&format!("evidence is not canonical CBOR: {e}")))? else {
        return Err(invalid("evidence is not a map"));
    };
    let bytes = |m: &mut std::collections::BTreeMap<String, Value>, k: &str| match m.remove(k) {
        Some(Value::Bytes(b)) => Ok(b),
        _ => Err(invalid(&format!("`{k}` is missing or not bytes"))),
    };
    if m.remove("v") != Some(Value::Int(1)) {
        return Err(invalid("unknown evidence version"));
    }
    let attest = bytes(&mut m, "attest")?;
    let signature = bytes(&mut m, "signature")?;
    let public = bytes(&mut m, "public")?;
    let Some(Value::Array(items)) = m.remove("chain") else { return Err(invalid("`chain` is missing")) };
    if items.is_empty() || items.len() > MAX_CHAIN {
        return Err(invalid("the chain must hold between one and five certificates"));
    }
    let chain = items
        .into_iter()
        .map(|v| match v {
            Value::Bytes(b) => Ok(b),
            _ => Err(invalid("a chain entry is not bytes")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !m.is_empty() {
        return Err(invalid("unknown field in the evidence"));
    }
    Ok(Evidence { attest, signature, public, chain })
}

/// Verifies TPM 2.0 key certification evidence for authority keys.
pub struct Tpm2CertifyVerifier<'a> {
    at: AuthorityTime,
    revocation: &'a dyn RevocationSource,
}

impl<'a> Tpm2CertifyVerifier<'a> {
    /// A verifier that judges certificate validity at `at` (authority time, injected: the
    /// adapter reads no clock) and asks `revocation` about every certificate in a chain.
    pub fn new(at: AuthorityTime, revocation: &'a dyn RevocationSource) -> Self {
        Self { at, revocation }
    }

    fn chain(&self, chain: &[Vec<u8>], roots: &[Vec<u8>]) -> Result<Certificate, VerificationError> {
        let certs: Vec<Certificate> = chain.iter().map(|c| Certificate::parse(c).ok_or_else(|| invalid("a certificate is not a P-256 X.509 certificate"))).collect::<Result<_, _>>()?;
        let anchors: Vec<Certificate> = roots.iter().filter_map(|r| Certificate::parse(r)).collect();
        if anchors.is_empty() {
            return Err(VerificationError::NoRoots(FORMAT.to_owned()));
        }
        for c in &certs {
            if !c.valid_at(self.at) {
                return Err(invalid("a certificate in the chain is not valid now"));
            }
            let status = self.revocation.status(&c.serial).map_err(|e| invalid(&format!("revocation status unavailable: {e}")))?;
            if status.revoked {
                return Err(VerificationError::Revoked);
            }
        }
        for pair in certs.windows(2) {
            if !pair[0].signed_by(&pair[1]) {
                return Err(invalid("a certificate in the chain is not signed by the next"));
            }
        }
        let last = certs.last().ok_or_else(|| invalid("empty chain"))?;
        let anchored = anchors.iter().any(|a| a.valid_at(self.at) && (a.der == last.der || last.signed_by(a)));
        if !anchored {
            return Err(invalid("the chain does not reach an attestation root in the trust bundle"));
        }
        Ok(certs[0].clone())
    }
}

impl AttestationVerifier for Tpm2CertifyVerifier<'_> {
    fn format(&self) -> &str {
        FORMAT
    }

    fn verify(
        &self,
        evidence: &AttestationEvidence,
        expected_challenge: &Nonce,
        key: &P256PublicKey,
        roots: &[Vec<u8>],
    ) -> Result<AttestationClaims, VerificationError> {
        if evidence.format != FORMAT {
            return Err(VerificationError::UnsupportedFormat(evidence.format.clone()));
        }
        let e = decode(&evidence.data)?;
        let ak = self.chain(&e.chain, roots)?;

        // The attestation key signed `attest` (TPMT_SIGNATURE: ECDSA, SHA-256, r, s).
        let mut s = Reader(&e.signature);
        if s.u16()? != ALG_ECDSA || s.u16()? != ALG_SHA256 {
            return Err(invalid("the attestation signature is not ECDSA with SHA-256"));
        }
        let (r, ss) = (s.sized()?, s.sized()?);
        s.done()?;
        if r.is_empty() || ss.is_empty() || r.len() > 32 || ss.len() > 32 {
            return Err(invalid("the attestation signature has a bad component"));
        }
        let mut rs = [0u8; 64];
        rs[32 - r.len()..32].copy_from_slice(r);
        rs[64 - ss.len()..].copy_from_slice(ss);
        if !der::verify_ecdsa(&ak.public_key, &e.attest, &rs) {
            return Err(invalid("the attestation signature does not verify"));
        }

        // TPMS_ATTEST.
        let mut a = Reader(&e.attest);
        if a.u32()? != TPM_GENERATED {
            return Err(invalid("the attestation was not generated by a TPM"));
        }
        if a.u16()? != ST_ATTEST_CERTIFY {
            return Err(invalid("the attestation is not a key certification"));
        }
        let _qualified_signer = a.sized()?;
        let extra = a.sized()?;
        a.take(17)?; // clockInfo: clock, resetCount, restartCount, safe
        a.take(8)?; // firmwareVersion
        let name = a.sized()?;
        let _qualified_name = a.sized()?;
        a.done()?;
        if extra != expected_challenge.as_bytes() {
            return Err(VerificationError::ChallengeMismatch);
        }

        // The certified object is `public`.
        let mut expected_name = ALG_SHA256.to_be_bytes().to_vec();
        expected_name.extend_from_slice(&der::sha256(&e.public));
        if name != expected_name {
            return Err(invalid("the certified name is not the digest of the presented public area"));
        }
        let mut p = Reader(&e.public);
        if p.u16()? != ALG_ECC || p.u16()? != ALG_SHA256 {
            return Err(invalid("the certified key is not an ECC key named by SHA-256"));
        }
        let attributes = p.u32()?;
        let _auth_policy = p.sized()?;
        if p.u16()? != ALG_NULL {
            return Err(invalid("a signing or agreement key has no symmetric algorithm"));
        }
        match p.u16()? {
            ALG_NULL => {}
            ALG_ECDSA => {
                p.u16()?;
            }
            _ => return Err(invalid("an unsupported signature scheme")),
        }
        if p.u16()? != CURVE_P256 || p.u16()? != ALG_NULL {
            return Err(invalid("the certified key is not on NIST P-256"));
        }
        let (x, y) = (p.sized()?, p.sized()?);
        p.done()?;
        if x.len() != 32 || y.len() != 32 {
            return Err(invalid("the certified point is malformed"));
        }
        let mut point = vec![0x04];
        point.extend_from_slice(x);
        point.extend_from_slice(y);
        if point != key.as_bytes() {
            return Err(VerificationError::KeyMismatch);
        }
        let inside = FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN;
        if attributes & inside != inside {
            return Err(invalid("the key is not fixed to the TPM and generated inside it"));
        }
        let kind = if attributes & SIGN != 0 {
            DeviceKeyKind::Signing
        } else if attributes & DECRYPT != 0 {
            DeviceKeyKind::Agreement
        } else {
            return Err(invalid("the key permits neither signing nor key agreement"));
        };
        Ok(AttestationClaims {
            security_level: SecurityLevel::Tpm,
            origin_generated: true,
            kind,
            challenge: *expected_challenge,
            os_patch_level: None,
            device_serial: None,
            unlocked_required: None,
            app_id: None,
            app_version: None,
            boot_state: None,
            bootloader_locked: None,
        })
    }
}
