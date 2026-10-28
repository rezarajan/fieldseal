//! Synthetic `tpm2-quote` evidence for the shared verifier suite and for tests.
//!
//! The evidence is built to the TCG TPM 2.0 structures (`TPMS_ATTEST`, `TPMT_SIGNATURE`,
//! `TPMT_PUBLIC`) and to X.509 DER by a small encoder, signed by keys derived from labels, so
//! every run gives the same bytes. It is **not** captured from a physical TPM or from a vendor:
//! a recording from real hardware needs that hardware.

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::P256PublicKey;
use fieldseal_kernel::id::Nonce;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::value::Value;
use fieldseal_trust::domain::AttestationEvidence;
use p256::ecdsa::signature::Signer as _;
use sha2::{Digest as _, Sha256};

use crate::der::sha256;
use crate::tpm2::FORMAT;

/// A TPM object's attributes: fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth, sign.
pub const SIGNING_KEY_ATTRIBUTES: u32 = (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 18);

fn key_from(label: &str) -> p256::ecdsa::SigningKey {
    let seed = Sha256::digest(format!("fieldseal.dev/vectors/attestation/{label}").as_bytes());
    p256::ecdsa::SigningKey::from_slice(&seed).expect("a SHA-256 output is a valid scalar")
}

fn sec1(key: &p256::ecdsa::SigningKey) -> [u8; 65] {
    let point = key.verifying_key().to_sec1_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(point.as_bytes());
    out
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(content);
    out
}

fn name(cn: &str) -> Vec<u8> {
    let attr = tlv(0x30, &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, cn.as_bytes())].concat());
    tlv(0x30, &tlv(0x31, &attr))
}

fn integer(bytes: &[u8]) -> Vec<u8> {
    let mut b: Vec<u8> = bytes.iter().copied().skip_while(|x| *x == 0).collect();
    if b.is_empty() {
        b.push(0);
    }
    if b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    tlv(0x02, &b)
}

fn der_signature(rs: &[u8]) -> Vec<u8> {
    tlv(0x30, &[integer(&rs[..32]), integer(&rs[32..])].concat())
}

fn utc(secs: u64) -> Vec<u8> {
    // Civil-from-days (Howard Hinnant), valid for 1970 to 2049, which UTCTime covers.
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let text = format!("{:02}{:02}{:02}{:02}{:02}{:02}Z", y % 100, m, d, rem / 3600, rem % 3600 / 60, rem % 60);
    tlv(0x17, text.as_bytes())
}

/// Builds a DER certificate for `subject_key`, signed by `signer`.
#[allow(clippy::too_many_arguments)]
pub fn certificate(
    subject: &str,
    issuer: &str,
    serial: u8,
    not_before_secs: u64,
    not_after_secs: u64,
    subject_key: &[u8; 65],
    signer: &p256::ecdsa::SigningKey,
) -> Vec<u8> {
    let alg = tlv(0x30, &tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]));
    let spki = tlv(
        0x30,
        &[
            tlv(0x30, &[tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]), tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])].concat()),
            tlv(0x03, &[&[0u8][..], &subject_key[..]].concat()),
        ]
        .concat(),
    );
    let tbs = tlv(
        0x30,
        &[
            tlv(0xa0, &tlv(0x02, &[2])),
            integer(&[serial]),
            alg.clone(),
            name(issuer),
            tlv(0x30, &[utc(not_before_secs), utc(not_after_secs)].concat()),
            name(subject),
            spki,
        ]
        .concat(),
    );
    let sig: p256::ecdsa::Signature = signer.sign(&tbs);
    tlv(0x30, &[tbs, alg, tlv(0x03, &[&[0u8][..], &der_signature(&sig.to_bytes())[..]].concat())].concat())
}

/// A test attestation PKI: a root and the attestation key it certifies.
pub struct Pki {
    root_key: p256::ecdsa::SigningKey,
    ak_key: p256::ecdsa::SigningKey,
    /// The root certificate, DER: what the trust bundle lists in `attestation_roots`.
    pub root: Vec<u8>,
    /// The attestation key's certificate, DER.
    pub ak: Vec<u8>,
    /// The serial of the attestation key's certificate.
    pub ak_serial: Vec<u8>,
}

/// 2020-01-01 and 2040-01-01, in seconds: the certificates' validity.
const FROM: u64 = 1_577_836_800;
const TO: u64 = 2_208_988_800;

impl Pki {
    /// The PKI for `label`.
    pub fn new(label: &str) -> Self {
        let root_key = key_from(&format!("{label}/root"));
        let ak_key = key_from(&format!("{label}/ak"));
        let root = certificate("Test TPM Root", "Test TPM Root", 1, FROM, TO, &sec1(&root_key), &root_key);
        let ak = certificate("Test TPM AK", "Test TPM Root", 2, FROM, TO, &sec1(&ak_key), &root_key);
        Self { root_key, ak_key, root, ak, ak_serial: vec![2] }
    }

    /// An attestation key certificate with a validity that has ended by `at`.
    pub fn expired_ak(&self) -> Vec<u8> {
        certificate("Test TPM AK", "Test TPM Root", 3, FROM, FROM + 86_400, &sec1(&self.ak_key), &self.root_key)
    }
}

/// Knobs to build a deliberately wrong attestation.
#[derive(Clone, Copy)]
pub struct Options {
    /// The certified object's `objectAttributes`.
    pub attributes: u32,
    /// The attestation structure's type.
    pub attest_type: u16,
    /// The attestation structure's magic.
    pub magic: u32,
    /// Sign with a key that is not the leaf certificate's.
    pub wrong_signer: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { attributes: SIGNING_KEY_ATTRIBUTES, attest_type: 0x8017, magic: 0xff54_4347, wrong_signer: false }
    }
}

fn sized(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend((bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The certified key for `label` and its `TPMT_PUBLIC`.
pub fn tpm_key(label: &str, attributes: u32) -> (P256PublicKey, Vec<u8>) {
    let k = sec1(&key_from(&format!("tpm-object/{label}")));
    let mut public = Vec::new();
    public.extend(0x0023u16.to_be_bytes());
    public.extend(0x000bu16.to_be_bytes());
    public.extend(attributes.to_be_bytes());
    sized(&mut public, &[]);
    public.extend(0x0010u16.to_be_bytes());
    public.extend(0x0010u16.to_be_bytes());
    public.extend(0x0003u16.to_be_bytes());
    public.extend(0x0010u16.to_be_bytes());
    sized(&mut public, &k[1..33]);
    sized(&mut public, &k[33..]);
    (P256PublicKey::from_bytes(&k).expect("a real SEC1 point"), public)
}

/// Evidence that the TPM object `label` was created in a TPM, bound to `challenge`.
pub fn evidence(pki: &Pki, label: &str, challenge: &Nonce, opts: Options) -> (AttestationEvidence, P256PublicKey) {
    let (key, public) = tpm_key(label, opts.attributes);
    let mut object_name = 0x000bu16.to_be_bytes().to_vec();
    object_name.extend(sha256(&public));
    let mut attest = Vec::new();
    attest.extend(opts.magic.to_be_bytes());
    attest.extend(opts.attest_type.to_be_bytes());
    sized(&mut attest, &[&0x000bu16.to_be_bytes()[..], &sha256(b"qualified signer")[..]].concat());
    sized(&mut attest, challenge.as_bytes());
    attest.extend([0u8; 17]);
    attest.extend(0x0000_0001_0000_0000u64.to_be_bytes());
    sized(&mut attest, &object_name);
    sized(&mut attest, &object_name);
    let signer = if opts.wrong_signer { &key_from("some-other-ak") } else { &pki.ak_key };
    let sig: p256::ecdsa::Signature = signer.sign(&attest);
    let rs = sig.to_bytes();
    let mut signature = Vec::new();
    signature.extend(0x0018u16.to_be_bytes());
    signature.extend(0x000bu16.to_be_bytes());
    sized(&mut signature, &rs[..32]);
    sized(&mut signature, &rs[32..]);
    (with_chain(&attest, &signature, &public, std::slice::from_ref(&pki.ak)), key)
}

/// Assembles the evidence container.
pub fn with_chain(attest: &[u8], signature: &[u8], public: &[u8], chain: &[Vec<u8>]) -> AttestationEvidence {
    let value = cbor::map([
        ("v", Value::Int(1)),
        ("attest", Value::Bytes(attest.to_vec())),
        ("signature", Value::Bytes(signature.to_vec())),
        ("public", Value::Bytes(public.to_vec())),
        ("chain", Value::Array(chain.iter().cloned().map(Value::Bytes).collect())),
    ]);
    AttestationEvidence { format: FORMAT.to_owned(), data: cbor::encode(&value).expect("encodes") }
}

/// The authority time all fixtures are valid at: 2027-01-15.
pub const AT: AuthorityTime = AuthorityTime(1_800_000_000_000);
