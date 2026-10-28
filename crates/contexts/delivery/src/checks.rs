//! Trust-bundle checks: receipts (DEL-007, DEL-064) and receiver proofs (DEL-062).
//!
//! Both authorise solely by a certificate that chains to the trust root, is current and
//! unrevoked, and by a signature that verifies. Neither looks at an address, a domain name
//! or a TLS certificate (ADR 0021).

use fieldseal_collection::domain::ReceiptClaim;
use fieldseal_collection::ports::{ReceiptCheck, ReceiptCheckError};
use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::{Purpose, Signature, tags};
use fieldseal_kernel::id::{Digest, KeyId, Seq, TenancyId};
use fieldseal_kernel::structure::Fields;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, WireError};
use fieldseal_trust::domain::{TrustError, TrustStore};

use crate::domain::{ReceiverChallenge, ReceiverProof};
use crate::ports::{ReceiverCheck, ReceiverCheckError};

/// The most a receipt may take (WIRE-144).
pub const MAX_RECEIPT: usize = 300;

/// Reads a receipt's canonical bytes (WIRE-142) into the claim Collection's
/// [`ReceiptCheck`] verifies. The claim's `statement` is the canonical signed structure and
/// its fields are read from that same structure, so a claim can't say one thing and sign
/// another.
pub fn receipt_claim(bytes: &[u8]) -> Result<ReceiptClaim, WireError> {
    let Value::Map(mut map) = cbor::decode_limited(bytes, MAX_RECEIPT)? else {
        return Err(WireError::new(fieldseal_kernel::ErrorCode::UnknownField, 0, "a receipt is a map"));
    };
    let sig = map.remove("sig");
    let statement = cbor::encode(&Value::Map(map.clone()))?;
    let mut f = Fields::new(Value::Map(map))?;
    f.version("v", &Value::Int(1))?;
    let tenancy = TenancyId::from(f.bytes_n::<32>("tenancy")?);
    let last_seq = Seq(f.uint("last_seq")?);
    let journal_hash = Digest::from(f.bytes_n::<32>("hash_at")?);
    let time = AuthorityTime(f.uint("received")?);
    let _of = f.bytes_n::<32>("of")?;
    let signer = KeyId::from(f.bytes_n::<16>("signer")?);
    f.finish()?;
    let Some(Value::Bytes(sig)) = sig else {
        return Err(WireError::new(fieldseal_kernel::ErrorCode::UnknownField, 0, "a receipt carries sig"));
    };
    if sig.len() != fieldseal_kernel::sign::SIGNATURE_LEN {
        return Err(WireError::new(fieldseal_kernel::ErrorCode::Sig, 0, "a signature is 64 bytes"));
    }
    Ok(ReceiptClaim { tenancy, last_seq, journal_hash, time, signer, statement, signature: Signature(sig) })
}

/// A receipt as the text a QR code carries (`FS1R:` and the check value, WIRE-144), so an
/// air-gapped device can import it by scanning (DEL-043, DEL-044). `None` if it is over the
/// 300 bytes a single code holds.
pub fn receipt_qr_text(receipt: &[u8]) -> Option<String> {
    (receipt.len() <= MAX_RECEIPT).then(|| fieldseal_kernel::text::encode(fieldseal_kernel::text::RECEIPT_PREFIX, receipt))
}

/// Reads the receipts an upload response carries: a CBOR array of receipt byte strings, one
/// per tenancy part acknowledged (DEL-006). The receipts are unverified.
pub fn receipts_from_response(body: &[u8]) -> Result<Vec<ReceiptClaim>, WireError> {
    let bad = |detail| WireError::new(fieldseal_kernel::ErrorCode::UnknownField, 0, detail);
    let Value::Array(items) = cbor::decode_limited(body, 64 * MAX_RECEIPT)? else { return Err(bad("an upload response is an array")) };
    items
        .into_iter()
        .map(|v| match v {
            Value::Bytes(b) => receipt_claim(&b),
            _ => Err(bad("a receipt is a byte string")),
        })
        .collect()
}

/// [`ReceiptCheck`] against a trust bundle: the receipt must be signed under
/// `fieldseal.dev/receipt/v1` by a `receipt` key that chains to the bundle's root and was
/// valid and unrevoked at the receipt's stated time, whatever route the receipt came by
/// (DEL-064, DEL-042).
pub struct TrustReceiptCheck<'a> {
    store: TrustStore<'a>,
}

impl<'a> TrustReceiptCheck<'a> {
    /// Checks receipts against `store`.
    pub fn new(store: TrustStore<'a>) -> Self {
        Self { store }
    }
}

impl ReceiptCheck for TrustReceiptCheck<'_> {
    fn verify(&self, claim: &ReceiptClaim) -> Result<(), ReceiptCheckError> {
        let bad = |_| ReceiptCheckError::BadSignature;
        let structure = cbor::decode(&claim.statement).map_err(bad)?;
        // The claim's fields must be the ones the statement says.
        let mut with_sig = match &structure {
            Value::Map(m) => m.clone(),
            _ => return Err(ReceiptCheckError::BadSignature),
        };
        with_sig.insert("sig".to_owned(), Value::Bytes(claim.signature.0.clone()));
        let stated = receipt_claim(&cbor::encode(&Value::Map(with_sig)).map_err(bad)?).map_err(bad)?;
        if stated != *claim {
            return Err(ReceiptCheckError::BadSignature);
        }
        match self.store.verify_signature(&claim.signer, &[], &tags::RECEIPT, &structure, &claim.signature, claim.time) {
            Ok(_) => Ok(()),
            Err(TrustError::BadSignature(_)) => Err(ReceiptCheckError::BadSignature),
            Err(_) => Err(ReceiptCheckError::UntrustedSigner),
        }
    }
}

/// [`ReceiverCheck`] against a trust bundle at a given authority time: the answer must
/// carry a current, unrevoked `receiver` certificate chaining to the root, and that key's
/// signature over exactly this challenge (DEL-062, WIRE-181).
pub struct TrustReceiverCheck<'a> {
    store: TrustStore<'a>,
    now: AuthorityTime,
}

impl<'a> TrustReceiverCheck<'a> {
    /// Checks answers against `store`, with certificates judged current at `now`.
    pub fn new(store: TrustStore<'a>, now: AuthorityTime) -> Self {
        Self { store, now }
    }
}

impl ReceiverCheck for TrustReceiverCheck<'_> {
    fn verify(&self, challenge: &ReceiverChallenge, proof: &ReceiverProof) -> Result<KeyId, ReceiverCheckError> {
        let cert = &proof.certificate;
        if cert.purpose() != Some(Purpose::Receiver) {
            return Err(ReceiverCheckError::NotAuthorised);
        }
        match self.store.verify_signature(
            cert.key_id(),
            std::slice::from_ref(cert),
            &tags::RECEIVER_CHALLENGE,
            &challenge.to_value(),
            &proof.signature,
            self.now,
        ) {
            Ok(c) => Ok(*c.key_id()),
            Err(TrustError::BadSignature(_)) => Err(ReceiverCheckError::BadSignature),
            Err(_) => Err(ReceiverCheckError::NotAuthorised),
        }
    }
}
