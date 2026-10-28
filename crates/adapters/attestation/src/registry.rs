//! The authority-evidence formats and which of them can be verified here (TRU §6.2).

use fieldseal_kernel::crypto::P256PublicKey;
use fieldseal_kernel::id::Nonce;
use fieldseal_trust::domain::{AttestationClaims, AttestationEvidence, TrustBundle};
use fieldseal_trust::ports::{AttestationVerifier, VerificationError};

/// The evidence formats the spec registers for authority keys (TRU §6.2).
pub const AUTHORITY_FORMATS: [&str; 3] = ["tpm2-quote", "hsm-key-attestation", "cloud-kms-attestation"];

/// The formats a verifier exists for in this build.
pub const VERIFIABLE_FORMATS: [&str; 1] = ["tpm2-quote"];

/// Authority-evidence verifiers, one per verifiable format (TRU-060). Evidence in a registered
/// format with no verifier, or in an unknown one, is refused (TRU-062).
pub struct EvidenceVerifiers<'a> {
    verifiers: Vec<&'a dyn AttestationVerifier>,
}

impl<'a> EvidenceVerifiers<'a> {
    /// Uses `verifiers`.
    pub fn new(verifiers: Vec<&'a dyn AttestationVerifier>) -> Self {
        Self { verifiers }
    }

    /// Verifies `evidence` for `key` against the attestation roots `bundle` lists for its
    /// format. A format with no roots in the bundle is refused (`NoRoots`).
    pub fn verify(
        &self,
        bundle: &TrustBundle,
        evidence: &AttestationEvidence,
        challenge: &Nonce,
        key: &P256PublicKey,
    ) -> Result<AttestationClaims, VerificationError> {
        let verifier = self
            .verifiers
            .iter()
            .find(|v| v.format() == evidence.format)
            .ok_or_else(|| VerificationError::UnsupportedFormat(evidence.format.clone()))?;
        let roots = bundle.attestation_roots(&evidence.format);
        if roots.is_empty() {
            return Err(VerificationError::NoRoots(evidence.format.clone()));
        }
        verifier.verify(evidence, challenge, key, roots)
    }
}
