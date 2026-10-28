//! `AttestationVerifier` adapters for authority-key evidence (Trust, TRU-099, TRU-110).
//!
//! [`tpm2::Tpm2CertifyVerifier`] verifies TPM 2.0 key certification (`tpm2-quote`) offline
//! against the X.509 roots in the trust bundle's `attestation_roots`. The formats
//! `hsm-key-attestation` and `cloud-kms-attestation` are registered in the spec but have no
//! adapter here: each vendor's evidence is its own format, and a verifier cannot be written
//! honestly without the vendor's specification and root certificates. Evidence in those
//! formats is refused as unsupported ([`registry::EvidenceVerifiers`]), never trusted.
//!
//! [`testing`] builds synthetic evidence in the `tpm2-quote` layout for the shared verifier
//! suite. It is built to the TCG structures, not captured from a physical TPM.

pub mod der;
pub mod registry;
pub mod testing;
pub mod tpm2;
