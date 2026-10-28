# fieldseal-adapters-attestation

## Overview

`AttestationVerifier` adapters for authority-key evidence (Trust spec, TRU-099, TRU-110; see [trust.md](../../../docs/reference/spec/trust.md)). The crate verifies TPM 2.0 key certification (`tpm2-quote`) offline against the X.509 roots in a trust bundle's `attestation_roots`. The formats `hsm-key-attestation` and `cloud-kms-attestation` are registered in the spec but have no adapter: evidence in those formats is refused as unsupported, never trusted.

Layer: adapter. Depends on `fieldseal-kernel` (crypto, ids), `fieldseal-trust` (the port and domain types), `p256`, `sha2`. Implemented port: `fieldseal_trust::ports::AttestationVerifier`.

## Interface

Modules (all public, declared in `src/lib.rs`):

- `tpm2`
  - `FORMAT: &str = "tpm2-quote"`.
  - `Tpm2CertifyVerifier<'a>::new(at: AuthorityTime, revocation: &'a dyn RevocationSource)`; implements `AttestationVerifier` (`format()` and `verify(evidence, expected_challenge, key, roots) -> Result<AttestationClaims, VerificationError>`).
  - Evidence is a canonical CBOR map `{"v": 1, "attest", "signature", "public", "chain"}` (`TPMS_ATTEST`, `TPMT_SIGNATURE`, `TPMT_PUBLIC`, DER chain).
- `registry`
  - `AUTHORITY_FORMATS` (`tpm2-quote`, `hsm-key-attestation`, `cloud-kms-attestation`) and `VERIFIABLE_FORMATS` (`tpm2-quote`).
  - `EvidenceVerifiers<'a>::new(Vec<&dyn AttestationVerifier>)` and `verify(bundle, evidence, challenge, key)`: dispatches by `evidence.format`.
- `der`: minimal strict DER reader. `Tlv`, `read`, `expect`, `Certificate` (`parse`, `signed_by`, `valid_at`; fields `der`, `issuer`, `subject`, `serial`, `not_before`, `not_after`, `public_key`), `ecdsa_signature`, `verify_ecdsa`, `sha256`.
- `testing`: builds synthetic `tpm2-quote` evidence for the shared verifier suite (`Pki`, `Options`, `certificate`, `tpm_key`, `evidence`, `with_chain`, `SIGNING_KEY_ATTRIBUTES`, `AT`). Built to the TCG structures, not captured from a physical TPM.

## Invariants

- Verification order in `Tpm2CertifyVerifier`: decode; certificate chain to a bundle root (each certificate valid at the injected time, not revoked, signed by the next); signature over `attest` by the leaf key (ECDSA, SHA-256); `attest` is a certify attestation whose `extraData` equals the challenge; `name` is the digest of `public`; `public` is a P-256 key equal to the presented key; the key is `fixedTPM`, `fixedParent` and `sensitiveDataOrigin`. Only then are claims returned, and only facts the TPM attests.
- Evidence whose `format` differs from `tpm2-quote` yields `UnsupportedFormat`; a format with no verifier is `UnsupportedFormat`; a format with no roots in the bundle is `NoRoots`; a revoked certificate is `Revoked`.
- The DER reader refuses unexpected certificate shapes rather than skipping them.
- The verifier is deterministic: `testing` keys are derived from labels, so runs give identical bytes.

## Side Effects

- None. No filesystem, network, or hardware access; the verifier reads no clock (authority time is injected) and queries revocation only through the supplied `RevocationSource`.

## Verification

- Run: `cargo test -p fieldseal-adapters-attestation` (repo-wide: `just test`)
