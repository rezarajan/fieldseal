# Trust domain

## Overview

The entities, value objects and rules of the Trust bounded context (spec: [trust.md](../../../../../docs/reference/spec/trust.md) section 2). This module is pure: it does no I/O, reads no clock (every check takes an `AuthorityTime` from the caller) and depends only on `fieldseal-kernel`. Authority trust material is split by concept: `purpose` (key roles and signing tags), `certificate`, `revocation`, `bundle`, `chain` (verification), `root` (ceremony), `period` (collection periods) and `custody` (issuance custody rules, [ADR 0038](../../../../../docs/explanation/adr/0038-authority-key-custody-classes.md)). `mod.rs` also defines the device-key, attestation and key-holder value types that the driven ports in `../ports.rs` use. `wire.rs` is a private helper module for the encoders and decoders.

## Interface

Everything below is re-exported from `crate::domain`.

- **Roles and tags** (`purpose`): `KeyRole` (`Root` or `Purpose(Purpose)`), `KeyAlgorithm` (`P256`, `X25519`), `ValidityLimit`, and the functions `signer_role(tag)`, `may_sign(role, tag)`, `may_open(purpose, tag)`, `validity_limit(role)`.
- **Certificates** (`certificate`): `AuthorityPublicKey`, `CertificateRequest`, `IssueTerms`, `UnsignedCertificate` (`root`, `issue`, `finish`) and `KeyCertificate`.
- **Revocation** (`revocation`): `Revocation`, `UnsignedRevocation`, `RevocationTarget` (a key, or one certificate by serial) and `RevocationReason`.
- **Bundles** (`bundle`): `TrustBundle`, `UnsignedTrustBundle`, `TrustBundleContents`, `BundleSignature`, `BundleVersion`, `RuntimeBuild`, `LogPin`; `TrustBundle::check_update` decides whether a candidate may replace it.
- **Verification** (`chain`): `TrustStore` with `verify_chain`, `verify_certificate`, `verify_signature` and `with_revocations`.
- **Root ceremony and periods** (`root`, `period`): `Threshold`, `Ceremony`, `CeremonyRecord`; `CollectionPeriod`, `RecordKeyTerms` (`latest_not_after`, `may_destroy`), `Retention`.
- **Custody** (`custody`): `Mode`, `Assurance`, `Means`, `Custody`, `CustodyMinimum`, `RootTier`, `IssuanceRecord` (`to_text` and `from_text`), `AuditFinding`, `AuditIssue`, and the functions `establish`, `admit`, `check_hot_key_terms`, `check_rotation`, `audit`.
- **Errors** (`error`): `TrustError`. `TrustError::code()` maps wire-level failures to a kernel `ErrorCode`: `Sig` for every untrusted-signer case, `Tag` for `UntrustedTag`, `UnknownField` for `InvalidVersion`, the decoder's own code for `Wire` and `BadSignature`, and `None` for refusals to issue or build.
- **Device and attestation types** (`mod.rs`): `SecurityLevel`, `DeviceKeyKind`, `KeyProtection`, `KeyHandle`, `BootState`, `AttestationEvidence`, `AttestationClaims`, `PersonRef`, `HoldingBounds`, `KeyHolding`, `AccessContext`, `KeyUse`, `KeyOperation`, `CustodyKey`, `RevocationStatus`.

## Invariants

- A `KeyCertificate` that exists is valid: `key_id` equals the digest identifier of its public key, the role allows the key algorithm (roots and signing purposes P-256, `record` X25519, `registration` either), a collection period is present exactly on `record` keys, a root is issued by itself, validity is non-empty, and validity does not exceed the role limit (root 10 years, publisher 2 years, other purposes 1 year, `record` period plus retention).
- No identity attributes: `CertificateRequest::new` refuses any attribute at all (`IdentityAttributes`), and certificates have no field for names. A P-256 request needs a valid proof of possession before it can be issued.
- Chains have depth 1: only a root issues, and `TrustStore` accepts a signer only through a certificate issued by a root listed in its bundle. Verification order is root signature, role, root validity, certificate validity, then revocation. A revocation invalidates a signature when it names the certificate and its `effective` time is at or before the signing time.
- A `TrustBundle` is always internally valid: every signature, root, certificate and revocation was checked at construction, and lists are put in canonical order. An update must be for the same authority name, have a higher version, be signed by a current root, and be signed by every root it adds.
- A root ceremony needs a threshold with 2 <= m <= n, exactly `n` distinct custodians, at least one witness, and no witness who is also a custodian. The root certificate's validity must equal the ceremony's.
- A record key may be destroyed only once the period end plus retention has passed and no sealed data is outstanding.
- Custody: a production root refuses `development` assurance and any key ever recorded as `development`; a rotation may not lower assurance; `IssuanceRecord::from_text` refuses unknown lines and requires `evidence` exactly when assurance is `attested`.
- Structure decoding is strict: unknown fields give `E_UNKNOWN_FIELD`, an unknown version gives `E_VERSION`.

## Side Effects

None. All types are values; the module performs no I/O, reads no clock and generates no randomness. Signing is not done here: the domain builds the structure to sign (`signed_structure`), and the caller obtains the signature through the `KeyCustody` port (see `../application.rs`) and passes it to `finish`, which verifies it. Private records and key-holder mappings are only defined as types; storing them is the job of port adapters.

## Verification

`cargo test -p fieldseal-trust` (repo-wide runner: `just test`). Fixtures live in `../../tests/vectors/` (certificates, chains, revocations, trust bundles).
