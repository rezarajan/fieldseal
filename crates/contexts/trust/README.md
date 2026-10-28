# fieldseal-trust

## Overview

The Trust bounded context of Fieldseal: authority key hierarchy (offline root, one-purpose online keys, depth-1 chains), key certificates, root revocations, signed trust bundles, collection-period record keys, authority key custody classes, and the types and ports for device keys, attestation and key-holder records. Normative behaviour is in [trust.md](../../../docs/reference/spec/trust.md); layering follows [ADR 0028](../../../docs/explanation/adr/0028-clean-architecture.md) and trust model [ADR 0008](../../../docs/explanation/adr/0008-trust-hierarchy.md). The crate sits in the contexts layer: it depends only on `fieldseal-kernel` (plus `thiserror`, `rand_core` and `zeroize`), and its domain and use cases perform no I/O. Adapters implement the traits in `src/ports.rs`; bindings and apps call the use cases. The crate's code is under `src/`.

## Interface

`src/lib.rs` exposes four public modules and nothing else:

- `domain`: entities, value objects, rules and `TrustError`; documented in [./src/domain/README.md](./src/domain/README.md).
- `application`: use cases (driving side). `Authority<'a, C: KeyCustody + ?Sized>` (`new(custody, caller)`) offers `init_root`, `request`, `issue`, `open_collection_period`, `rotate` (returns `Rotation`), `revoke` and `build_bundle`. Each builds the structure in the domain, has `KeyCustody` sign it, and checks the signature before returning. Also `verify_chain(bundle, revocations, signer, chain, purpose, at)` (no port needed), `VerifyEvidence` (`new(verifiers)`, `verify(bundle, evidence, challenge, key)`), `SOFTWARE_EVIDENCE_FORMAT` (`"software"`) and `UseCaseError` (`Trust` or `Custody`).
- `ports`: driven ports the context owns, which adapters implement:
  - `KeyCustody` (`generate`, `sign`, `open`, `public_key`, `usage_log`), error `CustodyError`;
  - `SecureKeyStore` (device keys: `generate`, `sign`, `agree`, `wrap`, `unwrap`, `delete`, `exists`), error `KeyStoreError`;
  - `Attestor` (`evidence`), error `AttestorError`;
  - `AttestationVerifier` (`format`, `verify`), error `VerificationError`;
  - `RevocationSource` (`status`), error `RevocationSourceError`;
  - `AuthorityClock` (`now`);
  - `RandomSource` (`fill`, default `nonce`), and `SourceRng`, which adapts it to the kernel's `CryptoRng`;
  - `KeyHolderRegistry` (register, resolve, list and end holdings; reviewer lookup), error `HolderRegistryError`.
- `contract`: reusable contract tests for adapters: `key_custody_contract`, `secure_key_store_contract`, `attestor_contract`, `attestation_verifier_contract` (with `VerifierFixture`), `revocation_source_contract`, `authority_clock_contract`, `random_source_contract`, `key_holder_registry_contract`. Adapter crates call them from their own tests; each panics with a message naming the broken obligation.

Errors: `domain::TrustError` (maps to wire codes through `code()`), `application::UseCaseError`, and one error enum per port.

## Invariants

- `Authority` never signs without the domain having approved the structure first: `UnsignedCertificate`, `UnsignedRevocation` and `UnsignedTrustBundle` check every issuing rule on construction, and `finish` verifies the returned signature.
- Only a root issues certificates, revokes, or signs bundles; chains have depth 1. `rotate` leaves the old certificate unrevoked and refuses `record` keys and an unchanged public key; `open_collection_period` sets `not_after` to period end plus retention.
- `KeyCustody` contract: one role per key, private parts never exported, tags limited to the role (`may_sign`, `may_open`), signatures over the kernel's signed message, every use logged with key ID, role and caller; opened plaintext is `Zeroizing`.
- `VerifyEvidence` refuses evidence whose format has no configured verifier, and hardware formats for which the bundle lists no attestation roots; `software` evidence must yield unattested claims. Sufficiency of claims is not decided here.
- `KeyHolderRegistry` is access-controlled and offers no way to dump the whole mapping; holdings never appear in certificates, bundles or logs.
- No component reads a clock: authority time is always an input.

## Side Effects

None in this crate itself. `domain` and `application` are pure given their inputs, except that `Authority` calls `KeyCustody::generate` and `KeyCustody::sign` on the port it is given (which generates keys and appends to the custody use log) and `VerifyEvidence` calls the supplied `AttestationVerifier`s. All I/O (HSM or KMS access, platform key stores, vendor revocation lists, clock, randomness, holder records) is behind the `ports` traits. `contract` functions run against adapters and panic on violation.

## Verification

`cargo test -p fieldseal-trust` (repo-wide runner: `just test`). Test fixtures live in `tests/` (`tests/vectors/*.json`, `tests/common`).
