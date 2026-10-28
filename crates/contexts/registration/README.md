# fieldseal-registration

## Overview

The Registration bounded context: how a collector's device becomes a registered tenancy at the factory. It owns single-use registration tokens, sealed registration requests, proof-of-possession and attestation checks, policy-gated confirmation and approval, tenancy certificates, close and reset certificates, device-lost handling, posture checks and runtime API authentication. Normative behaviour is in [the Registration spec](../../../docs/reference/spec/registration.md); layering follows [ADR 0028](../../../docs/explanation/adr/0028-clean-architecture.md).

The crate is pure: it performs no I/O, reads no clock and draws no randomness. Time, randomness, key custody, storage, identity, policy and logging all come through ports. It depends on `fieldseal-kernel`, `fieldseal-trust` and `fieldseal-policy` (and `thiserror`). Its code lives in `src/`:

- `domain/`: entities, wire forms and pure checks (see [./src/domain/README.md](./src/domain/README.md)).
- `application.rs`: use cases as methods of `Factory`.
- `ports.rs`: driven-port traits this context owns.
- `contract.rs`: contract-test functions every adapter must pass.

## Interface

`lib.rs` declares four public modules (`application`, `contract`, `domain`, `ports`) and re-exports nothing at the crate root. Domain types are documented in [./src/domain/README.md](./src/domain/README.md).

Use cases (`application`):

- `Factory::new(FactoryPorts, &TrustBundle, &EffectivePolicy, &FactoryConfig)` wires the use cases; it fails with `RegistrationError::Port` unless the signing key is a `registration` key certified in the bundle under one of its roots and the sealing key is an X25519 `registration` key in custody.
- Registration flow: `issue_token`, `submit(&SealedBox, Submission)`, `confirm`, `approve_held`, `reject_held`, `status`, `certificate`, `pending`, `held`, `list_devices`.
- Lifecycle: `mark_lost`, `retire`, `close(operator, tenancy, CloseReason)`.
- Runtime API: `posture_nonce`, `check_posture`, `authenticate_api` (PoP header), `issue_api_token`. Accessors: `sealing_key`, `bundle`, `policy`, `config`, `now`.
- Supporting types: `FactoryConfig`, `FactoryPorts`, `Submission` (`Online`, `Upload(AccountId)`), `Submitted`, `PostureOutcome`, `DeviceView`, `POP_WINDOW_MS` (300 s), `RegistrationError`.
- `RegistrationError` variants: `PolicyDenied`, `DeviceLimitReached`, `Authentication`, `NotAuthorised`, `Token`, `RouteMismatch`, `WrongAccount`, `NonceMismatch`, `ProofInvalid`, `EvidenceRejected`, `Malformed`, `Replay`, `NotPending`, `NotHeld`, `ConfirmationExpired`, `NotRegistered`, `Revoked`, `NotFound`, `TenancyExists`, `Port`.

Driven ports (`ports`), which adapters implement:

- `IdentityProvider` (`start_sign_in`, `finish_sign_in`; `SignInStart`, `PendingSignIn`, `IdentityError`).
- `RegistryStore` (tokens, accounts, tenancies, devices, nonces, PoP `jti`s, access tokens; `IssuedNonce`, `RegistryStoreError`, `TokenError`).
- `ReceivedProgress` (`highest_received`; `ProgressError`).
- `FleetRegistry` (`knows`).
- `Notifier` (`notify`; `PortalEvent`, `NotifierError`).

Ports owned by other contexts and used here: Trust's `KeyCustody`, `AttestationVerifier`, `AuthorityClock`, `RandomSource`; Policy's `PolicyEngine` and `DecisionLog`.

Contract tests (`contract`): `registry_store_contract`, `identity_provider_contract`, `received_progress_contract`, `notifier_contract`, `fleet_registry_contract`, and fixtures `sample_token`, `sample_tenancy`.

## Invariants

- A single-use token registers at most one tenancy, even under concurrent requests: `RegistryStore::consume_token` is atomic, and expiry is judged against the factory's clock.
- `submit` verifies in order: token, proof of possession, attestation evidence, then policy. The token is consumed only once the first three pass. Retrying the same request returns the existing result.
- A registration is `pending` until the account the token was issued to confirms the fingerprint words; policy `deny` is kept as `rejected` with reasons.
- A policy decision that cannot be logged is a deny (`decision-log-unavailable`); a policy-engine failure yields the decision point's failure verdict.
- Tenancy updates never remove keys from history (`RegistryStoreError::HistoryViolation`); posture nonces and PoP `jti`s are single use; PoP token `iat` must be within 300 s of the factory clock.
- `Notifier` failures are ignored; no security property depends on it.
- Adapters must not take authentication strength from configuration: `IdentityProvider` reports it from the provider's assertion or as `asserted`.

## Side Effects

- None inside the crate itself; all effects go through ports passed in `FactoryPorts`.
- Writes accounts, tokens, tenancies, devices, nonces and access tokens through `RegistryStore`.
- Signs tokens and certificates and opens sealed requests through Trust's `KeyCustody`.
- Appends every policy decision to Policy's `DecisionLog`.
- Sends best-effort `PortalEvent`s (`DeviceRegistered`, `DeviceMarkedLost`, `RegistrationHeld`) through `Notifier`; reads intake progress through `ReceivedProgress` to set cutoffs.

## Verification

`cargo test -p fieldseal-registration` (repo-wide: `just test`). Adapter crates verify their implementations with the functions in `contract`.
