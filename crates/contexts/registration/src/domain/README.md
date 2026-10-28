# Registration domain

## Overview

The pure core of the Registration bounded context: entities, value objects, tenancy and key states, the byte forms of tokens, requests, certificates and reports, and the fail-closed rules that judge authentication strength and attestation claims. It performs no I/O, reads no clock and draws no randomness; time and random values arrive as arguments, and the factory signs through `KeyCustody` and devices through their key store, so builders return the message to sign rather than taking a key. Normative behaviour is in [the Registration spec](../../../../../docs/reference/spec/registration.md).

Modules:

- `mod.rs`: accounts, roles, tokens, requests, tenancies, devices, keys, posture reports.
- `auth.rs`: authentication strength at the portal (REG-002, REG-002a).
- `checks.rs`: attestation sufficiency, runtime build acceptance, version ranges.
- `wire.rs`: deterministic-CBOR encodings (WIRE 5.9 to 5.13) and device-side builders.

## Interface

Entities and values (`mod.rs`):

- `AccountId`, `Account`, `Role` (`Collector`, `Operator`; `as_str`, `parse`), `DeviceId`, `RegisteredDevice`.
- `RegistrationToken` (signed, secret-bearing), `IssuedToken` (stored form: account, `expires_at`, `max_uses`, `AuthRecord`; `is_batch`), `TokenSecret` (16 bytes, `Debug` redacted), `RegistrationRoute` (`Online`, `AirGapped`).
- `RegistrationRequest` (decoded, structure-checked only), `KeyEvidence`, `RollProof`, `NonceSource` (`Factory`, `Device`), `FingerprintWords` (four indices into the 2048-word list; `from_indices`, `from_body_digest`, `indices`, `words`, `joined`).
- `TenancyRecord`, `TenancyState` (`Pending`, `Held`, `Rejected`, `Registered`, `Flagged`, `Lost`, `Closing`, `Closed`, `Retired`; `is_active`, `may_call_api`), `RegisteredKey`, `KeyState` (`Active`, `Rolled`, `Revoked`), `Window`, `CohortAssignment`, `TenancyTerms`.
- `CloseReason` (`Absent`, `ForgottenPin`, `Returned`, `Lost`, `Other`; `is_reset`), `ManagementMode`, `ReportedRestriction`, `PostureReport` (`gaps`), `AccessToken`, `policy_address`.
- `TenancyRecord` methods: `keeps_key_history`, `eligible_for_release`, `active_key`, `keys_attested`.
- Re-exports from `auth`: `AuthRecord`, `AuthenticatedPerson`, `AuthenticationMethods`, `MethodAssurance`.

`auth`: `check_authentication(policy, auth) -> Result<AuthRecord, AuthRefusal>`, `AuthRefusal` (`PhishingResistantRequired`, `AssertedNotAccepted`; `reason`), `phishing_resistant_from_claims`, `phishing_resistant_with`, `PHISHING_RESISTANT_AMR` (`hwk`, `swk`, `fido`, `sc`), `PHISHING_RESISTANT_ACR` (`phr`, `phrh`).

`checks`: `attestation_findings(...) -> Vec<String>` (kebab-case reason codes, empty when sufficient), `build_accepted`, `version_satisfies`, `UnattestedKeys` (`Refuse` default, `AllowNonProduction`).

`wire`:

- Constants: `MAX_REQUEST` and `MAX_POSTURE_REPORT` (64 KiB), `MAX_FACTORY_URL` (256), `REQUEST_FILE_MAGIC` (`FSRQ`).
- Token: `RegistrationToken::{signed_structure, to_value, encode, decode, to_text, from_text, verify}`, `TokenRefusal`, `factory_url_ok`, `root_fingerprint`.
- Request: `RequestBody` (`tenancy`, `encode`, `digest`, `pop_message`, `from_value`, `seal`), `decode_request`, `encode_request_file`, `decode_request_file`, `pop_structure`, `pop_message`, `verify_pop`.
- Certificates: `TenancyCertificate` and `CertifiedKey` (`signed_structure`, `encode`, `decode`, `verify`), `CloseCertificate` (`tag`, `encode`, `decode`, `to_text`, `from_text`, `verify`).
- Posture: `PostureBody` (`digest`, `pop_message`, `encode_report`), `decode_posture`.
- Helpers: `factory_sealing_key`, `device_key_id`, `value_uint`, and re-exports `base64url_encode`, `base64url_decode`, `PopToken`, `POP_HEADER`, `MAX_POP_TOKEN`.

## Invariants

- Fail closed: attestation facts the claims do not establish count as unmet; `version_satisfies` returns false for anything unparseable or an empty range.
- `check_authentication` refuses `Asserted` methods unless `accept_asserted_auth_methods` is set, then requires a phishing-resistant method when `require_phishing_resistant_auth` is set. Strength comes only from claims, never from issuer configuration.
- Unattested (`Software`) keys are accepted only under `UnattestedKeys::AllowNonProduction`; the default is `Refuse`.
- Keys are never removed from a tenancy's history (`keeps_key_history`). Only `Registered` tenancies are release-eligible; only `Registered` and `Flagged` may call the factory API; `Held`, `Registered` and `Flagged` count toward the device limit.
- Decoders refuse unknown fields, unknown versions and oversized input; signed structures are signed over `[tag, structure-without-sig]`. A request's tenancy ID must equal SHA-256 of `sign_pub`.
- Token `verify` requires the trust root to be a root of the device's bundle and a `registration` key certified by it; expiry is never evaluated by the device.
- `factory_url_ok` accepts `https` only, at most 256 bytes; plain `http` only for loopback hosts.
- `FingerprintWords::from_indices` rejects any index of 2048 or more. `TokenSecret` never prints its bytes.

## Side Effects

None. Everything here is pure computation over values passed in; randomness is supplied by the caller to `RequestBody::seal`. I/O, clocks, key custody and storage belong to the ports in [`../ports.rs`](../ports.rs) and the use cases in [`../application.rs`](../application.rs).

## Verification

`cargo test -p fieldseal-registration` (repo-wide: `just test`).
