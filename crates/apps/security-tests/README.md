# fieldseal-security-tests

## Overview
Adversarial tests for Fieldseal (issue #59): hostile bytes, replay, key misuse, leaks and injection. The crate has no production code. `src/` holds shared helpers used by the integration tests under `tests/` and by the cargo-fuzz harness in [`fuzz/`](./fuzz/README.md). See [ADR 0007](../../../docs/explanation/adr/0007-zero-trust-posture.md).

## Interface
- `Seeded`: reproducible xorshift64* generator (`new`, `next_u64`, `below`, `bytes`).
- `CANARIES` and `assert_no_canary(what, haystack)`: leak scan for planted values, including hex and byte forms.
- `to_high_s(signature)`: the high-`s` twin of a 64-byte P-256 signature (malleability, WIRE-022).
- `decoders::targets()` returning `Vec<Target>` where `Target = (&'static str, fn(&[u8]) -> Option<Vec<u8>>)`: every untrusted-bytes decoder across kernel, delivery, distribution, registration, trust, publishing, intake, collection and authoring, returning the re-encoding on acceptance.
- Test suites (in `tests/`): `decoder_hardening`, `bundle_attacks`, `registration_attacks`, `html_injection`.
- Fuzzing: [fuzz/README.md](./fuzz/README.md).

## Invariants
- A decoder must not panic, must return within a time bound, and an accepted input must re-encode to exactly itself (canonical form).
- Bundle import authenticates (factory signature) before it opens the seal.
- Rendered HTML (preview, portal) is inert: no event handlers or attribute breakouts.
- Canary values must never appear in outputs that must not carry them.
- All randomness is seeded, so failures reproduce.

- `tests/bundle_delivery.rs` (SR-2: a stolen token yields bytes only the device can open, a token for another URL is refused, a withheld tenancy is refused with reasons but still authenticates, no key in the bundle, the replay ledger is shared, no account gets another's cohort roster).
- `tests/operator_api.rs` (the operator routes: Bearer required, role, phishing resistance, no cookie accepted, no Bearer on the portal) and `tests/keycloak_realm.rs` (the realm file: API audience in access tokens only, `fieldseal-cli` public with PKCE, fixed `product-owner` id).

## Side Effects
- None in the library. Tests are in process over in-memory adapters; no ports or network.

## Verification
- Run: `cargo test -p fieldseal-security-tests` (repo-wide: `just test`)
- Open-ended fuzzing: see [fuzz/README.md](./fuzz/README.md).
