# fieldseal-e2e

## Overview
Test support and test suites for the end-to-end and fault-injection flows (issues #61 and #58). It is a test-only crate (`publish = false`): `src/lib.rs` builds a whole deployment in process from the real contexts over the in-memory adapters; the suites in `tests/` drive it. Every key is a software key and unattested. Only the platform underneath (storage, clocks, key store, network) is simulated.

## Interface
- `Site`: the authority side: root ceremony, purpose keys, transparency log, the sample instrument published with threshold signatures, registration factory, bundle builder and registry (`new`, `register_online`, `enrol`, `factory`, `token`, `assign`, `build_bundle`, `set_cohorts`, `simulate_attestation`, `record`, `fingerprint`, `device_now`, ...).
- `Phone`: a simulated device (`provisioning`, `runtime`, `registration_request`); `Opener`: the bundle opener over a `SimulatedDevice`.
- `Intake` / `Enrolled`: gate, upload endpoint and data platform over the same keys (`gate`, `upload`); `Couriers`: delivery fakes.
- Helpers: `PIN`, `examples`, `example`, `profile`, `sample_instrument_document`, `roster`, `village_a`, `now`, `text`, `nr`, `household_answers`, `capture_household`, `intake_subject`, `Scratch` (temp directory with `write`/`read`), `every_cut` (runs a closure at every power-cut step).
- Suites (in `tests/`, not documented further): `connected`, `air_gapped`, `multi_device`, `faults_authority`, `faults_device`, `faults_export`.

## Invariants
- Everything is in process and deterministic (seeded randomness, fixed clock); no network.
- The pieces are the real ones: requests are built from the runtime's own keys and answered by the real factory, bundles are sealed to the device and opened by the runtime's opener, exports are checked by the real gate.
- After any injected fault, nothing the device acknowledged may be missing at intake, and nothing lands twice.
- Examples are read from the repository's `examples/` directory.

## Side Effects
- Library: none beyond `Scratch`, which creates and writes files in a temporary directory, and reading `examples/`.
- No ports are bound and no network calls are made.

## Verification
- Run: `cargo test -p fieldseal-e2e` (repo-wide: `just test`)
