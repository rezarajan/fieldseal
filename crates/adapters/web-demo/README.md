# fieldseal-adapters-web-demo

## Overview

A demo authority for the showcase web app, so the app works standalone ([ADR 0036](../../../docs/explanation/adr/0036-showcase-web-app-and-web-device.md); [web-app spec](../../../docs/reference/spec/web-app.md)). It embeds the parts of a Fieldseal deployment a browser device needs to register, receive a bundle, capture, export, upload and verify receipts, all over in-memory ports with development keys. **Development only, unattested.** Nothing here may run in production.

What it assembles:

- The `DemoWorld` from `fieldseal-adapters-memory` (root ceremony, purpose keys, trust bundle, transparency log), started two days before `now_ms`.
- Published content: every valid instrument in `examples_dir/instruments`, each layout in `examples_dir/layouts` naming one of them, rosters, and a release policy, each reviewed twice, signed by both publishers and logged (`src/content.rs`).
- The real registration `Factory` and the portal/API from `fieldseal-adapters-factory-http`, served on `Demo::factory_url`.
- The real `BuildBundle` under the release policy, sealed to the registered device's agreement key.
- The real intake gate and upload service over a live view of the factory's registry, served on `Demo::upload_url` by `UploadHttp` from `fieldseal-adapters-upload-http`.
- Plain-data reports for the web app to render (`src/reports.rs`).

## Interface

`src/lib.rs`:

- `DemoConfig` (`new(examples_dir)`): `seed` (default 1), `now_ms` (must be set to the real time), `factory_bind` and `upload_bind` (default `127.0.0.1:0`), `examples_dir`, `factory_public_url`, `upload_public_url`, `release_rosters_to_unattested` (default true).
- `Demo::start(config) -> Result<&'static Demo, String>`: builds the world, publishes the examples, binds both servers and serves each on its own thread (`demo-factory`, `demo-upload`). The `Demo` is leaked and lives until process end.
- `Demo` methods: `factory`, `factory_url`, `upload_url`, `examples`, `warnings`, `trust_bundle`, `publishing_policy`, `provisional_record_key`, `confirm_registration(tenancy_hex)`, `now`, `set_portal_login("alice" | "bob")`, `issue_registration_token(login)`, `provisioning_json`, `build_bundle(tenancy_hex)`, `build_bundle_for(tenancy_hex, instruments)`, `publications`, `checkpoint`, `entries`, `registrations`, `intake`, `fingerprint_of`, `cohorts`.
- `BundleReport` (sealed FSB1 bytes and what they hold) and `intake_subject(roster_id)`.

Re-exports: from `src/intake_world.rs` `IntakeWorld`, `IntakeReport`, `IngestReport`, `SubmissionReport`, `LossReport`, `LongRow` (with `rows_csv`), `RecordingStore`, `is_landed`; from `src/reports.rs` `PublicationReport`, `SignatureReport`, `ThresholdReport`, `ReviewerReport`, `InclusionReport`, `BuildReport`, `CheckpointReport`, `LogEntryReport`, `RegistrationReport`; from `src/support.rs` `LiveRegistry`. `src/support.rs` also holds crate-private adapters: `RealClock`, `OsRandom`, `TrackingStore`.

## Invariants

- Every key is derived from `DemoConfig::seed`; anyone knowing the seed can derive the authority's keys. The root ceremony is simulated.
- Devices are unattested (software evidence), accepted only because the factory runs with `UnattestedKeys::AllowNonProduction` (REG-017). With `release_rosters_to_unattested` the release policy releases rosters with a flag in its decision log; the device's attestation status is never altered (TRU-061, TRU-063).
- The factory URL must be `https` or `http` on a loopback host (`factory_url_ok`), else `start` fails. `now_ms` must be at least two days after the epoch, and at least one instrument must publish.
- The portal has no login form: `{factory_url}/sign-in` signs in at once as the development identity provider's current login (`alice`, role `collector`, unless `set_portal_login` chose `bob`).
- All state (registry, transparency log, submission store, data platform) is in memory and lost on restart.
- Intake reads the factory registry live on every request (`LiveRegistry`), so devices registered after start-up can upload.
- The factory's software attestation verifier accepts runtime builds whose identity begins `fieldseal-simulator` or `fieldseal-web`.
- `build_bundle` includes every published instrument, but the simulated runtime's opener imports exactly one; use `build_bundle_for` to name one. Bundles carry the rosters of every certified cohort.

## Side Effects

- Binds two TCP listeners and spawns two server threads, each handling one request at a time over plain HTTP.
- Reads `examples_dir` (`instruments/`, `layouts/`, `rosters/`) from the filesystem at start; no writes.
- Reads the monotonic clock (`Instant`) to advance authority time from `now_ms`; uses OS randomness for token secrets, nonces and session values.

## Verification

- Run: `cargo test -p fieldseal-adapters-web-demo`. Repo-wide: `just test`.
