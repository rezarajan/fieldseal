# Drift Report — EGM contracts (2026-10-28)

Scope: the 57 README contracts created or updated by the EGM bootstrap run on 2026-10-28, checked against the current source by five Opus 5.5 drift reviewers. Only divergences are listed. Items marked *(Fixed in this run)* were corrected after the review.

## crates/contexts/trust/README.md

No drift detected.

## crates/contexts/trust/src/domain/README.md

- Minor omission: public `TrustStore::new`, `TrustStore::bundle` (src/domain/chain.rs:28,44) and `ROOT_MAX_VALIDITY_MS` (src/domain/purpose.rs:121) are not listed.

## crates/contexts/instrument/README.md

No drift detected.

## crates/contexts/instrument/src/application/README.md

No drift detected.

## crates/contexts/instrument/src/domain/README.md

- "Submodules (re-exported from `mod.rs`)" is inaccurate: submodules are `pub mod`, and `mod.rs` re-exports only selected items (src/domain/mod.rs:27-42); e.g. `compile::compile`, `locale::LocaleFormatter`, `message::parse_message` are reachable only via their modules.
- Invariant "a `Layout` only through `validate_layout`" is wrong: `application::default_layout` (src/application/layout.rs:122) also builds one, used for `PlanLayout::Default` (src/application/render.rs:62-64).
- Missing re-exports: `Code`, `CodeList`, `Concept`, `MediaRef`, `Nonresponse`, `OtherCode` (mod.rs:27); `Emphasis`, `InstrumentReference`, `Navigation`, `Presentation`, `RepeatAs` (mod.rs:36); `LayoutIdentity` (mod.rs:38); `SchemaRangeError` (mod.rs:42).
- Minor: `MAX_TABLE_ROWS` limits total rows across all lookup tables (src/domain/compile.rs:30; src/application/decode.rs:772), not per table.

## crates/contexts/instrument/src/domain/rules/README.md

- "`check` requires every `PathRef::Sibling` resolved first (INS-047)" is wrong: `check` returns `Ty::Any` for siblings without error; compilation enforces it (src/domain/rules/check.rs:142-143).
- Minor: public `CheckError { kind, message }` (check.rs:73) and `Val::is_set`/`Val::truthy` (eval.rs:37,42) not mentioned.

## crates/contexts/policy/README.md

- Minor: `DecisionLog::append` returns `Result<u64, DecisionLogError>`, not `u64` (src/ports.rs:82); same for `read`.

## crates/contexts/policy/src/domain/README.md

- "All items are re-exported from `domain`" is false (src/domain/mod.rs:27-42): `API_VERSION`, `KIND` (document.rs:17,19), `control_spec`, `SCHEMA_VERSION_MAJOR`, `SECTIONS` (schema.rs:214,15,18) and the `invariant` floor constants are module-only.
- Missing public items: `ControlSpec` (schema.rs:22), `merge::describe` (merge.rs:56), `schema::is_group`, `children`, `PER_KIND_GROUPS` (schema.rs:219-236); `LockTrigger` (re-exported, mod.rs:39) only mentioned in passing.

## crates/contexts/publishing/README.md

No drift detected.

## crates/contexts/publishing/src/domain/README.md

- "A missing checkpoint time token counts as too old" is attributed to `TreeHeadTracker`, but belongs to `verify::check_tree_head_age` (src/domain/verify.rs:135-151); the tracker has no time-token notion (checkpoint.rs:259-317).
- "Re-exported from `mod.rs`" heading is inaccurate for verification items, merkle functions and `secrets::find_secrets` (src/domain/mod.rs:26-38); low impact since items are labelled by module.
- Minor: `MAX_NOTE`, `MAX_NOTE_SIGNATURES` (checkpoint.rs:35,38) and `statement::entry_signature_der` (statement.rs:259) not named.

## crates/contexts/registration/README.md

- "Pending until the account confirms the fingerprint words" is incomplete: with `require_fingerprint_confirmation` false, `submit` approves immediately (src/application.rs:597-599).
- Undocumented: a request for a device with a live tenancy is stored `Held` with reason `device-has-live-tenancy` (src/application.rs:588-592).
- "Policy `deny` kept as `rejected`" conflates two paths: rejection in `submit` comes from the local `sufficiency` attestation check (application.rs:474,580-586); the `PolicyEngine` `RegistrationApprove` deny happens later in `approve` (application.rs:681,692-696).

## crates/contexts/registration/src/domain/README.md

- `CertifiedKey` is listed with `signed_structure/encode/decode/verify`, but it is a plain two-field struct with no methods (src/domain/wire.rs:429-435); `TenancyCertificate` also has unlisted `to_value`/`from_value` (wire.rs:513,523).
- Minor: `TokenSecret::from_bytes`/`as_bytes` (mod.rs:106,111), `AuthenticatedPerson::has` (auth.rs:76), `RegistrationRequest::fingerprint_words` (mod.rs:279) not mentioned.

## crates/contexts/README.md

- Delivery bullet lists ports as if complete; Delivery also owns `RegistrationRecords` (delivery/src/ports.rs:63) and `ReceiverCheck` (delivery/src/ports.rs:84). The other nine port lists match. *(Fixed in this run.)*

## crates/contexts/distribution/README.md

No drift detected.

## crates/contexts/distribution/src/application/README.md

- Verification-order invariant omits POL-052 applied-version monotonicity (`applied.admit`, verify.rs:190-194), roster generation must equal the certificate's (`StaleGeneration`, verify.rs:330-342), and unreferenced roster fields refused (`UnreferencedRosterField`, verify.rs:326-328).
- "No version or generation below held" is inaccurate: version is compared only within equal generation (`Roster::may_be_followed_by`, domain/roster.rs:97-108).
- "Fetch/download deliver the latest stored bundle" omits that `FetchBundle::fetch` returns `None` if the held bundle is current (fetch.rs:62) and `download` resolves the device's last tenancy (fetch.rs:72).

## crates/contexts/distribution/src/domain/README.md

- Roster succession: generation non-decreasing, version non-decreasing only within the same generation (roster.rs:101-106).
- Malformed/inauthentic time token returns `PublishingError::CheckpointTime` (time_token.rs:44-46); only a missing token takes the too-old path.
- Omits rule that a publication listed twice is rejected (content.rs:180-185).
- Omits `TimeToken::signed_structure`, `to_value`, `from_value` (time_token.rs:71,84,96).

## crates/contexts/collection/README.md

- Claims Delivery reuses `ReceiptCheck` "as its `ReceiptVerifier`"; no `ReceiptVerifier` exists. Delivery takes `ReceiptCheck` directly (delivery/src/application.rs:176) and provides `TrustReceiptCheck` (delivery/src/checks.rs:76).

## crates/contexts/collection/src/application/README.md

- Close erasure list omits what survives: the device-class `policy-versions` object is never deleted (close.rs:206), and the outbox entry stays.
- Recovery omits that orphaned `pending/…` entries are always deleted (recover.rs:111-115) and a close without an outbox entry completes at next unlock (recover.rs:140-142,157-178).

## crates/contexts/collection/src/domain/README.md

No drift detected.

## crates/contexts/delivery/README.md

- Label text uses an em dash: "Handed over — not confirmed" (domain.rs:76), not a hyphen.
- "Export verified in full before offered" holds for `build_export`/`build_outbox_export` (application.rs:360,386) but `upload` sends without `export::verify` (application.rs:654-660).
- DEL-029 unlocked-session requirement applies only to `build_export` (application.rs:347); `upload`, `upload_outbox`, `background_tick` use `export_source(false)` (application.rs:649,691,738).
- Side Effects omits the `upload-retry/<tenancy>` marker written by `background_tick` (application.rs:736-763).
- Invariants omit DEL-063 per-session refusal to retry failed-challenge addresses (application.rs:580,598-607) and the `NoNetwork` vs `NoAuthorisedDestination` mapping (application.rs:613).

## crates/contexts/intake/README.md

- "An error enum per port" is false for `PopLedger::first_use`, which returns `Result<bool, String>` (ports.rs:26).
- KeyCustody side effects omit receiver-challenge signing in `UploadService::answer_challenge` (upload.rs:79-83).
- Consent side effects omit `DataPlatform::reinstate` on accept (application.rs:157).
- PoP `iat` window is symmetric ±300 s (`abs_diff`, upload.rs:108); `authenticate` also refuses deny-listed tenancies (upload.rs:102-104).

## crates/contexts/intake/src/gate/README.md

- `dry_run` still stores raw bytes via `SubmissionStore::put` (gate/mod.rs:219-221) and signs receipts via `KeyCustody::sign` (gate/landing.rs:171-174); only `DataPlatform::land` is gated (gate/landing.rs:199).
- Side Effects omit `DataPlatform` reads (`envelopes` gate/landing.rs:53, `observations` gate/replay.rs:128 and gate/landing.rs:116, `evidence` gate/consent.rs:345) and policy-engine evaluation in stages 10-11.

## crates/contexts/deployment/README.md

- "Also uses Publishing's `ArtefactRegistry`" is false: no source uses `fieldseal_publishing` (only a doc comment at ports.rs:2); the Cargo.toml dependency appears unused.
- `development` bindings are refused in every tier except `Development` (`Tier::refuses_development`, custody.rs:51-53), including staging, not only production (custody.rs:136,180).
- Omits custody findings: hardware adapter declared `development` (custody.rs:121-123) and `hot` binding marked `offline` (custody.rs:128-130).
- Omits `Component::SERVICES` (domain.rs:71), `Release::to_value`, `Release::is_address` (release.rs:51,56).

## crates/adapters/README.md

- The boundary sentence omits that adapters may depend on other adapters, which several do: file and landing-files → memory; upload-http → memory, file, landing-files; web → authoring, html, memory; web-demo → memory, authoring, factory-http, upload-http (their Cargo.toml). *(Fixed in this run.)*

## crates/adapters/attestation/README.md

No drift detected.

## crates/adapters/authoring/README.md

- Dependency list omits `base64` and `unicode-normalization` (Cargo.toml), which back `!!binary` and the NFC check.
- `decode_path` also reports an unsupported/missing extension as `ErrorKind::Encoding` at 0:0 (src/lib.rs:126).

## crates/adapters/factory-http/README.md

- Route table omits unauthenticated `GET /healthz` and `GET /readyz` (src/lib.rs:329-330).
- Portal route paths are not named: `GET /`, `GET /sign-in`, `GET /sign-in/callback`, `POST /sign-out`, `POST /tokens`, `POST /pending/{id}/confirm`, `POST /devices/{id}/{lost|retire}`, `POST /uploads`, `GET /tenancies/{id}/certificate.cbor` (src/lib.rs:350-376).
- The 413 body limit is applied only in `run` (src/lib.rs:302-305); `handle` does not check `MAX_BODY`.
- Dependency list omits `thiserror`.

## crates/adapters/file/README.md

- Roster files are mode 0o644 (world-readable), not "restricted" (src/rosters.rs:42-45).
- `FileRegistryStore` exits the process (`std::process::exit(1)`) on journal write/`sync_data` failure (src/store.rs:146-149); fsync per append is not documented.
- `PublishedInstruments`: after a publication verifies, CBOR decode failure returns `Unavailable` and `validate_instrument` failure returns `Ok(None)` without trying later files (src/instruments.rs:46-47).

## crates/adapters/html/README.md

No drift detected.

## crates/adapters/landing-files/README.md

- Full rewrite covers only the three CSVs (src/lib.rs:177-197); `contracts/<instrument>.json` is written only by `write_contract`.
- `observations.csv` has both an `excluded` boolean and an exclusion-reason column (src/lib.rs:144-145).

## crates/adapters/memory/README.md

No drift detected.

## crates/adapters/oidc/README.md

No drift detected.

## crates/adapters/opa/README.md

- `bundled_policy_dir()` uses compile-time `CARGO_MANIFEST_DIR`, so a relocated binary points at the build tree (src/lib.rs:37-40).
- Binary mode spawns two helper threads per evaluation to drain stdout/stderr (src/lib.rs:356-362,375-376).

## crates/adapters/policy/README.md

No drift detected.

## crates/adapters/rekor/README.md

- On 409, `send` issues a follow-up `GET /api/v1/log/entries/{uuid}` that `render` does not produce (src/lib.rs:242-253), so "exactly one HTTP request" per transmission is false.
- Public `HttpRequest` (`method`, `url`, `body`) not listed (src/lib.rs:108).

## crates/adapters/translog/README.md

- `FileLogStore::open` does not create `head`; it is first written by `append_entry` via `head.tmp` + rename (src/store.rs:259-271).
- Append side effects omitted: write+fsync `log.dat`, write `head.tmp`, rename, fsync directory (src/store.rs:181-195,259-263); truncation on failed write (184-187); `open` writes `FSTLOG01` magic to a new log (290-293).
- Server also returns 405 for wrong method and 400 for a GET with a body (src/wire.rs:129-136).
- "Records over 1024 bytes are refused" is enforced only at replay on open (src/store.rs:310), not in `append_entry`.

## crates/adapters/upload-http/README.md

- Binary flags omit repeatable `--device` (src/bin/server.rs:262); `FIELDSEAL_UPLOAD_PUBLIC_URLS` defaults to `http://{listen}` (278-280); any `FIELDSEAL_UPLOAD_AUTHORITY` other than `stack` selects practice mode.
- `run` adds `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` (src/lib.rs:128).
- Exit codes 3 (bind failure) and 2 (stack world build failure) undocumented (server.rs:268-288).

## crates/adapters/web/README.md

- `device` interface omits `RegistrationRequest` (src/device.rs:696) and `HeldInstrument` (device.rs:710).
- `Provisioned` JSON keys not named: required `trustBundle`, `buildAnchor`, `provisionalRecordKey`; optional `authority`, `allowedBuilders`, `allowedSources`, `factoryUrl`, `uploadUrl` (device.rs:78-104).

## crates/adapters/web-demo/README.md

No drift detected.

## crates/apps/README.md

No drift detected.

## crates/apps/cli/README.md

- `device capture` is listed as making a network upload; it builds an `HttpUploadTransport` (device/stack.rs:138) but never sends, only writes the export if `--export` is given (146-152). The only network upload is `export upload`; `device simulate --upload` / `export build --upload` go to the in-process intake (device.rs:131-142).
- `device capture --export` is optional (device/stack.rs:149); required flags are `--device-dir --trust-bundle --bundle --script` (81-84).
- The `--json` envelope (`command`, `ok`, `exitCode`, `findings`) is not universal: `device capture` (device/stack.rs:158), `conformance run --json` (conformance_cmd/mod.rs:358-365) and `adapters --json` (main.rs:163) differ.
- `registry --log-url` falls back to `FIELDSEAL_TRANSLOG_URL` (registry_cmd.rs:89).
- `trust` "shared" flags `--custody --at --caller` apply only to `root-init`, `issue`, `bundle`, `revoke`; `show`/`verify` differ (trust_cmd.rs:37,57-58).

## crates/apps/cli/src/conformance_cmd/README.md

No drift detected.

## crates/apps/e2e/README.md

- Interface omits exported macros `device!` (src/lib.rs:750-760) and `delivery!` (641-662), and public `Site::person`, `Site::bundle_request` (286,331).
- Side Effects omits that `every_cut` spawns up to 8 OS threads (src/lib.rs:766-786).
- `Scratch` deletes its `fieldseal-e2e-<name>-<pid>` temp dir on `Drop` (src/lib.rs:722,741).

## crates/apps/factory/README.md

- Cited test `dep_012_the_rendered_environment_configures_the_factory` does not exist outside the `main.rs:26` comment.
- `deployment render` writes more variables than the factory reads (`FIELDSEAL_DEPLOYMENT`, `_COMPONENT`, `_LOG_FORMAT`, `_TRUST_BUNDLE_REF`, `_POLICY_LAYERS`, `_TIER`, `FIELDSEAL_ADAPTER_*`; contexts/deployment/src/render.rs:118-134).
- Strict non-empty/no-whitespace rule is bypassed by the `secret()` path for OIDC client id/secret, `_REF` forms and `FIELDSEAL_SECRET_*` (main.rs:151-158).
- Undocumented startup failure: non-https (non-loopback) OIDC issuer exits 1 (adapters/oidc/src/lib.rs:155-158; main.rs:338).
- Production can never start: `FIELDSEAL_CUSTODY` is required (main.rs:213) and both values are refused in production (215,219); the README implies otherwise.
- `cargo test -p fieldseal-factory` runs no tests (none exist).
- Minor: `FIELDSEAL_OIDC_ROLES_CLAIM` defaults to `roles` (oidc/src/lib.rs:74); `getrandom` failure panics (main.rs:67).

## crates/apps/translog/README.md

- Key generation panics on OS randomness failure (src/main.rs:30) instead of exiting 78/69.

## crates/apps/web/README.md

- Oversized-body 413 is built in `main.rs:154` without `dispatch` (still `.secured()`).
- `/device/bundle`: stack mode requires `instrument` (device.rs:47); demo mode requires only `tenancy` (55-59); only demo mode returns the full `X-Bundle-*` header set (49 vs 61-65).
- Stack mode also writes issued rosters to `/published/rosters` and reads `/opt/fieldseal/examples/rosters` (stack.rs:86-91).
- `device.js` also calls `localStorage.clear()` on reset (assets/device.js:1098,1111).
- `MAX_INGEST_BODY` applies only to the exact URL `/intake/ingest`; a query string falls back to `MAX_BODY` (main.rs:151).

## crates/apps/security-tests/README.md

No drift detected.

## crates/apps/security-tests/fuzz/README.md

No drift detected.

## crates/kernel/README.md

- Interface lists a `Challenge` id type that does not exist; the 32-byte challenge id is `Nonce` (crates/kernel/src/id.rs:87-91).
- Invariant "HPKE with `info` = domain tag" is true only for `seal`/`open`; `seal_with_context`/`open_with_context` use tag ‖ 0x00 ‖ context (crates/kernel/src/seal.rs:215-226, DIS-020).
- Structure-reader invariant omits that `Fields::version` returns `E_VERSION` on mismatch (crates/kernel/src/structure.rs:79-86).
- Two different `Tick` types are not distinguished: `time::Tick` (src/time.rs:36) and `payload::Tick` (src/payload.rs:21).
- Public API missing: `SigningKey::generate`/`public_key` (src/sign.rs:41,46); `FRAME_VERSION`, `FRAME_FLAGS` (src/frame.rs:10,12); `qr_sequence::MESSAGE_ID_LEN` (src/qr_sequence.rs:44); `ContentAddress::of/to_text/parse_text`, `Fingerprint::short_form` (src/digest.rs:48-69); `DomainTag::known/expect/usage` and remaining `tags::*`; `LocalEntry::seal/open`.
- Text prefixes listed by value, not by their constant names `TOKEN_PREFIX`, `CLOSE_PREFIX`, `RECEIPT_PREFIX`, `TIME_TOKEN_PREFIX` (src/text.rs:13-19).

## crates/bindings/README.md

- Overview credits `tools/build.sh` and the flake without saying which builds what: `tools/build.sh` builds only UniFFI/Android and Python; wasm is built only by the flake (flake.nix:186-202).

## crates/bindings/python/README.md

- Binding-raised `WireError` codes are missing: `E_CBOR_NONCANONICAL` for null/non-data-model JSON (src/lib.rs:24-26) and `E_CBOR_DUPLICATE` for duplicate keys (src/lib.rs:83); only `E_SIZE` is named.
- Minor: `fingerprint` with a bad salt length is the only call raising a plain `ValueError` rather than `WireError` (src/lib.rs:49); not called out.

## crates/bindings/uniffi/README.md

- Dependency list omits `uniffi` 0.32.2 with the `cli` feature (Cargo.toml:20); `thiserror` is declared but unused in src/lib.rs.
- Bindgen command hard-codes `libfieldseal_uniffi.so`; tools/build.sh:51 uses `.$HOST_LIB_EXT` (`dylib` on macOS, build.sh:11).

## crates/bindings/wasm/README.md

- Side Effects omits browser randomness via `getrandom` with the `js` feature (Cargo.toml:30).
- Minor: `options` also accepts `"layout": null` (src/lib.rs:33); the parser is duplicated as `options_of` (lib.rs:34) and `options` (device.rs:44).

## tools/README.md

- "Scripts use `set -euo pipefail`" does not hold for sourced `stack-engine.sh`; `stack-init.sh` runs in the container and uses `A=/authority` (stack-init.sh:8).
- "Coverage baseline only ratchets upward" is a comment convention (coverage-baseline.toml:1), not enforced; `check-coverage.py --baseline` only checks floors.
- Side Effects omits that `stack-acceptance.sh` runs `just purge` first (stack-acceptance.sh:12), destroying all stack state; this contradicts "only `--purge` forgets".
- `release-docs.sh` writes to its `<out-dir>` argument (release-docs.sh:11,16), not always `release-docs/`.
- Omits that `stack-run.sh` creates world-writable `deploy/local/.out` (stack-run.sh:14) and builds/loads the `demo` image unless `FIELDSEAL_SKIP_IMAGE_BUILD=1` (stack-run.sh:11); it is missing from the Nix-build list.
- `stack-images.sh` default excludes `demo` (stack-images.sh:5,11); not stated.
- `local-stack-passkey.py` `--no-reset` flag omitted (line 331).
- `check-coverage.py` `--root` omitted (line 269); README says it scans `runtimes` and `tests`, which do not exist at top level.
- `demo-pipeline.sh` defaults to `mktemp -d` (line 26) and runs `cargo build -p fieldseal-cli` if the binary is missing (lines 33-36).
- `stack-demo.sh`/`stack-init.sh` env vars omitted: `FIELDSEAL_DEMO_SURVEY`, `FIELDSEAL_LOG_ORIGIN`, `FIELDSEAL_TRANSLOG_URL`, `FIELDSEAL_INTAKE_URL` (stack-demo.sh:21-26, stack-init.sh:9).
- justfile recipes `seed`, `demo`, `resume`, `acceptance`, `status`, `logs`, `down`, `purge`, `images`, `release` not mapped to scripts.
- Code comment drift (not README): tools/release-images.sh:6 references a nonexistent `just release-images` recipe.

## tools/browser-tests/README.md

- `wcag.sh` always obtains chromium and python+websockets from Nix (wcag.sh:20-22); only `device-flow.sh` falls back conditionally. Side Effects understates Nix use.
- `constraints.py` exits 2 on bad usage (constraints.py:327-329), not just 0/1.
- `wcag.sh` temp-dir removal is a plain `rm -rf` at the end (wcag.sh:27), not a trap; a failed render leaves it behind.
- `device-flow.sh` Nix fallback hard-codes `x86_64-linux` (device-flow.sh:14).
- `WIDTH`/`HEIGHT` defaults 1280/820 (device-flow.py:28-29) undocumented.

## crates/README.md

No drift detected.

## README.md

- *(Fixed in this run.)* Subdirectories omits `.github/workflows` (ci.yml, build.yml), `.config/nextest.toml` and the `Containerfile`.
- *(Fixed in this run.)* Global Side Effects misses `deploy/local/.out` (stack-run.sh:14) and `deploy/local/.generated/images-<engine>` stamps (stack-images.sh:10); ports bind to 127.0.0.1 only (compose.yaml:41-46,117,131), translog on host 9001 → container 8080.
- *(Fixed in this run.)* "Development-only components refuse to run in production" is overstated: the file adapter does not refuse (adapters/file/src/lib.rs:3 only documents it); refusals live in the factory config (apps/factory/src/main.rs:215-246) and web app (apps/web/src/main.rs:56); web-demo relies on `UnattestedKeys::AllowNonProduction` (adapters/web-demo/src/lib.rs:291).
- *(Fixed in this run.)* `just check` builds only `checks.x86_64-linux.*`; `just test` also runs doc tests (test-budget.sh:10).
