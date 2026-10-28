# fieldseal-adapters-web

## Overview

Adapters shared by the web app server and the WebAssembly binding ([ADR 0036](../../../docs/explanation/adr/0036-showcase-web-app-and-web-device.md); [web-app spec](../../../docs/reference/spec/web-app.md); [platform profiles](../../../docs/reference/spec/platform-profiles.md)). It implements the Collection and Delivery ports for the `web` platform profile (PLAT-100 and following) as plain Rust with no browser calls, so it is tested natively; the WebAssembly binding supplies clocks and the HTTP call as closures. **Development only**: the `web` profile is refused in production by deployment validation. Keys are software keys, never attested (CLI-007, REG-017).

Modules (`src/lib.rs` declares all four as `pub mod`):

| Module | File | Role |
|---|---|---|
| `device` | `src/device.rs` | `WebDevice`: a browser device wiring the real Collection runtime and Delivery service to the web adapters, reporting results as JSON strings. |
| `platform` | `src/platform.rs` | The web ports. |
| `workbench` | `src/workbench.rs` | Instrument workbench shared by server and browser. |
| `json` | `src/json.rs` | JSON text of canonical values (CLI-011b mapping) and back. |

## Interface

`device`:

- `Host { now_ms, elapsed_ms, post }`: what the page provides (wall clock, `performance.now()`, one blocking POST as `PostFn`).
- `Provisioned::from_json(text)`: reads the provisioning JSON (trust bundle in base64url, allowed builders and sources, build anchor, provisional record key, factory and upload URLs).
- `WebDevice::open(provisioning_json, persisted, boot_count, host)` and operations: `state_json`, `create_tenancy(pin)`, `unlock(pin)`, `lock`, `registration_request(token, label)`, `import_bundle(file)`, `held_json`, `render`, `evaluate`, `roster_fields`, `record_consent`, `record_status`, `start_capture`, `set_values`, `override_soft`, `acknowledge_incomplete`, `seal`, `discard_capture`, `review`, `export(parity)`, `upload(address)`, `import_receipt`, `clear_preview`, `clear`, `last_seq`, `public_keys_json`, `drain_changes`, `take_downloads`, `provisioned`, `erase_all`.
- `WebBundleOpener` (implements `BundleOpener`: real FSB1 verification, WIRE-090..095) and a private `BrowserTransport` (implements `UploadTransport` over `Host::post`: challenge, PoP-authenticated upload, status mapping 200/401/502..504).

`platform`:

- `WebStorage` (implements `SecureStorage`): in-memory objects in three `Namespace`s (`Device`, `Session`, `Keys`) with a write-through `Change` log (`load`, `get`, `put`, `remove`, `names_in`, `sizes`, `drain_changes`) that the host drains into IndexedDB.
- `WebKeyStore` (implements `SecureKeyStore` and `Attestor`): P-256 signing, P-256 agreement (HPKE `fs1-p`) and AES-256-GCM wrapping keys; `open`, `set_locked`, `signing_handle`, `agreement_public`, `agreement_key`, `key_count`. Evidence is software evidence (`software_evidence`).
- `WebRandom` (`RandomSource`), `WebWall` (`WallClock`, an untrusted hint), `WebElapsed` (`ElapsedClock`), `ArgonHash` (`MemoryHardHash`, Argon2id, refuses parameters below the floor), `WebDisplay` (`SecureDisplay`, records protected windows only), `WebDevicePolicy` (`DevicePolicy`, `EmmManaged`, every restriction `Unknown`, `apply` fails with `NotDeviceOwner`), `WebCamera` (`Camera`, always `Unavailable`), `WebDownloads` (`FileAccess`, queues files for browser download; `take`), `NoShare` (`ShareTarget`, always `Failed`).
- Helpers: `Shared<T>`, `TenancyCell`, `toy_digest64`.

`workbench`: `Workbench` (`load`, `from_parts`, `with_salt`, `add_layout`, `identity`, `instrument`, `address`, `layouts`, `warnings`, `lints`, `plan`, `render`, `evaluate_json`), `RenderOptions`, `Rendered`, `LoadError`, `parse_map`, `map_json`, `severity_name`. It renders the same plan as `fieldseal instrument preview` (CLI-011, INS-208) and evaluates rules live (INS-040 and following).

`json`: `to_json`, `from_json` (strict authoring decoder: no null, no floats, NFC text), `string`, `quote`.

## Invariants

- Bundle verification, tenancy and PIN handling, the sealed dual write, field checks, export and receipt verification are the same Rust the other platforms run; this crate only wires adapters and reports JSON.
- Persistence contract: writes replace whole objects, appends add to the end, and once a call returns the change is in the log; the host must persist drained changes before reporting an operation done.
- Download read-back returns the bytes handed to the browser, not what the browser did with them, so verification covers the file as written.
- Argon2 parameters below `HashParams::meets_floor` yield no hash.
- Keys created as unlock-bound refuse to work while `WebKeyStore` is locked.
- `WebDevice` adapters live for the page's lifetime (`Box::leak`); a reload builds a new device from persisted objects.
- `Workbench` performs no I/O; the caller supplies the document bytes.

## Side Effects

- No filesystem or network access of its own. Network is the host's `post` closure; persistence is the host draining `Change`s.
- Randomness: `getrandom` (browser `crypto.getRandomValues` in the WebAssembly build, the OS natively).
- Clocks come from host closures.
- Key material is held in memory (zeroized wrappers) and exposed to the host through the `Keys` namespace, which the host script wraps.

## Verification

- Run: `cargo test -p fieldseal-adapters-web` (dev-dependency on `fieldseal-adapters-web-demo`). Repo-wide: `just test`.
