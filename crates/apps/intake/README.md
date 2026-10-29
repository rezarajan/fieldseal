# fieldseal-intake-app

## Overview
The intake service's composition root (ADR 0028). The binary `fieldseal-intake` reads its configuration from the environment only (twelve-factor III), wires adapters to the gate (`IntakeService`), replays the stored submissions, and then serves two listeners from one thread: the device-facing upload endpoint (`UploadHttp`) and the authority-staff portal with the results reader (`ResultsHttp`). The library `fieldseal_intake_app` lets tests start the app in process. See the [intake spec](../../../docs/reference/spec/intake.md) and the [deployment spec](../../../docs/reference/spec/deployment.md).

## Interface
- Binary `fieldseal-intake` (package `fieldseal-intake-app`). No arguments. Exit `2` for unusable configuration or an invalid export key, `1` for a start-up or runtime failure (including a stored submission that failed replay).
- Library: `Config::from_lookup`, `IntakeApp::build` / `build_with_clock`, `listen` (binds both listeners, after replay), `serve` / `serve_until`.

| Variable | Default | Meaning |
|---|---|---|
| `FIELDSEAL_ENVIRONMENT` | required | `development`, `staging`, `test` or `production` |
| `FIELDSEAL_INTAKE_BIND` | `0.0.0.0:8480` | upload listener (devices) |
| `FIELDSEAL_INTAKE_PUBLIC_URLS` | the bind address | comma-separated base URLs device tokens may be bound to |
| `FIELDSEAL_INTAKE_MAX_BODY` | 64 MiB | largest upload body |
| `FIELDSEAL_INTAKE_PORTAL_BIND` | `127.0.0.1:8481` | portal listener (authority staff) |
| `FIELDSEAL_INTAKE_PORTAL_URL` | required | public base URL of the portal; the sign-in callback and the cookie's `Secure` flag follow it |
| `FIELDSEAL_IDENTITY` | required | `oidc`, or `dev` (a fixed login; non-production only) |
| `FIELDSEAL_OIDC_*` | | as the factory's |
| `FIELDSEAL_INTAKE_READER_ROLE` | `results-reader` | role that may read results |
| `FIELDSEAL_CUSTODY`, `_CUSTODY_DIR`, `FIELDSEAL_TRUST_BUNDLE` | required | `file-dev` (keys in a directory, bundle read) or `memory-dev` (a development authority with fixed seeds, bundle written when set) |
| `FIELDSEAL_TENANCY_DIR` | required | the factory's state directory, read-only |
| `FIELDSEAL_LANDING_DIR` | required | landing files |
| `FIELDSEAL_INTAKE_SUBMISSIONS_DIR` | memory | accepted submissions, for start-up replay |
| `FIELDSEAL_INTAKE_PUBLISHED_DIR` | required | published instruments |
| `FIELDSEAL_INTAKE_ROSTERS_DIR` | memory | issued rosters |
| `FIELDSEAL_INTAKE_ALLOWED_BUILDERS`, `_ALLOWED_SOURCES` | none | publishing policy for instruments (comma-separated) |
| `FIELDSEAL_EXPORT_KEY_DIR` | required | directory that holds `export.key` |

## Invariants
- The upload listener is bound only after replay has finished; a failed replay (`replay-failed`) is exit `1`, with no override.
- In `production` every development adapter (file or memory custody, the file stores, the `dev` identity, the export key file) makes the app exit `2`. `landing-files` is not one.
- The export key is created by the authority's set-up step (`tools/stack-init.sh`, `tools/dev-web.sh`), never by the app; an absent, wrong-length or too-open key is exit `2`.
- The two listeners are separate so the device port can be exposed while the portal stays internal. Each is served on its own thread, and a request body is read on a thread of its own at no less than 8 KiB per second after a 10 second grace (`tiny_http` has no socket timeouts), so a slow client of one listener never holds up the other; at most 128 requests per listener wait for a body, and a client that goes fully silent keeps its reader thread until it disconnects. The portal answers `400` for a `Host` other than the host of `FIELDSEAL_INTAKE_PORTAL_URL`, and `FIELDSEAL_IDENTITY=dev` needs a loopback `FIELDSEAL_INTAKE_PORTAL_BIND` (exit `2`). The portal cookie is `fs_intake_session`.
- Events carry no personal data; the `development-adapters` event is written at every start.
- There is no authority switch and no seed. The results reader writes nothing to disk.

## Side Effects
- Binds two TCP listeners; writes landing files, the submission store and (for `memory-dev` with `FIELDSEAL_TRUST_BUNDLE`) the trust bundle.
- Reads the system clock and the OS random source; `oidc` makes outbound HTTP to the issuer during sign-in.

## Verification
- Run: `cargo test -p fieldseal-intake-app` (repo-wide: `just test`).
