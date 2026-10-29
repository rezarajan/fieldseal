# fieldseal-web

## Overview

The Fieldseal showcase web app (development only): a server-rendered viewer for instruments with live rule evaluation in the browser through the WebAssembly core, plus Publishing, Registration and Device pages that read the other services. The app holds no authority state: no key, seed, session or in-process authority (WEB-155). Results are read in the intake app's results reader, not here. Package `fieldseal-web`: library `fieldseal_web` and binary `fieldseal-web`. The binary refuses to start with `FIELDSEAL_ENVIRONMENT=production`. Every page carries the footer "Development showcase: unattested software device, not for production". For usage see [Use the web app](../../../docs/how-to/use-the-web-app.md); for the local stack see [Run the local stack](../../../docs/how-to/run-the-local-stack.md).

## Interface

### Binary

`fieldseal-web [--help|-h]`. Configuration comes only from the environment. A configuration error exits with status 2; a bind error exits with status 1. On start it logs `{"event":"listening",...}` as JSON to stderr. Four worker threads share one `tiny_http` server.

### Environment variables

| Variable | Meaning |
|---|---|
| `FIELDSEAL_ENVIRONMENT` | Required: `development`, `staging` or `test`; `production` is refused |
| `FIELDSEAL_WEB_BIND` | Listen address, default `127.0.0.1:8090` (port `0` picks a free one) |
| `FIELDSEAL_WEB_EXAMPLES_DIR` | Required: a directory with `surveys/` (one folder for each survey) and `rosters/` (one file for each cohort and version) |
| `FIELDSEAL_WEB_ROSTER_DIR` | Optional: the factory's roster store, read only (the stack mounts it at `/rosters`; `just web` uses `deploy/local/.state/dev-web/rosters`). When set, `GET /instruments/{id}/roster?cohort=<cohort>` answers with the cohort's latest stored version as counts (cohort, version, subjects, and how many granted, refused or unknown), never a name, a subject or a field value; the cohort is the one the device's bundle assigns the survey (the page's script reads it from the device's view in this browser); no `cohort`, a cohort with no roster or a directory that does not exist yet answers `{}`, and the app never creates the directory. A directory that group or others can reach is refused (422). Unset: the same counts, read from the roster files of `rosters/` in the examples directory (never the people) |
| `FIELDSEAL_WEB_WASM_DIR` | Directory with `fieldseal_wasm.js` and `fieldseal_wasm_bg.wasm`; without both, live evaluation is off |
| `FIELDSEAL_FACTORY_URL`, `FIELDSEAL_UPLOAD_URL`, `FIELDSEAL_LOG_URL`, `FIELDSEAL_WEB_PUBLIC_URL` | Optional `http(s)://` URLs; the first three are the `/proxy/*` upstreams, and the factory and log are also read by the Registration and Publishing pages |
| `FIELDSEAL_WEB_RESULTS_URL` | Optional `http(s)://` URL of the intake app's results reader, linked from every page's footer |
| `FIELDSEAL_WEB_STACK` | `true` runs as a compose-stack service (see Side Effects) |
| `FIELDSEAL_WEB_AUTHORITY_DIR` | Stack mode: the authority's directory (`trust-bundle.bundle`, `online/`), default `/authority` |
| `FIELDSEAL_WEB_PUBLISHED_DIR` | Stack mode: the directory of the `*.published` files that name the surveys and that the Publishing page verifies, default `/published` (mounted read only). A file names a survey only when the log (`FIELDSEAL_LOG_URL`) holds the entry the publication carries, read with `GET /entries/{from}/{to}` |
| `FIELDSEAL_WEB_ALLOWED_BUILDERS`, `FIELDSEAL_WEB_ALLOWED_SOURCES` | Stack mode: the comma-separated builders and sources the device's publishing policy accepts, copied from `FIELDSEAL_INTAKE_ALLOWED_BUILDERS` and `_ALLOWED_SOURCES` of the intake environment (`tools/stack-up.sh` writes `.generated/web.env`; `tools/dev-web.sh` exports them) |
| `FIELDSEAL_WEB_REGISTRY_DIR` | Stack mode: the CLI's artefact registry (`*.publication` files), verified on the Publishing page with the published files (each artefact once); default none |
| `FIELDSEAL_WEB_PROVISIONING_FILE` | Provisioning JSON served by `/device/provisioning` against another authority |

Empty values count as unset.

Stack mode runs in two ways: as the `web` service of the compose stack (`just up`, the defaults above are the stack's mount points), and natively from `just web` (`tools/dev-web.sh`), which sets the three directory variables to `deploy/local/.state/dev-web/` and the log and factory URLs to the processes it starts.

### HTTP routes

All responses get `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store` unless already set (`Response::secured`). Unmatched paths give a 404 page.

| Route | Behaviour |
|---|---|
| `GET /` | Redirect to `/demo` |
| `GET /demo`, `GET /demo/{1..8}` | The guided demo (WEB-195 to WEB-199): the banner and the table of the eight steps, then one page for each step with who does it in production, how to do it (a link, or a command to copy that is never run), a confirmation panel and Back and Next. Steps 1 and 2 are filled by the server (the surveys' compile, and the log's publications verified against the trust bundle); steps 3 to 7 by `assets/demo.js` from the device's own view and `GET /proxy/factory/v1/registrations/{tenancy}`; step 8 links to the results reader and confirms nothing |
| `GET /favicon.ico` | 204, empty |
| `GET /healthz` | 200 `{"status":"ok"}` |
| `GET /assets/*` | Static files (below) |
| `GET /instruments` | Instrument list |
| `GET /instruments/{id}` | Detail page; query `layout` (index or `default`), `lang`, `window` (window class) |
| `GET /instruments/{id}/render`, `/plan`, `/source`, `/roster?cohort=` | Rendered instrument, plan, source text, the roster of a cohort |
| `GET /instruments/{id}/layout/{i}/source` | Layout source |
| `GET /publishing` | The log's checkpoint and entries (`FIELDSEAL_LOG_URL`) and each published artefact, verified here against the stack's trust bundle and the allow-lists (signatures, threshold, provenance, inclusion); without a trust bundle it lists what the files and the log say and states that nothing is verified; an unreachable log is named |
| `GET /registration` | How registration works, the factory portal link; with `?tenancy=<64 hex>` the state the factory reports (`GET /v1/registrations/{tenancy}`) |
| `GET /device` | Browser device page |
| `GET /device/provisioning` | JSON from the stack trust bundle (with `factoryUrl`, `uploadUrl` and the allow-lists), or `FIELDSEAL_WEB_PROVISIONING_FILE` (404 if none, 500 on read error). The device gets its bundle from the factory (`GET /v1/bundle` through `/proxy/factory`); the app serves none |
| `GET /device/frame` | Blank document the page renders the instrument into |
| `* /proxy/{factory,upload,log}/*` | Reverse proxy to `FIELDSEAL_FACTORY_URL`, `FIELDSEAL_UPLOAD_URL`, `FIELDSEAL_LOG_URL`; 404 text if unconfigured |

There is no Intake page: `/intake` is 404 (WEB-154). Request bodies over `MAX_BODY` (1 MiB) get 413.

### Modules and public symbols

- `routes::dispatch(&AppState, &Request) -> Response`: the single entry; each page module exposes `handle(state, req) -> Option<Response>`.
- `http`: `Request`, `Response`, `parse_query`, `url_encode`, `proxy`, `MAX_BODY`, `PAGE_CSP`.
- `state`: `AppState` (`examples_dir`, `last_good`, `wasm_dir`, `factory_url`, `upload_url`, `log_url`, `public_url`, `results_url`, `provisioning_file`, `stack`, `authority_dir`, `published_dir`, `registry_dir`; `wasm_available()`).
- `assets`: `ASSETS` table, `Source`. `ui`: `NAV`, `FOOTER`, `BANNER`, `banner`, `escape`, `shell`, `tabs`, `page`, `error_page`, `placeholder`, `with_results_link`. `reports`: `PublicationReport` and the types it holds.
- `catalogue`: `Entry`, `Summary`, `LayoutFile`, `load_all`, `load`. `instruments`: `Choice`. `panels::detail`.
- `stack`: `surveys`, `provisioning`, `bundle`. Modules `demo_steps`, `device`, `publishing`, `registration` hold page handlers; `publishing::verified` gives the demo the verified publications.

### Static assets

`assets/` holds `tokens.css`, `nunito-sans.css`, `app.css`, `device.css`, `demo.css`, `tabs.js`, `instrument.js`, `answers.js`, `demo.js`, `device.js`, `device-worker.js` and four `fonts/nunito-sans-{400,600,700,800}.woff2`. They are compiled into the binary (`include_str!`/`include_bytes!`) and served at `/assets/<same path>` with fixed content types. `/assets/wasm/fieldseal_wasm.js` and `/assets/wasm/fieldseal_wasm_bg.wasm` are read from `FIELDSEAL_WEB_WASM_DIR` per request; missing gives 404. Pages use `PAGE_CSP` (`script-src 'self' 'wasm-unsafe-eval'`, no inline script or style).

## Invariants

- Refuses to start when `FIELDSEAL_ENVIRONMENT` is `production`, unset, or not `development`/`staging`/`test`.
- `FIELDSEAL_WEB_EXAMPLES_DIR` must be an existing directory; configured service URLs must start with `http://` or `https://`.
- Every response passes through `dispatch`, so carries the security headers.
- Assets are served by exact table match; only `GET /assets/...` is handled.
- Instrument routes are `GET` only; example files are re-read on every request. A survey that stops loading is shown as its last good version (kept in memory) with the findings of the file as it is now; with no good version yet, the findings alone.
- Proxy forwards only `Content-Type`, `Fieldseal-PoP` and `Authorization`, and hands back the status (a `304` included), `Fieldseal-Bundle-Sequence` and `Content-Disposition`; an unreachable upstream gives 502 `{"error":"upstream-unreachable"}`.
- Request bodies are capped (`MAX_BODY`).
- The guided demo performs nothing for the authority: no credential, no request but `GET`, no route that records a confirmation (WEB-196).
- The app holds no key, seed or session and needs no key material in its environment; its proxy forwards only to the configured factory, upload and log URLs, never to the intake portal (controls 1 and 2 of the design's section 7.2). The pages read the factory, the log and the files on disk and say plainly when a service is unreachable.
- `stack::surveys` lists a `*.published` file (not `deployment-policy`, not a layout) only when the log holds the entry at the index of the publication's first log record and it equals the publication's; with no log it lists nothing.
- `AppState` is shared read-only across workers.

## Side Effects

- Ports: `FIELDSEAL_WEB_BIND` (default 8090).
- Files read: `FIELDSEAL_WEB_EXAMPLES_DIR` (`surveys/`, `rosters/`) per request, `FIELDSEAL_WEB_ROSTER_DIR` (the roster store, read only) when set, the surveys through the resolver: a survey that does not resolve is listed with the resolver's errors; WASM files from `FIELDSEAL_WEB_WASM_DIR`; `FIELDSEAL_WEB_PROVISIONING_FILE`. Stack mode reads `/authority/trust-bundle.bundle` and `/published`.
- Outbound network (`ureq`): `proxy` to the factory, upload and log upstreams (15 s timeout); `GET {log}/checkpoint`, `/inclusion/{leaf}/{size}` and `/entries/{from}/{to}` from `/publishing` (10 s timeout); `GET {factory}/v1/registrations/{tenancy}` from `/registration` (10 s timeout); `GET {log}/checkpoint` and `/inclusion/{leaf}/{size}` from `/demo/2`; in stack mode `GET {log}/entries/{from}/{to}` for each published file.
- No subprocess: the app builds no bundle.
- Browser-side: `device.js` uses `localStorage` (`fs-registered-<tenancy>`, `fs-bundle-sequence-<tenancy>`, and `fs-device-view`, the counts and public identifiers `demo.js` reads; never sent to the server) and the worker uses IndexedDB `fieldseal-web-device`.
- In-memory state: immutable `AppState` and the last good version of each survey; no authority state.

## Verification

- `cargo test -p fieldseal-web` (integration tests in `tests/`: `accessibility.rs`, `browser_constraints.rs`, `demo_stepper.rs`, `dev_loop.rs`, `pages_from_services.rs`, `parity.rs`, `roster_store.rs`, `stack_mode.rs`).
- Repo-wide: `just test`.
