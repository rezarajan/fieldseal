# fieldseal-web

## Overview

The Fieldseal showcase web app (development only): a server-rendered viewer for instruments with live rule evaluation in the browser through the WebAssembly core, plus Publishing, Registration, Device and Intake pages that front the other services. Package `fieldseal-web`: library `fieldseal_web` and binary `fieldseal-web`. The binary refuses to start with `FIELDSEAL_ENVIRONMENT=production`. Every page carries the footer "Development showcase: unattested software device, not for production". For usage see [Use the web app](../../../docs/how-to/use-the-web-app.md); for the local stack see [Run the local stack](../../../docs/how-to/run-the-local-stack.md).

## Interface

### Binary

`fieldseal-web [--help|-h]`. Configuration comes only from the environment. A configuration error exits with status 2; a bind or demo start-up error exits with status 1. On start it logs `{"event":"listening",...}` (and `{"event":"demo-authority",...}`) as JSON to stderr. Four worker threads share one `tiny_http` server.

### Environment variables

| Variable | Meaning |
|---|---|
| `FIELDSEAL_ENVIRONMENT` | Required: `development`, `staging` or `test`; `production` is refused |
| `FIELDSEAL_WEB_BIND` | Listen address, default `127.0.0.1:8090` (port `0` picks a free one) |
| `FIELDSEAL_WEB_EXAMPLES_DIR` | Required: a directory with `surveys/` (one folder for each survey) and `rosters/` (one file for each cohort and version) |
| `FIELDSEAL_WEB_ROSTER_DIR` | Optional: the factory's roster store, read only (the stack mounts it at `/rosters`; `just web` uses `deploy/local/.state/dev-web/rosters`). When set, `GET /instruments/{id}/roster` takes the survey's cohort from `FIELDSEAL_WEB_SURVEY_COHORTS` and answers with the cohort's latest stored version as counts (cohort, version, subjects, and how many granted, refused or unknown), never a name, a subject or a field value; a survey with no cohort, a cohort with no roster or a directory that does not exist yet answers `{}`, and the app never creates the directory. A directory that group or others can reach is refused (422). Unset: the roster files of `rosters/` in the examples directory, as before |
| `FIELDSEAL_WEB_SURVEY_COHORTS` | Optional: `survey=cohort,...`, the cohort whose roster each survey's pages use. A survey with no entry has no roster. Not the factory's `cohorts` setting |
| `FIELDSEAL_WEB_WASM_DIR` | Directory with `fieldseal_wasm.js` and `fieldseal_wasm_bg.wasm`; without both, live evaluation is off |
| `FIELDSEAL_FACTORY_URL`, `FIELDSEAL_UPLOAD_URL`, `FIELDSEAL_LOG_URL`, `FIELDSEAL_WEB_PUBLIC_URL` | Optional `http(s)://` URLs; the first three are the `/proxy/*` upstreams |
| `FIELDSEAL_WEB_DEMO_AUTHORITY` | `true` starts the embedded demo authority (practice factory, intake, log over in-memory ports, development keys) |
| `FIELDSEAL_WEB_DEMO_FACTORY_BIND`, `FIELDSEAL_WEB_DEMO_UPLOAD_BIND` | Demo listeners, defaults `127.0.0.1:8091` and `127.0.0.1:8092`; they override the factory and upload URLs |
| `FIELDSEAL_WEB_STACK` | `true` runs as a compose-stack service (see Side Effects) |
| `FIELDSEAL_WEB_CLI` | The `fieldseal` executable used in stack mode, default `fieldseal` |
| `FIELDSEAL_WEB_AUTHORITY_DIR` | Stack mode: the authority's directory (`trust-bundle.bundle`, `online/`), default `/authority` |
| `FIELDSEAL_WEB_PUBLISHED_DIR` | Stack mode: the directory of the `*.published` files that name the surveys, default `/published` |
| `FIELDSEAL_WEB_REGISTRY_DIR` | Stack mode: the CLI's artefact registry (`*.publication` files), listed above the checkpoint on the Publishing page; default none |
| `FIELDSEAL_WEB_PROVISIONING_FILE` | Provisioning JSON served by `/device/provisioning` against another authority |

Empty values count as unset.

Stack mode runs in two ways: as the `web` service of the compose stack (`just up`, the defaults above are the stack's mount points), and natively from `just web` (`tools/dev-web.sh`), which sets the three directory variables to `deploy/local/.state/dev-web/` and the log and factory URLs to the processes it starts.

### HTTP routes

All responses get `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store` unless already set (`Response::secured`). Unmatched paths give a 404 page.

| Route | Behaviour |
|---|---|
| `GET /` | Redirect to `/instruments` |
| `GET /favicon.ico` | 204, empty |
| `GET /healthz` | 200 `{"status":"ok"}` |
| `GET /assets/*` | Static files (below) |
| `GET /instruments` | Instrument list |
| `GET /instruments/{id}` | Detail page; query `layout` (index or `default`), `lang`, `window` (window class) |
| `GET /instruments/{id}/render`, `/plan`, `/source`, `/roster` | Rendered instrument, plan, source text, roster |
| `GET /instruments/{id}/layout/{i}/source` | Layout source |
| `GET /publishing` | Demo publications, or the log's `/checkpoint` text if `FIELDSEAL_LOG_URL` is set; in stack mode also the artefacts of `FIELDSEAL_WEB_REGISTRY_DIR` (name, version, kind, address, log index) |
| `GET /registration` | How registration works, factory portal link |
| `POST /registration/token`, `POST /registration/confirm` | Demo only (form field `tenancy`); otherwise an error message in the page |
| `GET /device` | Browser device page |
| `GET /device/provisioning` | JSON from the demo, the stack trust bundle, or `FIELDSEAL_WEB_PROVISIONING_FILE` (404 if none, 500 on read error) |
| `GET /device/bundle?tenancy=&instrument=` | Bundle bytes (`application/octet-stream`) with `X-Bundle-*` headers; demo or stack only (400 missing parameter, 404, 409 demo failure, 422 stack failure) |
| `GET /device/frame` | Blank document the page renders the instrument into |
| `GET /intake`, `/intake/rows.csv`, `/intake/contract.json`; `POST /intake/ingest` | Demo authority only (else 404); ingest accepts an export file up to `MAX_INGEST_BODY` |
| `* /proxy/{factory,upload,log}/*` | Reverse proxy to `FIELDSEAL_FACTORY_URL`, `FIELDSEAL_UPLOAD_URL`, `FIELDSEAL_LOG_URL`; 404 text if unconfigured |

Request bodies over `MAX_BODY` (1 MiB; 32 MiB for `POST /intake/ingest`) get 413.

### Modules and public symbols

- `routes::dispatch(&AppState, &Request) -> Response`: the single entry; each page module exposes `handle(state, req) -> Option<Response>`.
- `http`: `Request`, `Response`, `parse_query`, `url_encode`, `proxy`, `MAX_BODY`, `MAX_INGEST_BODY`, `PAGE_CSP`.
- `state`: `AppState` (`examples_dir`, `last_good`, `wasm_dir`, `factory_url`, `upload_url`, `log_url`, `public_url`, `demo`, `provisioning_file`, `stack`, `authority_dir`, `published_dir`, `registry_dir`; `wasm_available()`), `DemoHandle`.
- `assets`: `ASSETS` table, `Source`. `ui`: `NAV`, `FOOTER`, `escape`, `shell`, `tabs`, `page`, `error_page`, `placeholder`.
- `catalogue`: `Entry`, `Summary`, `LayoutFile`, `load_all`, `load`. `instruments`: `Choice`. `panels::detail`. `intake::ROW_PAGE_SIZE`.
- `stack`: `surveys`, `provisioning`, `bundle`. Modules `device`, `publishing`, `registration` hold page handlers.

### Static assets

`assets/` holds `tokens.css`, `nunito-sans.css`, `app.css`, `device.css`, `tabs.js`, `instrument.js`, `answers.js`, `device.js`, `device-worker.js`, `intake.js` and four `fonts/nunito-sans-{400,600,700,800}.woff2`. They are compiled into the binary (`include_str!`/`include_bytes!`) and served at `/assets/<same path>` with fixed content types. `/assets/wasm/fieldseal_wasm.js` and `/assets/wasm/fieldseal_wasm_bg.wasm` are read from `FIELDSEAL_WEB_WASM_DIR` per request; missing gives 404. Pages use `PAGE_CSP` (`script-src 'self' 'wasm-unsafe-eval'`, no inline script or style).

## Invariants

- Refuses to start when `FIELDSEAL_ENVIRONMENT` is `production`, unset, or not `development`/`staging`/`test`.
- `FIELDSEAL_WEB_EXAMPLES_DIR` must be an existing directory; configured service URLs must start with `http://` or `https://`.
- Every response passes through `dispatch`, so carries the security headers.
- Assets are served by exact table match; only `GET /assets/...` is handled.
- Instrument routes are `GET` only; example files are re-read on every request. A survey that stops loading is shown as its last good version (kept in memory) with the findings of the file as it is now; with no good version yet, the findings alone.
- Proxy forwards only `Content-Type`, `Fieldseal-PoP` and `Authorization`; an unreachable upstream gives 502 `{"error":"upstream-unreachable"}`.
- Request bodies are capped (`MAX_BODY`, `MAX_INGEST_BODY` for `/intake/ingest`).
- `stack::bundle` requires a 64-hex-digit tenancy and a survey listed by `stack::surveys` (excludes `deployment-policy`).
- `AppState` is shared read-only across workers.

## Side Effects

- Ports: `FIELDSEAL_WEB_BIND` (default 8090); with the demo authority also 8091 (factory) and 8092 (upload) by default.
- Files read: `FIELDSEAL_WEB_EXAMPLES_DIR` (`surveys/`, `rosters/`) per request, `FIELDSEAL_WEB_ROSTER_DIR` (the roster store, read only) when set, the surveys through the resolver: a survey that does not resolve is listed with the resolver's errors; WASM files from `FIELDSEAL_WEB_WASM_DIR`; `FIELDSEAL_WEB_PROVISIONING_FILE`. Stack mode reads `/authority/trust-bundle.bundle`, `/published`, `/opt/fieldseal/examples/rosters`.
- Files written (stack mode only): the temporary directory `fieldseal-web-bundle-<tenancy>` in `std::env::temp_dir()`, removed and recreated per bundle build, by the spawned `fieldseal bundle build --stack` process (which uses `/authority/online`, `/factory-state`, `/clistate`).
- Outbound network (`ureq`): `proxy` to the factory, upload and log upstreams (15 s timeout); `GET {log}/checkpoint` from `/publishing` (10 s timeout).
- Subprocess: the `FIELDSEAL_WEB_CLI` executable in stack mode.
- Browser-side: `device.js` uses `localStorage` (`fs-registered-<tenancy>`) and the worker uses IndexedDB `fieldseal-web-device`.
- In-memory state: immutable `AppState`; the demo authority (`fieldseal_adapters_web_demo::Demo`, in-memory ports) holds registrations, intake and log state for the process lifetime.

## Verification

- `cargo test -p fieldseal-web` (integration tests in `tests/`: `accessibility.rs`, `browser_constraints.rs`, `e2e_web.rs`, `parity.rs`).
- Repo-wide: `just test`.
