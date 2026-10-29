# fieldseal-wasm (WebAssembly bindings)

## Overview

The Fieldseal core compiled to WebAssembly for the browser device and the instrument workbench
(ADR 0036). Both surfaces are thin: decisions are made by the same Rust code the CLI and services run.
Values cross the boundary as JSON text, parsed by the strict authoring decoder. Cargo package
`fieldseal-wasm` (`cdylib`, `rlib`).

Wrapped crates: `fieldseal-kernel`, `fieldseal-instrument`, `fieldseal-adapters-authoring`,
`fieldseal-adapters-html`, `fieldseal-adapters-web`, `fieldseal-adapters-memory`, `fieldseal-trust`,
`fieldseal-policy`, `fieldseal-publishing`, `fieldseal-registration`, `fieldseal-distribution`,
`fieldseal-collection`, `fieldseal-delivery`, `fieldseal-intake`.

## Interface

`src/lib.rs`, class `Workbench` (an instrument and its layouts, rendered as `instrument preview` does):

- `new Workbench(source, format)`: validates an instrument; `format` is `yaml`, `yml` or `json`.
- `addLayout(source, format) -> index`, `address()`, `render(options, values, roster) -> html`,
  `evaluate(options, values, roster) -> json`, `findings() -> json array of {severity, id, path, message}`.
- `options` is JSON `{"layout": 0, "languages": ["es"], "window": "compact"}`; empty text means defaults.

`src/device.rs` (module `device`), the browser device in the `web` platform profile:

- `RegistrationRequest` with getters `file`, `words`, `tenancy`.
- `Device`: `new Device(provisioning, persisted, boot_count)`, `drainChanges`, `eraseAll`,
  `takeDownloads`, `state`, `createTenancy(pin)`, `unlock(pin)`, `lock`, `publicKeys`,
  `registrationRequest(token, label)`, `importBundle(file)`, `fetchBundle(factoryUrl, held)`
  (`held` is the held sequence number or `-1`; answers JSON with `status` `imported`, `current`, `preparing` or `refused`), `held` (answers JSON with `surveys`: each assigned survey with its instrument's titles by language and its cohort, WIRE-096), `render`, `evaluate`, `rosterFields`,
  `recordConsent`, `recordStatus`, `startCapture`, `setValues`, `overrideSoft`, `acknowledgeIncomplete`,
  `seal`, `discardCapture`, `review`, `export(parity)`, `upload(address)`, `importReceipt`,
  `clearPreview`, `clear`, `lastSeq`.
- Host imports the page must define: `fieldsealPost(url, pop, body)` returning `{status, body: Uint8Array}`
  (one blocking POST), `fieldsealGet(url, pop)` returning `{status, headers: [[name, value]], body: Uint8Array}`
  (one blocking GET, used for `fetchBundle`), plus `performance.now`.

## Invariants

- Persistence is the host's job: after every call it drains `drainChanges` into IndexedDB.
- The device is meant to run in a dedicated worker because uploads use a blocking HTTP call.
- Errors reach JavaScript as thrown strings.
- `wasm-bindgen` is pinned to `=0.2.121` and must match the `wasm-bindgen-cli` in the flake's nixpkgs.

## Side Effects

- Reads the clock (`Date.now`, `performance.now`) and performs HTTP POSTs and GETs through the host's `fieldsealPost` and `fieldsealGet`.
- Build: the flake builds `fieldseal-wasm` for `wasm32-unknown-unknown` and runs `wasm-bindgen --target web`
  to produce `fieldseal_wasm.wasm` and its JS glue, consumed by `crates/apps/web`.

## Verification

- Run: `cargo test -p fieldseal-wasm`
