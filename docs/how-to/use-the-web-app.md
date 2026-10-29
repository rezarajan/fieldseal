# Use the showcase web app

The web app shows every stage of the system in a browser: instruments with live rule evaluation, the publishing log, registration, a collection device that runs in the tab. It holds no authority of its own: it reads the factory, the log and the intake app. It is a development and assessment tool: the device is an unattested software device and the app refuses to start in production ([ADR 0036](../explanation/adr/0036-showcase-web-app-and-web-device.md), [WEB](../reference/spec/web-app.md)).

## Run it with nothing else

With Nix (builds the server, the WebAssembly bundle and bundles `examples/`):

```sh
nix run path:.#fieldseal-web
```

Without Nix, from a dev shell (`nix develop path:.`):

```sh
cargo build -p fieldseal-wasm --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir target/web --out-name fieldseal_wasm \
  target/wasm32-unknown-unknown/release/fieldseal_wasm.wasm
FIELDSEAL_ENVIRONMENT=development FIELDSEAL_WEB_EXAMPLES_DIR=examples \
FIELDSEAL_WEB_WASM_DIR=target/web \
  cargo run -p fieldseal-web
```

Open `http://127.0.0.1:8090`. All settings are environment variables, listed at the top of `crates/apps/web/src/main.rs`. On its own the Instruments page works from `examples/` alone (a `surveys/<name>/` folder for each survey, `rosters/<cohort>.yaml` for each roster; the Instruments page takes a survey's cohort from the assignments in the bundle the Device page holds) and the other pages say which service they need. For the whole system, use `just web` below.

## Run it with the real services, without containers

`just web` runs the transparency log, the factory and the web app (as the collector stand-in) on your machine from `examples/deployments/dev-web.yaml`, publishes the bundled examples through the log, and re-reads survey files on every request:

```sh
just web
```

Open `http://127.0.0.1:8090`. Edit a file under `examples/surveys/` and reload: the change shows with no restart. An edit that does not load keeps the last good version on the Instruments page and shows the error, with file, line and column, above it. The Publishing page lists the artefacts in the log. `just publish <survey>` publishes a survey of your own through this log (see [Write and publish your first survey](../tutorials/write-and-publish-your-first-survey.md)). State is in `deploy/local/.state/dev-web/`; remove it to start over. `Ctrl-C` stops everything.

It uses ports 8080, 8090, 8180, 8480, 8481 and 9001, the ports the compose stack uses, so run one or the other; if a port is taken, `just web` names it and starts nothing. The factory and the results reader sign in through the development identity provider on 8180 (`fieldseal-dev-idp`, which refuses production): pick a login on its page. The Device page works here: register in the browser device flow, confirm the four words in the factory portal, and the device fetches its bundle from the factory.

## Give the guided demo

The collector stand-in opens on the **Guided demo** (`/demo`): eight steps from a survey on disk to results a person can read. Run `just web`, open `http://127.0.0.1:8090` and press **Start the demo**. Each step page says what happens, who does it in production, how to do it (a link to the page where it is done, or the exact command to copy, which the guide never runs) and a confirmation read from the service that did the work, with a "check it" link to where the same value exists on its own.

| Step | You do | The confirmation comes from |
|---|---|---|
| 1 Compile the survey | `fieldseal survey check examples/surveys/<survey>` and `fieldseal instrument hash ...` | The same core as the command line, computed in the app; the command output is the cross-check |
| 2 Publish to the factory | `just publish <survey>` (two of three publisher signatures, then the log) | The transparency log, verified in the app against the trust bundle |
| 3 Register a device | Issue a token on the factory portal (sign in as `presenter`), register on the Device page, confirm the four words in the portal | The factory's registration state; the tenancy is the device's own view |
| 4 Load the published bundle | Nothing: the factory builds the bundle and the device fetches it | The device's own view of the factory's answer; the factory's `bundle-built` event in `deploy/local/.state/dev-web/logs/factory.log` is the independent source |
| 5 Manage rosters | `fieldseal roster check`, `diff`, `issue` and `list` (the commands are on the page), then **Check for new surveys** in the list of surveys on the Device page | The roster counts in the bundle the device holds (the device's view); `roster list` is the cross-check |
| 6 Conduct a survey | Capture and seal records on the Device page | The device's journal (the device's view) |
| 7 Export | **Download the export file** and **Upload** on the Device page | The export's SHA-256 (the device's view); the receipt is verified in the browser against the trust bundle |
| 8 Read the results | Sign in to the results reader at `http://localhost:8481` as `presenter` | Nothing: the guide only links to the reader, which shows the row count, the manifest digest and the export schema version |

Everything except this collector stand-in is a production component; the device in the Device page stands in for the Android app, and a banner on the guide and the Device page says so. The last page names `just acceptance` and `just release`, which check the production path. To run the demo again, retire the old device on the factory portal (REG-043) before you register a new one, and note that `examples/rosters/next/village-a.yaml` (version 4) can be issued once: remove `deploy/local/.state/dev-web/` to start from nothing. `tools/browser-tests/demo-e2e.sh` runs all eight steps headless against a running `just web` (`tools/dev-web.sh --check --browser` runs it too).

## What each page does

- **Guided demo.** The eight steps above. It explains, links and reads; it holds no credential and makes no request except `GET`.
- **Instruments.** Pick an instrument, then a layout, a language and a window class. The page shows the instrument exactly as `fieldseal instrument preview` draws it, plus findings, the element tree, code lists, concepts and rules. Type answers into the form: rules and field checks are evaluated in your browser by the core compiled to WebAssembly (the "Live evaluation" panel), and questions hidden by a rule disappear.
- **Publishing.** The log's checkpoint and entries, and for every published artefact its signatures against the threshold, reviewers and inclusion proofs, verified in the server by the publishing context against the trust bundle. The page says plainly when the log cannot be reached.
- **Registration.** How a device registers, a link to the factory portal where the sign-in, the token and the four-word comparison happen, and a form that asks the factory for the state of a registration by its tenancy identifier (the Device page shows it under Device details). The page confirms nothing.
- **Device.** The browser device, in a worker: create the tenancy with a PIN, paste a token and register (the sealed request is built in the browser; compare its four words with the portal), load your surveys (the device fetches the bundle of the surveys assigned to the account from the factory, then verifies it step by step), choose a survey from the list (the cohort to visit is shown with it; **Switch survey** goes back to the list and **Check for new surveys** asks the factory again), capture, review, export (downloads a file), upload (challenge, proof of possession, verified receipt) and clear. Each screen fits a phone without scrolling; the status line, the security log and the device's details are behind **Details**, which lists each step as the core reported it.

The results are not on a page of this app: the intake app serves them in its results reader (`http://localhost:8481`, INT-089), and every page of this app links to it in the footer when `FIELDSEAL_WEB_RESULTS_URL` is set. The five destinations are Guided demo, Instruments, Publishing, Registration and Device.

## Honest limits

- The device's keys are software keys, unattested, kept in IndexedDB (wrapped with a non-extractable WebCrypto key). Clearing site data deletes the device.
- The browser device stays **unattested** everywhere: the development factory runs with the non-production allowance for unattested keys (REG-017), so the development policy releases rosters to it with a flag in the decision log. Production policy never does. The Device page says so every time.
- A browser cannot lock a device down or hide the screen: the posture findings show all restrictions as unreadable, and the capture is covered while the tab is hidden.

## Attach it to the compose stack

The compose stack ([run-the-local-stack.md](./run-the-local-stack.md)) runs its own factory (`:8080`), intake app (`:8480`) and log (`:9001`). Point the app at them:

```sh
FIELDSEAL_ENVIRONMENT=development FIELDSEAL_WEB_EXAMPLES_DIR=examples \
FIELDSEAL_WEB_WASM_DIR=<wasm dir> \
FIELDSEAL_FACTORY_URL=http://localhost:8080 FIELDSEAL_UPLOAD_URL=http://localhost:8480 \
FIELDSEAL_LOG_URL=http://localhost:9001 \
FIELDSEAL_WEB_PROVISIONING_FILE=provisioning.json cargo run -p fieldseal-web
```

`provisioning.json` carries the stack's trust bundle: `{"authority":"local-stack","trustBundle":"<base64url of deploy/local/.state/factory/trust-bundle.bin>","allowedBuilders":[...],"allowedSources":[...],"provisionalRecordKey":"<hex>","buildAnchor":"<hex>","factoryUrl":"http://localhost:8080","uploadUrl":"http://localhost:8480"}`. The Device page then registers against the real factory through `/proxy/factory`; sign in at the portal for the token and confirm the four words there. The device fetches its bundle from the factory (`GET /v1/bundle`) through the same proxy. One thing the stack does not do yet:

- **Upload.** The compose intake app accepts only devices the factory registered, so an upload from a browser device that has not registered is refused.

The `web-image` Nix package (`nix build path:.#web-image`) is the same app as a container image for the compose file; add it as a service that publishes `8090` and sets the URLs above.
