# Use the showcase web app

The web app shows every stage of the system in a browser: instruments with live rule evaluation, the publishing log, registration, a collection device that runs in the tab, and the intake. It is a development and assessment tool: the device is an unattested software device and the app refuses to start in production ([ADR 0036](../explanation/adr/0036-showcase-web-app-and-web-device.md), [WEB](../reference/spec/web-app.md)).

## Run it with nothing else

With Nix (builds the server, the WebAssembly bundle and bundles `examples/`):

```sh
FIELDSEAL_WEB_DEMO_AUTHORITY=true nix run path:.#fieldseal-web
```

Without Nix, from a dev shell (`nix develop path:.`):

```sh
cargo build -p fieldseal-wasm --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir target/web --out-name fieldseal_wasm \
  target/wasm32-unknown-unknown/release/fieldseal_wasm.wasm
FIELDSEAL_ENVIRONMENT=development FIELDSEAL_WEB_EXAMPLES_DIR=examples \
FIELDSEAL_WEB_WASM_DIR=target/web FIELDSEAL_WEB_DEMO_AUTHORITY=true \
  cargo run -p fieldseal-web
```

Open `http://127.0.0.1:8090`. All settings are environment variables, listed at the top of `crates/apps/web/src/main.rs`. Without `FIELDSEAL_WEB_DEMO_AUTHORITY` the Instruments page works from `examples/` alone and the other pages say what they need.

## What each page does

- **Instruments.** Pick an instrument, then a layout, a language and a window class. The page shows the instrument exactly as `fieldseal instrument preview` draws it, plus findings, the element tree, code lists, concepts and rules. Type answers into the form: rules and field checks are evaluated in your browser by the core compiled to WebAssembly (the "Live evaluation" panel), and questions hidden by a rule disappear.
- **Publishing.** The log's checkpoint and entries, and for every published artefact its signatures against the threshold, reviewers and inclusion proofs, verified in the server by the publishing context.
- **Registration.** How a device registers. In the demo, "Issue a registration token" gives a token like the portal's, and pending requests can be confirmed here (compare the four words first). The factory portal itself is at `http://127.0.0.1:8091` (sign-in is as the dev user alice).
- **Device.** The browser device, in a worker: create the tenancy with a PIN, paste a token and register (the sealed request is built in the browser; compare its four words with the portal), fetch the bundle (verified step by step), capture, review, export (downloads a file), upload (challenge, proof of possession, verified receipt) and clear. The security log lists each step as the core reported it.
- **Intake.** What the gate landed: submissions, the loss ledger, the landed long-format rows as they are (paged, filterable by column), the data contract and a CSV of the rows. The tool computes nothing from the answers; that is the data platform's job. You can also run the gate on an export file.

## Honest limits

- The device's keys are software keys, unattested, kept in IndexedDB (wrapped with a non-extractable WebCrypto key). Clearing site data deletes the device.
- The demo authority keeps everything in memory (gone on restart), uses development keys, and the browser device stays **unattested** everywhere: the demo factory runs with the non-production allowance for unattested keys (REG-017), so the development policy releases rosters to it with a flag in the decision log. Production policy never does. The Device page says so every time. Production policy never does this.
- A browser cannot lock a device down or hide the screen: the posture findings show all restrictions as unreadable, and the capture is covered while the tab is hidden.

## Attach it to the compose stack

The compose stack ([run-the-local-stack.md](./run-the-local-stack.md)) runs its own factory (`:8080`), upload endpoint (`:8480`) and log (`:9001`). Point the app at them instead of the demo authority:

```sh
FIELDSEAL_ENVIRONMENT=development FIELDSEAL_WEB_EXAMPLES_DIR=examples \
FIELDSEAL_WEB_WASM_DIR=<wasm dir> \
FIELDSEAL_FACTORY_URL=http://localhost:8080 FIELDSEAL_UPLOAD_URL=http://localhost:8480 \
FIELDSEAL_LOG_URL=http://localhost:9001 \
FIELDSEAL_WEB_PROVISIONING_FILE=provisioning.json cargo run -p fieldseal-web
```

`provisioning.json` carries the stack's trust bundle: `{"authority":"local-stack","trustBundle":"<base64url of deploy/local/.state/factory/trust-bundle.bin>","allowedBuilders":[...],"allowedSources":[...],"provisionalRecordKey":"<hex>","buildAnchor":"<hex>","factoryUrl":"http://localhost:8080","uploadUrl":"http://localhost:8480"}`. The Device page then registers against the real factory through `/proxy/factory`; sign in at the portal for the token and confirm the four words there. Two things the stack does not do yet:

- **Bundles.** Nothing serves bundles; build one for the web device with the CLI against the device's public keys (the Device page shows them) and open the file on the Device page.
- **Upload.** The compose upload endpoint accepts only its practice device's tenancy, so an upload from the browser device is refused until the upload endpoint takes its authority from the factory's registrations.

The `web-image` Nix package (`nix build path:.#web-image`) is the same app as a container image for the compose file; add it as a service that publishes `8090` and sets the URLs above.
