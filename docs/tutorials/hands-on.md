# Hands-on: the whole system, one step at a time

This walkthrough drives every part of Fieldseal yourself, on your own machine:
1. Start the factory.
2. Look at the authority's keys.
3. Publish an instrument.
4. Explore the register.
5. Download the instrument, open it, and answer it.
6. Issue the rosters and assign their cohorts.
7. Register a device.
8. Fetch its bundle, capture, upload, and see what intake landed.

Each step is one `just` command that prints what it did and what to look at next. Each step leaves its state in the stack, so you can stop between steps and come back.

Everything is local and development-only:
- **Keys:** software keys that are never reported as attested.
- **Identity provider:** a passkey-only Keycloak.
- **Persistence:** volumes that survive `just down`.

`just acceptance` runs exactly the steps marked `# step` below, in this order, against a fresh stack. The tutorial and its test cannot drift apart.

**You need** Nix (with flakes), `just`, and Docker; rootless Podman also works (`FIELDSEAL_CONTAINER_ENGINE=podman just …`). Run everything from the repository root.

## 1. Start the stack

```sh
just up   # step
```

The first run builds the images with Nix, which takes a few minutes; later runs reuse them.

`up` starts:
- **Keycloak** on `:8180`;
- **the factory and its portal** on `:8080`;
- **the transparency log** on `:9001`;
- **the intake app** on `:8480` (device uploads) and `:8481` (the results reader).

Before they start, a one-shot `init` service creates the stack's one authority. That is the root, the purpose keys, the log's key, and the trust bundle that pins the log.

`just status` shows the containers and the health of each endpoint at any time.

## 2. Look at the authority

```sh
just authority   # step
```

This shows the trust bundle every component and device accepts:
- the root;
- every purpose-key certificate: factory, registration (signing and sealing), receipt, record, publishers and builder, each with its key ID, validity and custody;
- the pinned log.

Compare the root key ID with the one in the `init` container's log (`just logs init`). Every certificate chains to it.

## 3. Publish the instruments

```sh
just publish   # step
```

This publishes two instruments and the deployment's publishing policy through the real publishing flow (PUB):
- the household water sample;
- the school meals survey.

Each artefact goes through these steps:
1. Provenance, with the builder's signature and two reviewers (one for Spanish).
2. Two of the three publishers' signatures.
3. An entry in the stack's transparency log.
4. A proof of inclusion.
5. A full verification against the trust bundle.

The log's tree size is printed before and after. The step then publishes again to show that a repeat changes nothing.

## 4. Explore the register

```sh
just registry   # step
```

This lists every published artefact with its kind, name, version and content address. It also shows how many publisher signatures it carries against the threshold, and whether each signature's log entry is included in the log. It checks the log's latest checkpoint against the pinned key.

To see one artefact in full, give its address (copy one from the list):

```sh
just registry sha256:…
```

## 5. Download an instrument, open it and answer it

```sh
just fetch school-meals-baseline   # step
```

`fetch` takes a name or an address. Names are not unique: another version, or another kind of artefact, may share one. A name that matches more than one artefact is refused, and the matches are listed with their addresses. Fetch by address to be exact, copying one from `just registry`:

```sh
just fetch sha256:…
```

The step downloads the published school meals survey from the register and verifies it as a device does. It writes three files to `deploy/local/.out/`, named after the artefact and its version:
- the publication;
- the instrument document;
- a rendering in the compact layout, `school-meals-baseline-1.0.0.html`.

Open the HTML file in your browser and answer the survey. The page checks every answer with the same rules the core applies. Try to break it:
- **Question 11a:** choose a fifth snack. It is refused, with "4 of 4 chosen".
- **An amount:** type 100 where at most 20 is allowed. It is refused, with the limit shown.
- **"Other":** choose it without typing the text. The item stays incomplete.

`just fetch household-water-access` does the same for the water sample, which also has a Spanish translation.

## 6. Issue the rosters and assign their cohorts

A roster lists the subjects of one cohort. Before a device can collect for a survey, the factory needs the rosters, and it needs to know which account collects which survey for which cohort. These are two operator steps, in this order. `just up` has already run both once, so here you run them again and see that they change nothing the second time.

```sh
just issue   # step
```

This stores the two example rosters, `village-a` and `cohort-a`, at the factory. Each is stored as a new version of its cohort, and a version, once stored, never changes. Issuing the same file again prints `unchanged`; issuing a changed file under the same version is refused.

```sh
just assign   # step
```

This assigns the water survey to the `village-a` cohort and the school meals survey to `cohort-a`. An assignment names ONE account, the collector's (here `product-owner`, whose subject is `00000000-0000-4000-8000-000000000003`), and applies to that account's tenancies now and any it registers later. A device registered afterwards receives the cohort's roster in its bundle without any further step. The factory refuses an assignment for a survey that is not published, or for a cohort with no stored roster, which is why publishing comes first.

Neither step removes anything: issuing adds a version, and assigning adds an assignment. Removing an assignment is not built yet.

Each step asks you to sign in as the operator. In the stack the demo container answers for you: the command opens the sign-in page with `tools/stack-browser.sh`, which registers a passkey for `product-owner` in headless Chromium and signs in with it, and the command carries on with the token Keycloak gives it. Because that passkey is registered afresh each time, the step removes the passkeys `product-owner` had before; this is a development stack.

## 7. Register a device

**Headless.** The stack drives a browser with a virtual passkey for you:

```sh
just enrol   # step
```

The headless step does everything below for you, printing each part as it goes:
1. It signs in to the portal as `product-owner`.
2. It registers a passkey, then signs in again with it. The first sign-in, made without a passkey, is refused for registration (REG-002a).
3. It gets a registration token.
4. The device in the stack builds a sealed registration request from the token and submits it to the factory over HTTP.
5. It confirms the device's four fingerprint words in the portal.
6. The device collects its tenancy certificate.

**By hand, with your own passkey.** Instead of `just enrol`:
1. Open <http://localhost:8080>, choose **Sign in**, and enter `product-owner`. Your browser asks you to register a passkey: do so.
2. **Sign out and sign in again with the passkey.** The first session ran at the lower level and is deliberately not accepted for registering devices.
3. Choose **Get a registration token** and copy the `FS1T:…` token.
4. Run:

   ```sh
   just register 'FS1T:…'
   ```

   It prints four words.
5. Reload the portal. Compare the four words shown under **Requests waiting for you** and, only if all four match, confirm them.
6. Run:

   ```sh
   just wait
   ```

   It collects the certificate and shows the tenancy as `registered`.

## 8. The device fetches its bundle

```sh
just bundle   # step
```

The factory builds a bundle for each registered device and serves the latest one at `GET /v1/bundle`. This step runs `fieldseal bundle fetch`, which proves with the device's own key that it is that device and stores the bundle in the `device` volume. The factory notices new publications within a few seconds, so the step asks again for up to a minute if the bundle is not built yet. The bundle carries:
- the instrument the log holds;
- the deployment policy;
- a roster.

It is sealed to the registered device's agreement key, so no other device can open it. The device verifies it when it imports it in the next step (WIRE-093): signature, threshold of publishers, log inclusion, roster generation, then decryption. The device is unattested, so the roster is released under the development factory's explicit allowance (REG-017). It is never released as if the device were attested.

## 9. Capture

```sh
just capture   # step
```

The registered device opens its bundle and captures the school meals survey for two pupils (`examples/scenarios/stack-capture-school-meals-baseline.yaml`; set `FIELDSEAL_DEMO_SURVEY=household-water-access` for the water survey). Each answer is checked by the core before it is stored. The device then seals the records into its journal and builds a signed export with parity.

## 10. Upload and receipts

```sh
just upload   # step
```

The export goes to the intake app. The flow is:
1. The receiver challenge, then the upload with a proof-of-possession token signed by the device's key.
2. One signed receipt for each accepted part.
3. Each receipt is verified against the trust bundle before it is stored.

## 11. What intake landed

```sh
just intake   # step
```

This shows the data contract, and the long-format observation rows that the gate landed for this device's tenancy. It also shows the loss ledger (`losses.csv`) and the field-check findings (`findings.csv`). The tool computes nothing from the answers; that is the data platform's job.

To read the results as files, open the results reader at <http://localhost:8481>, sign in as `product-owner` with the passkey and download the results files. The same export is available from the command line, against the stack's volumes:

```sh
fieldseal intake results --landing <landing dir> --published <published dir> \
  --export-key <export.key> --trust-bundle <trust-bundle.bundle> --out <out dir>
```

## Break it on purpose

- **A flipped byte in an export.** In `tools/demo-pipeline.sh` (the offline flow), stage 5 flips a byte in an export: verification fails, and repair from parity restores the file exactly. Run `tools/demo-pipeline.sh /tmp/fieldseal-demo` and read its summary.
- **A duplicate upload.** Run `just upload` again: the gate recognises the records it already landed and lands nothing new.
- **A restart.** Run `just down && just up && just resume`: the device registered before the restart is still registered, and its repeated upload changes nothing.

## Stop

```sh
just down    # keeps the passkey, the log, the registered device and what landed
just purge   # forgets everything
```

## The browser device

The showcase web app runs the same flow with the device in your browser: the core is compiled to WebAssembly. To start it, run:

```sh
FIELDSEAL_WEB_DEMO_AUTHORITY=true nix run path:.#fieldseal-web
```

Then open <http://127.0.0.1:8090>. See [use the web app](../how-to/use-the-web-app.md).

To see the whole pipeline in eight steps, with each confirmation read from the component that did the work, run `just web` and open <http://127.0.0.1:8090>: the guided demo starts there. See [use the web app](../how-to/use-the-web-app.md#give-the-guided-demo).
