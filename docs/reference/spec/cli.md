# CLI

**Prefix:** `CLI` · **Context:** All (reference implementation) · **Runs in:** workstations, CI · **Status:** Draft

## 1. Scope

`fieldseal` is the reference implementation of every Fieldseal protocol operation ([ADR 0006](../../explanation/adr/0006-cli-reference-implementation.md)). Authors use it to validate and preview artefacts, publishers and CI to sign and publish them, operators to run admin tasks against a release, and conformance suites to check other implementations. It drives the same application services and ports as the factory, intake and runtime; it adds no behaviour of its own.

This spec fixes the command tree, common behaviour, and for each command its inputs, outputs, ports and the requirements it implements. Byte formats are in WIRE; behaviour is in each context's spec.

## 2. Domain model

The CLI has no domain model of its own. Each command calls one driving port of one context.

| Element | Kind | Description |
|---|---|---|
| `Invocation` | Value object | Command, arguments, resolved environment, release, adapters chosen. |
| `Outcome` | Value object | Exit code, human output, `--json` document, events. |

## 3. Driving ports

The CLI is itself a driving adapter. The commands are its interface (§5).

## 4. Driven ports

The CLI uses whichever adapters its configuration selects, for every port of the contexts it drives: `KeyStore` (software or HSM), `Signer`, `TransparencyLog`, `ArtefactRegistry`, `PolicyEngine`, `TenancyRegistry`, `RecordKeyUnsealer`, `SubmissionStore`, `DataPlatform`, `ElapsedClock`, `Storage`. A software `KeyStore` adapter is always available for development and tests.

## 5. Requirements

### Common behaviour

- **CLI-001** The binary MUST be named `fieldseal` and MUST implement exactly the command tree in this section, as `fieldseal <noun> <verb> [arguments]`.
- **CLI-002** Configuration MUST come from `FIELDSEAL_*` environment variables and flags, with flags taking precedence. A configuration file MUST be read only when given explicitly with `--config` or `FIELDSEAL_CONFIG`.
- **CLI-003** Every command MUST accept `--json`, which writes exactly one JSON document to stdout describing the outcome, and nothing else to stdout.
- **CLI-004** Human-readable output MUST go to stdout; structured events (DEP-050) MUST go to stderr.
- **CLI-005** Exit codes MUST be: `0` success; `1` verification or validation failed; `2` usage error; `3` configuration or adapter error; `4` a resource was not found; `5` a policy denied the operation; `6` internal error.
- **CLI-006** Commands MUST be stateless between invocations except through the adapters they are configured with, and MUST be idempotent where the operation allows (repeating a publish of the same content address MUST succeed without a second log entry).
- **CLI-007** Keys generated or used through the software `KeyStore` adapter MUST be marked unattested in any request, evidence or output they appear in. The CLI MUST NOT produce evidence that claims hardware protection for a software key.
- **CLI-008** The CLI MUST NOT print secret values, private keys, decrypted subject data or roster contents to stdout or stderr, except `bundle open` and `intake replay`, which MUST require `--reveal` and print a warning to stderr.
- **CLI-009** The CLI MUST run as a one-off admin process against a release (factor XII): pointed at a deployment's environment, it uses that release's adapters and policies.

### Environment variables

| Variable | Meaning |
|---|---|
| `FIELDSEAL_CONFIG` | Optional configuration file |
| `FIELDSEAL_ENVIRONMENT` | Deployment environment name |
| `FIELDSEAL_RELEASE` | Release content address to act against |
| `FIELDSEAL_TRUST_BUNDLE` | Trust bundle path or content address |
| `FIELDSEAL_REGISTRY_URL` | Artefact registry URL |
| `FIELDSEAL_LOG_URL` | Transparency log URL |
| `FIELDSEAL_FACTORY_URL` | Factory URL. The scheme selects the transport (CLI-021): `http://` and `https://` are built in |
| `FIELDSEAL_INTAKE_URL` | Upload endpoint URL (`export upload --to`); the scheme selects the transport (CLI-021) |
| `FIELDSEAL_SIGNER` | Signer adapter and reference (for example `pkcs11:slot=publisher`, `soft:./keys/dev/`). `soft:<dir>` is the development custody: a key directory of software keys, unattested (CLI-007). A build without the named adapter refuses it with exit `3` |
| `FIELDSEAL_POLICY` | Policy layers (comma-separated content addresses or paths) |
| `FIELDSEAL_LOG_FORMAT` | `json` (default) or `text` for stderr events |
| `FIELDSEAL_ADAPTERS` | Adapter set: `memory` (default, one invocation) or `files` (the transparency log, artefact registry and issued registration tokens kept in `FIELDSEAL_STATE_DIR`) |
| `FIELDSEAL_STATE_DIR` | Directory for the `files` set (default `.fieldseal`) |
| `FIELDSEAL_LOG_ORIGIN` | Origin of the local development log (default `fieldseal-local-log`) |
| `FIELDSEAL_REKOR_URL` | Rekor base URL. The public log is contacted only when this is set explicitly |
| `FIELDSEAL_NOW` | Authority time to act at, for reproducible runs (default: the system clock); `--at` overrides |

### Commands

Each row gives the command, what it does, its main inputs and outputs, ports used, and the requirements it implements. Unlisted exit codes follow CLI-005.

#### `instrument`

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `instrument validate <file>` | Check an instrument against its schema version, strictly | YAML/JSON → findings | — | INS (schema, versioning) |
| `instrument lint <file>` | Style and safety checks beyond schema: unused items, unreachable rules, missing units, consent declared where subjects are named | file → findings | — | INS (authoring rules) |
| `instrument preview <file>` | Render the instrument headlessly with the control catalogue and evaluate rules against sample answers | file, `--answers` → rendered tree, rule verdicts | — | INS (controls, rules) |
| `instrument hash <file>` | Canonicalise and print the content address | file → `sha256:…` | — | WIRE §canonical, INS |
| `instrument compile <file>` | Expand the element tree, repeats and relative rules, and print the compiled instrument | file → compiled tree | — | INS §5.12–5.14 |
| `instrument i18n extract <file>` | Write each declared language's texts to XLIFF 2.1 files for translators | file, `--lang` → `.xlf` files | — | INS-082–INS-084 |
| `instrument i18n merge <file> <xlf>…` | Merge reviewed translations back into the authoring form, checking completeness and message variables | files → updated authoring form, findings | — | INS-082–INS-084 |
| `localisation validate <file>` | Check a runtime UI catalogue against a runtime's reference catalogue | file, `--reference` → findings | — | PLAT-050, PLAT-053 |
| `layout validate <file>` | Check a layout against its instrument: placement, no content overrides, allowed presentations | file, `--instrument` → findings | — | INS §5.21 |
| `layout lint <file>` | Choice-load lints, with thresholds from `--policy` or the defaults | file, `--instrument` → findings | — | INS-210–INS-213 |
| `layout compile <file>` | Compile instrument and layout into the render plan for a locale and window class; with no layout, the default | `--instrument`, `--lang`, `--window` → render plan | — | INS-206–INS-208 |

#### `schema`, `extension` and `unit` 

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `schema export [--kind <k>] [--version <v>]` | Print the closed JSON Schema of an artefact kind, with its content address | kind → JSON Schema | — | WIRE-209 |
| `schema check <file>` | Validate any Fieldseal document against its closed schema | file → findings | — | WIRE-208, WIRE-211 |
| `extension validate <file>` | Check an extension against the meta-schema and the additive-only rules | YAML/JSON → findings | — | INS-239–INS-251 |
| `extension hash <file>` | Canonicalise and print the content address | file → `sha256:…` | — | WIRE-011 |
| `extension diff <old> <new>` | Report removed or changed entries between two versions | files → findings | — | INS-250, PUB-124 |
| `unit list [--catalogue <address>]` | List the standard catalogue's entries | → entries | — | INS-231–INS-234 |

`instrument validate`, `compile` and `preview` accept `--extension <alias>=<file>` to resolve an unpublished extension for authoring (INS-246).

#### `policy`

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `policy validate <file>…` | Schema, layering and invariant floors | layers → findings | — | POL (schema, layering, invariants) |
| `policy evaluate --decision <name> --input <json>` | Evaluate a factory, runtime or intake decision | layers, input → decision and policy content address | `PolicyEngine` | POL (evaluation); REG, DIS, INT decisions |
| `policy diff <a> <b>` | Show the effective change between two policy sets | two sets (a file, or layers joined with commas) → per-control diff, each change tighter, looser or changed | — | POL |
| `policy effective [<file>…]` | Show the merged controls and the layer addresses | layers (or `FIELDSEAL_POLICY`) → effective controls, sources | — | POL-020–023 |

#### `artefact`

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `artefact provenance <file> --source <rev> --reviewers <ids>` | Emit a provenance statement | artefact → in-toto statement | `Signer` | PUB (provenance) |
| `artefact sign <file>` | Add a publisher signature over the content address and provenance | artefact, provenance → signature | `Signer` | PUB (signing, threshold) |
| `artefact verify <file>` | Verify signatures, threshold, provenance and log inclusion | artefact and evidence → findings | `TransparencyLog`, trust bundle | PUB (verification), TRU |
| `artefact publish <file> (--time-token <f> \| receipt key in custody)` | Append to the log and publish to the registry. The authority time token is required (PUB-072): given as a file, or issued by the custody's `receipt` key; with neither the command refuses (exit `2`) | artefact and evidence → registry entry | `TransparencyLog`, `ArtefactRegistry` | PUB (publish) |
| `artefact withdraw <address> --reason` | Log and publish a withdrawal | address → withdrawal entry | `TransparencyLog`, `ArtefactRegistry`, `Signer` | PUB (withdrawal) |

#### `log`

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `log key --key-file <file> [--generate]` | Print the public key (`public_key=<hex>`) of a self-hosted log's signing key file, for `trust bundle --log <origin>=<key>`; `--generate` creates the file once if absent and never replaces one (development: a production log key is in an HSM) | key file → public key | — | PUB (log), TRU-093 |
| `log append <entry>` | Append a signed entry (operators; `artefact publish` does this normally). The entry's key MUST be a current publisher key of the trust bundle | entry → inclusion proof file | `TransparencyLog` | PUB (log) |
| `log prove <address>` | Fetch inclusion proof and signed tree head | address → proof | `TransparencyLog` | PUB (log) |
| `log verify <proof> [--known-tree-head <note>]` | Verify the checkpoint is signed by a pinned log and the proof reaches its root; with a known tree head, that the checkpoint extends it (the consistency proof comes from the configured log) | proof (or a publication file) → findings | `TransparencyLog` (consistency only) | PUB (log) |

#### `trust`

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `trust root-init --ceremony <file> --out <dir>` | Create an offline root on an offline signer or HSM, with custodian threshold | ceremony parameters → root certificate, custodian credentials, signed ceremony record | `Signer` (offline) | TRU (root) |
| `trust issue --purpose <p> --validity <d> [--period <id> --period-start <t> --period-end <t> --retention <d>] --csr <file> --out <dir>` | Issue a purpose-tagged online key certificate (`--period` for `record` keys) | CSR → certificate | `Signer` | TRU (key hierarchy, domain tags) |
| `trust bundle --roots … --pins … [--attestation-roots …] [--runtime-builds …] --out <file>` | Build a trust bundle for publishing | inputs → `kind: TrustBundle` | `Signer` (offline; TRU-031) | TRU (trust bundles) |
| `trust verify <chain>` | Verify a chain against a trust bundle and revocations | chain → findings | — | TRU |
| `trust revoke <certificate> --reason <r> [--effective <time>]` | Sign a root revocation (custodian threshold) | certificate → revocation | `Signer` (offline) | TRU (revocation) |

#### `keys`

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `keys generate --purpose sign\|agree [--out <file>]` | Generate a device-style key pair (software: unattested). The handle is the key file's path (owner-readable; default `<state dir>/keys/<key ID>.key`) | — → key handle, public key | `KeyStore` | REG (local keys), CLI-007 |
| `keys generate --purpose <authority purpose> --csr <file> [--algorithm p256\|x25519]` | Generate an authority key in the key custody and export only its certificate signing request (TRU-016, TRU-091) | — → key ID, CSR | `KeyCustody` | TRU (key hierarchy), CLI-007 |
| `keys roll <handle> [--sign-key <handle>]` | Generate a successor key and a roll request: the old key's endorsement of the new public key (a signing key endorses itself and the new key proves possession; an agreement key is endorsed by the current signing key, `--sign-key`). Submitting the roll to the factory with a fresh token (REG-060) is the registration flow | handle → new handle, roll request | `KeyStore` | REG (key roll) |

#### `registration`

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `registration token --account <id> [--batch N]` | Issue a registration token as the portal would (operators, tests) | account → token text and QR PNG | factory `TokenIssuer`, `PolicyEngine` | REG (tokens, batch) |
| `registration request --token <t>` | Build a registration request with proof of possession | token, keys → sealed request, fingerprint words | `KeyStore`, `Attestor` | REG (request, PoP, fingerprint words) |
| `registration inspect <request>` | Open a request (with the registration key) and verify evidence | request → findings, words | `RecordKeyUnsealer` or registration key, `AttestationVerifier` | REG (verification), TRU |
| `registration request --token <t> --device-dir <dir>` | As `registration request`, and keep the device's software keys in `<dir>` (`sign.key`, `agree.key`, mode `0600`; reused if present) and the tenancy they register in `<dir>/tenancy`, so the device can later prove possession | token, bundle → request, words, tenancy | `KeyStore` | REG, CLI-007 |
| `registration submit <request> [--factory-url <url>]` | Submit a sealed request to the factory (`POST /v1/registrations`) and print the tenancy, its state and the fingerprint words, to compare with the portal (REG-021). Exit `3` if the factory is unreachable, `1` if it refuses | request → tenancy, state, words | factory client | REG (request), CLI-021, CLI-022 |
| `registration status [<tenancy>] [--factory-url <url>] [--device-dir <dir>]` | Read a tenancy's state (the tenancy defaults to `<dir>/tenancy`) | tenancy → state, reasons | factory client | REG (status), CLI-022 |
| `registration wait [<tenancy>] [--timeout <s>] [--interval <s>] [--device-dir <dir>] [--trust-bundle <file>]` | Poll the state until `registered` (exit `0`), a state that never becomes registered (`rejected`, `lost`, `closing`, `closed`, `retired`: exit `1`) or the timeout (default 60 s: exit `1`). With `--device-dir` it then fetches the tenancy certificate with a proof-of-possession token made by the device's own key (`GET /v1/certificate`), checks it names the device's tenancy and, given a trust bundle, that the factory signed it, and stores it as `<dir>/tenancy.certificate` | tenancy → certificate | factory client, `KeyStore` | REG (certificate), CLI-025 |
| `registration approve <request>` | Run the factory's approval decision and issue certificates | request → tenancy certificate or denial | `TenancyRegistry`, `PolicyEngine`, `Signer` | REG (approval) |

#### `bundle`

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `bundle build --tenancy <id> --instrument <addr> --roster <file> [--device-dir <dir>]` | Build and seal a bundle. With `--device-dir` the bundle is for the device that registered with a factory: its tenancy is the SHA-256 of the signing key in `<dir>` and the bundle is sealed to the agreement key in `<dir>` | inputs → bundle file |
| `bundle build --stack --device-dir <dir> --trust-bundle <f> --custody <dir> --publication <f> --policy-publication <f> --roster <f> --tenancy-dir <dir> --state <dir> [--issued-dir <dir>] [--allow-unattested] --out-dir <dir>` | Build the bundle with the local stack's own authority for a device that registered with its factory: the instrument and the release policy are the ones published through the stack's log (the registry `artefact publish` filled), the tenancy is the factory's (read from its state directory), the bundle is signed by the `factory` key in the key directory and sealed to the device's agreement key, and the roster issued is recorded in `--issued-dir` for the intake endpoint's consent checks. `--allow-unattested` marks the software keys attested for the roster release (INV-10), which production policy never accepts. `bundle verify --stack` checks it under the stack's publishing policy | device directory, publications, roster → bundle, device file, trust bundle | `ArtefactRegistry`, `RegistryStore` (read), `KeyCustody`, `PolicyEngine` | DIS-001–DIS-030, CLI-007, CLI-019 | `ArtefactRegistry`, `TenancyRegistry`, `Signer`, `PolicyEngine` | DIS (build, sealing) |
| `bundle inspect <file>` | Show the envelope and signatures without decrypting | bundle → header, signer, sizes | trust bundle | DIS (verification order), WIRE §bundle |
| `bundle open <file> --key <handle> [--reveal]` | Decrypt as the device would and validate | bundle, agreement key → contents summary (full with `--reveal`) | `KeyStore` | DIS, PUB (on-device verification) |
| `bundle verify <file>` | Full device-side verification: factory signature, artefact signatures, log inclusion, schema versions | bundle → findings | trust bundle, `TransparencyLog` | DIS, PUB, INS |

#### `device`

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `device export --device-dir <dir> --trust-bundle <file> --out <file> [--no-parity]` | Write the export of a device that registered with a factory: signed with its own key, carrying the factory's tenancy certificate (`registration wait --device-dir`), its records (`open`, `anchor`) and manifest sealed to the record key in the trust bundle; unattested (CLI-007) | device directory, bundle → export | software `KeyStore` | DEL-010–DEL-017, CLI-027 |
| `device capture --device-dir <dir> --trust-bundle <f> --bundle <f> --script <f> [--export <f>]` | Run the runtime of a device that registered with the stack's factory: it keeps its registered keys, imports the real sealed bundle (opened with its agreement key, verified against the trust bundle) and runs the script's `capture`, `status`, `consent` and `review` steps, then builds its export as the delivery code does (sealed to the stack's record key, carrying the factory's certificate), which `export upload` sends to the stack's intake endpoint | device directory, bundle, script → journal summary, export | software `KeyStore`, in-memory `Storage`, `FileBundleOpener` | COL, DEL-010–DEL-017, CLI-007, CLI-015 |
| `device simulate --script <file> [--export <file> [--no-parity]] [--upload]` | Run a headless runtime tenancy: register, import bundles, seal records (from scripted answers), review, field checks, export, upload, import receipts, clear, close. Script steps `export`, `import-receipt` and `upload` run against the real intake gate in the same process | script → journal, exports, events | software `KeyStore`, in-memory `Storage`, simulated `ElapsedClock` | COL, DEL, REG (runtime side), WIRE |

#### `export`

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `export build (--scenario <name> \| --script <file>) -o <file> [--no-parity] [--upload]` | Run a simulated device and write its tenancy's export, built and self-verified as the runtime does (parity on unless `--no-parity`); `--upload` also uploads to an in-process intake | scenario → export file, labels, gate result | software `KeyStore`, in-memory `PrivateStorage`, `FileAccess` | DEL-010–DEL-017, DEL-022 |
| `export inspect <file>` | Show header, parity flag, sizes, `seq` range (sealed parts stay sealed) | export → summary | — | WIRE §export, DEL-010–017 |
| `export verify <file> [--seed <n>]` | Verify as DEL-012 does. Without `--seed` the manifest stays sealed and only envelope, CRCs, section order and parity are checked, and the report says so; with the practice authority's seed it also checks the file signature, record signatures and chain | export → findings | trust bundle | DEL-012, WIRE |
| `export upload <file> [--to <url>] [--trust-bundle <file>] [--receipts-dir <dir>]` | Upload an export (sent without parity, DEL-016) to the endpoint at `--to` or `FIELDSEAL_INTAKE_URL` (the outbox route) and keep the receipts it returns, each verified against the trust bundle first. Exit `1` if the endpoint refuses, returns no receipt or any receipt fails to verify; exit `3` if it is unreachable | export → receipt files | upload client, trust bundle | DEL-006, DEL-007, DEL-064, CLI-026 |
| `export repair <file> -o <out> [--seed <n>]` | Repair from parity and write a corrected file, only if it then verifies; names the shards rebuilt, or `E_PARITY` and the frames that can be salvaged | export → repaired export, report | — | DEL-014, INT-005, CLI-016 |

#### `receipt`

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `receipt issue --tenancy <id> --last-seq <n> --journal-hash <h>` | Issue a receipt (operators, tests), signed by the `receipt` key of the development custody | inputs → receipt file and QR image (SVG, as `registration token`) | `ReceiptSigner` | DEL-006, DEL-043–044, INT-014 |
| `receipt verify <file>` | Verify a receipt | receipt → findings | trust bundle | DEL-007 |

#### `intake`

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `intake run <file>…` | Run submissions through the gate and land them | exports or upload bodies → gate states, findings, receipts | all intake ports | INT-001–061 |
| `intake replay <submission> [--reveal]` | Re-run a stored submission against given instrument and policy versions | submission ID → findings | all intake ports | INT-012, INT-053 |

#### `deployment`

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `deployment validate <manifest>` | Validate a deployment manifest | manifest → findings | `ArtefactRegistry` | DEP-001–006 |
| `deployment render <manifest> --environment <e> [--out <dir>]` | Render per-component environment and device provisioning configuration | manifest → env files, provisioning configuration | `ArtefactRegistry` | DEP-012, DEP-020 |
| `deployment release <manifest> --publication <addr> --build <component>=<file>… (--signing-key-file <f> \| --practice) [--out <f>]` | Create a release: signed builds plus the published manifest, content-addressed; one signing choice is required, and `--practice` (development key) is refused for production (DEP-023) | builds, manifest, publication evidence → release address | `BuildRegistry`, `ArtefactRegistry` | DEP-005, DEP-010, DEP-011 |

#### `docs`

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `docs build <manifest> --environment <e> --release <addr> -o <dir> [--instrument <f>]… [--policy <f>]… [--trust-bundle <f>]` | Generate the release's documentation bundle from the manifest and the artefacts it references | release → documentation bundle | `ArtefactRegistry`, `BuildRegistry`, `DocumentationSink` | DEP-030–033 |

#### `conformance`

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `conformance run [--suite <name>] [--target <impl>]` | Run golden vectors and contract tests against this CLI or another implementation, and report coverage by requirement ID | suite → pass/fail per requirement ID | as each suite needs | Every spec's §8 |

### Command requirements

- **CLI-010** `instrument validate` and `policy validate` MUST exit `1` on any finding of severity error, and MUST be usable as a CI gate.
- **CLI-011** `instrument preview` MUST use the same control catalogue, rule evaluator and render-plan compiler as the runtime (through the format core), and MUST accept `--layout` and `--window`.
- **CLI-011a** `layout validate` MUST exit `1` on any finding of severity error, and MUST be usable as a CI gate.
- **CLI-011b** The CLI's own messages MUST come from a message catalogue (PLAT-050 applies), and every machine-readable output (`--json`) MUST be locale-independent.
- **CLI-012** `artefact publish` MUST refuse an artefact that `artefact verify` would reject, and MUST refuse to publish without an authority time token (PUB-072).
- **CLI-013** `registration request` with software keys MUST mark the request unattested (CLI-007); `registration approve` MUST then deny it unless the policy in use explicitly allows unattested keys, which production policy MUST NOT do.
- **CLI-014** `bundle open` MUST perform the same verification order as the runtime before decrypting.
- **CLI-015** `device simulate` MUST produce journals and exports that pass `intake run` byte-for-byte equivalently to a real runtime's, apart from attestation evidence.
- **CLI-016** `export repair` MUST NOT change any record; it writes only bytes recovered by parity, and MUST report which shards were rebuilt.
- **CLI-017** `conformance run` MUST report, for every requirement ID in the specs, whether a test covers it and whether it passed; uncovered IDs MUST be listed.
- **CLI-018** `docs build` MUST be deterministic: the same release produces byte-identical documentation.
- **CLI-019** A command that signs with the software `KeyStore` or the development custody MUST say so in its output (a note, and `custody` and `attested: false` in `--json`), and a key held in either MUST NOT be described as hardware-protected.
- **CLI-020** Exit `5` MUST be returned when a policy decision other than `allow` or `flag` stops the operation (`deny`, or `hold` awaiting a person), for example `policy evaluate`, `registration token` and `registration approve`.
- **CLI-030** Every reader of CLI input (flags, positional arguments and `FIELDSEAL_*` environment variables) MUST reject unknown fields, enforce exact types, and enforce every declared constraint. An unknown flag, a flag without its value, a switch given a value (`--json=1`), and a surplus positional argument are usage errors (exit `2`); an environment variable with an unknown or malformed value is a configuration error (exit `3`), never ignored or defaulted.
- **CLI-031** A flag that takes a value MUST be given at most once unless the command tree marks it repeatable (`--lang`, `--layout`, `--reviewers`, `--revocations`, `--key`, `--policy`, `--build`, `--instrument`, `--log-origin`, `--log`); the last one MUST NOT silently win. A flag's value MUST NOT be another flag (write `--flag=--value` to pass one). Numbers are ASCII digits only (no sign, separators or prefix); hexadecimal is digits `0-9a-f` only; a duration is digits and one unit of `s`, `m`, `h`, `d`; a time is epoch milliseconds, `YYYY-MM-DD` or `YYYY-MM-DDThh:mm:ssZ`, with fixed-width fields naming a real date and time of day.
- **CLI-032** `registry show` and `registry fetch` MUST accept an artefact's content address, a prefix of one, or its name. Names are not unique (versions, kinds): a name or prefix that matches more than one artefact MUST be refused with exit `2` and the matches listed with their kind, name, version and address, never resolved by guessing. `registry fetch` MUST NOT hand out an artefact that does not verify against the trust bundle.
- **CLI-021** A command that talks to a service MUST choose the transport from the scheme of the service's URL (`--factory-url`/`FIELDSEAL_FACTORY_URL`, `--to`/`FIELDSEAL_INTAKE_URL`, `FIELDSEAL_TRANSLOG_URL`), the same way for every command and every service: `http://` and `https://` are built in; `grpc://` and `grpcs://` are the gRPC transport, built in slice 2 of [ADR 0035](../../explanation/adr/0035-service-contracts-and-transports.md) (until then they are refused, CLI-023).
- **CLI-022** Commands MUST depend only on transport-neutral client ports for the factory (submit a sealed registration request, read its status, fetch the tenancy certificate), the upload endpoint (upload an export, receive receipts) and the transparency log (the Publishing context's `TransparencyLog` port), and MUST NOT build HTTP requests themselves; a transport is an adapter behind the port.
- **CLI-023** A URL whose scheme names a transport that is not built into the binary MUST be refused with exit `3` and a message that says so, and an address without a known scheme with exit `3`; neither may fall back to another transport.
- **CLI-025** `registration wait` MUST exit `0` only when the factory reports the tenancy `registered` and, with `--device-dir`, the certificate it returned names the device's tenancy (and verifies against the trust bundle when one is given); it MUST NOT report success on a timeout.
- **CLI-026** `export upload` MUST verify every receipt against the trust bundle (DEL-007, DEL-064) before it stores any, and MUST fail when none is returned.
- **CLI-027** `device export` MUST sign with the device's registered key and use the factory's certificate and the record key the trust bundle certifies for the certificate's collection period; it MUST fail rather than produce an export that names another tenancy.
- **CLI-028** Every call a client port makes MUST carry a deadline, whatever the transport, with a default and a `--timeout <s>` flag; a deadline that passes is reported as an unreachable service (exit `3`). Built in slice 2 ([ADR 0035](../../explanation/adr/0035-service-contracts-and-transports.md)).
- **CLI-029** From slice 2, `grpc://` and `grpcs://` MUST build the gRPC client adapters (`tonic` over rustls) behind the same client ports as CLI-022, so that no command changes and CLI-023 applies only to transports still unbuilt; the adapters send the PoP token as `fieldseal-pop` metadata (WIRE-197) and map gRPC status to the same exit codes as the HTTP statuses (DEL-074). Built in slice 2.

- **CLI-040** No command MUST have a flag or environment variable that relaxes schema validation (WIRE-210). Every command that reads a document MUST validate it first and exit `1` with findings (WIRE-211) on failure.
- **CLI-041** `schema export` MUST print exactly the schema the validators use, and its output MUST be deterministic and addressed by content (WIRE-209).
- **CLI-042** `instrument preview` MUST enforce every constraint of INS-252 in the HTML it produces and MUST pass the scenario corpus of INS-255.
- **CLI-043** `conformance run` MUST provide the suites `strict-schema` (WIRE-213) and `ins-ui-constraints` (INS-255), and `conformance list` MUST name them.

## 6. Resources and formats

The CLI reads and writes resources defined in other specs. Its `--json` output documents follow:

```json
{
  "command": "export verify",
  "ok": false,
  "exitCode": 1,
  "findings": [
    { "id": "DEL-012", "severity": "error", "message": "record 42 signature invalid", "where": { "seq": 42 } }
  ],
  "release": "sha256:…"
}
```

## 7. Twelve-factor

| Factor | CLI |
|---|---|
| I. Codebase | Same repository and core as the services |
| II. Dependencies | Locked; distributed as a single binary where possible |
| III. Config | `FIELDSEAL_*` environment and flags; files only when named explicitly |
| IV. Backing services | Same adapters as the services, chosen by configuration |
| V. Build, release, run | Binary → binary + environment → invocation |
| VI. Processes | Stateless one-shot processes |
| VII. Port binding | Not applicable |
| VIII. Concurrency | Parallel invocations; no shared local state |
| IX. Disposability | Idempotent, resumable commands; interrupted publishes leave nothing half-logged |
| X. Dev/prod parity | Same binary for development, CI and operations |
| XI. Logs | Structured events to stderr; `--json` result to stdout |
| XII. Admin processes | The CLI is the admin-process tool for every service |

## 8. Conformance

| Test | Covers | Check |
|---|---|---|
| Command tree, exit codes, `--json` shape | CLI-001–005 | Snapshot tests of `fieldseal --help` and outcome documents |
| No secrets or subject data in output | CLI-008 | Output scanner over the conformance suite |
| Software keys always unattested and denied by production policy | CLI-007, CLI-013 | `registration request` then `registration approve` with production policy fixtures |
| Simulated device output accepted by intake | CLI-015 | `device simulate` then `intake run` |
| Repair touches only parity-recovered bytes | CLI-016 | Golden corrupted exports |
| Coverage report lists every requirement ID | CLI-017 | `conformance run --json` |
| Transport by URL scheme; unbuilt transports refused | CLI-021, CLI-023, CLI-028, CLI-029 | Unit tests of the client connect functions; `export upload --to grpc://…` exits `3` |
| Register over HTTP, upload, receipts verify | CLI-025, CLI-026, CLI-027, DEL-071 | `just demo` (compose stack), and the end-to-end flow of `docs/how-to/run-the-local-stack.md` |
| Deterministic documentation | CLI-018 | Two builds compared byte for byte |
| Flags and environment are closed and exact | CLI-030, CLI-031 | Unit tests of the argument parser, `support` parsers, `conformance` and `device` flags, and `Config::from_lookup` |

## 9. Open questions

1. Should the portal's registration-token and receipt QR images be produced by the CLI's code path, so they are byte-identical to `registration token` and `receipt issue`?
2. Should `device simulate` support a "fault" mode (power cut, corrupted write) for delivery fault-injection tests, or should that be a separate suite?

## 10. References

- ADRs: [0005](../../explanation/adr/0005-format-core.md), [0006](../../explanation/adr/0006-cli-reference-implementation.md), [0009](../../explanation/adr/0009-publishing-with-provenance.md), [0011](../../explanation/adr/0011-policy-as-signed-files.md), [0013](../../explanation/adr/0013-registration-via-authority-tokens.md), [0025](../../explanation/adr/0025-twelve-factor-deployments.md)
- in-toto attestation framework; SLSA build provenance
