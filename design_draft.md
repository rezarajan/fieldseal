# Developer Experience First: Survey Authoring, Results Export, Dev Loop and Guided Demo

*   **Author:** Reza Rajan
*   **Status:** Proposed
*   **Date:** 2026-10-28

--------------------------------------------------------------------------------

## Overview

Fieldseal is hard to pick up. This design covers four workstreams in one document, because they share files, decisions and a migration gate:

1.  **Survey authoring and the folder/`msgctxt` migration.** Each survey becomes one folder by convention (`instrument.yaml`, `layouts/<window>.yaml`, `i18n/<lang>.po`). `.po` becomes the only translation format, with keys that do not depend on position. A scaffold command, a check command, editor schema support and a tutorial give a newcomer a starting point. The decoder rewrite lands in its own commit first, and then the existing examples move to the new layout in one commit.
2.  **Open results export from one shared, versioned table.** Opening a results export shows the survey's answers and offers them as downloads in JSON Lines and CSV, with the data contract, a codebook view and a manifest of file digests. One table replaces the two long formats that exist today.
3.  **A container-free dev loop.** A `just web` recipe gives an edit-and-reload loop that does not rebuild container images. Baselines for `just up` and for CI are measured, and targets are set from them. The first version of the recipe arrives right after the authoring work and runs the services that already exist; each later phase adds its own service to it.
4.  **An eight-step guided demo on the production services.** The existing web pages are put in order and each step confirms what happened, read from the real services. The demo runs the production binaries (`fieldseal-factory`, `fieldseal-translog` and a new `fieldseal-intake` app) with development adapters behind their ports. Only the collector stand-in (`fieldseal-web`, with the WebAssembly device) is demo-only, and it reaches those services only over their production HTTP APIs. The authority-side results reader is a page of the intake app, behind the same OIDC sign-in as the factory portal.

Phase 0a comes first: it replaces the bundled food example with an original survey, so no later step names the old example. The rest of the work is ordered as survey authoring, a first dev loop on the services that already exist, the results export and the production services, the collector stand-in that reads them and the finished dev loop, and then the demo. The web tests on the real services, the removal of the in-memory demo authority and the documentation follow the demo. Much of the dev loop and demo already exists, but no recipe or document leads to it, so most of the work is finishing, connecting and documenting.

**Terms.** Tenancy, cohort, roster, fingerprint and custody are defined in the [glossary](../reference/glossary.md). The glossary does not define these. A section number written `§N` refers to the Technical Plan.

*   A *bound layout* is a layout whose canonical document names its instrument by the instrument's salted fingerprint, not by a file path (INS-200).
*   A *window class* is the screen-size class a layout targets, for example `compact` or `expanded`.
*   A *generation* is the number that rises when a cohort moves to a new tenancy (REG-045). The factory keeps it per cohort and tenancy.
*   *Succession* is the move of a cohort to a successor tenancy at `generation + 1` (REG-045, DIS-051). This design does not build it.
*   The *agreement key* is a tenancy's key-agreement public key. The tenancy's bundle is sealed to this key (DIS-020).
*   A *PoP token* is the proof-of-possession token that a device signs for each API call (WIRE-170).
*   *FSB1* is the magic of the sealed bundle file.
*   The *practice authority* is the fixed-seed, in-memory intake authority used for practice device exports and conformance runs (§7.1).
*   The *collector stand-in* is `fieldseal-web`, the web app that stands in for the native Android and iOS apps. It is the only demo-only component.
*   The *WebAssembly device* is the device runtime that the collector stand-in runs in a browser worker.
*   The *development IdP* is `fieldseal-dev-idp`, a development-only OIDC provider that `just web` runs where Keycloak runs in the stack (§7.5).
*   A *device export* is the sealed file that a device uploads to intake (the DEL requirements).
*   A *results export* is the set of open files that `fieldseal intake results` and the results reader produce (§6).
*   The *results reader* is the page of the intake app at `:8481/results`.
*   The *export pseudonymisation key* is the 32-byte key that turns roster subject ids into the keyed hashes in a results export (§6).
*   The *intake gate* is the set of checks a submission passes before it lands (`IntakeService`).
*   *Landing* is the step that writes accepted records to the authority's tables. Data that has passed it is *landed*.
*   The *reconciler* is the factory component that compares each tenancy's build inputs with those of its last build and calls `BuildBundle` when they differ (§7.3).
*   A *composition root* is the one place in a deployable that creates the adapters and wires them to the use cases (ADR 0028).
*   The *stepper* is the set of guided-demo pages at `/demo/1..8` (§9).
*   The *custodian* is the authority role that decides consent and exclusion for landed records (INT-055).
*   *Driven ports* are the ports that a use case calls out through, for storage, time or other services. *Driving ports* are the ones that call the use case.
*   *Characterisation tests* record what existing code does before a refactor, so that the refactor can be checked against them.
*   A *fuzzy entry* is a gettext `.po` entry that is marked for review. `msgfmt` skips it, and this design treats a stale entry the same way (§3).
*   To *overfit* to the demo is to build something that works for the demo and not for production.
*   The *golden set* is the recorded expanded documents, addresses and fingerprints of the examples (§2). The *migration gate* (`just migration-gate`) compares a tree against it (§5).
*   *Entry N* is the item numbered N in the file list of the Detailed Implementation Plan.
*   *The project owner* is the owner of this repository, who set the Demo fidelity rule (§10.1).
*   *SR-1* to *SR-4* are the four security reviews listed in Non-Functional Requirements.
*   Requirement ids carry a prefix that names the specification in `docs/reference/spec/`: INS (instrument.md), REG (registration.md), DIS (distribution.md), WIRE (wire-formats.md), DEP (deployment.md), DEL (delivery.md), INT (intake.md), CLI (cli.md), WEB (web-app.md), POL (policy.md), PLAT (platform-profiles.md), PUB (publishing.md) and TRU (trust.md).

**Hard constraints:**

*   No change weakens signing, threshold publication, sealing, attestation or fail-closed policy. Every artefact's address and layout fingerprint stays the same across the migration.
*   **Demo fidelity rule.** The demo runs the production binaries, ports, protocols and flows; only adapters behind ports differ (Technical Plan §10.1).

## The Problem

A developer who also writes surveys tried Fieldseal and hit these problems.

*   **No starting point.** There is no tutorial for writing a survey. `examples/README.md` warns against copying the examples blindly. `docs/index.md` says "Tutorials: None yet", although `docs/tutorials/hands-on.md` exists. The three file kinds use three header conventions (`survey:`, `layout:`, and `apiVersion`/`kind`). A roster's link to its survey exists only in a deployment config string. Deployments use `apiVersion`/`kind` while surveys use `survey:`.
*   **No rule for which file holds a setting.** Settings are spread over the instrument, the layout, the roster and the translation catalogues. Merging every file in a folder by content would not answer this, because any file could then hold any key. It would also leave the merge order undefined, and the authoring adapter promises that what a reviewer reads is exactly what gets signed (`crates/adapters/authoring/src/lib.rs`).
*   **Translations cannot be pieced together.**
    *   Layout translations are keyed by position (for example `steps.1.contents.0.card`), so inserting a step moves every later translation onto the wrong text.
    *   Catalogue paths come from the YAML file name, so a rename loses translations without a warning.
    *   Empty translations are dropped, and the English source text is discarded on load, so stale translations go unnoticed.
    *   One survey has two catalogue folders (`examples/instruments/i18n/<survey>/` and `examples/layouts/i18n/<survey>.compact/`).
    *   A second pipeline, `instrument i18n extract|merge`, writes XLIFF files.
*   **Weak error reporting and no single schema.** Survey files are untyped trees checked by hand in about 1,250 lines of `crates/adapters/authoring/src/compact.rs`, and errors in that syntax report line 0, column 0. Policy has a separate schema (`crates/contexts/policy/src/domain/schema.rs`).
*   **Three ways of finding a survey's layout and roster.** The CLI follows a relative path, the `web-demo` adapter matches by file name and skips invalid content with only a terminal warning, and example paths are hard-coded in tests, scripts, `include_str!` calls and the compose file.
*   **Two unfinished design records.** ADR 0039 (Proposed, marked incomplete) and ADR 0040 (Proposed) disagree on translation keys: 0039 uses short fixed ids, 0040 uses English text plus a context string. The compact dialect itself is already implemented in `crates/adapters/authoring/src/compact.rs`. What is missing is the schema export, the `expand` and `new` commands, and real error positions: the CLI has no `schema`, `expand` or `new` command, and syntax errors report line 0, column 0.
*   **A slow dev loop.** `just up` takes about five minutes. Image loading is already skipped when the Nix output is unchanged (`tools/stack-images.sh`), so the time goes into building the images: each is a separate crane build, and any source change rebuilds all of them. Waiting for Keycloak can add up to 240 seconds. A container-free loop exists (`FIELDSEAL_WEB_DEMO_AUTHORITY=true cargo run -p fieldseal-web`, in `docs/how-to/use-the-web-app.md`) but has no `just` recipe and is not listed in `just --list`. A CI run on a cold cache took over an hour.
*   **A demo with no order and no results.** The collector stand-in has Publishing, Registration, Device and Intake pages, and `tools/demo-pipeline.sh` covers all eight steps, but nothing guides a newcomer through them or confirms a step finished. The audience is field collectors and an IT person who will deploy to production. They cannot load a results export back and read it, so they have no reason to believe the results export format works in production.
*   **A demo that does not run what production runs.** `fieldseal-web` with `FIELDSEAL_WEB_DEMO_AUTHORITY=true` hosts an in-memory authority (`crates/adapters/web-demo`) that replaces the factory, the upload endpoint, the intake gate and the results table with an in-memory stand-in in one process. In stack mode it builds a device's bundle by spawning `fieldseal bundle build --stack` (`crates/apps/web/src/stack.rs`), a delivery path production does not have: the specs say a runtime fetches its bundle from the factory with a proof-of-possession token (DIS-040), and `crates/adapters/factory-http` has no such route. The only intake endpoint that runs as a service is the development binary `fieldseal-upload-server`, which is not a composition root (the one place that creates a deployable's adapters and wires them to its use cases) and does not refuse development adapters.
*   **Two long formats that disagree.** `crates/adapters/landing-files` writes the 20 `LONG_COLUMNS` from `crates/contexts/intake/src/data_contract.rs`. The collector stand-in's `/intake/rows.csv` (`crates/adapters/web-demo/src/intake_world.rs`) writes a different column set, decodes the roster `subject_id`, has no `retracted` column, and prefixes values starting with `=`, `+`, `-` or `@` with `'`, so `-5` becomes `'-5`. The CSV has no schema version, so adding columns later would break tables built on it.
*   **No separation of roles in the demo.** The in-memory demo runs authority, intake and collector in one process on one address. "The collector's browser never decrypts" holds, but the IT audience sees no real separation. `/intake` returns 404 against the container stack, so the results reader could show only the in-memory demo's data and never the data that a production-shaped intake landed.
*   **No way to tell whether any of this helps.** There is no target time for a first survey, no defined starting state, no baseline timing for `just up` and no target CI time. It is not known whether the CI cache (`FIELDSEAL_CACHIX`) is configured.

## Goals

*   **Each survey is one folder, and migrating the examples changes nothing signed.** A survey is one instrument, its layouts and its `.po` catalogues in a folder with a fixed shape.
    *   Done when: every example loads from its folder and keeps the same `sha256:` address and layout fingerprint, verified by the migration gate (Resolved Decisions 1 and 2 describe the mechanics).
*   **The migration is one revertible change with one way to find a survey.** The examples, every hard-coded loader and a shared resolver for surveys, layouts and rosters move together, and the CLI, the collector stand-in and tests all use that resolver.
    *   Done when: a single commit holds the migration, the resolver is the only lookup path, and no test, script, `include_str!` call or compose file hard-codes an example path.
*   **`.po` is the only translation format, and translations survive edits.** Inserting a step or renaming a file moves no translation and loses none.
    *   Done when: missing, orphaned and stale translations are reported with file and line, a declared language with no catalogue produces a warning, and no XLIFF code remains (Resolved Decisions 3 and 8).
*   **Authors get real error positions and editor support.** Errors carry real line and column numbers, and an editor schema gives autocomplete and errors.
    *   Done when: a test shows the schema and the decoder accept and reject the same documents, and a deliberate mistake reports its true line and column (Resolved Decision 4).
*   **A newcomer gets a working starting point.** `fieldseal new survey` creates a survey, and `fieldseal survey check <dir>` validates it.
    *   Done when: a freshly scaffolded survey passes `survey check` with no errors, and the check runs validation, lint, layout checks and the translation report in one pass (Resolved Decisions 5 and 6).
*   **A newcomer can write and publish a working survey without reading the ADRs, and how long that takes is known.**
    *   Done when: a defined test newcomer, on a defined machine, starts from `fieldseal new survey` and the tutorial and reaches a survey that passes `survey check` (Phase 5), then publishes it and sees its artefact address (Phase 5b); both times are recorded, and the target in Open Question 1 is set from them.
*   **Documentation tells a newcomer where things go.** There is a tutorial, "Write and publish your first survey", a reference table of which file holds each setting, and one design record.
    *   Done when: the tutorial and table exist, `docs/index.md` links to the tutorials that exist, and the design record "Survey source tree and authoring toolchain" replaces ADR 0039 and takes over ADR 0040 sections 2 and 3, with sections 4 and 5 left as a separate decision.
*   **Editing a survey and seeing the result needs no container rebuild.** A `just web` recipe starts the development identity provider, the production service binaries natively (`fieldseal-factory`, `fieldseal-translog`, `fieldseal-intake`) with development adapters, and the collector stand-in.
    *   Done when: `just web` runs all five processes (the development IdP, the three services and the collector stand-in) from one rendered deployment configuration, an authoring edit shows on the Instruments page without a restart, and `tools/dev-web.sh --check` verifies the configuration (Resolved Decisions 13 and 14). The first version, on the services that exist, arrives in Phase 5b, and each later phase adds its own service.
*   **The time spent in `just up` and in CI is known, stage by stage.**
    *   Done when: `just up` is timed per stage (image builds, image loads, Keycloak wait, service start), a CI run on a warm cache is timed, both baselines are recorded in `docs/explanation/build-system.md`, targets are set from them (Open Question 1), and whether `FIELDSEAL_CACHIX` is set in CI is answered (Open Question 2).
*   **Every demo step is performed by the production component that performs it in production.** See Technical Plan §10.1 for the Demo fidelity rule.
    *   Done when: a table in Technical Plan §9 names, for each of the eight steps, the production component, binary, command or page that performs it, and the demo uses exactly that; no demo-only endpoint, authentication or delivery path exists; and a test or check lists every development adapter a running demo uses and fails if a service uses one that its rendered configuration does not label as development.
*   **A newcomer can walk through the whole system in eight confirmed steps.** The existing web pages are put in order, and each step shows a confirmation the audience can trace to a real service.
    *   Done when: all eight steps run on the bundled examples and each shows an artefact address, log index, receipt or correlation id read from the service that issued it, a banner states that the collector stand-in stands in for native apps, and the demo points the IT audience to `just acceptance` or `just release` for production. The stepper performs no action on the authority's behalf: publication and roster issue are CLI commands that the presenter runs, and the factory builds each bundle.
*   **Results can be read on the authority side, behind a real sign-in.** A page of the intake app and a `fieldseal` CLI verb open the same results export. The verb is new (for example `fieldseal intake results`), because `fieldseal export` is taken by the sealed delivery file.
    *   Done when: the results reader is served by `fieldseal-intake` on its own port behind the OIDC sign-in, session, CSRF and role checks the factory portal uses (the development IdP in `just web`, Keycloak in the stack); a test shows that a signed-in `collector` without the `results-reader` role, and the collector stand-in, are refused; a second test shows a device bundle never contains the record key's secret.
*   **A device gets its bundle the way production delivers it.** The factory builds a registered device's bundle on registration and when an input changes (a publication, a roster version, an assignment made through the operator API), and the device fetches it with a proof-of-possession token.
    *   Done when: the factory app wires the artefact registry, roster source and bundle store and builds and stores bundles; `GET /v1/bundle` and the portal download serve the stored bundle; both are specified in the registration and distribution specs; the CLI (`fieldseal bundle fetch`) and the WebAssembly device both use the route; and the collector stand-in's `GET /device/bundle`, which spawns the CLI, and the `bundle build --stack` variant are removed (Technical Plan §7.3; spec change, security reviews SR-2 and SR-3).
*   **Rosters have production commands.** `fieldseal roster check`, `issue`, `diff`, `list` and `assign` exist and are specified. `issue` and `assign` are operator operations of the factory, behind a Bearer token and journaled.
    *   Done when: the five commands are in `docs/reference/spec/cli.md` with requirement ids, the roster store passes the `RosterSource` contract test, a version once issued cannot change, no command prints subject ids without `--reveal`, an assignment targets one account, and demo step 5 is done with these commands (Technical Plan §7.4).
*   **Results export to open formats from one shared, versioned table.** Opening a results export shows the survey's answers and offers them as downloads in JSON Lines and CSV, with a data contract, a codebook view and a manifest. A documented DuckDB command converts the output to Parquet for a lakehouse.
    *   Done when: the results reader's `results.csv` download is the shared table, each format reads back to the same rows as the table, rows excluded for consent never appear, and the DuckDB command produces a Parquet file from both formats (Resolved Decisions 7 to 12).
*   **No security property is weakened.** Signing, threshold publication, sealing, attestation and fail-closed policy defaults are unchanged.
    *   Done when: the existing security tests pass unchanged and no default for these properties differs from before.

## Non-Goals

*   Merging survey content across files by content. It is rejected until there is a defined rule for which file wins and how order is set, because file order could change question order and the hash.
*   A guided survey-builder UI (deferred).
*   Native Android and iOS apps. Only the UniFFI bindings exist today; the demo says the collector stand-in stands in for them.
*   Running Keycloak outside a container. Passkeys need it at `localhost:8180`.
*   Publishing or threshold signing from the browser.
*   Editing rosters in the browser, or showing roster subjects on any web page. The roster commands are CLI-only (they sign in through the IdP's loopback flow, not through a web page); web pages show counts.
*   Demo-only endpoints, authentication or delivery paths (Demo fidelity rule, Technical Plan §10.1).
*   An authority-side process inside `fieldseal-web`, or an in-memory demo authority (`crates/adapters/web-demo`) on the demo path.
*   A native Parquet writer. It is deferred and, when added, goes behind a Cargo feature that is off by default; DuckDB converts in the meantime.
*   A one-row-per-response (wide) results export. Analysts pivot the long format themselves.
*   Any change to the defaults for signing, sealing, attestation or policy.
*   Live reload as part of the demo. The demo runs on the bundled examples; reload exists only in the `just web` dev loop.
*   Moving deployments or policies into survey folders.

## Resolved Decisions

1.  **Address-preserving migration.** Moving the examples into survey folders changes no `sha256:` address, layout fingerprint or expanded document, and the migration gate proves it (§5).
2.  **Decoder rewrite lands first, in its own commit.** The decoder rewrite is committed and gated before the migration, so a changed address can be traced to one change (§2, §5).
3.  **Stable translation keys.** Translations are keyed by `msgctxt` paths and authored layout ids, never by position (§3).
4.  **Schema source: a declarative schema module in the format core.** One declaration of each authoring key drives both the decoder and the generated JSON Schema (§2).
5.  **Scaffold contents.** `fieldseal new survey` writes a working instrument with pinned answer codes, a layout with ids, `.po` stubs, a README and a roster stub, and the result passes `survey check` unedited (§4).
6.  **Deployments and policies stay outside survey folders.** They vary by environment, authority or tenant, not by survey (§1).
7.  **Rosters name only their cohort and version.** A cohort can serve several surveys, so the link to a survey is assignment state, not roster content (§1).
8.  **XLIFF is removed.** `.po` is the only translation format, and the XLIFF code and spec rows are deleted (§3).
9.  **One long format.** The results export uses the Intake context's `LONG_COLUMNS` table and no other long format (§6).
10. **Export contents and versioning.** A results export is a manifest, JSON Lines and CSV tables, free-text files, data contracts and a codebook, with a semver `export_schema_version` (§6).
11. **Decimal typing.** Numbers are canonical decimal text in `value_number`, never JSON numbers (§6).
12. **Free text goes to a separate file of the results export.** A free-text answer's text is written only to `free_text.jsonl` and `free_text.csv` (§6).
13. **Content reload in the dev loop only, for the Instruments page; publishing stays a CLI step.** Editing a survey shows at once in `just web`, and a change reaches the log only through `just publish` (§8).
14. **The demo runs the production service binaries natively, with development adapters.** `just web` starts the factory, log and intake app as native processes behind the same ports as the stack (§7.1, §8).
15. **Results reader access is OIDC, as the factory portal does it.** The results reader needs a session, a role, a CSRF token on sign-out and a phishing-resistant method (§7.2).
16. **The authoring schema is `fieldseal schema export --kind survey`.** `--kind survey` covers `instrument.yaml`, and `--kind layout` covers `layouts/*.yaml` (§4).
17. **Survey-to-cohort assignments are tenancy registry state, one account per assignment.** The factory journals them, and an operator makes them through an authenticated operation (§7.4, §1).
18. **A stale `.po` entry is treated as missing.** The English text is used and `survey check` reports the entry (§3).
19. **Landed state survives a restart by replay at start-up.** A failed replay stops start-up and fails readiness (§6).
20. **Subject ids in a results export are keyed hashes.** A results export replaces each roster subject id with an HMAC under the export pseudonymisation key (§6, §10.2).
21. **Demo fidelity rule.** The demo uses production binaries, ports, protocols and flows, and only adapters behind ports differ (§10.1).
22. **A new app crate, `crates/apps/intake`, is the intake composition root.** It replaces the development upload server (§7.1).
23. **The factory builds bundles and serves the stored bundle at `GET /v1/bundle`.** The route never builds (§7.3).
24. **A `fieldseal roster` command group.** `check`, `diff` and `list` are local; `issue` and `assign` are operator operations of the factory (§7.4).
25. **The role is `results-reader`.** It is a configured role name, with no change to the Registration context (§7.2).
26. **`DataPlatform` gains an additive `instruments()` method.** The results reader and the CLI list landed instruments through the port (§6).
27. **`crates/adapters/web-demo` is deleted.** Its tests move to the real services (§7.1).
28. **The factory portal serves the stored bundle as a download.** A signed-in collector gets it for their own device (§7.3).
29. **Operator CLI commands sign in with OIDC authorization code and PKCE on a loopback redirect.** The CLI sends a Bearer access token for the factory API and stores no token (§7.5).
30. **`just web` uses a development-only OIDC provider, `crates/apps/dev-idp`.** It stands where Keycloak stands and refuses to run outside development (§7.5).
31. **The runtime reports its profile at registration.** The profile carries the instrument-schema and catalogue versions (§7.3).
32. **Layouts in bundles follow the policy control `factory.release.layouts`.** The default `bound` includes every bound layout (§7.3).
33. **Tests that need the built services run in a separate nextest `integration` profile.** `just test` keeps its 20 second budget (§8).

## Open Questions

*   **Question 1** (answered 2026-10-29): Targets. A first survey, from `new survey` to a published address, in 15 minutes; warm `just up` in 3 minutes; warm CI in 20 minutes. The test newcomer is a developer who has never seen the repository, on a typical laptop (about 8 cores, 16 GB). Recorded in `docs/explanation/build-system.md`.
*   **Question 2** (answered 2026-10-29): CI cache. `FIELDSEAL_CACHIX` is not set (the repository has no Actions variables), and it stays unset: CI uses only the GitHub Actions cache (`FIELDSEAL_CACHE_GHA`, on by default). Recorded in `docs/explanation/build-system.md`.

## Critical User Journeys (CUJs)

### CUJ 1: A newcomer writes and publishes a first survey

*   **Given**: A developer who has not read the ADRs, a checkout of the repository, the Nix dev shell, and the tutorial "Write and publish your first survey". `just web` is running, so there is a transparency log and a set of publisher keys to publish to.
*   **When**: They run `fieldseal new survey my-survey`, edit `surveys/my-survey/instrument.yaml`, run `fieldseal survey check surveys/my-survey --roster rosters/my-survey-cohort.yaml` until it reports no errors, and publish the survey with `just publish my-survey` while `just web` is running (the last steps of the tutorial). `new survey` creates the survey under `surveys/` and its roster stub under `rosters/`, both in the working directory.
*   **Then**: The scaffold passes `survey check` before any edit. Each error after an edit names the file, line and column. The published survey shows an artefact address on the Publishing page of the collector stand-in. The time from `new survey` to a passing `survey check`, and the time from there to the published address, are recorded against the targets set from Open Question 1.

### CUJ 2: An author edits English text and a translation is reported stale

*   **Given**: A survey folder with `i18n/es.po` whose entries each carry `msgctxt`, `msgid` (the English text) and `msgstr`.
*   **When**: The author changes the English label of one answer in `instrument.yaml` and runs `fieldseal survey check <dir>`.
*   **Then**: The report lists the Spanish entry for that `msgctxt` as stale, with the `.po` file and line, the old `msgid` and the new English text. A step inserted before it in a layout moves no translation, because layout keys use authored ids. A language declared in `translations:` with no `.po` file gets a warning.

### CUJ 3: A developer edits a survey and sees it in `just web` without a restart

*   **Given**: `just web` is running the production services natively (factory, log, intake) and the collector stand-in on the bundled examples, with the survey folder under the root that the collector stand-in reads.
*   **When**: The developer saves a change to a question label in `instrument.yaml`.
*   **Then**: On the next request the Instruments page shows the new label. If the edit is invalid, the page shows the last good version that this process has loaded and the error with file, line and column. After a restart whose first load is invalid, the page shows only the error. To publish the change the developer raises `survey.version` and runs `just publish <survey>`, which runs the same `artefact provenance|sign|publish` commands as production and prints them; the Publishing page then shows a new log entry read from the log. A second publication of the same name and version is refused by the artefact registry, as in production. No process restarted and no container image was built.

### CUJ 4: A demo presenter runs the eight steps, each done by its production component

*   **Given**: `just web` is running, or the same services run in the container stack with the collector stand-in pointed at them. The presenter opens the guided demo page. A banner states that the collector stand-in stands in for native Android and iOS apps.
*   **When**: The presenter moves through the steps: (1) compile the survey, (2) publish to the factory, (3) register a device, (4) load the published artefact, (5) manage rosters, (6) conduct the survey, (7) upload the device export, (8) read the results. The table in Technical Plan §9 says, for each step, who performs it in production and which command or page the demo uses. Steps that production does through the CLI (publish with threshold signatures; roster check, diff, issue and assign) are run by the presenter as the same CLI commands, shown on screen. The factory builds each device's bundle itself, so the presenter runs no bundle command. Operator commands (`roster issue`, `roster assign`) sign in through the IdP with a loopback redirect: under the development IdP this completes at once, and in the stack it is a passkey touch.
*   **Then**: Each step ends with a confirmation read from the service that issued it, with a "check it" link:
    1.  Step 1: the artefact address and layout address, from the local compile and labelled as such.
    2.  Step 2: the log index and verdict, from the log.
    3.  Step 3: the tenancy and registration state, from the factory.
    4.  Step 4: the bundle sequence from the factory's bundle response, and the device's verification steps.
    5.  Step 5: the roster cohort, version and subject count, from the bundle the device holds after a new roster version is issued and fetched.
    6.  Step 6: the record count and sequence range, from the device.
    7.  Step 7: the device export's file name, its SHA-256 and the receipt ids, from the upload response.
    8.  Step 8: the row count, the manifest digest and the `export_schema_version`, on the results reader.

    The stepper never performs an action for the authority. The last screen points the IT person to `just acceptance` and `just release` for production.

### CUJ 5: The authority opens the results export and downloads open-format files

*   **Given**: Landed data from step 7 in the intake app, and a signed-in person with the `results-reader` role.
*   **When**: The authority runs `fieldseal intake results --landing <dir> --published <dir> --export-key <file> --out <dir>` and, separately, signs in to the results reader (the development IdP in `just web`, Keycloak in the stack) and downloads the results export files from it.
*   **Then**: Both give the same set of files, byte for byte, for the same landing snapshot: the long table as JSON Lines and CSV, `free_text.jsonl` and `free_text.csv`, the instrument's JSON data contract, the codebook view, and `manifest.json` with each file's SHA-256 and `export_schema_version`. The results reader links all its downloads to one landing mark, so a page and its downloads agree even while data lands. The results reader states beside its download links, and the CLI prints, that the files are outside Fieldseal's protection. The documented DuckDB command then converts `results.jsonl` (and the CSV) to a Parquet file, and a query on that file returns the same row count as the manifest. After the intake app is restarted, the same results export is produced again (Technical Plan §6).

### CUJ 6: A signed-in collector, and the collector stand-in, are refused the results

*   **Given**: `just web` is running. Two logins exist on the development IdP: `presenter` (roles `collector`, `operator` and `results-reader`) and `collector1` (role `collector` only).
*   **When**: (a) A request with no session asks the results reader or a results download. (b) `collector1` signs in to the results reader and asks for the same routes. (c) A request that originates in the collector stand-in (a `/proxy/*` request or a page script on its origin) asks for a results route.
*   **Then**: (a) is redirected to sign-in, and a non-page request gets 401. (b) gets 403 with the code `not-authorised`. (c) is refused by the five controls of Technical Plan §7.2. Tests in `crates/adapters/results-http` (Technical Plan §7.2) and `crates/apps/security-tests` fail if any of these becomes reachable.

### CUJ 7: A maintainer runs the migration and the migration gate proves addresses unchanged

*   **Given**: The decoder-rewrite commit has landed with its gate passing. The maintainer has the migration commit on a branch.
*   **When**: They run the migration gate (`just migration-gate`, in §5) on the base commit and on the migration commit.
*   **Then**: For every example, the bound instrument address, the layout fingerprint under the pinned salt and the expanded document are identical before and after. The gate also fails if any hard-coded loader from the inventory still names an old example path. The migration is one commit and `git revert` of it restores the old tree and passes the same gate.


## Technical Plan (Architecture)

Phase numbers in this document refer to the Phases table in the Detailed Implementation Plan.

The work follows the dependency rule in `architecture.toml` (checked by `tools/check-architecture.py`): `kernel <- contexts <- adapters <- bindings, apps`. Contexts are pure and may not use `std::fs`, `std::env`, `std::process` or print (`inner_forbidden_source`), so everything that walks a directory, reads a file or serves HTTP lives in an adapter or an app. No new context is added. The format core, `fieldseal-kernel`, gains one pure module, `schema` (§2). Four contexts change their public interface, and only in these ways:

*   Intake gains one additive field in the data contract and the additive `DataPlatform::instruments()` method (§6).
*   Deployment changes the port and adapter lists of the Intake component (§7.1).
*   Registration changes the registration request body and the `ReportedProfile` record, which carry the runtime profile (§7.3), and the `RegistryStore` port, which gains the assignment and roster-issue records (§7.4).
*   Policy gains one new control, `factory.release.layouts` (§7.3).

### 1. Survey source tree and resolver

**Folder shape.** One survey is one folder under `examples/surveys/` (the root name is a constant in one place per language). The folder name is the survey name and must equal `survey.name` in `instrument.yaml`.

```text
examples/
  surveys/
    household-water-access/
      instrument.yaml            # survey: {name, version}, items, lists, rules
      layouts/
        compact.yaml             # one layout per window class; the file stem is the window class
      i18n/
        es.po                    # one catalogue per language, instrument and layout texts together
    school-meals-baseline/
      instrument.yaml
      layouts/compact.yaml
      layouts/expanded.yaml
      i18n/es.po
  rosters/<cohort>.yaml          # outside the publishable folder (§1)
  deployments/                   # unchanged location (§4)
  scenarios/                     # scripts; refer to a survey by folder
```

Each setting has one home file: content, rules and lists in `instrument.yaml`; presentation in `layouts/<window>.yaml`; translated text in `i18n/<lang>.po`. Files are not merged by content. A layout file's stem must equal the `window` it declares (one layout per window class per survey), otherwise the resolver reports an error. Files in the folder that are none of these (other than `README.md`) are reported as warnings so a stray `instrument.yaml.bak` is not ignored without a message. `SurveyTree::open` ignores directories whose names begin with a dot, so the schema directory `<root>/.fieldseal/` (§4) is not a survey.

**The resolver.** A new module `survey` in `fieldseal-adapters-authoring` (`crates/adapters/authoring/src/survey.rs`) is the only code that knows the folder shape. It belongs in an adapter because it walks directories, and that crate already depends only on `fieldseal-kernel` and already reads files in `decode_path` (`crates/adapters/authoring/src/lib.rs`), so every adapter and app can use it without a new edge in `architecture.toml`. It never prints and never skips content without reporting it; it returns values, and callers decide how to show them.

```text
SurveyTree::open(root)              -> SurveyTree                  # lists survey folders
SurveyTree::survey(name)            -> SurveyRef { dir, instrument, layouts[], catalogues[] }
SurveyRef::load()                   -> LoadedSurvey {
                                          instrument: Value,       # expanded, with catalogues applied
                                          layouts: [(window, Value)],
                                          translation_report: [Finding] }
RosterSet::open(dir)                -> by cohort and version       # cohort files
ResolveError { pointer, line, column, kind, message }              # JSON Pointer (RFC 6901); every error has a position or a pointer
```

`ResolveError.kind` is exactly one of these:

| Kind | Meaning |
|---|---|
| `io` | a file cannot be read; the position is 0:0 and the message names the file |
| `no-instrument` | the folder has no `instrument.yaml` |
| `name-mismatch` | the folder name differs from `survey.name` |
| `window-mismatch` | a layout's file stem differs from its declared `window` |
| `missing-layout-id` | a titled step or card has no `id:` |
| `duplicate-layout-id` | two steps or two cards of one layout share an `id:` |
| `stray-file` | a file in the folder is none of the expected files (a warning) |
| `po-syntax` | a malformed `.po` file |
| `po-duplicate-context` | a repeated `msgctxt` |
| `po-bad-context` | a `msgctxt` outside the grammar of §3 |
| the six kinds of `SchemaError` (§2) | the resolver passes them through unchanged when a document fails validation |

`LoadedSurvey` is produced by the same `decode`/`expand_with` path as today, so the bytes that are hashed and signed are the bytes the decoder produces for the equivalent documents (§2, §5).

**Callers.** In the migration commit (§5), every code path that finds a survey, a layout or a roster switches to the resolver: the CLI verbs (`survey check|list`, the `instrument` and `layout` verbs when given a folder, and `device simulate` scenarios), the collector stand-in (the Instruments page keeps the resolver error of a survey that fails to load and shows it), the `web-demo` directory walk (adapted in Phase 4, because the crate lives until Phase 16c, §7.1), and the tests and tools that named example paths. The Phase 4 entries list each file.

**Embedded examples and shell paths.** Binaries that must work without the repository on disk embed examples at build time. A build script in the CLI crate calls the resolver over the survey root and generates the embedded table into `OUT_DIR`, so no source file names an example path. The Nix source filesets already include `./examples`. If `tools/check-architecture.py` rejects a build-dependency on an adapter crate, the check is extended in the same commit (see Risks & Mitigations). Shell scripts name a survey and pass the folder to the CLI. The survey root is one variable in `tools/stack-engine.sh`, and the scripts do not mention `instruments/`, `layouts/` or `.compact.yaml`. The compose file refers to the examples only through the manifest and the image, so it needs no path change.

**Assignment of rosters to surveys.** A roster names only its cohort and version. A cohort can serve several surveys, and naming one survey in the roster would force copies of personal data, so the roster file keeps `cohort:` and `version:` and nothing else. The assignment of a cohort to a survey is not in any source file or deployment manifest. It is tenancy registry state: it targets one collector's account, is made through an authenticated factory operation and is journaled (§7.4). The `cohorts: "cohort-a:1,village-a:1"` string of the `TenancyRegistry` `file-dev` config in `examples/deployments/local-stack.yaml:60` is removed in Phase 12, when `roster assign` exists, and so is `FIELDSEAL_COHORTS` in the factory (`crates/apps/factory/README.md`). The resolver knows nothing about assignments: `fieldseal survey check --roster <file>` takes the roster explicitly, and the collector stand-in lists roster files by cohort file name, as `crates/apps/web/src/catalogue.rs` does today.

**Deployments and policies stay outside survey folders.** They are per environment, per authority or per tenant, not per survey (`examples/deployments/local-stack.yaml`, `examples/deployments/policy/deployment-default.yaml`), and ADR 0040 section 4 forbids environment-varying values in a manifest. The scaffold's README says where they live. The header-convention mismatch (`apiVersion`/`kind` in deployments against `survey:` in surveys) is left to the separate deployment decision (ADR 0040 sections 4 and 5).

```text
Authoring flow

  examples/surveys/<name>/                  (or a folder made by `fieldseal new survey`)
    instrument.yaml  layouts/*.yaml  i18n/*.po
          |
          v
  +--------------------------------------------+
  | resolver  (adapters/authoring::survey)     |  one lookup path: folder shape, names,
  +--------------------------------------------+  window = file stem, catalogue per language
          |  file list + positions
          v
  +--------------------------------------------+
  | spans-aware decoder (yaml.rs / json.rs)    |  Value + line/column table
  +--------------------------------------------+
          |
          v
  +--------------------------------------------+     +-------------------------------+
  | schema module (kernel::schema)             |<----| JSON Schema generator         |
  | each key: type, values, docs               |     | -> `schema export` output     |
  +--------------------------------------------+     +-------------------------------+
          |  checked Value, findings with JSON Pointers (spans looked up by pointer)
          v
  +--------------------------------------------+
  | expand_with(catalogues)  (compact.rs)      |  layout ids dropped; msgid checked;
  +--------------------------------------------+  translation report built
          |  expanded documents (canonical Value)
          v
  +--------------------------------------------+
  | validate / lint / layout checks            |  instrument + layout contexts (pure)
  +--------------------------------------------+
          |  canonical bytes -> sha256: address; layout bound to salted fingerprint
          v
  sign / publish   (CLI artefact verbs, factory, transparency log; unchanged)
```

### 2. Declarative schema module and decoder rewrite

**Where it lives.** A new module `schema` in the format core, `fieldseal-kernel` (`crates/kernel/src/schema.rs`). WIRE-209 requires each schema to be defined once, in the format core, with no hand-written copy elsewhere. The module describes the compact authoring dialect: the declaration table, a validator over `Value`, and the generator of the closed JSON Schema. It is pure. It reads no file, holds no clock and uses none of `std::fs`, `std::env` or `std::process`, and it adds no dependency, so the kernel rules in `architecture.toml` hold. The authoring adapter does the I/O: it reads the files, decodes YAML or JSON into a `Value` and a span table, and calls the kernel's validator (WIRE-210). The expansion of the dialect into canonical documents is code, not schema, and stays in the adapter (`compact.rs`). The policy schema (`crates/contexts/policy/src/domain/schema.rs`) is the precedent for a declarative table but is separate and unchanged.

**What it declares.** The module declares two kinds, `survey` (the keys of `instrument.yaml`) and `layout` (the keys of `layouts/*.yaml`). Each authoring key is declared once: its path pattern, type (text, integer, boolean, enum with allowed values, list, map, reference to another declared shape), whether it is required, a one-line documentation string, and whether the key has cross-key rules the table cannot express (for example that a `show:` path exists). The 1,250 lines of hand-written key and type checks in `crates/adapters/authoring/src/compact.rs` are replaced by validation against this table. The expansion logic itself (slugs, ordered content, defaults) stays as code but reads keys through the table's accessors, so an unknown or ill-typed key is rejected in one place.

**Two readers, no drift.** The decoder validates the document against the table. `fieldseal_kernel::schema::json_schema(kind)` generates the editor JSON Schema of a kind from the same table, as a `Value`; the authoring adapter writes it as JSON text, and `fieldseal schema export --kind survey|layout` prints it (§4). Each kind has its own schema header: `instrument.yaml` points at the survey schema and each `layouts/*.yaml` at the layout schema. There is no hand-written schema file.

**Findings, paths and spans.** The kernel's validator reports each finding as `SchemaError { pointer, kind, message }`. `pointer` is a JSON Pointer (RFC 6901) to the offending location, for example `/lists/water-sources/items/2/label`; a `~` in a key is written `~0` and a `/` is written `~1`. `kind` is exactly one of the WIRE-211 kinds: `UnknownField`, `MissingField`, `TypeMismatch`, `EnumValue`, `DuplicateKey` or `CoercionRefused`. The validator sees a finished `Value`, so the decoders report `DuplicateKey` and `CoercionRefused` themselves, with the same fields. The YAML and JSON decoders (`yaml.rs`, `json.rs`) currently return a `Value` only. They gain a variant that also returns a span table: a map from JSON Pointer to the 1-based line and column of the key and of the value, taken from the parser events (`saphyr-parser` markers; the hand-written JSON parser already tracks positions for syntax errors). The adapter turns each `SchemaError` into a located finding (`pointer, line, column, kind, message`) by looking up the span of its pointer; expansion errors look up the span of the pointer they report. Line 0, column 0 remains only for I/O errors, where the message carries the file path. A test misspells a key, gives a wrong type and an out-of-range enum value in a fixture and checks each reported line and column.

**Differential test.** A test in the authoring crate takes a corpus and checks that the decoder and the generated JSON Schema accept and reject the same documents: every example must be accepted by both; for every declared key, mutations (drop a required key, wrong type, value outside the enum, unknown sibling key) must be rejected by both. A JSON Schema validator is added as a dev-dependency only (dev-dependencies are free under `architecture.toml`). Keys flagged as having cross-key rules are checked only for the structural part, and the flag lists what the schema cannot say.

**Invalid-document corpus.** WIRE-213 requires an invalid-document corpus and the `strict-schema` conformance suite. `tests/schema-corpus/` holds, for the survey schema and for the layout schema, one document for each of: an unknown field at every nesting level, a missing required field, a wrong type, an out-of-enumeration value, a duplicate key and a coerced value. The decoder and the generated JSON Schema must both reject every document, and `fieldseal conformance run --suite strict-schema` runs the corpus through them (CLI-043).

**Commit-before-migration gate.** The decoder rewrite lands in its own commits, before the migration commit: 1a records the golden set with the old decoder, and 1b is the rewrite. In those commits:

1.  A golden set records, for every example (keyed by survey and layout name, not by path), the expanded document as pretty-printed JSON, its `sha256:` address (the SHA-256 of the canonical bytes of the expanded document) and, under the pinned salts of §5, the instrument fingerprint and the bound layout address. The old decoder generates the golden set, before the rewrite is written.
2.  A test recomputes those values with the new decoder and compares them. The golden set is unchanged by the rewrite.
3.  The same golden set, being keyed by name, is reused unchanged by the migration commit's gate (§5).
4.  The `next_salt()` replacement of §5 (`DemoWorld::salt_for`, and its three callers) lands in commit 1b, so the migration commit changes no decoder or test-world code.

If both changes shared one commit and an address changed, the cause could not be isolated. This gate makes the rewrite's effect on every address observable by itself.

### 3. Translations

**Format.** `.po` is the only translation format. A survey has one catalogue per language, `i18n/<lang>.po`, holding the instrument's texts and every layout's titles. The catalogue path is derived from the survey folder and the language only, so renaming a layout file does not change which catalogue is read. `decode_path` (`crates/adapters/authoring/src/lib.rs`) stops reading `i18n/<file stem>/<lang>.po`; the resolver passes the survey's catalogues to `expand_with`, and each document takes the entries whose `msgctxt` begins with its own prefix.

**`msgctxt` grammar.**

```text
msgctxt   = "instrument/" path
          | "layout/" window "/" part
path      = segment *( "." segment )        ; the text's path in the instrument, as today
                                            ; e.g. instrument/lists.water-sources.borehole
window    = window class, equal to the layout file stem   ; e.g. compact
part      = authored id of a layout step or card         ; e.g. household, who-lives-here
```

`msgid` is the English text; `msgctxt` is never a position. Layout titles are the only translatable layout text, so every `layout/<window>/<part>` key names the title of a step or card. The existing instrument keys (`title`, `lists.water-sources.borehole`, `crates/adapters/authoring/src/compact.rs`) already follow paths, so the prefix `instrument/` is the only change for them. Layout keys such as `steps.1.contents.0.card` are replaced by authored ids.

**Authored layout ids.** Layout steps and cards that have a title take an `id:` key (required by the schema, generated by the scaffold). Ids must be unique within a layout. They are dropped when the layout is expanded, so they are never part of the signed document and no layout fingerprint changes (the migration gate in §5 checks this). Example:

```text
steps:
- id: household
  title: The household
  contents:
  - card: {id: who-lives-here, title: Who lives here, contents: [...]}
```

**Keeping `msgid`.** `parse_po` (`crates/adapters/authoring/src/compact.rs`, around line 1196) today discards `msgid` and drops entries with an empty `msgstr`. It returns an entry list instead: `PoEntry { msgctxt, msgid, msgstr, line }`, keeps empty `msgstr` as "missing", and still rejects a repeated `msgctxt` with the line of the second occurrence.

**Report.** `survey check` builds a translation report from the catalogues and the source texts, each finding with the `.po` file and line (or the source file and line for a missing entry):

| Finding | Meaning |
|---|---|
| missing | a source text has no entry, or its `msgstr` is empty |
| orphaned | an entry's `msgctxt` matches no source text (for example after a deleted question or a renamed layout id) |
| stale | the entry's `msgid` differs from the current English text |
| no catalogue | a language is declared under `translations:` and `i18n/<lang>.po` does not exist |

A stale entry is treated as missing at expansion, as `msgfmt` skips fuzzy entries: the English text is used for that string and the stale `msgstr` is not applied. `survey check` lists every stale entry with the `.po` file and line, the old `msgid` and the current English text, and `instrument lint` reports the string as untranslated. All four findings are warnings; `survey check --strict` makes them errors for CI. The example catalogues have matching `msgid`s, so the migration is unaffected. Orphan and stale checks run once per survey over the union of instrument and layout contexts, so a layout entry is not reported as an orphan by the instrument pass.

**XLIFF removal.** The XLIFF code in `crates/apps/cli/src/i18n_cmd.rs` (`xliff`, `parse_xliff`, `extract`, `merge`, the `.xlf` writer and the `instrument i18n extract|merge` verbs, and the matching strings in `crates/apps/cli/src/messages.rs`) is deleted. Because the spec is normative, the same change updates ADR 0034, `docs/reference/spec/cli.md` (the `instrument i18n` rows and their requirement ids), `docs/reference/spec/instrument.md`, and `docs/reference/authoring-audit.md`. Translators who need XLIFF convert `.po` with standard tools. The `localisation` verbs in the same file are a different feature (locale data) and stay.

**Docs.** The new design record "Survey source tree and authoring toolchain" (ADR 0041) supersedes ADR 0039 and takes over ADR 0040 sections 2 and 3; sections 4 and 5 of ADR 0040 (deployments, rosters, policy) remain a separate decision. Phase 5 sets ADR 0039's status to Superseded and updates `docs/explanation/adr/README.md`.

### 4. Authoring CLI

All three commands are added to `crates/apps/cli` (new modules beside `commands.rs`; wiring in `main.rs`; strings in `messages.rs`) and use the resolver and schema module of §1 and §2.

**`fieldseal new survey <name> [--lang es,...] [--root <dir>]`** creates `<root>/<name>/` with the following. `--root` defaults to `surveys` in the working directory, and the command refuses a `<root>/<name>` that exists.

*   `instrument.yaml` with a schema header (`# yaml-language-server: $schema=../.fieldseal/survey.schema.json`) that points at a local file, so authors may work offline. The file is written by `fieldseal schema export --kind survey` (below).
*   A small working instrument with one list, a few items, pinned answer codes (every list item carries an explicit `code:`, so editing a label does not change its generated code, which would otherwise be rejected on the author's first wording change), and the `survey:` header.
*   `layouts/compact.yaml` with `id:` on each step and card and its own schema header (`# yaml-language-server: $schema=../../.fieldseal/layout.schema.json`), written by `fieldseal schema export --kind layout`.
*   `i18n/<lang>.po` stubs for each requested language, with every current `msgid` filled in and `msgstr` empty.
*   A short `README.md` mapping each file to its role and saying where deployments and policies live.
*   A roster stub in `<root>/../rosters/<name>-cohort.yaml` (the `rosters/` directory beside `surveys/`; the cohort is named `<name>-cohort`), outside the publishable folder, so personal data cannot be published with the survey.

The scaffold must pass `survey check` with no errors, and a test generates one and runs the check.

**`fieldseal survey check <dir> [--roster <file>] [--strict] [--json]`** runs, in one pass and with one findings list: resolver checks (folder shape, names, window equals stem), decoding and schema validation with spans, instrument validation and lint (`instrument validate`, `instrument lint`), layout validation, binding and layout lint (`layout validate`, `layout lint`), and the translation report of §3. Exit status follows CLI-005 (1 on any error). With `--roster`, it reads the roster's `fields` keys and compares them with `roster_refs`, the roster fields the compiled instrument reads (`crates/contexts/instrument/src/domain/compile.rs`, `roster_refs`): a field the instrument reads that the roster does not supply is an error (for example `head_name`), and a roster field the instrument never reads is a note (the bundle builder drops it anyway, DIS-013). `--strict` turns warnings into errors for CI.

**`fieldseal schema export --kind survey|layout [--out <path>]` and `fieldseal schema check <file>`** implement the commands that `docs/reference/spec/cli.md` already defines (rows at lines 87 and 88, CLI-041); no spec name changes. `--kind survey` covers `instrument.yaml`, and `--kind layout` covers `layouts/*.yaml`. `export` prints the JSON Schema generated by `schema::json_schema(kind)` and its content address, and with `--out` writes the schema alone. The scaffold calls it with `--out <root>/.fieldseal/survey.schema.json` and `--out <root>/.fieldseal/layout.schema.json`, and the headers refer to those relative paths; re-running it refreshes the files when the CLI is upgraded. `check` validates one source file against the schema of its kind. The spec rows gain the kinds `survey` and `layout` (authoring kinds, not artefact kinds) in the same change. The other kinds the spec lists are not part of this design.


### 5. Migration

**What moves.** In one commit, after the decoder-rewrite commit of §2:

*   `examples/instruments/*.yaml`, `examples/layouts/*.yaml` and the two `i18n` trees move into `examples/surveys/<name>/` (with `git mv`, so history follows). Layout files are renamed to `layouts/<window>.yaml`; their `instrument:` line becomes `../instrument.yaml`.
*   The two `.po` trees per survey become one `i18n/<lang>.po`, with `msgctxt` rewritten to the grammar of §3 and layout ids added to the layout files. A one-off conversion script produces this and is not committed.
*   Rosters move to `examples/rosters/<cohort>.yaml` (the assignment is factory state, §7.4).
*   Every loader in the inventory below switches to the resolver.

**Pinned salts in tests and the gate.** The in-memory demo world (`DemoWorld`, used by tests) draws salts from a counter seeded by the world seed (`crates/adapters/memory/src/demo.rs`, `next_salt`, `salts: AtomicU64`), so a different load order gives a different fingerprint for the same file. The decoder-rewrite commit (§2) replaces `next_salt()` with a function of the survey name: `SHA-256("fieldseal.dev/demo/salt" || name)`, the same domain string as today. The migration gate and the tests pin the same function for the CLI's `--salt`, and the golden set stores the salt it used for each name. Publishing pins nothing: `just publish` and `tools/dev-publish.sh` use a random salt for each instrument, as ADR 0027 requires (the script draws it from `/dev/urandom` and keeps it beside the artefact registry, because no CLI command prints the salt of a publication and a layout must bind to it), so two versions with the same content do not share a fingerprint.

**Bound addresses only.** A layout with no bound instrument fingerprint writes its raw `instrument:` source path into the canonical document (`crates/contexts/instrument/src/domain/layout.rs`, the `Source` form), so its address would change when the path changes. The gate compares only layouts bound to their instrument (`load_layout` with a `LayoutBinding` in `crates/apps/cli/src/commands.rs`, which turns the source into the salted fingerprint) and never the unbound form. Bound layouts are what `just publish` and the factory's bundles carry, so this is the address that matters.

**Expanded-document diff.** The golden set also stores the expanded, canonical document of each instrument and layout as pretty-printed JSON (`crates/apps/e2e/tests/golden/expanded/<survey>/...`). On a mismatch the gate prints a textual diff of the expanded documents before the hash comparison, so a changed address comes with the changed text.

**The migration gate.** An integration test in `crates/apps/e2e` (so it runs in `just test` and in the CI `tests` check) loads each survey through the resolver, expands it, and compares: instrument address, instrument fingerprint under the pinned salt, bound layout addresses, and the expanded documents. `just migration-gate` runs that test alone. The golden set is the one created in the decoder-rewrite commit (§2) and is not edited by the migration commit.

**Hard-coded loader inventory.** Every hard-coded loader moves or is removed in the migration commit: the CLI's embedded tables and the conformance suite, the e2e helpers, the memory and web tests, the `web-demo` directory walk, the collector stand-in's catalogue and stack modules, the five scenario files, four shell scripts, and the Nix and compose files (which copy the whole `./examples` tree and need no change; they are listed so the check confirms it). The Phase 4 entries list each file with its line numbers. The `cohorts: "cohort-a:1,village-a:1"` string of `examples/deployments/local-stack.yaml` stays in this commit and is removed in Phase 12, when `roster assign` exists (§7.4). Paths in `docs/`, `README.md` and `examples/README.md` are updated in the same commit. A repository check (`tools/check-example-paths.py`, run by `just test`) fails if a source file, script, compose file or Nix file outside `docs/` still names `instruments/`, `layouts/`, `.compact.yaml`, `.expanded.yaml` or an `examples/.../i18n` path.

**One revertible commit.** The commit contains the tree move, the `.po` rewrite, the loader changes, the scenarios and scripts, and the docs paths, and nothing else (the resolver, schema module and decoder are already in earlier commits). `git revert` of it restores the old tree and old loaders, and the gate passes on the reverted tree because the golden set is keyed by name, not path.

### 6. Shared results table and export

**One schema.** `LONG_COLUMNS` (20 columns, `crates/contexts/intake/src/data_contract.rs:36`) is the only long format. It gains one sibling constant, `TYPED_VALUE_COLUMNS` (`value_number`, `value_text`, `value_date`, `value_bool`, `value_codes`), and a constant `EXPORT_SCHEMA_VERSION` (semver, starting at `1.0.0`; a minor version only adds columns). The JSON Lines column list is `LONG_COLUMNS` with `value` replaced by the five typed columns. The CSV column list is `LONG_COLUMNS` unchanged (it keeps `value` plus `value_type`).

**Where the code lives.** The writers and the manifest are a module `export` in `fieldseal-adapters-landing-files` (`crates/adapters/landing-files/src/`). That crate already owns the hand-written CSV and JSON writers (`csv_field`, `json`, `long_header`, `long_row`) and depends on the intake context, so no new crate and no new dependency is needed. The CLI (`fieldseal intake results`) and the results reader (`crates/adapters/results-http`, §7.2) call it. `FileDataPlatform`'s `observations.csv` is written by the same CSV writer; it keeps its full-fidelity role (excluded rows appear with flags), and the results export is the analysis-ready derivative of it.

**`/intake/rows.csv` becomes a view in the intake app.** `IntakeReport::rows_csv` and the web-only `LongRow` (`crates/adapters/web-demo/src/intake_world.rs`) leave the demo path with the `web-demo` authority (§7.1). The intake app's download `results.csv` (`GET /results/exports/{mark}/results.csv`, §7.2) is the shared table. The web-only columns go: `instrument_name` (in the manifest and contract), `outcome` (derivable from `nonresponse` and `retracted`), `subject_id` (the decoded roster id; the `subject` column remains and holds the keyed hash described below), and the renamed time columns (`not_before_ms`, `not_after_ms` become `tick_lower_bound` and `received_at`, in milliseconds on the authority clock). WEB-161 and WEB-162 in `docs/reference/spec/web-app.md` are rewritten in the same change. WEB-162 is restated, not dropped: the CSV guard always applies to text columns and never to numbers (below).

**Typed columns for all nine item types.** For an answered row, exactly one typed column is filled, the one that matches `value_type`. A `string` row fills none, because every `string` item is free text:

| `value_type` | Filled column | Content |
|---|---|---|
| `integer` | `value_number` | canonical integer text, for example `12` |
| `decimal` | `value_number` | canonical decimal text; a non-terminating result is already rounded to 9 places by `num_text` |
| `money` | `value_number` | canonical decimal text at the currency's minor-unit digits (`12.50`); the currency is in `unit` |
| `string` | none | `value` and every typed column are null; the text goes to its own file (below) |
| `code` | `value_text` | the code |
| `codes` | `value_codes` | a list of codes (JSON array; in CSV the existing `\|` join in `value`) |
| `boolean` | `value_bool` | `true` or `false` |
| `date` | `value_date` | `YYYY-MM-DD` text |
| `evidence` | `value_text` | the evidence reference |

`lang` and `flags` are arrays in JSON Lines and `|`-joined in CSV, following their logical type in `LONG_COLUMNS`. `tick_lower_bound` and `received_at` are JSON integers in milliseconds on the authority clock, with no time zone; the codebook says so and shows the DuckDB conversion.

**What the value columns hold in the other states.**

*   Answered: one typed column filled; `nonresponse` empty; `retracted` false.
*   Free text (`free_text = true`): `value` and every typed column are null; `nonresponse` empty; `retracted` false. The text is in the free-text file, never in `results.jsonl` or `results.csv`.
*   Nonresponse (`dont-know`, `refused`, `not-applicable`): all typed columns null, `nonresponse` holds the code, `retracted` false.
*   Retracted (WIRE-052): all typed columns null, `retracted` true, `nonresponse` empty.
*   In CSV a null is an empty cell. In JSON Lines it is `null`. Read-back treats an empty CSV cell and a JSON null as equal.

**Canonical decimal text.** `value_number` is the text produced by the existing `decimal_text` (`crates/contexts/intake/src/data_contract.rs:224`) and `num_text` (`crates/contexts/intake/src/landing.rs:139`), never a JSON number, so no precision is lost to a float. Money's scale comes from its currency (`unit`). The value is exact as landed, and consumers cast it (`CAST(value_number AS DECIMAL(p,s))`; the DuckDB recipe below shows one). No fixed precision is imposed on the file; a lakehouse picks its own.

**CSV formula guard.** The CSV writer always guards text, so a spreadsheet does not run a respondent's words as a formula: a cell that starts with `=`, `+`, `-`, `@`, a tab (`\t`) or a carriage return (`\r`) is written with a `'` prefix. The guard covers `value` in `results.csv` when `value_type` is not `integer`, `decimal` or `money`, `value_text` in `free_text.csv`, and every text column of `codebook.csv`. Numeric values are never guarded, so `-5` stays `-5`. The guard has no option, CLI flag or query parameter: the CLI and the results reader apply the same rule, so their bytes are identical. JSON Lines is never guarded. A program that reads the CSV strips one leading `'` from a text cell that starts with `'` and one of those characters (`'=`, `'+`, `'-`, `'@`, `'` and a tab, `'` and a carriage return); the codebook says so. The guard replaces the `'` prefix that `csv_field` in `intake_world.rs` applied to every value that started with one of these characters, including numbers.

**Listing landed instruments.** The results reader and the CLI need the instruments that have landed data. `DataPlatform` (`crates/contexts/intake/src/ports.rs`) gets an additive method `instruments() -> Result<Vec<Fingerprint>, DataPlatformError>`, ascending by fingerprint, implemented by `MemoryDataPlatform` and `FileDataPlatform` (which keeps the set already, used by `rewrite`) and forwarded by the intake app's event wrapper. `data_platform_contract` in the Intake context gains a case: an instrument appears after a landing that has an observation for it, once. `FileDataPlatform::rewrite` uses the method instead of its private set. This is the one change to Intake's port in this design. The changes to Registration's ports are in §7.3 and §7.4.

**Free text in a separate file.** The data contract gains one additive item field, `free_text` (true when `value_type` is `string`, which includes the synthesised "other" text items marked by `other_text_of`); `sensitivity` already marks special-category items. In the results export, a free-text item's answered row stays in the main table with `value` and all typed columns null (so row counts and nonresponse rows are unchanged, and no free text reaches the results file), and its text goes to `free_text.jsonl` and `free_text.csv` with columns `record_id`, `item_path`, `value_text`. Joining back is one line in DuckDB: `... LEFT JOIN read_json_auto('free_text.jsonl') USING (record_id, item_path)`. Nonresponse and retracted rows have no text and have no free-text row.

**Analysis-ready by default.** Rows with `excluded = true` (consent or custodian decision, INT-055) are left out of every file, and the manifest records how many were left out. A test builds a results export containing excluded rows and asserts none appears in any file. Readable roster ids are never written: the hex-decoding helper (`unhex` in `intake_world.rs`) is deleted, and the `subject` column holds a keyed hash (next paragraph). The results reader and the CLI state that the files contain free text, special-category items (marked in the contract), the consent basis and record, tenancy and sequence ids, and are outside Fieldseal's protection.

**Subject pseudonyms in the results export.** In the demo, intake's `subject` is the hex of the roster identifier's bytes, so anyone can decode it to text such as `hh-0001`. The results export therefore replaces `subject` with `lower_hex(HMAC-SHA-256(export_key, subject))`. The HMAC input `subject` is the UTF-8 bytes of the `subject` column text as intake lands it (in the demo, the lower-case hex text of the roster identifier's bytes), with no prefix and no terminator. `export_key` is the export pseudonymisation key held by the intake app. It is the file `export.key` in `FIELDSEAL_EXPORT_KEY_DIR`: 32 random bytes stored raw (no header, no encoding), with file mode 0600. The explicit authority set-up step creates the file (`tools/stack-init.sh` in the stack, `tools/dev-web.sh` in `just web`); neither the intake app nor the CLI creates it. The intake app exits `2` when the file is absent, is not 32 bytes long, or on Unix has a mode wider than 0600, and the CLI refuses the same cases. A file store is a development adapter (§10.1). The key is never the record key. Custody of this key in production is a deployment decision outside this design. Pseudonyms are stable within one authority, so its exports join. Different authorities produce different pseudonyms, so their exports do not join. The manifest records the key id, never the key. The key id is the first 32 hex digits of `lower_hex(SHA-256("fieldseal.dev/export-key-id" followed by the 32 key bytes))`, where the domain text is taken as its UTF-8 bytes. The shared writer takes a subject mapper: the results export passes the HMAC, and the authority's own landing directory (`FileDataPlatform`, below) keeps the intake name because it stays inside the authority. The results reader and its downloads show the results export. Test: an export built from the bundled rosters is scanned in every file (JSON Lines, CSV, free text, contracts, codebook, manifest) and no roster subject id appears in readable or hex form; a second authority key gives different pseudonyms for the same input, and the same key gives the same ones. `hmac` and `sha2` are already allowed dependencies (`architecture.toml`).

**Landed state survives a restart: already handled by replay at start (INT-013a).** `FileDataPlatform` does not reload its files at start; that is not needed. In `stack` mode the development upload server keeps every accepted submission in `FileSubmissionStore` (content-addressed files plus an `index` of arrival times, `crates/adapters/file/src/submissions.rs`) and, before it serves, runs `stored()` through the gate again in the original order and at the original times (`crates/adapters/upload-http/src/bin/server.rs`, `REPLAYING` loop). Each replayed submission calls `FileDataPlatform::land`, which refills the in-memory platform and rewrites `observations.csv`, `findings.csv` and `losses.csv`. Replay also restores what a file reload could not: envelopes, evidence and consent cases. INT-013a (`docs/reference/spec/intake.md`) requires this behaviour, and `tools/stack-run.sh` already checks that a `replayed` event with `landed` above zero appears after a restart. The intake app (§7.1) keeps this start-up replay. What replay needs, and what this design adds:

*   The submissions directory must be configured. `FIELDSEAL_INTAKE_SUBMISSIONS_DIR` is optional in the binary and falls back to memory, the manifest `examples/deployments/local-stack.yaml` declares `SubmissionStore: memory` for intake, and `deploy/local/compose.yaml` sets the variable by hand outside the rendered environment (a DEP-012 deviation). The manifest and `fieldseal deployment render` must carry it (§7.1), so that `just web` gets it too.
*   The published-instrument, roster and tenancy directories must be the same as before the restart, or replay validates against different inputs. Replay treats the published directory as append-only: it does not apply a withdrawal made after the original landing, so a later withdrawal never removes a landed submission.
*   A submission that fails on replay logs `replay-failed`. Any `replay-failed` stops readiness: start-up exits `1` and `/readyz` fails. There is no override, so a submission that was accepted and receipted is never dropped without a trace.
*   Custodian `exclude` and `reinstate` calls are not submissions and are not replayed. The intake app has no route that calls them, so nothing is lost today; a later route would have to journal them.
*   The server never calls `write_contract`; only `fieldseal intake` does (`crates/apps/cli/src/intake_cmd.rs`). The results reader therefore renders each data contract from the published instrument when the results export is built (§7.2) and does not depend on files in `contracts/`.

A test is added: land a device export through `POST /v1/upload`, produce the results export directory, restart the intake process on the same directories, produce it again, and compare every file byte for byte (the long table, the manifest digests, the findings). A second test makes one stored submission fail on replay and asserts that start-up exits `1` and `/readyz` fails. `tools/stack-run.sh` extends its restart check to this comparison. The container stack's landing directory then survives a restart, and `fieldseal intake results --landing <dir>` reads it without a record key (it is already decrypted data) and writes the same results export. The collector stand-in has no results page; the results reader is a page of the intake app.

**Results export directory.**

```text
<out>/
  manifest.json
  results.jsonl            results.csv
  free_text.jsonl          free_text.csv
  contracts/<fingerprint hex>.json    # the existing data contract, plus `free_text` and `exportSchemaVersion`; the name is the instrument fingerprint as exactly 64 lower-case hex digits
  codebook.csv             # generated from the contracts; no second source
```

`codebook.csv` has one row per item and language, and one per code and language: `item_path, lang, item_label, code, code_label, value_type, unit, sensitivity, free_text`. It is rendered from the contract by a function, never edited or stored separately.

`manifest.json`:

```text
{ "export_schema_version": "1.0.0",
  "landing_mark": 56,
  "pseudonymisation_key_id": "<hex>",
  "instruments": [{ "fingerprint": "<hex>", "address": "sha256:..." }],
  "layouts":     ["sha256:..."],
  "files": [{ "name": "results.jsonl", "sha256": "<hex>", "bytes": 1234, "rows": 56 }, ...],
  "rows_omitted_excluded": 3 }
```

A file cannot contain its own digest, so `manifest.json` is not listed in `files`; the CLI and the results reader print its SHA-256. `landing_mark` is defined below. CSV and JSON Lines have no place for metadata without breaking readers, so their version is given by their manifest entry and by the contract file's `exportSchemaVersion`.

**Snapshot and landing mark.** The CLI and the results reader both open the landing through the landing-files `DataPlatform` adapter, which reads `observations.csv` once into memory. The landing adapter writes each of its files with the shared atomic-write helper in `crates/adapters/file` (a temporary file in the same directory, `fsync`, then rename), so a read never sees a torn file. The *landing mark* is the number of rows in that snapshot, excluded rows included, and the manifest records it as `landing_mark`. Everything in one results export comes from one snapshot. A custodian `exclude` or `reinstate` route does not exist (INT-013a note above); a later route would have to advance the mark.

**Where the manifest and contracts come from.** The rows are keyed by the instrument's salted fingerprint, and a survey folder carries no salt, so the results export never reads survey folders. Both the CLI and the results reader read the published directory (`FIELDSEAL_INTAKE_PUBLISHED_DIR` for the results reader, `--published` for the CLI) and verify each publication against the trust bundle. From it:

*   `instruments` lists each instrument that has at least one landed row, ascending by fingerprint hex. `address` is the address of that instrument's publication.
*   `layouts` lists the addresses of the published, non-withdrawn layouts bound to those fingerprints (INS-200), ascending by address text, without repeats.
*   `files` lists the files ascending by name.
*   Each contract is rendered from the published instrument and written as `contracts/<fingerprint hex>.json`.

**Byte rules.** The CLI and the results reader apply the same rules, so their files are identical byte for byte.

*   Row order: a sort of the landed rows by `instrument`, `tenancy`, `seq` (as an integer), `record_id`, `item_path` and `retracted` (false first), then by `lang`, and last by the bytes of the row's JSON Lines text, with text compared bytewise. The last key makes the order total, so two readers cannot place equal-looking rows differently. `free_text.*` rows sort by `record_id`, then `item_path`, then the bytes of the row's JSON Lines text.
*   JSON is compact (no spaces), UTF-8, written by the existing `json` function of `landing-files`: text escapes `\"`, `\\`, `\n`, `\r`, `\t` and `\u00xx` (lower-case hex) for other control characters; all other characters are written as UTF-8. Object keys of `manifest.json` and of the contract files are sorted ascending by their UTF-8 bytes (the file shown above lists them in reading order). Keys of a JSON Lines row are in the column order of the JSON Lines list. Numbers are written as plain decimal digits.
*   JSON Lines: one object per line, each line ending in `\n`. `manifest.json` ends with one `\n`. An empty table writes a zero-byte file.
*   CSV: a header row, then the rows; comma separator; `\n` line ends; UTF-8 with no byte order mark; a field is quoted by `csv_field` only when it holds a comma, a double quote, CR or LF; arrays are `|`-joined.

**Read-back equivalence test.** In `crates/adapters/landing-files`, a test writes a results export for a table that covers all nine item types, nonresponses, retractions, an excluded row and a free-text answer; reads each format back with a separate small parser; and compares the rows sorted by `(record_id, item_path)`. Decimal text must match exactly, and an empty value equals null. The free-text file is joined back before comparison.

**`fieldseal intake results --landing <dir> --published <dir> --export-key <file> --out <dir> [--trust-bundle <file>] [--format jsonl,csv]`.** (`crates/apps/cli/src/intake_cmd.rs`.) It reads the landing the intake app wrote through the landing-files `DataPlatform` adapter (a snapshot, as above), reads the published instruments and layouts from `--published` and verifies them against `--trust-bundle` (or `FIELDSEAL_TRUST_BUNDLE`), writes the results export directory, and prints the file list, the manifest digest and the unprotected-data warning. `--published` is required because a survey folder carries no salt, so the CLI cannot compute the fingerprints that key the rows. `--export-key` names the key file `export.key` that the intake app uses (§6, subject pseudonyms) and is required, so the CLI never derives a key. The name is `intake results` because `fieldseal export` already builds, inspects, verifies and repairs the sealed delivery file (`crates/apps/cli/src/export_cmd.rs`). There is no `--authority demo --seed <n>` form, because there is no demo authority, and no mode that reads a practice device export file; `intake replay --reveal` does that. A test must show that, for the same landing snapshot, published directory and key file, the CLI and the downloads of the results reader (§7.2) are byte-identical files.

**DuckDB recipe** (documented in `docs/how-to/`, tested in CI only if `duckdb` is on the dev shell's path):

```text
duckdb -c "COPY (SELECT * REPLACE (CAST(value_number AS DECIMAL(38,9)) AS value_number)
                 FROM read_json_auto('results.jsonl'))
           TO 'results.parquet' (FORMAT PARQUET)"
```

Parquet and a wide results export are not produced natively (Non-Goals).

### 7. Intake app, reader access, bundle delivery, rosters and operator sign-in

The demo uses the production authority services, not a second implementation. The services that the demo needs already exist as production binaries except one: the intake endpoint exists only as the development binary `fieldseal-upload-server`. This section promotes it (§7.1), gives the results reader the factory portal's sign-in (§7.2) and specifies the bundle delivery route (§7.3). It then specifies the roster commands and the cohort assignments they need (§7.4), the operator sign-in and the development IdP (§7.5), and the environment variables (§7.6).

```text
Demo and results flow  (each arrow is a production protocol; development adapters in [brackets])

 COLLECTOR STAND-IN  (fieldseal-web, 127.0.0.1:8090)   PRODUCTION SERVICES (localhost)
                                                       |
 Instruments page: surveys from the folder (resolver)  |
                                                       |
 presenter / operator CLI  (the same fieldseal commands as production)
   artefact provenance|sign|publish ------------------> fieldseal-translog :9001 (log) + registry dir
   roster check | diff | list ------------------------> local files, read-only
   roster issue  --> fieldseal-factory POST /v1/rosters     (OIDC Bearer) --> roster store [file-dev]
                                                       |                      + tenancy registry journal [file-dev]
   roster assign --> fieldseal-factory POST /v1/assignments (OIDC Bearer) --> tenancy registry journal [file-dev]
                                                       |
                       fieldseal-factory :8080  <-- reads registry dir + roster store, builds the
                         bundle on registration and on change, stores it [file-dev bundle store]
                                                       |
 WebAssembly device (wasm core, worker)                |
   register  -- /proxy/factory --> POST /v1/registrations --> factory
   (collector confirms words on the factory portal; sign-in at the development IdP / Keycloak)
   get bundle -- /proxy/factory --> GET /v1/bundle (PoP) --> factory  (the stored bundle, sealed
                                                       |     to the device key)
   verify (log inclusion via /proxy/log), import
   conduct survey (local records)
   device export (sealed to the record key)
   upload    -- /proxy/upload --> POST /v1/challenge, /v1/upload --> fieldseal-intake :8480
   <- receipts, verified in the browser                          gate -> landing [landing-files]
                                                       |                          |
 guided steps read: factory status, log, bundle        |   fieldseal-intake portal :8481 (OIDC, role, CSRF)
 response, receipts, device state. No key, no          |   results reader: results export, downloads
 session, no route to :8481.                           |        |
                                                       |   fieldseal intake results (CLI)
                                                       |        v
                                                       |   <out>/ manifest.json, results.jsonl/.csv,
                                                       |         free_text.jsonl/.csv, contracts/, codebook.csv
                                                       |        |
                                                       |   DuckDB: COPY ... TO 'results.parquet'
```

#### 7.1 The intake app (`crates/apps/intake`)

**Why a new app.** `fieldseal-upload-server` lives in `crates/adapters/upload-http/src/bin/server.rs`. It is a binary inside an adapter crate, so it is not a composition root in the sense of ADR 0028 ("one composition root per deployable"), it defaults to a practice authority with fixed seeds, and it does not refuse development adapters in production. It also has no results reader. The factory is the pattern: `crates/apps/factory` reads its configuration from the environment only, wires adapters to use cases and refuses development adapters when `FIELDSEAL_ENVIRONMENT=production`.

**Names.** The directory is `crates/apps/intake`. The Cargo package is `fieldseal-intake-app`, because `fieldseal-intake` is the Intake context. The binary is `fieldseal-intake`. `architecture.toml` gets `fieldseal-intake-app` in the `apps` list (apps may depend on kernel, contexts and adapters). The two new adapter crates of §7.2, `fieldseal-adapters-portal` and `fieldseal-adapters-results-http`, are matched by the existing `fieldseal-adapters-` prefix. `tools/check-architecture.py` needs no change.

**What it hosts.** One process, two listeners:

| Listener | Variable | Default | Audience | Routes |
|---|---|---|---|---|
| Upload | `FIELDSEAL_INTAKE_BIND` | `0.0.0.0:8480` | devices | `POST /v1/challenge`, `POST /v1/upload`, `POST /v1/upload/outbox`, `GET /healthz`, `GET /readyz` (unchanged protocol, served by `UploadHttp` from `fieldseal-adapters-upload-http`) |
| Portal | `FIELDSEAL_INTAKE_PORTAL_BIND` | `127.0.0.1:8481` | authority staff | sign-in, sign-out and the results reader (§7.2) |

The two listeners are separate so that the device-facing port can be exposed to the internet while the staff portal stays on an internal network. The app also builds the gate (`IntakeService`), the landing (`DataPlatform`), the submission store and the start-up replay that the development binary has today.

**Configuration** is environment only and strict, like the factory's (§7.6). Names follow the factory's where the meaning is the same; the upload listener variables are renamed from `FIELDSEAL_UPLOAD_*` to `FIELDSEAL_INTAKE_*`. The variables and their meanings are in the table of §7.6. The identity variables are the factory's. `FIELDSEAL_IDENTITY` is `oidc` or `dev`. `dev` signs the results reader in as the factory's `memory-dev` identity does, with a fixed login and no identity provider. It is a development adapter behind the identity port (§10.1), and production refuses it (exit `2`) as it refuses the factory's. It exists so that the app starts under `just web` in Phase 10, before the development IdP exists (Phase 11); from Phase 11 on `just web` uses `oidc`, and the container stack uses `oidc` throughout.

There is no `FIELDSEAL_UPLOAD_AUTHORITY` switch and no seed: the app always serves the authority named by its custody and trust bundle. `fieldseal deployment render` writes the variables from the manifest (DEP-012).

**Development adapters and production.** In production the app refuses to start (exit `2`) with any development adapter in the table of §10.1. As for the factory, there is no production adapter for several of those ports yet, so the app cannot start in production until there is one. The factory is in the same state (`crates/apps/factory/README.md`, Invariants). In every environment the app also exits `2` on an invalid export key (§6, export key). At every start the app writes the `development-adapters` event (§10.1).

**Start-up replay.** The app replays stored submissions through the gate before it serves, as described in §6; the upload listener accepts no connection until replay has finished. A failed replay stops start-up (§6).

**Practice mode.** The practice authority (fixed seeds, in-memory ports, one practice device per `--device` label) is for development and conformance runs (`docs/reference/spec/delivery.md`, DEL-071). `fieldseal intake practice` does not start it: that command only writes a practice device export file. It is not a production path and does not belong in the intake app. It moves to a second binary in the crate that already holds the server code: `fieldseal-upload-practice` (`crates/adapters/upload-http/src/bin/practice.rs`). It refuses `FIELDSEAL_ENVIRONMENT=production`, appears in no Nix image, compose file or deployment manifest, and keeps the flags `--listen`, `--public-url`, `--seed`, `--max-body` and `--device`. The `EventPlatform` and `EventStore` wrappers move to the intake app. They have no test today, so the conformance contracts entry in `crates/apps/cli/src/conformance_cmd/contracts.rs` (`cargo test -p fieldseal-adapters-upload-http --bin fieldseal-upload-server int_011`) runs no test at all; Phase 10 adds one that runs `data_platform_contract` over `EventPlatform` and points the entry at it. After the change `upload-http` holds the protocol code (client and handler, `src/lib.rs`) and the practice binary.

**Other files that change with it.** The Nix image and package, the compose service and the Keycloak client are renamed or added for the intake app. The Deployment context's Intake component gains the identity provider port and the file-dev stores. DEL-071, DEP-057 and INT-013a are updated, and ADR 0028 and ADR 0021 get a note. Phase 10's entries list each file. `crates/adapters/web-demo` is deleted once the web parity tests run against the real services (the factory, log and intake app started by the test harness). Until then it is a test-only crate. `fieldseal-web` keeps its dependency on it, unused on the demo path, until Phase 16b removes it (entry 460), and nothing on the demo path links it.

#### 7.2 Reader access: OIDC, as the factory portal does it

**What is reusable.** The sign-in is already split from the portal by a port: `IdentityProvider` (`start_sign_in`, `finish_sign_in`) in the Registration context, implemented by `OidcIdentityProvider` (`crates/adapters/oidc`: authorization code with PKCE, ID-token checks, `amr` and `acr` read from the token) and, for tests, by `MemoryIdentityProvider` (`crates/adapters/memory/src/registration.rs`, which signs in as a configured login). What is not reusable as it stands is the session machinery: the session store, the pending sign-in map, the `fs_session` cookie (`HttpOnly`, `SameSite=Lax`, `Secure` when the public URL is https), the per-session CSRF token and its check (`portal_post`) are private to `FactoryHttp` in `crates/adapters/factory-http/src/lib.rs`. They are moved, without a change in behaviour, into a new adapter crate `fieldseal-adapters-portal` (`crates/adapters/portal`), and `FactoryHttp` uses it. The crate has no tests today, so characterisation tests of the current sign-in, session and CSRF behaviour are written first (Phase 7a) and must pass unchanged after the move (Phase 7b); they are the proof of the refactor.

**What the intake app adds.** A second adapter crate, `fieldseal-adapters-results-http` (`crates/adapters/results-http`), serves the results reader on the intake portal listener using `fieldseal-adapters-portal`, `fieldseal-adapters-landing-files` (the results export writers of §6) and the Intake context's ports. Differences from the factory portal:

*   The cookie is named `fs_intake_session`, so a browser that holds both the factory's and the intake app's cookies on `localhost` (cookies are scoped by host, not by port) does not mix them.
*   Every results route needs a session whose `AuthenticatedPerson.role_names` contains the `results-reader` role (`FIELDSEAL_INTAKE_READER_ROLE`, default `results-reader`) and, by default, a phishing-resistant authentication method (REG-002). The roles that exist today are `collector` and `operator` (`Role` in `crates/contexts/registration/src/domain/mod.rs`); `role_names` carries any other name, so no change to the Registration context is needed. The new role name is `results-reader`, set by `FIELDSEAL_INTAKE_READER_ROLE` in the intake app; reusing `operator` was rejected because operators who mark devices lost would also read personal data, and deciding access through a new policy decision point is a later step, not part of this design.
*   No tenancy registry or token operation exists in this portal; it reads results only, and it logs sign-ins without the account's personal data.

| Route (intake portal listener) | Auth | Result |
|---|---|---|
| `GET /` | none | redirect to `/results` when signed in, else a sign-in page |
| `GET /sign-in`, `GET /sign-in/callback` | none | identity-provider flow |
| `POST /sign-out` | session and CSRF | ends the session |
| `GET /results` | session and role | plain paged table of the results export for the current landing mark (§6); data contracts; manifest preview; the unprotected-data statement; download links to `/results/exports/{mark}/{path}` for that mark |
| `GET /results/exports/{mark}/{path}` | session and role | one file of the results export frozen at landing mark `{mark}`, byte-identical to what `fieldseal intake results` writes for the same landing snapshot, published directory and key. `{path}` is exactly one of `results.csv`, `results.jsonl`, `free_text.csv`, `free_text.jsonl`, `codebook.csv`, `manifest.json`, or `contracts/<fingerprint>.json` where `<fingerprint>` is exactly 64 lower-case hex digits and appears in the manifest. Any other path is `404 not-found`; a mark the results reader does not hold is `404 unknown-mark` and the page links to the current mark. The CSV guard of §6 has no switch |
| any results route | no session | 302 to sign-in for a page, 401 `sign-in-required` for a download |
| any results route | session without the role | 403 `not-authorised` |

The page shows the unprotected-data statement of §6 beside the download links and the development-adapter label when the app reports any (§10.1). The page computes nothing from the answers (INT-092): counts are the gate's and the landing's, and the data contract is rendered from the published instrument at request time (the server does not write `contracts/` files, §6). The `POST /intake/ingest` form of the demo (running the gate on an uploaded device export file) is not carried over; the file route is a CLI path (`SubmissionSource::File`) and the upload endpoint is the production route.

**Snapshots.** A page and its downloads must describe one state of the landing even while data lands. The results reader opens the landing snapshot (§6), takes its landing mark and builds the results export for that mark once. It keeps the built export directory in memory for the last four marks and never changes it, and it writes nothing to disk. The page links to the current mark. A download for a held mark is served from the held copy, so two downloads of one page agree even if a submission landed between them. The manifest records the mark.

**Where the development IdP, Keycloak and the real provider apply.** The same binary, configuration names and code run in all three, with `FIELDSEAL_IDENTITY=oidc`; only the issuer's process differs. `just web` runs the development IdP (`crates/apps/dev-idp`, §7.5) on the issuer URL the stack's Keycloak uses, with two logins: `presenter` (`collector`, `operator`, `results-reader`) and `collector1` (`collector` only). The container stack uses its Keycloak. Production uses the real identity provider. Nothing in the services is a development adapter for identity; the development IdP is a development tool that stands where Keycloak stands, started explicitly and refused anywhere else (§10.1).

**How the collector stand-in is kept away from the results reader.** Five controls, each with a test:

1.  *No key.* The collector stand-in (`fieldseal-web`) has no authority state: its `AppState` holds no key, seed or `Demo` handle, and it starts and serves all its pages with no key material in its environment. Test in `crates/apps/web/tests/`.
2.  *No route.* Results routes exist only on the intake portal listener. The collector stand-in's proxy forwards only to the configured factory, upload and log URLs, never to the portal. Test: a `/proxy/*` request aimed at the portal, and a request for `/results` on the collector stand-in, return 404 or 502.
3.  *No session, no role.* The results reader is refused without a session and with a session that lacks the role, and `POST /sign-out` is refused without the CSRF token. Tests in `crates/adapters/results-http` (against `MemoryIdentityProvider` with the two development logins) and, against a running intake app, in `crates/apps/security-tests`.
4.  *No shared cookie.* In `just web` and in the container stack the collector stand-in is served from `127.0.0.1:8090`, and the factory and the intake portal from `localhost` (Keycloak needs `localhost` for passkeys), so the browser sends their cookies to `localhost` only. Test: start the services, sign in to the portal with a browser harness, request any collector stand-in page, and assert that the request carries no `fs_session` or `fs_intake_session` cookie. The test runs against `just web` and against the stack. The stack also keeps the distinct cookie names and the role check.
5.  *No key in the bundle.* Test in `crates/apps/security-tests`: build bundles for registered devices, open each as the device would, and assert that neither the bundle bytes nor its decrypted contents contain the record key's secret or the export pseudonymisation key; the bundle carries only the record public key and certificate chain.

Collector pages keep `PAGE_CSP` (`script-src 'self' 'wasm-unsafe-eval'`) with `connect-src` and `form-action` limited to `'self'`, so a collector stand-in page script cannot call the portal's origin. A link that the presenter follows to the portal is navigation by a person, not access by the collector stand-in. Test: the CSP header of every collector stand-in page names no service origin.

**Tests.** (1) The five controls. (2) The CLI and the results reader produce byte-identical files for the same landing snapshot, published directory and key file (§6). (3) A path outside the fixed list, a `contracts/` name that is not 64 lower-case hex digits, and a fingerprint absent from the manifest all give `404`; a held mark stays unchanged while a new submission lands. (4) After an intake restart on the same directories, the results export is byte-identical (§6, restart test). (5) `FIELDSEAL_ENVIRONMENT=production` with each development adapter makes the intake app exit `2`, one test per adapter, as for the factory.

#### 7.3 Bundle building and delivery: the factory builds, `GET /v1/bundle` serves

**Decision: the factory builds and serves bundles, as DIS §3 says.** `BuildBundle` is called by the factory "on registration, assignment change, artefact or policy change, key roll"; `FetchBundle` is called by the runtime "with a proof-of-possession token" (DIS-040); `DownloadBundle` serves the signed-in collector (DIS-041, REG-054). The Distribution context implements all three (`crates/contexts/distribution/src/application/build.rs` and `fetch.rs`), but `crates/apps/factory` wires none of the driven ports they need, and `crates/adapters/factory-http` has no bundle route. This design wires them. The demo has no operator bundle-build step.

**Wiring in `fieldseal-factory`.** `BundleBuilder` takes `FactoryPorts` (`registry`, `artefacts`, `rosters`, `profiles`, `policy`, `anchors`, custody) and a `BundleStore`. The factory app already holds the tenancy registry, custody, policy engine and decision log. It gains the following. The `ArtefactRegistry` and `RosterSource` rows are wired in Phase 12: the artefact registry read-only, the roster store for reading and writing, because `IssueRoster` writes it and `AssignCohort` checks `unknown-survey` and `unknown-cohort` against both (§7.4). Phase 13 adds the rest and the building:

| Port | Adapter | Notes |
|---|---|---|
| `ArtefactRegistry` | `FileRegistry`, moved from `crates/apps/cli/src/stores.rs` into `crates/adapters/file` (`registry` module) | reads the `*.publication` files and the `withdrawals/` directory that `artefact publish` writes under `<state>/registry` when `FIELDSEAL_ADAPTERS=files`; `FIELDSEAL_FACTORY_REGISTRY_DIR` names that directory. The `*.published` copies are a different directory, which the intake app reads (`FIELDSEAL_INTAKE_PUBLISHED_DIR`); development adapter |
| `RosterSource` | new `FileRosterSource` in `crates/adapters/file` | reads the roster store that the factory writes when an operator issues a roster (`POST /v1/rosters`, §7.4; `FIELDSEAL_ROSTER_DIR`; the stack mounts it as the `rosters` volume) and answers for the cohorts and generations assigned to the tenancy; development adapter |
| `RuntimeProfiles` | a file adapter over the registration record | the schema versions the runtime reported at registration (DIS-012, DIS-017). Today only `MemoryRuntimeProfiles` exists (`crates/adapters/memory/src/distribution.rs`). The runtime reports the profile in the registration request: WIRE-130 gains `schema` (instrument-schema version, required) and `catalogue` (UI reference-catalogue version, optional), inside the proof-of-possession body; the tenancy registry journals it with the tenancy (`ReportedProfile`, REG-091); `FileRuntimeProfiles` serves it. The CLI device, the WebAssembly device and the UniFFI binding (`runtime_profile()`) send it. A tenancy whose runtime reported an older schema gets no instrument it cannot run (DIS-012). DIS-077 (an extension's meta-schema version and an instrument's catalogue address) is not enforced by this change: the profile carries neither, and no extension reaches a bundle yet. `catalogue` is optional and nothing reads it yet; it is added in this change because adding it later would mean a second signed-content wire change and security review when Localisation artefacts arrive. Phase 8; security review SR-1 |
| `AnchorSource` | new `ClockAnchorSource` in `crates/adapters/memory/src/distribution.rs`, the file that owns `sign_time_token` | reads the factory's `AuthorityClock` for each token and signs it with the `receipt` key in custody by calling `sign_time_token`; the factory's custody directory already holds the key. `MemoryAnchorSource`, a counter, stays for tests |
| `BundleStore` | new `FileBundleStore` in `crates/adapters/file` (`FIELDSEAL_BUNDLE_DIR`) | one directory per tenancy, files named `fieldseal-bundle-<date>-<sequence>.fsb` (DIS-023); a sequence not higher than the latest is refused (`NotNewer`); development adapter |

**Build triggers.** A build runs when the inputs of a registered, eligible tenancy change, or when its stored bundle's anchor is too old. The inputs are the set of published artefacts and withdrawals the tenancy's assignments select, the current roster version of each assigned cohort, the assignments of the tenancy's account (tenancy registry state, §7.4), the serial of the tenancy's certificate, the tenancy's reported runtime profile, the release policy and the agreement key. The factory keeps a digest of the inputs beside each tenancy's stored bundle (`<bundle dir>/<tenancy>/inputs.sha256`), not in the signed bundle manifest, so the bundle format does not change, and compares it with the digest of the inputs it reads at that time:

*   **On registration.** When a tenancy becomes `registered`, the factory builds its first bundle (sequence 1).
*   **On change.** A new publication, a new roster version or a changed assignment makes the digest differ, and the factory builds sequence + 1 (DIS-015). A key roll builds for the new agreement key (DIS-050). When an assignment changes a tenancy's cohort set, the Registration context reissues the tenancy's certificate first (§7.4), and the new bundle carries it.
*   **Idempotent.** If the digest is unchanged, nothing is built. A rebuild after a restart therefore produces no extra bundle.
*   **Anchor freshness.** A bundle must contain a fresh anchor (DIS-010). The reconciler rebuilds a tenancy's bundle, with a new anchor and sequence + 1, when the anchor in the stored bundle is older than `FIELDSEAL_FACTORY_MAX_ANCHOR_AGE_S` (§7.6; `fieldseal deployment render` writes it), even if the digest is unchanged. A `reconciler.rs` test checks this rule; it is not a stack gate.
*   **Write order.** For each build the factory writes in this order: (1) the issued rosters for intake (`record_issued`), flushed to disk; (2) the bundle, through the atomic-write helper of §6; (3) the digest, through the same helper. The digest is last, so it never names inputs for which no bundle is stored. A crash between any two steps leaves the previous bundle in place, and the next pass rebuilds. The reconciler exposes a public `BuildWriteHook` trait that it calls after each step and whose default does nothing. The crash-injection test installs a hook that fails after each step in turn and checks this, and later crash tests use the same hook.
*   **How the change is seen.** Two kinds of change reach the reconciler differently. (1) An assignment and a roster issue are made through the factory's own operator operations (§7.4), so the handler journals the change and calls the `ReconcileNotify` callback (`Arc<dyn Fn(TenancyId) + Send + Sync>`, defined in `factory-http` in Phase 12 as a no-op until Phase 13 connects it to the reconciler): the affected tenancies are rebuilt at once, with no restart and no wait. A registration is also an in-process event. (2) New publications arrive as files written by the CLI (`artefact publish`), and the file adapters have no change events, so the reconciler re-reads the artefact registry directory at an interval (`FIELDSEAL_FACTORY_BUILD_INTERVAL_S`: default 5 in development and 60 elsewhere; whole seconds from 1 to 3600, and a value outside that range exits `2`). The polling is only for those file changes; a production adapter (a database or an event stream) would trigger the same reconciler by event and the poll would go. A restart rebuilds nothing unless the digest differs or the anchor is too old.
*   **Which instrument version.** For each survey assigned to the tenancy, the bundle carries the highest semver among the non-withdrawn published instruments of that name that satisfy DIS-012 for the tenancy's reported schema. A new version published later therefore replaces it in the next bundle, and a withdrawn version is never chosen. If no version satisfies DIS-012, the survey is left out and the reconciler records `bundle-withheld(instrument-incompatible)`.
*   **Trust in the release policy.** The release policy is the artefact named `deployment-policy` (kind Policy). It is itself a publication, so the factory never verifies it under the publishing policy it carries: one publisher key could publish a `deployment-policy 99.0.0` with `publisherThreshold` 1 of 3, signed by itself. The factory verifies it against a trusted publishing policy first. Outside development (staging and production) that is a pinned digest: `FIELDSEAL_FACTORY_POLICY_DIGEST`, rendered from the manifest (`policyDigest` of the factory's `PolicyEngine`), is the content address of the one policy the factory reads, any other is refused, and the factory refuses to start without it. In development the policy is verified under the schema defaults with the builders and sources of `FIELDSEAL_FACTORY_ALLOWED_BUILDERS` and `_ALLOWED_SOURCES` (`allowedBuilders` and `allowedSources` of the `PolicyEngine`), highest version first, and a version that fails is skipped with an `artefact-skipped` event. Only then is the publishing policy of the other kinds taken from it. Instruments and layouts are verified as they are selected, with the same fall-back, and a withdrawal counts only when it verifies.
*   **Refusals.** A tenancy that is not eligible (DIS-001, DIS-003, REG-081) gets no new bundle, and the reconciler records `BundleWithheld(reason)` as an event. While no `deployment-policy` artefact is published, no tenancy gets a bundle: the reconciler records `bundle-withheld(no-policy)`, and the first poll after the policy is published builds them. Publishing the policy therefore comes before the first assignment (§8). A build that fails (an unpublished artefact, an incompatible schema, a roster that fails its check) keeps the previous bundle in the store and writes an event with the reason; no partial bundle is released (DIS-075).

**Which layouts a bundle carries.** DIS-016 lets factory policy assign layouts. The policy control `factory.release.layouts` (Policy spec §6.1, naming as `factory.release.requireRegisteredTenancy`) takes `bound` (default) or `none`. `bound`: for each instrument in the bundle, every published, non-withdrawn layout bound to that instrument's fingerprint (INS-200), newest version per window class (INS-207). `none`: no layouts. The `bundle.release` decision still gates the whole bundle. DIS-016 keeps its text. The default policy file `examples/deployments/policy/deployment-default.yaml` sets `bound`. A layout is published under the name `<survey>-<window>` (artefact names are lower-case and hyphenated, so a dot cannot be used), where `<window>` is `compact`, `medium` or `expanded` (`WindowClass::ALL`); the layout file's `layout.name` carries it, and `tools/dev-publish.sh` only names its own `*.layout.published` files with a dot. The artefact registry lists by kind and name only, so the reconciler asks `ArtefactRegistry::list(Layout, "<survey>-<window>")` for each of the three names, keeps the layouts bound to the instrument's fingerprint and takes the newest version of each. The Publishing context needs no change.

**What happens to `bundle build --stack`.** The generic `fieldseal bundle build --tenancy ... --instrument ... --roster ...` stays: DIS conformance and the offline and air-gapped routes (REG-050, REG-054, `docs/reference/spec/distribution.md` test table) need a builder that runs without a factory. The `--stack` variant is removed from `docs/reference/spec/cli.md`, from `tools/stack-demo.sh` and from `crates/apps/web/src/stack.rs`, because the factory builds bundles (§7.3). `bundle verify --stack` stays as a checker. `bundle build` keeps `--allow-unattested`, because its normal path reads it (`bundle_cmd.rs`, lines 265 and 271); only `--stack` and the flags that only it reads go. The factory's own allowance is `FIELDSEAL_ALLOW_UNATTESTED` (non-production only).

**Route.**

| Item | Value |
|---|---|
| Method and path | `GET /v1/bundle` with optional query `held=<decimal sequence>` |
| Authentication | `Fieldseal-PoP` header (WIRE-170), the same check as `GET /v1/certificate`: `Factory::authenticate_api` with method `GET` and the factory's public URL plus path. Query rule (a change to WIRE-171): the token's `url` is the request URL without its query string, so the query is not signed. It only narrows the answer. A proxy that rewrites `held` changes which answer the device gets (a full bundle instead of `304`, or the reverse), which has the same effect as a dropped response: the device verifies any bundle it imports (DIS-030) and fetches again. |
| `200` | body: the stored sealed bundle (`application/octet-stream`, `FSB1`), headers `Fieldseal-Bundle-Sequence: <n>` and `Content-Disposition: attachment; filename="fieldseal-bundle-<date>-<n>.fsb"` (DIS-023) |
| `304` | no body: the bundle the device holds (`held`) is the latest |
| `401` | `pop-required`, `proof-invalid` or `replay` (same codes as the other PoP routes) |
| `403` | `not-registered` or `revoked` (tenancy unknown, or `lost`, `closing`, `closed`, `retired`); `withheld` with a `reasons` list when policy or tenancy state withholds bundles (DIS-001, DIS-003, REG-081) |
| `404` | `no-bundle`: the tenancy is eligible but no bundle has been built yet (the first build is still running, or it failed; the reason is in the factory's events) |
| `503` | `unavailable` |

The route only serves what is stored; it never builds. `FetchBundle::fetch` returns `None` both when nothing is stored and when the held bundle is current (`crates/contexts/distribution/src/application/fetch.rs`), so the route could not tell `404 no-bundle` from `304`. `fetch` therefore returns a `BundleFetchResponse` of `NoBundle`, `Current` or `Bundle`, decided by reading `BundleStore::latest` first (entry 578). The answer reveals no subject, cohort, tenancy or instrument outside the seal (DIS-022); the roster is inside the seal, sealed to the tenancy's agreement key (DIS-020), so a stolen or replayed token yields bytes only that device can open. Responses carry `Cache-Control: no-store`. The client's bundle call allows a larger answer than the 1 MiB `MAX_ANSWER` of the other calls, up to the bundle limit (DIS open question 2 proposes 8 MiB).

**Portal download (DIS-041, REG-054).** The factory portal gets `GET /devices/{device}/bundle.fsb` for a signed-in collector, for their own device only, serving the same stored bundle through `DownloadBundle` with the file name of DIS-023. It needs a session (not CSRF, it changes nothing) and an account check that the device belongs to the signed-in account (REG-043). The device list page links to it beside the certificate link. It is the route for an air-gapped device: the collector downloads the file and the device imports it from storage (DIS-041, DIS-060). Missing from `factory-http` today.

**Changes by component.** `factory-http` serves the fetch and download routes and its client gains the bundle call. `fieldseal-factory` builds `BundleBuilder` and the reconciler from the ports above, drops `FIELDSEAL_COHORTS` (assignments are tenancy registry state, §7.4) and serves the operator routes of §7.4. `fieldseal bundle fetch --device-dir <dir> [--factory-url <url>] [--trust-bundle <file>] [--held <seq>] --out <file>` makes the PoP token with the device's signing key (as `registration wait --device-dir` does), stores the bundle under its DIS-023 name, and exits `0` (stored or already current), `1` (refused) or `3` (unreachable). The WebAssembly device builds the PoP token with the core's existing `PopToken` code and gains `fetchBundle(factoryUrl, held)`, and the token is bound to the factory's public URL while the request goes through the collector stand-in's same-origin proxy, as registration does. The collector stand-in drops `GET /device/bundle` and `stack::bundle`; the Device page polls registration and fetches the bundle. The new factory variables are in §7.6, and the factory README gains them and the new events (`bundle-built`, `bundle-withheld`, `bundle-failed`, without personal data, DEP-051). The Phase 13 and 14 entries list each file.

**Spec changes and security review.** This is a change to `docs/reference/spec/registration.md` REG-085 (the operation `GetBundle`, `GET /v1/bundle`, PoP), and the portal rows of REG-054, which the HTTP adapter's tests cover (there is no gRPC adapter yet and REG-087 has no contract table); to `docs/reference/spec/distribution.md` DIS-040 (HTTP mapping and error table above) and new DIS-082 to DIS-084 (entry 381); to `docs/reference/spec/wire-formats.md` WIRE-171 (the query rule above, entry 540); and to the `fieldseal.v1.Factory` contract of ADR 0035. Two security reviews apply, because there are two new surfaces: the fetch and download routes (SR-2) and the factory as a builder (SR-3). Their points are listed in Non-Functional Requirements, Security & Privacy.

#### 7.4 The `fieldseal roster` command group and cohort assignments

Rosters are today a file shape plus a port. The file (`examples/rosters/*.yaml`) has `cohort`, `version` and `subjects`, each with `subject` (a pseudonymous id), `display`, `consent` (`granted`, `refused` or `unknown`), optional `prior_status`, and `fields`. The `RosterSource` port (`crates/contexts/distribution/src/ports.rs`) returns current rosters for the cohorts assigned to a tenancy and the number of other active tenancies per cohort; its contract says a cohort's version never decreases. DIS-013 says a bundle's roster carries only the fields the instrument references, DIS-014 gives it a cohort, a monotonic version and the tenancy's generation, and DIS-063 sets the closed-schema rules (unique subjects, strictly increasing ordinals, one roster per cohort, a consent state from the declared set). No command creates, checks, versions or assigns a roster today. This command group adds that production feature, and demo step 5 uses it.

Two commands change factory state, so they are operator operations of the factory: `roster issue` (`IssueRoster`) and `roster assign` (`AssignCohort`). Each needs an operator sign-in (§7.5) and is journaled. The other commands are local: `check` writes nothing, and `diff` and `list` read a copy of the roster store.

| Command | Purpose | Inputs → outputs | Ports | Implements |
|---|---|---|---|---|
| `roster check <file> --instrument <survey dir>... [--json]` | Validate the roster against its closed schema (DIS-063) and against the `roster.<field>` reads of each instrument (found by `collect_roster_fields` in `crates/contexts/distribution/src/domain/facts.rs`, which reads every text of the expanded instrument, so a field read only through a message variable or a `type: roster` item counts): a field an instrument reads that a subject lacks is an error; a field no instrument reads is a note that DIS-013 will drop it. Reports the consent counts. `survey check --roster` (§4) calls the same code | roster, instruments → findings, counts | — | DIS-013, DIS-063, CLI-050 |
| `roster issue <file>... --factory-url <url> [--instrument <survey dir>...] [--login <name>] [--browser <command>\|none]` | Ask the factory to add each roster file as a new version in its roster store. The command runs `roster check` locally first (`--instrument` takes a survey folder only, as it does for `roster check`; without it only the closed schema is checked), and the factory runs the DIS-063 check again. The file's `version` is the stored version, and it must be higher than the store's latest for the cohort. The same content at the same version returns `unchanged` and different content at an existing version is refused. Several files share one sign-in. Calls `POST /v1/rosters` | roster files, OIDC sign-in → stored version, content digest | factory client, OIDC client | REG-047, DIS-014, DIS-080, CLI-051 |
| `roster diff <a> <b> [--store <dir>]` | Each operand is a roster file or a stored version written `<cohort>@<version>` (for example `village-a@3`), which is read from `--store`, a read-only copy of the factory's roster store. Compare two versions: subjects added, removed and kept, consent changes by from/to state, `prior_status` changes, and which field names changed. Prints counts only; subject ids and values are printed only with `--reveal`, which warns on stderr (CLI-008) | two rosters or two stored versions → counts | — | DIS-081, CLI-008, CLI-052 |
| `roster list --store <dir> [--cohort <id>]` | List stored versions, named `<cohort>@<version>`, with digests, subject counts and consent counts (no ids) | store → table | `RosterSource` | CLI-053 |
| `roster assign --factory-url <url> --account <oidc-subject> (--assign <survey>=<cohort>)... [--login <name>] [--browser <command>\|none]` | Sign in as an operator (§7.5), then ask the factory to assign each cohort to its survey for one account: the collector whose OIDC subject is given. The assignment applies to the account's active tenancies and to tenancies the account registers later, and the factory records generation 1 for each cohort on each of those tenancies (DIS-014). Several `--assign` options share one sign-in. Calls `POST /v1/assignments`; `roster assign --list` calls `GET /v1/assignments` and prints the journaled history. The command removes nothing. If the collector has not signed in yet, the factory creates the account. It prints the account (the subject given), the cohort and the survey | OIDC sign-in → assignment records | factory client, OIDC client | REG-046, CLI-055 |

**Example rosters, next versions.** The examples ship the next version of each roster in `examples/rosters/next/` (`village-a.yaml` with `version: 4`, because `examples/rosters/village-a.yaml` is at version 3, and `cohort-a.yaml` with `version: 2`): the same subjects plus two new ones, one consent state changed and one field value changed. The directory is below the one that `RosterSet` and the collector stand-in list, so the current files stay the ones that `survey check` and the Instruments page load. Demo step 5 issues them (§9).

**What the store holds.** The factory writes `<store>/<cohort>/v<version>.roster` when it accepts `IssueRoster`: the roster in its canonical form (the closed schema of DIS-063, so unknown fields are rejected at issue, not at build), with its SHA-256 recorded beside it. The store carries every column the roster has; the builder cuts it down per DIS-013 and the factory never exposes the store. Only the factory writes it. It holds personal data (display names, consent), so it is a file store with restricted permissions, a development adapter (§10.1). The operator reads a copy for `diff` and `list` (in the stack the demo container mounts the volume read-only). `FileRosterSource` serves it; the `RosterSource` contract test (`roster_source_contract`) runs against it. The factory's reconciler records the issued rosters for intake's consent checks, per tenancy and restricted to the fields the instrument reads, into `FIELDSEAL_ISSUED_ROSTERS_DIR` when it builds a bundle (`record_issued`, `crates/adapters/file/src/rosters.rs`; intake reads the directory as `FIELDSEAL_INTAKE_ROSTERS_DIR`), so intake and the factory see the same roster versions (§7.3).

**Assignment: tenancy registry state, per account.** An assignment says that one account, the collector identified by an OIDC subject, receives a survey's published instrument and a cohort's roster on its tenancies. It is data about who may collect what, so it lives in the factory's tenancy registry beside tenancies and devices, is changed only by an authenticated operator, and is journaled so that it can be audited. It replaces both the `assignments` manifest field and the `cohorts:` string. A tenancy's cohorts are the cohorts of its account's assignments, each at the generation recorded for that tenancy. REG-032 puts them in the tenancy certificate, and DIS-014 in the roster. The account is identified by its `AccountId`, which is the OIDC subject; the opaque `collector` reference in certificates is a separate random value (`Account.collector`) that is never derived from the subject.

The assignment targets an account, not every tenancy, for three reasons:

1.  *Cohort limit.* `factory.cohorts.maxActiveTenanciesPerCohort` defaults to 1 (REG-041, `docs/reference/spec/policy.md` §6.1), and the `bundle.release` rule `cohort-tenancy-limit` (`crates/adapters/opa/policy/policy.rego`) holds a bundle for a cohort that already has that many other active tenancies. An assignment to all tenancies would give every device every cohort, so only the first device would ever get a bundle.
2.  *Generations.* DIS-014 makes the generation a property of one cohort on one tenancy. Succession moves a cohort to another tenancy at `generation + 1` (REG-045, DIS-051). One generation per cohort across all tenancies cannot express that.
3.  *Privacy.* A roster carries display fields and consent states. Sending every cohort's roster to every device contradicts data minimisation (DIS-013) and grows the bundle towards its size limit (8 MiB, DIS open question 2). The residual risk is recorded under Risks & Mitigations.

Succession is out of scope for this design: no operation here moves a cohort to another tenancy.

*Operations.* Three operations are added to the Factory contract (REG-085), all operator-only:

| rpc | HTTP | Authentication | Payload |
|---|---|---|---|
| `IssueRoster` | `POST /v1/rosters` | operator Bearer access token (§7.5) | closed document: the roster in its canonical form (DIS-063); canonical CBOR on the wire (REG-085, WIRE-196), shown as JSON by the CLI |
| `AssignCohort` | `POST /v1/assignments` | operator Bearer access token | closed document `{account, survey, cohort}`; `account` is the collector's OIDC subject, which is the `AccountId` |
| `ListAssignments` | `GET /v1/assignments` | operator Bearer access token | the journaled records, oldest first |

*The account may not exist yet.* The factory creates an `Account` today only when the first registration token is issued (`crates/contexts/registration/src/application.rs`, lines 391 to 398), and `just up` and `just web` assign before anyone has signed in. `AssignCohort` therefore creates the account when it is missing: `id` is the OIDC subject, `collector` is a random 16-byte reference, and `roles` is empty until the person's first sign-in sets them. `Assignment.account` stores that `AccountId`.

The roster body carries personal data. The factory serves the route over TLS outside development, logs no body, and the security review SR-4 covers it.

*Refusals.* `401 bearer-required` or `token-invalid` (missing token, bad signature, wrong issuer or audience, wrong `typ`, a `nonce` claim, wrong client, expired); `403 not-authorised` (valid token, no `operator` role) or `authentication-too-weak` (sign-in not phishing-resistant). `AssignCohort` also answers `404 unknown-survey` (no published instrument of that name in the `ArtefactRegistry`), `404 unknown-cohort` (the roster store holds no version of the cohort). `IssueRoster` also answers `422 roster-invalid` (the DIS-063 check failed), `409 version-taken` (different content at an existing version) and `409 not-newer` (a version lower than the latest). Neither operation has a remove. The only spec basis for removal is succession (REG-045, DIS-051), which this design does not build, so removals stay refused and the CLI names REG-045. An identical request returns `200` with `unchanged` and writes no record.

*Generation.* The factory records generation 1 for each cohort on each tenancy that receives it, as DIS-014 requires. No operation in this design changes a generation. The rule for moving a cohort to a successor tenancy at a higher generation is the Cohort succession Future Improvement.

*Ports and where the code lives.* The Registration context can depend only on the Trust and Policy contexts (`architecture.toml`), and an app cannot depend on another app, so the use cases reach everything else through three new ports defined in the Registration context: `RosterIssuer::issue(cohort, canonical_bytes) -> IssueOutcome` (`Issued { version, digest }`, `AlreadyIssued`, `VersionTaken`, `NotNewer` or `Invalid(reason)`), `SurveyDirectory::exists(name) -> bool` and `CohortDirectory::exists(cohort) -> bool`. The DIS-063 closed-schema check is a pure function in the Distribution context beside `Roster` (`crates/contexts/distribution/src/domain/roster.rs`, entry 562), so the CLI's `roster check` and the factory's adapter call the same code. `crates/adapters/file` implements `RosterIssuer` with that function and `RosterStore` (entry 572), and the factory app wires it, `SurveyDirectory` over the artefact registry and `CohortDirectory` over the roster store. The `IssueRoster` request body is the roster wire form of WIRE-095 without `generation`, because a generation belongs to one cohort on one tenancy (DIS-014) and the store holds none; `wire-formats.md` defines the form (entry 573). `IssueRoster` writes in this order: (1) the roster store write, which is idempotent by content digest; (2) the journal record. If the process stops between the two, the next issue of the same bytes returns `AlreadyIssued` and writes the missing journal record.

*Journal records.* The factory's `RegistryStore` (`crates/contexts/registration/src/ports.rs`) gains `put_assignment`, `assignments`, `put_roster_issue` and `roster_issues`, with cases in `registry_store_contract`; the file journal (`crates/adapters/file/src/store.rs`, `codec.rs`) gains two record kinds. Each record is written in the same journaled change as the tenancy updates it causes.

| Record | Fields |
|---|---|
| `Assignment` | `seq` (journal order), `account` (the `AccountId`, which is the collector's OIDC subject), `survey` (the name of the published instrument), `cohort`, `generation`, `by` (the signed-in operator's account), `roles` (role names at the time), `methods` (the `amr` and `acr` values the sign-in carried), `at` (the factory's clock time) |
| `RosterIssue` | `seq`, `cohort`, `version`, `digest` (SHA-256 of the canonical roster), `by`, `roles`, `methods`, `at`; no subject data |

The events `assignment-made` (survey, cohort, generation) and `roster-issued` (cohort, version, digest) carry no roster value and no account subject (DEP-051). Because each record names who, when and what, an auditor lists the assignment history with `roster assign --list`.

*Registration applies the account's assignments.* A tenancy that an account registers later receives the account's assignments at registration, and each affected tenancy's own journal record (cohorts with generations) is written in the same change. `TenancyTerms.cohorts` (`crates/contexts/registration/src/domain/mod.rs`, line 394), which `register` copies into the tenancy record (`application.rs`, line 565), is today a fixed list set by the deployment. The field stays, and the factory sets it empty; `register` adds the cohorts of the account's assignments to it, and the same use case fills it again whenever the account's assignments change, in the same change as the certificate reissue below. `FIELDSEAL_COHORTS` is removed in Phase 12.

*Certificate reissue.* REG-032 puts a tenancy's cohort assignments and generations in its signed `TenancyCertificate`. When an assignment changes a tenancy's cohort set, the Registration context issues a new certificate from the tenancy record (`certificate_for`, `crates/contexts/registration/src/application.rs`) with a new serial, stores it in the record and journals it in the same change. `GetCertificate` returns the stored certificate. A bundle carries the current certificate when it carries rosters (`BundleContents.certificate`, `crates/contexts/distribution/src/domain/content.rs`; DIS-030 step 5 checks that it names the device's agreement key). The serial is a build input (§7.3), so the next bundle brings the new certificate. Tests: the context reissues the certificate, the bundle carries the new cohort set, and the device accepts the new certificate (Phase 14).

*Cohort limit and the presenter's reset.* The default `maxActiveTenanciesPerCohort = 1` stays in production. With it, an account's second active tenancy for a cohort is held (`cohort-tenancy-limit`). The presenter resets the demo by retiring the old device on the factory portal (REG-043 *retire*, the `Retire` driving port, which issues a close certificate) and then registering again. A retired tenancy is not active (`TenancyState::is_active` is true only for `held`, `registered` and `flagged`), so the new tenancy sees no other active tenancy and receives the cohort. No development policy raises the limit. `examples/deployments/policy/dev-web-publishing.yaml` and the stack's policy set `factory.cohorts.maxActiveTenanciesPerCohort: 1` explicitly, with a comment that the demo's reset relies on the limit and on retirement. The e2e harness (`crates/apps/e2e/src/lib.rs`) and the `web-demo` adapter raise the limit in tests that register many devices in process; `web-demo` is deleted in Phase 16c and the e2e override stays in tests.

*Rebuild.* After the journal write the handler notifies the reconciler (§7.3). If a device fetches while the rebuild runs, it gets the old bundle or `404 no-bundle` and retries; the new bundle is served from the first fetch after the build finishes. Setting up the demo or a stack therefore needs no restart: `fieldseal roster issue` and `fieldseal roster assign` are run after the services are up.

**Personal data stays off web pages.** No roster command is exposed in the browser. The collector stand-in's roster page (`/instruments/{id}/roster`) shows the roster's shape and counts only (cohort, version, subject count, consent counts, field names), never `display`, `subject` or field values. It reads them from the roster store (through a read-only mount) or from `examples/rosters/`, not from the survey folder. The CLI prints counts, not ids (CLI-008).

**Initial assignments in the stack.** After the waits, `tools/stack-up.sh` runs three steps in the order of §8: `tools/stack-run.sh seed` publishes the instruments, their layouts and the policy (idempotent), `tools/stack-run.sh issue` runs `fieldseal roster issue` for version 1 of each example roster, and `tools/stack-run.sh assign` runs `fieldseal roster assign --account 00000000-0000-4000-8000-000000000003` (the `product-owner` subject of §7.5) in the `demo` container. Both commands run with `FIELDSEAL_BROWSER` set to `tools/stack-browser.sh`, which Phase 12 creates (entry 346) over `tools/local-stack-passkey.py` (entry 347). The opener opens the authorisation URL, performs the passkey sign-in and lets Keycloak redirect to the CLI's loopback listener. `stack-run.sh` builds the demo image when it is not loaded, so `just up` includes that image build; Phase 12 records the added time.

**Spec text this adds.** The requirement text is written once, in the phase entry that changes each spec (ids are provisional until that change assigns them): DIS-080 in Phase 8 (entry 215); CLI-050, CLI-052, CLI-053 and DIS-081 in Phase 9 (entries 225 and 226); REG-070a in Phase 11 (entry 303); CLI-051, CLI-055, REG-046, REG-047 and the `AssignCohort`, `ListAssignments`, `IssueRoster` rows of REG-085 in Phase 12 (entries 339 and 340); DIS-082 to DIS-084, `GetBundle` in REG-085 and REG-054 in Phase 13 (entries 380 and 381). The `bundle build --stack` row is removed and `bundle fetch` is added to the `bundle` table in Phases 13 and 14 (entries 382 and 410). The operator operations need security review SR-4 (Non-Functional Requirements), and the bundle routes need SR-2 and SR-3.

#### 7.5 Operator authentication and the development IdP

The operator operations of §7.4 (`IssueRoster`, `AssignCohort`, `ListAssignments`) authenticate with a Bearer access token. The CLI obtains it by signing the operator in through OIDC. REG-001 forbids an identity-provider client in the runtime. The CLI's device commands (`registration`, `bundle fetch`, `device ...`) never touch the OIDC client: only `roster issue` and `roster assign` call the sign-in module, and a test asserts that device commands neither call it nor read `FIELDSEAL_OIDC_*` or `FIELDSEAL_BROWSER`.

*Authentication: OIDC authorization code with PKCE on a loopback redirect (RFC 8252), as `gh auth login` does.* The operations need an account with the `operator` role (`Role::Operator`) that signed in with a phishing-resistant method (REG-002). The CLI acts for that person like this:

1.  The command starts a listener on `127.0.0.1` on an ephemeral port and calls `OidcIdentityProvider::start_sign_in("http://127.0.0.1:<port>/callback")` from `crates/adapters/oidc` (state, nonce, PKCE `S256` verifier, `acr_values`), which returns the authorization URL. The client is the public client `fieldseal-cli`. The CLI reads the issuer and the client id from `FIELDSEAL_OIDC_ISSUER` and `FIELDSEAL_OIDC_CLIENT_ID`, and the flags `--issuer` and `--client-id` override them; a command that finds neither a variable nor a flag exits `2`. The `demo` service in `compose.yaml`, `tools/stack-demo.sh`, `tools/dev-web.sh` and `tools/svc-fixture.sh` set both.
2.  It opens the URL in the browser (`--browser <command>` or `$FIELDSEAL_BROWSER` overrides the opener; `none` prints the URL), the person signs in at the same IdP the factory portal uses (a passkey in the stack), and the IdP redirects to the loopback listener with the code.
3.  The CLI checks `state`, exchanges the code with the verifier at the token endpoint, and keeps the returned access token. A new `finish_sign_in_raw` returns the raw tokens next to the verified person; the CLI verifies the ID token's `nonce` as the portal flow does, so the exchange is bound to its own request. It then closes the listener.
4.  It sends the access token as `Authorization: Bearer <access token>` on the API call.

*Which token: a JWT access token for the factory API (RFC 9068 profile).* The token is an access token whose audience is the factory API, not an ID token. An ID token says who signed in to a client; an access token says what a client may call, and its audience names the API that must accept it. A token issued for the factory portal or the intake portal is not accepted on the factory API, and a token issued for the factory API is not accepted by either portal. `crates/adapters/oidc` verifies only ID tokens today (RS256/ES256 against the JWKS, `iss`, `aud`/`azp`, `exp`, `iat`, `nonce`, `sub`), so the adapter is extended (below). The token is short-lived (the IdP's access-token lifetime, 5 minutes in the Keycloak realm) and is held in memory for one command.

*Extending `crates/adapters/oidc`: `verify_access_token`.* A new `OidcIdentityProvider::verify_access_token(token) -> AuthenticatedPerson` reuses the adapter's signature and JWKS code and applies the checks below. Roles, `acr` and `amr` come from the access token, with the phishing-resistant mapping the adapter applies to ID tokens, and from no second source. The factory requires the `operator` role and a phishing-resistant method, the rule the portal applies to token issue. `factory-http` defines a `BearerVerifier` trait for this, implemented by the OIDC adapter, so no Registration port changes beyond `RegistryStore`.

| Check | Rule |
|---|---|
| Signature | RS256 or ES256 against the IdP's key set. `none` and symmetric algorithms are refused. The key set is refetched once on an unknown `kid` |
| `iss` | equals the configured issuer |
| `aud` | contains the factory API audience (`FIELDSEAL_OIDC_API_AUDIENCE`) |
| `exp`, `iat`, `nbf` | `exp` has not passed (with leeway); `iat` is not in the future; `nbf` is honoured when present |
| `sub` | present and non-empty |
| Header `typ` | `at+jwt`. A plain `JWT` is accepted only when `FIELDSEAL_OIDC_ACCEPT_TYP_JWT=true`, and then the payload `typ` must be `Bearer`. Any other value is refused |
| `nonce` | a token that carries a `nonce` claim is refused, because only ID tokens carry one |
| Client | `client_id`, or `azp` when `client_id` is absent, equals the CLI public client (`FIELDSEAL_OIDC_CLI_CLIENT_ID`) |
| Roles, `acr`, `amr` | roles from `roles_claim`; `acr` and `amr` from the access token with the ID-token mapping |

Keycloak ID tokens carry the header `typ: JWT`, so a header check alone would accept an ID token for `fieldseal-cli` if its audience held the API. Three rules close this: the realm puts the API audience in the access token only, the `nonce` rule refuses an ID token, and a `JWT` header needs the payload `typ: Bearer` (Keycloak access tokens carry `Bearer`; ID tokens carry `ID`). A realm test asserts that the API audience never appears in an ID token, and a test presents an ID token from `fieldseal-cli` that carries the API audience and asserts that it is refused. **This API-route access-token verification is a new authentication path and is subject to security review SR-4 (Non-Functional Requirements, Security & Privacy).**

*Fixed subjects.* Each login has a fixed subject, so that `roster assign --account` can name an account before it has signed in (§7.4). These values are used everywhere, in the dev IdP configuration, the Keycloak realm, the scripts and the tests:

| Login | Subject |
|---|---|
| dev IdP `presenter` | `00000000-0000-4000-8000-000000000001` |
| dev IdP `collector1` | `00000000-0000-4000-8000-000000000002` |
| Keycloak `product-owner` | `00000000-0000-4000-8000-000000000003` |
| Keycloak `collector` (if the realm gains one) | `00000000-0000-4000-8000-000000000004` |

*Keycloak in the stack.* The realm gains a public client `fieldseal-cli` (no secret, standard flow only, PKCE `S256` required, redirect URI `http://127.0.0.1/*`) with these mappers, and a fixed id for the user `product-owner` so that `tools/stack-run.sh assign` can name the account:

*   an audience mapper that adds `fieldseal-factory-api` to the access token's `aud` and to no ID token;
*   a roles mapper that puts the realm roles into the `roles` claim of the access token;
*   the `acr` claim in the access token (the acr mapper's "add to access token" on), with the passkey flow mapped to the level the factory treats as phishing-resistant.

The Keycloak behaviours that this sign-in assumes are listed once, as items to confirm, in the Keycloak row of Risks & Mitigations.

*Caching.* No token is cached on disk. A stored access or refresh token would be a bearer credential that outlives the command and could be read by another process of the user; the access token lives minutes anyway, and a refresh token would need `offline_access` and a store that a phishing-resistant sign-in policy does not expect. Each command signs in once and keeps the token in memory until it exits; commands that need several calls take them together (several files for `roster issue`, several `--assign` options for `roster assign`). The cost is a browser round trip per command: a passkey touch in the stack and nothing under the development IdP.

*The development IdP (`crates/apps/dev-idp`).* `just web` runs a development-only OIDC provider in place of Keycloak, so that the factory, the intake app and the CLI use the same `oidc` adapter against it as against Keycloak or a real IdP. There is no second sign-in code path.

*   **Where it lives.** A new app crate `crates/apps/dev-idp`, package `fieldseal-dev-idp`, binary `fieldseal-dev-idp`, added to the `apps` list in `architecture.toml`. It belongs in the app layer because it is a server with its own configuration and no context logic, and apps may depend on kernel, contexts and adapters. It must not sit in `crates/adapters/oidc`, which is the production client and holds no token-issuing code. It is not built into any image, appears in no compose file or deployment manifest, and has no Nix image; `just web` builds it with Cargo in the dev shell.
*   **Routes.** It serves Keycloak's paths under the issuer URL the stack's Keycloak uses (`http://localhost:8180/realms/fieldseal`), so the factory and intake configuration is identical in both and discovery is the only thing a client reads:
    *   `GET /realms/fieldseal/.well-known/openid-configuration`;
    *   `GET /realms/fieldseal/protocol/openid-connect/auth` (PKCE `S256` required; loopback redirect `http://127.0.0.1:<any port>/...` for the public client per RFC 8252 section 7.3; registered redirect URIs for the portal clients; `login_hint` selects a login and approves at once, otherwise a page lists the logins);
    *   `POST /realms/fieldseal/protocol/openid-connect/token`;
    *   `GET /realms/fieldseal/protocol/openid-connect/certs`.
*   **Token claims.** It signs with ES256 and a key generated at start. The ID token carries `iss`, `aud` (the client), `sub`, `nonce`, `roles`, `amr`, `acr` (`phr` for both logins), `iat` and `exp`. The access token has the header type `at+jwt` and carries `iss`, `sub`, `aud` (the API audience), `client_id`, `scope`, `jti`, `roles`, `acr`, `amr`, `iat` and `exp`; it has no `nonce`.
*   **Configuration file.** `examples/deployments/dev-idp.yaml` lists the logins (login name, subject, roles, `amr`, `acr`), the clients (`fieldseal-factory` and `fieldseal-intake` confidential, with redirect URIs and a secret read at start-up from `FIELDSEAL_SECRET_FACTORY_OIDC_CLIENT_SECRET` and `FIELDSEAL_SECRET_INTAKE_OIDC_CLIENT_SECRET`; `fieldseal-cli` public, with no secret) and the API audience `fieldseal-factory-api`. `just web` ships `presenter` (roles `collector`, `operator`, `results-reader`; phishing-resistant `acr`) and `collector1` (role `collector` only), each with the fixed subject of the table above.
*   **Bind and issuer.** `--bind <addr:port>` (default `localhost:8180`) names where it listens. It accepts loopback hosts only (`localhost`, `127.0.0.1` and `[::1]`) and exits `2` for any other, and it derives its issuer from the bind as `http://<bind>/realms/fieldseal`, so the default is the issuer the stack's Keycloak uses. `tools/dev-web.sh` and `tools/svc-fixture.sh` both use the default, so they cannot run together or beside `just up` (§8).
*   **Refusals.** It refuses to start unless it is started as a development tool: it requires the flag `--development-tool`, `FIELDSEAL_ENVIRONMENT=development` (any other value, including `production`, makes it exit `2`), and a loopback bind address. It prints a banner on start and writes a `development-adapters`-style event naming itself. Because it is a separate binary that no image contains, production cannot run it by mistake.
*   **What stays of the development identity (`FIELDSEAL_IDENTITY=dev`).** `MemoryIdentityProvider` (`crates/adapters/memory/src/registration.rs`) stays as a test double for unit and contract tests, where no HTTP IdP is wanted. The factory's `FIELDSEAL_IDENTITY=dev` mode and the deployment adapter `memory-dev` stay only for the factory's own tests and its refusal tests; `just web` and the stack both use `FIELDSEAL_IDENTITY=oidc`. The intake app has the same `dev` option (§7.1), used by `just web` in Phase 10 only; production refuses it, and Phase 11 switches `just web` to `oidc`.
*   **Results reader sign-in.** The results reader uses the same `oidc` flow: a presenter chooses `presenter` or `collector1` on the development IdP's page (or passes `login_hint` in a scripted call) and needs no restart to show the refusal of `collector1`.

*Running non-interactively.* With the development IdP the CLI flow completes without a human: with `--browser none --login <name>` the CLI requests the authorization URL itself with `login_hint`, the IdP answers with a redirect to the CLI's loopback listener, and the CLI follows it. This succeeds only if the first response is a redirect; if the IdP returns a login page the command fails with "this sign-in needs a person" (the case against Keycloak). In the Keycloak stack the passkey browser harness does the sign-in (§8). Recipes call `roster issue` and `roster assign` once each, with all their files or `--assign` options, so each performs one sign-in.

#### 7.6 Environment variables

Every service reads its configuration from the environment only (DEP-012), and `fieldseal deployment render` writes the variables from the manifest. A set variable is non-empty and trimmed, flags are `true` or `false`, and a service exits `2` for unusable configuration and `1` for a start-up or runtime failure. The phase entries point to this table.

| Variable | Component | Default | Meaning |
|---|---|---|---|
| `FIELDSEAL_ENVIRONMENT` | all services, development IdP | required | `development` or `production`; production refuses every development adapter |
| `FIELDSEAL_INTAKE_BIND` | intake | `0.0.0.0:8480` | upload listener (renamed from `FIELDSEAL_UPLOAD_LISTEN`) |
| `FIELDSEAL_INTAKE_PUBLIC_URLS` | intake | none | base URLs that device tokens may be bound to (renamed from `FIELDSEAL_UPLOAD_PUBLIC_URLS`) |
| `FIELDSEAL_INTAKE_MAX_BODY` | intake | none | largest upload body (renamed from `FIELDSEAL_UPLOAD_MAX_BODY`) |
| `FIELDSEAL_INTAKE_PORTAL_BIND` | intake | `127.0.0.1:8481` | intake portal listener |
| `FIELDSEAL_INTAKE_PORTAL_URL` | intake | none | public base URL of the portal; the sign-in callback and the cookie's `Secure` flag follow it |
| `FIELDSEAL_IDENTITY`, `FIELDSEAL_OIDC_*` | factory, intake | none | identity provider settings; identical for both. `dev` (a fixed login, no identity provider) is a development adapter that production refuses; the intake app uses it only in Phase 10 |
| `FIELDSEAL_OIDC_ISSUER`, `FIELDSEAL_OIDC_CLIENT_ID` | CLI | none | issuer URL and public client id (`fieldseal-cli`) of the operator sign-in; the flags `--issuer` and `--client-id` override them (§7.5) |
| `FIELDSEAL_OIDC_API_AUDIENCE` | factory | none | audience of the factory API access token (§7.5) |
| `FIELDSEAL_OIDC_CLI_CLIENT_ID` | factory | none | the CLI public client that may use the operator API |
| `FIELDSEAL_OIDC_ACCEPT_TYP_JWT` | factory | `false` | accept a plain `JWT` header type, with the payload `typ` rule (§7.5) |
| `FIELDSEAL_INTAKE_READER_ROLE` | intake | `results-reader` | role that may read results |
| `FIELDSEAL_CUSTODY`, `FIELDSEAL_CUSTODY_DIR`, `FIELDSEAL_TRUST_BUNDLE` | factory, intake | none | record, receipt and receiver keys; `file-dev` or `memory-dev`, non-production only |
| `FIELDSEAL_TENANCY_DIR` | intake | none | the factory's state directory, read-only (`TenancyRegistry` `file-dev`) |
| `FIELDSEAL_LANDING_DIR` | intake | none | landing files |
| `FIELDSEAL_INTAKE_SUBMISSIONS_DIR` | intake | none | submission store, used by start-up replay |
| `FIELDSEAL_INTAKE_PUBLISHED_DIR` | intake | none | published instruments |
| `FIELDSEAL_INTAKE_ROSTERS_DIR` | intake | none | issued rosters, as the factory records them |
| `FIELDSEAL_INTAKE_ALLOWED_BUILDERS`, `FIELDSEAL_INTAKE_ALLOWED_SOURCES` | intake | none | publishing policy for instruments |
| `FIELDSEAL_EXPORT_KEY_DIR` | intake | none | directory that holds `export.key` (§6, export pseudonymisation key) |
| `FIELDSEAL_FACTORY_REGISTRY_DIR` | factory | none | the artefact registry directory, `<state>/registry` |
| `FIELDSEAL_ROSTER_DIR` | factory | none | the roster store; the factory reads and writes it |
| `FIELDSEAL_BUNDLE_DIR` | factory | none | stored bundles, one directory per tenancy |
| `FIELDSEAL_ISSUED_ROSTERS_DIR` | factory | none | issued rosters for intake (intake reads it as `FIELDSEAL_INTAKE_ROSTERS_DIR`) |
| `FIELDSEAL_FACTORY_BUILD_INTERVAL_S` | factory | 5 in development, 60 elsewhere | seconds between artefact registry directory scans, 1 to 3600 |
| `FIELDSEAL_FACTORY_MAX_ANCHOR_AGE_S` | factory | `86400` | rebuild a bundle whose anchor is older than this; 60 to 604800 |
| `FIELDSEAL_COHORTS` | factory | removed | replaced by assignments (§7.4) |
| `FIELDSEAL_SECRET_<REFERENCE>` | factory, intake, development IdP | none | resolves a manifest `secretRef` at start-up; `FACTORY_OIDC_CLIENT_SECRET` and `INTAKE_OIDC_CLIENT_SECRET` |
| `FIELDSEAL_BROWSER` | CLI | none | command that opens the authorisation URL for `roster issue` and `roster assign`; `--browser` overrides it |
| `FIELDSEAL_WEB_AUTHORITY_DIR` | collector stand-in | `/authority` | authority directory in stack mode |
| `FIELDSEAL_WEB_REGISTRY_DIR` | collector stand-in | none | in stack mode, the CLI's file artefact registry (`<state>/registry`); the Publishing page lists the artefacts in it (Phase 5b) |
| `FIELDSEAL_WEB_SURVEY_COHORTS` | collector stand-in | none | `survey=cohort,...`: which cohort's roster a survey's pages use; the stand-in reads no assignments, so the map stays after Phase 12. It finds the roster by cohort in `examples/rosters/`, or in the roster store when `FIELDSEAL_WEB_ROSTER_DIR` is set |
| `FIELDSEAL_WEB_ROSTER_DIR` | collector stand-in | none | the roster store, mounted read-only (Phase 12); the roster page reads it when set and `examples/rosters/` otherwise |
| `FIELDSEAL_WEB_PUBLISHED_DIR` | collector stand-in | `/published` | in stack mode, the directory of `*.published` files that names the published surveys; read-only (Phase 14) |
| `FIELDSEAL_WEB_ALLOWED_BUILDERS`, `FIELDSEAL_WEB_ALLOWED_SOURCES` | collector stand-in | none | comma-separated publishing allow-lists for the provisioning document; `tools/stack-up.sh` and `tools/dev-web.sh` copy them from the rendered intake environment (`FIELDSEAL_INTAKE_ALLOWED_BUILDERS`, `_SOURCES`) (Phase 14) |

### 8. Dev loop

**`just web`.** A new recipe runs `tools/dev-web.sh` inside the existing Nix shell. It runs the production service binaries natively, configured the way the container stack is, and then the collector stand-in. The order is the production order: publish first, then issue rosters, then assign. The factory refuses an assignment for a survey that is not published (`unknown-survey`) or for a cohort with no roster in its store (`unknown-cohort`, §7.4). The plan assumes that `fieldseal deployment render` stays; ADR 0040 section 4 proposes removing the command, and that decision stays open (§3, Docs).

1.  The script checks that ports 8080, 8090, 8180, 8480, 8481 and 9001 are free and exits with a message that names the port when one is taken. `just web` and `just up` cannot run at the same time: the development IdP and Keycloak both use 8180, and the services use the same ports as the stack's. It creates the client secrets once (mode 0600), as `tools/stack-up.sh` does for the stack, and loads them into the environment of the development IdP, the factory and the intake app, and of no other process (§7.6).
2.  The script starts the development IdP (`fieldseal-dev-idp --development-tool`, on `localhost:8180`, §7.5) and waits for its discovery document. The script then validates and renders the deployment manifest `examples/deployments/dev-web.yaml` with `fieldseal deployment validate` and `fieldseal deployment render --environment development`. The manifest is `examples/deployments/local-stack.yaml` with directories under `deploy/local/.state/dev-web/` instead of volumes; neither carries assignments or a `cohorts` string. The identity provider is the same `oidc` adapter at the same issuer URL in both, and only the process that listens there differs. The factory's `AttestationVerifier: software` adapter makes the render write `FIELDSEAL_ALLOW_UNATTESTED=true` into the factory's environment (REG-017, non-production only). Validation prints the development adapters in use (§10.1). The rendered environment is the only configuration the services read (DEP-012).
3.  The script creates the authority once with the script the stack uses (`tools/stack-init.sh`, parameterised by directory instead of the fixed `/authority`): root ceremony, purpose keys, the log's key, the trust bundle and the export pseudonymisation key (§6).
4.  The script starts `fieldseal-translog` on `localhost:9001`. When `/checkpoint` answers, `tools/dev-publish.sh --all` publishes the bundled examples with the production CLI verbs (`artefact provenance`, `artefact sign` for two of three publisher keys, `artefact publish`): for each survey, the instrument and then its layouts (kind Layout, bound to the fingerprint of the instrument just published), and then the deployment policy `examples/deployments/policy/dev-web-publishing.yaml`. The script draws a random salt for each instrument from `/dev/urandom` and keeps it beside the artefact registry, because no CLI command prints the salt of a publication and a layout binds to it. The publish script runs the CLI with these variables:

    | Variable | Value | Effect |
    |---|---|---|
    | `FIELDSEAL_ADAPTERS` | `files` | keeps the artefact registry in files (the adapter set is `memory`, the default, or `files`; `crates/apps/cli/src/composition.rs`) |
    | `FIELDSEAL_STATE_DIR` | `deploy/local/.state/dev-web/cli` | puts the artefact registry directory at `<state>/registry` |
    | `FIELDSEAL_TRANSLOG_URL` | `http://localhost:9001` | sends publications to the translog server, not the CLI's local file log |
    | `FIELDSEAL_POLICY` | the policy file | the policy that every publication is checked against |
    | `FIELDSEAL_TRUST_BUNDLE` | the authority's trust bundle | the trust anchors the CLI verifies against |

    Each publication's `*.published` copy goes to the directory that the intake app reads as `FIELDSEAL_INTAKE_PUBLISHED_DIR`.
5.  The script starts `fieldseal-factory` (`:8080`) and `fieldseal-intake` (upload `:8480`, portal `:8481`), each with its rendered environment file, and waits for each `/healthz` (DEP-053). The factory builds bundles from the artefact registry directory and the roster store, and builds nothing while no deployment policy is published (`bundle-withheld(no-policy)`, §7.3). Once the factory is up, the recipe runs `fieldseal roster issue --factory-url http://localhost:8080 --browser none --login presenter examples/rosters/village-a.yaml examples/rosters/cohort-a.yaml`, and then `fieldseal roster assign --factory-url http://localhost:8080 --browser none --login presenter --account 00000000-0000-4000-8000-000000000001 --assign household-water-access=village-a --assign school-meals-baseline=cohort-a` (the `presenter` subject of §7.5; both commands run with `FIELDSEAL_OIDC_ISSUER=http://localhost:8180/realms/fieldseal` and `FIELDSEAL_OIDC_CLIENT_ID=fieldseal-cli`). Against the development IdP the OIDC loopback sign-in completes without a human (§7.5). Rosters are issued and cohorts assigned by these commands, never by configuration. An edit to Rust code rebuilds incrementally, with no container image.
6.  The script starts `fieldseal-web` with `FIELDSEAL_WEB_STACK=true` on `127.0.0.1:8090`, with `FIELDSEAL_FACTORY_URL`, `FIELDSEAL_UPLOAD_URL` and `FIELDSEAL_LOG_URL` pointing at the services and the trust bundle of step 3 as its provisioning. The collector stand-in is on `127.0.0.1` and the services are on `localhost` so that their cookies are not sent to the collector stand-in (§7.2).
7.  The script prints the URLs (collector stand-in, factory portal, results reader), the two logins, the development adapters in use, a note that the identity provider is the development IdP, and the commands for the CLI steps (`just publish`, `fieldseal roster ...`). It stops all processes on exit. Each process writes its stderr to `deploy/local/.state/dev-web/logs/<service>.log`; the structured events (`development-adapters`, `bundle-built` and the others) are read there, and the guided demo names the file beside each confirmation that comes from an event.

The policy `examples/deployments/policy/dev-web-publishing.yaml` has the publishing values that `tools/stack-demo.sh` writes for the stack: two approvals for each of Instrument, Policy, TrustBundle and Deployment, `authorMayApprove: false`, a publisher threshold of 2 of 3, `requireTransparencyLog: true`, and the allowlists `allowedBuilders: ["https://ci.example.org/builders/fieldseal-publish"]` and `allowedSources: ["https://git.example.org/authority/artefacts"]`. It also sets `factory.cohorts.maxActiveTenanciesPerCohort: 1` explicitly (§7.4). The intake app checks published instruments against the same two lists, so its rendered environment carries them. The two values live in one place, the `PolicyEngine` config of the intake component, and `fieldseal deployment render` writes them (§7.1).

`FIELDSEAL_ENVIRONMENT=development` is set for every process. Keycloak stays in its container and is not part of `just web`: the development IdP signs in the factory portal, the results reader and the operator CLI, and the passkey flow remains in `just up`. One wrapper recipe, `just publish <survey>`, prints the CLI commands it runs and runs them unchanged (`artefact provenance`, `artefact sign` for two of three publisher keys, `artefact publish` to the local log and artefact registry, with a CLI-generated salt). It takes a survey name, looked up in `surveys/` and then in `examples/surveys/`, or a survey folder. It exists so that the presenter and the tutorial reader do not retype long commands; it adds no behaviour that the CLI lacks. Roster commands (`fieldseal roster ...`, §7.4) are run directly. Bundles need no recipe: the factory builds them (§7.3). The container stack (`just up`) remains for acceptance and CI.

**How `just web` is built up.** The recipe is introduced early, in Phase 5b, and runs the binaries that exist before this plan: `fieldseal-translog`, `fieldseal-factory` and `fieldseal-web` in stack mode, all from the rendered `examples/deployments/dev-web.yaml`, with content reload for survey edits. Phase 5b also publishes the bundled examples at start-up and provides `just publish <survey>`, so the tutorial's publish step works. Stack mode's fixed paths (`/authority`, `/published`, `/factory-state`, `/clistate` in `crates/apps/web/src/stack.rs`) are container paths. Phase 5b makes only the authority path configurable (`FIELDSEAL_WEB_AUTHORITY_DIR`), so the Device page's device and bundle steps do not work under `just web` until Phase 14, which removes the bundle-building code that used the other paths (§7.3). Until Phase 14, `just web` serves the Instruments page, the Publishing and Registration pages and the services' own portals. Until the development IdP exists (Phase 11) the factory uses its existing `FIELDSEAL_IDENTITY=dev` identity, which production refuses, and until assignments exist (Phase 12) it reads `FIELDSEAL_COHORTS` from the manifest. Each later phase adds its own service or step to `tools/dev-web.sh`: the intake app in Phase 10 (with the `dev` identity option, because the development IdP comes later), the development IdP, the client secrets and the switch to `oidc` in Phase 11, the roster issue and the assignments in Phase 12, and the factory's bundle building and `bundle fetch` in Phase 13. Phase 16b completes the recipe with the development-adapter comparison, and Phase 15 documents it. The seven steps above describe the finished recipe.

**Content reload (dev loop only).** There is no authority process to reload, and publishing on every edit would be a demo-only path, so reload applies to the Instruments page only. The collector stand-in already re-reads survey, layout and roster files on every request (`crates/apps/web/README.md`, invariants), through the resolver (§1). An edit therefore shows on the Instruments page at once, and an invalid edit keeps the last good version and shows the resolver error with file, line and column. The collector stand-in keeps an in-memory cache of the last good `LoadedSurvey` for each survey name; a successful load replaces the entry, a failed load leaves it and records the error beside it. The cache is not on disk, so after a restart whose first load of a survey is invalid the page shows only the error. Publishing a change is the CLI step above and needs a new `survey.version`, as in production. The guided demo does not depend on reload; it runs on the bundled examples with or without it.

**Stage timing of `just up`.** `tools/stack-engine.sh` gets a `stage <name> <command>` helper that records elapsed seconds, and `tools/stack-up.sh` and `tools/stack-images.sh` use it for: secrets and manifest render, each image's `nix build`, each image's load, `compose up`, the Keycloak wait (up to 240 s), and the waits for factory, intake, log and web. A final table is printed and saved to `deploy/local/.generated/stack-timing.txt`. Three runs are recorded: from `just purge`, with nothing changed, and after a one-line Rust change. The numbers go into `docs/explanation/build-system.md` as the baseline, and Open Question 1 sets the targets from them.

**Warm-cache CI timing.** The `ci` workflow (`.github/workflows/ci.yml`) is started twice on one commit with `gh workflow run ci`. Job durations are read with `gh run view` and recorded beside the `just up` baseline with the run ids. Whether `FIELDSEAL_CACHIX` is set cannot be read from the repository: the workflow reads it from `vars.FIELDSEAL_CACHIX`, a repository variable. The Actions cache (`FIELDSEAL_CACHE_GHA`) is on by default. The answer to Open Question 2 comes from the repository's Actions variables or from whether the Cachix step is skipped in a job log.

**CI triggers.** The `ci` workflow (`.github/workflows/ci.yml`) runs only for a release tag (`v*`) and for a manual start (`workflow_dispatch`); any phase that edits it keeps these two triggers.

**Test infrastructure.** Tests that need the built services (the WebAssembly device flow, the collector stand-in isolation tests and the security tests that talk to a running factory and intake app) are `#[ignore]`d tests in `svc_*` test binaries. `just test` does not run them, so its 20 second budget is unchanged. A separate nextest profile, `integration`, selects them, so that they run against the real services instead of an in-memory authority without lengthening the default run. `just integration` runs `cargo build --workspace --bins --locked` and then `cargo nextest run --workspace --profile integration --run-ignored only --locked`. A nextest setup script (`tools/svc-fixture.sh`) starts the built `fieldseal-dev-idp`, `fieldseal-translog`, `fieldseal-factory` and `fieldseal-intake` once per run from the same rendered manifest as `just web` and passes their endpoints to the tests. It uses the fixed ports of `just web` and refuses to run while `just web` or `just up` holds any of them, with the same port check (step 1 above). Setup scripts are still experimental in the pinned nextest (0.9.136), so `.config/nextest.toml` sets `experimental = ["setup-scripts"]`. `just acceptance` runs `just integration` first, and the `ci` workflow has an `integration` job that runs the same two commands. Phase 16a adds the profile.

### 9. Guided demo

The guided demo is a stepper in the collector stand-in, over pages and services that exist. New module `crates/apps/web/src/demo_steps.rs` serves `GET /demo` and `GET /demo/{1..8}`; `NAV` in `crates/apps/web/src/ui.rs` gets a "Guided demo" entry first and `/` redirects to `/demo`. Each step page has a title, one sentence on what happens, a line saying who does this in production, the way to do it (a link to the page where the action is done, or, for a CLI step, the exact command to copy, which the stepper does not run), a confirmation panel, and Back and Next links. A banner on `/demo` and on the Device page reads: "This collector stand-in stands in for the native Android and iOS apps, which do not exist yet; only the bindings do." The existing footer stays.

**The stepper performs no action for the authority.** Publishing and roster issue are commands the presenter runs, with the signing keys of the development authority; the factory builds the bundles. The stepper has no key, no session at the factory or the intake app, and no endpoint that changes a service. It only reads, from these sources:

*   public, read-only endpoints reached through the collector stand-in's proxy: the factory's `GET /v1/registrations/{tenancy}` (state only), the log's checkpoint and entries;
*   responses the WebAssembly device itself received, for example the bundle response headers of §7.3 and the upload receipts, which the device verifies against the trust bundle;
*   the device's own state, read in the browser from the same-origin device worker (tenancy, held bundle, journal range), and labelled as the device's own view.

There is no `POST /demo/confirm` store: a record that the device reports to the collector stand-in's server is a demo-only path and proves nothing. Each confirmation has a "check it" link to the place where the same value exists independently (the log, the factory portal, the CLI output).

**Who performs each step in production, and in the demo.**

| Step | Who performs it in production | Binary, command or page in the demo | What the confirmation shows, and where it comes from |
|---|---|---|---|
| 1 Compile the survey | The survey author, and CI for publishers: `fieldseal survey check`, then `instrument compile` and `layout` commands | Presenter shows `fieldseal survey check <dir>` output; the Instruments page (`/instruments/{id}`) shows the same compile | Instrument address, layout addresses, languages, finding counts. Computed locally by the same core (`catalogue::load`, `panels.rs`), not by a service; the panel says so, and the CLI output is the cross-check |
| 2 Publish to the factory | The publishers, two of three threshold signatures: `artefact provenance`, `artefact sign`, `artefact publish` to the transparency log and the artefact registry. The factory has no publish endpoint; it builds only from what is published (DIS-011) | Presenter runs `just publish <survey>` (the same commands, printed) against `fieldseal-translog`; the Publishing page reads the log through `/proxy/log` | Log index, signatures against the threshold, inclusion verdict. From the log's checkpoint and entries, verified in the app with the trust bundle (WEB-141) |
| 3 Register a device | A signed-in collector at the factory portal issues a token; the device sends a sealed request (`POST /v1/registrations`); the collector confirms the four words (REG-021); the factory registers it and the device fetches its certificate (`GET /v1/certificate`) | Factory portal on `localhost:8080` (sign-in at the development IdP in `just web`, at Keycloak in the stack); Device page registers through `/proxy/factory`. To run the demo again, the presenter retires the old device on the factory portal (REG-043) and registers a new one (§7.4) | Tenancy id and state `registered`, from `GET /v1/registrations/{tenancy}`; the "unattested software" label (REG-017 allowance, shown as a development adapter) |
| 4 Load a published artefact | The factory builds the bundle after registration from the published artefacts and the issued roster (`BuildBundle`, §7.3); the device fetches it with `GET /v1/bundle` and a PoP token, verifies it in DIS-030 order, including log inclusion, and imports it. The portal serves the same file for an air-gapped device | No operator step. The Device page polls registration, then "Get my bundle" calls the factory route through the proxy | Bundle sequence and file name from the factory's response; the device's verification steps (signature, inclusion, schema); the log index of the artefact, cross-checked against step 2; the factory's `bundle-built` event as the independent source, read from the factory's output (`deploy/local/.state/dev-web/logs/factory.log` under `just web`, `tools/stack-compose.sh logs factory` in the stack), with the command shown beside the confirmation |
| 5 Manage rosters | The operator, with `fieldseal roster check`, `roster issue`, `roster diff` and `roster assign` (§7.4); `issue` and `assign` are factory operations behind an operator sign-in. The factory journals the new roster version and builds bundle sequence + 1 (DIS-014, DIS-015, DIS-082), which the device fetches | Presenter runs `roster check` and `roster diff village-a@3 examples/rosters/next/village-a.yaml --store <dir>`, then `roster issue --factory-url <url> examples/rosters/next/village-a.yaml` (the file is version 4, one above the stored version 3; the sign-in completes at once under the development IdP and is a passkey touch in the stack); the Device page "Get my bundle" fetches the new sequence. The roster page shows counts only, never subjects | Cohort, version, subject count and consent counts of the roster in the bundle the device holds after the issue (a new sequence), and "fields the instrument does not read are dropped before sealing (DIS-013)"; from the device's imported bundle, cross-checked with `roster list` output |
| 6 Conduct the survey | The field collector, on the native app | Device page (the WebAssembly device, standing in for the app) | Record count and sequence range, from the device's own journal, labelled as the device's view; step 7 confirms them with signed receipts |
| 7 Upload the device export | The runtime exports and uploads in the background to the intake upload endpoint (`POST /v1/challenge`, `POST /v1/upload`); intake runs the gate and returns receipts | Device page "Export and upload" (the device export) through `/proxy/upload` to `fieldseal-intake` on `:8480` | Device export file name and SHA-256 (from the device); receipt ids and covered sequence range, signed by intake's receipt key and verified in the browser against the trust bundle (DEL-007, DEL-064) |
| 8 Read the results | An authorised person on the results reader, or the CLI `fieldseal intake results`; with a lakehouse landing, the lakehouse tools | The intake app's portal on `localhost:8481`, signed in as `presenter`; the stepper shows only a link | The stepper confirms nothing here, because it has no access. The results reader shows the row count, the manifest digest and `export_schema_version` from the landing and the shared results export writer |

The last step names `just acceptance` (every walkthrough step run headless against a fresh stack) and `just release` (release images and signed release record) as the way to check the production path. The WebAssembly device cannot run in production (WEB-190), so the audience is told which parts of the demo are the production components (everything except the collector stand-in) and which stand in for the Android app.

**Tests.** (1) An end-to-end test, in the browser harness of `tools/browser-tests` against a native `just web` stack, runs the CLI commands for steps 2 and 5, drives steps 3, 4, 6 and 7 on the Device page, signs in to the results reader for step 8, and asserts that each confirmation carries its identifiers and that each identifier also appears at its independent source (the log, the factory status, the receipts, the results reader). (2) A test that the stepper's server code holds no credential and makes no non-`GET` request to a service. (3) The accessibility script (`just a11y <url>`, `tools/browser-tests/wcag.sh`) runs on `/demo` and `/demo/1..8`. `docs/reference/spec/web-app.md` changes with this design: WEB-100 and WEB-180 (the Intake destination moves to the intake app; the app keeps Instruments, Publishing, Registration and Device), WEB-150 to WEB-155 (the "demo authority" requirements are replaced by requirements that the app is served against the real factory, log and upload endpoint and holds no authority), WEB-160 to WEB-162 (moved to the results reader) and new ids for the stepper and the banner. ADR 0036 gets a short note that the collector stand-in hosts no authority.

### 10. Demo fidelity rule and security invariants

#### 10.1 Demo fidelity rule

The project owner's rule is:

> While we are working on a demo, we shall not take shortcuts which overfit to the demo. In all cases the end product must conform to the architectural requirements. The demo must represent what production would actually do, functionally correct.

In this design the rule means:

*   The demo uses the same binaries, ports, protocols and flows as production: `fieldseal-factory`, `fieldseal-translog`, `fieldseal-intake` and `fieldseal` run natively in `just web` and in containers in the stack, configured by the same rendered environment (DEP-012). The routes are the production routes (`/v1/registrations`, `/v1/bundle`, `/v1/upload`). The sign-in is the production sign-in.
*   Only adapters behind ports differ, and only these:

| Development adapter or tool | Port | Where | How production refuses it |
|---|---|---|---|
| `FIELDSEAL_IDENTITY=dev` / `memory-dev` | `IdentityProvider` | factory (tests only after Phase 11); intake (Phase 10 only, for `just web`) | start-up check (exists for the factory, new for the intake app); `deployment validate` (DEP-023). Not used by `just web` or the stack after Phase 11 |
| development IdP `fieldseal-dev-idp` (a tool, not an adapter) | the external identity provider | `just web` | exits `2` without `--development-tool` or outside `development`; in no image, compose file or manifest (§7.5) |
| `file-dev`, `memory-dev` custody | `KeyCustody`, `Signer`, `RecordKeyUnsealer` | factory, intake | start-up check; DEP-023 |
| file registry journal (`FIELDSEAL_STATE_DIR`), `file-dev` tenancy registry | `RegistryStore`, `TenancyRegistry` | factory, intake | start-up check; DEP-023 |
| file artefact registry (`FIELDSEAL_FACTORY_REGISTRY_DIR`), file roster store (`FIELDSEAL_ROSTER_DIR`), file bundle store (`FIELDSEAL_BUNDLE_DIR`), file runtime profiles | `ArtefactRegistry`, `RosterSource`, `BundleStore`, `RuntimeProfiles` | factory | start-up check (new) |
| file submission store, roster history, published-instrument reader | `SubmissionStore`, `RosterHistory`, `InstrumentSource` | intake | start-up check (new); `deployment validate`, because the manifest names them `file-dev` (DEP-023) |
| export pseudonymisation key file | export pseudonymisation key (§6) | intake | start-up check (new) |
| software attestation, `FIELDSEAL_ALLOW_UNATTESTED` | `AttestationVerifier`, release policy | factory | start-up check (exists); REG-017 |
| web platform profile (WebAssembly device) | the device's platform ports | `fieldseal-web` | WEB-190 (exists) |
| practice authority | the whole intake authority | `fieldseal-upload-practice` | refuses `production`; in no image or manifest (§7.1) |

*   Each is labelled. A service writes one `development-adapters` event at start listing every port bound to one of these (no personal data, DEP-051); `fieldseal deployment validate` lists the same set for a manifest; `tools/dev-web.sh` and the stack scripts print it.
*   A test or check lists the development adapters in use and fails on a difference: `tools/dev-web.sh --check` and `tools/stack-smoke.sh` read each service's `development-adapters` event and compare it with the set the rendered manifest declares as development; an adapter in use that the manifest does not declare fails the check. One refusal test per adapter and per service starts it with `FIELDSEAL_ENVIRONMENT=production` and asserts exit `2`.
*   These shortcuts are not used, because they overfit to the demo: the in-memory `web-demo` authority, the `--role authority` process in `fieldseal-web`, the provisioning-file handoff between the two, the per-run bearer token, `GET /device/bundle` that spawns the CLI, `POST /demo/confirm`, auto-publication on edit, and the seed-derived keys of `--authority demo`.

`landing-files` is not a development adapter. Its README does not mark it as one, and the deployment context's `DEVELOPMENT_ADAPTERS` list (`crates/contexts/deployment/src/validate.rs`: `memory`, `memory-dev`, `file-dev`, `software`, `dev` and `web`) does not include it, so it stays out of that list and out of the intake app's start-up refusal. The file stores for submissions, roster history and published instruments are bound under the name `file-dev`, which the list already includes, so `deployment validate` and the start-up check both refuse them in production.

#### 10.2 Security and privacy invariants

Unchanged: signing, threshold publication, sealing, attestation and fail-closed policy defaults. The only change to `crates/kernel` is the new pure `schema` module (§2); no existing kernel code changes, and nothing in this design edits the trust, publishing or delivery contexts, or changes any existing default in `crates/contexts/policy/src/domain/schema.rs`. The changes inside the Intake, Deployment, Registration and Policy contexts are the ones listed at the start of the Technical Plan.

| Invariant | What could affect it here | Proof |
|---|---|---|
| What a reviewer reads is what is signed | decoder rewrite, folder resolver, layout ids, `.po` rewrite | golden addresses, fingerprints and expanded documents unchanged across both commits (§2, §5); differential test (§2) |
| Layout fingerprints and addresses unchanged | authored ids and renamed files | ids are dropped before signing; the bound-address gate (§5) |
| Sealing and the record key stay with the authority | intake app, results reader, bundle route | the five controls of §7.2, including the bundle test in `crates/apps/security-tests`; the bundle route returns only bytes sealed to the tenancy's agreement key (§7.3) |
| Only an authorised, signed-in person reads results | the results reader | OIDC session, role check, CSRF, phishing-resistant method by default; tests in §7.2 |
| Development adapters never reach production | file stores, file custody in more services; the development IdP | the Demo fidelity rule table above: start-up refusal per adapter, one test each; ADR 0038: assurance `development`, development root absent from production bundles (TRU-034) |
| Attestation and `UnattestedKeys::AllowNonProduction` stay non-production | the stack runs real binaries with the allowance | the factory configuration is unchanged; `FIELDSEAL_ALLOW_UNATTESTED` is listed at start-up and refused in production; the existing registration tests |
| Fail-closed policy defaults | none intended | a snapshot test of the policy control defaults table is added so any later change shows in review; the existing policy tests pass unchanged |
| Publication stays fail-closed on bad content | resolver | a survey with an error is not published; the collector stand-in keeps the last good view and shows the error |
| The factory builds only for eligible tenancies, and a failed build keeps the previous bundle | the reconciler runs outside request handling with the `factory` key | eligibility checked at build (`check_state`) and at fetch; tests for a lost, retired and flagged tenancy and for a build that fails on an unpublished artefact; security review SR-3 (Non-Functional Requirements) |
| Only an operator signed in with a phishing-resistant method can issue a roster or assign a cohort, and every such change is journaled | the Bearer access-token verification on `/v1/assignments` and `/v1/rosters`, the development IdP (`crates/apps/dev-idp`), the loopback listener in the CLI | signature, issuer, factory-API audience, `typ`, absence of `nonce`, client, expiry, `operator` role and phishing-resistant method checked per request; no token stored; refusals of unknown survey and cohort; journal records with who, when and what; tests for each refusal, for a collector-role account, for an ID token (including one from `fieldseal-cli` that carries the API audience) and a portal-client token presented as Bearer, and for `fieldseal-dev-idp` exiting `2` without `--development-tool` or in `production`; security review SR-4 (Non-Functional Requirements) |
| A tenancy receives only the cohorts of its own account | assignments, certificate reissue, the reconciler | an assignment names one account; a tenancy's roster and certificate carry only that account's cohorts; a test with two accounts asserts that neither bundle holds the other's cohort; privacy risk recorded under Risks & Mitigations |
| A submission that was accepted is never dropped without a trace | start-up replay | a failed replay stops start-up and fails `/readyz` (§6) |
| A stored bundle always has a digest that matches its inputs | the reconciler's write order | the digest is written last, through the atomic-write helper; a crash-injection test stops the factory after each write step |
| Roster plaintext stays in the roster store, the factory and sealed bundles | the roster store, `roster` commands, the portal download | store is a restricted-permission file store (development adapter); commands print counts only unless `--reveal` (CLI-008); web pages show counts only; the portal download serves the sealed file for the account's own device (tested with another account's device) |
| A withheld device gets no bundle | the new fetch route | eligibility checked at fetch (`check_state`, DIS-003); a test for each non-eligible tenancy state (§7.3) |
| Personal data in the results export | new files outside Fieldseal's protection | consent-excluded rows omitted (tested); subject ids are keyed hashes, and no roster id appears in readable or hex form (tested); free text in its own file; special-category items marked in the contract; the unprotected-data statement on save |
| Spreadsheet formula injection | respondents' free text in CSV files | the CSV guard always applies to text columns and has no switch; numeric columns are never guarded, so `-5` stays `-5` (tested); free text is in a separate file |
| New ports and routes | intake portal listener; `GET /v1/bundle` | portal on loopback by default and behind sign-in; no route returns key material; the bundle route needs a PoP token and is security-reviewed |

The existing security tests (`crates/apps/security-tests`), conformance suites (`fieldseal conformance run`), and `just test` pass unchanged; the migration gate (§5) and the tests named above are added to the same run.

## Alternatives Considered

Each title names the workstream: Authoring (workstream 1), Export (workstream 2), Dev loop (workstream 3), Services (the production services and the demo of workstream 4) or Scope (the whole document).

### Alternative 1 (Authoring): Merge survey files by content, in this design or later

*   **Pros**: Terraform-style merging lets an author split a survey across any number of files. Shipping the folder convention first would let merging follow if surveys outgrow it.
*   **Cons**: Nothing says which file wins on a repeated key or how order is set, and file order could change question order and so the signed hash. If any file may hold any key, the author still cannot tell where a setting lives. Deferring merging adds an unscheduled second feature, and the examples are 170 to 260 lines each, so there is no present need.
*   **Reason for Rejection**: The authoring adapter promises that what a reviewer reads is what is signed (`crates/adapters/authoring/src/lib.rs`). A fixed folder shape gives each setting one home file and changes nothing signed (§1; Non-Goals). Merging waits for a defined precedence rule.

### Alternative 2 (Authoring): Translation keys as short symbolic ids (ADR 0039)

*   **Pros**: Short ids do not change when the English text changes.
*   **Cons**: Translators see an id, not the sentence, and a changed English text gives no sign that a translation is out of date.
*   **Reason for Rejection**: English `msgid` plus a stable `msgctxt` lets `survey check` detect stale entries (§3). The new design record supersedes ADR 0039.

### Alternative 3 (Authoring): Keep XLIFF as a converter and deprecate it later

*   **Pros**: Existing XLIFF users would see no break.
*   **Cons**: Nothing in the repository shows users of the XLIFF pipeline. It keeps two translation code paths in `crates/apps/cli/src/i18n_cmd.rs`, and the spec is normative, so a deprecation period means keeping the spec text too.
*   **Reason for Rejection**: One format, and the XLIFF code and its spec rows go in one change (§3).

### Alternative 4 (Authoring): Hand-written JSON Schema with a differential test

*   **Pros**: No change to the existing decoder; the schema can ship first.
*   **Cons**: The schema and the 1,250 lines in `crates/adapters/authoring/src/compact.rs` are two sources that a test must keep equal.
*   **Reason for Rejection**: A declarative table that the decoder and the generated schema both read leaves nothing to drift, and the decoder rewrite lands in its own gated commit (§2).

### Alternative 5 (Authoring): Typed serde structs with schemars

*   **Pros**: The schema comes from the types with little code.
*   **Cons**: It adds dependencies and replaces the `Value`-tree decoding that `expand_with` and the spans table use, which is a larger rewrite on the signed path.
*   **Reason for Rejection**: The declarative module keeps the `Value` decoding, and the golden-set gate covers the change (§2).

### Alternative 6 (Authoring): A guided survey-builder UI

*   **Pros**: It would help authors who do not use a text editor.
*   **Cons**: It is a separate product, and the scaffold, schema and `survey check` are needed first.
*   **Reason for Rejection**: Deferred (Non-Goals). It would build on the folder format and the schema of §1 and §2.

### Alternative 7 (Authoring): Stale translations applied with a warning, or expansion refused

*   **Pros**: Applying with a warning keeps text in every language; refusing forces a fix.
*   **Cons**: Applying shows a translation of old wording to respondents. Refusing blocks a publication over a text that has an English fallback.
*   **Reason for Rejection**: A stale entry is treated as missing, as `msgfmt` treats fuzzy entries, and `survey check` lists it (§3).

### Alternative 8 (Export): Subject ids in the results export: warn only, or leave as they are

*   **Pros**: No key to manage; rows keep a readable roster id.
*   **Cons**: In the demo, `subject` is the hex of the roster id, so anyone can decode it to text such as `hh-0001`. A warning does not change what the file holds. Even without that decoding, `subject_id` is pseudonymous (DIS-013, INT-060) but stable across every results export, so anyone holding two exports, or an export and a roster, can link the same person.
*   **Reason for Rejection**: The results export replaces `subject` with a keyed hash under the authority's export pseudonymisation key (§6). A keyed hash per authority prevents that linking: exports from different authorities cannot be joined, and a holder of a roster cannot recompute the pseudonyms without the key.

### Alternative 9 (Authoring): Rosters name their survey

*   **Pros**: The link from a roster to its survey would be in the file.
*   **Cons**: A cohort can serve several surveys, so the roster would be copied once per survey, and each copy holds personal data.
*   **Reason for Rejection**: The survey-to-cohort assignment is factory state (§1, §7.4).

### Alternative 10 (Export): Parquet in this design, always built or behind a feature

*   **Pros**: A typed columnar file loads straight into a lakehouse.
*   **Cons**: The `arrow` and `parquet` crates would likely cost more compile time than the rest of the workspace (not measured), and a separate crate still builds under `cargo build --workspace` unless a feature is off. Reader support for newer Parquet column types is uneven.
*   **Reason for Rejection**: Deferred (Non-Goals; Future Improvements). JSON Lines and CSV use the existing writers, and DuckDB converts them (§6).

### Alternative 11 (Export): Decimals as JSON numbers, or one fixed precision and scale

*   **Pros**: JSON numbers need no parsing; a fixed Parquet decimal has a single schema.
*   **Cons**: A JSON number can lose precision as a float. Money's scale depends on the currency and other decimals are rounded to 9 places, so one fixed precision needs an overflow rule.
*   **Reason for Rejection**: `value_number` is canonical decimal text, exact as landed, and consumers cast it (§6).

### Alternative 12 (Export): One text `value` column plus `value_type` everywhere

*   **Pros**: One column, no per-type rules, and it is what the CSV has today.
*   **Cons**: Tools must parse every value, and a multi-choice answer is a `|`-joined string that cannot be split without being told.
*   **Reason for Rejection**: JSON Lines has typed columns, including a real list for `value_codes`. CSV keeps `value` and `value_type` for spreadsheet users (§6).

### Alternative 13 (Export): A wide export, or both shapes

*   **Pros**: One row per response is what some analysts expect.
*   **Cons**: The column set changes whenever the survey changes, so tables built on it break.
*   **Reason for Rejection**: Long only; analysts pivot it themselves (§6; Non-Goals).

### Alternative 14 (Export): Everything flagged, or a minimal export by default

*   **Pros**: Everything flagged keeps all rows for the analyst to filter; minimal is the safest file.
*   **Cons**: Flagged rows put consent-excluded data into an open file. A minimal file fails the stated need of loading results into analysis tools.
*   **Reason for Rejection**: The default is analysis-ready: excluded rows are omitted and counted in the manifest (§6).

### Alternative 15 (Export): Free text inline with a warning, or omitted by default

*   **Pros**: Inline keeps one file; omission leaves the riskiest column out of the table.
*   **Cons**: Inline means every copy of the main table carries the personal-data risk of free text. Omitting it loses the "other" answers that analysts need.
*   **Reason for Rejection**: Free text goes to its own files, joinable on `record_id` and `item_path` (§6).

### Alternative 16 (Export): A separate codebook source and a "provenance record"

*   **Pros**: A hand-written codebook could carry more prose.
*   **Cons**: The codebook would duplicate the data contract, which holds every item and code label in each language. Intake stores no receipts or log indexes, a file cannot contain its own digest, and "provenance" already means something in `crates/contexts/publishing`.
*   **Reason for Rejection**: A codebook view rendered from the contract and a `manifest.json` of file digests replace both (§6).

### Alternative 17 (Export): A results reader that lists instruments by reading `*.published` files

*   **Pros**: It needs no change to the `DataPlatform` port.
*   **Cons**: It ties the results reader to a file adapter, so a results reader running over a production landing would not work, which breaks the Demo fidelity rule.
*   **Reason for Rejection**: `DataPlatform::instruments()` is an additive method that each adapter implements (§6). The CLI's `intake results --landing` also reads through the landing-files `DataPlatform` adapter, not by parsing `observations.csv` itself, so it has no torn reads and stays consistent with the results reader.

### Alternative 18 (Services): How the demo authority is composed

*   **Pros**: A single-process authority (`FIELDSEAL_WEB_DEMO_AUTHORITY=true`) needs one command and no services. A second run mode of `fieldseal-web` or a new authority app crate keeps the authority in one place. Moving only intake and the results reader is smaller. Keeping `crates/adapters/web-demo` permanently as a test-only crate gives tests a fast in-memory authority.
*   **Cons**: Each option leaves something that production does not run. One process gives no separation of roles and replaces the factory, the upload endpoint, the gate and the results table with an in-memory stand-in. A run mode in `fieldseal-web` adds a dev-only mode and keeps authority state next to the collector stand-in. A new authority crate is a composition root that production does not have. Moving only two parts leaves the factory and log faked. A permanent `web-demo` is a second authority implementation that drifts from the real services.
*   **Reason for Rejection**: The Demo fidelity rule (§10.1). The demo runs the production binaries plus one new app, `crates/apps/intake`, promoted from the development upload server. `web-demo` is test-only until the parity tests run against the real services, then deleted (§7.1, §8).

### Alternative 19 (Services): The results reader in the factory app, or CLI only

*   **Pros**: The factory already has the portal and sign-in; a CLI-only results reader needs no web page.
*   **Cons**: The intake record key would live in the factory, which mixes two roles. CLI only gives the audience no page to look at.
*   **Reason for Rejection**: The results reader is a page of the intake app, and the CLI verb opens the same results export (§7.2).

### Alternative 20 (Services): Authentication: results reader access, the operator CLI and the API credential

*   **Pros**: For results reader access, a per-run bearer token or a loopback-only listener is simple, and Keycloak is the stack's provider. For the operator CLI, a portal-issued token or a portal assignment page needs no loopback listener in the CLI. For the API credential, the adapter already verifies ID tokens.
*   **Cons**: Loopback is not a boundary between local processes, a bearer token exists only in the demo, and Keycloak cannot run natively (passkeys need `localhost:8180`). A portal-issued token is a credential type only Fieldseal has, and in the Keycloak stack it can be obtained only through the browser harness; a portal assignment page cannot be scripted. An ID token says who signed in to a client, not what the client may call, and its audience is the client, so a token for the portal would be accepted on the API.
*   **Reason for Rejection**: Reader access uses OIDC sign-in, session, CSRF and role check as the factory portal does, with the development IdP in `just web` (§7.2). The CLI uses authorization code with PKCE on a loopback redirect (RFC 8252) and sends a JWT access token whose audience is the factory API, with no token stored (§7.5).

### Alternative 21 (Services): Bundle delivery by download and file pick, a dev-only shared folder, or an out-of-band file by design

*   **Pros**: Each works without a new factory route.
*   **Cons**: None is a delivery path that production has. DIS-040 says a runtime fetches its bundle with a proof-of-possession token, and `crates/adapters/factory-http` has no such route.
*   **Reason for Rejection**: A designed `GET /v1/bundle` and a specified portal download serve the stored bundle (§7.3).

### Alternative 22 (Services): An operator command builds bundles (`bundle build --stack`)

*   **Pros**: It already exists and needs no factory change.
*   **Cons**: DIS §3 says the factory builds bundles on registration and on change. The command is a delivery path production does not have.
*   **Reason for Rejection**: The factory builds, and the `--stack` variant is removed. The generic `bundle build` stays for offline routes (§7.3).

### Alternative 23 (Services): Roster management as a state-only display, or a portal roster page

*   **Pros**: A page is easy for a presenter to show.
*   **Cons**: A page puts personal data on the web, and a state-only display gives no way to issue or change a roster.
*   **Reason for Rejection**: A `fieldseal roster` command group; web pages show counts only (§7.4; Non-Goals).

### Alternative 24 (Services): Survey-to-cohort assignments in the deployment manifest, in `assignments.yaml`, in manifest seeds, or in a development file adapter that the reconciler polls

*   **Pros**: A file is reviewable and needs no new operation or authentication path. A development file adapter behind an `AssignmentSource` port would be polled by the reconciler, which already re-reads files every few seconds, so a change would need no restart.
*   **Cons**: A manifest or `assignments.yaml` change needs a restart, is not journaled, and mixes operational state with per-environment configuration (ADR 0040 section 4). A development file adapter answers the restart objection but not the main one: production refuses development adapters, so production would have no mechanism at all for assigning a survey to a cohort, and the demo would run a mechanism that production does not have.
*   **Reason for Rejection**: Assignments are tenancy registry state with an operator API (§7.4). The Demo fidelity rule (§10.1) is that the demo runs the production mechanism. Development adapters may stand in for external systems behind ports, not for missing product features, and a missing assignment mechanism is a missing product feature.

### Alternative 25 (Services): Development IdP routes inside the factory, or `FIELDSEAL_IDENTITY=dev` in place of a development IdP

*   **Pros**: Routes inside the factory add no extra process in `just web`. `FIELDSEAL_IDENTITY=dev` already exists, production already refuses it, and `MemoryIdentityProvider` carries several people with roles, so it needs no new crate.
*   **Cons**: Routes inside the factory mean production would ship identity-provider code that only a configuration check keeps switched off. The in-memory identity provider signs people in for the portal but cannot issue the OIDC access token that the CLI's loopback sign-in sends to the factory API (§7.5). Using one identity mechanism for the portal and another for the CLI would make the demo's sign-in differ from production's, which breaks the Demo fidelity rule.
*   **Reason for Rejection**: A separate app, `crates/apps/dev-idp` (`fieldseal-dev-idp`), in no image and refused outside development, so the portal, the results reader and the CLI all use the production `oidc` adapter (§7.5). `FIELDSEAL_IDENTITY=dev` stays for the factory's own tests.

### Alternative 26 (Services): Reader role: reuse `operator`, or a policy decision point

*   **Pros**: `operator` exists; a decision point is the general form.
*   **Cons**: Operators would gain access to decrypted results they may not need. A policy decision point needs policy-engine work in this design.
*   **Reason for Rejection**: A configured `results-reader` role with no Registration context change (§7.2).

### Alternative 27 (Services): `FileDataPlatform` reloads its files at start

*   **Pros**: A small change that restores landed rows after a restart.
*   **Cons**: Start-up replay already restores landed state, and also envelopes, evidence and consent cases, which a file reload could not.
*   **Reason for Rejection**: Start-up replay (INT-013a) already restores landed state, so a file reload is not needed (§6).

### Alternative 28 (Dev loop): Native Keycloak

*   **Pros**: One identity provider in every path.
*   **Cons**: Passkeys need Keycloak at `localhost:8180`, which needs its container.
*   **Reason for Rejection**: The development IdP replaces Keycloak in `just web`, and the passkey flow stays in `just up` (§7.5, §8; Non-Goals).

### Alternative 29 (Dev loop): Live reload in the demo

*   **Pros**: The presenter could edit a survey during the demo.
*   **Cons**: It would need publishing on every edit, a demo-only path, and the demo would depend on file watching.
*   **Reason for Rejection**: The demo uses the bundled examples. Reload applies to the Instruments page in `just web` only (§8; Non-Goals).

### Alternative 30 (Scope): One design per workstream, or authoring first

*   **Pros**: Smaller documents that review and land separately. The dependency runs one way: the production services and the demo (Phases 7 to 18) need the authoring and results export work (Phases 0a to 6), and that work needs nothing from them.
*   **Cons**: Two documents mean two reviews, two sets of cross-links and an approval in two parts. The demo depends on the results table, the intake app and the factory changes, so the second document would still have to track those cross-dependencies.
*   **Reason for Rejection**: One document. The project owner reviews and approves the design as a whole, and Phases 0a to 6 can already ship and be used before Phase 7 starts, so splitting the document buys no earlier delivery.

### Alternative 31 (Services): Assignments that apply to all tenancies

*   **Pros**: One record per survey and cohort, no account to name, and the demo needs one `roster assign` call with no account.
*   **Cons**: The default cohort limit (`maxActiveTenanciesPerCohort = 1`, REG-041) would give a bundle to the first device of each cohort only, because every device would hold every cohort and `cohort-tenancy-limit` would hold the rest. DIS-014 makes the generation a property of a cohort on one tenancy, so one generation per cohort across all tenancies cannot express succession (REG-045, DIS-051). Every device would receive every cohort's roster, including display fields and consent, which contradicts data minimisation (DIS-013).
*   **Reason for Rejection**: An assignment targets one account, and the generation is kept per cohort and tenancy (§7.4). The limit stays at its default of 1 in production.

--------------------------------------------------------------------------------

## Risks & Mitigations

| Risk | Likelihood / impact | Mitigation | Phase |
|---|---|---|---|
| `tools/check-architecture.py` rejects the CLI's build-dependency on the authoring adapter (§1) | Low / low | The check is extended in the same commit; the edge goes from an app to an adapter, which the layer rules allow | 4 |
| Keycloak does not behave as the operator sign-in assumes (§7.5). Items to confirm: the loopback redirect URI is matched on any port; the access token carries `acr` at the passkey level; there is no default `amr` (the check then rests on `acr`, as the factory portal's does with `acrValues: phr`, and `amr` is used only if a mapper adds it); the `client_id` claim is present or `azp` can stand in; the header `typ` is `JWT` (hence `FIELDSEAL_OIDC_ACCEPT_TYP_JWT`) or `at+jwt` if the realm option for it is turned on | Medium / medium | Each item is confirmed against the realm at implementation and recorded in the Phase 12 commit message; `FIELDSEAL_OIDC_ACCEPT_TYP_JWT` covers a `JWT` header; a realm test covers the audience mapper | 12 |
| `fieldseal deployment render` is removed (ADR 0040 section 4, still open), and `tools/dev-web.sh` and the stack scripts depend on it (§8) | Low / medium | The plan assumes the command stays. If it is removed, the render step moves into the scripts and the manifest stays the source of the environment | 5b, 10 to 13 |
| The development IdP diverges from Keycloak in claims, headers or redirect handling (§7.5) | Medium / medium | Both are used through the same `oidc` adapter; the development IdP copies Keycloak's paths and claim names; `just acceptance` runs the same flows against Keycloak | 11, 12 |
| Start-up replay validates against changed inputs, because the published, roster or tenancy directories differ from those at landing (§6) | Low / high | A failed replay stops start-up and fails `/readyz` (§6); replay treats the published directory as append-only | 10 |
| The reconciler polls the artefact registry directory every 5 s in development (§7.3) | Low / low | Only publications are polled; assignments, roster issues and registrations are in-process events; idle CPU is sampled and a production adapter would use events | 13 |
| No production adapter exists for the ports in the development-adapter table (§10.1; Future Improvements) | Certain today / high for production use | The factory and the intake app refuse to start in production until production adapters exist; the design does not claim production readiness | 10, 13 |
| Privacy of assignments: an assignment sends a cohort's roster (display fields and consent states) to every device that the target account registers. A wrong account, or an account with several devices, receives personal data it need not hold (§7.4) | Medium / high | Assignments target one account, not all tenancies; the bundle carries only the fields the instrument reads (DIS-013) and is sealed to the device key; the cohort limit holds a second active tenancy (`cohort-tenancy-limit`); every assignment is journaled with who, when and what, and `roster assign --list` shows it; a test with two accounts asserts that neither receives the other's cohort | 12, 13 |
| Succession is not built, so a cohort cannot move to another tenancy through assignments (REG-045, DIS-051) | Medium / medium | Out of scope and stated as such; succession is a Future Improvement | 12 |
| A realm change never reaches an existing `keycloak-data` volume, because `--import-realm` skips a realm that already exists (Phases 10 and 12 change the realm) | High / medium | `tools/stack-up.sh` records the SHA-256 of the realm JSON in `deploy/local/.state/realm.sha256`, refuses to start when it differs (or when a volume exists with no record) and prints "the Keycloak realm changed; run `just purge`"; `just purge` removes the record; the Phase 10 and Phase 12 gates run `just purge` first | 10, 12 |
| The presenter forgets to retire the old device before registering again, so the new tenancy is held by the cohort limit (§7.4) | Medium / low | The guided demo names the retire step; the factory portal shows the hold reason | 17 |

--------------------------------------------------------------------------------

## Non-Functional Requirements

Only the requirements that carry risk for this design are listed.

### Security & Privacy

*   **Security reviews.** Five reviews are required (SR-1 to SR-5), and each blocks the merge of the phase named. No other phase changes signing, threshold publication, sealing, attestation or a fail-closed policy default; a snapshot test of the policy control defaults table is added in Phase 13 so a later change shows in review.
    *   SR-1 (Phase 8; the registration reviewer signs off before Phase 8 merges): the registration request carries the runtime profile inside the proof-of-possession body. Points: strict decode, a changed profile breaks the proof, the factory records only what was signed, a downgrade cannot widen what a tenancy receives.
    *   SR-2 (Phase 13; the delivery reviewer): the `GET /v1/bundle` and portal download routes, which return sealed bytes that carry personal data. Points: the PoP binding excludes the query and a rewritten `held` is equivalent to a dropped response, eligibility is checked at fetch as well as at build, the `jti` ledger is shared with the other PoP routes, a withheld tenancy can still upload.
    *   SR-3 (Phase 13; the key-custody reviewer): the factory as a builder, including its layout and profile selection. It reads publications and roster plaintext and uses its `factory` signing key on a timer. Points: roster and custody directory permissions, no build for an ineligible tenancy, a failed build never replaces a stored bundle, the write order (issued rosters, bundle, digest) under a crash, the anchor freshness rebuild, no subject data in events, `bundle.release` still gating roster release. SR-3 follow-ups from the Phase 8 review (SR-1 Minors 1 and 2): wire `FileRuntimeProfiles` into the bundle builder, and add the build-level `dis_012_...` test.
    *   SR-4 (the identity reviewer opens it in Phase 11 and signs it off before Phase 12 merges): the Bearer access-token path and the operator operations it protects (`IssueRoster`, `AssignCohort`, `ListAssignments`). Points: `verify_access_token`, the `typ` rule and the payload `typ: Bearer` rule, the `nonce` refusal, the API audience never appearing in an ID token (realm test), the client claim and its `azp` fallback, `acr` and `amr` taken from the access token and from no second source, clock leeway, no token cache, the loopback listener and the development IdP, the roster body as personal data in transit, the journal records, certificate reissue on an assignment change, and that an assignment reaches only the target account's tenancies.
*   SR-5 (Phase 10; the data-protection reviewer): the results reader. Points: the sign-in and callback, the `results-reader` role check on every results route, CSRF on sign-out, the allowlist of snapshot paths (the fixed file list and the 64-digit contract names), that nothing is written to disk and a held mark never changes, the CSV guard, and that the `dev` identity option is refused in production. It blocks the Phase 10 merge.
*   **Export privacy.** Rows excluded for consent or by the custodian never appear in a results export file (INT-086). Exported subject ids are keyed hashes under a per-authority key; no readable or hex roster id appears in any results export file (INT-087). Free text goes to its own file, and the CSV guard always protects text cells. The results reader and the CLI state that exported files are no longer protected by Fieldseal. The export pseudonymisation key is held in a development file store (§10.1); its production custody is outside this design (Future Improvements).
*   **Reader access.** The results reader requires an OIDC session with the `results-reader` role, a phishing-resistant method by default, and the CSRF token on sign-out. The collector stand-in is kept away from it by five controls (Technical Plan §7.2).
*   **Development tools stay out of production.** `fieldseal-dev-idp` and `fieldseal-upload-practice` are in no image, compose file or manifest and refuse to start outside development.

### Performance

*   **Build and compile cost.** No `arrow` or `parquet` crate enters the workspace (Parquet deferral: Non-Goals). No new third-party crate enters a normal build beyond those already in the tree (`hmac` and `sha2` are allowed by `architecture.toml`; `tiny_http`, `ureq`, `p256` and `ring` are reused). `jsonschema` is a dev-dependency only. Phase 0b records the dependency count and a cold `cargo build --workspace --timings`; every phase that adds a crate or a dependency re-measures both, and `cargo tree -i arrow` and `cargo tree -i parquet` must report no match.
*   **Reconciler polling.** The factory re-reads the artefact registry directory every `FIELDSEAL_FACTORY_BUILD_INTERVAL_S` seconds (default 5 in development and 60 elsewhere) only to see publications written by the CLI; assignments, roster issues and registrations are in-process events and need no wait. A tenancy whose input digest is unchanged costs one directory scan and one hash. The idle CPU of the factory over 60 seconds with the interval at 5 is sampled and recorded in Phase 13; no target is set by this design. A production adapter would trigger the same reconciler by event and the poll would go.
*   **`just test` stays within its 20 second nextest budget.** New tests run in process on ephemeral ports with no sleep longer than 100 ms. Tests that need the built services run in the nextest `integration` profile, not in `just test` (Technical Plan §8). `tools/test-budget.sh` is run at the end of every phase and the figure is recorded in the pull request; a phase that would exceed 20 seconds moves its slowest tests behind an opt-in script instead of raising the budget.
*   **`just up` and CI.** Baselines (Phase 0b) and final numbers (Phase 18) are recorded stage by stage; targets come from Open Question 1. The stack's initial assignment step changes `just up` (Technical Plan §8); Phase 12 records the cost.

### Rollout & Rollback

*   **Each phase is one revertible commit, or a small named series.** Phase 1 (two commits), Phase 7 (two) and Phase 10 (two) are series; every commit in a series is green on its own. A phase merges only after its gate passes and its named security review has signed off.
*   **The migration gate.** The golden set of Phase 1 is generated by the old decoder and is never edited by Phases 2 to 4. `just migration-gate` must pass before and after the decoder rewrite (Phase 1) and the folder migration (Phase 4); a revert rehearsal on a throwaway worktree must pass the same gate. The migration commit contains no schema, decoder or resolver change.
*   **Rollback by `git revert` of the phase's commit.** Phases 5, 6, 8, 9 and 11 add code that nothing else calls, and Phase 5b adds a recipe and a script that nothing else uses, so they revert alone. Phase 7 reverts together with its characterisation tests. Phase 8 changes the registration request and the registry journal, so it needs `just purge` of the factory state, and every runtime (the CLI device, the WebAssembly device and the UniFFI binding) must be reverted together with it. Reverting Phase 12 or 13 needs Phase 14 and later reverted first (later phases call the routes); the order is the reverse of the execution order. A stack started before a revert keeps its volumes; `just purge` clears them. The factory journal gains two record kinds in Phase 12 (assignments and roster issues); earlier code may reject them (the decoder is strict), so rolling back across Phase 12 means `just purge` of the factory state in development (no production factory exists: the factory cannot start in production until production adapters exist).
*   **Spec version notes.** The specs are `fieldseal.dev/v1alpha1`, status Draft; requirement ids are never reused or renumbered. Every id this plan names (INS-258 to INS-261, CLI-044 to CLI-046, CLI-048 to CLI-053, CLI-055, INT-085 to INT-092, DIS-080 to DIS-084, REG-046, REG-047, REG-070a, REG-091, REG-092, POL-068, DEP-076, WIRE-198, WIRE-199, WEB-195 to WEB-199) is provisional until the phase's spec change assigns it. ADR 0039 reserves CLI-054, so this plan does not use it. a spec change and the tests that cite it land in the same phase so `tools/test-inventory.py --check` passes. Changes to existing requirements (WIRE-130, WIRE-171, REG-032, REG-054, REG-085, REG-087, DIS-040, DEL-071, DEP-057, INT-013a, PUB-110, CLI-008, CLI-041, the `instrument i18n` rows of `cli.md`, WEB-100, WEB-150 to WEB-162, WEB-180) are listed in the phase that makes them; `docs/reference/spec/README.md` gets no change because the version and status do not change. The bundle format does not change (the build-input digest is kept beside the bundle, not in its manifest). The registration request body changes (WIRE-130 gains `schema` and `catalogue`); it is a signed-content change, reviewed under SR-1, and a registry journal written before Phase 8 is not readable afterwards (development stacks: `just purge`).

--------------------------------------------------------------------------------

## Additional Resources

*   ADRs: [0010 declarative instruments](../explanation/adr/0010-declarative-instruments.md), [0015 bundles sealed per device](../explanation/adr/0015-bundles-sealed-per-device.md), [0017 runtime authentication](../explanation/adr/0017-runtime-authentication.md), [0021 export, upload and receipts](../explanation/adr/0021-export-upload-receipts.md), [0023 generic intake and landing](../explanation/adr/0023-generic-intake-and-landing.md), [0025 twelve-factor deployments](../explanation/adr/0025-twelve-factor-deployments.md), [0027 salted instrument fingerprints](../explanation/adr/0027-salted-instrument-fingerprints.md), [0028 clean architecture](../explanation/adr/0028-clean-architecture.md), [0033 presentation layouts](../explanation/adr/0033-presentation-layouts.md), [0034 internationalisation](../explanation/adr/0034-internationalisation-and-localisation.md), [0035 service contracts and transports](../explanation/adr/0035-service-contracts-and-transports.md), [0036 showcase web app and web device](../explanation/adr/0036-showcase-web-app-and-web-device.md), [0038 authority key custody classes](../explanation/adr/0038-authority-key-custody-classes.md), [0039 authoring language](../explanation/adr/0039-authoring-language-and-developer-experience.md) (Proposed, superseded by the new ADR 0041), [0040 compact declarations](../explanation/adr/0040-compact-declarations-and-twelve-factor-config.md) (Proposed; sections 2 and 3 taken over, sections 4 and 5 left open).
*   Specs: [instrument](../reference/spec/instrument.md) (INS-082 to INS-086, INS-200, INS-207), [CLI](../reference/spec/cli.md) (CLI-005, CLI-008, CLI-022, CLI-041), [registration](../reference/spec/registration.md) (REG-002, REG-017, REG-021, REG-043, REG-045, REG-054, REG-070, REG-081, REG-082, REG-085, REG-087), [distribution](../reference/spec/distribution.md) (DIS-001 to DIS-003, DIS-010 to DIS-017, DIS-020 to DIS-023, DIS-030, DIS-040, DIS-041, DIS-063, DIS-075, DIS-077), [intake](../reference/spec/intake.md) (INT-011, INT-013a, INT-040 to INT-045, INT-055), [delivery](../reference/spec/delivery.md) (DEL-071), [deployment](../reference/spec/deployment.md) (DEP-012, DEP-023, DEP-051, DEP-053, DEP-057), [web app](../reference/spec/web-app.md) (WEB-100 to WEB-192), [wire formats](../reference/spec/wire-formats.md) (WIRE-011, WIRE-170, WIRE-185, WIRE-196, WIRE-209 to WIRE-211).
*   Project docs: `architecture.toml` and `tools/check-architecture.py`; `justfile`; `flake.nix`; `deploy/local/compose.yaml` and `deploy/local/keycloak/fieldseal-realm.json`; `crates/apps/factory/README.md` (template for the intake app's contract); [run the local stack](../how-to/run-the-local-stack.md); [use the web app](../how-to/use-the-web-app.md); [build system](../explanation/build-system.md); [hands-on tutorial](../tutorials/hands-on.md); [authoring audit](../reference/authoring-audit.md); [conformance](../reference/conformance.md); [test inventory](../reference/test-inventory.md).
*   External: RFC 7636 (PKCE), RFC 8252 (OAuth for native apps, loopback redirect), RFC 9068 (JWT profile for access tokens), RFC 2119 and RFC 8174; the GNU gettext PO file format; DuckDB `read_json_auto` and `COPY ... (FORMAT PARQUET)`.

## Future Improvements

*   **A native Parquet writer behind a Cargo feature that is off by default.** DuckDB converts the output until then.
*   **A guided survey-builder UI** over the same schema module and resolver.
*   **Native Android and iOS apps** that replace the collector stand-in; the guided demo then says so.
*   **An event-driven reconciler.** A production tenancy registry, roster store and artefact registry would notify the factory, and the polling interval (`FIELDSEAL_FACTORY_BUILD_INTERVAL_S`) would go.
*   **Production adapters** for the ports that have only development adapters (the table in §10.1). Until they exist the factory and the intake app cannot start in production.
*   **Production custody for the export pseudonymisation key** (a key store with rotation and an audit log), and a decision on whether keys rotate per results export period.
*   **Deployment header unification** (ADR 0040 sections 4 and 5): `apiVersion`/`kind` for deployments against `survey:` for surveys, and where deployment manifests, policies and rosters live.
*   **A one-row-per-response (wide) results export**, if analysts ask for it; today they pivot the long table.
*   **A results-reader policy decision point** instead of a role name, and journaling of custodian `exclude` and `reinstate` calls if a route is ever added for them (INT-013a replay does not restore them).
*   **A token cache for the operator CLI** (a refresh token with `offline_access` and a protected store), if a passkey touch per command proves too slow.
*   **A converter from `.po` to XLIFF** for translators who need it, outside the CLI.
*   **Cohort succession.** An operation that moves a cohort to a successor tenancy at `generation + 1` (REG-045, DIS-051). It would also add a generation rule to `roster assign`: an assignment that would give one tenancy a cohort at two generations is refused with `409 generation-conflict`, which names the cohort and the generation in use and writes nothing. The refusal covers two cases: the same account already holds the cohort, for any survey, at a different generation, or one of the account's tenancies holds it at a different generation. The check and the write run under the tenancy registry's single-writer lock, so two concurrent assignments cannot both pass. Different accounts may hold the same cohort at different generations.

--------------------------------------------------------------------------------

## Detailed Implementation Plan

The work is split into 23 phases (0a, which is done, then 0b, 1 to 5, 5b, 6 to 15, 16a, 16b, 16c, 17 and 18). The numbers are labels, not the order: after Phase 14 the order is 16b, 17, 16a, 16c, 15 and 18, so the demo (Phase 17) waits only for what it uses. Each phase is one revertible commit, or a small named series, and has a gate that must pass before the next phase starts. A phase is ordered after everything it calls, so every phase leaves the tree green.

Order and reasons:

*   Phase 0a (done, commit `a0ffcd8`) replaced the bundled food example, which must never be published, with an original survey before any golden file, baseline or later phase names it. Its entries stay as the record of what that commit changed. Phase 0b then measures, so later phases are judged against numbers.
*   Phases 1 to 4 are the authoring work in the order Resolved Decision 2 requires: the golden set and the decoder rewrite (gate: every example's expanded document and `sha256:` address identical before and after) come before the resolver and translation groundwork, and the folder and `msgctxt` migration (gate: addresses and bound layout fingerprints unchanged, salts pinned, expanded documents diffed, every hard-coded loader moved to the resolver) is a separate commit after them. XLIFF removal (Phase 3) changes no signed byte and sits before the migration so the migration commit carries one catalogue format.
*   Phase 5 (authoring CLI, tutorial, ADR 0041) needs the folder layout. Phase 5b adds the first `just web` straight after it, on the binaries that already exist, with the publish step that the tutorial ends on (`just publish`, and the bundled examples published at start-up), so the dev loop is usable long before the services it will include. Phase 6 (results table and export) is independent of the services and precedes the intake app that serves it.
*   Phases 7 to 9 prepare the services: portal sessions (proved by characterisation tests written first), file adapters together with the runtime profile that registration reports, and the roster commands that need no factory (`check`, `diff`, `list`).
*   Phase 10 builds the intake app and results reader (SR-5). Phases 11 and 12 add the operator authentication path and the operator operations it protects (SR-4): Phase 12 adds `IssueRoster`, `AssignCohort` and `ListAssignments`, gives the factory the artefact registry (read-only) and the roster store (read and write), and makes the stack and `just web` issue the rosters through the factory and assign cohorts, in the order of §8. Phase 13 adds bundle building and delivery (SR-2, SR-3). Phase 14 switches the devices to it and deletes the spawn path. Phases 10 to 13 each add their service to `tools/dev-web.sh`.
*   Phase 16b makes the collector stand-in hold no authority state, so its pages read the real services, and completes `just web` with the development-adapter comparison. Phase 17 adds the stepper on the four-destination navigation that Phase 16b leaves; this is the demo. Phase 16a then moves the web tests onto the real services, Phase 16c deletes `web-demo`, Phase 15 documents the finished loop, and Phase 18 records the final timings.

### Phases

| Phase | Name | Gate (summary) | Security review |
|---|---|---|---|
| 0a | Replace the food example with an original survey (done, commit `a0ffcd8`) | `school-meals-baseline` validates and lints in both languages; goldens regenerated; no reference to the old example remains; the licence check passes and fails on a planted placeholder. | None |
| 0b | Baselines and stage timing | Three `just up` stage tables, CI warm-cache durations and the build-cost and test-suite baselines are recorded. | None |
| 1 | Golden set and declarative schema | `just migration-gate` passes on the old decoder (1a) and on the rewrite (1b) with the golden set unchanged; differential, error-position and invalid-document corpus tests pass, and `fieldseal conformance run --suite strict-schema` covers surveys and layouts. | None |
| 2 | Survey resolver and translation groundwork | Resolver, `.po` and report tests pass; golden set unchanged; the example catalogues have no stale entry. | None |
| 3 | Remove XLIFF | No XLIFF code or spec row remains; `cargo test -p fieldseal-cli`, `fieldseal conformance run` and the inventory check pass. | None |
| 4 | Migration to survey folders | `just migration-gate` (addresses, fingerprints, bound layout addresses, expanded documents equal the untouched golden set), `tools/check-example-paths.py`, revert rehearsal, `just acceptance`. | None |
| 5 | Authoring CLI, tutorial, ADR 0041 | A scaffolded survey passes `survey check`; `schema export` is deterministic; the time from `new survey` to a passing `survey check` is recorded. | None |
| 5b | First `just web` | `just web` runs the log, the factory and the collector stand-in and publishes the bundled examples; `just publish` publishes a new survey and the time to its address is recorded; `tools/dev-web.sh --check` passes the port and edit-and-reload checks. | None |
| 6 | Shared results table and results export | Read-back equivalence, privacy scan and pseudonym tests pass; landing files stay byte-identical. | None |
| 7 | Portal session extraction | Characterisation tests written first pass unchanged after the move; registration attack tests and the WebAssembly device flow pass unchanged. | None |
| 8 | File adapters and runtime profile at registration | Contract suites pass for the file adapters; the registration request carries the profile and a request without it is refused; every runtime builds the new request. | SR-1 signs off before merge |
| 9 | `fieldseal roster` check, diff, list | `roster_cli` tests pass; no subject id is printed without `--reveal`. | None |
| 10 | Intake app and results reader | Production-refusal tests per adapter; restart results export byte-identical; `just up`, stack smoke and `just acceptance` pass. | SR-5 signs off before merge |
| 11 | OIDC access-token verification and development IdP | Every access-token refusal test; the development IdP drives the production OIDC adapter end to end; refusal to run outside development. | SR-4 opens |
| 12 | Roster issue, assignments and certificate reissue | `IssueRoster` and `AssignCohort` tests (journal, per-account assignment, certificate reissue), CLI loopback tests and the Keycloak realm test; the stack and `just web` issue rosters and assign cohorts with `roster issue` and `roster assign` (order as §8). | SR-4 signs off before merge |
| 13 | Factory builds and serves bundles | Bundle route, reconciler (profile, layout, anchor freshness and crash-order rules) and delivery security tests; bundle sequence 1 then 2 in the stack; `just acceptance`. | SR-2 and SR-3 sign off before merge |
| 14 | Device fetches bundle; spawn path removed | `just acceptance` and browser smoke pass; no `bundle build --stack`, `/device/bundle` or `FIELDSEAL_WEB_CLI` remains. | None |
| 16b | Pages served from the real services; complete `just web` | `tools/dev-web.sh --check --browser` passes (development-adapter comparison, edit-and-reload, cookie scoping, no Intake page); `just web` prints the finished summary; `just publish` and `just test` pass. | None |
| 17 | Guided demo stepper | Browser run of the eight steps with every identifier found at its independent source; WCAG 2.2 AA; fidelity check. | None |
| 16a | Web tests on the real services | `just integration` (nextest `integration` profile) passes against the real services, including the stand-in isolation tests; `just test` budget unchanged. | None |
| 16c | Delete `web-demo` | No `web-demo` reference remains; `python3 tools/check-architecture.py`, `just test` and `just integration` pass. | None |
| 15 | Documentation for `just web` | No removed variable is named in the how-to, tutorial, README or index; `just test`. | None |
| 18 | CI timing | Warm-cache timings recorded; `ci.yml` triggers unchanged. | None |

### Target Files to Create/Modify

Files are listed under the phase that changes them, with global numbering. A file changed in several phases appears once per phase. Entry numbers are global and stable.

Routine housekeeping (test-inventory regeneration, `Cargo.lock`, crate README contracts) is one line at the end of each phase instead of separate entries. New requirement ids and test names are provisional until the phase's spec change assigns them; each test name carries the id of the requirement it covers (`tools/test-inventory.py`).

Some entries sit in an earlier or later phase than their number suggests:

| Entries | Phase | Why they are there |
|---|---|---|
| 89, 96, 538, 552, 553 | 1 | Commit 1b: the salt function and its callers, the invalid-document corpus, the `strict-schema` suite and the Nix source set it needs. |
| 548 to 551, 556 | 4 | The school-meals catalogue and the deletion of each old catalogue, and the stand-in's cohort map. |
| 561 | 5 | `collect_roster_fields` made public, for `survey check --roster`. |
| 100, 102, 418 to 425, 501, 533, 534, 554 | 5b | The first `just web`, its publish script, the last-good survey cache and the Publishing page. |
| 546, 547, 555, 559, 560 | 6 | The atomic-write helper and its users, `DataPlatform::instruments` for the upload server, the file adapter's submission test and the `hmac` dependency. |
| 557 | 7 | REG-092, portal sessions and CSRF. |
| 558 | 8 | The registration vector test. |
| 536, 537 | 9 | The next versions of the example rosters. |
| 562, 563 | 9 | The closed-schema roster check as a pure function in the Distribution context, and its tests. |
| 502, 545, 564 to 569 | 10 | `just web` and the authority script gain the intake app; the file-adapter and event-platform tests, the manifest keys, the example manifests, the realm-digest purge and the shared start-up event. |
| 503 | 11 | `just web` switches to the development IdP. |
| 504, 535, 541, 542, 544, 570 to 577 | 12 | The roster and assignment operations: `just web` wiring, Nix source set and tests, the other `RegistryStore` implementations, the file roster issuer, the roster form in `wire-formats.md`, the stand-in's roster source, the example manifests and the factory's manifest. |
| 324 to 327, 505, 539, 540, 578 to 580, 600 to 602 | 13 | The policy control of entries 324 to 327 and its typed access (601, 602) is first used there; the fetch response type, the clock anchor source and the example manifests. |
| 447, 581 to 589 | 14 | The log's entries route, the shared publishing policy, the stand-in's allow-lists and README. Entry 447 deletes `e2e_web.rs`, which calls the route this phase removes. |
| 284, 427 to 430, 491, 506, 543, 590 to 593 | 16b | Completing `just web`: development-adapter checks, the last `dev-web.sh` change, compose, the moved browser-test lines and the stand-in's tests. |
| 594 | 17 | The stepper pages in `wcag.sh`. |
| 595, 596 | 16a | The conformance rows that named the moved device flow test. |
| 597 to 599 | 16c | The last references to the demo authority outside the crate. |

Numbers with no entry (their content is in another entry or was dropped): 14, 28, 30, 31, 53, 55, 59, 64, 118, 119, 130, 133, 145, 149, 163, 165, 168, 173, 183, 185, 186, 187, 199, 205, 211, 217, 221, 224, 229, 253, 255, 258, 268, 269, 270, 271, 289, 292, 305, 306, 307, 308, 313, 320, 323, 328, 330, 351, 357, 363, 372, 374, 392, 397, 406, 417, 426, 436, 446, 461, 472, 473, 479, 496, 497. Entries 40 and 41 are merged into 39, 44 into 43, 46 into 45, 48 and 49 into 47, 52 into 51, 83 to 85 into 82, and 469 to 471 into 467.

### Phase 0a: Replace the food example with an original survey (Done, commit a0ffcd8)

This phase is complete. The goal, gate and entries below stay as the record of what the commit changed; no later phase repeats them.

*   **Goal**: The bundled food example (`examples/instruments/food-intake-baseline.yaml`, its two layouts `examples/layouts/food-intake-baseline.{compact,expanded}.yaml`, and `docs/explanation/adr/0040-examples/food-intake-baseline.{survey.yaml,compact.layout.yaml}` with `docs/explanation/adr/0040-examples/i18n/es.po`) is a port of a third-party paper questionnaire whose copyright holder is unconfirmed. It has been removed from the public repository and must never be published. This phase deletes it from the tree (entry 514); until then code, tests, golden files, scripts and documents refer to it. This phase writes a new instrument from scratch, `school-meals-baseline`, that exercises the same features, retargets every reference, regenerates the goldens, and adds a check that no example declares a placeholder licence. Every later phase names `school-meals-baseline`, including the phases that convert and bundle examples.
*   **Depends on**: None.
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `fieldseal instrument validate` and `instrument lint` pass on `examples/instruments/school-meals-baseline.yaml`, `fieldseal layout validate` and `layout lint` pass on both of its layouts, and `fieldseal layout compile --lang es` renders Spanish text for every translated string.
    *   The regenerated golden files (`crates/contexts/instrument/tests/golden/spec-example.en.plan`, `crates/apps/cli/tests/golden/school-meals-baseline.expanded.outline`) are reviewed in the diff: only the example's name, wording and structure change.
    *   `grep -rIn 'food-intake-baseline' . --exclude-dir=target --exclude-dir=.git --exclude-dir=.claude --exclude-dir=designs --exclude=design_draft.md` finds nothing.
    *   `python3 tools/check-example-licences.py` passes on the tree and fails on a copy of the tree with `LicenseRef-to-be-confirmed` planted in any file under `examples/`.
    *   `fieldseal conformance run`, `just test` and `just acceptance`. `just acceptance` runs once on this commit because it is the only check that runs the stack scripts, whose example names changed.
*   **CI triggers**: `.github/workflows/ci.yml` runs only on `v*` tags and `workflow_dispatch`, to save Actions minutes. This phase does not edit it. Any phase that does edit it keeps both triggers.
*   **Security review**: None. No signing, sealing or policy code changes.

#### 507. `examples/instruments/school-meals-baseline.yaml` (Create)

*   **Type / Scope**: Example instrument
*   **Proposed Changes**: A new instrument in the compact dialect (ADR 0040), written for this project from the feature list in `examples/README.md`, not from the removed food example and not from any third-party questionnaire. Header: `survey: {name: school-meals-baseline, version: 1.0.0}`, `language: en`, English and Spanish (`translations:` declares `es`), `copyright: {notice: © 2026 Fieldseal contributors, licence: Apache-2.0}`, and no `derived-from` block. Original wording and generic food items throughout. Content: (1) general information read from the roster (school, class, age and the pupil's name as `roster.<field>` items), with the administrator and the date recorded by the session; (2) a code list of generic food groups (for example bread and cereals, rice and pasta, vegetables, fruit, milk and yoghurt, eggs, meat and fish, beans and lentils, nuts, sweets, snacks, sweet drinks, water) with an "other" entry; (3) a repeat over that list, each repetition asking how often the group is eaten on one of two nine-step frequency scales with numeric values (a per-day scale and a per-week scale); (4) per-item unit overrides over a default unit (slices, cups, spoonfuls, grams, millilitres); (5) one soft rule written once and expanded per item (an amount above a plausible daily maximum asks the interviewer to confirm); (6) measurement pairs with an entry unit (a portion given in a household measure and in grams); (7) `money` (weekly spend at the school shop); (8) conditional questions (an amount only for groups eaten; a free-text answer for "other"); (9) display elements (a heading and an instruction note); (10) field checks (age in a plausible range); (11) consent (required, a form-seen basis, a versioned statement, optional evidence). It validates and lints with no error.

#### 508. `examples/layouts/school-meals-baseline.compact.yaml` (Create)

*   **Type / Scope**: Example layout
*   **Proposed Changes**: Compact window: the general-information cards on step 1, then one step per food group. Declares `instrument: ../instruments/school-meals-baseline.yaml` (Phase 4 rewrites it) and titles in both languages.

#### 509. `examples/layouts/school-meals-baseline.expanded.yaml` (Create)

*   **Type / Scope**: Example layout
*   **Proposed Changes**: Expanded window: the general-information cards on step 1; the food groups as free tabs of `list` repeats on step 2.

#### 510. `examples/instruments/i18n/school-meals-baseline/es.po` (Create)

*   **Type / Scope**: Example catalogue
*   **Proposed Changes**: A complete Spanish catalogue for the instrument's texts, in the format the current loader reads (Phase 4 merges it with the layout catalogue). Original translation, written for this project.

#### 511. `examples/layouts/i18n/school-meals-baseline.compact/es.po` (Create)

*   **Type / Scope**: Example catalogue
*   **Proposed Changes**: Spanish titles for the compact layout's steps and cards, in the current loader's format.

#### 512. `examples/rosters/school-meals-baseline.yaml` (Create)

*   **Type / Scope**: Example roster
*   **Proposed Changes**: Cohort `cohort-a`, version 1: two participants, one with a carried-over `prior_status`, with the `fields` that the instrument reads (school, class, age, name). Invented names and ids.

#### 513. `examples/scenarios/school-meals-baseline.yaml` and `examples/scenarios/stack-capture-school-meals-baseline.yaml` (Create)

*   **Type / Scope**: Example scenarios
*   **Proposed Changes**: The device scenarios that the removed food scenarios provided, retargeted to the new survey: the built-in `consent` scenario and the stack capture.

#### 514. `examples/instruments/food-intake-baseline.yaml` and the other removed food files (Delete)

*   **Type / Scope**: Example (removed)
*   **Proposed Changes**: Delete `examples/instruments/food-intake-baseline.yaml`, `examples/layouts/food-intake-baseline.compact.yaml`, `examples/layouts/food-intake-baseline.expanded.yaml`, `examples/rosters/food-intake-baseline.yaml`, `examples/scenarios/food-intake-baseline.yaml`, `examples/scenarios/stack-capture-food-intake-baseline.yaml`, `crates/apps/cli/tests/golden/food-intake-baseline.expanded.outline` and the food files of `docs/explanation/adr/0040-examples/`.

#### 515. `examples/deployments/local-stack.yaml` and `examples/deployments/sample.yaml` (Modify)

*   **Type / Scope**: Example deployment manifests
*   **Proposed Changes**: `ref: instrument/food-intake-baseline` becomes `ref: instrument/school-meals-baseline` (local-stack line 35, sample line 24).

#### 516. `examples/README.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Replace the food rows in the instruments, layouts and rosters tables and the command examples with `school-meals-baseline`; describe it as an original survey written for this project; remove the sentence that its copyright notice and licence are placeholders.

#### 517. `crates/apps/cli/src/device.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: The built-in scenario, instrument and layout tables (lines 73, 79, 81, 82) and the comment at line 10 name `school-meals-baseline`.

#### 518. `crates/apps/cli/src/conformance_cmd/col.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: `const FOOD` (line 35) names `school-meals-baseline` (rename the constant to match).

#### 519. `crates/apps/e2e/src/lib.rs` (Modify)

*   **Type / Scope**: Test support library
*   **Proposed Changes**: Line 84: `example("instruments/school-meals-baseline.yaml")`, and the local variable and the `expect` message in `sample_instrument_document` that named the food example now say `meals` and `school meals consent block`.

#### 520. `crates/apps/web/tests/parity.rs` and `crates/apps/web/tests/browser_constraints.rs` (Modify)

*   **Type / Scope**: Integration tests
*   **Proposed Changes**: The stem list (`parity.rs` line 63) and the page path (`browser_constraints.rs` line 51) name `school-meals-baseline`.

#### 521. `crates/adapters/memory/tests/common/mod.rs` (Modify)

*   **Type / Scope**: Test support
*   **Proposed Changes**: `load("school-meals-baseline")` at line 126.

#### 522. `crates/contexts/instrument/tests/support/fixtures.rs` and `crates/contexts/instrument/tests/support/layouts.rs` (Modify)

*   **Type / Scope**: Test support
*   **Proposed Changes**: Retarget the references to the example; fixtures that assert on the old example's items assert on the new one's.

#### 523. `crates/contexts/instrument/tests/golden/spec-example.en.plan` (Modify)

*   **Type / Scope**: Golden data
*   **Proposed Changes**: Regenerate from the new instrument and review the diff.

#### 524. `crates/apps/cli/tests/golden/school-meals-baseline.expanded.outline` (Create)

*   **Type / Scope**: Golden data
*   **Proposed Changes**: Regenerate from the new instrument and layout (the old `food-intake-baseline.expanded.outline` is deleted in entry 514).

#### 525. `tools/stack-demo.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Lines 26, 96, 146 and 249: the default survey, the publish step, the roster flag and the wanted name become `school-meals-baseline`.

#### 526. `tools/release-docs.sh` and `tools/stack-acceptance.sh` (Modify)

*   **Type / Scope**: Shell scripts
*   **Proposed Changes**: Change `release-docs.sh` line 25 and `stack-acceptance.sh` line 19 (the rendered `school-meals-baseline-*.html`) to the new name.

#### 527. `tools/browser-tests/wcag.sh`, `device-flow.sh`, `device-flow.py` and `README.md` (Modify)

*   **Type / Scope**: Shell and Python scripts, documentation
*   **Proposed Changes**: Instrument names and paths (`wcag.sh` lines 13 and 17; `device-flow.sh` line 7; `device-flow.py` line 9) and the README row.

#### 528. `justfile` (Modify)

*   **Type / Scope**: Build configuration
*   **Proposed Changes**: `fetch artefact="school-meals-baseline"` (line 46). `just test` also runs `tools/check-example-licences.py`.

#### 529. `flake.nix` (Modify)

*   **Type / Scope**: Nix flake
*   **Proposed Changes**: The comment at line 508 names `examples/instruments/school-meals-baseline.yaml`. No code change.

#### 530. `tools/check-example-licences.py` (Create)

*   **Type / Scope**: Repository check
*   **Proposed Changes**: Walks `examples/`, reads each instrument's `copyright` block, and fails with the file and line if any file under `examples/` contains `LicenseRef-to-be-confirmed` or a copyright notice that says the holder is to be confirmed. Run by `just test`. It has a self-test that plants the placeholder in a temporary copy and expects a failure.

#### 531. `docs/explanation/adr/0040-examples/` (Modify)

*   **Type / Scope**: ADR examples
*   **Proposed Changes**: The ADR 0040 worked example uses `school-meals-baseline` as its survey: create `school-meals-baseline.survey.yaml`, `school-meals-baseline.compact.layout.yaml`, `i18n/es.po` and `i18n/school-meals-baseline.expanded.outline` from the new instrument, and update `fieldseal.deploy.yaml`. In `docs/explanation/adr/0039-examples/fieldseal.yaml`, `metadata.name` becomes `school-meals-baseline`.

#### 532. `docs/explanation/adr/0040-compact-declarations-and-twelve-factor-config.md`, `docs/reference/authoring-audit.md`, `docs/reference/spec/instrument.md` and `docs/tutorials/hands-on.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Replace the example name and the descriptions of its content with the new survey; keep every normative statement unchanged.

**Housekeeping**: update the example name in `crates/apps/cli/README.md`; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py`.

### Phase 0b: Baselines and stage timing

*   **Goal**: Measure `just up` per stage and CI on a warm cache before any other change, so every later phase is compared with a recorded number.
*   **Depends on**: None.
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `just lint` (shellcheck on `tools/stack-*.sh`)
    *   `just purge && just up`, `just up` again with nothing changed, and `just up` after a one-line Rust change; each prints the stage table and writes `deploy/local/.generated/stack-timing.txt`; the three tables are copied into `docs/explanation/build-system.md`
    *   `ci` workflow started twice on one commit with `gh workflow run ci` (it runs only for release tags and manual starts), the second run only after the first has finished, because `ci.yml` sets `cancel-in-progress: true` for one ref; run ids and job durations (from `gh run view`) are written beside the `just up` tables
    *   The answer to Open Question 2 (is `vars.FIELDSEAL_CACHIX` set) is written next to the CI numbers
    *   Build-cost baseline recorded beside them: the number of distinct normal dependencies (`cargo tree --workspace --edges normal --prefix none | sort -u | wc -l`), a cold `cargo build --workspace --timings` time, and `cargo tree -i arrow` and `cargo tree -i parquet` both failing with "did not match any packages" (`cargo tree -i` exits non-zero when the package is absent, and that is the passing result)
    *   Test-suite baseline: `tools/test-budget.sh` output (seconds against the 20 s budget) and the test count from `docs/reference/test-inventory.md`
*   **Security review**: None.

#### 1. `tools/stack-engine.sh` (Modify)

*   **Type / Scope**: Shell library
*   **Proposed Changes**: Add `stage <name> <command...>`: runs the command (a function of the calling script works too), measures elapsed seconds with `date +%s%N`, appends `<name>\t<seconds>` to `$LOCAL/.generated/stack-timing.tsv` (creating the directory if needed) and returns the command's status. `stage` writes nothing to stdout itself and passes the command's stdout through, so `out=$(stage <name> <command...>)` captures the command's output. A command run through `stage` is called as the condition of an `if`, so `set -e` is off inside a function passed to it: every step in such a function ends in `|| die ...`. Add `stage_report`, which prints the rows as an aligned table, the total, and copies the table to `$LOCAL/.generated/stack-timing.txt`. The file is truncated at the start of `tools/stack-up.sh`.

#### 2. `tools/stack-up.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Wrap each step in `stage`: `cli` (`FS=$(stage cli "$ROOT/tools/stack-cli.sh")`, the `nix build` of the CLI that `stack-cli.sh` runs at line 16), `secrets+render` (secret generation, `deployment validate` and `deployment render`, moved into a function `secrets_and_render` that `stage` calls), `compose-up`, `wait-keycloak` (the 240 s wait), `wait-factory`, `wait-intake`, `wait-log` and `wait-web`. The call to `tools/stack-images.sh` is not wrapped: that script records its own `build-<name>` and `load-<name>` rows (entry 3), and an outer `images` row would count the same seconds twice in the total. Call `stage_report` before the closing message.

#### 3. `tools/stack-images.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Wrap, per image name, `nix build` (`build-<name>`, as `out=$(stage "build-$name" nix build ...)`) and `<engine> load` (`load-<name>`) in `stage`, so image build time and image load time are separate rows. A skipped load records `0`. The rows are appended to the same TSV, so `just images` run alone also appends rows (to a file that `stack-up.sh` truncates only when it starts).

#### 4. `docs/explanation/build-system.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Add a section "Measured baselines": the three `just up` stage tables (purge, unchanged, one-line Rust change), the CI warm-cache durations with run ids, the machine description, and the date. Targets for `just up` and for CI are added here when Open Question 1 is answered.

#### 5. `docs/reference/toolchain.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: In "Continuous integration", state whether `FIELDSEAL_CACHIX` is set (answer to Open Question 2) and that `FIELDSEAL_CACHE_GHA` defaults to on, with a link to the baseline section.

### Phase 1: Golden set and declarative schema

*   **Goal**: Record every example's expanded document and addresses with the old decoder, then replace the hand-written key checks in `compact.rs` with a declarative schema module that also reports real line and column numbers. Resolved Decisions 2 and 4.
*   **Depends on**: Phase 0a (the example is replaced) and Phase 0b (baseline recorded).
*   **Commits**: Two commits, in order. 1a: `Record the expanded form and addresses of every example` (tests and golden set only; the old decoder produces them). 1b: `Check survey sources against a declared schema` (the rewrite, the invalid-document corpus, the `strict-schema` suite and the replacement of `next_salt()` by `DemoWorld::salt_for` at its three callers; the golden set is not edited).
*   **Gate** (must pass before the next phase starts):
    *   After 1a: `cargo nextest run -p fieldseal-e2e --test migration_gate` passes on the old decoder; `just migration-gate` runs the same test.
    *   After 1b: the same command passes, and `git diff <1a>..<1b> -- crates/apps/e2e/tests/golden` is empty (the rewrite changed no expanded document, address or fingerprint). `fieldseal conformance run --suite strict-schema` rejects every document in `tests/schema-corpus/` (entries 538 and 552) for both kinds, and `nix build path:.#checks.x86_64-linux.tests` finds the corpus (entry 553).
    *   `cargo test -p fieldseal-kernel` (the `schema` module), `cargo test -p fieldseal-adapters-authoring` (differential test, error-position test) and `cargo test -p fieldseal-cli --test strict_schema_corpus`; `python3 tools/check-architecture.py` (the kernel gains no I/O call and no dependency); `cargo test -p fieldseal-security-tests --test decoder_hardening` unchanged and passing.
    *   `just test` (inventory, 20 s budget, clippy, architecture).
*   **Security review**: None.

#### 6. `crates/apps/e2e/tests/migration_gate.rs` (Create)

*   **Type / Scope**: Integration test (migration gate)
*   **Proposed Changes**: Loads each example by survey and layout name through a table in `fieldseal_e2e` (`survey_sources(name)`, old paths in this commit), expands it, and compares it with `tests/golden/examples.json` and `tests/golden/expanded/**`. For one survey the steps follow `Site::new` (`crates/apps/e2e/src/lib.rs:158–166`): (1) decode and expand the instrument; (2) `bytes = cbor::encode(&doc)` and the instrument address is `ContentAddress::of(&bytes)`; (3) the salt is `pinned_salt(name)` and the salted fingerprint is `artefact_address(ArtefactKind::Instrument, &bytes, Some(&salt))`, which is the address a publication of that instrument gets, so no `DemoWorld` is needed; (4) for each layout, replace `spec.instrument` with `Value::Bytes(<fingerprint>)`, `cbor::encode`, and the bound layout address is `ContentAddress::of` of those bytes; (5) validate the bound layout with `validate_layout_with` and `LayoutOptions { binding: Some(LayoutBinding { expected: <fingerprint>, resolve }) }`, so a layout bound to another fingerprint fails; (6) render the expanded instrument and each expanded layout with `expanded_json` and compare the text with the golden file first, printing a textual diff on mismatch. Cases: `wire_011_every_example_instrument_keeps_its_address`, `wire_185_every_example_keeps_its_salted_fingerprint`, `ins_200_every_bound_layout_keeps_its_address`, `ins_200_expanded_documents_match_the_golden_text`. A mismatch fails with the example name, the field and both values.

#### 7. `crates/apps/e2e/tests/golden/examples.json` (Create)

*   **Type / Scope**: Golden data
*   **Proposed Changes**: Keyed by survey name and layout window: `{ "<survey>": { "salt": "<hex>", "instrument_address": "sha256:...", "instrument_fingerprint": "<hex>", "layouts": { "<window>": "sha256:..." } } }`. `instrument_address` is the SHA-256 of the canonical bytes of the expanded instrument (the golden set of Technical Plan §2 has no separate hash field). Generated once by the old decoder (`FIELDSEAL_GOLDEN=write cargo test -p fieldseal-e2e --test migration_gate` writes the file; CI never sets the variable, and a change to a golden set is a reviewed event). The test reads it with `fieldseal_adapters_authoring::decode_raw(.., Format::Json)`. Not edited by Phases 1b to 4.

#### 8. `crates/apps/e2e/tests/golden/expanded/household-water-access/instrument.json` (Create)

*   **Type / Scope**: Golden data
*   **Proposed Changes**: Pretty-printed canonical JSON of `household-water-access`'s expanded instrument, written by the old decoder. Used for the text diff when an address changes.

#### 9. `crates/apps/e2e/tests/golden/expanded/household-water-access/layout-compact.json` (Create)

*   **Type / Scope**: Golden data
*   **Proposed Changes**: Pretty-printed canonical JSON of `household-water-access`'s compact layout, expanded and bound, written by the old decoder. Used for the text diff when an address changes.

#### 10. `crates/apps/e2e/tests/golden/expanded/school-meals-baseline/instrument.json` (Create)

*   **Type / Scope**: Golden data
*   **Proposed Changes**: Pretty-printed canonical JSON of `school-meals-baseline`'s expanded instrument, written by the old decoder. Used for the text diff when an address changes.

#### 11. `crates/apps/e2e/tests/golden/expanded/school-meals-baseline/layout-compact.json` (Create)

*   **Type / Scope**: Golden data
*   **Proposed Changes**: Pretty-printed canonical JSON of `school-meals-baseline`'s compact layout, expanded and bound, written by the old decoder. Used for the text diff when an address changes.

#### 12. `crates/apps/e2e/tests/golden/expanded/school-meals-baseline/layout-expanded.json` (Create)

*   **Type / Scope**: Golden data
*   **Proposed Changes**: Pretty-printed canonical JSON of `school-meals-baseline`'s expanded-window layout, expanded and bound, written by the old decoder. Used for the text diff when an address changes.

#### 13. `crates/apps/e2e/src/lib.rs` (Modify)

*   **Type / Scope**: Test support library
*   **Proposed Changes**: Add `pinned_salt(name: &str) -> Salt` (`SHA-256("fieldseal.dev/demo/salt" || name)` with `fieldseal_kernel::digest::sha256`; in commit 1b its body becomes `DemoWorld::salt_for(name)`, entry 89, so there is one derivation), `survey_sources(name) -> SurveySources { instrument, layouts: [(window, path)], catalogues }` (a table of the current example paths) and `expanded_json(&Value) -> String`. `expanded_json` is written in this crate, because an app crate cannot use the CLI's `json.rs`: keys in sorted order (maps are `BTreeMap`), two-space indent, a final newline, `Value::Bytes` as lowercase hex text (`fieldseal_kernel::digest::lower_hex`), decimals as JSON numbers with every written digit (their canonical decimal text) and text escaped minimally (`"`, `\`, control characters). Existing helpers are unchanged in this commit.

#### 15. `justfile` (Modify)

*   **Type / Scope**: Build configuration
*   **Proposed Changes**: Add recipe `migration-gate`: `cargo nextest run -p fieldseal-e2e --test migration_gate` (comment: the migration gate for address-preserving changes; Technical Plan §5).

#### 16. `crates/kernel/src/schema.rs` (Create)

*   **Type / Scope**: Rust module (format core, declarative schema; pure, no I/O)
*   **Proposed Changes**: A table of every authoring key of the compact dialect. Types: `PathPattern(&'static [&'static str])`, the segments from the document root with `"*"` for any map key or array index (for example `["lists", "*", "items", "*", "label"]`); `ShapeId(&'static str)`, the name of one map shape (for example `"survey.item"`); `Shape { id: ShapeId, keys: &'static [KeySpec] }`, the keys one map may hold; `KeySpec { name: &'static str, ty: Ty, required: bool, doc: &'static str, cross_key: Option<&'static str> }`; `Ty` = `Text | Integer | Boolean | Enum(&[&str]) | List(Box<Ty>) | Map(ShapeId) | Ref(ShapeId)`. A shape is reached from the root shape of its kind (`schema::root(kind) -> ShapeId`) by following `Map` and `Ref` types, and a `PathPattern` names the position in the document where each shape applies (used in findings and in the generated JSON Schema). `SchemaError { pointer: String, kind: SchemaErrorKind, message: String }` with `SchemaErrorKind` = `UnknownField | MissingField | TypeMismatch | EnumValue | DuplicateKey | CoercionRefused` (the WIRE-211 list and no other); `pointer` is an RFC 6901 JSON Pointer. API: `schema::shapes() -> &'static [Shape]`, `schema::root(kind: DocKind) -> ShapeId`, `schema::check(doc: &Value, kind: DocKind) -> Vec<SchemaError>`, `schema::json_schema(kind: DocKind) -> Value` (the editor JSON Schema, generated from the same table, draft 2020-12) and `schema::accessors`: `Reader::new(map: &Map, shape: ShapeId)` with `text`, `int`, `flag`, `list`, `map` and `raw` reads by key name, each of which asserts in debug builds that the key is declared in the shape, so the expander cannot read a key the table does not declare. `DocKind` = `Survey | Layout | Roster`, because `compact.rs` also expands compact rosters (`roster()`, line 1152). Cross-key rules the table cannot state (for example that a `show:` path exists) are listed in `cross_key` and stay as code in `compact.rs`. `id` is declared as an optional key on layout steps and cards (made mandatory by the resolver in Phase 2, not here, so the old layouts still pass). `crates/kernel/src/lib.rs` gains `pub mod schema;`. The module uses no dependency beyond the kernel's and none of the calls that `inner_forbidden_source` lists; `python3 tools/check-architecture.py` confirms it. Unit tests in the module: `wire_209_every_key_of_both_kinds_is_declared_once`, `wire_209_the_json_schema_is_generated_from_the_same_table`, `wire_211_pointer_segments_escape_tilde_and_slash` and `wire_211_every_error_kind_is_one_of_the_six`.

#### 17. `crates/adapters/authoring/src/compact.rs` (Modify)

*   **Type / Scope**: Rust module (expander)
*   **Proposed Changes**: Today the 1,254-line file interleaves its key and type checks with the expansion: each function reads keys through `Obj::req`, `Obj::text`, `Obj::number` and the like, and `Obj::done` rejects any key left over. The change: `expand_with` runs `fieldseal_kernel::schema::check` on the compact document first, and the checks that `Obj` performed (required, type, unknown key, enum) are deleted, since the schema covers them. The expansion code (slugs, ordered content, defaults, generated scales) stays and reads keys through `schema::accessors::Reader`. Cross-key checks stay here. Errors take their line and column from the span table, looked up by JSON Pointer. No change to the expanded output.

#### 18. `crates/adapters/authoring/src/yaml.rs` (Modify)

*   **Type / Scope**: Rust module (YAML decoder)
*   **Proposed Changes**: Add the internal `decode_with_spans(text: &str) -> Result<(Value, Spans), AuthoringError>`: a map from JSON Pointer (for example `/lists/water-sources/items/2/label`) to the 1-based line and column of the key and of the value, taken from the `saphyr-parser` markers. The decoder tracks the pointer of the node it is reading, so these existing error kinds carry it: `ErrorKind::DuplicateKey` is reported as the schema kind `DuplicateKey`, and `Null`, `Float`, `Number` and `AmbiguousBoolean` as `CoercionRefused`, each with its pointer and position. `decode` calls it and drops the spans, so existing callers do not change.

#### 19. `crates/adapters/authoring/src/json.rs` (Modify)

*   **Type / Scope**: Rust module (JSON decoder)
*   **Proposed Changes**: The same span table, from the positions the hand-written parser already tracks for syntax errors: an internal `decode_with_spans(text: &str) -> Result<(Value, Spans), AuthoringError>`, with the same error-kind mapping as YAML.

#### 20. `crates/adapters/authoring/src/error.rs` (Modify)

*   **Type / Scope**: Rust module (errors)
*   **Proposed Changes**: Add `Position { line: usize, column: usize }` (1-based) and `LocatedFinding { pointer, position: Position, kind, message }`, built from the kernel's `SchemaError` and the span table, with `kind` one of the six WIRE-211 kinds and a `Display` that prints `file:line:column`. `AuthoringError` keeps its public `line` and `column` fields (nine callers read them: `crates/adapters/web/src/workbench.rs:88,112,249`, `crates/adapters/web/src/device.rs:79,519`, `crates/apps/cli/src/support.rs:108`, `crates/apps/cli/src/artefact_cmd.rs:224`, `crates/apps/cli/src/commands.rs:129` and `crates/adapters/authoring/src/lib.rs:144`), and gains `position: Option<Position>` (`Some` for every error with a real source position, equal to `line`/`column`; `None` for I/O errors, which keep `0:0` and carry the file path in the message) and `findings: Vec<LocatedFinding>` (empty except for a schema failure, where `line`, `column` and `message` are those of the first finding and `findings` holds all of them). No caller changes.

#### 21. `crates/adapters/authoring/src/lib.rs` (Modify)

*   **Type / Scope**: Rust module (public API)
*   **Proposed Changes**: `pub use` of `Position`, `LocatedFinding` and `Spans`, and the public `decode_with_spans(text: &str, format: Format) -> Result<(Value, Spans), AuthoringError>`, which gives spans for both YAML and JSON (the schema itself is `fieldseal_kernel::schema`). `decode` runs `schema::check` on a compact document (`compact::is_compact`; the kind is `Survey`, `Layout` or `Roster` as `expand_with` already chooses) before expanding it, and returns a schema failure as an `AuthoringError` with `findings`. `decode` and `decode_path` keep their signatures; other documents behave as before.

#### 22. `crates/adapters/authoring/Cargo.toml` (Modify)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Add dev-dependencies `jsonschema = { version = "0.60", default-features = false }` (the JSON Schema validator; `Cargo.lock` pins the exact version) and `serde_json = "1"` (the validator takes `serde_json::Value`), for the differential test. Dev-dependencies are free under `architecture.toml`, whose allow-list applies only to the kernel and contexts. No new normal dependency.

#### 23. `crates/adapters/authoring/tests/schema_differential.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Cases: `wire_210_every_example_is_accepted_by_decoder_and_json_schema`; `wire_210_dropping_a_required_key_is_rejected_by_both`; `wire_210_a_wrong_type_is_rejected_by_both`; `wire_210_a_value_outside_an_enum_is_rejected_by_both`; `wire_210_an_unknown_sibling_key_is_rejected_by_both`; `wire_209_json_schema_output_is_deterministic`; `wire_213_every_document_in_the_schema_corpus_is_rejected_by_both` (entry 538). Mutations are generated from `fieldseal_kernel::schema::shapes()` for every declared key. Keys flagged `cross_key` are compared on their structural part only. The test converts a kernel `Value` to `serde_json::Value` with a helper in the test file: integers as numbers (text when they exceed `i64`), decimals as numbers parsed from their canonical text, bytes as lowercase hex text, maps and arrays element by element.

#### 24. `crates/adapters/authoring/tests/error_positions.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Three fixtures, each with one deliberate mistake; the test asserts the reported file, line and column: `wire_211_a_misspelled_key_reports_its_line_and_column`, `wire_211_a_wrong_type_reports_the_value_position`, `wire_211_an_out_of_range_enum_reports_the_value_position`, `wire_211_findings_carry_a_json_pointer_and_one_of_the_six_kinds`, `wire_211_a_repeated_key_reports_duplicate_key_at_its_position` and `wire_211_an_io_error_keeps_position_zero_and_names_the_file`.

#### 25. `crates/adapters/authoring/tests/fixtures/errors/misspelled-key.yaml` (Create)

*   **Type / Scope**: Test fixture
*   **Proposed Changes**: Survey source with a key misspelled one line below a correct sibling; the expected position is stated in a comment on the line above and read by the test.

#### 26. `crates/adapters/authoring/tests/fixtures/errors/wrong-type.yaml` (Create)

*   **Type / Scope**: Test fixture
*   **Proposed Changes**: Survey source with an integer where text is required; the expected position is stated in a comment on the line above and read by the test.

#### 27. `crates/adapters/authoring/tests/fixtures/errors/bad-enum.yaml` (Create)

*   **Type / Scope**: Test fixture
*   **Proposed Changes**: Survey source with an item `type:` outside the allowed values; the expected position is stated in a comment on the line above and read by the test.

#### 29. `docs/reference/authoring-audit.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Mark the audit rows on hand-written key checks and `0:0` positions as resolved by `crates/kernel/src/schema.rs`, with the commit name.

#### 89. `crates/adapters/memory/src/demo.rs` (Modify)

*   **Type / Scope**: Rust module (in-memory demo world)
*   **Proposed Changes**: Replace `next_salt(&self)` and the `salts: AtomicU64` counter (struct field at line 151, initialiser at line 332, method at line 361) with the associated function `DemoWorld::salt_for(name: &str) -> Salt` = `SHA-256("fieldseal.dev/demo/salt" || name)`: the same domain string as today, and the same derivation as `pinned_salt` (entry 13). It needs no state, so it is an associated function, called `DemoWorld::salt_for(name)`. `next_salt` has no caller inside this file; its three callers are in entry 96. This change lands in commit 1b, not in the migration commit, so the migration commit changes no test-world code.

#### 96. `crates/apps/cli/src/bundle_cmd.rs`, `crates/apps/e2e/src/lib.rs` and `crates/adapters/web-demo/src/content.rs` (Modify)

*   **Type / Scope**: Rust modules (the three callers of `next_salt`)
*   **Proposed Changes**: All three callers change in commit 1b, with entry 89, so the tree builds after it. `crates/apps/cli/src/bundle_cmd.rs:215`: `world.next_salt()` becomes `DemoWorld::salt_for(<survey name>)`, where the name is the instrument's `metadata.name` (the value `metadata(&instrument, "name", ..)` already reads on the next lines). `crates/apps/e2e/src/lib.rs:158` (`Site::new`): `Some(world.next_salt())` becomes `Some(DemoWorld::salt_for(&meta(&doc, "name")))`, and `pinned_salt` (entry 13) now calls `DemoWorld::salt_for`. `crates/adapters/web-demo/src/content.rs:101`: `Some(world.next_salt())` becomes `Some(DemoWorld::salt_for(&name))`.

#### 538. `tests/schema-corpus/survey/*.yaml` and `tests/schema-corpus/layout/*.yaml` (Create)

*   **Type / Scope**: Test data (invalid-document corpus, WIRE-213)
*   **Proposed Changes**: For the survey schema and the layout schema, one invalid document for each of: an unknown field at every nesting level, a missing required field, a wrong type, an out-of-enumeration value, a duplicate key and a coerced value, each with a comment naming the expected `SchemaError` kind and JSON Pointer. The differential test (entry 23) runs the corpus through the decoder and the generated JSON Schema, and the `strict-schema` conformance suite (entry 552, CLI-043) runs it through the decoder and the kernel validator; every document must be rejected by every reader. Landed in commit 1b.

#### 552. `crates/apps/cli/src/conformance_cmd/strict_schema.rs` and `crates/apps/cli/src/conformance_cmd/mod.rs` (Create, Modify)

*   **Type / Scope**: Rust module (CLI conformance suite)
*   **Proposed Changes**: The `strict-schema` suite that CLI-043 requires and WIRE-213 describes. `strict_schema.rs` embeds the corpus with one `include_str!("../../../../../tests/schema-corpus/<kind>/<file>")` per file in a static table `CORPUS: &[(DocKind, &str /*file name*/, &str /*text*/)]`, so the installed binary needs no files. `pub fn units() -> Vec<Unit>` returns two vector units, `schema:survey` and `schema:layout` (`Unit::new(id, &["strict-schema"], run)`). For each document, `run` records one `Collector::case(&["WIRE-210", "WIRE-211", "WIRE-213"], <file name>, ..)` that passes only when two readers both reject it with the kind and pointer named in the document's comment: the kernel validator (`fieldseal_kernel::schema::check`) and the authoring decoder (`fieldseal_adapters_authoring::decode`). The JSON Schema validator (`jsonschema`) is a dev-dependency of the authoring crate and is not in the CLI's dependencies, so the JSON Schema run is the differential test of entry 23. In `mod.rs`: `mod strict_schema;`, `all.extend(strict_schema::units());` in `units()` (line 106), and a row `("strict-schema", "the invalid-document corpus (WIRE-213) through every reader")` in `SUITES` (lines 123 to 152), because `selected()` (line 155) accepts only names in `SUITES`; `conformance list` prints the suite from that table. A test `crates/apps/cli/tests/strict_schema_corpus.rs` (`wire_213_the_embedded_corpus_lists_every_file`, `cli_043_conformance_list_names_strict_schema`, `cli_043_the_strict_schema_suite_rejects_every_corpus_document`) compares the table with `read_dir` of the corpus.

#### 553. `flake.nix` (Modify)

*   **Type / Scope**: Nix flake
*   **Proposed Changes**: Add `./tests` to the `workspaceSrc` fileset (lines 94 to 107). Without it the corpus is not in the Nix source set: `checks.tests` finds no files for the corpus test, and the CLI's `include_str!` of the corpus (entry 552) does not compile in the Nix build. Landed in commit 1b.

**Housekeeping**: `crates/kernel/README.md`: Document the `schema` module (pure; no I/O); `crates/adapters/authoring/README.md`: Document `Spans`, `decode_with_spans` and `LocatedFinding`, and that the schema lives in the kernel; update the invariants (one declaration of each key; errors carry real positions) and the test commands; `Cargo.lock`: Dev-dependencies `jsonschema` and `serde_json` and their dependencies; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 2: Survey resolver and translation groundwork

*   **Goal**: Add the only code that knows the survey folder shape, the `.po` entry model with `msgid`, the `msgctxt` grammar with authored layout ids, and the translation report. Nothing is moved and no example changes. Technical Plan §1 and §3; Resolved Decisions 3 and 18.
*   **Depends on**: Phase 1 (schema module and golden set).
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `cargo test -p fieldseal-adapters-authoring` (resolver, `.po`, report tests on the new fixtures).
    *   `just migration-gate` still passes with the golden set unchanged (`git diff --stat -- crates/apps/e2e/tests/golden` is empty).
    *   A test over the current examples shows the legacy catalogues produce no stale or orphaned finding (so stale-as-missing cannot change an address): `ins_260_the_example_catalogues_have_no_stale_entries`.
    *   `python3 tools/check-architecture.py` (no new edge); `just test`.
*   **Security review**: None.

#### 32. `crates/adapters/authoring/src/survey.rs` (Create)

*   **Type / Scope**: Rust module (resolver)
*   **Proposed Changes**: The only code that knows the folder shape. `SurveyTree::open(root) -> SurveyTree` (lists folders), `SurveyTree::survey(name) -> SurveyRef { dir, instrument, layouts: Vec<LayoutFile>, catalogues: Vec<Catalogue> }`, `SurveyRef::load() -> LoadedSurvey { instrument: Value, layouts: Vec<(String, Value)>, translation_report: Vec<Finding> }`, `RosterSet::open(dir)` (the roster files directly in `dir`, read for their `cohort` and `version`, never for their file name; it does not recurse, so `examples/rosters/next/` is not listed; `latest(cohort)` and `cohorts()`; a survey does not name its roster, so callers find a roster by cohort), `ResolveError { pointer, line, column, kind, message }` (kinds as listed in Technical Plan §1), `Finding { kind: Missing | Orphaned | Stale | NoCatalogue, file, line, msgctxt, old_msgid, new_text }`. Rules: folder name equals `survey.name`; a layout file's stem equals its declared `window`; every titled step and card in a layout has an `id:` (error `missing-layout-id`) and ids are unique in a layout; files that are neither `instrument.yaml`, `layouts/*.yaml`, `i18n/*.po` nor `README.md` are warnings; `SurveyTree::open` ignores directories whose names begin with a dot (so `<root>/.fieldseal/` is not a survey). It never prints and never skips content without returning it. `load()` calls the same `decode`/`expand_with` path as today.

#### 33. `crates/adapters/authoring/src/po.rs` (Create)

*   **Type / Scope**: Rust module (catalogues)
*   **Proposed Changes**: `PoEntry { msgctxt, msgid, msgstr, line }` and `parse_po(text) -> Result<Vec<PoEntry>, AuthoringError>`: keeps an empty `msgstr` as missing and rejects a repeated `msgctxt` with the line of the second occurrence. It accepts any `msgctxt`, so catalogues in the legacy form keep parsing until Phase 4. The `msgctxt` grammar is `instrument/<path>` and `layout/<window>/<authored id>`; a separate `check_context(msgctxt: &str) -> Result<ContextKind, String>` enforces it, and only the resolver (`SurveyRef::load`) calls it. `EntryCatalogues = BTreeMap<String, BTreeMap<String, PoEntry>>` (language, then `msgctxt`) is what the resolver hands to the expander.

#### 34. `crates/adapters/authoring/src/compact.rs` (Modify)

*   **Type / Scope**: Rust module (expander)
*   **Proposed Changes**: `parse_po` moves to `po.rs`. `compact::parse_po` stays as an adapter over `po::parse_po`: it returns `BTreeMap<String, String>` (`msgctxt` to `msgstr`) and drops entries with an empty `msgstr`, as it does today, and `compact::Catalogues` and `expand_with` keep their signatures, so their callers (`crates/apps/cli/src/device.rs:220`, `crates/apps/cli/src/conformance_cmd/col.rs:48` and `crates/adapters/authoring/src/lib.rs:144`) are untouched until Phase 4. Add `expand_with_entries(doc, &po::EntryCatalogues)`, which the resolver uses. Both entry points call one internal expander; the legacy one gives each entry no `msgid`, which turns the stale check off. With entries, an entry applies only when its `msgid` equals the current English text (stale entries are treated as missing, as `msgfmt` skips fuzzy entries). Layout steps and cards with an `id:` take `layout/<window>/<id>` keys and the id is dropped from the expanded document; steps without an id keep the positional keys, so the unmigrated examples expand exactly as before. The orphan/stale/missing report is built once per survey over the union of instrument and layout contexts.

#### 35. `crates/adapters/authoring/src/lib.rs` (Modify)

*   **Type / Scope**: Rust module (public API)
*   **Proposed Changes**: `pub mod survey; pub mod po;` and re-export `SurveyTree`, `SurveyRef`, `LoadedSurvey`, `ResolveError`, `Finding`, `PoEntry` and `EntryCatalogues`. `decode_path` still reads the legacy `i18n/<file stem>/<lang>.po` tree through `compact::parse_po` until Phase 4.

#### 36. `crates/adapters/authoring/tests/survey_resolver.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Cases: `ins_258_a_valid_folder_loads`, `ins_258_folder_name_must_equal_survey_name`, `ins_258_layout_stem_must_equal_window`, `ins_258_titled_steps_and_cards_need_unique_ids`, `ins_258_unknown_files_are_warnings_not_ignored`, `ins_258_a_survey_that_fails_to_load_returns_its_error_with_position`, `ins_258_rosters_are_listed_by_cohort_and_version`, `ins_258_a_roster_in_a_subdirectory_is_not_listed`.

#### 37. `crates/adapters/authoring/tests/translation_report.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Cases: `ins_260_missing_entry_is_reported_with_the_source_line`, `ins_260_empty_msgstr_counts_as_missing`, `ins_260_orphaned_entry_after_a_deleted_question`, `ins_260_stale_entry_reports_old_msgid_and_new_text`, `ins_260_stale_entry_is_not_applied`, `ins_260_a_declared_language_without_a_catalogue_warns`, `ins_259_one_catalogue_serves_instrument_and_layouts`, `ins_261_layout_ids_never_reach_the_expanded_document`, `ins_260_the_example_catalogues_have_no_stale_entries`, `ins_260_strict_turns_warnings_into_errors`.

#### 38. `crates/adapters/authoring/tests/po_entries.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Cases: `ins_259_parse_po_keeps_msgid_msgstr_and_line`, `ins_260_an_empty_msgstr_is_kept_and_counts_as_missing`, `ins_259_a_repeated_msgctxt_is_rejected_with_the_second_line`, `ins_259_multi_line_strings_and_escapes_round_trip`, `ins_259_parse_po_accepts_a_legacy_context`, `ins_259_check_context_accepts_instrument_and_layout_contexts`, `ins_259_check_context_rejects_other_prefixes`, `ins_259_the_compact_adapter_keeps_the_old_map_and_drops_empty_msgstr`.

#### 39. `crates/adapters/authoring/tests/fixtures/surveys/valid/{instrument.yaml,layouts/compact.yaml,i18n/es.po}` (Create)

*   **Type / Scope**: Test fixture
*   **Proposed Changes**: Fixture folder `valid`: a small survey with one list, three items, a compact layout with ids and a Spanish catalogue that is complete.

#### 42. `crates/adapters/authoring/tests/fixtures/surveys/name-mismatch/instrument.yaml` (Create)

*   **Type / Scope**: Test fixture
*   **Proposed Changes**: Fixture folder `name-mismatch`: folder name differs from `survey.name`.

#### 43. `crates/adapters/authoring/tests/fixtures/surveys/window-mismatch/{instrument.yaml,layouts/expanded.yaml}` (Create)

*   **Type / Scope**: Test fixture
*   **Proposed Changes**: Fixture folder `window-mismatch`: file stem `expanded` declares `window: compact`.

#### 45. `crates/adapters/authoring/tests/fixtures/surveys/stray-file/{instrument.yaml,instrument.yaml.bak}` (Create)

*   **Type / Scope**: Test fixture
*   **Proposed Changes**: Fixture folder `stray-file`: a backup file beside the instrument.

#### 47. `crates/adapters/authoring/tests/fixtures/surveys/stale-and-orphaned/{instrument.yaml,layouts/compact.yaml,i18n/es.po}` (Create)

*   **Type / Scope**: Test fixture
*   **Proposed Changes**: Fixture folder `stale-and-orphaned`: an entry whose `msgid` differs from the current English text, and one whose `msgctxt` names a deleted item.

#### 50. `crates/adapters/authoring/tests/fixtures/surveys/no-catalogue/instrument.yaml` (Create)

*   **Type / Scope**: Test fixture
*   **Proposed Changes**: Fixture folder `no-catalogue`: `translations:` declares `es` and no `i18n/es.po` exists.

#### 51. `crates/adapters/authoring/tests/fixtures/surveys/missing-layout-id/{instrument.yaml,layouts/compact.yaml}` (Create)

*   **Type / Scope**: Test fixture
*   **Proposed Changes**: Fixture folder `missing-layout-id`: a titled step with no `id:`.

#### 54. `docs/reference/spec/instrument.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add INS-258 (a survey is one folder: `instrument.yaml`, `layouts/<window>.yaml`, `i18n/<lang>.po`; folder name equals `survey.name`; layout stem equals window), INS-259 (one catalogue per language holds instrument and layout texts, keyed by `msgctxt` in the grammar `instrument/<path>` and `layout/<window>/<authored id>`), INS-260 (translation report: missing, orphaned, stale, no catalogue; a stale entry is treated as missing at expansion), INS-261 (layout ids are authoring-only and never part of the signed document). Ids are provisional until this change assigns them.

**Housekeeping**: `crates/adapters/authoring/README.md`: Document the `survey`, `po` modules, `Finding` kinds, the `msgctxt` grammar, the rule that stale entries are treated as missing, and the tests; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 3: Remove XLIFF

*   **Goal**: Delete the XLIFF converter and the `instrument i18n extract|merge` verbs so `.po` is the only translation format. Resolved Decision 8.
*   **Depends on**: Phase 2 (the `.po` report replaces what `merge` checked).
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `cargo test -p fieldseal-cli`; `fieldseal conformance run` (the `ins-*` suites pass; INS-082 to INS-085 are still enforced by `instrument validate`).
    *   `grep -rniE 'xliff|\.xlf|i18n extract|i18n merge' crates docs/reference tools` returns nothing (the historical mentions are in ADRs 0034, 0039 and 0040 under `docs/explanation/adr/`, which the command does not search).
    *   `python3 tools/test-inventory.py --check` and `just test`.
*   **Security review**: None.

#### 56. `crates/apps/cli/src/i18n_cmd.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: Delete `xliff`, `parse_xliff`, `extract`, `merge`, the XML helpers, `run_i18n` and `localised_texts`/`get_mut`/`load_instrument_doc` where only they use them. Keep `run_localisation`, `catalogue` and `validate_catalogue` (`localisation validate`, PLAT-050, PLAT-053). Update the module comment.

#### 57. `crates/apps/cli/src/main.rs` (Modify)

*   **Type / Scope**: Rust module (CLI entry)
*   **Proposed Changes**: Remove the `["instrument", "i18n"]` arm.

#### 58. `crates/apps/cli/src/messages.rs` (Modify)

*   **Type / Scope**: Rust module (CLI strings)
*   **Proposed Changes**: Remove the strings used only by `extract` and `merge`: `merge-needs-xliff` (line 142) and `xliff-written` (line 143), and the two `instrument i18n` lines of the `usage` text (line 10).

#### 60. `docs/reference/spec/cli.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Delete the rows `instrument i18n extract <file>` and `instrument i18n merge <file> <xlf>…` (lines 76 and 77) and their requirement references.

#### 61. `docs/reference/spec/instrument.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: In the INS-082 to INS-084 text, say authors keep translations in `.po` catalogues; remove XLIFF 2.1 from the references line (line 706). The test table row for INS-082 to INS-086 stays (`instrument validate` over invalid fixtures).

#### 62. `docs/reference/authoring-audit.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Row 19 ("XLIFF unit ids are JSON Pointers"): reword the construct to "Translation unit ids are JSON Pointers" so that the row no longer contains the word the Phase 3 grep looks for, and mark it resolved by the removal of the XLIFF converter.

#### 63. `docs/explanation/adr/0034-internationalisation-and-localisation.md` (Modify)

*   **Type / Scope**: ADR note
*   **Proposed Changes**: Line 30 and line 55: add a note that XLIFF exchange was removed and `.po` is the single format (the link to ADR 0041 is added in Phase 5).

**Housekeeping**: `crates/apps/cli/README.md`: Remove the `instrument i18n` rows from the command list; state that `.po` is the translation format; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 4: Migration to survey folders (one commit)

*   **Goal**: Move the examples into `examples/surveys/<name>/`, give layouts authored ids, merge the two catalogue trees into one `.po` per language with `msgctxt` in the new grammar, and move every hard-coded loader to the resolver. Nothing signed changes. Technical Plan §5; Resolved Decisions 1 and 2.
*   **Depends on**: Phase 1 (golden set and schema) and Phase 2 (resolver). Phase 3 is not required but precedes it.
*   **Commits**: One commit containing the tree move, the `.po` rewrite, the loader changes, scenarios, scripts and doc paths, and nothing else. A one-off conversion script produces the `.po` and layout ids and is not committed.
*   **Gate** (must pass before the next phase starts):
    *   `just migration-gate`: instrument addresses, salted fingerprints under `pinned_salt` (entry 13), bound layout addresses and the expanded documents equal the golden set (the golden set is not in the diff: `git diff --stat HEAD~1 -- crates/apps/e2e/tests/golden` is empty).
    *   `python3 tools/check-example-paths.py` reports no old example path outside `docs/`.
    *   `just test` (all suites, 20 s budget) and `nix build path:.#checks.x86_64-linux.{clippy,tests,architecture}`.
    *   Revert rehearsal: `git worktree add ../fs-revert HEAD && cd ../fs-revert && git revert --no-edit HEAD && just migration-gate` passes on the reverted tree (the golden set is keyed by name, not path).
    *   `cargo test -p fieldseal-cli --test demo_pipeline` (runs `tools/demo-pipeline.sh` on the moved paths) and `just acceptance` once on this commit (the stack scripts changed paths).
*   **Security review**: None.

#### 65. `examples/surveys/household-water-access/instrument.yaml` (Create)

*   **Type / Scope**: Example (moved with git mv from `examples/instruments/household-water-access.yaml`)
*   **Proposed Changes**: Unchanged.

#### 66. `examples/surveys/school-meals-baseline/instrument.yaml` (Create)

*   **Type / Scope**: Example (moved with git mv from `examples/instruments/school-meals-baseline.yaml`)
*   **Proposed Changes**: Unchanged.

#### 67. `examples/surveys/household-water-access/layouts/compact.yaml` (Create)

*   **Type / Scope**: Example (moved with git mv from `examples/layouts/household-water-access.compact.yaml`)
*   **Proposed Changes**: `instrument:` becomes `../instrument.yaml`; every titled step and card gets an `id:`, nine in all: `household` (step "The household"), `who-lives-here` (its card), `water` (step "Water"), `the-source`, `use-and-treatment` and `cost` (its three cards), `sanitation-and-hygiene` (step "Sanitation and hygiene"), `the-toilet` and `hygiene` (its two cards); ids are dropped at expansion.

#### 68. `examples/surveys/school-meals-baseline/layouts/compact.yaml` (Create)

*   **Type / Scope**: Example (moved with git mv from `examples/layouts/school-meals-baseline.compact.yaml`)
*   **Proposed Changes**: `instrument:` becomes `../instrument.yaml`; ids added to titled steps and cards.

#### 69. `examples/surveys/school-meals-baseline/layouts/expanded.yaml` (Create)

*   **Type / Scope**: Example (moved with git mv from `examples/layouts/school-meals-baseline.expanded.yaml`)
*   **Proposed Changes**: `instrument:` becomes `../instrument.yaml`; ids added; the file stem `expanded` equals its `window`.

#### 70. `examples/surveys/household-water-access/i18n/es.po` (Create)

*   **Type / Scope**: Example (moved with git mv from `examples/instruments/i18n/household-water-access/es.po`)
*   **Proposed Changes**: Moved with `git mv`; `msgctxt` prefixed `instrument/`; the nine layout entries of `examples/layouts/i18n/household-water-access.compact/es.po` are appended as `layout/compact/<id>` (for example `steps.0` becomes `layout/compact/household`), each with its `msgid` and `msgstr` unchanged. One catalogue serves the instrument and its layout.

#### 548. `examples/surveys/school-meals-baseline/i18n/es.po` (Create)

*   **Type / Scope**: Example (moved with git mv from `examples/instruments/i18n/school-meals-baseline/es.po`)
*   **Proposed Changes**: `msgctxt` prefixed `instrument/`. The entries of `examples/layouts/i18n/school-meals-baseline.compact/es.po` are appended as `layout/compact/<id>`, and those of `examples/layouts/i18n/school-meals-baseline.expanded/es.po` (embedded today at `crates/apps/cli/src/device.rs:214` and `215`) as `layout/expanded/<id>`, each with its `msgid` and `msgstr` unchanged; the ids are the ones that entries 68 and 69 add. One catalogue serves the instrument and both layouts.

#### 71. `examples/rosters/cohort-a.yaml` (Create)

*   **Type / Scope**: Example (moved with git mv from `examples/rosters/school-meals-baseline.yaml`)
*   **Proposed Changes**: Renamed to its cohort (`cohort: cohort-a`). Content unchanged. A roster names only its cohort and version.

#### 72. `examples/rosters/village-a.yaml` (Create)

*   **Type / Scope**: Example (moved with git mv from `examples/rosters/household-water-access.yaml`)
*   **Proposed Changes**: Renamed to its cohort (`cohort: village-a`). Content unchanged, including `version: 3`.

#### 73. `examples/instruments/household-water-access.yaml` (Delete)

*   **Type / Scope**: Example (old location)
*   **Proposed Changes**: Removed by the move to `examples/surveys/household-water-access/instrument.yaml`.

#### 74. `examples/instruments/school-meals-baseline.yaml` (Delete)

*   **Type / Scope**: Example (old location)
*   **Proposed Changes**: Removed by the move to `examples/surveys/school-meals-baseline/instrument.yaml`.

#### 75. `examples/layouts/household-water-access.compact.yaml` (Delete)

*   **Type / Scope**: Example (old location)
*   **Proposed Changes**: Removed by the move to `examples/surveys/household-water-access/layouts/compact.yaml`.

#### 76. `examples/layouts/school-meals-baseline.compact.yaml` (Delete)

*   **Type / Scope**: Example (old location)
*   **Proposed Changes**: Removed by the move to `examples/surveys/school-meals-baseline/layouts/compact.yaml`.

#### 77. `examples/layouts/school-meals-baseline.expanded.yaml` (Delete)

*   **Type / Scope**: Example (old location)
*   **Proposed Changes**: Removed by the move to `examples/surveys/school-meals-baseline/layouts/expanded.yaml`.

#### 78. `examples/instruments/i18n/household-water-access/es.po` (Delete)

*   **Type / Scope**: Example (old location)
*   **Proposed Changes**: Removed by the move to `examples/surveys/household-water-access/i18n/es.po` (entry 70).

#### 549. `examples/instruments/i18n/school-meals-baseline/es.po` (Delete)

*   **Type / Scope**: Example catalogue (old location)
*   **Proposed Changes**: Removed by the move to `examples/surveys/school-meals-baseline/i18n/es.po` (entry 548).

#### 79. `examples/rosters/school-meals-baseline.yaml` (Delete)

*   **Type / Scope**: Example (old location)
*   **Proposed Changes**: Removed by the move to `examples/rosters/cohort-a.yaml`.

#### 80. `examples/rosters/household-water-access.yaml` (Delete)

*   **Type / Scope**: Example (old location)
*   **Proposed Changes**: Removed by the move to `examples/rosters/village-a.yaml`.

#### 81. `examples/layouts/i18n/household-water-access.compact/es.po` (Delete)

*   **Type / Scope**: Example catalogue (old location)
*   **Proposed Changes**: Its entries are appended to `examples/surveys/household-water-access/i18n/es.po` (entry 70) with the new `msgctxt` grammar.

#### 550. `examples/layouts/i18n/school-meals-baseline.compact/es.po` (Delete)

*   **Type / Scope**: Example catalogue (old location)
*   **Proposed Changes**: Its entries are appended to `examples/surveys/school-meals-baseline/i18n/es.po` as `layout/compact/<id>` (entry 548).

#### 551. `examples/layouts/i18n/school-meals-baseline.expanded/es.po` (Delete)

*   **Type / Scope**: Example catalogue (old location)
*   **Proposed Changes**: Its entries are appended to `examples/surveys/school-meals-baseline/i18n/es.po` as `layout/expanded/<id>` (entry 548).

#### 82. `examples/scenarios/{clear,connected-flow,household-water-access,school-meals-baseline}.yaml` (Modify)

*   **Type / Scope**: Example scenario
*   **Proposed Changes**: Replace `instrument: ../instruments/<name>.yaml` and `layouts: [../layouts/<name>.<window>.yaml]` with `survey: ../surveys/<name>` and `layouts: [<window>, ...]` (window names); update the usage comments. Two scenarios (`stack-capture.yaml`, `stack-capture-school-meals-baseline.yaml`) name no path and are unchanged.

#### 86. `examples/README.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Replace every command path with the folder form (`examples/surveys/school-meals-baseline`, `--layout .../layouts/expanded.yaml`); remove the warning against copying examples blindly and state the folder shape; list rosters by cohort.

#### 87. `crates/adapters/authoring/src/lib.rs` (Modify)

*   **Type / Scope**: Rust module (public API)
*   **Proposed Changes**: `decode_path` stops reading `i18n/<file stem>/<lang>.po`; for a file inside a survey folder it asks the resolver for the survey's catalogues. A file outside a folder decodes with no catalogue.

#### 88. `crates/adapters/authoring/src/compact.rs` (Modify)

*   **Type / Scope**: Rust module (expander)
*   **Proposed Changes**: Delete the positional-key fallback that Phase 2 kept for unmigrated layouts, together with the legacy `compact::parse_po` adapter, `compact::Catalogues` and `expand_with`, whose callers (`device.rs`, `col.rs` and `lib.rs`) all move to the resolver in this commit.

#### 90. `crates/adapters/memory/tests/common/mod.rs` (Modify)

*   **Type / Scope**: Test support
*   **Proposed Changes**: Line 82: load `examples/surveys/{name}/instrument.yaml` through `SurveyTree` instead of `decode_path(".../examples/instruments/{name}.yaml")`.

#### 91. `crates/apps/cli/build.rs` (Create)

*   **Type / Scope**: Cargo build script
*   **Proposed Changes**: Calls `fieldseal_adapters_authoring::survey::SurveyTree` over `../../examples/surveys` and writes `$OUT_DIR/embedded_surveys.rs`: a static table of (survey, file role, bytes) for scenarios, instruments, layouts and catalogues, used by `device simulate` and the conformance suite. Emits `cargo:rerun-if-changed=../../examples`. No source file names an example path.

#### 92. `crates/apps/cli/Cargo.toml` (Modify)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Add `[build-dependencies] fieldseal-adapters-authoring.workspace = true`. `tools/check-architecture.py` reads every dependency kind from `cargo metadata` and allows apps to depend on adapters (lines 40 to 51), so a build edge needs no change to the check.

#### 93. `crates/apps/cli/src/device.rs` (Modify)

*   **Type / Scope**: Rust module (CLI `device simulate`)
*   **Proposed Changes**: Replace the `include_str!` tables at lines 72 to 82 and the three-way catalogue branch at lines 207 to 215 (which also embeds `examples/layouts/i18n/school-meals-baseline.expanded/es.po` at lines 214 and 215) with `include!(concat!(env!("OUT_DIR"), "/embedded_surveys.rs"))`; scenarios use `survey:` and window names; the `.po` is read from the embedded survey, whose single catalogue now holds the expanded layout's entries too (entry 548).

#### 94. `crates/apps/cli/src/conformance_cmd/col.rs` (Modify)

*   **Type / Scope**: Rust module (conformance)
*   **Proposed Changes**: Replace `include_bytes!`/`include_str!` at lines 39 to 47 and the `example("instruments/...")` calls at lines 123, 124 and 225 with the embedded table; the `"household-water-access.compact"` layout name becomes the window `compact` of `household-water-access`.

#### 95. `crates/apps/cli/src/commands.rs` (Modify)

*   **Type / Scope**: Rust module (CLI `instrument`/`layout`)
*   **Proposed Changes**: `load_layout` resolves `spec.instrument` through the resolver when the layout sits in a survey folder, and by relative path otherwise. `instrument` and `layout` verbs accept a survey folder.

#### 97. `crates/apps/e2e/src/lib.rs` (Modify)

*   **Type / Scope**: Test support library
*   **Proposed Changes**: `examples()` points at the survey root; `example(path)` becomes `survey(name) -> LoadedSurvey` through the resolver; `sample_instrument_document` and the layout lines (lines 83, 84, 161) use it. `survey_sources` from Phase 1 is deleted.

#### 98. `crates/apps/e2e/tests/migration_gate.rs` (Modify)

*   **Type / Scope**: Integration test (migration gate)
*   **Proposed Changes**: Only the loader changes: surveys come from the resolver. The golden set and the assertions are unchanged. Add `ins_258_no_hard_coded_loader_names_an_old_example_path`: it shells out to `tools/check-example-paths.py` and reports `skipped` (and passes) when `python3` or the script is missing. The script is outside the Nix source set, so the test skips in `checks.tests`; `just test` runs the script directly (entry 110).

#### 99. `crates/apps/web/src/catalogue.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Find surveys and layouts through `SurveyTree`. Find a survey's roster by cohort, because the rosters are named by cohort from this phase: the code at `catalogue.rs:129` looked for `rosters/<survey>.yaml`, which no longer exists. It opens `RosterSet::open(<root>/rosters)` and reads the map `survey=cohort,...` from `FIELDSEAL_WEB_SURVEY_COHORTS` (entry 103); a survey with no entry in the map has no roster. A survey that fails to load keeps its `ResolveError` in the catalogue instead of a terminal warning; today it is dropped silently (`catalogue.rs:123,136`).

#### 101. `crates/apps/web/src/stack.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: `ROSTERS` keeps its mount point. In `bundle()` the loop at lines 89 to 91 passes every entry of the roster directory to `--roster`; it now passes only files (`*.yaml`, `*.yml`, `*.json`), so `examples/rosters/next/` (Phase 9) is not passed as a roster. `surveys()` (lines 25 to 35) lists the `*.published` files in `/published` by file name, and `tools/stack-demo.sh` names each file after its survey, so it stays as it is in this phase; it does not use the resolver.

#### 103. `crates/apps/web/src/main.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Help text and the module table: `FIELDSEAL_WEB_EXAMPLES_DIR` is a directory with `surveys/` and `rosters/`. New variable `FIELDSEAL_WEB_SURVEY_COHORTS` (`survey=cohort,...`; default none): which cohort's roster a survey's pages use until assignments replace the map (Phase 12). The factory's own `cohorts` string (`cohort:generation` pairs) is a different setting and is not used for this.

#### 104. `crates/apps/web/tests/parity.rs` (Modify)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Line 64 and the `read_dir(examples/layouts)` call at line 66 use `SurveyTree`.

#### 105. `crates/apps/web/tests/browser_constraints.rs` (Modify)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: There is no `read_dir` walk in this file: it builds `AppState { examples_dir: examples() }` (line 48) and fetches the stand-in's pages, so entry 99 is what it exercises. Rename the leftover `food` locals and the `food.html` name (lines 51 and after) to `meals`.

#### 106. `crates/adapters/web-demo/src/content.rs` (Modify)

*   **Type / Scope**: Rust module (removed in Phase 16c)
*   **Proposed Changes**: Minimal change so the demo and its tests still load: walk `surveys/*/` through `SurveyTree`, and find each survey's roster by cohort with a fixed map in the code (`school-meals-baseline` to `cohort-a`, `household-water-access` to `village-a`) instead of `rosters/<survey>.yaml` (line 82). The crate is deleted in Phase 16c, so no further work is put in.

#### 107. `crates/adapters/web-demo/src/lib.rs` (Modify)

*   **Type / Scope**: Rust module (removed in Phase 16c)
*   **Proposed Changes**: Doc comment of `DemoConfig` at line 123 names the survey layout.

#### 108. `crates/contexts/instrument/tests/support/layouts.rs` (Modify)

*   **Type / Scope**: Test support
*   **Proposed Changes**: Comments at lines 45 and 119 name `examples/surveys/school-meals-baseline/...`. The synthetic `instrument: "../instruments/school-meals-mini.yaml"` string at line 128 is not an example path and stays.

#### 109. `tools/check-example-paths.py` (Create)

*   **Type / Scope**: Repository check
*   **Proposed Changes**: Scans files with the extensions `.rs`, `.sh`, `.py`, `.yaml`, `.yml`, `.nix`, `.toml`, `.json` and the `justfile` (Markdown and itself are excluded) and fails if one names `examples/instruments/`, `examples/layouts/`, a `*.compact.yaml` or `*.expanded.yaml` of an example, `instruments/<survey>.yaml` for a survey in `examples/surveys/`, or an `examples/**/i18n/` path outside a survey folder. Exit 1 with `file:line`. Run by `just test`; not run in the Nix `architecture` check because it needs files outside the Nix fileset.

#### 110. `justfile` (Modify)

*   **Type / Scope**: Build configuration
*   **Proposed Changes**: `test` runs `python3 tools/check-example-paths.py` after the inventory check.

#### 111. `tools/stack-engine.sh` (Modify)

*   **Type / Scope**: Shell library
*   **Proposed Changes**: Add `SURVEYS="$ROOT/examples/surveys"` and `ROSTERS="$ROOT/examples/rosters"`: the only place the root names are written for scripts.

#### 112. `tools/stack-demo.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: All paths below are read inside the container, where `EX` is `/opt/fieldseal/examples`. `publish_artefact` (lines 49 to 52 and 58): the caller passes `$EX/surveys/<name>/instrument.yaml` (the function runs `cat "$file"`, so a folder cannot be passed); for a survey it copies the file to `instrument.yaml` and the catalogues `$(dirname "$file")/i18n/*.po` to `i18n/<lang>.po` in `$W/publish/$name`, which is then a survey folder whose name equals `survey.name`, and the `artefact provenance` call (line 58) names `instrument.yaml`; the policy keeps `$name.yaml`. Lines 94 and 96: the two `publish_artefact` calls take the `instrument.yaml` paths. Line 146: `--roster "$EX/rosters/cohort-a.yaml" --roster "$EX/rosters/village-a.yaml"`. Line 187: `intake contract "$EX/surveys/$SURVEY/instrument.yaml"`. Line 260: `layout="$EX/surveys/$name/layouts/compact.yaml"`. The comment at lines 45 and 46 describes the folder form.

#### 113. `tools/demo-pipeline.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Lines 100, 101, 129, 163 and 165: survey folder paths; the copied `i18n/water` directory becomes the survey's `i18n/`.

#### 114. `tools/release-docs.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Lines 25 and 26: `--instrument "$ROOT/examples/surveys/school-meals-baseline"` and `--instrument "$ROOT/examples/surveys/household-water-access"`.

#### 115. `tools/browser-tests/wcag.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Change lines 13 and 14 of `wcag.sh`: the `instrument preview` calls take `examples/surveys/<name>/instrument.yaml` and `--layout examples/surveys/<name>/layouts/<window>.yaml`.

#### 116. `flake.nix` (Modify)

*   **Type / Scope**: Nix flake
*   **Proposed Changes**: Comment at line 508: `nix run path:.#fieldseal -- instrument validate examples/surveys/school-meals-baseline/instrument.yaml`. The `./examples` filesets at lines 101, 204 to 208 and 276 to 281 already include the new tree; no code change. `deploy/local/compose.yaml` refers to the examples only through the manifest and the image, apart from the stand-in's cohort map (entry 556); the repository check confirms both.

#### 556. `deploy/local/compose.yaml` (Modify)

*   **Type / Scope**: Compose file
*   **Proposed Changes**: Add `FIELDSEAL_WEB_SURVEY_COHORTS: "school-meals-baseline=cohort-a,household-water-access=village-a"` to the `web` service environment, beside `FIELDSEAL_WEB_STACK` (line 182), so the stand-in finds each survey's roster by cohort (entry 99).

#### 117. `README.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Example paths in the quick-start commands use the survey folders.

#### 120. `docs/tutorials/hands-on.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Line 166 names `examples/scenarios/stack-capture-school-meals-baseline.yaml`, which does not move, so it stays. Change every command in the tutorial that names an instrument, layout or catalogue path to the survey-folder form.

#### 121. `docs/how-to/use-the-web-app.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Directory description: `surveys/<name>/` and `rosters/<cohort>.yaml`.

#### 122. `docs/how-to/run-the-local-stack.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Change the example paths in the walkthrough text to the survey-folder form.

#### 123. `docs/explanation/adr/0036-showcase-web-app-and-web-device.md` (Modify)

*   **Type / Scope**: ADR note
*   **Proposed Changes**: Path mentions updated to the survey folders (the reasoning is unchanged).

#### 124. `docs/reference/authoring-audit.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: The audit has no row named for the two catalogue trees. Row 1 ("Inline translations", fix: per-locale PO catalogues) is now fully resolved by one catalogue per language per survey: mark it resolved. Row 20 (header envelope per file) stays open.

**Housekeeping**: `crates/apps/e2e/README.md`: Describe the migration gate test and the golden directory; `crates/apps/web/README.md`: `FIELDSEAL_WEB_EXAMPLES_DIR` layout and the resolver error display.

### Phase 5: Authoring CLI, tutorial and ADR 0041

*   **Goal**: Give a newcomer `fieldseal new survey`, `fieldseal survey check|list`, `fieldseal schema export|check --kind survey`, a tutorial, the reference table of which file holds each setting, and the design record that replaces ADR 0039. Technical Plan §3 (docs) and §4; Resolved Decisions 5, 6, 7 and 16.
*   **Depends on**: Phase 4 (the examples are folders and the resolver is the one lookup path).
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `cargo test -p fieldseal-cli --test survey_cli` (a scaffold passes `survey check` with no errors).
    *   `fieldseal survey check examples/surveys/household-water-access --roster examples/rosters/village-a.yaml --strict` exits 0; the same for `school-meals-baseline` with `examples/rosters/cohort-a.yaml`.
    *   `fieldseal schema export --kind survey` run twice gives identical bytes and the same content address; the editor schema accepts every example (Phase 1 differential test).
    *   Timed run of the tutorial by the test newcomer of Open Question 1: the time from `new survey` to a passing `survey check` is written into `docs/explanation/build-system.md` beside the target. The publish step and its time belong to Phase 5b.
    *   `just test`.
*   **Security review**: None.

#### 125. `crates/apps/cli/src/new_cmd.rs` (Create)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: `fieldseal new survey <name> [--lang es,...] [--root <dir>]` (`--root` defaults to `surveys`). Writes `<root>/<name>/instrument.yaml` (schema header `# yaml-language-server: $schema=../.fieldseal/survey.schema.json`, one list with explicit `code:` on every item, a few items, the `survey:` header), `layouts/compact.yaml` with `id:` on each step and card and the header `# yaml-language-server: $schema=../../.fieldseal/layout.schema.json`, `i18n/<lang>.po` stubs with every `msgid` filled and `msgstr` empty, a `README.md` that maps each file to its role and says where deployments and policies live, `<root>/.fieldseal/survey.schema.json` and `<root>/.fieldseal/layout.schema.json` (same bytes as `schema export --kind survey|layout --out`), and a roster stub `<root>/../rosters/<name>-cohort.yaml` (cohort `<name>-cohort`) outside the publishable folder. Refuses to overwrite. The flag table (valued `--lang`, `--root`) is declared in this module, in the way `crates/apps/cli/src/commands.rs:60–71` declares its own; `--lang` is already in `REPEATABLE` (`args.rs:21`).

#### 126. `crates/apps/cli/src/survey_cmd.rs` (Create)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: `fieldseal survey check <dir> [--roster <file>] [--strict] [--json]` runs in one pass and one findings list: resolver checks, decode and schema validation with spans, `instrument validate` and `lint`, `layout validate` and `lint`, and the translation report. Exit 1 on any error (CLI-005). `--strict` turns warnings into errors. `fieldseal survey list [--root <dir>]` prints name, version, languages, layout windows. The flag tables (valued `--roster`, `--root`; switches `--strict`, `--json`) are declared in this module; `--roster` is already in `REPEATABLE`.

#### 127. `crates/apps/cli/src/roster_check.rs` (Create)

*   **Type / Scope**: Rust module (CLI, shared)
*   **Proposed Changes**: `compare_roster(roster: &Roster, instrument: &Value) -> Vec<Finding>`. The roster is parsed by `bundle_cmd::parse_roster` (`bundle_cmd.rs:127`, made `pub(crate)` for this module); the instrument is the expanded document (`LoadedSurvey.instrument`). The fields the instrument reads come from `fieldseal_distribution::domain::collect_roster_fields` (entry 561), which reads every text of the document, so a field read through a message variable or a `type: roster` item counts, not only the fields that rules reference. A field the instrument reads that a subject's `attributes` lack is an error naming the field and the subject's ordinal, not its id (for example `head_name` missing for subject 2); a field in `Roster::field_names()` that no instrument reads is a note (the builder drops it, DIS-013). Used by `survey check --roster` here and by `roster check` in Phase 9.

#### 561. `crates/contexts/distribution/src/domain/facts.rs` and `crates/contexts/distribution/src/domain/mod.rs` (Modify)

*   **Type / Scope**: Rust module (Distribution context)
*   **Proposed Changes**: Make `collect_roster_fields(value: &Value, out: &mut BTreeSet<String>)` (`facts.rs:80–91`) `pub` and add it to the `pub use facts::{..}` list at `domain/mod.rs:20`. It is the function `instrument_facts` already uses (`facts.rs:67–107`), so `survey check`, `roster check` and the bundle builder read the same set of roster fields. `CompiledRule::roster_refs` (`compiled.rs:197`) is not used for this, because it holds only the fields that rules reference. Unit test in the crate: `dis_013_roster_fields_read_through_message_variables_and_roster_items_are_found`.

#### 128. `crates/apps/cli/src/schema_cmd.rs` (Create)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: `schema export --kind survey|layout [--out <path>] [--version <v>]`. The text is `schema_text(kind: DocKind) -> String` in this module: `crate::json::pretty(&fieldseal_kernel::schema::json_schema(kind))` (object keys in sorted order, two-space indent, no trailing spaces) followed by exactly one `\n`. The content address is `sha256:` and the lowercase hex of the SHA-256 of exactly those bytes (`fieldseal_kernel::digest::sha256`, WIRE-209, CLI-041). Without `--out`, the command prints the text and then a line `address: sha256:<hex>`; with `--json` it prints one document holding both. With `--out` the file holds the schema text alone, byte for byte, so the scaffold's copies (entry 125) are identical to it. `--version <v>` (already in the `cli.md:87` row) is accepted when it equals the schema's own version (`1.0.0`) and refused with exit 2 otherwise. `--kind survey` covers `instrument.yaml` and `--kind layout` covers `layouts/*.yaml`. `schema check <file>` validates one source file against the schema of its kind. Implements the two rows at `docs/reference/spec/cli.md` lines 87 and 88 for the kinds `survey` and `layout`; the flag table (valued `--kind`, `--out`, `--version`) is declared in this module.

#### 129. `crates/apps/cli/src/main.rs` (Modify)

*   **Type / Scope**: Rust module (CLI entry)
*   **Proposed Changes**: Add `mod new_cmd; mod survey_cmd; mod schema_cmd; mod roster_check;` and arms `["new", "survey"]`, `["survey", verb]`, `["schema", verb]`.

#### 131. `crates/apps/cli/src/messages.rs` (Modify)

*   **Type / Scope**: Rust module (CLI strings)
*   **Proposed Changes**: Messages for the new commands and their findings.

#### 132. `crates/apps/cli/tests/survey_cli.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Cases: `cli_044_a_scaffold_passes_survey_check_with_no_errors`, `cli_044_a_scaffold_refuses_to_overwrite`, `cli_044_scaffold_pins_answer_codes`, `cli_045_survey_check_reports_file_line_and_column`, `cli_045_survey_check_roster_flags_a_missing_field_as_an_error`, `cli_045_survey_check_roster_notes_an_unused_field`, `cli_045_strict_turns_warnings_into_errors`, `cli_045_json_output_lists_findings`, `cli_046_survey_list_names_every_example`, `cli_041_schema_export_is_deterministic_and_addressed`, `cli_044_the_scaffold_headers_point_at_the_exported_survey_and_layout_schemas`, `ins_260_a_stale_translation_is_listed_with_old_and_new_text`.

#### 134. `docs/reference/spec/cli.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add rows for `new survey`, `survey check`, `survey list`; the kinds `survey` and `layout` in the two `schema` rows (`schema export` already has `--version` at `cli.md:87`); requirements CLI-044 (scaffold passes `survey check` and pins codes), CLI-045 (`survey check` runs validation, lint, layout checks and the translation report in one pass; roster comparison) and CLI-046 (`survey list`). `schema export` is covered by the existing CLI-041 (deterministic and addressed by content), which this plan cites and does not duplicate. Ids provisional.

#### 135. `docs/explanation/adr/0041-survey-source-tree-and-authoring-toolchain.md` (Create)

*   **Type / Scope**: ADR
*   **Proposed Changes**: "Survey source tree and authoring toolchain". Decides: the folder shape and the one home file per setting; `.po` as the only translation format with `msgctxt` grammar and stale-as-missing; authored layout ids; the declarative schema module in the format core and the generated editor schema; address-preserving migration with the migration gate; rosters name only cohort and version; deployments and policies stay outside survey folders. Supersedes ADR 0039 and takes over ADR 0040 sections 2 and 3; sections 4 and 5 of ADR 0040 stay a separate decision. Status Proposed.

#### 136. `docs/explanation/adr/0039-authoring-language-and-developer-experience.md` (Modify)

*   **Type / Scope**: ADR
*   **Proposed Changes**: Status line: Superseded by ADR 0041.

#### 137. `docs/explanation/adr/0040-compact-declarations-and-twelve-factor-config.md` (Modify)

*   **Type / Scope**: ADR note
*   **Proposed Changes**: Add a note that sections 2 and 3 are taken over by ADR 0041 and sections 4 and 5 remain open.

#### 138. `docs/explanation/adr/0034-internationalisation-and-localisation.md` (Modify)

*   **Type / Scope**: ADR note
*   **Proposed Changes**: Link the removal note added in Phase 3 to ADR 0041.

#### 139. `docs/explanation/adr/README.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Add the ADR 0041 row; mark the 0039 row superseded.

#### 140. `docs/tutorials/write-and-publish-your-first-survey.md` (Create)

*   **Type / Scope**: Tutorial
*   **Proposed Changes**: "Write and publish your first survey". Steps: `fieldseal new survey my-survey --lang es`; the folder tour; edit the instrument; `survey check` until clean; read an error with its position; change English text and see a stale translation; ends with a pointer to the publish section that Phase 5b adds (entry 534). Written for a reader who has not read the ADRs.

#### 141. `docs/reference/survey-folder.md` (Create)

*   **Type / Scope**: Reference
*   **Proposed Changes**: The table of which file holds each setting: content, rules and lists in `instrument.yaml`; presentation in `layouts/<window>.yaml`; translated text in `i18n/<lang>.po`; cohort and version in `rosters/<cohort>.yaml`; deployments and policies outside; the `msgctxt` grammar; the findings and their meaning.

#### 142. `docs/index.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Replace "Tutorials: None yet" with links to `tutorials/hands-on.md` and `tutorials/write-and-publish-your-first-survey.md`; add `reference/survey-folder.md`.

#### 143. `examples/README.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Point to the tutorial and the folder reference.

#### 144. `docs/explanation/build-system.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Record the time from `new survey` to a passing `survey check` (Phase 5) and, from Phase 5b, the time from there to the published address, for the test newcomer, against the targets (Open Question 1).

**Housekeeping**: `crates/apps/cli/README.md`: Add the new commands, exit codes and the shared roster check; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 5b: First `just web`: the dev loop on the services that exist

*   **Goal**: Give a developer the container-free edit-and-reload loop early, before every service exists. `just web` runs `fieldseal-translog`, `fieldseal-factory` and the collector stand-in `fieldseal-web` (in stack mode) natively from a rendered deployment manifest, publishes the bundled examples through the log, and the collector stand-in re-reads survey files on every request. `just publish <survey>` publishes a survey that an author made, which is the last step of the tutorial. Each later phase adds its own service to `tools/dev-web.sh`. The Instruments page keeps the last good version of a survey and shows the resolver error beside it (entries 100 and 102), and the Publishing page lists the artefacts in the CLI's artefact registry (entry 554). Technical Plan §8; Resolved Decisions 13 and 14.
*   **Depends on**: Phase 5 (survey folders, the resolver and the tutorial). It uses only binaries that exist before this plan.
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `just web` starts the three processes, publishes the bundled instruments, layouts and policy, prints the URLs and the note about the development identity (the factory's `FIELDSEAL_IDENTITY=dev` sign-in), and `Ctrl-C` stops them all. With port 8080 already taken, it exits with a message that names the port and starts nothing.
    *   `fieldseal new survey my-survey` then `just publish my-survey` shows the artefact (name, version, kind, address and log index) on the Publishing page of the collector stand-in and a new log entry; a second `just publish my-survey` of the same name and version is refused by the artefact registry, with a message that says the version is taken and tells the author to raise `survey.version`. The time from a passing `survey check` to the published address is written into `docs/explanation/build-system.md` beside the target of Open Question 1.
    *   `tools/dev-web.sh --check`: validates and renders the manifest, waits for each service to answer (the log's `/checkpoint`, because the log has no `/healthz`; the factory's `/healthz`; the stand-in's `/healthz`), and runs the edit check: change a question label in `examples/surveys/household-water-access/instrument.yaml`, request `/instruments/household-water-access`, see the new label with no restart, then break the file and see the last good version plus the resolver error with file, line and column; restore the file.
    *   `just lint` covers `tools/dev-web.sh` (shellcheck); `just test`.
*   **Security review**: None. The factory runs its existing development identity (`FIELDSEAL_IDENTITY=dev`), which production refuses at start-up.

#### 418. `tools/dev-web.sh` (Create)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: `just web` entry, first version. The script does these steps in order:
    1.  Checks that ports 8080, 8090 and 9001 are free and exits with a message that names the port when one is taken (later phases add 8180, 8480 and 8481). `just web` and `just up` cannot run at the same time, because they use the same ports.
    2.  Builds the CLI once (`FIELDSEAL_BIN="$(tools/stack-cli.sh)"`, exported), so that `tools/stack-init.sh` and `tools/dev-publish.sh` use that binary.
    3.  Runs `fieldseal deployment validate examples/deployments/dev-web.yaml`, then `deployment render --environment development` into `deploy/local/.state/dev-web/env/`. The rendered environment is the only configuration the services read (DEP-012).
    4.  Creates the authority once with `tools/stack-init.sh` and `FIELDSEAL_AUTHORITY_DIR=deploy/local/.state/dev-web/authority`.
    5.  Starts `fieldseal-translog` (`:9001`; its bind address, directory, origin and key file come from the `publishing` component of the manifest) with `cargo run -p ...` and its rendered env file, waits for `/checkpoint` (the log has no `/healthz`), and runs `tools/dev-publish.sh --all` (entry 419), so the bundled instruments, layouts and policy are published before any later step needs them.
    6.  Starts `fieldseal-factory` (`:8080`) the same way and waits for `/healthz` (DEP-053). The factory uses its existing `FIELDSEAL_IDENTITY=dev` identity, which production refuses, and reads its cohorts from the manifest.
    7.  Starts `fieldseal-web` with `FIELDSEAL_WEB_STACK=true` on `127.0.0.1:8090`, `FIELDSEAL_WEB_AUTHORITY_DIR`, `FIELDSEAL_WEB_REGISTRY_DIR=deploy/local/.state/dev-web/cli/registry` (entry 554), `FIELDSEAL_WEB_SURVEY_COHORTS` (entry 103) and the URLs of the services. The collector stand-in is on `127.0.0.1` and the services on `localhost`, so cookies are not sent to the stand-in.
    8.  Prints the URLs and a note that the sign-in is the factory's development identity (`FIELDSEAL_IDENTITY=dev`), writes each process's stderr to `deploy/local/.state/dev-web/logs/<service>.log`, and stops everything on exit.

    `--check` runs the checks listed in the gate. The script sets `FIELDSEAL_ENVIRONMENT=development` for every process. Later phases add their service or step to this script (entries 502 to 505) and Phase 16b completes it (entry 506).
*   **Known limits in this phase**: the collector stand-in still builds bundles through the CLI with the container paths that only the stack has (removed in Phase 14), so the Device page's device and bundle steps do not work under `just web` until Phase 14. The stand-in has no upload target (the intake app arrives in Phase 10). The factory uses the schema-default policy (it reads the published `deployment-policy` artefact and `factory.release.layouts` only from Phase 13) and does not yet read the artefact registry (`FIELDSEAL_FACTORY_REGISTRY_DIR` arrives in Phase 12).

#### 420. `examples/deployments/dev-web.yaml` (Create)

*   **Type / Scope**: Deployment manifest
*   **Proposed Changes**: `local-stack.yaml` with these differences: no `intake` component yet (entry 502 adds it), directories under `deploy/local/.state/dev-web/` (relative to the repository root, where `tools/dev-web.sh` starts every process) instead of volumes, the `127.0.0.1` bind addresses of the processes that run natively, and the factory's identity is the `memory-dev` adapter (`FIELDSEAL_IDENTITY=dev`) instead of `oidc`. Later phases add the intake component (entry 502), switch the identity provider to `oidc` at `http://localhost:8180/realms/fieldseal`, the issuer the stack's Keycloak uses (entry 503), and drop the `cohorts` string (entry 504). The file in full:

    ```yaml
    apiVersion: fieldseal.dev/v1alpha1
    kind: Deployment
    metadata:
      name: dev-web
      schemaVersion: 1.0.0
    spec:
      authority:
        displayName: Dev Web Authority
        trustBundle: { ref: trust/development-root, channel: development }
      registries:
        artefacts: { url: "http://localhost:9000", transparencyLog: "http://localhost:9001" }
        builds: { container: "localhost/fieldseal", runtime: "http://localhost:9002" }
      policies:
        layers:
          - { ref: policy/deployment-default, digest: "sha256:e2a2c86e21517b946eb84d13c5ec14bfe396227e2955a21fb0c842eef1b50dcb" }
      instruments:
        - { ref: instrument/school-meals-baseline, channel: development }
        - { ref: instrument/household-water-access, channel: development }
      components:
        factory:
          bind: "127.0.0.1:8080"
          adapters:
            # The development identity: the factory runs FIELDSEAL_IDENTITY=dev (memory-dev).
            # Entry 503 switches this to `oidc` against the development IdP.
            IdentityProvider: { adapter: memory-dev, config: {} }
            # The authority that tools/stack-init.sh creates (development custody: files).
            Signer:
              adapter: file-dev
              config:
                dir: deploy/local/.state/dev-web/authority/online
                trustBundle: deploy/local/.state/dev-web/authority/trust-bundle.bundle
            # The render writes FIELDSEAL_ALLOW_UNATTESTED=true for this adapter (REG-017, non-production only).
            AttestationVerifier: { adapter: software, config: {} }
            PolicyEngine: { adapter: built-in, config: {} }
            # Entry 504 removes `cohorts` when `roster assign` exists.
            TenancyRegistry: { adapter: file-dev, config: { dir: deploy/local/.state/dev-web/factory, cohorts: "cohort-a:1,village-a:1" } }
          scaling: { replicas: 1 }
        publishing:
          bind: "127.0.0.1:9001"
          adapters:
            TransparencyLog:
              adapter: translog
              config:
                origin: "fieldseal.local/log"
                dir: deploy/local/.state/dev-web/log
                keyFile: deploy/local/.state/dev-web/authority/translog.key
            Signer: { adapter: memory, config: {} }
      runtime:
        provisioning:
          factoryUrl: "http://localhost:8080"
          destinationUrl: "http://localhost:8480"
          platforms:
            android: { management: self-managed, deviceOwner: fieldseal, lockTask: false }
      environments:
        development: {}
    ```

#### 421. `tools/stack-init.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: `A="${FIELDSEAL_AUTHORITY_DIR:-/authority}"`; `FS="${FIELDSEAL_BIN:-fieldseal}"`. Behaviour in the container is unchanged.

#### 423. `deploy/local/.gitignore` (Modify)

*   **Type / Scope**: Ignore file
*   **Proposed Changes**: Add `/.state/`.

#### 424. `crates/apps/web/src/stack.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: The authority path comes from `FIELDSEAL_WEB_AUTHORITY_DIR` (default `/authority`). `surveys()` (lines 25 to 35) also skips file names that end in `.layout`, because `tools/dev-publish.sh` publishes each layout as `<survey>.<window>.layout.published` into the directory the stand-in lists (entry 419). The artefact registry directory comes from `FIELDSEAL_WEB_REGISTRY_DIR` (default none; entry 554).

#### 425. `crates/apps/web/src/main.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Read `FIELDSEAL_WEB_AUTHORITY_DIR` and `FIELDSEAL_WEB_REGISTRY_DIR`; document both in the module table and the help text.

#### 554. `crates/apps/web/src/publishing.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: In stack mode (`state.stack` is set) the Publishing page lists the published artefacts above the checkpoint it shows today (`publishing.rs:21,42–57`, which in stack mode shows only the log checkpoint): one row per `*.publication` file in the directory `FIELDSEAL_WEB_REGISTRY_DIR`, with name, version, kind, address and log index, sorted by log index. It reads each file with `fieldseal_publishing::domain::Publication::decode` (the stand-in already depends on `fieldseal-publishing`; `FileRegistry` stays private to the CLI until Phase 8), takes the log index from the `leaf_index` of the inclusion proof of the publication's first `LogRecord`, and shows an empty list with a note when the directory is unset or empty. A file that does not decode is listed as unreadable with its file name. Test in `crates/apps/web/tests/`: `web_140_the_publishing_page_lists_the_artefacts_of_the_registry_directory` (WEB-140 asks the page to show each published artefact).

#### 100. `crates/apps/web/src/instruments.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Show the resolver error (file, line, column) on the Instruments page for a survey that fails to load, with the last good version when the cache holds one. The cache is in memory only: after a restart whose first load of a survey is invalid, the page shows the error alone.

#### 102. `crates/apps/web/src/state.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Doc comment of `examples_dir`: a directory with `surveys/` and `rosters/`. Add the last-good cache: a map from survey name to its last successfully loaded `LoadedSurvey`, held as `Arc<Mutex<..>>` because `AppState` derives `Clone` and `Default`, replaced on each successful load and left alone by a failed one.

#### 419. `tools/dev-publish.sh` (Create)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: `tools/dev-publish.sh <survey>|--all`, behind `just publish` and called by `tools/dev-web.sh`. It adds no behaviour the CLI lacks: it prints and runs, unchanged, the verbs of `publish_artefact` in `tools/stack-demo.sh` (`artefact provenance`, `artefact sign` for two of three publisher keys, `artefact publish`).
    *   **Environment**: `FIELDSEAL_BIN` (the CLI that `tools/dev-web.sh` built first; run alone through `just publish`, the script builds it with `tools/stack-cli.sh`). `FIELDSEAL_ADAPTERS=files` (the CLI adapter set that keeps the artefact registry in files; `memory` is the default). `FIELDSEAL_STATE_DIR=deploy/local/.state/dev-web/cli`, so the artefact registry directory is `<state>/registry` (the stand-in's Publishing page reads it as `FIELDSEAL_WEB_REGISTRY_DIR`, entry 554, and the factory reads it as `FIELDSEAL_FACTORY_REGISTRY_DIR` from Phase 12). `FIELDSEAL_TRANSLOG_URL` (the log of `just web`, instead of the CLI's local file log). `FIELDSEAL_POLICY` (the policy of entry 533). `FIELDSEAL_TRUST_BUNDLE` (the authority's). `FIELDSEAL_SIGNER` set per verb to the authority's builder and publisher key directories, as `publish_artefact` sets it. When `FIELDSEAL_INTAKE_PUBLISHED_DIR` is set, each `*.published` file is also copied there.
    *   **Behaviour**: `<survey>` is a survey name, looked up in `surveys/` and then in `examples/surveys/`, or a survey folder. For the instrument the script draws a random 32-byte salt from `/dev/urandom` (it pins nothing, as ADR 0027 requires), passes it as `--salt`, and keeps it in `<state>/dev-publish/<name>-<version>.salt` once the publication succeeds, because no CLI command prints the salt of a publication. Provenance takes `--reviewers` as `publish_artefact` does: one general reviewer and, for each language other than the default that the instrument declares (INS-083), one reviewer who holds it (`reviewer-<lang>:<lang>`). It then publishes each layout (kind Layout) with `artefact provenance <layout> --instrument <the survey's instrument.yaml> --salt <that salt>`, so the layout binds to the fingerprint just published and the factory's default `factory.release.layouts: bound` (from Phase 13) finds it. The published files are named `<survey>.published` for the instrument, `<survey>.<window>.layout.published` for a layout and `deployment-policy.published` for the policy. `--all` does this for every survey under `examples/surveys/` and then publishes the policy `examples/deployments/policy/dev-web-publishing.yaml`; an artefact whose salt file exists is already published and is skipped, as `publish_artefact` skips it. A layout of an already published instrument is published with the salt from the file.
    *   **Refusals and events**: publishing a survey name and version that is already published through `just publish <survey>` is refused by the CLI's artefact registry (`VersionTaken`); the script prints that refusal, adds that the author must raise `survey.version`, and exits 1. If the instrument is in the registry but its salt file is missing (the state directory was edited by hand), the script stops with a message that says so and does not publish its layouts. A failed CLI verb stops the script with that verb's exit code.

#### 422. `justfile` (Modify)

*   **Type / Scope**: Build configuration
*   **Proposed Changes**: Recipe `publish survey=""`: with no argument it runs the existing walkthrough step (`tools/stack-run.sh publish`); with a survey name it runs `tools/dev-publish.sh <survey>`. A `just --list` comment explains both. Extend `lint` to `tools/dev-publish.sh`.

#### 501. `justfile` (Modify)

*   **Type / Scope**: Build configuration
*   **Proposed Changes**: Recipe `web`: `tools/dev-web.sh`, with a `just --list` comment. Extend `lint` to `tools/dev-web.sh`.

#### 533. `examples/deployments/policy/dev-web-publishing.yaml` (Create)

*   **Type / Scope**: Example policy (deployment layer)
*   **Proposed Changes**: The publishing policy that `just web` publishes at start-up and that the CLI checks every publication against. Its publishing values are those that `publish_all` in `tools/stack-demo.sh` writes inline for the stack (lines 76 to 92); the values the stand-in needs in stack mode (`BUILDER` and `SOURCE`, `crates/apps/web/src/stack.rs:20–21`) are the same two URLs, so these are the single source for all three. Kinds not listed under `requiredApprovals` and `publisherThreshold` take the schema defaults (2 approvals, a threshold of 2 of 3), which covers kind Layout. It also sets `factory.cohorts.maxActiveTenanciesPerCohort: 1` explicitly, with a comment: the limit equals the default, and the demo's reset relies on it by retiring the old device before registering again (Technical Plan §7.4). From Phase 13 the factory reads it as the published `deployment-policy` artefact (until then the factory uses the schema defaults and the policy is used by the CLI's publishing checks), and the intake app's allowlists (`FIELDSEAL_INTAKE_ALLOWED_BUILDERS`, `FIELDSEAL_INTAKE_ALLOWED_SOURCES`) hold the same two values (Technical Plan §8).

    ```yaml
    apiVersion: fieldseal.dev/v1alpha1
    kind: Policy
    metadata: { name: dev-web-publishing, version: 1.0.0 }
    spec:
      schemaVersion: 1.0.0
      layer: { scope: deployment }
      publishing:
        requiredApprovals: { Instrument: 2, Policy: 2, TrustBundle: 2, Deployment: 2 }
        authorMayApprove: false
        publisherThreshold: { m: 2, n: 3 }
        allowedBuilders: [ "https://ci.example.org/builders/fieldseal-publish" ]
        allowedSources: [ "https://git.example.org/authority/artefacts" ]
        requireTransparencyLog: true
      factory:
        # Equal to the default. The demo's reset retires the old device before it
        # registers a new one, so the limit is not raised (Technical Plan 7.4).
        cohorts: { maxActiveTenanciesPerCohort: 1 }
    ```

#### 534. `docs/tutorials/write-and-publish-your-first-survey.md` (Modify)

*   **Type / Scope**: Tutorial
*   **Proposed Changes**: Add the publish section, after the `survey check` steps. The reader starts `just web` in a second terminal (it creates the authority, starts the log and publishes the bundled examples, so the keys, trust bundle, policy and log exist), runs `just publish my-survey`, which prints the `artefact provenance`, `artefact sign` and `artefact publish` commands it runs, and opens the Publishing page of the collector stand-in to see the artefact address. The section says what `FIELDSEAL_ADAPTERS=files` does (the CLI keeps its artefact registry in files under `FIELDSEAL_STATE_DIR`; the default `memory` forgets everything at exit), why a second publish of the same name and version is refused, and that the survey must have a raised `survey.version` to publish a change. The section names the time to record: from a passing `survey check` to the artefact address.

**Housekeeping**: `docs/how-to/use-the-web-app.md`: add a short `just web` section; `crates/apps/web/README.md`: The new variable and the two ways to run the collector stand-in (`just web`, the stack).

### Phase 6: Shared results table, results export and `fieldseal intake results`

*   **Goal**: One versioned long table with typed value columns, written as JSON Lines and CSV (the results export) with a data contract, codebook, manifest and keyed subject pseudonyms. Technical Plan §6; Resolved Decisions 9 to 12, 20 and 26.
*   **Depends on**: Phase 4 (the survey folders that the tests publish). Otherwise independent of the authoring phases; placed after them to keep the survey work first.
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `cargo test -p fieldseal-adapters-landing-files` (read-back equivalence, privacy scan, pseudonym tests) and `cargo test -p fieldseal-adapters-file` (the atomic-write helper unit tests and `--test submissions`, the submission store contract).
    *   `cargo test -p fieldseal-intake`, `cargo test -p fieldseal-adapters-memory` and `cargo test -p fieldseal-adapters-upload-http` (`data_platform_contract` includes `instruments()`, for the memory platform, the landing-files platform and the upload server's `EventPlatform`).
    *   `cargo test -p fieldseal-cli --test intake_results`.
    *   The existing `observations.csv`, `findings.csv` and `losses.csv` writers produce byte-identical files for the existing intake tests (checked by `just test`).
    *   DuckDB recipe test passes when `duckdb` is on `PATH` (otherwise it reports `skipped` by name).
    *   `just test`.
*   **Security review**: None.

#### 546. `crates/adapters/file/src/atomic.rs` (Create)

*   **Type / Scope**: Rust module (file adapter)
*   **Proposed Changes**: `write_atomic(path, bytes) -> io::Result<()>`: writes the bytes to a temporary file in the same directory, calls `sync_all` on it, renames it over `path` and syncs the directory, so a reader sees the old file or the new one and never a torn file, and a failed write leaves no temporary file. Exported as `pub mod atomic` from `lib.rs`. Unit tests in the module: the new bytes replace the old, a failed write leaves the old file in place, and no temporary file remains. Users: the landing files (entry 151), the bundle store (entry 190) and the reconciler's digest write (entry 368); `FileSubmissionStore::put` moves to it (entry 547). The log store's `write_head` (`crates/adapters/translog/src/store.rs`) does the same steps in a crate that does not depend on this one, and stays as it is.

#### 146. `crates/contexts/intake/src/data_contract.rs` (Modify)

*   **Type / Scope**: Rust module (Intake context)
*   **Proposed Changes**: Add `TYPED_VALUE_COLUMNS = [value_number, value_text, value_date, value_bool, value_codes]` and `EXPORT_SCHEMA_VERSION = "1.0.0"` beside `LONG_COLUMNS`; add the additive item field `free_text` (true when `value_type` is `string`, including items with `other_text_of`) and the contract field `exportSchemaVersion`. `LONG_COLUMNS` is unchanged.

#### 147. `crates/contexts/intake/src/ports.rs` (Modify)

*   **Type / Scope**: Rust module (Intake context)
*   **Proposed Changes**: Add to `DataPlatform`: `fn instruments(&self) -> Result<Vec<Fingerprint>, DataPlatformError>` (ascending by fingerprint).

#### 148. `crates/contexts/intake/src/contract.rs` (Modify)

*   **Type / Scope**: Rust module (contract suite)
*   **Proposed Changes**: `data_platform_contract` gains a case: an instrument appears once after a landing that has an observation for it.

#### 150. `crates/adapters/memory/src/intake.rs` (Modify)

*   **Type / Scope**: Rust module (in-memory adapter)
*   **Proposed Changes**: Implement `DataPlatform::instruments` for `MemoryDataPlatform`.

#### 151. `crates/adapters/landing-files/src/lib.rs` (Modify)

*   **Type / Scope**: Rust module (landing adapter)
*   **Proposed Changes**: `FileDataPlatform::instruments` from the set it already keeps; `rewrite` uses it. Every landing file is written through the atomic-write helper (entry 546), so a reader never sees a torn file. `FileDataPlatform::open_read_only(dir)` opens a landing directory as a snapshot: it reads `observations.csv` once into memory and answers the read side of `DataPlatform` from them, including the landing mark (the number of rows in the snapshot). `csv_field`, `json`, `long_header`, `long_row` move to `export/writers.rs` and are re-exported; the bytes they write for `observations.csv` do not change.

#### 152. `crates/adapters/landing-files/src/export/mod.rs` (Create)

*   **Type / Scope**: Rust module (export)
*   **Proposed Changes**: `ExportTable::from_observations(rows, contracts, mapper)`, `write_export(table, &ExportOptions, out_dir) -> ExportResult`, `ExportOptions { formats: {Jsonl, Csv}, subject: Box<dyn SubjectMapper> }` (the CSV guard has no option). Rows with `excluded = true` are left out of every file and counted in `rows_omitted_excluded`.

#### 153. `crates/adapters/landing-files/src/export/writers.rs` (Create)

*   **Type / Scope**: Rust module (export)
*   **Proposed Changes**: JSON Lines writer (typed columns, `lang` and `flags` as arrays, nulls as `null`) and CSV writer (`LONG_COLUMNS` unchanged, `|`-joined arrays, empty cell for null). The CSV formula guard (`'` prefix for text starting with `=`, `+`, `-`, `@`, a tab or a carriage return) always applies to `value` when `value_type` is not `integer`, `decimal` or `money`, to `value_text` in `free_text.csv` and to every text column of `codebook.csv`; it never applies to numeric values and has no switch. Typed-column mapping for the nine item types as in Technical Plan §6 (a `string` row fills no typed column and leaves `value` empty). Row order (a total order, ending with the bytes of the row's JSON Lines text), JSON and CSV bytes follow the "Byte rules" of Technical Plan §6.

#### 154. `crates/adapters/landing-files/src/export/manifest.rs` (Create)

*   **Type / Scope**: Rust module (export)
*   **Proposed Changes**: `manifest.json`: `export_schema_version`, `landing_mark`, `pseudonymisation_key_id`, `instruments[{fingerprint, address}]`, `layouts[]`, `files[{name, sha256, bytes, rows}]` (not listing the manifest itself), `rows_omitted_excluded`. `instruments` and `layouts` come from the published directory, sorted as Technical Plan §6 says ("Where the manifest and contracts come from"); keys are sorted and the file ends with one `\n`. Returns the manifest's own SHA-256 for printing.

#### 155. `crates/adapters/landing-files/src/export/codebook.rs` (Create)

*   **Type / Scope**: Rust module (export)
*   **Proposed Changes**: `codebook.csv` rendered from the data contract by `fn codebook(contract) -> String`: `item_path, lang, item_label, code, code_label, value_type, unit, sensitivity, free_text`, one row per item and language and per code and language. Never stored separately. Also `free_text.jsonl` and `free_text.csv` (`record_id, item_path, value_text`).

#### 156. `crates/adapters/landing-files/src/export/pseudonym.rs` (Create)

*   **Type / Scope**: Rust module (export)
*   **Proposed Changes**: `SubjectMapper` trait; `KeyedSubject(export_key)` = `lower_hex(HMAC-SHA-256(export_key, subject))` with the `hmac` and `sha2` crates (entry 560); `key_id(key)` as defined in Technical Plan §6; `ExportKey::load(dir)` reads `<dir>/export.key` under the rules of §6 (export pseudonymisation key) and never writes it (file store, development adapter); `ExportKey::load_file(path)` applies the same length and mode rules to one file, for `intake results --export-key` (the CLI is given the key file, not a directory); `IdentitySubject` for the authority's own landing directory.

#### 157. `crates/adapters/landing-files/src/export/reader.rs` (Create)

*   **Type / Scope**: Rust module (export)
*   **Proposed Changes**: Builds `ExportTable` rows from a landing snapshot (`FileDataPlatform::open_read_only`, entry 151), not by parsing `observations.csv` itself, for `fieldseal intake results --landing`; the results reader uses the same path, so the two cannot read differently. It also reads the landing mark for the manifest. Also reads a published directory (`*.published` files, verified against a trust bundle) into the instruments and layouts the results export needs, keyed by instrument fingerprint; the results reader and the CLI both use it.

#### 158. `crates/adapters/landing-files/Cargo.toml` (Modify)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Add `hmac.workspace = true`, `sha2.workspace = true` (entry 560 adds `hmac` to the workspace) and `fieldseal-adapters-file` (the atomic-write helper, entry 546).

#### 159. `crates/adapters/landing-files/tests/support/mod.rs` (Create)

*   **Type / Scope**: Test support
*   **Proposed Changes**: Builds a table covering all nine item types, nonresponses, a retraction, an excluded row and a free-text answer; a separate small CSV parser and JSON Lines parser for read-back.

#### 160. `crates/adapters/landing-files/tests/export_readback.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Cases: `int_085_jsonl_and_csv_read_back_to_the_same_rows`, `int_085_decimal_text_is_exact_and_money_keeps_currency_scale`, `int_085_nonresponse_and_retraction_rows_have_null_typed_columns`, `int_085_an_empty_csv_cell_equals_a_json_null`, `int_088_free_text_is_joined_back_by_record_and_item`, `int_085_numbers_are_never_prefixed_and_text_starting_with_a_formula_character_is`, `int_085_the_guard_covers_free_text_csv_and_the_codebook`, `int_085_rows_have_a_total_order_even_when_the_listed_keys_are_equal`, `int_085_the_manifest_records_the_landing_mark`, `int_085_codebook_is_rendered_from_the_contract`, `int_085_manifest_digests_match_the_files`, `int_085_export_schema_version_is_in_manifest_and_contract`, `int_085_rows_are_sorted_by_instrument_tenancy_seq_record_and_item`, `int_085_json_lines_are_compact_with_column_order_keys`, `int_085_manifest_and_contract_keys_are_sorted`, `int_088_a_free_text_item_has_a_null_value_and_null_typed_columns_in_both_formats`.

#### 161. `crates/adapters/landing-files/tests/export_privacy.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Cases: `int_086_excluded_rows_appear_in_no_file_and_are_counted`, `int_087_no_roster_subject_id_appears_in_any_file_in_readable_or_hex_form` (scans JSON Lines, CSV, free text, contracts, codebook and manifest built from the bundled rosters), `int_087_the_same_key_gives_the_same_pseudonym`, `int_087_another_key_gives_different_pseudonyms`, `int_087_the_manifest_records_the_key_id_not_the_key`, `int_087_an_absent_or_wrong_key_file_is_refused_and_never_created`.

#### 162. `crates/adapters/landing-files/tests/duckdb_recipe.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `int_085_duckdb_converts_jsonl_and_csv_to_parquet_with_the_manifest_row_count`: runs the documented DuckDB command; reports `skipped: duckdb not on PATH` and passes when the tool is absent.

#### 164. `crates/apps/cli/src/intake_cmd.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: Add `intake results --landing <dir> --published <dir> --export-key <file> --trust-bundle <file> --out <dir> [--format jsonl,csv]`. It opens the intake app's landing directory through the landing-files `DataPlatform` adapter (a snapshot, entry 151), takes instruments and layouts from the published directory, verifies them against the trust bundle, and writes the results export. `--published`, `--export-key` (the file `export.key`, read with `ExportKey::load_file`, entry 156) and `--trust-bundle` are required; the CLI never derives a key. `intake` has its own argument parser (`intake_cmd.rs:40–68`, routed from `main.rs:86`, outside `args.rs`), so the flags are added to that parser's `Opts` and `parse` (fields `landing`, `published`, `export_key`, `trust_bundle` and `format`). There is no mode that reads a device export file (`intake replay --reveal` does that) and no `--authority demo` form. Prints the file list, the manifest SHA-256 and the unprotected-data statement.

#### 166. `crates/apps/cli/src/messages.rs` (Modify)

*   **Type / Scope**: Rust module (CLI strings)
*   **Proposed Changes**: Messages for `intake results`, including the statement that the files are outside Fieldseal's protection.

#### 167. `crates/apps/cli/tests/intake_results.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Cases: `cli_048_results_from_a_landing_directory_writes_every_file_and_prints_the_manifest_digest`, `cli_048_the_unprotected_data_statement_is_printed`, `cli_048_the_csv_guard_prefixes_text_and_never_numbers`, `cli_048_the_manifest_records_the_landing_mark_of_the_snapshot`, `cli_048_a_second_export_key_changes_pseudonyms`, `cli_048_the_export_key_is_required`, `cli_048_published_is_required`, `cli_048_trust_bundle_is_required`, `cli_048_a_key_file_of_the_wrong_length_or_mode_is_refused`, `cli_048_contract_files_are_named_by_fingerprint_hex`.

#### 169. `docs/reference/spec/intake.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add INT-085 (one long table with `EXPORT_SCHEMA_VERSION`; a minor version only adds columns; CSV text cells that start with `=`, `+`, `-`, `@`, a tab or a carriage return are prefixed with `'` and numeric values never are; the manifest records the landing mark, and every file of one results export comes from one landing snapshot), INT-086 (excluded rows are omitted from every export file and counted), INT-087 (the exported `subject` is a keyed hash; no readable roster id), INT-088 (free text goes to a separate file), INT-091 (`DataPlatform::instruments`). Ids provisional.

#### 170. `docs/reference/spec/cli.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add the `intake results` row and CLI-048.

#### 171. `docs/how-to/export-results-to-parquet.md` (Create)

*   **Type / Scope**: How-to
*   **Proposed Changes**: Reading a landing directory with `fieldseal intake results --landing`, the files, the data contract and codebook, and the DuckDB command (`COPY (SELECT * REPLACE (CAST(value_number AS DECIMAL(38,9)) AS value_number) FROM read_json_auto('results.jsonl')) TO 'results.parquet' (FORMAT PARQUET)`), the free-text join, and the statement that exported files are unprotected.

#### 172. `docs/index.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Link the export how-to.

#### 547. `crates/adapters/file/src/submissions.rs` (Modify)

*   **Type / Scope**: Rust module (file adapter)
*   **Proposed Changes**: `FileSubmissionStore::put` writes the submission file through `write_atomic` instead of its own `std::fs::write` (line 61) and `rename` (line 62), which adds the `fsync` it lacks. The `index` append is unchanged. The `SubmissionStore` contract suite, run by entry 559, is the test.

#### 555. `crates/adapters/upload-http/src/bin/server.rs` (Modify)

*   **Type / Scope**: Rust module (upload server binary)
*   **Proposed Changes**: `EventPlatform` (line 109) is a third implementation of `DataPlatform` (`impl DataPlatform for EventPlatform`, line 111) and does not compile once the trait gains `instruments()` (entry 147). Add `fn instruments(&self) -> Result<Vec<Fingerprint>, DataPlatformError> { self.0.instruments() }`, which forwards to the inner platform and prints no event. The existing `int_011` contract run (`conformance_cmd/contracts.rs` names `EventPlatform` for `data_platform_contract`) covers it through the new contract case of entry 148.

#### 559. `crates/adapters/file/tests/submissions.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: The crate has no tests directory today, and the conformance contract table (`conformance_cmd/contracts.rs:119`) points at `cargo test -p fieldseal-adapters-file int_013`, which names no test. Add `int_013_the_file_submission_store_satisfies_the_contract`: it runs `fieldseal_intake::contract::submission_store_contract` with a `FileSubmissionStore` in a fresh temporary directory for each call, and it covers entry 547's change. The neighbouring pointers for `del_071`, `int_040` and `int_070` have the same problem and are not part of this plan.

#### 560. `Cargo.toml` (Modify)

*   **Type / Scope**: Workspace manifest
*   **Proposed Changes**: Add `hmac = { version = "0.13", default-features = false }` to `[workspace.dependencies]`. Version 0.13 is the one that matches the workspace's `sha2 = "0.11"`: `Cargo.lock` has `hmac 0.13.0` depending on `digest 0.11.3`, the same `digest` as `sha2 0.11.1`. `hmac 0.13.0` is already in the lock file (a dependency of `hpke`), so no new package is added. `architecture.toml` lists `hmac` in the allow-list for the kernel and contexts; adapters are not subject to that list.

**Housekeeping**: `crates/contexts/intake/README.md`: Document `instruments()`, the new constants and the `free_text` contract field; `crates/adapters/landing-files/README.md`: Document the `export` module, options, files, privacy rules and tests; `crates/apps/cli/README.md`: Add `intake results`; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 7: Portal session extraction (`fieldseal-adapters-portal`)

*   **Goal**: Move the session store, pending sign-in map, `fs_session`-style cookie handling, per-session CSRF token and its check out of `FactoryHttp` into a new adapter crate, with no change in behaviour, so the results reader can reuse them. Technical Plan §7.2.
*   **Depends on**: Phase 0b. No other dependency.
*   **Commits**: Two commits. 7a: `Characterise the factory portal's sign-in, session and CSRF behaviour` (tests only, passing against the current code). 7b: `Move portal sessions into their own adapter` (the 7a tests are not edited).
*   **Gate** (must pass before the next phase starts):
    *   After 7a: `cargo test -p fieldseal-adapters-factory-http --test portal_session` passes on the current code. (The crate has no tests today, so 7a creates the proof.)
    *   After 7b: the same command passes with `git diff <7a>..<7b> -- crates/adapters/factory-http/tests` empty; `cargo test -p fieldseal-security-tests --test registration_attacks` and `cargo test -p fieldseal-adapters-web --test device_flow` pass unchanged; `cargo test -p fieldseal-adapters-portal`; the registration spec has REG-092 (entry 557) and every test of this phase names a defined id.
    *   `python3 tools/check-architecture.py`; `cargo clippy -p fieldseal-adapters-portal -p fieldseal-adapters-factory-http -- -D warnings`; `just test`.
*   **Security review**: None.

#### 174. `crates/adapters/factory-http/tests/portal_session.rs` (Create)

*   **Type / Scope**: Integration test (characterisation, commit 7a)
*   **Proposed Changes**: Drives `FactoryHttp::handle` with the in-memory registration ports and `MemoryIdentityProvider`. `MemoryIdentityProvider` emits no PKCE challenge, so no case asserts one. REG-043 is the device list, so the session and CSRF cases cite REG-092 (entry 557). Cases: `reg_002_sign_in_redirects_to_the_provider_with_a_state`, `reg_002_callback_with_an_unknown_state_is_refused`, `reg_092_a_session_cookie_is_httponly_samesite_lax_and_secure_on_https`, `reg_092_a_page_without_a_session_redirects_to_sign_in`, `reg_092_a_post_without_the_csrf_token_is_refused`, `reg_092_a_post_with_another_sessions_token_is_refused`, `reg_092_sign_out_ends_the_session`, `reg_092_the_session_cookie_name_is_fs_session`.

#### 175. `crates/adapters/portal/Cargo.toml` (Create)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Package `fieldseal-adapters-portal`; dependencies `fieldseal-kernel` (for `AuthorityTime`), `fieldseal-registration` (for `AuthenticatedPerson`, `IdentityProvider`, `PendingSignIn`), `getrandom = "0.2"`, `serde_json = "1"` (for `Response::json`, as `factory-http` has it today) and `thiserror`. No HTTP server dependency.

#### 176. `crates/adapters/portal/src/lib.rs` (Create)

*   **Type / Scope**: Rust module (portal)
*   **Proposed Changes**: Re-exports. Crate doc states the invariants: cookies are `HttpOnly`, `SameSite=Lax`, `Secure` when the public URL is https; session ids and CSRF tokens come from the operating system's CSPRNG; a state-changing request needs the session's CSRF token.

#### 177. `crates/adapters/portal/src/http.rs` (Create)

*   **Type / Scope**: Rust module (portal)
*   **Proposed Changes**: `Request`, `Response`, `parse_form` and `multipart_field` move from `factory-http/src/lib.rs` (lines 70 to 180 and 694) with their tests-by-use unchanged. The helpers that are private there become public, because the results reader (Phase 10) needs them: `Request::header`, `Request::cookie`, `Request::form`, and `Response::new`, `Response::json`, `Response::html`, `Response::redirect` and `Response::with` (`lib.rs:90–146`). The content-security policy becomes a parameter, `Response::html(status, body, csp: &str)`, because each app has its own; the factory passes the policy it sends today and the results reader passes its own. `fieldseal-adapters-factory-http` re-exports the moved items, so its public API does not change.

#### 178. `crates/adapters/portal/src/sessions.rs` (Create)

*   **Type / Scope**: Rust module (portal)
*   **Proposed Changes**: `PortalSessions::new(cookie_name: &str, secure: bool, ttl_ms: u64)`. Every call that depends on time takes the caller's clock, `now: AuthorityTime` (the factory passes `self.factory.now()`, as `session()` at `lib.rs:437–438` does today), so the store has no clock of its own. `begin(provider: &dyn IdentityProvider, callback_url: &str) -> Result<String, PortalError>` (the redirect URL; keeps the `PendingSignIn` by its state); `finish(provider: &dyn IdentityProvider, query: &BTreeMap<String, String>, now) -> Result<(SessionId, String), PortalError>` (takes the whole decoded query map, as `finish_sign_in(&pending, &req.query)` does at `lib.rs:462–465`, and returns the session id and the `Set-Cookie` value built from the cookie name, `Secure` flag and `ttl_ms`); `session(cookie_header: Option<&str>, now) -> Option<SessionView { id, person, csrf }>` (drops expired sessions first); `check_csrf(&SessionView, submitted: &str) -> bool`; `end(&SessionId)`. The code is the current `sessions`/`pending` maps, `session()`, `sign_in()`, `sign_in_callback()` and `portal_post()` logic of `FactoryHttp`, without the factory pages.

#### 179. `crates/adapters/portal/tests/sessions.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Cases: `reg_092_ids_and_tokens_are_unique_and_unguessable_length`, `reg_092_cookie_attributes`, `reg_092_csrf_is_per_session`, `reg_002_pending_sign_ins_are_single_use`, `reg_092_end_removes_the_session`, `reg_092_an_expired_session_is_not_returned`, `reg_092_a_cookie_name_is_configurable_so_two_portals_do_not_mix`.

#### 180. `crates/adapters/portal/README.md` (Create)

*   **Type / Scope**: Crate contract (EGM)
*   **Proposed Changes**: Purpose, public API, invariants, what it does not do (no pages, no role policy), and test commands, following the template of `crates/adapters/factory-http/README.md`.

#### 181. `crates/adapters/factory-http/src/lib.rs` (Modify)

*   **Type / Scope**: Rust module (factory HTTP adapter)
*   **Proposed Changes**: Delete the session, pending and CSRF code and use `PortalSessions` with cookie name `fs_session` (constant `SESSION_COOKIE` stays), `config.session_ttl_ms` and `self.factory.now()`. Re-export `Request`, `Response`, `parse_form`, `multipart_field` from the portal crate, and pass the factory's content-security policy to `Response::html`. Behaviour, routes and messages are unchanged.

#### 182. `crates/adapters/factory-http/Cargo.toml` (Modify)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Add `fieldseal-adapters-portal`; drop `getrandom` if nothing here uses it (`serde_json` stays, the factory pages use it).

#### 184. `Cargo.toml` (Modify)

*   **Type / Scope**: Workspace manifest
*   **Proposed Changes**: Add `fieldseal-adapters-portal = { path = "crates/adapters/portal" }` to `[workspace.dependencies]` (the `crates/adapters/*` member glob already includes it).

#### 557. `docs/reference/spec/registration.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add REG-092 (provisional), "Portal sessions and CSRF": a portal session MUST be kept in a cookie that is `HttpOnly`, `SameSite=Lax` and, when the portal's public URL is https, `Secure`; session identifiers and CSRF tokens MUST come from the operating system's CSPRNG; each session MUST have its own CSRF token and every state-changing portal request MUST carry it; signing out MUST end the session; a pending sign-in MUST be usable once. No existing requirement covers this (REG-043 is the device list, REG-002 the authentication). Add REG-092 to the portal row of the traceability table. The characterisation tests (entry 174) and the portal crate's tests (entry 179) cite it.

**Housekeeping**: `crates/adapters/factory-http/README.md`: State that sessions and CSRF come from `fieldseal-adapters-portal`; `Cargo.lock`: New workspace member; `crates/adapters/README.md`: List `portal`; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 8: File adapter moves, new file adapters and the runtime profile at registration

*   **Goal**: Move `FileRegistry` (the file `ArtefactRegistry`) out of `crates/apps/cli/src/stores.rs` into `crates/adapters/file`, add the file adapters the factory needs to build bundles (`FileRosterSource` over a roster store, `FileBundleStore`), and make the runtime report its profile at registration: extend the registration request (WIRE-130) with the instrument-schema version and the UI reference-catalogue version the runtime implements, journal them with the tenancy, and serve them through a file `RuntimeProfiles` adapter so DIS-012 and DIS-017 are enforced per tenancy. DIS-077 (an extension's meta-schema version and an instrument's catalogue address) is not enforced by this change: the profile carries neither, and no extension reaches a bundle yet. Technical Plan §7.3 (wiring table); Resolved Decision 31.
*   **Depends on**: Phase 0b.
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `cargo test -p fieldseal-adapters-file --test contracts` (the shared contract suites pass for each file adapter).
    *   `cargo test -p fieldseal-cli` (`artefact publish` through `FIELDSEAL_ADAPTERS=files` behaves as before) and `fieldseal conformance run --suite contracts`.
    *   `cargo test -p fieldseal-registration -p fieldseal-kernel` (the registration vectors, read by `crates/contexts/registration/tests/vectors.rs`, include the new fields), `cargo test -p fieldseal-security-tests --test registration_profile`, `cargo test -p fieldseal-adapters-web` and `cargo test -p fieldseal-e2e`: every runtime builds a request that carries its profile, and a request without it is refused as malformed.
    *   `cargo build --target wasm32-unknown-unknown -p fieldseal-wasm` and `cargo build -p fieldseal-uniffi`.
    *   `python3 tools/check-architecture.py`; `just test`.
*   **Security review**: SR-1: the registration request body is covered by `body_sha256` and the proof of possession, so adding two fields changes signed content. Scope: strict decode of the new fields (semver text, length limits, no unknown keys), that a changed profile breaks the proof of possession, that the factory records what was signed and nothing else, and that a downgrade cannot widen what a tenancy may receive (DIS-012). SR-2 (the bundle routes) follows in Phase 13. SR-1 signs off before this phase merges.

#### 188. `crates/adapters/file/src/registry.rs` (Create)

*   **Type / Scope**: Rust module (file adapter)
*   **Proposed Changes**: `FileRegistry`, moved from `crates/apps/cli/src/stores.rs` lines 104 to 166 with its `backend` helper: `*.publication` files and a `withdrawals/` directory. The CLI's `crate::support::hex` that it calls cannot be reached from an adapter, so the moved code uses `fieldseal_kernel::digest::lower_hex`. This is the artefact registry that `artefact publish` fills when `FIELDSEAL_ADAPTERS=files` (`<state>/registry`). The factory reads this directory (not the `*.published` copies that intake reads); the factory variable `FIELDSEAL_FACTORY_REGISTRY_DIR` therefore names the artefact registry directory.

#### 189. `crates/adapters/file/src/roster_store.rs` (Create)

*   **Type / Scope**: Rust module (file adapter)
*   **Proposed Changes**: `RosterStore::open(dir)`: `issue(roster) -> Result<IssueOutcome, RosterStoreError>` writes `<dir>/<cohort>/v<version>.roster` (canonical closed form, DIS-063) with its SHA-256 beside it as `v<version>.sha256`; same content at the same version returns `Unchanged`, different content returns `VersionTaken`, a lower version than the latest returns `NotNewer`; `latest(cohort)`, `get(cohort, version)`, `cohorts()`. File mode 0600 on Unix (the store holds display names and consent). `FileRosterSource::new(store, tenancy_registry_dir)` implements `RosterSource`: `current_rosters(tenancy)` returns the latest roster of each cohort the tenancy record holds, at the tenancy's generation; `active_tenancies(cohort, except)` counts from the tenancy registry snapshot (`FileRegistryStore::snapshot`). The factory calls `issue` from the `IssueRoster` operation (Phase 12); no CLI command writes the store. Development adapter.

#### 190. `crates/adapters/file/src/bundles.rs` (Create)

*   **Type / Scope**: Rust module (file adapter)
*   **Proposed Changes**: `FileBundleStore::new(dir)` implements `BundleStore`: one directory per tenancy, files named `fieldseal-bundle-<date>-<sequence>.fsb` (DIS-023); `put` refuses a sequence not higher than the latest (`NotNewer`) and writes through the atomic-write helper (entry 546); `latest(tenancy)` reads the highest. Development adapter.

#### 191. `crates/adapters/file/src/profiles.rs` (Create)

*   **Type / Scope**: Rust module (file adapter)
*   **Proposed Changes**: `FileRuntimeProfiles::new(tenancy_registry_dir)` implements `RuntimeProfiles`: `profile(tenancy)` reads the tenancy record from a `FileRegistryStore::snapshot` and returns `RuntimeProfile { instrument_schema, localisation_reference }` built from the profile the runtime reported at registration (Registration's `ReportedProfile`); `None` for an unknown tenancy. The mapping from the Registration types to the Distribution types (`ReportedVersion` to the instrument context's `SchemaVersion`) is done here, because Distribution depends on Registration and not the reverse. Development adapter (the tenancy registry journal is a file store).

#### 192. `docs/reference/spec/wire-formats.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: WIRE-130: the registration request body gains `"schema": tstr` (the instrument-schema version the runtime implements, semantic version text, required) and `"catalogue": tstr?` (the UI reference-catalogue version of the runtime build, present only when the build has one; nothing reads it yet, and it is added in this change so that Localisation artefacts, when they arrive, need no second signed-content wire change and security review). The body stays a closed map: unknown keys are refused, and a body without `schema` is refused. Both fields are inside `body_sha256` and therefore covered by the proof of possession (WIRE-132). `"v"` stays `1` while the specs are `v1alpha1`; the vectors are regenerated.

#### 193. `docs/reference/spec/registration.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add REG-091 (provisional): the factory MUST record the instrument-schema version and the reference-catalogue version from a registration request with the tenancy, in the tenancy registry journal, and MUST NOT accept them from any other source; a key roll replaces the recorded profile with the one both keys signed (the roll request carries it), because keeping a higher version after a downgrade would widen what the tenancy receives (DIS-012). Add the profile to the tenancy record description. Note that the request body change is a signed-content change (security review SR-1).

#### 194. `crates/contexts/registration/src/domain/wire.rs` (Modify)

*   **Type / Scope**: Rust module (Registration context)
*   **Proposed Changes**: `RequestBody` gains `schema: ReportedVersion` (a `{major, minor, patch}` value type defined in the Registration domain, because `architecture.toml` does not let Registration depend on the Instrument context that owns `SchemaVersion`) and `catalogue: Option<String>`; encode and strict decode (WIRE-130) with limits (semver text at most 32 bytes, catalogue at most 64 bytes); `RequestBody::digest()` (`wire.rs:296`) covers them.

#### 195. `crates/contexts/registration/src/domain/mod.rs` (Modify)

*   **Type / Scope**: Rust module (Registration context)
*   **Proposed Changes**: Add `ReportedVersion` and `ReportedProfile { instrument_schema: ReportedVersion, catalogue_reference: Option<String> }`; `RegistrationRequest` and `TenancyRecord` carry it. `TenancyRecord.profile` is a `ReportedProfile`, not an `Option`: a request without `schema` is refused, so every record has one. The record is constructed in three places, and all three change: `application.rs:539` (entry 196), `contract.rs:47` (`sample_tenancy`, entry 197) and `codec.rs:339` (entry 200).

#### 196. `crates/contexts/registration/src/application.rs` (Modify)

*   **Type / Scope**: Rust module (Registration context)
*   **Proposed Changes**: Registration copies the request's profile into the new `TenancyRecord`; a refused (malformed) request records nothing; a key roll replaces it with the profile both keys signed, as REG-091 says (keeping a higher version after a downgrade would widen what the tenancy receives, DIS-012).

#### 197. `crates/contexts/registration/src/contract.rs` (Modify)

*   **Type / Scope**: Rust module (contract suite)
*   **Proposed Changes**: `registry_store_contract`: a tenancy record round-trips its `ReportedProfile` (memory and file adapters). `sample_tenancy` (line 47) fills the profile with a fixed demo version and no catalogue.

#### 198. `crates/contexts/registration/tests/vectors/registration.json` (Modify)

*   **Type / Scope**: Test vectors
*   **Proposed Changes**: Add the WIRE-130 body vectors with the two new fields: `request` (with `catalogue`) and a new `request_no_catalogue` (without it), and a negative row in `invalid` (a body without `schema`, structure `request-body`). The file's header names `FIELDSEAL_REGENERATE_VECTORS=1 cargo test -p fieldseal-registration --test vectors`; that test does not exist today, and entry 558 adds it, so the command in the header becomes true.

#### 558. `crates/contexts/registration/tests/vectors.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Reads `tests/vectors/registration.json`, which nothing reads today. Cases: `wire_130_the_request_body_vectors_decode_with_schema_and_catalogue` (`RequestBody::decode` of `request` and `request_no_catalogue` gives the stored `schema`, and `catalogue` only for the first; `RequestBody::digest()` (`wire.rs:296`) equals the stored `body_sha256`), `wire_130_a_body_without_schema_is_refused` (the new negative row) and `wire_130_the_vectors_are_current`. The last case rebuilds the new entries from fixed seeds (`SHA-256("fieldseal.dev/vectors/<label>")`, as `crates/kernel/tests/vectors.rs` derives its keys), compares them with the file and fails with the regenerate command; with `FIELDSEAL_REGENERATE_VECTORS=1` it rewrites them.

#### 200. `crates/adapters/file/src/codec.rs` (Modify)

*   **Type / Scope**: Rust module (file adapter)
*   **Proposed Changes**: The tenancy journal record encodes the profile; strict decode. A tenancy registry journal written before this phase is not readable (development stacks: `just purge`).

#### 201. `crates/adapters/memory/src/registration.rs` (Modify)

*   **Type / Scope**: Rust module (in-memory adapter)
*   **Proposed Changes**: The test request builder `body()` (line 506) keeps its signature and fills the demo schema (`DEMO_SCHEMA`, converted to a `ReportedVersion`) and no catalogue, so its callers do not change. Add `body_with_profile(token, label, profile: ReportedProfile)` for tests that need another profile.

#### 202. `crates/apps/cli/src/registration_cmd.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: `registration request` builds `RequestBody` with the CLI device's implemented schema version (the same value `RuntimeProfile.instrument_schema` takes in `bundle build`) and no catalogue.

#### 203. `crates/adapters/web/src/device.rs` (Modify)

*   **Type / Scope**: Rust module (WebAssembly device adapter)
*   **Proposed Changes**: The request body built at line 333 carries the schema version of the core compiled into the WebAssembly device and no catalogue. (The `fetch_bundle` change follows in Phase 14.)

#### 204. `crates/bindings/uniffi/src/lib.rs` (Modify)

*   **Type / Scope**: Rust module (UniFFI binding)
*   **Proposed Changes**: Add `runtime_profile() -> RuntimeProfile { instrument_schema: String, catalogue_reference: Option<String> }` beside `core_version()`, so the native apps put the core's schema version and their catalogue version into the registration request they build. Today the binding exposes only `core_version`.

#### 206. `crates/apps/e2e/src/lib.rs` (Modify)

*   **Type / Scope**: Test support library
*   **Proposed Changes**: The request built at line 452 carries `profile()`'s schema (`DEMO_SCHEMA`); no behaviour change. (The loader changes of Phase 4 are separate.)

#### 207. `crates/apps/security-tests/tests/registration_profile.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `wire_130_a_request_without_schema_is_refused`, `wire_130_unknown_keys_are_still_refused`, `wire_132_changing_the_reported_schema_breaks_the_proof_of_possession`, `reg_091_the_recorded_profile_is_the_signed_one`, `reg_091_a_malformed_semver_is_refused_and_nothing_is_recorded`, `reg_091_a_key_roll_cannot_raise_the_profile_without_the_new_key`, `dis_012_an_older_reported_schema_never_widens_what_a_tenancy_may_receive`.

#### 208. `crates/adapters/file/src/lib.rs` (Modify)

*   **Type / Scope**: Rust module (file adapter)
*   **Proposed Changes**: `pub mod registry; pub mod roster_store; pub mod bundles; pub mod profiles;` and a crate-level list of which adapters are development adapters.

#### 209. `crates/adapters/file/Cargo.toml` (Modify)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Add `fieldseal-distribution` (ports `RosterSource`, `BundleStore`, `RuntimeProfiles`, and the roster type). `fieldseal-registration`, `fieldseal-publishing` and `fieldseal-adapters-memory` are already normal dependencies of this crate (the memory adapter supplies the sample data for the contract tests), so nothing else is added.

#### 210. `crates/adapters/file/tests/contracts.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Cases: `pub_060_the_file_registry_satisfies_the_artefact_registry_contract` (`artefact_registry_contract`), `dis_080_the_file_roster_source_satisfies_the_roster_source_contract` (`roster_source_contract`), `dis_015_the_file_bundle_store_satisfies_the_bundle_store_contract` (`bundle_store_contract`), `dis_012_the_file_runtime_profiles_satisfy_the_runtime_profiles_contract` (`runtime_profiles_contract`, with a tenancy registered through the tenancy registry journal), `dis_012_a_tenancy_that_reported_an_older_schema_reports_that_schema_back`, `dis_080_a_roster_version_once_issued_does_not_change`, `dis_080_a_lower_version_is_refused`, `dis_023_bundle_files_carry_the_dated_name`, `dis_015_a_second_bundle_with_an_old_sequence_is_refused`. Each name carries the id of the requirement it covers (the inventory check enforces this); PUB-060 is the existing id of the artefact registry contract, and DIS-080 is added by entry 215.

#### 212. `crates/apps/cli/src/stores.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: Delete `FileRegistry` and its `backend` helper; import it from `fieldseal_adapters_file::registry`. `crate::support::hex` stays in `support.rs` (other callers use it).

#### 213. `crates/apps/cli/src/artefact_cmd.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: Line 42: import `FileRegistry` from the file adapter crate.

#### 214. `crates/apps/cli/src/conformance_cmd/contracts.rs` (Modify)

*   **Type / Scope**: Rust module (conformance)
*   **Proposed Changes**: Line 15 import; register contract entries for `FileRosterSource` (`["DIS-080"]`), `FileBundleStore` (`["DIS-015", "DIS-023"]`) and `FileRuntimeProfiles` (`["DIS-012"]`), each with `Location::CargoTest("cargo test -p fieldseal-adapters-file --test contracts")`; the `FileRegistry` entry points at the new path.

#### 215. `docs/reference/spec/distribution.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add DIS-080 and a note under DIS-012 and DIS-017 that the profile is the one recorded with the tenancy at registration (REG-091). Add a note under DIS-077 that the profile does not yet carry the extension meta-schema version or the catalogue address, so the requirement is not enforced until extensions reach bundles. DIS-080: a roster version, once issued, MUST NOT change, and a source MUST return, for a cohort, the highest version issued (the contract `FileRosterSource` and the roster store satisfy). Id provisional.

#### 216. `docs/reference/conformance.md` (Modify)

*   **Type / Scope**: Generated documentation
*   **Proposed Changes**: Regenerate the matrix with `fieldseal conformance matrix`.

**Housekeeping**: `crates/contexts/registration/README.md`: `ReportedProfile` and the changed request body; `crates/bindings/uniffi/README.md`: Document `runtime_profile`; `crates/adapters/file/README.md`: Add the four adapters, their directory layouts, and that each is a development adapter; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 9: `fieldseal roster` group: check, diff, list

*   **Goal**: The roster commands that do not need the factory: `check`, `diff` and `list`. `roster issue` and `roster assign` are operator operations of the factory and follow in Phase 12. Technical Plan §7.4; Resolved Decision 24.
*   **Depends on**: Phase 5 (shared roster comparison) and Phase 8 (roster store).
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `cargo test -p fieldseal-cli --test roster_cli`.
    *   `fieldseal roster check examples/rosters/village-a.yaml --instrument examples/surveys/household-water-access` exits 0; with a roster that lacks `head_name` it exits 1 and names the field.
    *   With a store built by the test through `RosterStore::issue` (entry 189) from `examples/rosters/village-a.yaml` (version 3), `fieldseal roster diff village-a@3 examples/rosters/next/village-a.yaml --store <tmp>` prints counts, and `roster list --store <tmp>` names `village-a@3` with its digest and counts.
    *   No command prints a subject id without `--reveal` (tested by scanning stdout and stderr).
    *   `just test`.
*   **Security review**: None.

#### 218. `crates/apps/cli/src/roster_cmd.rs` (Create)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: `roster check <file> --instrument <survey dir>... [--json]` (closed-schema check DIS-063, `compare_roster`, consent counts, writes nothing). `--instrument` takes a survey folder only: it loads the folder through the resolver and passes the expanded instrument to `compare_roster`; an artefact address is not accepted (resolving one needs an artefact registry or a published directory, and `roster check` reads nothing but its arguments), and a value that is not a survey folder is a usage error (exit 2). `roster diff <a> <b> [--store <dir>] [--reveal]` (each operand is a file or `<cohort>@<version>` read from `--store`, a read-only copy of the factory's roster store; counts of added, removed and kept subjects, consent changes by from/to state, `prior_status` changes, changed field names; ids and values only with `--reveal`, which warns on stderr, CLI-008). `roster list --store <dir> [--cohort <id>]` (versions named `<cohort>@<version>`, digests, subject and consent counts; no ids). The flag tables are declared in this module. It reuses `bundle_cmd::parse_roster` (`bundle_cmd.rs:127`), `Roster::field_names` and `Roster::restricted_to` (`roster.rs:97–116`) and, for the factory's records, `record_issued` and `FileRosterHistory` (`crates/adapters/file/src/rosters.rs`). `roster issue` and `roster assign` are added in Phase 12 as calls to the factory. The factory records issued rosters for intake's consent check when it builds a bundle (it needs the tenancy and the restricted fields, through `record_issued`), not the CLI.

#### 219. `crates/apps/cli/src/roster_check.rs` (Modify)

*   **Type / Scope**: Rust module (CLI, shared)
*   **Proposed Changes**: Call `check_issue_form` (entry 562) for the closed-schema check of DIS-063, which lives in the Distribution context so that the factory's adapter calls the same code, and keep `compare_roster` (entry 127) beside it for the comparison with the instruments, reusing `Roster::may_be_followed_by` for the version rule where two versions are compared.

#### 562. `crates/contexts/distribution/src/domain/roster.rs` (Modify)

*   **Type / Scope**: Rust module (Distribution context)
*   **Proposed Changes**: Add `check_issue_form(value: Value) -> Result<RosterIssueForm, Vec<RosterFinding>>`, the closed-schema check of DIS-063 as a pure function beside `Roster`: unique subjects, strictly increasing ordinals, exactly one non-empty cohort, `version` at least 1, consent from the declared set (`granted`, `refused`, `unknown`) and no unknown key. `generation` is not part of the form (WIRE-198, entry 573), because a generation belongs to a cohort on one tenancy. The function reports every finding, not only the first. `RosterIssueForm { cohort, version, entries }` has `encode()` (canonical CBOR) and `digest()` (SHA-256 of that encoding). It takes a `Value`, so the CLI passes the value decoded from YAML (`roster check`, entry 219) and the file adapter passes the value decoded from canonical CBOR after checking that re-encoding gives the same bytes (entry 572). The module stays pure: no `std::fs`, `std::env` or `std::process` (`architecture.toml`).

#### 563. `crates/contexts/distribution/tests/roster_form.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Cases: `dis_063_a_well_formed_form_passes_and_has_a_stable_digest`, `dis_063_a_repeated_subject_is_a_finding`, `dis_063_ordinals_must_strictly_increase`, `dis_063_an_unknown_key_is_a_finding`, `dis_063_a_generation_key_is_refused_in_the_issue_form`, `dis_063_a_consent_state_outside_the_declared_set_is_a_finding`, `dis_063_every_finding_is_reported_not_only_the_first`.

#### 220. `crates/apps/cli/src/main.rs` (Modify)

*   **Type / Scope**: Rust module (CLI entry)
*   **Proposed Changes**: `mod roster_cmd;` and arm `["roster", verb]`.

#### 222. `crates/apps/cli/src/messages.rs` (Modify)

*   **Type / Scope**: Rust module (CLI strings)
*   **Proposed Changes**: Messages and the `--reveal` warning.

#### 223. `crates/apps/cli/tests/roster_cli.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Cases: `cli_050_check_fails_on_a_field_the_instrument_reads_and_a_subject_lacks`, `cli_050_check_writes_nothing`, `cli_050_check_notes_a_field_no_instrument_reads`, `cli_052_diff_reads_a_stored_version_named_cohort_at_version`, `cli_052_diff_prints_counts_only`, `cli_052_diff_with_reveal_warns_on_stderr`, `cli_053_list_prints_no_subject_ids`, `dis_081_a_diff_is_computable_without_exposing_a_subject`. The `roster issue` cases (`cli_051_*`) are in entry 541.

#### 225. `docs/reference/spec/cli.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add the `#### roster` table with the rows `check`, `diff` and `list` and three requirements. CLI-050: `roster check` MUST fail on any field an instrument reads that a subject lacks and MUST NOT write anything. CLI-052: `roster diff` MUST NOT print subject ids or values without `--reveal`. CLI-053: `roster list` MUST NOT print subject ids. Amend CLI-008, which allows `--reveal` only for `bundle open` and `intake replay`, to name `roster diff` as well. The `issue` row and CLI-051 are added in Phase 12 (entry 339). Ids provisional.

#### 226. `docs/reference/spec/distribution.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add DIS-081: the difference between two roster versions MUST be computable without exposing a subject. (DIS-080 was added in Phase 8.) Id provisional.

#### 536. `examples/rosters/next/village-a.yaml` (Create)

*   **Type / Scope**: Example roster
*   **Proposed Changes**: Cohort `village-a`, `version: 4`: `examples/rosters/village-a.yaml` is at version 3, and the store refuses a version that is not higher (`NotNewer`), so the next version is 4. The subjects of `examples/rosters/village-a.yaml` plus two new subjects, one consent state changed and one field value changed. It is the changed roster that demo step 5 checks, diffs and issues through the factory (Technical Plan §7.4 and §9). `RosterSet::open` does not recurse, so the directory `examples/rosters/next/` is not listed and the current files stay the ones that `survey check` and the Instruments page load.

#### 537. `examples/rosters/next/cohort-a.yaml` (Create)

*   **Type / Scope**: Example roster
*   **Proposed Changes**: Cohort `cohort-a`, `version: 2` (`examples/rosters/cohort-a.yaml` is at version 1), derived from `examples/rosters/cohort-a.yaml` in the same way as entry 536, for `school-meals-baseline`.

#### 227. `docs/how-to/manage-rosters.md` (Create)

*   **Type / Scope**: How-to
*   **Proposed Changes**: Check a roster against its survey, diff two versions (a file or `<cohort>@<version>`), list the store (the `issue` and `assign` sections are added in Phase 12); which fields reach a device (DIS-013); no subject ids on screen.

#### 228. `docs/index.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Link the roster how-to.

**Housekeeping**: `crates/apps/cli/README.md`: Add the roster verbs; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 10: Intake app, results reader and deployment wiring

*   **Goal**: Promote the development upload server to the production composition root `crates/apps/intake`, add the OIDC-protected results reader (`fieldseal-adapters-results-http`), keep practice mode as a separate binary, and rename the image and service. Technical Plan §7.1 and §7.2; Resolved Decisions 14, 15, 22, 25.
*   **Depends on**: Phase 5b (`just web` and `tools/dev-web.sh`, which entry 502 changes), Phase 6 (results export writers), Phase 7 (portal sessions), Phase 8 (file adapters).
*   **Commits**: Two commits. 10a: `Add the intake app and the practice endpoint` (new crates, practice split, deployment context, specs). 10b: `Run the intake app in the local stack` (flake, compose, Keycloak realm, scripts, docs).
*   **Gate** (must pass before the next phase starts):
    *   After 10a: `cargo test -p fieldseal-intake-app -p fieldseal-adapters-results-http -p fieldseal-adapters-upload-http`; `cargo test -p fieldseal-adapters-file --test intake_ports`; `cargo test -p fieldseal-deployment`; `fieldseal conformance run --suite contracts`; `python3 tools/check-architecture.py`.
    *   The intake app's production-refusal tests pass: one test per development adapter (the stores, the custody and the `dev` identity), exit 2 with `FIELDSEAL_ENVIRONMENT=production`. `landing-files` is not a development adapter and is not refused (§10.1).
    *   After 10b: run `just purge` first (the realm changed, and `tools/stack-up.sh` refuses an old `keycloak-data` volume, entry 276). Then `just up` starts, `tools/stack-smoke.sh --no-up` passes with the intake app on `:8480` and its portal on `:8481`; `tools/stack-run.sh` restart check finds a `replayed` event with `landed` above zero; `just acceptance` passes.
    *   Restart test: land a device export through `POST /v1/upload`, write the results export, restart the intake process on the same directories, write the results export again, and compare every file byte for byte.
    *   `just test` (20 s budget; re-measured against Phase 0b).
*   **Security review**: SR-5 (the data-protection reviewer): the results reader, covering the sign-in, the `results-reader` role check, CSRF on sign-out, the snapshot path allowlist and that nothing is written to disk. It blocks the Phase 10 merge. The five-control tests of §7.2 are the proof it reviews.

#### 230. `crates/apps/intake/Cargo.toml` (Create)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Package `fieldseal-intake-app`, binary `fieldseal-intake`, library `fieldseal_intake_app`. Dependencies: kernel, intake, delivery, collection, policy, trust, instrument, publishing, registration and deployment contexts (the deployment context supplies the `development-adapters` event, entry 569); adapters `file`, `landing-files`, `upload-http`, `portal`, `results-http` and `memory` (`MemoryIdentityProvider` for the `dev` identity, and ports); `tiny_http`, `getrandom`, `serde_json`. `fieldseal-adapters-oidc` is not a workspace dependency, so it is a path dependency (`{ path = "../../adapters/oidc" }`), as in the factory's manifest.

#### 231. `crates/apps/intake/src/main.rs` (Create)

*   **Type / Scope**: Rust module (composition root)
*   **Proposed Changes**: Reads configuration from the environment only, strictly (§7.6), builds the app, runs the replay, then serves two listeners.

#### 232. `crates/apps/intake/src/lib.rs` (Create)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: `IntakeApp::build(Config) -> Result<IntakeApp, ConfigError>`, `serve(&IntakeApp)`; the pieces below. A library so tests start the app in process.

#### 233. `crates/apps/intake/src/config.rs` (Create)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: `Config` with the intake variables of the table in Technical Plan §7.6: `FIELDSEAL_ENVIRONMENT`, `FIELDSEAL_INTAKE_BIND`, `_PUBLIC_URLS`, `_MAX_BODY` (renamed from `FIELDSEAL_UPLOAD_LISTEN`, `_PUBLIC_URLS`, `_MAX_BODY`), `FIELDSEAL_INTAKE_PORTAL_BIND`, `_PORTAL_URL`, `FIELDSEAL_IDENTITY` (`oidc`, or `dev` in development) with `FIELDSEAL_OIDC_*`, `FIELDSEAL_INTAKE_READER_ROLE`, `FIELDSEAL_CUSTODY*`, `FIELDSEAL_TRUST_BUNDLE`, `FIELDSEAL_TENANCY_DIR`, the directories `FIELDSEAL_LANDING_DIR`, `FIELDSEAL_INTAKE_SUBMISSIONS_DIR`, `FIELDSEAL_INTAKE_PUBLISHED_DIR` and `FIELDSEAL_INTAKE_ROSTERS_DIR`, `FIELDSEAL_INTAKE_ALLOWED_BUILDERS` and `_ALLOWED_SOURCES`, `FIELDSEAL_EXPORT_KEY_DIR`. Configuration is environment only and strict, and the exit codes follow §7.6. The export key is loaded as §6 (export key) says. There is no authority switch and no seed: the app serves the authority named by its custody and trust bundle. The results reader writes nothing to disk, so there is no save directory.

#### 234. `crates/apps/intake/src/wiring.rs` (Create)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: Builds `IntakeService` (gate), `DataPlatform` (landing-files), `SubmissionStore` (file), `InstrumentSource`, `RosterHistory`, `TenancyRegistry` (file, read-only snapshot of the factory's state), the receipt and receiver keys from custody, and the `UploadHttp` handler. Moves `EventPlatform` and `EventStore` from `crates/adapters/upload-http/src/bin/server.rs`; they have no test there, and entry 565 adds one. The `IdentityProvider` is `OidcIdentityProvider`, or `MemoryIdentityProvider` with the fixed login when `FIELDSEAL_IDENTITY=dev`.

#### 235. `crates/apps/intake/src/replay.rs` (Create)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: Start-up replay (INT-013a): runs `FileSubmissionStore::stored()` through the gate in the original order and times. A submission that fails logs `replay-failed`; start-up fails as §6 (landed state) says, and replay follows the append-only rule there. The upload listener does not accept connections until replay has finished (§7.1).

#### 236. `crates/apps/intake/src/dev_adapters.rs` (Create)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: The list of ports bound to development adapters; writes one `development-adapters` event at start (no personal data, DEP-051), built by the shared function of entry 569; refuses start (exit 2) in `production` with any development adapter in the table of §10.1 (the `file-dev` stores, the custody and the `dev` identity; not `landing-files`).

#### 237. `crates/apps/intake/tests/config.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Cases: `dep_012_every_variable_is_read_from_the_environment_only`, `dep_012_an_empty_or_untrimmed_value_is_unusable_configuration`, `dep_012_flags_are_true_or_false`, `dep_012_missing_required_variables_exit_2`, `int_089_the_results_reader_role_defaults_to_results_reader`, `dep_012_a_missing_wrong_length_or_wrong_mode_export_key_exits_2_and_is_never_created`.

#### 238. `crates/apps/intake/tests/production_refusal.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: One test per development adapter, exit 2 under `FIELDSEAL_ENVIRONMENT=production`: `dep_023_production_refuses_file_dev_custody`, `..._memory_dev_custody`, `..._a_file_submission_store`, `..._a_memory_submission_store`, `..._a_file_roster_history`, `..._a_file_instrument_source`, `..._a_file_tenancy_registry`, `..._the_dev_identity`, and `..._a_file_export_key`; plus `dep_051_the_development_adapters_event_lists_every_development_port`.

#### 239. `crates/apps/intake/tests/upload_flow.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Starts the app in process on ephemeral ports with memory-dev custody in a temp dir: `int_011_challenge_upload_and_receipts`, `int_013a_replay_runs_before_the_upload_listener_serves`, `int_013a_a_failed_replay_stops_start_up_and_readyz`, `int_013a_a_withdrawal_after_landing_does_not_remove_a_replayed_submission`, `int_011_a_duplicate_upload_lands_nothing`.

#### 240. `crates/apps/intake/tests/restart_export.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `int_013a_the_export_is_byte_identical_after_a_restart_on_the_same_directories`: upload a device export, write the results export directory (`write_export`), restart, write again, compare every file including the manifest digests and findings.

#### 241. `crates/apps/intake/README.md` (Create)

*   **Type / Scope**: Crate contract (EGM)
*   **Proposed Changes**: Purpose; the two listeners and their audiences; the configuration table; invariants (never serves uploads before replay; refuses development adapters in production; no personal data in events; portal separate from the device-facing port); template: `crates/apps/factory/README.md`.

#### 242. `crates/adapters/results-http/Cargo.toml` (Create)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Package `fieldseal-adapters-results-http`; dependencies: kernel, trust (for `AuthorityClock`), intake and registration contexts, `fieldseal-adapters-portal`, `fieldseal-adapters-landing-files`, `serde_json`.

#### 243. `crates/adapters/results-http/src/lib.rs` (Create)

*   **Type / Scope**: Rust module (results reader adapter)
*   **Proposed Changes**: `ResultsHttp::new(sessions: PortalSessions, provider: &dyn IdentityProvider, platform: &dyn DataPlatform, instruments: &dyn InstrumentSource, export_key: ExportKey, clock: &dyn AuthorityClock, cfg: ResultsConfig)`; `handle(&Request) -> Response`. The intake app builds the sessions as `PortalSessions::new("fs_intake_session", secure, ttl_ms)`, with `secure` following `FIELDSEAL_INTAKE_PORTAL_URL`. Every call that depends on time passes `now: AuthorityTime` read from `clock`; the callback passes the whole decoded query map to `PortalSessions::finish`. Every page goes through `Response::html(status, body, csp)` with `ResultsConfig.csp`, which is the factory's policy without `img-src` because the reader shows no images: `default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`. Downloads carry `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`. Every results route needs a session whose `AuthenticatedPerson.role_names` contains the `results-reader` role and, by default, a phishing-resistant method (REG-002).

#### 244. `crates/adapters/results-http/src/routes.rs` (Create)

*   **Type / Scope**: Rust module (results reader adapter)
*   **Proposed Changes**: Routes: `GET /`, `GET /sign-in`, `GET /sign-in/callback`, `POST /sign-out` (session and CSRF), `GET /results`, and `GET /results/exports/{mark}/{path}`. `{path}` is matched against a fixed list (`results.csv`, `results.jsonl`, `free_text.csv`, `free_text.jsonl`, `codebook.csv`, `manifest.json`) or `contracts/<fingerprint>.json` where `<fingerprint>` is exactly 64 lower-case hex digits and appears in the manifest; any other path is `404 not-found`, and a mark the results reader does not hold is `404 unknown-mark`. No session: 302 to sign-in for a page, 401 `sign-in-required` for a download. No role: 403 `not-authorised`. There is no route that changes server state other than sign-in and sign-out.

#### 245. `crates/adapters/results-http/src/pages.rs` (Create)

*   **Type / Scope**: Rust module (results reader adapter)
*   **Proposed Changes**: HTML: a plain paged table of the results export for the current landing mark; contracts; manifest preview; links to the downloads of that mark; the unprotected-data statement beside the links; the development-adapter label when the app reports any. Computes nothing from answers (counts are the gate's and the landing's); the data contract is rendered from the published instrument at request time.

#### 246. `crates/adapters/results-http/src/downloads.rs` (Create)

*   **Type / Scope**: Rust module (results reader adapter)
*   **Proposed Changes**: `GET /results/exports/{mark}/{path}`: opens the landing snapshot, takes its landing mark, builds the results export for that mark once with the shared writer and the keyed subject mapper, keeps the built export in memory for the last four marks (immutable; nothing is written to the server's disk) and serves the one requested file as a download, byte-identical to what `fieldseal intake results` writes for the same landing snapshot, published directory and key. The CSV guard of §6 applies and has no switch. Logs sign-ins and downloads without the account's personal data.

#### 247. `crates/adapters/results-http/tests/reader_access.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: With `MemoryIdentityProvider` and two logins: `int_089_no_session_redirects_a_page_and_gives_401_for_a_download`, `int_089_a_collector_without_the_role_gets_403_not_authorised`, `int_089_a_reader_with_a_weak_method_is_refused`, `int_089_sign_out_without_the_csrf_token_gets_403`, `int_089_sign_out_ends_the_session`, `int_089_the_cookie_is_named_fs_intake_session`, `int_090_events_carry_no_account_personal_data`.

#### 248. `crates/adapters/results-http/tests/export_view.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `int_085_results_csv_download_is_the_results_export_of_the_shared_table`, `int_085_every_download_equals_the_cli_output_byte_for_byte_for_the_same_landing_and_key` (results.csv, results.jsonl, free_text.csv, free_text.jsonl, the data contract, the codebook and manifest.json), `int_085_the_results_reader_writes_nothing_to_disk`, `int_085_a_held_mark_does_not_change_when_a_submission_lands`, `int_085_an_unknown_or_evicted_mark_is_404`, `int_085_a_path_outside_the_fixed_list_is_404`, `int_085_a_contract_name_that_is_not_64_lower_case_hex_digits_is_404`, `int_085_a_fingerprint_absent_from_the_manifest_is_404`, `int_090_the_page_shows_the_replay_gap_count`, `int_088_free_text_csv_matches_the_free_text_file`, `int_086_excluded_rows_never_appear_in_the_results_reader`, `int_087_subjects_in_the_results_reader_are_keyed_hashes`, `int_092_the_page_computes_nothing_from_the_answers`.

#### 249. `crates/adapters/results-http/README.md` (Create)

*   **Type / Scope**: Crate contract (EGM)
*   **Proposed Changes**: Purpose, routes table, access rules, invariants, tests.

#### 250. `crates/adapters/upload-http/src/bin/server.rs` (Delete)

*   **Type / Scope**: Rust binary (development upload server)
*   **Proposed Changes**: Replaced by the intake app (stack mode) and by `practice.rs` (practice mode).

#### 251. `crates/adapters/upload-http/src/bin/practice.rs` (Create)

*   **Type / Scope**: Rust binary
*   **Proposed Changes**: `fieldseal-upload-practice`: the practice authority (fixed seeds, in-memory ports, one practice device per `--device` label) with flags `--listen`, `--public-url`, `--seed`, `--max-body`, `--device`. Refuses `FIELDSEAL_ENVIRONMENT=production`. In no image, compose file or manifest. Used for development and DEL-071 conformance runs; `fieldseal intake practice` does not start it, because that command writes a practice device export file and starts no server.

#### 252. `crates/adapters/upload-http/Cargo.toml` (Modify)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: `[[bin]]` becomes `fieldseal-upload-practice` (`src/bin/practice.rs`); drop both `fieldseal-adapters-file` and `fieldseal-adapters-landing-files`: only the deleted binary used them (`src/bin/server.rs`, lines 32 to 37), and the practice binary uses in-memory ports.

#### 254. `crates/apps/cli/src/conformance_cmd/contracts.rs` (Modify)

*   **Type / Scope**: Rust module (conformance)
*   **Proposed Changes**: The `EventPlatform` entry (INT-011, line 118) becomes `cargo test -p fieldseal-intake-app --test event_platform int_011` (entry 565). The command it replaces names the binary `fieldseal-upload-server`, which entry 250 deletes, and that binary has no test, so the entry runs nothing today. The three entries that name no test are repointed at the tests of entry 564: `FileTenancyRegistry` (INT-006, line 117) to `cargo test -p fieldseal-adapters-file --test intake_ports int_006`, `FileRosterHistory` (INT-040, line 120) to `... int_040`, and `PublishedInstruments` (INT-070, line 121) to `... int_070`.

#### 564. `crates/adapters/file/tests/intake_ports.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: The conformance table points `FileTenancyRegistry`, `FileRosterHistory` and `PublishedInstruments` at `cargo test -p fieldseal-adapters-file del_071`, `int_040` and `int_070`, which name no test, and the crate has no `tests` directory before Phase 6 (entries 559 and 210). Cases, each running the shared contract of `fieldseal_intake::contract` with a fresh temporary directory per call: `int_006_the_file_tenancy_registry_satisfies_the_contract` (`tenancy_registry_contract`, with a tenancy record written through `FileRegistryStore`), `int_040_the_file_roster_history_satisfies_the_contract` (`roster_history_contract`) and `int_070_the_published_instruments_reader_satisfies_the_contract` (`instrument_source_contract`, with one `*.published` file built from the publishing test fixtures and the matching trust bundle and policy).

#### 565. `crates/apps/intake/tests/event_platform.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `int_011_the_event_platform_satisfies_the_data_platform_contract`: runs `fieldseal_intake::contract::data_platform_contract` with an `EventPlatform` over an in-memory platform for each call, and `int_011_the_event_platform_prints_one_event_per_landing_and_none_for_instruments` (it captures the event lines the wrapper writes). The wrappers had no test in `server.rs`.

#### 256. `crates/contexts/deployment/src/validate.rs` (Modify)

*   **Type / Scope**: Rust module (Deployment context)
*   **Proposed Changes**: `ports(Intake)` gains the required ports `IdentityProvider` (`oidc`, `memory-dev`), `RosterHistory` (`file-dev`) and `InstrumentSource` (`file-dev`), and `SubmissionStore` gains the adapter `file-dev`. DEP-002 then requires every manifest to bind the new ports (entry 567). `file-dev` and `memory-dev` are already in `DEVELOPMENT_ADAPTERS`, so validation refuses them in `production` (DEP-023). `landing-files` is not a development adapter (§10.1): it stays out of `DEVELOPMENT_ADAPTERS` and out of the intake app's start-up refusal list.

#### 257. `crates/contexts/deployment/src/render.rs` (Modify)

*   **Type / Scope**: Rust module (Deployment context)
*   **Proposed Changes**: `intake_aliases` writes the renamed variables `FIELDSEAL_INTAKE_BIND`, `_PUBLIC_URLS` and `_MAX_BODY` (from `bind`, `publicUrl` and `maxBodyBytes`, entry 566), `FIELDSEAL_INTAKE_PORTAL_BIND` and `_PORTAL_URL` (from `portal.bind` and `portal.publicUrl`), the identity variables, `FIELDSEAL_INTAKE_ALLOWED_BUILDERS` and `FIELDSEAL_INTAKE_ALLOWED_SOURCES` (comma-separated, from the `PolicyEngine` config keys `allowedBuilders` and `allowedSources`), `FIELDSEAL_INTAKE_SUBMISSIONS_DIR` (the `SubmissionStore` `dir`), `FIELDSEAL_INTAKE_PUBLISHED_DIR` (`dirs.published`), `FIELDSEAL_INTAKE_ROSTERS_DIR` (`dirs.rosterHistory`), `FIELDSEAL_EXPORT_KEY_DIR` (`dirs.exportKey`) and `FIELDSEAL_ENVIRONMENT`. It keeps `FIELDSEAL_LANDING_DIR` (line 231, DEP-057; `dirs.landing` when set, else the `DataPlatform` `dir`) and `FIELDSEAL_TENANCY_DIR` unchanged, and it stops writing `FIELDSEAL_UPLOAD_AUTHORITY=stack` (line 218): the intake app has no authority switch.

#### 566. `crates/contexts/deployment/src/manifest.rs` (Modify)

*   **Type / Scope**: Rust module (Deployment context)
*   **Proposed Changes**: `ComponentSpec` (lines 80 to 87) gains the named keys that the intake app needs and that no adapter config carries: `portal.bind`, `portal.publicUrl`, `publicUrl`, `maxBodyBytes` and `dirs.{published,issued,landing,rosterHistory,exportKey}`. `portal` and `dirs` are decoded strictly: an unknown key under either is refused. The intake `rosterHistory` directory is `/published/rosters` in Phases 10 to 12 and `/issued` (read-only) from Phase 13; `published` is `/published`.

#### 567. `examples/deployments/sample.yaml` (Modify)

*   **Type / Scope**: Deployment manifest and examples
*   **Proposed Changes**: Also `docs/explanation/adr/0040-examples/fieldseal.deploy.yaml` and the example in `docs/reference/spec/deployment.md` (section 6, around line 154). The intake component binds the ports that entry 256 makes required: `IdentityProvider: { adapter: oidc, config: { issuer, clientId: { secretRef: ... } } }`, `RosterHistory: { adapter: file-dev, config: { dir } }` and `InstrumentSource: { adapter: file-dev, config: { dir } }`, so both files and the spec example validate (DEP-002). Because `file-dev` is a development adapter, DEP-023 refuses these manifests in `production`, which is also true of the services themselves until production adapters exist (§10.1). The spec example gains the same three lines and a sentence saying so.

#### 569. `crates/contexts/deployment/src/events.rs` (Create)

*   **Type / Scope**: Rust module (Deployment context)
*   **Proposed Changes**: `development_adapters_event(service: &str, adapters: &[(&str, &str)]) -> String`: the one place that builds the `development-adapters` start-up event (service name, then each port with the development adapter bound to it; no personal data, DEP-051). The intake app (entry 236), the factory (entry 322) and the transparency-log server (entry 593) print its result, so the three events have the same shape. Pure formatting, so it fits the context layer; a test in `crates/contexts/deployment/tests/development_adapters.rs` (entry 429) checks the shape.

#### 259. `crates/contexts/deployment/tests/intake_component.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `dep_057_the_intake_component_renders_the_listed_variables`, `dep_057_a_file_submission_store_is_a_development_adapter`, `dep_023_validate_refuses_intake_development_adapters_in_production` (the three `file-dev` stores and the `memory-dev` identity), `dep_023_validate_does_not_refuse_landing_files_in_production`, `dep_002_a_manifest_without_the_new_intake_ports_is_refused`, `dep_002_the_example_manifests_bind_the_new_intake_ports`, `dep_012_the_rendered_environment_carries_the_directories_the_intake_app_reads`.

#### 260. `docs/reference/conformance.md` (Modify)

*   **Type / Scope**: Generated documentation
*   **Proposed Changes**: Regenerate the matrix with `fieldseal conformance matrix` (the INT-011 command changed).

#### 261. `docs/reference/spec/delivery.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: DEL-071 names the intake app and says practice mode is `fieldseal-upload-practice`.

#### 262. `docs/reference/spec/deployment.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: DEP-057 lists the rendered variables for intake and states that the `file-dev` stores for submissions, roster history and published instruments are development adapters, and that `landing-files` is not. The example in section 6 gains the intake ports of entry 256 (entry 567).

#### 263. `docs/reference/spec/intake.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: INT-013a: "the intake service" and the replay rule (a failed replay stops start-up and fails readiness; replay does not apply later withdrawals); add INT-089 (the results reader requires a session with the `results-reader` role and a phishing-resistant method; sign-out needs CSRF; every other results route is a GET), INT-090 (results reader events carry no account personal data) and INT-092 (the results reader MUST NOT derive anything from the answers: no indicators, scores, unit conversions or per-question statistics; the operational counts that the gate and the landing report are allowed). INT-092 restates the former WEB-161 for the reader.

#### 264. `docs/explanation/adr/0028-clean-architecture.md` (Modify)

*   **Type / Scope**: ADR note
*   **Proposed Changes**: Add a note that `crates/apps/intake` is the intake composition root.

#### 265. `docs/explanation/adr/0021-export-upload-receipts.md` (Modify)

*   **Type / Scope**: ADR note
*   **Proposed Changes**: Add a note that the server binary is now the intake app.

#### 266. `architecture.toml` (Modify)

*   **Type / Scope**: Architecture rules
*   **Proposed Changes**: Add `fieldseal-intake-app` to the `apps` list. The two new adapter crates match the `fieldseal-adapters-` prefix.

#### 267. `Cargo.toml` (Modify)

*   **Type / Scope**: Workspace manifest
*   **Proposed Changes**: Add `fieldseal-adapters-results-http` to `[workspace.dependencies]`.

#### 272. `flake.nix` (Modify)

*   **Type / Scope**: Nix flake
*   **Proposed Changes**: `serviceImage` (line 220) takes `name bin port mounts` and exposes one port; it changes to take a list of ports (`ports`), and `ExposedPorts` becomes the union of them. The three callers change with it: `factory-image` passes `[ 8080 ]`, `translog-image` passes `[ 8080 ]`, and the upload image (renamed below) passes `[ 8480 8481 ]`. `uploadBin` becomes `intakeBin = serviceBin "fieldseal-intake" "fieldseal-intake-app"`; `upload-image` becomes `intake-image = serviceImage "fieldseal-intake" intakeBin [ 8480 8481 ] [ "/landing" "/submissions" "/published" ]`; the package output `fieldseal-upload-server` becomes `fieldseal-intake`; the `inherit` list at line 458 follows by renaming `uploadBin` to `intakeBin`.

#### 273. `deploy/local/compose.yaml` (Modify)

*   **Type / Scope**: Compose file
*   **Proposed Changes**: Service `upload` becomes `intake`, image `fieldseal-intake:local`, `network_mode: "service:keycloak"` (as the factory) so the issuer URL a browser uses is the one the app reaches; ports 8480 and 8481 move to Keycloak's `ports` list; `env_file: [.generated/intake.env]` carries all configuration and the hand-set `FIELDSEAL_INTAKE_*_DIR`, `FIELDSEAL_INTAKE_ALLOWED_BUILDERS`, `FIELDSEAL_INTAKE_ALLOWED_SOURCES` and `FIELDSEAL_UPLOAD_PUBLIC_URLS` lines are removed; `FIELDSEAL_INTAKE_URL` in `demo` and `FIELDSEAL_UPLOAD_URL` in `web` become `http://localhost:8480`; add the OIDC client secret for `fieldseal-intake` (`FIELDSEAL_SECRET_INTAKE_OIDC_CLIENT_SECRET`) to the intake service, and to the `keycloak` service, which reads it for the realm placeholder (`${FIELDSEAL_SECRET_INTAKE_OIDC_CLIENT_SECRET:?run just up}`, the pattern of line 36 for the factory client).

#### 274. `deploy/local/keycloak/fieldseal-realm.json` (Modify)

*   **Type / Scope**: Keycloak realm
*   **Proposed Changes**: Add realm role `results-reader`; give it to the existing user `product-owner`; add confidential client `fieldseal-intake` (secret `${FIELDSEAL_SECRET_INTAKE_OIDC_CLIENT_SECRET}`, redirect URI `http://localhost:8481/sign-in/callback`, PKCE `S256`, `acr.loa.map` `{"phr":"2"}`, roles mapper into the ID token as for the factory client). Keycloak imports the realm only into an empty volume, so this change reaches an existing stack only after `just purge` (entry 276).

#### 275. `examples/deployments/local-stack.yaml` (Modify)

*   **Type / Scope**: Deployment manifest
*   **Proposed Changes**: Intake: `bind: 0.0.0.0:8480`, `portal: { bind: 0.0.0.0:8481, publicUrl: http://localhost:8481 }` (the listeners must be on all interfaces because the service shares Keycloak's network namespace), `IdentityProvider: oidc` (client `fieldseal-intake`, secretRef `intake-oidc-client-secret`), `SubmissionStore: file-dev` at `/submissions`, `RosterHistory: file-dev` at `/published/rosters` (Phase 13 moves it to `/issued`, entry 387), `InstrumentSource: file-dev` at `/published`, `DataPlatform: landing-files` at `/landing`, `dirs.exportKey` `/authority/export-key`, and the publishing allowlists in the `PolicyEngine` config (`allowedBuilders: ["https://ci.example.org/builders/fieldseal-publish"]`, `allowedSources: ["https://git.example.org/authority/artefacts"]`, the values of the published policy; Technical Plan §8).

#### 276. `tools/stack-up.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: (1) Generate `FIELDSEAL_SECRET_INTAKE_OIDC_CLIENT_SECRET`. The script writes `.env.secrets` only when the file is missing (line 21), so it now appends any secret that an existing file lacks instead of leaving the file alone. (2) Keep Keycloak's realm honest: record the SHA-256 of `deploy/local/keycloak/fieldseal-realm.json` in `deploy/local/.state/realm.sha256` when the `keycloak-data` volume is first created. `--import-realm` skips a realm that already exists, so an old volume would never see a new client or role; when the digest differs from the record, or no record exists but the engine lists a `keycloak-data` volume, the script refuses to start and prints "the Keycloak realm changed; run `just purge`". (3) Wait for `:8480/healthz` named "intake"; print the results reader URL `http://localhost:8481`.

#### 568. `tools/stack-down.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: `--purge` also removes `deploy/local/.state/realm.sha256` and nothing else under `.state`, which `just web` uses. Without this the record would outlive the volume it describes.

#### 545. `tools/stack-init.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: The explicit authority set-up step also creates `export.key` in the authority's `export-key` directory as §6 (export key) specifies, and leaves an existing file unchanged. The step goes before the early exit at line 10 (`[ ! -f "$A/.initialised" ] || { ...; exit 0; }`), so an authority that was initialised before this phase also gets its key. `tools/dev-web.sh` reaches the same step through this script (entry 418).

#### 277. `tools/stack-images.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Names: `factory intake translog cli web demo`.

#### 278. `tools/stack-status.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Probe `intake` on both ports.

#### 279. `tools/stack-smoke.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Probe `intake /healthz` and the portal `GET /` (200) and `GET /results` without a session (302).

#### 280. `tools/stack-run.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: `compose logs intake`; extend the restart check to produce the results export directory before and after the restart and compare it byte for byte.

#### 281. `tools/stack-demo.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Default `INTAKE` URL `http://localhost:8480`.

#### 282. `tools/release-images.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Line 17: `for svc in factory intake translog web cli`.

#### 283. `tools/release-docs.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Line 21: `--build "intake=$(image intake)"`; comment at line 6.

#### 285. `.github/workflows/build.yml` (Modify)

*   **Type / Scope**: CI workflow
*   **Proposed Changes**: Comment at line 6: the service list names `intake`.

#### 286. `docs/how-to/run-the-local-stack.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Service names, ports 8480 and 8481, the results reader sign-in.

#### 287. `docs/how-to/use-the-web-app.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Change the upload endpoint's name to the intake app's.

#### 288. `docs/tutorials/hands-on.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Section 10 (what intake landed) mentions the results reader and `fieldseal intake results`.

#### 502. `tools/dev-web.sh` and `examples/deployments/dev-web.yaml` (Modify)

*   **Type / Scope**: Shell script and deployment manifest
*   **Proposed Changes**: Add the intake app: the manifest gains the Intake component with the bindings of entry 256 (`IdentityProvider: memory-dev` for now, `SubmissionStore`, `RosterHistory` and `InstrumentSource` as `file-dev`, `DataPlatform: landing-files`) and directories under `deploy/local/.state/dev-web/`; the script starts `fieldseal-intake` (`:8480`, `:8481`) with `cargo run -p fieldseal-intake-app` and its rendered env file, with `FIELDSEAL_IDENTITY=dev` and no client secret, and waits for `/healthz`. Until the development IdP exists (Phase 11) the results reader signs in as the factory's `memory-dev` identity does. The authority set-up of entry 545 has already created `export.key`.

**Housekeeping**: `crates/adapters/upload-http/README.md`: Holds the protocol code (client and handler) and the practice binary only; `crates/contexts/deployment/README.md`: Intake component ports and adapters; `Cargo.lock`: New workspace members; `crates/apps/README.md`: List `intake`; `crates/adapters/README.md`: List `results-http`; line 21: `upload-http` holds the protocol code and the practice binary (no `fieldseal-upload-server`); `crates/README.md`: Line 17: the apps description names the intake app; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 11: OIDC access-token verification and the development IdP

*   **Goal**: Add `OidcIdentityProvider::verify_access_token` and a raw-token sign-in finish to `crates/adapters/oidc`, and the development-only OIDC provider `crates/apps/dev-idp`. Neither is called by a service yet. Technical Plan §7.5; Resolved Decisions 29 and 30.
*   **Depends on**: Phase 5b (entry 503 changes `tools/dev-web.sh`) and Phase 0b. (`dev-idp` itself has no dependency on the earlier phases.)
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `cargo test -p fieldseal-adapters-oidc --test access_token` (every refusal and the accepted cases).
    *   `cargo test -p fieldseal-dev-idp`: the provider serves discovery, authorisation with PKCE, token and JWKS; a test drives it with `OidcIdentityProvider` end to end (sign in, ID token verified, access token verified).
    *   `fieldseal-dev-idp` exits 2 without `--development-tool`, with `FIELDSEAL_ENVIRONMENT=production`, and on a non-loopback bind address.
    *   `python3 tools/check-architecture.py`; `just test`.
*   **Security review**: SR-4 (operator access-token path: verifier, client claim, `typ` and `nonce` rules, `acr`/`amr` source, clock leeway, and the development IdP). The review starts with this commit and must sign off before Phase 12 merges. Nothing calls the verifier before Phase 12.

#### 290. `crates/adapters/oidc/src/lib.rs` (Modify)

*   **Type / Scope**: Rust module (OIDC adapter)
*   **Proposed Changes**: `OidcConfig` gains `api_audience: Option<String>`, `cli_client_id: Option<String>`, `accept_typ_jwt: bool`. New `OidcIdentityProvider::verify_access_token(&self, token: &str) -> Result<AuthenticatedPerson, IdentityError>` reusing the signature and JWKS code and applying the claim checklist in the table of Technical Plan §7.5 (signature and algorithm, `iss`, `aud`, `exp`, `iat`, `nbf`, `sub`, header `typ` with the payload `typ: Bearer` rule, the `nonce` refusal, the client claim with its `azp` fallback, and the sources of roles, `acr` and `amr`). The access-token lifetime is the IdP's (5 minutes in the Keycloak realm); nothing caches the token. New `finish_sign_in_raw(&self, pending: &PendingSignIn, callback: &BTreeMap<String, String>) -> Result<RawSignIn, IdentityError>`, with `RawSignIn { person: AuthenticatedPerson, access_token: String, id_token_nonce_checked: bool }`, so the CLI gets the raw access token next to the verified person. It takes the same arguments as `IdentityProvider::finish_sign_in` and does the same checks on the ID token.

#### 291. `crates/adapters/oidc/tests/access_token.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: The crate has no tests today, so the mock IdP is new: a `tiny_http` server (already a dev-dependency) that serves discovery and a key set. The fixture `tests/fixtures/test-rsa-2048.der`, which nothing uses yet, is an RSAPrivateKey in PKCS#1 form (`openssl asn1parse` shows a version of 0, then the modulus and the other integers, with no algorithm identifier). The mock therefore signs tokens with ring's `RsaKeyPair::from_der`, which takes PKCS#1; `from_pkcs8` would reject the file. Cases: `reg_070a_a_valid_token_yields_the_person_roles_and_methods`, `reg_070a_a_bad_signature_is_refused`, `reg_070a_alg_none_and_hs256_are_refused`, `reg_070a_a_wrong_issuer_is_refused`, `reg_070a_a_token_without_the_api_audience_is_refused`, `reg_070a_an_id_token_is_refused_as_an_access_token`, `reg_070a_an_expired_token_is_refused`, `reg_070a_iat_or_nbf_in_the_future_is_refused`, `reg_070a_a_missing_sub_is_refused`, `reg_070a_typ_at_jwt_is_accepted`, `reg_070a_typ_jwt_is_refused_unless_configured`, `reg_070a_typ_jwt_is_accepted_only_with_the_payload_typ_bearer`, `reg_070a_a_token_carrying_a_nonce_is_refused`, `reg_070a_an_id_token_from_the_cli_client_that_carries_the_api_audience_is_refused`, `reg_070a_another_typ_is_refused`, `reg_070a_a_token_for_another_client_is_refused`, `reg_070a_azp_stands_in_when_client_id_is_absent`, `reg_070a_acr_without_amr_is_phishing_resistant_by_acr`, `reg_070a_the_key_set_is_refetched_once_on_an_unknown_kid`.

#### 293. `crates/apps/dev-idp/Cargo.toml` (Create)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Package `fieldseal-dev-idp`, binary `fieldseal-dev-idp`, library `fieldseal_dev_idp`. Dependencies: `fieldseal-kernel`, `p256.workspace`, `tiny_http`, `serde_json`, `getrandom`, `fieldseal-adapters-authoring` (YAML config), dev-dependency `fieldseal-adapters-oidc`.

#### 294. `crates/apps/dev-idp/src/main.rs` (Create)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: Refuses to start unless `--development-tool` is given, `FIELDSEAL_ENVIRONMENT=development` (any other value, including `production`, exits 2) and the bind address is loopback. Prints a banner and writes a `development-adapters`-style event naming itself. Flags `--config` (default `examples/deployments/dev-idp.yaml`) and `--bind <addr:port>` (default `localhost:8180`; loopback hosts only, and the issuer is `http://<bind>/realms/fieldseal`, §7.5).

#### 295. `crates/apps/dev-idp/src/lib.rs` (Create)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: `DevIdp::start(Config, listener)`; the pieces below.

#### 296. `crates/apps/dev-idp/src/config.rs` (Create)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: Loads logins (login, subject, roles, `amr`, `acr`), clients (`fieldseal-factory` and `fieldseal-intake` confidential, with redirect URIs and a secret read at start-up from the `FIELDSEAL_SECRET_*` variables of Technical Plan §7.6; `fieldseal-cli` public, with no secret), and the API audience. The file contents are listed under "Configuration file" in Technical Plan §7.5.

#### 297. `crates/apps/dev-idp/src/server.rs` (Create)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: Issuer `http://localhost:8180/realms/fieldseal`. Routes: the four Keycloak paths listed under "Routes" in Technical Plan §7.5 (discovery, authorization with PKCE `S256`, token, certs). The paths follow Keycloak's, so discovery is the only thing a client reads and the factory and intake configuration is identical against the development IdP and Keycloak.

#### 298. `crates/apps/dev-idp/src/tokens.rs` (Create)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: ES256 signing with a key generated at start. The ID token and access token claims are those listed under "Token claims" in Technical Plan §7.5: the access token has the header type `at+jwt`, the API audience, `client_id`, `jti` and no `nonce`; the ID token carries `nonce` and `acr` (`phr` for both logins).

#### 299. `crates/apps/dev-idp/tests/flows.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `reg_002_the_factory_adapter_signs_in_against_the_dev_idp`, `reg_070a_the_cli_flow_obtains_an_access_token_the_verifier_accepts`, `reg_070a_login_hint_approves_without_a_page`, `reg_070a_without_a_login_hint_the_login_page_lists_the_logins`, `reg_002_pkce_s256_is_required`, `reg_002_an_unregistered_redirect_uri_is_refused`, `reg_002_the_issuer_follows_the_bind_address`.

#### 300. `crates/apps/dev-idp/tests/refusals.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `dep_023_exits_2_without_development_tool`, `dep_023_exits_2_in_production`, `dep_023_exits_2_on_a_non_loopback_bind`, `dep_023_it_appears_in_no_image_compose_file_or_manifest` (greps `flake.nix`, `deploy/local/compose.yaml` and `examples/deployments/*.yaml` for the pattern `fieldseal-dev-idp`, and excludes `examples/deployments/dev-idp.yaml`, which is the tool's own configuration).

#### 301. `crates/apps/dev-idp/README.md` (Create)

*   **Type / Scope**: Crate contract (EGM)
*   **Proposed Changes**: Purpose (a development tool standing where Keycloak stands), routes, config file, refusals, what it is not (not an adapter, not in any image).

#### 302. `examples/deployments/dev-idp.yaml` (Create)

*   **Type / Scope**: Example configuration
*   **Proposed Changes**: Logins `presenter` (subject `00000000-0000-4000-8000-000000000001`; roles `collector`, `operator`, `results-reader`) and `collector1` (subject `00000000-0000-4000-8000-000000000002`; role `collector` only), both with `acr: phr`, which the OIDC adapter treats as phishing-resistant by default; clients `fieldseal-factory`, `fieldseal-intake`, `fieldseal-cli`; API audience `fieldseal-factory-api`.

#### 303. `docs/reference/spec/registration.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add REG-070a: operator API routes MUST authenticate an `Authorization: Bearer` JWT access token (RFC 9068 profile) from the configured IdP, verified for signature, issuer, audience (the factory API identifier), expiry, `typ` (a `JWT` header only with the payload `typ: Bearer`), the absence of a `nonce` claim, the client, the `operator` role and a phishing-resistant sign-in method. Id provisional.

#### 304. `architecture.toml` (Modify)

*   **Type / Scope**: Architecture rules
*   **Proposed Changes**: Add `fieldseal-dev-idp` to the `apps` list.

#### 503. `tools/dev-web.sh` and `examples/deployments/dev-web.yaml` (Modify)

*   **Type / Scope**: Shell script and deployment manifest
*   **Proposed Changes**: Add the development IdP: the script starts `fieldseal-dev-idp --development-tool` on `localhost:8180` before the services and waits for its discovery document; the manifest switches the factory's identity provider from the `dev` identity to `oidc` at the issuer `http://localhost:8180/realms/fieldseal`, the one the stack's Keycloak uses. The script also creates `deploy/local/.state/dev-web/secrets` once (mode 0600) with `FIELDSEAL_SECRET_FACTORY_OIDC_CLIENT_SECRET` and `FIELDSEAL_SECRET_INTAKE_OIDC_CLIENT_SECRET` (24 random bytes each, as 48 hex digits, as `tools/stack-up.sh` does for the stack), and loads the file into the environment of the development IdP, the factory and the intake app only. The manifest names them `{ secretRef: factory-oidc-client-secret }` and `{ secretRef: intake-oidc-client-secret }`.

**Housekeeping**: `crates/adapters/oidc/README.md`: Document `verify_access_token`, `finish_sign_in_raw`, the new config fields and invariants (no token is cached; no second source for `acr`/`amr`), and correct the Verification section (line 42), which says the tests use an in-test mock identity provider although the crate had no tests before this phase; `Cargo.lock`: New workspace member; `crates/apps/README.md`: List `dev-idp`; `crates/README.md`: Line 17: the apps description names the development IdP; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 12: Roster issue, cohort assignments and certificate reissue as factory operations; `roster issue` and `roster assign`

*   **Goal**: The operator operations `IssueRoster`, `AssignCohort` (which creates the collector's account when it does not exist yet) and `ListAssignments` (`POST /v1/rosters`, `POST/GET /v1/assignments`) behind Bearer access tokens; the journaled `RosterIssue` and `Assignment` records (an assignment targets one account, and generation 1 is recorded per cohort and tenancy); certificate reissue when a tenancy's cohort set changes; and `fieldseal roster issue` and `roster assign` with the OIDC loopback sign-in. The `cohorts:` string and `FIELDSEAL_COHORTS` go. The factory also reads the artefact registry and reads and writes the roster store, because `IssueRoster` writes it and `AssignCohort` checks `unknown-survey` and `unknown-cohort` against both. The stack and `just web` run publish, issue and assign in the order of §8. Technical Plan §7.4 and §7.5; Resolved Decisions 17, 24 and 29.
*   **Depends on**: Phase 5b (the publish script and the policy), Phase 8 (file artefact registry and roster adapters), Phase 9 (roster group), Phase 10 (stack with intake and realm changes), Phase 11 (verifier and development IdP).
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `cargo test -p fieldseal-registration -p fieldseal-adapters-memory -p fieldseal-adapters-file` (`registry_store_contract` includes the assignment case).
    *   `cargo test -p fieldseal-deployment`; `cargo test -p fieldseal-adapters-factory-http --test assignments --test rosters`; `cargo test -p fieldseal-security-tests --test operator_api --test keycloak_realm`; `cargo test -p fieldseal-cli --test roster_assign --test roster_issue`.
    *   Run `just purge` first (the realm changes again, entry 342). `just up` runs `tools/stack-run.sh seed`, `issue` and `assign` (order as §8; the assignments go to the `product-owner` account, subject `00000000-0000-4000-8000-000000000003`, which has not signed in yet, so `AssignCohort` creates the account; the operator sign-in runs through `tools/stack-browser.sh`); `fieldseal roster assign --list` prints both journaled assignments; a second run prints `unchanged` and writes no record. Record how much the demo-image build adds to `just up`.
    *   An assignment for a survey that is not published is refused `unknown-survey`, and one for a cohort with no stored roster is refused `unknown-cohort`; after `seed` and `issue` the same command succeeds. `just web` and the service fixture of Phase 16a follow §8.
    *   A registered tenancy's certificate is reissued with a new serial when an assignment changes its cohort set, and the reissued certificate names the new cohorts; a tenancy of another account is unchanged.
    *   The items to confirm in the Keycloak row of Risks & Mitigations are confirmed and recorded in the commit message.
    *   `just test`.
*   **Security review**: SR-4 signs off before merge (sign-in path, verification per request, no token cache, the roster body as personal data, journal records, certificate reissue, per-account scope).

#### 309. `crates/contexts/registration/src/domain/mod.rs` (Modify)

*   **Type / Scope**: Rust module (Registration context)
*   **Proposed Changes**: Add `Assignment` with the fields listed under "Journal records" in Technical Plan §7.4 (`seq`, `account` (an `AccountId`, the OIDC subject), `survey`, `cohort`, `generation`, `by`, `roles`, `methods`, `at`) and `RosterIssue` (`seq`, `cohort`, `version`, `digest`, `by`, `roles`, `methods`, `at`). An assignment targets one account and applies to that account's active tenancies and to tenancies it registers later. `TenancyTerms.cohorts` (line 394) keeps its type, because eight constructors in tests and harnesses set it; the factory now sets it empty. Records are journaled as §7.4 (journal records) says.

#### 310. `crates/contexts/registration/src/ports.rs` (Modify)

*   **Type / Scope**: Rust module (Registration context)
*   **Proposed Changes**: `RegistryStore` gains `put_assignment(&Assignment) -> Result<(), RegistryStoreError>`, `assignments() -> Result<Vec<Assignment>, RegistryStoreError>`, `put_roster_issue(&RosterIssue) -> Result<(), RegistryStoreError>` and `roster_issues() -> Result<Vec<RosterIssue>, RegistryStoreError>`. The trait gets no default bodies: a silent default could drop assignments, so each of the four implementors writes its own (entries 314, 316, 570 and 571). Three new ports: `RosterIssuer::issue(&self, cohort: &CohortId, canonical_bytes: &[u8]) -> IssueOutcome` with `IssueOutcome` = `Issued { version, digest }`, `AlreadyIssued`, `VersionTaken`, `NotNewer` or `Invalid(reason)`; `SurveyDirectory::exists(&self, name: &str) -> bool`; and `CohortDirectory::exists(&self, cohort: &CohortId) -> bool`. They live in the Registration context because it may depend only on the Trust and Policy contexts (`architecture.toml`).

#### 311. `crates/contexts/registration/src/application.rs` (Modify)

*   **Type / Scope**: Rust module (Registration context)
*   **Proposed Changes**: Use cases `AssignCohort`, `ListAssignments` and `IssueRoster`. `AssignCohort` needs the operator role and a phishing-resistant method, refuses an unknown survey or cohort through `SurveyDirectory` and `CohortDirectory`, creates the target `Account` when it is missing (`id` is the subject, `collector` a random reference, no roles) with `put_account`, records generation 1 for each cohort on each tenancy reached, returns `unchanged` for an identical assignment, and has no remove (REG-045). `IssueRoster` has the same authentication, calls `RosterIssuer::issue`, maps `Invalid`, `VersionTaken`, `NotNewer` and `AlreadyIssued` to `roster-invalid`, `version-taken`, `not-newer` and `unchanged`, and journals the `RosterIssue` after the store write. If the issuer reports `AlreadyIssued` and no record exists for that cohort, version and digest, it writes the missing record, so a stop between the two writes heals on the next issue. When an assignment changes a tenancy's cohort set, and at registration into an account that has assignments, the use case fills `TenancyRecord.cohorts` from the account's assignments and issues a new certificate with `certificate_for` (`application.rs`, line 702) under a new serial; it stores the certificate in the tenancy record, so `GetCertificate` returns it. `register` appends the account's assignments to `TenancyTerms.cohorts` (line 565).

#### 312. `crates/contexts/registration/src/contract.rs` (Modify)

*   **Type / Scope**: Rust module (contract suite)
*   **Proposed Changes**: `registry_store_contract` gains cases: assignments and roster issues are returned oldest first; `put_assignment` and `put_roster_issue` assign `seq`; the records survive closing and opening the store again (file adapter); an assignment names its account and a second account's tenancies are not changed; an assignment for an account that does not exist creates it with no roles.

#### 314. `crates/adapters/memory/src/registration.rs` (Modify)

*   **Type / Scope**: Rust module (in-memory adapter)
*   **Proposed Changes**: `MemoryRegistryStore` implements `put_assignment`, `assignments`, `put_roster_issue` and `roster_issues`, each assigning `seq`.

#### 315. `crates/adapters/file/src/codec.rs` (Modify)

*   **Type / Scope**: Rust module (file adapter)
*   **Proposed Changes**: Two new journal record kinds, one for `Assignment` and one for `RosterIssue`; strict decode.

#### 316. `crates/adapters/file/src/store.rs` (Modify)

*   **Type / Scope**: Rust module (file adapter)
*   **Proposed Changes**: `FileRegistryStore` implements `put_assignment`, `assignments`, `put_roster_issue` and `roster_issues`; records are journaled as §7.4 (journal records) says.

#### 570. `crates/apps/cli/src/registration_cmd.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: `TokenFiles` (line 189) is a second `RegistryStore` implementation that wraps an inner store. It implements the four new methods by delegating to `inner`, as it does for the existing ones (the `delegate!` macro at lines 185 to 187 covers the plain ones). The trait has no default bodies, so this must be written.

#### 571. `crates/adapters/web-demo/src/support.rs` (Modify)

*   **Type / Scope**: Rust module (web demo adapter)
*   **Proposed Changes**: `TrackingStore` (line 67) is a third `RegistryStore` implementation. It delegates the four new methods to its inner store. The crate is deleted in Phase 16c; until then it must compile.

#### 572. `crates/adapters/file/src/roster_issuer.rs` (Create)

*   **Type / Scope**: Rust module (file adapter)
*   **Proposed Changes**: `FileRosterIssuer::new(store: RosterStore)` implements the Registration context's `RosterIssuer`. `issue(cohort, canonical_bytes)` decodes the bytes with the kernel's CBOR reader, refuses them unless re-encoding gives the same bytes, calls `check_issue_form` (entry 562) and returns `Invalid` with the findings if there are any, checks that the form's cohort equals `cohort`, then calls `RosterStore::issue`, which is idempotent by content digest, and maps its outcome (`Unchanged` to `AlreadyIssued`, `VersionTaken`, `NotNewer`). The roster store write comes first; the journal record is the caller's second write (§7.4). Development adapter.

#### 317. `crates/adapters/factory-http/src/lib.rs` (Modify)

*   **Type / Scope**: Rust module (factory HTTP adapter)
*   **Proposed Changes**: `BearerVerifier` trait (`verify(&str) -> Result<AuthenticatedPerson, BearerError>`) and `type ReconcileNotify = Arc<dyn Fn(TenancyId) + Send + Sync>`, which `FactoryHttp` takes and calls after each journaled change (a no-op until Phase 13 connects it to the reconciler); routes `POST /v1/assignments`, `GET /v1/assignments` and `POST /v1/rosters` with `Authorization: Bearer`; request bodies are canonical CBOR (REG-085, WIRE-196); for `POST /v1/rosters` the handler reads only the `cohort` text key from the body and passes the bytes unchanged to `IssueRoster`, whose issuer does the full check. Refusals: `401 bearer-required`, `401 token-invalid`, `403 not-authorised`, `403 authentication-too-weak`, `404 unknown-survey`, `404 unknown-cohort`, `409 version-taken`, `409 not-newer`, `422 roster-invalid`; `200 unchanged`. The roster body is never logged.

#### 318. `crates/adapters/factory-http/src/messages.rs` (Modify)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: Codes and texts for the refusals.

#### 319. `crates/adapters/factory-http/src/client.rs` (Modify)

*   **Type / Scope**: Rust module (client)
*   **Proposed Changes**: `assign(bearer, ...)`, `assignments(bearer)` and `issue_roster(bearer, ...)` (CLI-022).

#### 321. `crates/adapters/factory-http/tests/assignments.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: With a stub `BearerVerifier`: `reg_046_an_operator_can_assign_and_list`, `reg_046_a_collector_is_not_authorised`, `reg_046_a_weak_method_is_refused`, `reg_046_an_unknown_survey_or_cohort_is_refused`, `reg_046_an_assignment_records_generation_1_for_each_cohort_on_each_tenancy`, `reg_046_an_assignment_reaches_only_the_target_accounts_tenancies`, `reg_046_an_assignment_applies_to_tenancies_the_account_registers_later`, `reg_046_an_assignment_creates_the_account_when_it_does_not_exist`, `reg_046_the_assignment_names_the_account_by_subject`, `reg_046_an_identical_assignment_is_unchanged_and_writes_nothing`, `reg_046_each_assignment_is_journaled_with_account_roles_methods_and_time`, `reg_032_an_assignment_change_reissues_the_certificate_with_the_new_cohort_set`, `reg_032_a_tenancy_of_another_account_keeps_its_certificate`.

#### 542. `crates/adapters/factory-http/tests/rosters.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: With a stub `BearerVerifier` and a temporary roster store: `reg_047_an_operator_can_issue_a_roster_version`, `reg_047_a_collector_is_not_authorised`, `reg_047_a_weak_method_is_refused`, `reg_047_an_invalid_roster_is_422_and_stores_nothing`, `reg_047_a_lower_version_is_not_newer`, `reg_047_different_content_at_an_existing_version_is_version_taken`, `reg_047_identical_content_is_unchanged_and_writes_no_record`, `reg_047_each_issue_is_journaled_with_account_roles_methods_time_cohort_version_and_digest`, `reg_047_the_journal_and_events_hold_no_subject_data`, `reg_047_an_issue_notifies_the_reconciler`.

#### 322. `crates/apps/factory/src/main.rs` (Modify)

*   **Type / Scope**: Rust module (composition root)
*   **Proposed Changes**: Removes `FIELDSEAL_COHORTS` and wires the operator operations.
    *   **Environment**: Remove `FIELDSEAL_COHORTS`: the `cohorts` parse and its duplicate check (lines 227 to 243), the `cohorts` field (line 101), its place in the `Ok(Self { ... })` at line 254, its use in `TenancyTerms` at line 322 (an empty list from now on) and the table row in the module comment (line 22). Read the variables of the factory rows in the table of Technical Plan §7.6 (`FIELDSEAL_OIDC_API_AUDIENCE`, `FIELDSEAL_OIDC_CLI_CLIENT_ID`, `FIELDSEAL_OIDC_ACCEPT_TYP_JWT`, `FIELDSEAL_FACTORY_REGISTRY_DIR`, `FIELDSEAL_ROSTER_DIR`).
    *   **Behaviour**: Wire `BearerVerifier` to `OidcIdentityProvider::verify_access_token`. Build `FileRegistry` (read-only in this phase) and the roster store with `FileRosterSource` (read and write), and wrap the roster store in the `FileRosterIssuer` of entry 572; Phase 13 reuses both to build bundles. Inject `SurveyDirectory` (a survey exists when the artefact registry holds a published instrument of that name) and `CohortDirectory` (a cohort exists when the roster store holds a version) for `AssignCohort`. Pass a no-op `ReconcileNotify` to `FactoryHttp`.
    *   **Refusals and events**: Refuse both file adapters in `production` (exit 2). Write the `development-adapters` event with the function of entry 569, listing them. Events `assignment-made` (survey, cohort, generation) and `roster-issued` (cohort, version, digest); no roster value and no account subject (DEP-051).

#### 576. `crates/apps/factory/Cargo.toml` (Modify)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Add `fieldseal-publishing` (the `ArtefactRegistry` trait, read by `FileRegistry` and by the survey lookup). `fieldseal-adapters-file` and `fieldseal-adapters-memory` are already normal dependencies; Phase 13 adds the other contexts (entry 370).

#### 329. `crates/apps/security-tests/tests/operator_api.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Against `FactoryHttp` with a `BearerVerifier` test double that returns the outcomes the OIDC verifier returns (token-level refusals are tested in `crates/adapters/oidc/tests/access_token.rs`, because the development IdP crate is an app and cannot be a dependency of another app): `reg_070a_a_collector_role_account_is_refused_with_403`, `reg_070a_a_weak_sign_in_method_is_refused_with_403`, `reg_070a_a_verifier_refusal_is_401_token_invalid`, `reg_070a_no_authorization_header_is_401_bearer_required`, `reg_070a_the_same_refusals_apply_to_post_v1_rosters`, `reg_046_a_portal_session_cookie_is_never_accepted_on_the_assignment_routes`, `reg_046_a_bearer_token_is_never_accepted_on_the_portal_pages`.

#### 544. `crates/apps/security-tests/tests/keycloak_realm.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Reads `deploy/local/keycloak/fieldseal-realm.json`: `reg_070a_the_api_audience_mapper_adds_to_the_access_token_only`, `reg_070a_no_client_puts_the_api_audience_in_an_id_token`, `reg_070a_fieldseal_cli_is_a_public_client_with_pkce_s256`, `reg_070a_product_owner_has_a_fixed_id` (it expects the `id` `00000000-0000-4000-8000-000000000003`).

#### 331. `crates/apps/cli/src/oidc_login.rs` (Create)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: Loopback sign-in used only by `roster issue` and `roster assign`: starts a listener on `127.0.0.1` on an ephemeral port, builds the `OidcConfig` from `FIELDSEAL_OIDC_ISSUER` and `FIELDSEAL_OIDC_CLIENT_ID` (the flags `--issuer` and `--client-id` override them; neither set is exit 2), calls `start_sign_in("http://127.0.0.1:<port>/callback")`, opens the browser (`--browser <command>`, `$FIELDSEAL_BROWSER`, or `none` to print the URL), checks `state`, exchanges the code, verifies the ID token `nonce`, closes the listener, returns the access token held in memory only. With `--browser none --login <name>` it requests the authorisation URL with `login_hint` and follows the redirect itself; if the first response is not a redirect it fails with "this sign-in needs a person". No device command (`registration`, `bundle fetch`, `device ...`) calls this module (REG-001).

#### 332. `crates/apps/cli/src/roster_cmd.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: Add `roster issue <file>... --factory-url <url> [--instrument <survey dir>...] [--login <name>] [--browser <command>|none]` (`--instrument` takes a survey folder only, as `roster check` does; it runs `roster check` locally, then one sign-in and one `POST /v1/rosters` per file; prints the stored version and digest, or `unchanged`) and `roster assign --factory-url <url> --account <oidc-subject> (--assign <survey>=<cohort>)... [--login <name>] [--browser <command>|none]` (one sign-in for all `--assign` options) and `roster assign --list`. `roster assign` prints the account, the cohort and the survey, and names REG-045 for removal requests.

#### 333. `crates/apps/cli/src/clients.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: Factory client sends `Authorization: Bearer` on the assignment calls.

#### 334. `crates/apps/cli/src/main.rs` (Modify)

*   **Type / Scope**: Rust module (CLI entry)
*   **Proposed Changes**: `mod oidc_login;`.

#### 335. `crates/apps/cli/Cargo.toml` (Modify)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Add `fieldseal-adapters-oidc = { path = "../../adapters/oidc" }`. It is not a workspace dependency, so it is a path dependency, as `fieldseal-adapters-factory-http` already is for the CLI.

#### 336. `crates/apps/cli/src/args.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: Flags of `roster issue` and `roster assign` (including `--account`, `--issuer` and `--client-id`).

#### 337. `crates/apps/cli/src/messages.rs` (Modify)

*   **Type / Scope**: Rust module (CLI strings)
*   **Proposed Changes**: Messages and refusals of `roster assign`.

#### 338. `crates/apps/cli/tests/roster_assign.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: With `tiny_http` stand-ins for the IdP and the factory: `cli_055_assign_signs_in_through_a_loopback_redirect_and_sends_the_access_token`, `cli_055_one_sign_in_serves_several_assign_options`, `cli_055_no_token_is_written_to_disk` (scans the working and temp directories), `cli_055_login_with_browser_none_completes_without_a_person_when_the_idp_redirects`, `cli_055_a_login_page_makes_it_fail_with_needs_a_person`, `cli_055_a_removal_request_names_reg_045`, `cli_055_state_mismatch_is_refused`, `cli_055_the_output_shows_the_account_the_cohort_and_the_survey`, `cli_055_missing_issuer_and_client_id_exit_2`, `reg_001_device_commands_never_call_the_oidc_client_or_read_its_variables` (it sets `FIELDSEAL_OIDC_ISSUER`, `FIELDSEAL_OIDC_CLIENT_ID` and `FIELDSEAL_BROWSER` and asserts that no device command reads them).

#### 541. `crates/apps/cli/tests/roster_issue.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: With `tiny_http` stand-ins for the IdP and the factory: `cli_051_issue_runs_check_first_and_sends_nothing_when_it_fails`, `cli_051_issue_signs_in_once_for_several_files`, `cli_051_issue_refuses_a_version_not_higher_than_the_latest`, `cli_051_issue_accepts_identical_content_at_the_same_version`, `cli_051_issue_refuses_different_content_at_an_existing_version`, `cli_051_no_token_is_written_to_disk`.

#### 339. `docs/reference/spec/cli.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add the `roster issue` and `roster assign` rows to the `#### roster` table, and requirements CLI-051 (`roster issue` MUST run the check first, MUST refuse a version that is not higher than the store's latest for the cohort unless the content is identical, and MUST authenticate through the OIDC loopback flow and send the access token it obtains) and CLI-055 (`roster assign` MUST NOT remove a cohort, MUST authenticate through the OIDC loopback flow (RFC 8252) and send the access token it obtains, and MUST NOT store that token). Ids provisional.

#### 340. `docs/reference/spec/registration.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add REG-046: the factory MUST keep survey-to-cohort assignments in its tenancy registry and change them only through `AssignCohort`, which MUST require an `operator` account signed in by a phishing-resistant method, MUST name the account the assignment targets, MUST refuse an unknown survey or cohort, MUST record generation 1 for each cohort on each tenancy it reaches (DIS-014), and MUST NOT remove an assignment (the out-of-scope succession statement of REG-045 is the only basis for removal, and this design builds none). Add REG-047: the factory MUST accept a new roster version only through `IssueRoster`, with the same authentication, the DIS-063 check and the version rule of DIS-014, and MUST NOT remove a version. Each change of either kind MUST be journaled with the account, its roles and methods, the time and the change (for a roster, cohort, version and content digest, never subject data). An assignment MUST apply to the target account's tenancies, current and later. REG-032 gains a rule: when a tenancy's cohort set changes, the factory MUST reissue its certificate. REG-085 gains the rows `IssueRoster`, `AssignCohort` and `ListAssignments` (authentication: operator Bearer access token); the HTTP adapter's tests cover them (there is no gRPC adapter yet and REG-087 has no contract table, so this entry does not change REG-087). This changes the Registration context's `RegistryStore` port. Ids provisional.

#### 341. `docs/explanation/adr/0035-service-contracts-and-transports.md` (Modify)

*   **Type / Scope**: ADR note
*   **Proposed Changes**: `fieldseal.v1.Factory` gains `IssueRoster`, `AssignCohort` and `ListAssignments` (`GetBundle` is added in Phase 13, entry 384).

#### 573. `docs/reference/spec/wire-formats.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add WIRE-198 (provisional): the `IssueRoster` request body is the roster of WIRE-095 without `generation`, canonical CBOR (WIRE-196): `{cohort, version, subjects}`, with the subject fields of WIRE-095; a body that carries `generation` or an unknown key MUST be refused as `roster-invalid`. The generation is a property of a cohort on one tenancy (DIS-014), assigned when the cohort reaches a tenancy.

#### 342. `deploy/local/keycloak/fieldseal-realm.json` (Modify)

*   **Type / Scope**: Keycloak realm
*   **Proposed Changes**: Public client `fieldseal-cli`, with the audience, roles and `acr` mappers listed under "Keycloak in the stack" in Technical Plan §7.5 (no secret, standard flow only, PKCE `S256` required, redirect URI `http://127.0.0.1/*`; the audience `fieldseal-factory-api` is added to the access token and to no ID token), and the fixed `id` `00000000-0000-4000-8000-000000000003` for the user `product-owner` so that `tools/stack-run.sh assign` can name the account (§7.5). Keycloak imports the realm only into an empty volume, so this change needs `just purge` (entry 276 refuses to start without it). The items to confirm are in the Keycloak row of Risks & Mitigations.

#### 343. `crates/contexts/deployment/src/validate.rs` (Modify)

*   **Type / Scope**: Rust module (Deployment context)
*   **Proposed Changes**: Factory `IdentityProvider` config accepts `apiAudience`, `cliClientId`, `acceptTypJwt`. `ports(Factory)` gains the required ports `ArtefactRegistry` and `RosterSource` (`file-dev` each, with a `dir`), so every manifest that binds the factory must bind them (entry 575). Unknown adapter config keys are not refused (DEP-007 is open), so the `cohorts` key is not refused either; entry 344 stops reading it.

#### 344. `crates/contexts/deployment/src/render.rs` (Modify)

*   **Type / Scope**: Rust module (Deployment context)
*   **Proposed Changes**: Write `FIELDSEAL_OIDC_API_AUDIENCE`, `FIELDSEAL_OIDC_CLI_CLIENT_ID`, `FIELDSEAL_OIDC_ACCEPT_TYP_JWT`; `factory_aliases` (lines 197 to 200) stops reading the `TenancyRegistry` `cohorts` key and writing `FIELDSEAL_COHORTS`; write `FIELDSEAL_FACTORY_REGISTRY_DIR` and `FIELDSEAL_ROSTER_DIR`.

#### 577. `crates/contexts/deployment/tests/factory_component.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `dep_012_a_cohorts_key_in_the_tenancy_registry_config_is_no_longer_rendered`, `dep_012_the_factory_component_renders_the_new_variables`, `dep_002_a_manifest_without_the_new_factory_ports_is_refused`, `dep_002_the_example_manifests_bind_the_new_factory_ports`.

#### 345. `examples/deployments/local-stack.yaml` (Modify)

*   **Type / Scope**: Deployment manifest
*   **Proposed Changes**: Remove `cohorts: "cohort-a:1,village-a:1"`. (This removal waits for this phase because `roster assign` replaces the `cohorts` string.) add `apiAudience: fieldseal-factory-api`, `cliClientId: fieldseal-cli`, `acceptTypJwt: true` (Keycloak emits `typ: JWT`) to the factory's `IdentityProvider` config; add the factory's `ArtefactRegistry` and `RosterSource` as `file-dev` with the directories `/clistate/registry` and `/rosters` (the factory writes `/rosters`).

#### 575. `examples/deployments/sample.yaml` (Modify)

*   **Type / Scope**: Deployment manifest and examples
*   **Proposed Changes**: Also `docs/explanation/adr/0040-examples/fieldseal.deploy.yaml` and the example in `docs/reference/spec/deployment.md` (section 6, around line 154). The factory component binds the ports that entry 343 makes required, `ArtefactRegistry: { adapter: file-dev, config: { dir } }` and `RosterSource: { adapter: file-dev, config: { dir } }`, so both files and the spec example validate (DEP-002). As for entry 567, `file-dev` makes DEP-023 refuse them in `production`.

#### 346. `tools/stack-browser.sh` (Create)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: The opener the CLI runs in the demo container (`FIELDSEAL_BROWSER=/opt/fieldseal/tools/stack-browser.sh`): calls `local-stack-passkey.py --open <url>`, which registers a passkey on first use or signs in with it, and lets Keycloak redirect to the CLI's loopback listener (the listener and the browser share Keycloak's network namespace). `tools/dev-web.sh` does not use it: under the development IdP `--browser none` completes without a browser.

#### 347. `tools/local-stack-passkey.py` (Modify)

*   **Type / Scope**: Python script
*   **Proposed Changes**: Add `--open <url>`: register-or-sign-in as `product-owner` at an arbitrary authorisation URL and wait for the redirect to complete. The script resets the user's credentials on each run (`reset_user`, lines 57 to 79, called unless `--no-reset` is given), so every `--open` run removes the passkeys and registers one again. This stays, because the stack is development-only; `--no-reset` skips it. `just up`'s assign step runs before any manual sign-in, so the reset costs nothing there.

#### 348. `tools/stack-demo.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: `publish_all` publishes each survey's layouts after its instrument with the same `artefact provenance|sign|publish` verbs (kind Layout, bound to the fingerprint of the instrument just published; the CLI generates the salt), each under the name `<survey>-<window>` (`compact`, `medium` or `expanded`), which the reconciler looks up (§7.3). Add step `issue`: `fieldseal roster issue --factory-url $FACTORY --browser "$FIELDSEAL_BROWSER" examples/rosters/village-a.yaml examples/rosters/cohort-a.yaml` (one sign-in; the issuer and client id come from `FIELDSEAL_OIDC_ISSUER` and `FIELDSEAL_OIDC_CLIENT_ID` in the demo container). Add step `assign`: `fieldseal roster assign --factory-url $FACTORY --browser "$FIELDSEAL_BROWSER" --account 00000000-0000-4000-8000-000000000003 --assign household-water-access=village-a --assign school-meals-baseline=cohort-a` (one sign-in). `demo`, `enrol` and `resume` run `seed`, `issue` and `assign` first (order as §8; each step is idempotent). The inline stack policy sets `factory.cohorts.maxActiveTenanciesPerCohort: 1` explicitly.

#### 349. `tools/stack-run.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Document the `issue` and `assign` steps.

#### 350. `tools/stack-up.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: After the waits, run `tools/stack-run.sh seed`, `tools/stack-run.sh issue` and `tools/stack-run.sh assign`, in the order of §8.

#### 352. `deploy/local/compose.yaml` (Modify)

*   **Type / Scope**: Compose file
*   **Proposed Changes**: `demo` service: environment `FIELDSEAL_BROWSER`, `FIELDSEAL_OIDC_ISSUER: http://localhost:8180/realms/fieldseal` and `FIELDSEAL_OIDC_CLIENT_ID: fieldseal-cli`; it already shares Keycloak's network namespace. The factory mounts `clistate:/clistate:ro` (the artefact registry directory is `/clistate/registry`) and a new volume `rosters:/rosters` read-write (the factory writes the roster store); `demo` mounts `rosters:/rosters:ro`, for `roster diff` and `roster list`, and `web` mounts it read-only too with `FIELDSEAL_WEB_ROSTER_DIR: /rosters` (entry 574).

#### 353. `justfile` (Modify)

*   **Type / Scope**: Build configuration
*   **Proposed Changes**: Recipes `issue` (`tools/stack-run.sh issue`) and `assign` (`tools/stack-run.sh assign`), the walkthrough steps of `docs/tutorials/hands-on.md`, after `publish` and before `enrol`.

#### 354. `docs/tutorials/hands-on.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Add a `just issue # step` and a `just assign # step` after `just publish` and before registering a device, with an explanation of what is assigned and why.

#### 355. `docs/how-to/run-the-local-stack.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Add the issue and assignment steps and the operator sign-in.

#### 356. `docs/how-to/manage-rosters.md` (Modify)

*   **Type / Scope**: How-to
*   **Proposed Changes**: Add `roster issue`, `roster assign` and `--list`, and the account an assignment names.

#### 535. `flake.nix` (Modify)

*   **Type / Scope**: Nix flake
*   **Proposed Changes**: `factory-image` declares the volume `/rosters` (the roster store, written by the factory). `stackOpt` (line 279) copies `tools/stack-$f.sh` for `init demo enroll`; add `browser`, so that `tools/stack-browser.sh` is in the CLI and demo images at `/opt/fieldseal/tools/`.

#### 574. `crates/apps/web/src/catalogue.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: The roster page (`/instruments/{id}/roster`) reads the roster store once this phase lands. New variable `FIELDSEAL_WEB_ROSTER_DIR` (read in `main.rs`, documented in its module table): when it is set, the page takes the survey's cohort from `FIELDSEAL_WEB_SURVEY_COHORTS` and reads that cohort's latest stored version with `RosterStore::latest` from `fieldseal-adapters-file`, mounted read-only at `/rosters` in the stack (entry 352) and set to `deploy/local/.state/dev-web/rosters` by `tools/dev-web.sh` (entry 504); when it is unset, the page reads `examples/rosters/` as before. `crates/apps/web/Cargo.toml` gains `fieldseal-adapters-file` and `fieldseal-distribution`. The page still shows counts only, never `display`, `subject` or field values. Test in `crates/apps/web/tests/`: `web_110_the_roster_page_reads_the_mounted_roster_store_when_set_and_the_examples_otherwise`.

#### 504. `tools/dev-web.sh` and `examples/deployments/dev-web.yaml` (Modify)

*   **Type / Scope**: Shell script and deployment manifest
*   **Proposed Changes**: Follow the order of §8. The examples are already published (Phase 5b, `tools/dev-publish.sh --all`). Once the factory is up, run one `fieldseal roster issue --factory-url http://localhost:8080 --browser none --login presenter examples/rosters/village-a.yaml examples/rosters/cohort-a.yaml` and then one `fieldseal roster assign --factory-url http://localhost:8080 --browser none --login presenter --account 00000000-0000-4000-8000-000000000001 (the `presenter` subject, §7.5) --assign household-water-access=village-a --assign school-meals-baseline=cohort-a`; against the development IdP the loopback sign-in completes without a human (§7.5). The CLI commands run with `FIELDSEAL_OIDC_ISSUER=http://localhost:8180/realms/fieldseal` and `FIELDSEAL_OIDC_CLIENT_ID=fieldseal-cli`, and the collector stand-in gets `FIELDSEAL_WEB_ROSTER_DIR`. The manifest and the factory's rendered environment gain the artefact registry directory (`FIELDSEAL_FACTORY_REGISTRY_DIR`, `deploy/local/.state/dev-web/cli/registry`) and the roster directory (`FIELDSEAL_ROSTER_DIR`) under `deploy/local/.state/dev-web/`. Remove the `cohorts` string from the manifest.

**Housekeeping**: `crates/contexts/registration/README.md`: New port methods, use cases and invariants; `crates/adapters/factory-http/README.md`: New routes, `BearerVerifier`, refusals; `crates/apps/factory/README.md`: Variables, the removed `FIELDSEAL_COHORTS`, the new event and the new routes; `crates/apps/security-tests/README.md`: List `operator_api.rs`; `crates/apps/web/README.md`: Document `FIELDSEAL_WEB_ROSTER_DIR`; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 13: Factory builds and serves bundles (`GET /v1/bundle`) and portal download

*   **Goal**: The factory app, which already reads the artefact registry and the roster store (Phase 12), wires the runtime profiles and the bundle store and uses all four; a reconciler builds a registered tenancy's bundle on registration, when an input changes and when the anchor in the stored bundle is too old; `GET /v1/bundle` and the portal download serve the stored bundle; `fieldseal bundle fetch` is the CLI client; the policy control `factory.release.layouts` (first used by the reconciler) chooses which layouts a bundle carries. Technical Plan §7.3; Resolved Decisions 23 and 28.
*   **Depends on**: Phase 8 (file adapters), Phase 9 (roster store), Phase 12 (assignments are build inputs, and the factory already reads the artefact registry directory and the roster store).
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `cargo test -p fieldseal-policy --test release_layouts`; `cargo test -p fieldseal-adapters-memory --test fetch_response`; `cargo test -p fieldseal-deployment`; `cargo test -p fieldseal-adapters-factory-http --test bundle_routes`; `cargo test -p fieldseal-factory --test reconciler`; `cargo test -p fieldseal-security-tests --test bundle_delivery`; `cargo test -p fieldseal-cli --test bundle_fetch`.
    *   In the stack: register a device, `fieldseal bundle fetch` returns sequence 1; `roster issue` of `examples/rosters/next/village-a.yaml` (version 4, one above the stored version 3) triggers a rebuild at once, so the next fetch returns sequence 2, and `roster assign` also triggers a rebuild at once; a restart builds nothing new; a publication written by the CLI is seen within `FIELDSEAL_FACTORY_BUILD_INTERVAL_S`. The anchor-age rule is checked by the `reconciler.rs` test `dis_010_a_bundle_whose_anchor_is_older_than_the_maximum_age_is_rebuilt_with_the_next_sequence`, not in the stack.
    *   `cargo test -p fieldseal-factory --test crash_order` (entry 539) passes: the factory stopped after each write step leaves the previous bundle and a digest that never names inputs without a stored bundle.
    *   `just acceptance` passes with a tutorial that does not use `bundle build --stack` (the removal itself is Phase 14).
    *   `just test`.
*   **Security review**: SR-2 (fetch and download routes; SR-1, the registration request change, signed off with Phase 8) and SR-3 (factory as builder, including the layout and profile selection) must both sign off before merge; SR-4 from Phase 12 is already signed off.
*   **SR-3 follow-ups (from the Phase 8 review of SR-1, Minors 1 and 2)**: wire `FileRuntimeProfiles` into the bundle builder, and add the build-level `dis_012_...` test.

#### 324. `crates/contexts/policy/src/domain/schema.rs` (Modify)

*   **Type / Scope**: Rust module (Policy context)
*   **Proposed Changes**: Add the control `factory.release.layouts` (the key DIS-016 expects, named like `factory.release.requireRegisteredTenancy`): `Kind::Choice(LayoutAssignment::NAMES)` with names `["bound", "none"]`, default `choice("bound")`, merge `TIGHTER_HIGH` (`none` is tighter than `bound`). `LayoutAssignment` is an enum beside `PostureFailure` in `choice.rs` (entry 601), and `sections.rs` reads it (entry 602). It is not an invariant floor and loosens nothing: it only chooses which already-published, already-verified layouts accompany an instrument.

#### 601. `crates/contexts/policy/src/domain/choice.rs` (Modify)

*   **Type / Scope**: Rust module (Policy context)
*   **Proposed Changes**: Add `LayoutAssignment` with the `choice!` macro beside `PostureFailure` (line 94): `Bound = "bound"` and `None = "none"`, so `LayoutAssignment::NAMES` and `LayoutAssignment::parse` exist for `schema.rs` and `sections.rs`.

#### 602. `crates/contexts/policy/src/domain/sections.rs` (Modify)

*   **Type / Scope**: Rust module (Policy context)
*   **Proposed Changes**: The typed `factory` section gains `release_layouts: LayoutAssignment`, read as `self.choice(&p("release.layouts"), LayoutAssignment::parse)` beside `require_registered_tenancy` (`self.bool_(&p("release.requireRegisteredTenancy"))`, line 450), so the reconciler reads the control without string keys.

#### 325. `docs/reference/spec/policy.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add the row `release.layouts` to the §6.1 control table (`bound` / `none`, default `bound`, tighten) and POL-068 (provisional): `release.layouts` = `bound` means a bundle carries, for each instrument, every published layout bound to that instrument's fingerprint, newest version per window class; `none` means no layout; an unknown value is refused. DIS-016 is not reworded: the factory policy it names is this control.

#### 326. `examples/deployments/policy/deployment-default.yaml` (Modify)

*   **Type / Scope**: Example policy
*   **Proposed Changes**: Add `factory.release.layouts: bound` under `factory:` so the generated policy table shows the control set by a layer. The change alters the file's digest, so recompute it and update the pinned `sha256:` values in `examples/deployments/local-stack.yaml` (line 33) and `examples/deployments/sample.yaml` (line 22).

#### 327. `crates/contexts/policy/tests/release_layouts.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `pol_068_the_default_is_bound`, `pol_068_none_is_accepted`, `pol_068_an_unknown_value_is_refused`, `pol_068_a_tighter_layer_can_set_none_but_a_looser_layer_cannot_restore_bound`, `pol_068_the_typed_section_exposes_the_layout_choice`, `pol_068_the_other_control_defaults_are_unchanged` (the defaults snapshot of the NFR section, extended by this one row).

#### 358. `crates/adapters/factory-http/src/lib.rs` (Modify)

*   **Type / Scope**: Rust module (factory HTTP adapter)
*   **Proposed Changes**: `FactoryHttp` takes an optional `BundleRoutes { fetch: &dyn FetchBundle, download: &dyn DownloadBundle }`, which the factory builds from Distribution's existing `BundleDelivery` (it implements both traits, so the new type has another name). `GET /v1/bundle?held=<n>`: `Fieldseal-PoP` header (WIRE-170) checked by `Factory::authenticate_api` with method `GET` and the factory's public URL plus path (the query is not signed; see WIRE-171 in entry 540); `200` with the stored `FSB1` bytes, `Fieldseal-Bundle-Sequence`, `Content-Disposition: attachment; filename="fieldseal-bundle-<date>-<n>.fsb"`, `Cache-Control: no-store`; `304` when `held` is the latest; `401 pop-required|proof-invalid|replay`; `403 not-registered|revoked`; `403 withheld` with `reasons`; `404 no-bundle`; `503 unavailable`. The route never builds. It maps the three outcomes of `BundleFetchResponse` (entry 578) to `404 no-bundle`, `304` and `200`. Portal: `GET /devices/{device}/bundle.fsb` for a signed-in collector, own device only (REG-043), same stored file and name, no CSRF (changes nothing); `download` reports `Withheld(["no-bundle-built"])` when nothing is stored, and the portal turns exactly that reason into `404 no-bundle`. The answer limit for this call is the bundle limit (proposed 8 MiB), not the 1 MiB `MAX_ANSWER`.

#### 578. `crates/contexts/distribution/src/application/fetch.rs` (Modify)

*   **Type / Scope**: Rust module (Distribution context)
*   **Proposed Changes**: `FetchBundle::fetch` returns `Result<BundleFetchResponse, DistributionError>` in place of `Result<Option<SealedBundle>, DistributionError>`, which could not tell "nothing stored" from "the held bundle is current" (lines 19 and 62). `BundleFetchResponse` is `NoBundle`, `Current` or `Bundle(SealedBundle)`. `BundleDelivery::fetch` checks eligibility, reads `BundleStore::latest` first, and then decides: nothing stored is `NoBundle`, a stored bundle whose sequence is not above `held` is `Current`, anything newer is `Bundle`. `DownloadBundle::download` is unchanged. The type is not called `BundleDelivery`, which is already the struct that implements both traits. Re-export `BundleFetchResponse` from `application/mod.rs`. No other code calls `fetch`: `crates/apps/cli/src/conformance_cmd/dis_release.rs` only imports the trait.

#### 579. `crates/adapters/memory/tests/fetch_response.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Runs the Distribution use case over the in-memory tenancy registry and bundle store (a context's own tests cannot use an adapter, `architecture.toml`): `dis_040_fetch_reports_no_bundle_when_nothing_is_stored`, `dis_040_fetch_reports_current_when_held_is_the_latest`, `dis_040_fetch_returns_the_bundle_when_held_is_older`, `dis_040_fetch_refuses_an_ineligible_tenancy_before_it_reads_the_store`, `dis_041_download_reports_withheld_no_bundle_built_when_nothing_is_stored`.

#### 600. `crates/adapters/memory/src/distribution.rs` (Modify)

*   **Type / Scope**: Rust module (in-memory adapter)
*   **Proposed Changes**: Add `ClockAnchorSource::new(clock: &dyn AuthorityClock, custody: &dyn KeyCustody, signer: KeyId)`, which implements `AnchorSource`: `time_token()` reads `clock.now()` and returns `sign_time_token(custody, &signer, now)`, the function in this file (line 87) that `MemoryAnchorSource` also uses. `MemoryAnchorSource`, a counter that advances one second per token, stays for tests. The file is in `fieldseal-adapters-memory`, already a normal dependency of the factory. Test in the module: `dis_010_the_clock_anchor_source_signs_the_current_time_of_its_clock`.

#### 359. `crates/adapters/factory-http/src/client.rs` (Modify)

*   **Type / Scope**: Rust module (client)
*   **Proposed Changes**: `FactoryHttpClient::bundle(pop_header, held) -> BundleAnswer::{Bundle{bytes, sequence}, Current, Refused{code, reasons}, Unavailable}` (CLI-022).

#### 360. `crates/adapters/factory-http/src/html.rs` (Modify)

*   **Type / Scope**: Rust module (portal pages)
*   **Proposed Changes**: Device list page links to the bundle download beside the certificate link.

#### 361. `crates/adapters/factory-http/src/messages.rs` (Modify)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: Texts for the new codes and the download link.

#### 362. `crates/adapters/factory-http/Cargo.toml` (Modify)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Add `fieldseal-distribution`.

#### 364. `crates/adapters/factory-http/tests/bundle_routes.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `dis_040_a_registered_device_with_a_valid_token_gets_the_stored_bundle`, `dis_040_held_equal_to_latest_gives_304`, `dis_040_the_query_is_outside_the_pop_binding`, `dis_040_a_rewritten_held_gives_a_full_bundle_or_304_and_never_a_forged_one`, `dis_040_no_token_gives_pop_required`, `dis_040_a_replayed_token_is_refused`, `dis_040_an_unknown_tenancy_is_not_registered`, `dis_040_a_lost_closing_closed_or_retired_tenancy_is_revoked`, `dis_003_a_withheld_tenancy_gets_403_with_reasons_and_can_still_upload`, `dis_040_an_eligible_tenancy_with_no_bundle_yet_gets_no_bundle`, `dis_040_a_current_held_bundle_gives_304_and_nothing_stored_gives_404_no_bundle`, `dis_084_the_route_never_builds`, `dis_022_the_answer_reveals_nothing_outside_the_seal`, `dis_040_responses_carry_cache_control_no_store`, `dis_041_the_portal_download_needs_a_session`, `reg_043_the_portal_download_serves_only_the_collectors_own_device`.

#### 365. `crates/apps/factory/src/lib.rs` (Create)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: Exposes `config`, `inputs`, `reconciler` so integration tests start them in process.

#### 366. `crates/apps/factory/src/config.rs` (Create)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: Moves `Config` and its parsing out of `main.rs`, with the two variables that Phase 12 added (`FIELDSEAL_FACTORY_REGISTRY_DIR`, `FIELDSEAL_ROSTER_DIR`); adds `FIELDSEAL_BUNDLE_DIR`, `FIELDSEAL_ISSUED_ROSTERS_DIR`, `FIELDSEAL_FACTORY_BUILD_INTERVAL_S` and `FIELDSEAL_FACTORY_MAX_ANCHOR_AGE_S`, with the defaults and ranges of the table in Technical Plan §7.6 (an out-of-range value exits 2). The runtime profile needs no variable: `FileRuntimeProfiles` reads the tenancy registry journal in `FIELDSEAL_STATE_DIR`. All are non-production (file adapters).

#### 367. `crates/apps/factory/src/inputs.rs` (Create)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: `BuildInputs::collect(tenancy, ports) -> BuildInputs`, `digest() -> [u8;32]` and `request_for(inputs) -> BuildRequest`.
    *   **Environment**: Reads only through ports. The inputs are: the published artefacts and withdrawals the tenancy's assignments select, the current roster version of each assigned cohort, the assignments of the tenancy's account, the serial of the tenancy's certificate, the tenancy's reported profile, the effective policy values `factory.release.layouts` and the release policy, and the agreement key. The digest covers exactly these. It is stored beside the bundle (`<bundle dir>/<tenancy>/inputs.sha256`), not in the signed manifest, so no bundle format changes.
    *   **Behaviour**: `request_for`: for each assigned survey the instrument is the highest semver among its non-withdrawn published versions that satisfy DIS-012 for the tenancy's reported schema. Layouts follow `factory.release.layouts`: `bound` (default) asks `ArtefactRegistry::list(Layout, "<survey>-<window>")` for `compact`, `medium` and `expanded`, keeps the layouts bound to that instrument's fingerprint (INS-200) and takes the newest version of each (INS-207); `none` = no layouts. The bundle carries the tenancy's current certificate (`BundleContents.certificate`).
    *   **Refusals and events**: if no version satisfies DIS-012, the survey is left out and a `bundle-withheld(instrument-incompatible)` event names it, with no subject data.

#### 368. `crates/apps/factory/src/reconciler.rs` (Create)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: `Reconciler::run_once()` and `spawn(interval)`. For each registered, eligible tenancy: compare the digest with the stored one, and compare the age of the stored bundle's anchor with `FIELDSEAL_FACTORY_MAX_ANCHOR_AGE_S`; if the digest differs or the anchor is too old, build in this order: (1) record the issued rosters for intake (`record_issued`, restricted to the fields the instrument reads) into `FIELDSEAL_ISSUED_ROSTERS_DIR` and flush them to disk; (2) `BundleBuilder::build` and `BundleStore::put` (written through the atomic-write helper, entry 546); (3) write the digest through the same helper. After each step it calls the public `BuildWriteHook` trait, whose default does nothing (entry 539 installs a hook that fails). Triggers: the `ReconcileNotify` callback of entry 317, which `main.rs` connects to the reconciler in this phase, on registration, on assignment and on roster issue (rebuild at once), and the poll for publications written by the CLI (`artefact publish`). Not eligible (DIS-001, DIS-003, REG-081): record `bundle-withheld(reason)`. No `deployment-policy` artefact published: build nothing and record `bundle-withheld(no-policy)`; the next poll after the policy is published builds. Build failure: keep the previous bundle, record `bundle-failed(reason)`. Events carry no subject data (DEP-051).

#### 369. `crates/apps/factory/src/main.rs` (Modify)

*   **Type / Scope**: Rust module (composition root)
*   **Proposed Changes**: Build `BundleBuilder` and the reconciler from `FileRegistry` (read-only) and `FileRosterSource` (read and write), both wired in Phase 12, `FileRuntimeProfiles` (over the tenancy registry journal), a `ClockAnchorSource` (entry 600) over the factory's `AuthorityClock` and the `receipt` key in custody, and `FileBundleStore`; pass `BundleRoutes` over a `BundleDelivery` to `FactoryHttp` and connect its `ReconcileNotify` to the reconciler; read the effective release policy from the published `deployment-policy` artefact in the artefact registry, and with none published build nothing (`bundle-withheld(no-policy)`); start the reconciler thread; refuse each new file adapter in `production` (exit 2) and list them in the `development-adapters` event.

#### 370. `crates/apps/factory/Cargo.toml` (Modify)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: `[lib]` plus `[[bin]]`; add `fieldseal-distribution`, `fieldseal-instrument` and `fieldseal-intake` (for `IssuedRoster`). `fieldseal-publishing` (Phase 12, entry 576) and `fieldseal-adapters-memory` (a normal dependency already, now also for `ClockAnchorSource`) are present.

#### 371. `crates/apps/factory/tests/reconciler.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: In process with memory-dev custody: `dis_082_registration_builds_sequence_one`, `dis_082_a_new_publication_builds_the_next_sequence`, `dis_082_a_new_roster_version_builds_the_next_sequence`, `dis_082_an_assignment_rebuilds_without_a_restart`, `dis_083_an_unchanged_input_digest_builds_nothing`, `dis_083_a_restart_builds_nothing_new`, `dis_010_a_bundle_whose_anchor_is_older_than_the_maximum_age_is_rebuilt_with_the_next_sequence`, `dis_010_a_fresh_anchor_with_an_unchanged_digest_builds_nothing`, `dis_082_a_roster_issue_rebuilds_without_a_restart`, `dis_082_an_assignment_that_changes_the_cohort_set_brings_the_reissued_certificate_in_the_next_bundle`, `dis_013_two_accounts_get_only_their_own_cohorts`, `reg_041_a_retired_tenancy_frees_the_cohort_slot_for_the_accounts_new_device`, `reg_041_a_second_active_tenancy_of_one_cohort_is_held_by_the_cohort_limit`, `dis_083_a_failed_build_keeps_the_previous_bundle`, `dis_003_a_lost_retired_or_flagged_tenancy_gets_no_new_bundle`, `dis_075_a_build_with_an_unpublished_artefact_releases_nothing`, `dis_002_with_no_published_policy_nothing_is_built_and_no_policy_is_recorded`, `dis_012_the_highest_non_withdrawn_version_the_runtime_can_run_is_bundled`, `dis_012_a_withdrawn_version_is_never_bundled`, `dis_012_a_tenancy_whose_runtime_reported_an_older_schema_gets_no_instrument_it_cannot_run`, `dis_077_the_profile_used_is_the_one_recorded_at_registration`, `dis_016_the_default_bundles_every_bound_layout_newest_per_window_class`, `dis_016_an_explicit_none_bundles_no_layout`, `dis_016_a_layout_bound_to_another_fingerprint_is_never_included`, `dis_016_layouts_are_found_by_the_name_survey_dot_window`, `ins_207_at_most_one_layout_per_window_class`, `dis_002_the_bundle_release_decision_gates_roster_release`, `dep_051_build_events_carry_no_subject_data`, `int_040_issued_rosters_are_recorded_for_intake_with_restricted_fields`.

#### 539. `crates/apps/factory/tests/crash_order.rs` (Create)

*   **Type / Scope**: Integration test (crash injection)
*   **Proposed Changes**: The test installs a failing `BuildWriteHook` (entry 368) that stops the reconciler's build after each of its three write steps (issued rosters flushed, bundle renamed, digest renamed) and restarts it on the same directories: `dis_083_a_crash_after_record_issued_leaves_the_previous_bundle_and_the_next_pass_rebuilds`, `dis_083_a_crash_after_the_bundle_rename_leaves_a_digest_that_does_not_claim_the_new_inputs`, `dis_083_a_crash_after_the_digest_rename_leaves_a_consistent_store`, `dis_083_no_crash_point_leaves_a_partial_bundle_file_in_the_store`.

#### 373. `crates/apps/security-tests/tests/bundle_delivery.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `dis_021_a_stolen_token_yields_bytes_only_the_device_can_open`, `dis_040_a_token_for_another_url_is_refused`, `reg_082_a_withheld_tenancy_can_still_upload`, `dis_020_neither_bundle_bytes_nor_decrypted_contents_contain_the_record_key_secret_or_the_export_pseudonymisation_key` (control 5 of §7.2), `dis_040_the_replay_ledger_is_shared_with_the_other_pop_routes`, `dis_013_neither_account_receives_the_others_cohort_roster`.

#### 375. `crates/apps/cli/src/bundle_cmd.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: Add `bundle fetch --device-dir <dir> [--factory-url <url>] [--trust-bundle <file>] [--held <seq>] --out <file>`: makes the PoP token with the device's signing key (as `registration wait --device-dir` does), stores the bundle under its DIS-023 name; exits 0 (stored or already current), 1 (refused), 3 (unreachable).

#### 376. `crates/apps/cli/src/clients.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: Bundle call on the factory client.

#### 377. `crates/apps/cli/src/args.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: Flags of `bundle fetch`.

#### 378. `crates/apps/cli/src/messages.rs` (Modify)

*   **Type / Scope**: Rust module (CLI strings)
*   **Proposed Changes**: Messages of `bundle fetch`.

#### 379. `crates/apps/cli/tests/bundle_fetch.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Against a `tiny_http` factory stand-in: `cli_049_fetch_stores_the_bundle_under_its_dated_name`, `cli_049_fetch_with_held_current_exits_0_and_writes_nothing`, `cli_049_a_refusal_exits_1`, `cli_049_an_unreachable_factory_exits_3`, `cli_049_the_token_is_bound_to_the_factory_url`.

#### 380. `docs/reference/spec/registration.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: REG-085 gains the row `GetBundle` (`GET /v1/bundle`, PoP); the HTTP adapter's tests cover it (there is no gRPC adapter yet and REG-087 has no contract table, so this entry does not change REG-087); REG-054 names `GET /devices/{device}/bundle.fsb`.

#### 381. `docs/reference/spec/distribution.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: DIS-040: the HTTP mapping and error table; new DIS-082 (the factory builds a tenancy's next bundle when registered state, selected artefacts, an assigned cohort's roster version, assignments or the agreement key change; an assignment change triggers a rebuild without a restart), DIS-083 (a build is idempotent on its inputs and a failed build leaves the previous bundle), DIS-084 (the factory serves the latest stored bundle over `FetchBundle` and `DownloadBundle` and does not build in the request).

#### 540. `docs/reference/spec/wire-formats.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: WIRE-171 gains: the `url` of the token is the request URL without its query string, so a server MUST NOT require the query to be signed and a client MUST NOT sign it. A query only narrows the answer (for example `held` on `GET /v1/bundle`); a proxy that rewrites it has the same effect as a dropped response, because every answer is verified by the device before use.

#### 382. `docs/reference/spec/cli.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add `bundle fetch` to the `bundle` table and CLI-049. (`bundle build --stack` is removed in Phase 14.)

#### 383. `docs/reference/spec/deployment.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: DEP-057 for the factory: the new rendered variables. The adapters these variables configure are development adapters. The example in section 6 gains the factory ports of entry 385 (entry 580).

#### 384. `docs/explanation/adr/0035-service-contracts-and-transports.md` (Modify)

*   **Type / Scope**: ADR note
*   **Proposed Changes**: `fieldseal.v1.Factory` gains `GetBundle`.

#### 385. `crates/contexts/deployment/src/validate.rs` (Modify)

*   **Type / Scope**: Rust module (Deployment context)
*   **Proposed Changes**: `ports(Factory)` gains the required ports `BundleStore` and `RuntimeProfiles` (`file-dev` each; `ArtefactRegistry` and `RosterSource` were added in Phase 12), so every manifest that binds the factory must bind them (entry 580).

#### 386. `crates/contexts/deployment/src/render.rs` (Modify)

*   **Type / Scope**: Rust module (Deployment context)
*   **Proposed Changes**: Write the new factory variables (`FIELDSEAL_BUNDLE_DIR`, `FIELDSEAL_ISSUED_ROSTERS_DIR`, `FIELDSEAL_FACTORY_BUILD_INTERVAL_S`, `FIELDSEAL_FACTORY_MAX_ANCHOR_AGE_S`).

#### 387. `examples/deployments/local-stack.yaml` (Modify)

*   **Type / Scope**: Deployment manifest
*   **Proposed Changes**: Factory: `BundleStore` and `RuntimeProfiles` as `file-dev` (the factory state directory, `/state/factory`) with the other directories `/bundles` and `/issued`; intake `RosterHistory` directory moves from `/published/rosters` to `/issued` (read-only), because from this phase the factory records the issued rosters there (`FIELDSEAL_ISSUED_ROSTERS_DIR`) and nothing writes `/published/rosters`. (`/clistate/registry` and `/rosters` were declared in Phase 12.)

#### 580. `examples/deployments/sample.yaml` (Modify)

*   **Type / Scope**: Deployment manifest and examples
*   **Proposed Changes**: Also `docs/explanation/adr/0040-examples/fieldseal.deploy.yaml` and the example in `docs/reference/spec/deployment.md` (section 6, around line 154). The factory component binds the ports that entry 385 makes required, `BundleStore: { adapter: file-dev, config: { dir } }` and `RuntimeProfiles: { adapter: file-dev, config: { dir } }`, so both files and the spec example validate (DEP-002). As for entry 567, `file-dev` makes DEP-023 refuse them in `production`.

#### 388. `deploy/local/compose.yaml` (Modify)

*   **Type / Scope**: Compose file
*   **Proposed Changes**: New volumes `bundles` and `issued` (read-write for the factory; `issued` read-only for intake). (The `clistate` and `rosters` mounts were added in Phase 12.)

#### 389. `flake.nix` (Modify)

*   **Type / Scope**: Nix flake
*   **Proposed Changes**: `factory-image` mounts: `/bundles`, `/issued`; `intake-image` mount `/issued`. (`/rosters` was added in Phase 12.)

#### 390. `tools/stack-demo.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Registration, `registration wait`, then `bundle fetch` replace the bundle step. (Layout publishing and the `roster issue` step were added in Phase 12; `bundle build --stack` is still present until Phase 14.)

#### 391. `docs/how-to/run-the-local-stack.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: How a device gets its bundle; the new volumes.

#### 505. `tools/dev-web.sh` and `examples/deployments/dev-web.yaml` (Modify)

*   **Type / Scope**: Shell script and deployment manifest
*   **Proposed Changes**: Add bundle building and fetch: the manifest and the factory's rendered environment gain the bundle and issued-roster directories under `deploy/local/.state/dev-web/` (the artefact registry and roster directories exist since Phase 12); `--check` registers a device with the CLI and confirms that `fieldseal bundle fetch` returns sequence 1.

**Housekeeping**: `crates/contexts/policy/README.md`: Document `factory.release.layouts`; `crates/adapters/factory-http/README.md`: `BundleDelivery`, the route table and the invariants (serves only what is stored; eligibility checked at fetch); `crates/apps/factory/README.md`: New variables, events (`bundle-built`, `bundle-withheld`, `bundle-failed`), reconciler behaviour and the polling note (the poll is only for file changes; a production adapter would trigger by event); `crates/apps/security-tests/README.md`: List `bundle_delivery.rs`; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 14: Devices fetch their bundle from the factory; the spawn path is removed

*   **Goal**: The WebAssembly device and the collector stand-in use `GET /v1/bundle`; delete `GET /device/bundle`, `stack::bundle` and `bundle build --stack`. The transparency log gains `GET /entries/{from}/{to}`, which the collector stand-in uses to list the published surveys. Technical Plan §7.3 (changes by component).
*   **Depends on**: Phase 13.
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `cargo test -p fieldseal-adapters-translog --test entries`; `cargo test -p fieldseal-adapters-web --test fetch_bundle`; `cargo test -p fieldseal-web --test stack_mode`; `cargo build --target wasm32-unknown-unknown -p fieldseal-wasm` (inside the dev shell) and `nix build path:.#fieldseal-wasm`.
    *   `just acceptance` and `tools/stack-smoke.sh --browser`: the WebAssembly device registers, gets its bundle from the factory, captures, uploads and verifies receipts.
    *   `grep -rn 'bundle build --stack\|FIELDSEAL_WEB_CLI' crates tools deploy flake.nix docs/reference` finds nothing, and `grep -rn '"/device/bundle"' crates/apps/web/src` finds nothing. The gate does not search for the bare string `device/bundle`, which names a directory in `tools/stack-demo.sh`; this phase renames that directory to `/device/fetched` (entry 411).
    *   `just test` passes with `crates/apps/web/tests/e2e_web.rs` deleted (entry 447). Between this phase and Phase 16a no test covers WEB-156 and WEB-170, which that file carried; the WEB coverage floor of 100 is checked in Phase 18.
*   **Security review**: None.

#### 581. `crates/adapters/translog/src/store.rs` (Modify)

*   **Type / Scope**: Rust module (log adapter)
*   **Proposed Changes**: Add `FileLogStore::entries(from: u64, to: u64) -> Result<Vec<Vec<u8>>, LogError>`: the canonical `LogEntry` bytes at indices `from` (inclusive) to `to` (exclusive), clipped to the size of the signed head and to 256 entries, read from `log.dat` (records are `[length][entry][chain hash]`, which `replay` already walks). A `from` at or beyond the size, or a `to` below `from`, is `LogError::OutOfRange`. The log has no way to list its entries today, and Phases 14, 16b and 17 read them.

#### 582. `crates/adapters/translog/src/wire.rs` (Modify)

*   **Type / Scope**: Rust module (log adapter)
*   **Proposed Changes**: `handle()` (lines 137 to 175) serves `/append`, `/checkpoint`, `/inclusion` and `/consistency` only. Add `GET /entries/{from}/{to}`, in the style of RFC 9162 get-entries: `200` with, for each entry in order, a 4-byte big-endian length and the canonical `LogEntry` bytes, at most 256 entries per answer (a reader asks again from the next index); `400` for indices that are not decimal numbers or a `to` below `from`; `404` for a `from` past the end of the log; `405` for another method; a lookup carries no body. A `decode_entries(bytes) -> Result<Vec<LogEntry>, LogError>` reads the answer back, and `render` gains the matching request. This is a production log feature, not a demo shortcut (§10.1).

#### 583. `crates/adapters/translog/src/client.rs` (Modify)

*   **Type / Scope**: Rust module (log adapter)
*   **Proposed Changes**: `HttpTranslog::entries(from, to) -> Result<Vec<LogEntry>, LogError>`, sent through `HttpLogTransport` or the in-process `HandlerTransport` (`src/http.rs`), so the collector stand-in and the tests read entries with the same client. It is an inherent method of the HTTP client, not part of the `TransparencyLog` port: public logs such as Rekor keep their own API behind their own adapter (PUB-110).

#### 584. `crates/adapters/translog/tests/entries.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: The crate has no `tests` directory today. Cases: `pub_110_get_entries_returns_the_canonical_entries_in_order`, `pub_110_get_entries_stops_at_256_entries`, `pub_110_get_entries_past_the_end_is_404`, `pub_110_get_entries_with_a_bad_range_is_400`, `pub_110_get_entries_with_a_body_or_another_method_is_refused`, `pub_110_the_client_reads_back_what_the_server_stores`.

#### 585. `docs/reference/spec/publishing.md` (Modify)

*   **Type / Scope**: Specification and ADR note
*   **Proposed Changes**: PUB-110 gains the `GetEntries` operation of `fieldseal.v1.TransLog` and says its HTTP mapping is `GET /entries/{from}/{to}`, answering canonical `LogEntry` bytes without re-encoding (WIRE-196). `docs/reference/spec/wire-formats.md` gains WIRE-199 (provisional): the answer is, per entry, a 4-byte big-endian length and the entry, at most 256 entries. `docs/explanation/adr/0035-service-contracts-and-transports.md` lists the operation. Public logs keep their own API.

#### 393. `crates/adapters/web/src/device.rs` (Modify)

*   **Type / Scope**: Rust module (WebAssembly device adapter)
*   **Proposed Changes**: Add `fetch_bundle(factory_url, held) -> BundleFetch` using the core's `PopToken` (as uploads do) and `Host.get` beside `Host.post` (entry 394); the result is passed to `import_bundle`, which verifies in DIS-030 order.

#### 394. `crates/adapters/web/src/device.rs` (Modify)

*   **Type / Scope**: Rust module (WebAssembly device adapter)
*   **Proposed Changes**: The second change to this file. `Host` (lines 44 to 56) gains `get: GetFn`, with `type GetFn = Rc<dyn Fn(&str, Option<&str>) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String>>`: one blocking GET, `(url, proof-of-possession header)` to `(status, headers, body)`, beside `post: PostFn`. `platform.rs` has no transport trait and does not change.

#### 395. `crates/adapters/web/tests/fetch_bundle.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: With a stub `Host.get`: `dis_040_the_device_fetches_and_imports_a_bundle`, `dis_040_a_304_keeps_the_held_bundle`, `dis_040_a_404_no_bundle_is_reported_as_still_preparing`, `dis_030_a_bundle_that_fails_verification_is_not_imported`, `dis_040_the_pop_token_is_bound_to_the_factory_url_not_the_proxy_url`, `dis_030_the_device_accepts_a_bundle_that_carries_a_reissued_certificate_with_a_new_cohort_set`.

#### 396. `crates/bindings/wasm/src/device.rs` (Modify)

*   **Type / Scope**: Rust module (WebAssembly binding)
*   **Proposed Changes**: New host import `fieldsealGet(url, pop)` beside `fieldsealPost`; new exported function `fetchBundle(factoryUrl, held)`. `importBundle` stays as the file route.

#### 398. `crates/apps/web/assets/device-worker.js` (Modify)

*   **Type / Scope**: JavaScript
*   **Proposed Changes**: Define `globalThis.fieldsealGet` (blocking GET through the same-origin proxy, returns status, headers and bytes).

#### 399. `crates/apps/web/assets/device.js` (Modify)

*   **Type / Scope**: JavaScript
*   **Proposed Changes**: After registration poll `GET /proxy/factory/v1/registrations/{tenancy}`; when `registered`, call `fetchBundle`; show `404 no-bundle` as "the factory is still preparing your bundle" and retry; the single primary action is "Get my bundle" (retry or check for newer). Remove the `/device/bundle` fetch at line 426.

#### 400. `crates/apps/web/src/http.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: The proxy (`proxy`, line 165) already forwards the `Fieldseal-PoP` request header (line 174). Only the response side is new: it returns `Fieldseal-Bundle-Sequence` and `Content-Disposition` and passes status `304` through unchanged.

#### 401. `crates/apps/web/src/device.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Delete the `GET /device/bundle` route arm (line 17) and the `bundle` handler (lines 43 to 68), including its stack branch that calls `stack::bundle`. Entry 453 uses the line numbers as they stand after this change.

#### 402. `crates/apps/web/src/stack.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Delete `bundle()`, the constants `FACTORY_STATE`, `CLI_STATE`, `ROSTERS`, `BUILDER` and `SOURCE`, and the `use std::process::Command` import (`PUBLISHED` stays as the default of the published directory, and `AUTHORITY` for the trust-bundle read). `surveys(state: &AppState) -> Vec<String>` lists the `*.published` files in `state.published_dir` (`FIELDSEAL_WEB_PUBLISHED_DIR`, default `/published`, mounted read-only), skipping the deployment policy and the `.layout` files, and keeps a name only when the log holds the entry that the publication carries: it reads the entries with `GET /entries/{from}/{to}` through `log_url` (entry 582) and compares the entry at the `leaf_index` of the publication's first `LogRecord` with the publication. The log entries alone hold digests, not survey names (WIRE-191), so the names come from the files and the log vouches for them. `provisioning(state)` takes the allow-lists from `state.allowed_builders` and `state.allowed_sources` (`FIELDSEAL_WEB_ALLOWED_BUILDERS` and `_SOURCES`, copied from the rendered intake environment, entry 588) in place of the two constants.

#### 403. `crates/apps/web/src/state.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: `stack` changes from `Option<String>` (the CLI path) to `bool`. `AppState` gains `published_dir: PathBuf`, `allowed_builders: Vec<String>` and `allowed_sources: Vec<String>` (entry 404).

#### 404. `crates/apps/web/src/main.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Remove `FIELDSEAL_WEB_CLI` (the table row at line 18 and the read at line 81): `FIELDSEAL_WEB_STACK=true` now sets `stack: true`. Read `FIELDSEAL_WEB_PUBLISHED_DIR`, `FIELDSEAL_WEB_ALLOWED_BUILDERS` and `FIELDSEAL_WEB_ALLOWED_SOURCES`; update `HELP` and the module table.

#### 405. `crates/apps/web/tests/stack_mode.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `web_153_get_device_bundle_is_gone`, `web_153_the_proxy_passes_the_pop_header_and_bundle_headers`, `web_191_the_stack_mode_needs_no_cli_path`.

#### 447. `crates/apps/web/tests/e2e_web.rs` (Delete)

*   **Type / Scope**: Integration test (removed here, restored as `svc_e2e_web.rs` in Phase 16a)
*   **Proposed Changes**: Delete the file. Its one test, `web_170_the_whole_path_through_the_routes_and_the_device`, calls `GET /device/bundle` (line 70), which this phase removes, so `just test` would fail if it stayed. The file also carries `// covers: WEB-156`, so WEB-156 and WEB-170 have no test until Phase 16a restores the cases as `svc_e2e_web.rs` (entry 448); Phase 18 checks the WEB floor of 100. `parity.rs`, `browser_constraints.rs` and `accessibility.rs` do not use `Demo`; `accessibility.rs` embeds `src/intake.rs`, so it changes in Phase 16b (entry 591).

#### 407. `crates/apps/cli/src/bundle_stack.rs` (Delete)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: `bundle build --stack` and its helpers. `publishing_policy()`, `BUILDER` and `SOURCE` move to `crates/apps/cli/src/policy_support.rs` (entry 586), because three other places call `publishing_policy()`: `bundle_cmd.rs` (line 351), `registry_cmd.rs` (line 47) and `device/stack.rs` (line 91).

#### 408. `crates/apps/cli/src/bundle_cmd.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: Remove `--stack` from `build` (the switch list at line 91 and the dispatch at line 187) and the flags that only the `--stack` path reads: `--trust-bundle`, `--custody`, `--publication`, `--tenancy-dir`, `--state`, `--issued-dir`, `--policy-publication` and `--tenancy`. Keep `--allow-unattested`, which the normal path reads (lines 265 and 271), and `--device-dir`. Keep `verify --stack`; its `publishing_policy()` call (line 351) comes from the new module.

#### 409. `crates/apps/cli/src/main.rs` (Modify)

*   **Type / Scope**: Rust module (CLI entry)
*   **Proposed Changes**: Remove `mod bundle_stack;` and add `mod policy_support;`.

#### 586. `crates/apps/cli/src/policy_support.rs` (Create)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: `publishing_policy()` with its constants `BUILDER` (`https://ci.example.org/builders/fieldseal-publish`) and `SOURCE` (`https://git.example.org/authority/artefacts`), moved from `bundle_stack.rs` (line 55) unchanged.

#### 587. `crates/apps/cli/src/registry_cmd.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: Also `crates/apps/cli/src/device/stack.rs`. Both call `crate::policy_support::publishing_policy()` (`registry_cmd.rs` line 47, `device/stack.rs` line 91). The module comment of `device/stack.rs` (line 7) says the bundle is built by `bundle build --stack`; it now says the device gets it from the factory.

#### 410. `docs/reference/spec/cli.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Delete the `bundle build --stack` row (line 160); keep `bundle verify --stack` and add a row for it to the `bundle` table, which has none.

#### 411. `tools/stack-demo.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Delete every use of `bundle build --stack`; the step is `registration wait` then `bundle fetch`. Rename the demo container's directory `/device/bundle` (lines 152 and 228) to `/device/fetched`, so the grep gate of this phase does not match it.

#### 588. `tools/stack-up.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: After rendering, write `deploy/local/.generated/web.env` with `FIELDSEAL_WEB_ALLOWED_BUILDERS` and `FIELDSEAL_WEB_ALLOWED_SOURCES`, copied from `FIELDSEAL_INTAKE_ALLOWED_BUILDERS` and `_ALLOWED_SOURCES` in `.generated/intake.env`; the `web` service reads the file (entry 415). `tools/dev-web.sh` exports the same two variables to the collector stand-in from its rendered intake environment (entry 505). The values stay in one place, the `PolicyEngine` config of the intake component (§8).

#### 412. `tools/browser-tests/device-flow.js` (Modify)

*   **Type / Scope**: JavaScript test
*   **Proposed Changes**: Remove the `#fetch-bundle` click on `/device/bundle`; the device gets its bundle through the factory.

#### 413. `tools/browser-tests/device-flow.py` (Modify)

*   **Type / Scope**: Python test
*   **Proposed Changes**: Remove the `#fetch-bundle` click on `/device/bundle`; the device gets its bundle through the factory.

#### 414. `flake.nix` (Modify)

*   **Type / Scope**: Nix flake
*   **Proposed Changes**: `webImage`: remove `fieldsealCli` and the `FIELDSEAL_WEB_CLI` environment; keep the `authority` and `published` mount points (`fakeRootCommands` drops `factory-state clistate`); the stand-in reads `published` to name the published surveys (entry 402).

#### 415. `deploy/local/compose.yaml` (Modify)

*   **Type / Scope**: Compose file
*   **Proposed Changes**: `web`: remove the `factory-state` and `clistate` mounts, make the `published` mount read-only, and add `env_file: [.generated/web.env]` (entry 588).

#### 416. `docs/how-to/use-the-web-app.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Replace the text about the bundle route with: the device fetches its bundle from the factory.

#### 589. `crates/apps/web/README.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Rewrite the four places that name the removed route and the CLI process: the `FIELDSEAL_WEB_CLI` row (line 25), the `GET /device/bundle?tenancy=&instrument=` row (line 49), and the two lines on the temporary directory `fieldseal-web-bundle-<tenancy>` and on the `FIELDSEAL_WEB_CLI` subprocess (lines 85 and 87). State that the device fetches its bundle from the factory, and add `FIELDSEAL_WEB_PUBLISHED_DIR`, `FIELDSEAL_WEB_ALLOWED_BUILDERS` and `FIELDSEAL_WEB_ALLOWED_SOURCES`.

**Housekeeping**: `crates/bindings/wasm/README.md`: Document `fetchBundle` and `fieldsealGet`; `crates/apps/web/README.md`: see entry 589; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 16b: Serve the pages from the real services; complete `just web`

*   **Goal**: The collector stand-in holds no key, session or authority state and reads the real services only (pages, state, navigation and specs), and `just web` is complete: `tools/dev-web.sh --check` compares the development adapters in use with the manifest, and `--browser` checks cookie scoping. The guided demo of Phase 17 needs exactly this. The in-memory demo authority stays as a test-only crate until Phase 16c. Technical Plan §7.1 (last bullets), §7.2 (controls 1, 2, 4), §8 and §10.1; Resolved Decisions 13, 14 and 27.
*   **Depends on**: Phases 5b, 10, 11, 12, 13 and 14 (all services exist and the device fetches its bundle from the factory).
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `tools/dev-web.sh --check --browser` passes with all services running: the development-adapter comparison of §10.1, the edit check of Phase 5b, the cookie-scoping check (control 4 of §7.2, `tools/browser-tests/cookies.sh`), and the Instruments, Publishing (verified against the trust bundle, WEB-141), Registration (factory status) and Device pages; the collector stand-in has no Intake page and `/intake` returns 404.
    *   `just web` starts all five processes, prints the URLs, the two logins, the development adapters in use and the CLI commands; `Ctrl-C` stops them all. `tools/stack-smoke.sh --browser` passes with the collector stand-in served from `127.0.0.1:8090` (entry 543).
    *   `just publish household-water-access` after raising `survey.version` shows a new log entry on the Publishing page and the factory builds the next bundle sequence; a second publish of the same name and version is refused by the artefact registry.
    *   `just up` timing is not worse than the Phase 0b baseline except for the recorded demo-image addition of Phase 12.
    *   `cargo test -p fieldseal-web` (default profile) and `just test`.
*   **Security review**: None.

#### 506. `tools/dev-web.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Complete `--check` with the development-adapter comparison of §10.1 (using the set that `deployment validate` returns, entry 427). Add the option `--browser`, which runs the cookie-scoping check (`tools/browser-tests/cookies.sh`, entry 463); Phase 17 adds the browser run of the eight steps to it (entry 492). Print the finished summary: URLs, the two logins, the development adapters in use, the IdP note and the CLI commands (`just publish`, `fieldseal roster ...`). Extend `lint` to `tools/stack-browser.sh` and `tools/browser-tests/*.sh`.

#### 427. `crates/contexts/deployment/src/validate.rs` (Modify)

*   **Type / Scope**: Rust module (Deployment context)
*   **Proposed Changes**: `validate` returns the set of development adapters a manifest uses (extends the `DEVELOPMENT_ADAPTERS` handling) so callers can print it.

#### 428. `crates/apps/cli/src/deployment_cmd.rs` (Modify)

*   **Type / Scope**: Rust module (CLI)
*   **Proposed Changes**: `deployment validate` prints the development adapters in use per component.

#### 429. `crates/contexts/deployment/tests/development_adapters.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `dep_023_validate_lists_the_development_adapters_per_component`, `dep_023_validate_refuses_them_in_production`, `dep_012_dev_web_and_local_stack_differ_only_in_directories` (loads both manifests and compares everything except directory values), `dep_051_the_development_adapters_event_has_the_same_shape_in_every_service` (the function of entry 569).

#### 430. `docs/reference/spec/deployment.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: DEP-076: `deployment validate` lists the development adapters a manifest uses; each service writes one `development-adapters` event at start.

#### 449. `crates/apps/web/src/state.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Delete `demo: Option<DemoHandle>`, `DemoHandle` and the `Demo` import; the state holds URLs, directories and the trust bundle path only.

#### 450. `crates/apps/web/src/main.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Delete the demo authority start-up (the `let demo = ...` block, lines 107 to 120), the three `demo*` fields of `Config` (lines 44 to 46) and their reads (lines 77 to 79), `demo` in the `AppState` literal (line 128), the `/intake/ingest` special case in `serve` (line 151) and `MAX_INGEST_BODY` in `http.rs` (line 12), together with the variables `FIELDSEAL_WEB_DEMO_AUTHORITY`, `FIELDSEAL_WEB_DEMO_FACTORY_BIND` and `FIELDSEAL_WEB_DEMO_UPLOAD_BIND`; update `HELP` and the module table. The line numbers are those before Phase 14, whose entry 404 moves them by a few lines.

#### 451. `crates/apps/web/src/publishing.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: In stack mode `log_body` fetches the log's checkpoint (`GET /checkpoint`) and entries (`GET /entries/{from}/{to}`, entry 582) on the server, and the page verifies signatures, threshold and inclusion in the app against the trust bundle (WEB-141) with `fieldseal_adapters_translog::{HttpLogTransport, decode_checkpoint, decode_inclusion}` and `fieldseal_publishing::VerifyPublication`; without a trust bundle it says what is not verified. It fills `PublicationReport` (entry 590) for each publication and renders it with `publication_section` (line 93), which stays: deleting `demo_body` would otherwise leave it unused. Delete `demo_body` and the web-demo import.

#### 590. `crates/apps/web/src/reports.rs` (Create)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: `PublicationReport` and the report types it contains move here from `crates/adapters/web-demo/src/reports.rs` (line 91), because `publication_section` renders them and the page keeps that function after `demo_body` goes. The web-demo copy is deleted with the crate in Phase 16c. `lib.rs` declares it (entry 459).

#### 452. `crates/apps/web/src/registration.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Delete the demo token shortcut and confirm form (the two `POST` routes at lines 13 to 30, and the "Demo shortcuts" block of `render` at lines 44 to 73); show the factory portal link and the registration state read from `GET /v1/registrations/{tenancy}`.

#### 453. `crates/apps/web/src/device.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Delete the `state.demo` branches (lines 26 to 28 and 44 to 51, as the file stands after Phase 14 removed the `bundle` handler); modes are `stack` and `provisioning file`.

#### 454. `crates/apps/web/src/intake.rs` (Delete)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: The Intake page moved to the results reader (Phase 10). `tests/accessibility.rs` embeds this file with `include_str!` (line 17), so it changes in the same phase (entry 591).

#### 455. `crates/apps/web/assets/intake.js` (Delete)

*   **Type / Scope**: JavaScript
*   **Proposed Changes**: Delete the file; only the Intake page used it.

#### 456. `crates/apps/web/src/routes.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Drop `intake` from the dispatch chain and the `use` line.

#### 457. `crates/apps/web/src/ui.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: `NAV` loses the Intake entry (four destinations, room for the guided demo in Phase 17); a footer link points to the results reader URL when configured.

#### 458. `crates/apps/web/src/assets.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Remove the `intake.js` entry.

#### 459. `crates/apps/web/src/lib.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Remove `pub mod intake;` and add `pub mod reports;` (entry 590). The modules of this file are `pub mod`, and each module file starts with a module doc comment because the crate warns on `missing_docs`.

#### 460. `crates/apps/web/Cargo.toml` (Modify)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Remove `fieldseal-adapters-web-demo`, `fieldseal-adapters-memory` (the app has no other use for it) and `fieldseal-intake` (only `intake.rs` used it); add `fieldseal-adapters-translog` (entry 451).

#### 284. `tools/browser-tests/device-flow.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Remove `FIELDSEAL_WEB_DEMO_AUTHORITY` from the usage comment (lines 3 and 6): the script runs against `just web` or the stack through `BASE=...`, not against the in-memory demo authority that this phase removes. The grep gate of Phase 16c would match the comment otherwise.

#### 591. `crates/apps/web/tests/accessibility.rs` (Modify)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `web_192_scrollable_tables_are_keyboard_reachable` embeds the page sources with `include_str!` (line 17), and `../src/intake.rs` is one of them, so deleting that file (entry 454) breaks the build. Drop it from the list.

#### 592. `crates/apps/web/tests/pages_from_services.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: With `tiny_http` stand-ins for the factory, the log and the upload endpoint (the app is started in process in stack mode): `web_151_the_publishing_page_reads_the_log_and_the_registration_page_reads_the_factory`, `web_151_a_page_says_plainly_when_its_service_is_unreachable`, `web_152_the_provisioning_document_carries_the_trust_bundle_and_the_allow_lists_from_the_environment`, `web_154_the_intake_route_is_404_and_no_page_links_to_it`.

#### 593. `crates/apps/translog/src/main.rs` (Modify)

*   **Type / Scope**: Rust module (composition root)
*   **Proposed Changes**: Write one `development-adapters` event at start, built with the function of entry 569, listing the file-held signing key (`FIELDSEAL_TRANSLOG_KEY_FILE`, created by `FIELDSEAL_TRANSLOG_GENERATE_KEY=1`) as the development adapter of the log's signer; `tools/dev-web.sh --check` and `tools/stack-smoke.sh` compare it with the manifest (DEP-076). Test in `crates/apps/translog/tests/`: `dep_051_the_translog_server_writes_one_development_adapters_event`.

#### 463. `tools/browser-tests/cookies.sh` (Create)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Control 4 of §7.2, run with the browser harness against a running `just web` and against a running stack. Run by `tools/dev-web.sh --check --browser` and `tools/stack-smoke.sh --browser`.

#### 543. `deploy/local/compose.yaml` (Modify)

*   **Type / Scope**: Compose file
*   **Proposed Changes**: The `web` service (the collector stand-in) changes its public URL: `FIELDSEAL_WEB_PUBLIC_URL` (line 186) becomes `http://127.0.0.1:8090`, so the browser holds the collector stand-in at a different host from the factory and the intake portal (`localhost`) and sends their cookies to `localhost` only (control 4 of §7.2). Port 8090 is already published on `127.0.0.1` (line 46). `tools/stack-up.sh` (lines 53 and 61) and `tools/stack-status.sh` wait for and print `http://127.0.0.1:8090` for the collector stand-in. This change was done early, in Phase 10 (security review SR-5, finding m4): the compose value, the `wait_for` and the printed line in `tools/stack-up.sh`, and a new `web app` probe in `tools/stack-status.sh` are already in place, so Phase 16b only keeps them.

#### 491. `tools/browser-tests/wcag.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Line 17: the pages list drops `/intake`: `/instruments /instruments/school-meals-baseline /publishing /registration /device`. Phase 17 adds the stepper pages (entry 594). The change belongs to this phase because the list names `/intake`, which returns 404 from here on.

#### 476. `docs/reference/spec/web-app.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: The demo-authority requirements are replaced in place; the ids stay, and a withdrawn requirement stays in the file marked `*Withdrawn`. Final map and text (ids of the new requirements are provisional):
    *   WEB-100: the page list is Instruments, Publishing, Registration and Device (Intake moves to the intake app); the Guided demo joins it in Phase 17 (entry 493).
    *   WEB-150: unchanged (the Registration page links to the factory portal and explains the flow and the four-word comparison).
    *   WEB-151: "The app MUST be served against the real factory, transparency log and upload endpoint, whose base URLs it reads from its environment, and every page that shows authority state (publications, registration state, receipts) MUST read it from the service that holds it and say plainly when that service is unreachable."
    *   WEB-152: "The app MUST provision the device with the authority's trust bundle and the publishing allow-lists as a document (DEP-024 style), read from the trust bundle file and the rendered environment." (The text of the former WEB-155.)
    *   WEB-153: "The app MUST NOT build, hold or serve bundles: it has no bundle route (`GET /device/bundle` is 404), and the device fetches its bundle from the factory (`GET /v1/bundle`, DIS-040) through the same-origin proxy." The test `web_153_get_device_bundle_is_gone` keeps its name.
    *   WEB-154: "The app MUST have no Intake page (`/intake` is 404): what the device uploads goes to the intake app's upload endpoint, and results are read in the results reader (INT-089)."
    *   WEB-155: "The app MUST hold no authority state: no key, seed, session or in-process authority. It MUST start and serve every page with no key material in its environment. Its proxy MUST forward only to the configured factory, upload and log URLs and never to the intake portal, and the content security policy of its pages MUST name no service origin."
    *   WEB-156: unchanged.
    *   WEB-160 to WEB-162: withdrawn. WEB-160 (the gate on an uploaded device export) has no successor: the upload endpoint is the production route and the file route is a CLI path. WEB-161 becomes INT-092 (the reader derives nothing from the answers). WEB-162 becomes the CSV rule of INT-085: text cells that start with a formula character are prefixed with `'`, and numeric values never are.
    *   WEB-180: "Top-level navigation MUST have at most five destinations, in pipeline order: Instruments, Publishing, Registration, Device." Phase 17 puts the Guided demo first.
    *   Tests: WEB-151, WEB-152 and WEB-154 in entry 592; WEB-153 in entry 405; WEB-155 in entry 462.

#### 477. `docs/explanation/adr/0036-showcase-web-app-and-web-device.md` (Modify)

*   **Type / Scope**: ADR note
*   **Proposed Changes**: The collector stand-in hosts no authority.

#### 478. `docs/how-to/use-the-web-app.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Replace the Intake page section with a pointer to the results reader (INT-089), and list the four pages.

**Housekeeping**: `crates/apps/web/README.md`: The app holds no authority state; invariants for controls 1 and 2 of §7.2; remove the embedded demo authority text (line 89); `Cargo.lock`: The `web` package loses its dependencies on the demo crate; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 17: Guided demo stepper

*   **Goal**: Put the existing pages in order as eight steps, each confirmed from the service that performed it, with a banner that the collector stand-in stands in for the native apps. The stepper performs no action for the authority. Technical Plan §9; Resolved Decision 21.
*   **Depends on**: Phase 16b (the collector stand-in holds no authority state, has four destinations, and `tools/dev-web.sh --check --browser` exists).
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `cargo test -p fieldseal-web --test demo_stepper` (no credential, no non-GET to a service, banner, table of production components).
    *   End-to-end test in the browser harness against `just web` (`tools/browser-tests/demo-e2e.sh`, in `tools/dev-web.sh --check --browser`): runs the CLI commands of steps 2 and 5, drives steps 3, 4, 6 and 7 on the Device page, signs in to the results reader for step 8, and asserts each confirmation carries its identifiers and each identifier appears at its independent source (log, factory status, receipts, results reader).
    *   `just a11y http://127.0.0.1:8090` (WCAG 2.2 AA) on `/demo` and `/demo/1` to `/demo/8`.
    *   The demo fidelity check of Technical Plan §10.1 passes on a running `just web` and on the stack (`tools/dev-web.sh --check`, `tools/stack-smoke.sh`).
    *   `just test`.
*   **Security review**: None.

#### 480. `crates/apps/web/src/demo_steps.rs` (Create)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: `GET /demo` and `GET /demo/{1..8}`. Each step page: title, one sentence on what happens, who does it in production, how to do it (a link to the page where the action is done, or, for a CLI step, the exact command to copy; never run by the stepper), a confirmation panel, Back and Next. The table of Technical Plan §9 is the page data. Reads only: the factory's `GET /v1/registrations/{tenancy}` and the log's checkpoint and entries through the proxy, responses the WebAssembly device received (bundle headers, receipts), and the device's own state read in the browser. No credential, no non-`GET` request to a service, no `POST /demo/confirm`. Step 3 tells a presenter who runs the demo again to retire the old device on the factory portal (REG-043) before registering a new one (Technical Plan §7.4). Step 8 shows only a link to the results reader. Final page names `just acceptance` and `just release`.

#### 481. `crates/apps/web/assets/demo.js` (Create)

*   **Type / Scope**: JavaScript
*   **Proposed Changes**: Reads the device worker's state (tenancy, held bundle, journal range) and the factory/log responses to fill each confirmation panel and its "check it" link; labels the device's own view as such.

#### 482. `crates/apps/web/assets/demo.css` (Create)

*   **Type / Scope**: Stylesheet
*   **Proposed Changes**: Stepper layout using the existing tokens (`tokens.css`); one primary action per screen (WEB-181).

#### 483. `crates/apps/web/src/assets.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Register `demo.js` and `demo.css`.

#### 484. `crates/apps/web/src/routes.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: `/` redirects to `/demo`; add `demo_steps::handle` to the chain.

#### 485. `crates/apps/web/src/ui.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: `NAV` gets "Guided demo" first (five destinations, WEB-180); banner helper: "This collector stand-in stands in for the native Android and iOS apps, which do not exist yet; only the bindings do."

#### 486. `crates/apps/web/src/lib.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Add `pub mod demo_steps;`; the file starts with a module doc comment because the crate warns on `missing_docs`.

#### 487. `crates/apps/web/src/device.rs` (Modify)

*   **Type / Scope**: Rust module (collector stand-in)
*   **Proposed Changes**: Show the banner on the Device page.

#### 488. `crates/apps/web/tests/demo_stepper.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: `web_196_the_stepper_holds_no_credential_and_makes_no_non_get_request_to_a_service`, `web_195_each_step_names_its_production_component`, `web_198_the_banner_is_on_the_demo_and_device_pages`, `web_197_step_8_links_to_the_results_reader_and_confirms_nothing`, `web_199_step_3_says_to_retire_the_old_device_before_registering_again`, `web_199_the_last_page_points_to_acceptance_and_release`, `web_180_navigation_has_five_destinations_in_pipeline_order`, `web_181_each_step_has_one_primary_action`.

#### 489. `crates/apps/web/tests/accessibility.rs` (Modify)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Add `/demo` and `/demo/1` to `/demo/8`, and add `include_str!("../src/demo_steps.rs")` to the list of page sources in `web_192_scrollable_tables_are_keyboard_reachable` (Phase 16b removed `intake.rs` from it, entry 591).

#### 490. `tools/browser-tests/demo-e2e.sh` (Create)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Runs CUJ 4 headless against `just web` with the existing harness files (`tools/browser-tests/device-flow.py` and `device-flow.js`; `tools/local-stack-passkey.py` is for the stack only). In order, it:
    1.  Signs in at the development IdP's page as `presenter`, reusing the harness's browser session.
    2.  Issues the registration token on the factory portal.
    3.  Confirms the four words.
    4.  Reads `deploy/local/.state/dev-web/logs/factory.log` for the `bundle-built` event and compares its sequence with the one the Device page shows (step 4 of the stepper).
    Around these four, the script runs the CLI commands of demo steps 2 and 5, drives demo steps 6 and 7 on the Device page, and signs in to the results reader for step 8.

#### 594. `tools/browser-tests/wcag.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Line 17: the pages list gains `/demo` and `/demo/1` to `/demo/8` (Phase 16b removed `/intake`, entry 491).

#### 492. `tools/dev-web.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: `--check --browser` also runs `demo-e2e.sh` (Phase 16b added the option with `cookies.sh`).

#### 493. `docs/reference/spec/web-app.md` (Modify)

*   **Type / Scope**: Specification
*   **Proposed Changes**: Add the stepper requirements (ids provisional):
    *   WEB-195: "The app MUST serve a guided demo at `/demo` and `/demo/{1..8}`. Each step page MUST show a title, one sentence on what happens, who performs the step in production, how to do it (a link to the page where the action is done, or for a command-line step the exact command, which the app never runs), a confirmation panel, and Back and Next links."
    *   WEB-196: "The guided demo MUST perform no action for the authority: it MUST hold no credential, MUST make no request to a service other than GET, and MUST have no route that records a confirmation."
    *   WEB-197: "Each confirmation MUST be read from the service or device state named beside it, MUST link to a place where the same value exists independently, and MUST label the device's own view as such. Step 8 MUST show only a link to the results reader and confirm nothing."
    *   WEB-198: "`/demo` and the Device page MUST show a banner stating that the collector stand-in stands in for the native Android and iOS apps, which do not exist yet."
    *   WEB-199: "Step 3 MUST tell a presenter who runs the demo again to retire the old device on the factory portal (REG-043) before registering a new one, and the last page MUST name `just acceptance` and `just release`."
    *   WEB-100 gains the Guided demo in its page list, and WEB-180 puts it first of five destinations (entry 476 set the four-page text).

#### 494. `docs/how-to/use-the-web-app.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: The guided demo, the eight steps, which parts are production components.

#### 495. `docs/tutorials/hands-on.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Pointer to the guided demo at the end.

**Housekeeping**: regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 16a: Run the web tests against the real services

*   **Goal**: The web and security tests that need an authority run against the real factory, log, intake app and development IdP, started once per run by a nextest setup script, instead of against the in-memory demo authority. Technical Plan §8 (test infrastructure) and §9 (tests); Resolved Decision 27.
*   **Depends on**: Phase 16b (the collector stand-in no longer holds an authority) and Phases 10 to 14. It runs after Phase 17, which it does not need.
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `just integration` passes: `cargo build --workspace --bins --locked`, then `cargo nextest run --workspace --profile integration --run-ignored only --locked`, which starts the built `fieldseal-dev-idp`, `fieldseal-translog`, `fieldseal-factory` and `fieldseal-intake` once for the run through a nextest setup script. It includes the WebAssembly device flow, the web end-to-end cases and the collector stand-in isolation tests (`crates/apps/security-tests/tests/svc_stand_in_isolation.rs`, entry 462).
    *   `just test` does not run them and its 20 s budget is unchanged (`tools/test-budget.sh`).
    *   `just acceptance` runs `just integration` first; the `ci` workflow has an `integration` job that runs the same two commands.
*   **Security review**: None.

#### 437. `crates/apps/web/tests/support/mod.rs` (Create)

*   **Type / Scope**: Test support
*   **Proposed Changes**: `Services::from_env()` reads the endpoints that the nextest setup script wrote into the test environment (`FIELDSEAL_SVC_FACTORY_URL`, `_INTAKE_URL`, `_PORTAL_URL`, `_LOG_URL`, `_IDP_URL`, `_DIR`) and fails with "run with `just integration`" if they are missing. Helpers: sign in through the development IdP, register a device, run CLI steps with the built `fieldseal`. Shared by the web and security-tests integration tests through `#[path]`. The file starts with `#![allow(dead_code)]`, because each test binary that includes it uses only some of the helpers and the workspace denies warnings.

#### 438. `tools/svc-fixture.sh` (Create)

*   **Type / Scope**: Shell script (nextest setup script)
*   **Proposed Changes**: Starts the built binaries from `target/debug` once per nextest run. It first runs the port check of `tools/dev-web.sh` (§8, step 1) on the fixed `just web` ports (8080, 8180, 8480, 8481 and 9001) and exits with a message naming the port when `just web` or `just up` holds one; ephemeral ports are not possible, because the development IdP's issuer is derived from its port (§7.5) and the manifest names the others. Then it creates a temp directory, runs `tools/stack-init.sh` for the authority, renders `examples/deployments/dev-web.yaml` into it, starts `fieldseal-dev-idp --development-tool`, `fieldseal-translog`, `fieldseal-factory` and `fieldseal-intake` on those ports, waits for each `/healthz`, publishes the bundled instruments, layouts and policy (`tools/dev-publish.sh --all`), issues the example rosters and makes the assignments, in the order of §8, with `FIELDSEAL_OIDC_ISSUER` and `FIELDSEAL_OIDC_CLIENT_ID` set for the CLI steps, then writes the endpoint variables to `$NEXTEST_ENV` and exits. A detached supervisor stops all four and removes the temp directory when the nextest process (the script's parent) ends. Fails with the name of the missing binary if `cargo build --workspace --bins` was not run first.

#### 439. `.config/nextest.toml` (Modify)

*   **Type / Scope**: Test runner configuration
*   **Proposed Changes**: Keep `[profile.default]` as is (it skips `#[ignore]`d tests, so the 20 s suite is unchanged). Setup scripts are still experimental in the pinned nextest (cargo-nextest 0.9.136 in the dev shell; the feature exists since 0.9.59 and its documentation still says "Experimental: enable with `experimental = ["setup-scripts"]`"), so add the top-level `experimental = ["setup-scripts"]`. Add `[profile.integration]` with `default-filter = "binary(~svc_)"`, a longer `slow-timeout`, `[scripts.setup.services] command = "tools/svc-fixture.sh"` and `[[profile.integration.scripts]] filter = "binary(~svc_)"` with `setup = "services"`.

#### 440. `justfile` (Modify)

*   **Type / Scope**: Build configuration
*   **Proposed Changes**: Recipe `integration`: `cargo build --workspace --bins --locked` then `cargo nextest run --workspace --profile integration --run-ignored only --locked`. Recipe `acceptance` depends on it (`acceptance: integration`). `test` is unchanged.

#### 441. `tools/test-budget.sh` (Modify)

*   **Type / Scope**: Shell script
*   **Proposed Changes**: Comment and explicit `--profile default`: only the default profile is timed; integration tests (`#[ignore]` in `svc_*` test binaries) are outside the 20 s budget. Neither this script nor `tools/test-inventory.py` classifies tests, so the inventory needs no change: it still requires each test, ignored or not, to name a requirement id.

#### 442. `.github/workflows/ci.yml` (Modify)

*   **Type / Scope**: CI workflow
*   **Proposed Changes**: Keep the existing triggers (`push` on `v*` tags and `workflow_dispatch`). Add job `integration` (same checkout, Nix install and cache steps as `checks`): `nix develop path:. --command bash -c 'cargo build --workspace --bins --locked && cargo nextest run --workspace --profile integration --run-ignored only --locked'`. The `checks` job is unchanged: `cargo test` skips the ignored tests.

#### 443. `crates/apps/web/tests/svc_device_flow.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Moved from `crates/adapters/web/tests/device_flow.rs`: `plat_110_web_device_registers_verifies_captures_exports_uploads_and_lands` against the real services (registration with the factory, bundle fetch, capture, device export, upload, receipts verified, landing seen through the intake app's results export). `#[ignore]` for the default profile.

#### 444. `crates/adapters/web/tests/device_flow.rs` (Delete)

*   **Type / Scope**: Integration test (moved)
*   **Proposed Changes**: Moved to `crates/apps/web/tests/svc_device_flow.rs`.

#### 445. `crates/adapters/web/Cargo.toml` (Modify)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Remove the dev-dependency on `fieldseal-adapters-web-demo`.

#### 448. `crates/apps/web/tests/svc_e2e_web.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: The cases of `e2e_web.rs` (deleted in Phase 14, entry 447) against the real services from the fixture: Instruments, Publishing (verified log read), Registration (factory status) and Device pages end to end. `#[ignore]`d for the default profile.

#### 462. `crates/apps/security-tests/tests/svc_stand_in_isolation.rs` (Create)

*   **Type / Scope**: Integration test
*   **Proposed Changes**: Uses the same harness through `#[path = "../../web/tests/support/mod.rs"]`; every test is `#[ignore]`d for the default profile. Cases: `web_155_the_stand_in_starts_and_serves_every_page_with_no_key_material_in_its_environment` (control 1), `web_155_a_proxy_request_aimed_at_the_portal_returns_404_or_502_and_results_is_404` (control 2), `web_155_the_csp_of_every_page_names_no_service_origin`, `int_089_a_stand_in_origin_request_to_a_results_route_is_refused`, `int_089_the_stand_in_response_sets_no_session_cookie`. Control 4 (cookie host scoping) is a browser-harness check in `tools/browser-tests/cookies.sh` (below).

#### 464. `crates/apps/security-tests/Cargo.toml` (Modify)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Add `tiny_http` and `ureq` dev-dependencies for the harness.

#### 595. `crates/apps/cli/src/conformance_cmd/contracts.rs` (Modify)

*   **Type / Scope**: Rust module (conformance)
*   **Proposed Changes**: Seven entries (lines 152 to 160: `DevicePolicy`, `Camera`, `BundleOpener`, `ShareTarget`, `UploadTransport`, the `Attestor` of `WebKeyStore` and the `RandomSource` of `WebRandom`) name `cargo test -p fieldseal-adapters-web --test device_flow`, which entry 444 deletes. Their command becomes `just integration` (the device flow runs there as `svc_device_flow`, entry 443). The `--test platform` entries are not part of this change.

#### 596. `docs/reference/conformance.md` (Modify)

*   **Type / Scope**: Generated documentation
*   **Proposed Changes**: Regenerate the matrix with `fieldseal conformance matrix` (the seven commands changed).

**Housekeeping**: `crates/adapters/web/README.md`: Test command does not name web-demo; device flow test moved; regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 16c: Delete `crates/adapters/web-demo`

*   **Goal**: Delete the in-memory demo authority. Nothing links it any more: the collector stand-in dropped it in Phase 16b and the tests moved to the real services in Phase 16a. Technical Plan §7.1 (last bullets); Resolved Decision 27.
*   **Depends on**: Phases 16a and 16b.
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `grep -rIn 'web-demo\|web_demo\|FIELDSEAL_WEB_DEMO_AUTHORITY' crates tools deploy docs examples flake.nix justfile README.md Cargo.lock --exclude=developer-experience-first.md` finds nothing outside the historical text of ADR 0036. (It does not search the root files `design_draft.md`, `concepts_brief.md` and `*_DRIFT_REPORT.md`, which are working papers.)
    *   `python3 tools/check-architecture.py`; `just test`; `just integration`.
*   **Security review**: None.

#### 465. `crates/adapters/web-demo/Cargo.toml` (Delete)

*   **Type / Scope**: Cargo manifest
*   **Proposed Changes**: Crate removed.

#### 466. `crates/adapters/web-demo/README.md` (Delete)

*   **Type / Scope**: Crate contract
*   **Proposed Changes**: Crate removed.

#### 467. `crates/adapters/web-demo/src/{content,lib,reports,support}.rs` (Delete)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: Crate removed.

#### 468. `crates/adapters/web-demo/src/intake_world.rs` (Delete)

*   **Type / Scope**: Rust module
*   **Proposed Changes**: Crate removed (the web-only `LongRow`, `unhex` and the `'` formula prefix go with it).

#### 474. `crates/apps/cli/src/conformance_cmd/contracts.rs` (Modify)

*   **Type / Scope**: Rust module (conformance)
*   **Proposed Changes**: Remove the four `external!` entries that name `(web demo)` adapters (lines 161 to 164).

#### 475. `docs/reference/conformance.md` (Modify)

*   **Type / Scope**: Generated documentation
*   **Proposed Changes**: Regenerate.

#### 597. `crates/adapters/web/src/device.rs` (Modify)

*   **Type / Scope**: Rust module (WebAssembly device adapter)
*   **Proposed Changes**: The doc comment at line 77 says the provisioning JSON is the one "the authority serves (see the web-demo crate)"; it now points to the collector stand-in's `stack.rs`. The grep gate of this phase matches it otherwise.

#### 598. `docs/tutorials/hands-on.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: The block at lines 203 to 207 runs `FIELDSEAL_WEB_DEMO_AUTHORITY=true nix run path:.#fieldseal-web`; replace it with `just web`. Phase 15 (entry 432 and the housekeeping line) writes the finished tutorial text; this change is here so that this phase's grep gate passes.

#### 599. `docs/how-to/use-the-web-app.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Remove the sentences and commands that name `FIELDSEAL_WEB_DEMO_AUTHORITY` and the embedded demo authority, and point to `just web` and the stack. Phase 15 (entry 431) writes the finished text; this part belongs to this phase so that its grep gate passes.

**Housekeeping**: `Cargo.lock`: Workspace member removed; `crates/adapters/README.md`: Remove the `web-demo` entry (line 23) and its mention in the introduction (line 5); regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 15: Documentation for `just web`

*   **Goal**: The how-to, tutorial, build-system note, README and index describe the finished loop: `just web`, the two logins, the CLI steps, the results reader and the guided demo. Technical Plan §8; Resolved Decisions 13 and 14.
*   **Depends on**: Phases 16c and 17 (the in-memory demo authority is gone and the guided demo exists, so the text describes the final state).
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `grep -rIn 'FIELDSEAL_WEB_DEMO_AUTHORITY' README.md docs/how-to docs/tutorials docs/index.md` finds nothing.
    *   `just test`.
*   **Security review**: None.

#### 431. `docs/how-to/use-the-web-app.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Replace "Run it with nothing else" and "Attach it to the compose stack" with `just web` and the stack; no `FIELDSEAL_WEB_DEMO_AUTHORITY`; the two logins; the CLI steps.

#### 432. `docs/tutorials/write-and-publish-your-first-survey.md` (Modify)

*   **Type / Scope**: Tutorial
*   **Proposed Changes**: Update the publish section added in Phase 5b for the finished loop: the results reader and the guided demo as the next steps after the Publishing page.

#### 433. `docs/explanation/build-system.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Describe the dev loop and what it shares with the container path.

#### 434. `README.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Quick start: `just web`.

#### 435. `docs/index.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Link the dev loop.

**Housekeeping**: regenerate `docs/reference/test-inventory.md` with `python3 tools/test-inventory.py` (every new test names a requirement id).

### Phase 18: CI timing

*   **Goal**: Record warm-cache timings after the whole change and check them against the targets. Technical Plan §8 (warm-cache CI timing). The `ci` workflow runs only on `v*` tags and `workflow_dispatch`; it has no `pull_request` trigger, so there is no path filter to fix, and the phase keeps both triggers.
*   **Depends on**: Phase 15, the last phase before it (so the measured tree is the final one). The baseline was recorded in Phase 0b.
*   **Commits**: One commit.
*   **Gate** (must pass before the next phase starts):
    *   `actionlint .github/workflows/ci.yml` (in the dev shell) passes and the `on:` block still lists only `push: tags: ["v*"]` and `workflow_dispatch`.
    *   `ci` started twice on one commit on a warm cache (`gh workflow run ci`): job durations (from `gh run view`) are recorded beside the Phase 0b numbers; targets from Open Question 1 are checked.
    *   `tools/check-coverage.py --baseline tools/coverage-baseline.toml` passes, including the WEB floor of 100 (WEB-156 and WEB-170 lost their test in Phase 14 and regained it in Phase 16a), and, where the measured value is higher, the floors are raised (upward only).
*   **Security review**: None.

#### 498. `docs/explanation/build-system.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: Add the post-change `just up` and CI numbers, the targets (Open Question 1) and whether each is met.

#### 499. `docs/reference/toolchain.md` (Modify)

*   **Type / Scope**: Documentation
*   **Proposed Changes**: State the `ci` triggers (`v*` tags and `workflow_dispatch`) and the final warm-cache numbers.

#### 500. `tools/coverage-baseline.toml` (Modify)

*   **Type / Scope**: Coverage floors
*   **Proposed Changes**: Raise the MUST-coverage floors for CLI, DEL, DEP, DIS, INT, REG and WEB where the measured value is higher; never lower.

### Verification Plan

The commands below are run in the Nix dev shell (`nix develop path:.`, which `just` enters). Each phase's gate (above) lists the commands that must pass before the next phase starts; this section lists the whole-change checks and the measurements.

*   **Compilation/Build**:
    *   `cargo build --workspace --locked` and `cargo build --target wasm32-unknown-unknown -p fieldseal-wasm --locked`.
    *   `nix build path:.#checks.x86_64-linux.clippy path:.#checks.x86_64-linux.tests path:.#checks.x86_64-linux.architecture --no-link` (what `just check` and the `ci` workflow run).
    *   Packages: `nix build path:.#fieldseal path:.#fieldseal-factory path:.#fieldseal-intake path:.#fieldseal-translog path:.#fieldseal-web path:.#fieldseal-wasm --no-link`.
    *   Images (Linux): `nix build path:.#factory-image path:.#intake-image path:.#translog-image path:.#web-image path:.#cli-image path:.#demo-image --no-link`.
    *   `fieldseal-upload-server` and `upload-image` no longer exist. `fieldseal-dev-idp` and `fieldseal-upload-practice` are built by Cargo only and appear in no Nix output.
    *   `tools/stack-images.sh` and `just up` build and load the renamed images.
*   **Unit Tests**:
    *   `cargo test -p <package>` for each changed package: `fieldseal-kernel`, `fieldseal-adapters-authoring`, `fieldseal-adapters-landing-files`, `fieldseal-adapters-file`, `fieldseal-adapters-portal`, `fieldseal-adapters-factory-http`, `fieldseal-adapters-results-http`, `fieldseal-adapters-oidc`, `fieldseal-adapters-translog`, `fieldseal-adapters-upload-http`, `fieldseal-adapters-web`, `fieldseal-adapters-memory`, `fieldseal-intake`, `fieldseal-registration`, `fieldseal-distribution`, `fieldseal-deployment`, `fieldseal-cli`, `fieldseal-factory`, `fieldseal-intake-app`, `fieldseal-dev-idp`, `fieldseal-web`, `fieldseal-wasm`, `fieldseal-uniffi`, `fieldseal-policy`, `fieldseal-e2e`, `fieldseal-security-tests`.
    *   `just test` runs everything: `tools/test-inventory.py --check` (every test names a requirement id the specs define; the inventory document is current), `tools/test-budget.sh` (all default-profile tests plus doc tests in 20 seconds, building excluded; `#[ignore]`d `svc_*` tests are not run), `cargo clippy --workspace --all-targets --locked -- -D warnings`, `tools/check-architecture.py`, `tools/check-example-licences.py` (from Phase 0a) and, from Phase 4, `tools/check-example-paths.py`.
    *   The test count grows from 84 (Phase 0b) by the tests named in the phases; the figure after each phase is recorded.
*   **Static Analysis & Linting**: only checks the repository already runs. Clippy with `-D warnings` (the workspace forbids `unsafe_code` and warns on `missing_docs`); `tools/check-architecture.py` (new apps `fieldseal-intake-app` and `fieldseal-dev-idp` are in `architecture.toml`; `fieldseal-adapters-portal` and `-results-http` match the adapter prefix; no app depends on another app; contexts use no `std::fs`, `std::env` or `std::process`); `just lint` (shellcheck on `tools/stack-*.sh`; extend the recipe to `tools/dev-web.sh`, `tools/dev-publish.sh` in Phase 5b and to `tools/stack-browser.sh` and `tools/browser-tests/*.sh` in Phase 16b); and `actionlint` on `.github/workflows/*.yml`. This plan adds no `cargo deny`, `yamllint`, `ruff` or `taplo` check: no configuration for them exists and none of them is in the dev shell.
*   **Test Coverage Requirement**: `python3 tools/check-coverage.py --baseline tools/coverage-baseline.toml` must not fall below any floor in `tools/coverage-baseline.toml` (CLI 77.3, DEL 86.0, DEP 50.0, DIS 88.0, INS 85.2, INT 80.0, REG 88.6, WEB 100.0 and the others); every new MUST requirement named in this plan has at least one test named after it (the inventory check enforces this), so the new ids do not lower a prefix's percentage; floors are raised only upward, in Phase 18. WEB must stay at 100.0 after the requirement rewrite of Phase 16b.
*   **E2E/Integration**:
    *   `just migration-gate` (golden addresses, salted fingerprints, bound layout addresses and expanded documents) before and after Phases 1 and 4, and the revert rehearsal of Phase 4.
    *   `fieldseal conformance run --suite strict-schema` over `tests/schema-corpus/` for surveys and layouts (Phase 1); `cargo test -p fieldseal-security-tests --test keycloak_realm` and `--test operator_api` (Phase 12); `cargo test -p fieldseal-factory --test crash_order` (Phase 13).
    *   `just web` and `tools/dev-web.sh --check [--browser]`: all five processes start from one rendered manifest; the edit-and-reload check; the development-adapter comparison; cookie scoping (`tools/browser-tests/cookies.sh`); the browser run of the eight steps (`tools/browser-tests/demo-e2e.sh`).
    *   `just integration` (from Phase 16a; `cargo build --workspace --bins`, then the nextest `integration` profile with the service fixture); also a `ci` job.
    *   `just acceptance` (runs `just integration` first, then every tutorial step against a fresh container stack), `tools/stack-smoke.sh --browser`, and the restart test (`tools/stack-run.sh resume`: a `replayed` event with `landed` above zero, a duplicate that lands nothing, and the results export directory byte-identical before and after).
    *   The demo fidelity check: a running `just web` and a running stack each print the development adapters in use per service (expected: the set in the table of §10.1), and the check fails if a service reports one that the rendered manifest does not declare.
    *   Journey coverage: CUJ 1 by `cli_044`/`cli_045` tests and the timed tutorial run (Phases 5 and 5b); CUJ 2 by `ins_260` tests; CUJ 3 by the edit check of Phase 5b; CUJ 4 by `demo-e2e.sh`; CUJ 5 by `cli_048`, `int_085` to `int_088` and the restart test; CUJ 6 by the `int_089` tests, `svc_stand_in_isolation.rs` and `cookies.sh`; CUJ 7 by `just migration-gate` and the revert rehearsal.
*   **Measurements** (recorded in `docs/explanation/build-system.md` against the Phase 0b baseline):
    *   `just up` per stage (`deploy/local/.generated/stack-timing.txt`) from `just purge`, with nothing changed, and after a one-line Rust change; the targets of Open Question 1 are checked in Phase 18.
    *   `ci` job durations on a warm cache, twice on one commit, from `gh run view`; whether `FIELDSEAL_CACHIX` is set (Open Question 2).
    *   Time from `fieldseal new survey` to a passing `survey check` (recorded in Phase 5) and from there to a published address (recorded in Phase 5b), for the defined test newcomer on the defined machine (Open Question 1).
    *   Test suite seconds against the 20 second budget, the test count, the distinct-dependency count, a cold `cargo build --workspace --timings`, and the absence of `arrow` and `parquet` in `cargo tree`, after every phase.
    *   Idle CPU of the factory over 60 seconds with the reconciler at its default interval (Phase 13).
