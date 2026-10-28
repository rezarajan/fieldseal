# Developer Experience First: Survey Authoring, Dev Loop and End-to-End Demo

* **Author:** Reza Rajan
* **Date:** 2026-10-28

## Overview

Fieldseal is hard to pick up. When the developer, who also writes the surveys, tested it, three problems came up.

1. **Writing a survey.** Starting from a blank file there is no obvious first step. Settings are spread across several files with no rule for which file holds what: the instrument, the layout, the roster and the translation catalogues. Translations are hard to piece together mentally.
2. **The development loop.** `just up` takes about five minutes because it rebuilds container images with Nix. The usual edits are to Rust code and the web UI. A CI run on a cold cache took over an hour.
3. **The demo.** The web app does not walk a newcomer through the product from start to finish, and it gives no feedback after each step. The audience is field collectors and an IT person who will deploy to production. Exported results cannot be loaded back and read. That leaves the audience with no reason to believe the export format works in production.

Order of work, as agreed: survey authoring first, then the development loop, then the demo. The hard constraint is that no simplification may weaken signing, threshold publication, sealing, attestation or fail-closed policy.

Six reviewers (design, codebase details, zoom-out, comprehension, implementation readiness and structure) stress-tested this plan against the repository. Their main finding: **much of what parts 2 and 3 ask for already exists but is hard to find, and part 1 overlaps two unfinished design records (ADR 0039 and ADR 0040).** Most of the work is therefore finishing, connecting and documenting, not building from scratch.

## Analysis

### 1. Merging a survey folder could change what gets signed

The original idea was that the tool merges every file in a survey folder by its content, the way Terraform merges `.tf` files. The reviewers ranked this the most serious risk.

- **The authoring adapter promises that what a reviewer reads is exactly what gets signed** (`crates/adapters/authoring/src/lib.rs`). The instrument's address is a hash of the expanded document (`crates/apps/cli/src/commands.rs`).
- **A layout is its own signed artefact.** It binds to the instrument's fingerprint (ADR 0033, `crates/contexts/instrument/src/domain/layout.rs`).
- **The merge rules are undefined.** Nothing says which file wins when two define the same key, how order is set, or which files count. If file order can change question order, it can also change the hash.
- **Merging hides the "which file" question instead of answering it.** If any file can hold any key, an author still doesn't know where to look.

A **folder convention** solves the stated problem with no new semantics:

```text
survey/
  instrument.yaml
  layouts/<window>.yaml
  i18n/<lang>.po
```

Merging is only worth it if real surveys grow far past the current examples, which are about 170 to 260 lines each.

### 2. Two unfinished design records already cover this ground

- **ADR 0039** (Proposed, marked incomplete) proposes a `fieldseal.yaml` manifest, a `fieldseal schema` command, and `i18n init`, `extract` and `check` commands.
- **ADR 0040** (Proposed) replaces 0039's survey syntax. It promises a generated JSON Schema, errors with line and column numbers, a `fieldseal expand` command, and pinned answer codes.
- **They disagree on how translations are keyed.** 0039 uses short fixed ids. 0040 uses the English text plus a context string.
- **None of it is built.** The CLI has no `schema`, `expand` or `new` command.

Adding a third half-finished design on top would make things worse. The next step is one record that replaces both.

### 3. The current translation setup is fragile and fails silently

- **Layout translations are keyed by position**, for example `steps.1.contents.0.card`. Inserting a step moves every later translation onto the wrong text.
- **Catalogue paths come from the file name.** Renaming a YAML file loses its translations without a warning.
- **Stale and missing translations go unnoticed.** Empty translations are dropped and the original English text is thrown away on load.
- **There are two catalogue folders for one survey:** `examples/instruments/i18n/<survey>/` and `examples/layouts/i18n/<survey>.compact/`.
- **There is a second translation pipeline:** `instrument i18n extract|merge` writes XLIFF files.

Keeping `.po` files is right because the translators are outside professionals. The friction comes from how Fieldseal uses them, not from the format.

### 4. There is no single source for a schema

- **Survey files are not read into typed structures.** They are untyped trees checked by hand in about 1,250 lines of `compact.rs`.
- **Errors in that syntax report line 0, column 0.**
- **Policy has its own separate schema** (`crates/contexts/policy/src/domain/schema.rs`).

A JSON Schema written by hand for editor autocomplete will drift from the decoder unless a test checks the two against each other. The reviewers split on whether to write it by hand now or build one declarative schema module that both the decoder and the editor schema read.

### 5. Three different ways of finding a survey's layout and roster

- **The CLI** follows the relative path in the layout file.
- **The web demo** matches files by name. It skips invalid content with only a warning in the terminal, so the page simply doesn't show the survey.
- **Paths to the examples are hard-coded** in tests, scripts, `include_str!` calls and the compose file.

Any change to the folder structure has to replace all three with one shared resolver, or authors will see different behaviour in the CLI and in the web app.

### 6. The development loop: the cause was misread

- **Image loading is already skipped when the Nix output is unchanged** (`tools/stack-images.sh`), and `FIELDSEAL_SKIP_IMAGE_BUILD=1` exists.
- **The time goes into building the images.** Each image is a separate crane build, so any source change rebuilds all of them.
- **Waiting for Keycloak may add up to 240 seconds.** Keycloak can't run outside a container, because passkeys need it at `localhost:8180`.
- **A loop without containers already exists:** `FIELDSEAL_WEB_DEMO_AUTHORITY=true cargo run -p fieldseal-web` runs the factory, upload, intake gate and transparency log in one process (`docs/how-to/use-the-web-app.md`). It isn't exposed as a `just` recipe, so it's easy to miss.
- **CI runs the full Rust check when only an example YAML file changes.**

### 7. The demo: the pieces exist, the sequence and feedback don't

- **The pages already exist.** The web app has Publishing, Registration, Device (export and upload) and Intake pages, including `/intake/rows.csv`.
- **The steps already exist.** The `just` walkthrough and `tools/demo-pipeline.sh` cover all eight steps.
- **What is missing:**
  - a guided sequence
  - a confirmation after each step
  - a starting point that is easy to find

The results reader raises a design question nobody has settled:

- **Exports are sealed so only intake can open them.** Opening one today uses the practice authority's record key (`crates/apps/cli/src/export_cmd.rs`).
- **The web demo runs authority, intake and collector in one process on one web address.** So "the collector's browser never decrypts" holds, but the IT audience sees no real separation between the roles.
- **`/intake` returns 404 when the web app runs against the container stack.**
- **The stack's landing files are not reloaded after a restart,** so a reader could show only part of the data.

**The demo must also say plainly that the web app stands in for native apps.** No Android or iOS project exists yet, only the UniFFI bindings. The web app also refuses to start in production, so the IT person's part of the demo has to use the container stack (`just acceptance` or `just release`), not the web app.

### 8. A newcomer has no starting point

- **No tutorial covers writing a survey.** `examples/README.md` warns against copying the examples blindly.
- **The files use three different header conventions:** `survey:`, `layout:`, and `apiVersion`/`kind`.
- **A roster's link to its survey exists only in a deployment config string.**
- **`docs/index.md` says "Tutorials: None yet",** although `docs/tutorials/hands-on.md` exists.
- **Generated answer codes will trip a new author.** Under ADR 0040, editing a label changes its generated code, which is rejected unless the code was pinned. A new author will hit this on their first wording change.

### 9. Success can't be measured yet

There is no target number of minutes for a first survey, no defined starting state, no baseline timing for `just up` and no target CI time. It is also unknown whether the CI cache (`FIELDSEAL_CACHIX`) is configured.

### 10. Second review: the open-format export and the folder migration

A second pass by four reviewers (design, codebase details, zoom-out and implementation readiness) checked the decisions made after the first review.

- **There are already two long formats, and they disagree.**
  - `crates/adapters/landing-files` writes the 20 `LONG_COLUMNS` defined in `crates/contexts/intake/src/data_contract.rs`.
  - The web app's `/intake/rows.csv` (`crates/adapters/web-demo/src/intake_world.rs`) writes a different set of columns. It adds `instrument_name`, `outcome` and the decoded roster `subject_id`, has no `retracted` column, and renames the time columns.
  - It also prefixes any value starting with `=`, `+`, `-` or `@` with `'` (a spreadsheet formula guard), so `-5` becomes `'-5`.
  - One shared table has to replace both writers. Otherwise "the formats hold the same data" can't be true.
- **A folder migration can change addresses even when the content is unchanged.**
  - Content hashing works on the expanded document, so moving files by itself is safe.
  - But publication salts in the demo come from a counter that depends on load order (`crates/adapters/memory/src/demo.rs`), and a folder walk loads files in a different order.
  - A layout with no bound fingerprint writes its raw source path (`crates/contexts/instrument/src/domain/layout.rs`).
- **The translation decision goes further than ADR 0040.**
  - ADR 0040 sets `msgctxt` to the element's *path*. Today, layout paths are positions, and layout titles have no ids at all (`crates/adapters/authoring/src/compact.rs`).
  - One `i18n/<lang>.po` holding several layouts would produce clashing keys.
  - `parse_po` throws away `msgid`, so stale English can't be detected yet.
  - Decision 6 therefore needs a key grammar (for example `instrument/<path>` and `layout/<window>/<id>`) and authored ids for layout parts.
- **The export has no version of its own.** Neither the column list nor the data contract has a schema version. Adding about five columns without one would break lakehouse tables later.
- **The typed columns don't cover every item type.**
  - There are nine item types. `integer` and `evidence` have no stated column, and `date` lands as text today.
  - Money's scale depends on the currency, and other decimals are rounded to 9 places. A single Parquet decimal column needs one fixed precision and scale, and JSON has no decimal type.
  - Not yet defined:
    - the timestamp type and time zone
    - which columns become lists
    - what the value columns hold for "don't know", "refused" and retracted answers
  - "Other" free text is already landed as its own row.
- **An open-format file holds more than pseudonymous ids.** It also holds:
  - free text
  - the consent basis
  - excluded rows (kept with a flag)
  - record, tenancy and sequence ids, which can link records together
  - items marked special-category

  The web CSV goes further and decodes the roster's `subject_id`.
- **Parquet is costly to compile and may not be needed yet.**
  - The `arrow`/`parquet` crates would likely take more compile time than the rest of the workspace. A separate crate still builds under `cargo build --workspace` and in CI unless it sits behind a feature that is off by default.
  - DuckDB, Polars and Spark all read JSON Lines directly.
  - JSON Lines and CSV can be written with the existing hand-written writers and need no new dependencies.
- **The provenance record can't be built as stated.**
  - Intake doesn't store receipts or log indexes.
  - A file can't contain its own digest.
  - "Provenance" already means something else in `crates/contexts/publishing`.
- **The codebook duplicates the data contract,** which already holds every item and code label in each language.
- **The name "export" is taken.** `fieldseal export` already builds, inspects, verifies and repairs the sealed delivery file.
- **The web results page relies on an unstated key boundary.** `crates/apps/web/src/intake.rs` serves decrypted rows from the same process as the collector stand-in, guarded only by `FIELDSEAL_WEB_DEMO_AUTHORITY`. Which custody class (ADR 0038) and process holds the record key has to be decided before the page is built, not after.

## Goals vs. Non-Goals

* **In-Scope Goals:**
  * One folder per survey, by convention:
    * one instrument
    * its layouts
    * its `.po` catalogues

    It must leave every published artefact's address and layout fingerprint unchanged.
  * `.po` as the only translation format. Layout translations get keys that don't depend on position. Missing, orphaned and stale translations are reported with file and line.
  * Survey errors reported with real line and column numbers.
  * A schema for editor autocomplete and errors, tested against the decoder.
  * A `fieldseal new survey` scaffold that creates:
    * a schema header pointing at a local file, because authors may work offline
    * pinned answer codes
    * `.po` stubs
    * a short README mapping each file to its role
    * a roster stub outside the publishable folder
  * A `fieldseal survey check <dir>` command that runs validation, lint, layout checks and the translation report together.
  * One resolver for surveys, layouts and rosters, shared by the CLI, the web app and tests.
  * A tutorial, "Write and publish your first survey", plus a reference table of which file each setting belongs in.
  * A `just web` recipe for an edit-and-reload loop with no container rebuild.
  * Measured baselines for `just up` (stage by stage) and for CI on a warm cache, with targets set from them.
  * An eight-step guided demo built on the existing web pages. Each step shows a confirmation the audience can trace: the artefact address, the log index, a receipt or correlation id. A banner says the web app stands in for native apps.
  * A results reader on the authority side, both as a web page labelled as using development keys and through the `fieldseal` CLI.
  * Saving results as JSON Lines and CSV from one shared, versioned table. Each export comes with:
    * the data contract
    * a codebook view generated from it
    * a manifest listing each file's SHA-256
  * The migration of the existing examples to the folder and `msgctxt` model, in one commit with a release gate.
* **Out-of-Scope Non-Goals:**
  * Merging survey content across files without a defined rule for which file wins.
  * A guided survey-builder UI (deferred).
  * Native Android and iOS apps.
  * A native Parquet writer (deferred; DuckDB converts in the meantime).
  * A one-row-per-response (wide) export.
  * Running Keycloak outside a container.
  * Publishing or threshold signing from the browser.
  * Editing rosters in the browser.
  * Any change to the defaults for signing, sealing, attestation or policy.

## Key Decisions & Staging for Next Steps

**Decided:**

1. **Order of work:** survey authoring, then the development loop, then the demo. The reviewers note that `just web` takes about a day and gives a fast place to try authoring changes. It can be done early without changing the order.
2. **Translators are outside professionals,** so `.po` stays.
3. **The guided builder UI is deferred.**
4. **Security and privacy properties stay as they are.**
5. **Folder model: a folder by convention.** Each survey is a folder with `instrument.yaml`, `layouts/<window>.yaml` and `i18n/<lang>.po`. Every setting has one home file, and nothing changes in what gets signed. Merging by content is rejected.
6. **Translation keys: English text plus context, extending ADR 0040.** Each `msgid` is the English text. Each `msgctxt` is a stable key built to a fixed grammar, for example `instrument/<path>` and `layout/<window>/<id>`, and never a position. Layout parts get authored ids, which are dropped before signing. Loading a catalogue keeps the `msgid`, so a translation whose English has changed is reported as stale. Translators see the source sentence.
7. **Demo content: the bundled examples.** No live reload is needed for the demo.
8. **Results are read in two places.**
   - An authority-side page in the web app, labelled as using development keys.
   - The `fieldseal` CLI, opening the same export to show the format doesn't depend on the web app.
9. **Results must be saved in an open format.** Opening an export must show the survey's answers. It must also offer a save in an open, structured format that common tools can load and process straight away. That later feeds data ingestion into a lakehouse.
   - **Already exists:** intake writes `observations.csv` in long format (one row per answer), `findings.csv`, `losses.csv`, and a JSON data contract for each instrument (`crates/adapters/landing-files`).
   - **Gaps:**
     - multi-valued answers are joined with `|`, which tools can't split without being told
     - no typed columnar format such as Parquet
     - no one-row-per-response (wide) view
     - the CLI and the web reader don't write these files yet
   - **Privacy:** once results are saved in an open format, they are outside Fieldseal's protection. Subject ids are pseudonymous, and private roster fields are already stripped before sealing (DIS-013). The save step must say plainly that the file is unprotected.
10. **Open-format export details.**
    - **Formats:** JSON Lines and CSV. Parquet is deferred (see decision 11).
    - **Shape:** long format only (one row per answer). Analysts pivot it themselves.
    - **Types:**
      - In JSON Lines (and in Parquet, when it comes), the single variant `value` column (`crates/contexts/intake/src/data_contract.rs`) is replaced by typed columns: `value_number` (decimal), `value_text`, `value_date`, `value_bool` and `value_codes` (a list of strings). Only the column that matches the item's type is filled.
      - Multi-choice answers become a real list instead of a `|`-joined string.
      - CSV keeps `value` plus `value_type` for spreadsheet users.
    - **Metadata saved with every export:**
      - the instrument's JSON data contract
      - a codebook generated from the data contract as a readable view, not a second source
      - a manifest listing each file's SHA-256 and the instrument and layout addresses (the second review found the "provenance record" can't be built as first stated)
    - **One schema:** `LONG_COLUMNS` becomes the only long format, and `/intake/rows.csv` becomes a view of the same table. The spreadsheet formula guard becomes a CSV-only option, off by default and never applied to numeric columns.
    - **Versioning:** the export carries an `export_schema_version` (semver, where minor versions only add columns) in the manifest and the file metadata.
    - **Consistency:** read each format back into the shared table and compare rows sorted by `(record_id, item_path)`. Decimals must match exactly, and an empty value equals null.
    - **Command name:** a new verb such as `fieldseal intake results`, because `fieldseal export` already handles the sealed delivery file.

11. **Parquet is deferred.** JSON Lines and CSV ship first, written with the existing hand-written writers and no new dependencies. A documented DuckDB command converts them to Parquet for the lakehouse. A native Parquet writer comes later, and only behind a Cargo feature that is off by default.
12. **The open export is analysis-ready by default.**
    - Excluded rows are left out by default.
    - Free text and special-category items are kept. The data contract marks the special-category columns, and the save step states that the file contains them and is not protected.
    - Decoded roster ids are never included, so `subject` stays pseudonymous. The web CSV stops decoding `subject_id`.
    - A test checks that rows excluded for consent never appear.
13. **The folder and `msgctxt` migration is in scope, as one commit.** The existing examples, the loaders and a shared resolver all move together, under the release gate in staged item 2.
14. **The results reader runs in a separate authority process.**
    - It runs on its own port and holds a key of the development custody class.
    - The collector stand-in can't reach it, and a test enforces that.
    - `just web` starts both processes, so the demo still needs a single command.

**Staged for `/egm-draft`:**

1. **Write one design record, "Survey source tree and authoring toolchain".** It fully replaces ADR 0039 and takes over ADR 0040 §2–3. ADR 0040 §4–5 (deployments, rosters, policy) stays a separate decision.
2. **Release gate:** after migration, every example keeps the same `sha256:` address and layout fingerprint. Salts are pinned per name, only bound addresses are compared, and the expanded documents are diffed. Every hard-coded loader is listed and moved to the shared resolver in the same commit. That single commit can be reverted.
3. **Fix the groundwork before the scaffold:**
   - line and column numbers in errors
   - keep the English source text so stale translations are caught
   - stable layout keys
   - a warning when a declared language has no catalogue
   - one translation format
4. **Keep the native and container paths aligned.** Containers stay for acceptance and CI. A smoke test checks that the native and container paths give the same results.
5. **Demo safety tests:** the collector app cannot reach the results reader, and a device bundle never contains the intake key.
6. **Suggested order:**
   1. The design record (the `msgctxt` grammar and the export schema version).
   2. The migration together with its release gate, in one commit.
   3. The shared results table and its formats.
   4. The CLI reader.
   5. The custody decision.
   6. The web results page.
   7. The guided demo.

**Open questions for the user:**

1. **Decimal typing.** For `value_number`, one fixed decimal precision and scale with an overflow rule, or canonical decimal text plus a scale?
2. **Schema source.** Write the schema by hand with a test against the decoder, or build a new declarative schema module that both read?
3. **Targets.**
   - How many minutes for a first survey?
   - What target for `just up`?
   - What target for CI on a warm cache?
   - Who is the test newcomer, and on what machine?
4. **Deployments and policies.** Do they join the folder model, and does the scaffold create them?
5. **Rosters.** Should each roster name its survey or cohort explicitly?
6. **CI cache.** Is `FIELDSEAL_CACHIX` set in CI today?
7. **XLIFF.** Can the XLIFF translation pipeline be dropped?
