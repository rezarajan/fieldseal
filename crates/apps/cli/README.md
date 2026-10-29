# Fieldseal CLI

## Overview

Package `fieldseal-cli` builds the `fieldseal` binary: the reference implementation of every Fieldseal operation (ADR [0006](../../../docs/explanation/adr/0006-cli-reference-implementation.md)). `src/main.rs` is also the composition root (ADR [0028](../../../docs/explanation/adr/0028-clean-architecture.md)): it reads configuration from the environment (ADR [0025](../../../docs/explanation/adr/0025-twelve-factor-deployments.md)), chooses adapters, and dispatches `fieldseal <noun> <verb> [arguments]` to per-family command modules that call the bounded contexts' use cases. The command tree is specified in [the CLI spec](../../../docs/reference/spec/cli.md). The `conformance` subcommand is documented in [src/conformance_cmd/README.md](./src/conformance_cmd/README.md).

## Interface

Binary: `fieldseal` (`src/main.rs`). `--version` prints `fieldseal <version>`; `--help` prints the usage text. `--json` is accepted by every command (one machine-readable document on stdout). Noun and verb are the first two non-flag arguments. A command's valued flags may be given once unless listed in `args::REPEATABLE` (`--lang --layout --reviewers --revocations --key --policy --build --instrument --log-origin --log --roster`); `--flag=value` and `--` are accepted; unknown flags are usage errors (CLI-022).

Subcommands and flags (beyond `--json`/`--help`):

- `instrument validate|lint|compile <file>`; `instrument hash <file> [--salt]`; `instrument preview <file> [--layout --lang --window --answers --roster --format -o/--output --salt]` (`commands.rs`).
- `layout validate <file> [--instrument --salt]`; `layout lint <file> [--instrument --policy --salt]`; `layout compile <file> [--instrument --lang --window --salt]`.
- `instrument i18n extract [--lang --out/-o]`, `instrument i18n merge [--out/-o]`; `localisation validate [--reference]` (`i18n_cmd.rs`).
- `new survey <name> [--lang --root]` (`new_cmd.rs`); `survey check <dir> [--roster] [--strict]` and `survey list [--root]` (`survey_cmd.rs`); `schema export --kind survey|layout [--out --version]` and `schema check <file>` (`schema_cmd.rs`). `survey check` and `roster_check::compare_roster` (shared with `roster check` later) read the roster fields the instrument reads through `fieldseal_distribution::domain::collect_roster_fields` (DIS-013). `--strict` makes errors of resolver, validation and translation warnings, not of lint findings.
- `policy validate|diff|effective`; `policy evaluate [--decision --input]` (`policy_cmd.rs`).
- `trust root-init|issue|bundle|revoke|show|verify` (`trust_cmd.rs`). Shared: `--custody --at --caller`. `root-init`: `--ceremony --out`. `issue`: `--purpose --validity --period --period-start --period-end --retention --csr --out --root --serial`. `bundle`: `--roots --pins --attestation-roots --runtime-builds --out --name --version --publishers --log-origin --log --revocations --previous`. `revoke`: `--reason --effective --out --root --key-wide`. `show`: `--trust-bundle --custody`. `verify`: `--trust-bundle --purpose --revocations --at`.
- `keys generate [--purpose --custody --csr --caller --algorithm --out --state]`; `keys roll [--out --new-out --sign-key --state]` (`keys_cmd.rs`).
- `artefact provenance|sign|verify|publish|withdraw` and `log prove|append|key|verify` (`artefact_cmd.rs`, `log_cmd.rs`). Shared (`COMMON`): `--custody --trust-bundle --policy --state --log-origin --at --key --out/-o --caller`. Extras: `provenance` `--source --source-uri --reviewers --author --builder --definition --salt --instrument`; `verify` `--revocations`; `publish` `--revocations --time-token`; `withdraw` `--reason --draft`. `log key [--key-file] [--generate]`; `log verify [--trust-bundle --known-tree-head --state --log-origin --at]`.
- `registry list|show [--dir --trust-bundle --log-url]`; `registry fetch [... --out/-o --document]` (`registry_cmd.rs`).
- `receipt issue [--tenancy --last-seq --journal-hash --of --custody --key --at --out/-o --qr --caller]`; `receipt verify [--trust-bundle --tenancy --journal-hash]` (`receipt_cmd.rs`).
- `registration token|request|inspect|approve` (`registration_cmd.rs`): shared `--custody --trust-bundle --policy --state --at --factory-url --record-key --out/-o --caller`; `token` `--account --batch --route --qr`; `request` `--token --label --device-dir`; `approve` `--words` and switch `--allow-unattested`. Network verbs `registration submit|status|wait` (`registration_remote.rs`): `--factory-url --device-dir --trust-bundle --at`, `wait` also `--timeout --interval`.
- `bundle build|verify|inspect|open` (`bundle_cmd.rs`): `build` flags `--instrument --layout --roster --out-dir --seed --time --generation --salt --device --device-dir --tenancy --trust-bundle --custody --publication --tenancy-dir --state --issued-dir --policy-publication` and switches `--practice --allow-unattested --stack`; `verify` `--trust --device-file --now`, `--stack`; `inspect` `--trust --now`; `open` `--key --trust --tenancy --now --out`, `--reveal`.
- `device simulate (--script <file> | --scenario <name>) [--review] [--export <file> [--no-parity]] [--upload]`; built-in scenarios `household-water-access` (alias `capture`), `school-meals-baseline` (alias `consent`), `clear` (alias `lifecycle`). `device capture --device-dir --trust-bundle --bundle --script --export [--no-parity]` (`device.rs`, `device/stack.rs`). `device export [--device-dir --trust-bundle --out/-o --at] [--no-parity]` (`device_export.rs`).
- `export build (--scenario <name> | --script <file>) -o <file> [--no-parity] [--upload]`; `export inspect <file>`; `export verify <file> [--seed]`; `export repair <file> -o <out> [--seed]` (`export_cmd.rs`). `export upload <file> [--to --trust-bundle --receipts-dir]` (`upload_cmd.rs`).
- `intake contract <instrument> [--salt --out]`; `intake run <export>... [--instrument --device --seed --now --out --reveal]`; `intake replay <export>`; `intake practice --out <file> [--device --seed --no-parity]`; `intake results --landing <dir> --published <dir> --export-key <file> --trust-bundle <file> --out <dir> [--format jsonl,csv] [--json]` writes the results export of a landing directory (INT-085 to INT-088, CLI-048; `intake_cmd.rs`).
- `deployment validate <manifest> [--policy]`; `deployment render <manifest> --environment [--out]`; `deployment release <manifest> --publication --build ... (--signing-key-file | --practice) [--environment --out]`; `docs build <manifest> --environment --release -o <dir> [--instrument --policy --trust-bundle]` (`deployment_cmd.rs`).
- `adapters`: lists context, port and adapter bindings.
- `conformance run|list|matrix`: see [src/conformance_cmd/README.md](./src/conformance_cmd/README.md).

Environment (`composition::KNOWN_ENV`; a variable set but empty is refused with exit 3, CLI-030): `FIELDSEAL_ADAPTERS` (`memory` default, or `files`), `FIELDSEAL_LOG_FORMAT` (`json` default, or `text`; stderr events), `FIELDSEAL_STATE_DIR`, `FIELDSEAL_LOG_ORIGIN`, `FIELDSEAL_SOURCE_URI`, `FIELDSEAL_BUILDER`, `FIELDSEAL_NOW` (default time for `--at`), `FIELDSEAL_POLICY` (comma-separated, fallback for `--policy`), `FIELDSEAL_SIGNER`, `FIELDSEAL_TRUST_BUNDLE`, `FIELDSEAL_FACTORY_URL` (fallback for `--factory-url`), `FIELDSEAL_TRANSLOG_URL`, `FIELDSEAL_REKOR_URL`. Also read outside `KNOWN_ENV`: `FIELDSEAL_INTAKE_URL` (fallback for `export upload --to`) and `FIELDSEAL_REGISTRY_DIR` (fallback for `registry --dir`, default `published`). Flags take precedence over environment (`support::setting`).

Key modules: `args` (parser), `commands` (`Ctx`, instrument and layout), `composition` (`Config`, `AdapterSet`, `AuthoringTools`, bindings), `outcome` (`Outcome`, `exit`), `support` (`run_command`, `setting`, `now`), `messages` (`msg` catalogue), `clients` (`FactoryClient`, `UploadClient`, `connect_factory`, `connect_upload`), `stores` (`FileLog`, `FileRegistry`, `remote_translog`, `translog_at`), `transport` (`NullTransport`), `custody` (`DirCustody`, `OsRandom`), `device_dir`/`device_keys`/`device_delivery`, `bundle_stack`, `artefact_kinds`, `new_cmd`, `survey_cmd`, `schema_cmd`, `roster_check`.

## Invariants

- Exit codes (CLI-005): 0 OK, 1 verification or validation failed, 2 usage, 3 configuration or adapter, 4 not found, 5 policy denied, 6 internal. `Outcome::fail` keeps the highest-priority failure: a validation failure (1) never hides 2, 3, 4 or 6.
- Results go to stdout; structured events and errors go to stderr. With `--json` stdout is one document with `command`, `ok`, `exitCode`, `findings`.
- Repeating a non-repeatable valued flag, passing an unknown flag, or a flag-like value is a usage error (exit 2); a flag is never silently overridden.
- Flags win over `FIELDSEAL_*` environment variables; an empty `KNOWN_ENV` variable or unknown `FIELDSEAL_ADAPTERS`/`FIELDSEAL_LOG_FORMAT` value stops the process with exit 3.
- `grpc://` and `grpcs://` addresses are recognised and refused (exit 3) before anything is read; only `http://` and `https://` are built in (CLI-023).
- Uploaded receipts are stored only after verifying against the trust bundle, whatever the route (DEL-064). Exports are uploaded without parity (DEL-016).
- Roster contents and item values never reach stdout or stderr; only counts and IDs (CLI-008). `intake run --reveal` prints decrypted data and warns on stderr.
- Software devices (`device simulate`, `device capture`, `device export`) are unattested (CLI-007).
- If the OS random generator (`/dev/urandom`) cannot be read, the process exits 3 rather than use predictable bytes.
- Local logs use `NullTransport`; the transmission is still built but sent nowhere (ADR 0030).

## Side Effects

- Files read: authoring documents (YAML/JSON, plus `i18n/<lang>.po` for compact surveys), trust bundles, policy layers, custody and device directories, export files, scenarios, manifests, `/dev/urandom`. Files written: `--out`/`-o` outputs, a new survey folder, the schemas in `<root>/.fieldseal/` and a roster stub (`new survey`), key and custody material (`DirCustody`), device directories, receipts (`--receipts-dir`), bundles (`--out-dir`), rendered deployment and docs output, and, with `FIELDSEAL_ADAPTERS=files`, the local log and registry under `FIELDSEAL_STATE_DIR`. `--version` and `--help` touch nothing.
- Network (HTTP/HTTPS only): factory client (`registration submit|status|wait`, certificate fetch) via `fieldseal-adapters-factory-http`; upload endpoint (`export upload`, `device capture` upload) via `fieldseal-adapters-upload-http` (cleartext allowed because the operator chose the address); transparency log via `FIELDSEAL_TRANSLOG_URL` (self-hosted) or `FIELDSEAL_REKOR_URL` (Rekor, takes precedence); `registry --log-url`. Without these the local file log is used.
- Child processes: `conformance run` re-invokes the current executable per unit.
- Ports bound: none. Stdin: not read. Stdout, stderr and exit codes as under Invariants.

## Verification

- `cargo test -p fieldseal-cli` (repo-wide: `just test`; `just check` for the full gate). Integration tests are in `crates/apps/cli/tests/` (`conformance.rs`, `demo_pipeline.rs`, `survey_cli.rs`, with `fixtures/` and `golden/`); `tiny_http` is a dev-dependency for local HTTP stubs.
- Conformance suites: `fieldseal conformance run --suite all`.
- Docs: [CLI spec](../../../docs/reference/spec/cli.md), [conformance reference](../../../docs/reference/conformance.md), [build and check](../../../docs/how-to/build-and-check.md).
