# Conformance Command

## Overview

`fieldseal conformance` runs the golden vectors and conformance suites that the specs' section 8 tables name, in-process, and reports the result per requirement ID (CLI-017). Work is split into units (a vector file, a table of checks, or one port-contract function against one adapter). Each unit runs in its own child `fieldseal` process, so a panicking contract (a release build aborts on panic) is reported as a failure of that unit's requirements, never as a missing result. The module also generates the port, contract and adapters matrix for [docs/reference/conformance.md](../../../../../docs/reference/conformance.md). It is part of the `fieldseal-cli` package; see [the CLI README](../../README.md).

## Interface

Entry point: `conformance_cmd::run(args: &[String]) -> ExitCode` (args start at `conformance`). Also exported: `entries()` and `Location` (from `contracts`), and `matrix() -> String`.

Subcommands:

- `fieldseal conformance run [--suite <name>[,<name>...]] [--adapter <name>] [--json]`: runs the selected units (all when no `--suite`).
- `fieldseal conformance list`: prints each suite name and description.
- `fieldseal conformance matrix`: prints the port, contract, adapters table as Markdown.

Flags (parsed strictly by `parse_flags`): `--json`; `--suite` (repeatable, comma lists, empty names refused); `--adapter` (once); `--child <unit-id>` (once; internal, runs one unit and prints its rows as a JSON array). `--flag=value` is accepted. Any other flag is a usage error (CLI-022). `--adapter` keeps units whose id ends in `:<adapter>` (case-insensitive).

Suites (`SUITES`): `wire`, `trust`, `publishing`, `transparency-log`, `distribution` (alias `dis-verify`), `ins-rules` (alias `ins-eval`), `policy`, `contracts`, `collection`, `delivery`, `deployment`, `instrument`, `intake`, `registration`, `col-lifecycle`, `col-session`, `col-crash`, `reg-token`, `reg-verify`, `reg-revoke`, `reg-attacks`, `dis-release`, `ins-checks`, `ins-locale`, `ins-codes`, `ins-nonresponse`, `ins-units`, `strict-schema`, `all`.

Source files:

- `mod.rs`: `Unit` (kinds `Vector`, `Table`, `Contract`), `units()`, `selected`, `execute`, `report`, `matrix`.
- `harness.rs`: `Status`, `CheckResult`, `Collector`, `Check`, `Chk`, `same`, `unhex`, `requirement_ids`, `label`.
- `contracts.rs`: `Entry`, `Location` (`Here(fn())` or `CargoTest(&str)`), `entries()`; port contracts against each in-process adapter.
- Vector suites: `wire.rs`, `trust.rs`, `publishing.rs`, `distribution.rs`, `rules.rs`.
- Scenario suites: `col.rs`, `reg.rs`, `reg_attacks.rs`, `dis_release.rs`.
- `strict_schema.rs`: the `strict-schema` suite (CLI-043, WIRE-213): the invalid-document corpus of `tests/schema-corpus/`, embedded with `include_str!`, through the authoring decoder and the kernel validator.
- Instrument suites: `ins.rs` with `ins_clinic.rs`, `ins_invalid.rs`, `ins_render.rs`, `ins_spec.rs` (checks copied from the instrument context's integration tests; support code is included by `#[path]` from `crates/contexts/instrument/tests/support/mod.rs`).

## Invariants

- Every unit runs in a separate `fieldseal conformance run --child <id>` process; a non-zero child exit or unreadable output becomes a failing check named `unit` carrying that unit's requirement IDs.
- A requirement passes only if every check naming it passes. Checks with no requirement ID that fail are reported separately as `unnumbered_failures`.
- The `run` exit code is 0 if no check failed, else 1 (`exit::FAILED`). Usage errors (bad flag, unknown suite) exit 2. An unknown `--child` unit, or no in-process unit matching the filter, exits 4 (`NOT_FOUND`); the latter lists adapters that run only under `cargo test`.
- Unknown suite names are refused, listing the known ones. `dis-verify` and `ins-eval` are accepted as aliases.
- Contracts whose adapter needs a fixture the binary lacks are `Location::CargoTest`; they are listed (JSON `external_contracts`) but not run here.
- Golden vectors are embedded with `include_str!`/`include_bytes!` from the kernel, trust, publishing, memory-adapter and examples trees; no network or runtime vector file is read.
- `matrix()` output begins with a "Generated ... do not edit by hand" comment; a test keeps the docs table current.

## Side Effects

- Spawns child processes: `std::env::current_exe()` with `conformance run --child <id>`, one per unit; captures their stdout and stderr.
- Stdout: per-requirement `PASS`/`FAIL` lines and a summary, or with `--json` one document (`command`, `suites`, `requirements`, `unnumbered_failures`, `external_contracts`, `summary`). `list` and `matrix` print to stdout. Errors go to stderr as `fieldseal: ...`. Child units print a JSON array to stdout and install a panic hook that prints `panic: <message>` to stderr.
- Files: contract units create and remove temporary directories named `fieldseal-conformance-<pid>-<n>` under `std::env::temp_dir()`. Nothing else is read or written.
- No network calls, no ports bound, no stdin.

## Verification

- `cargo test -p fieldseal-cli` (repo-wide: `just test`). Unit tests inside this directory are in `dis_release.rs`; the CLI-level test is `crates/apps/cli/tests/conformance.rs`.
- Run the suites: `fieldseal conformance run --suite all`.
- Reference: [docs/reference/conformance.md](../../../../../docs/reference/conformance.md), [CLI spec](../../../../../docs/reference/spec/cli.md).
