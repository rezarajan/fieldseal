# fieldseal-adapters-landing-files

## Overview

A file-based `DataPlatform` for Intake: the generic long format as CSV, findings and losses as CSV, and each instrument's data contract as JSON. CSV was chosen over Parquet for this first adapter because it needs no dependency beyond the standard library, opens in every analysis tool and diffs cleanly; a lakehouse adapter is a drop-in replacement behind the same port. Values are landed locale-free (ADR 0034, see [0034-internationalisation-and-localisation.md](../../../docs/explanation/adr/0034-internationalisation-and-localisation.md)).

Layer: adapter. Wraps `fieldseal_adapters_memory::intake::MemoryDataPlatform` for state.

## Interface

- `FileDataPlatform`
  - `new(dir) -> Result<Self, DataPlatformError>`: creates `dir` and `dir/contracts`.
  - `dir() -> &Path`.
  - `write_contract(&DataContract) -> Result<PathBuf, DataPlatformError>`: writes `contracts/<instrument hex>.json` (INT-056).
  - Implements `fieldseal_intake::ports::DataPlatform`: `land`, `exclude`, `reinstate` (each rewrites the files), and read methods `observations`, `envelopes`, `evidence`, `consent_case`, `consent_cases`, `losses`, `findings` (delegated to the in-memory platform).
- Free functions: `csv_field(&str) -> String` (RFC 4180 quoting), `json(&Value) -> String` (RFC 8259, keys in order, bytes as lowercase hex), `long_header() -> String` (names from `LONG_COLUMNS`, INT-071, INS-072), `long_row(&LandedObservation) -> String`.

## Invariants

- State lives in memory for the life of the process; after every `land`, `exclude` or `reinstate` the files are rewritten in full from it. The files therefore show the full current state, exclusions appear as flags (`excluded` columns), and nothing is deleted.
- State is not reloaded from disk on start: a new `FileDataPlatform` begins empty.
- `observations.csv` has the `LONG_COLUMNS` header and one row per landed observation of every instrument seen in a batch; fields are CSV-quoted only when they contain `,`, `"`, CR or LF.
- `findings.csv` header: `submission,kind,rule,detail`; `losses.csv` header: `tenancy,from_seq,through_seq,reason`.
- Multi-valued fields (language, codes, flags) are joined with `|`; layout is `default` or the hex of the published layout address.

## Side Effects

- Filesystem writes in the target directory: `observations.csv`, `findings.csv`, `losses.csv`, `contracts/<instrument>.json`. Files are overwritten, not appended.
- Mutex-guarded in-memory state. No network, clock or crypto.
- I/O failures surface as `DataPlatformError::Backend`.

## Verification

- Run: `cargo test -p fieldseal-adapters-landing-files` (repo-wide: `just test`)
