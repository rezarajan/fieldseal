# fieldseal-adapters-landing-files

## Overview

A file-based `DataPlatform` for Intake: the generic long format as CSV, findings and losses as CSV, and each instrument's data contract as JSON. Its `export` module turns a landing directory into the results export: a versioned long table as JSON Lines and CSV, free text apart, data contracts, a codebook and a manifest. CSV was chosen over Parquet for this first adapter because it needs no dependency beyond the standard library, opens in every analysis tool and diffs cleanly; a lakehouse adapter is a drop-in replacement behind the same port. Values are landed locale-free (ADR 0034, see [0034-internationalisation-and-localisation.md](../../../docs/explanation/adr/0034-internationalisation-and-localisation.md)).

Layer: adapter. Wraps `fieldseal_adapters_memory::intake::MemoryDataPlatform` for state, writes through `fieldseal_adapters_file::atomic::write_atomic`, and reads published instruments through the publishing, trust, policy and distribution contexts.

## Interface

- `FileDataPlatform`
  - `new(dir) -> Result<Self, DataPlatformError>`: creates `dir` and `dir/contracts`.
  - `open_read_only(dir) -> Result<Self, DataPlatformError>`: opens a landing directory as a snapshot. It reads `observations.csv` once into memory (header, types and enumerations are checked strictly, INT-072) and answers `instruments` and `observations`; the write methods and the reads of envelopes, evidence, consent, losses and findings are errors. Nothing is written and the directory is not created.
  - `landing_mark() -> Result<u64, DataPlatformError>`: the number of observation rows held, excluded rows included.
  - `dir() -> &Path`.
  - `write_contract(&DataContract) -> Result<PathBuf, DataPlatformError>`: writes `contracts/<instrument hex>.json` (INT-056).
  - Implements `fieldseal_intake::ports::DataPlatform`: `land`, `exclude`, `reinstate` (each rewrites the files), and read methods `instruments` (INT-091), `observations`, `envelopes`, `evidence`, `consent_case`, `consent_cases`, `losses`, `findings` (delegated to the in-memory platform).
- `export` (INT-085 to INT-088):
  - `ExportTable::from_observations(rows, contracts, mapper)` leaves out excluded rows (and counts them), fills the typed columns, maps subjects, sets free text apart and puts the rows in a total order; `with_publications(instruments, layouts)` adds the addresses the manifest names. `write_export(&table, &ExportOptions, out_dir) -> ExportResult` writes `results.jsonl`, `results.csv`, `free_text.jsonl`, `free_text.csv` (the chosen `Format`s), `codebook.csv`, `contracts/<fingerprint hex>.json` and, last, `manifest.json`, each through the atomic-write helper, and returns the file list and the manifest's SHA-256.
  - `writers`: `csv_field`, `json`, `long_header`, `long_row` (unchanged bytes for `observations.csv`), `guard`, `jsonl_columns`. `codebook`: `codebook(&DataContract)` and the free-text writers. `manifest`: the manifest bytes.
  - `pseudonym`: `SubjectMapper`, `KeyedSubject` (`lower_hex(HMAC-SHA-256(key, subject))`), `IdentitySubject`, `ExportKey::load(dir)` (`<dir>/export.key`) and `ExportKey::load_file(path)`, `key_id`. A key is 32 raw bytes; a file that is absent, of another length or (on Unix) wider than mode 0600 is refused, and nothing here creates a key.
  - `render_export(&table, &options)` builds every file in memory (`RenderedExport`); `write_export` writes exactly those bytes, and the results reader serves them.
  - `reader`: `Published::read(dir, trust_bundle, publishing_policy)` keeps the verified instruments and layouts of a published directory; `export_table(&snapshot, &published, &mapper)` builds the table. An instrument with landed rows and no verified publication is an error.
- Free functions: `csv_field(&str) -> String` (RFC 4180 quoting), `json(&Value) -> String` (RFC 8259, keys in order, bytes as lowercase hex), `long_header() -> String` (names from `LONG_COLUMNS`, INT-071, INS-072), `long_row(&LandedObservation) -> String`.

## Invariants

- State lives in memory for the life of the process; after every `land`, `exclude` or `reinstate` the files are rewritten in full from it. The files therefore show the full current state, exclusions appear as flags (`excluded` columns), and nothing is deleted.
- State is not reloaded from disk on start: a new `FileDataPlatform` begins empty. A reader that needs the landed rows uses `open_read_only`, which never writes.
- Every file is written with `write_atomic` (a temporary file in the same directory, `fsync`, rename), so a reader never sees a torn file.
- A results export is built from one snapshot, so all its files agree; the manifest records the snapshot's row count as `landing_mark`. The CLI and the results reader call the same functions, so their files are identical byte for byte.
- The results export never contains an excluded row, a readable roster id or the key; free text is in the free-text files only; CSV text cells that start with `=`, `+`, `-`, `@`, a tab or a carriage return get a `'` prefix and numeric values never do.
- `observations.csv` has the `LONG_COLUMNS` header and one row per landed observation of every instrument seen in a batch; fields are CSV-quoted only when they contain `,`, `"`, CR or LF.
- `findings.csv` header: `submission,kind,rule,detail`; `losses.csv` header: `tenancy,from_seq,through_seq,reason`.
- Multi-valued fields (language, codes, flags) are joined with `|`; layout is `default` or the hex of the published layout address.

## Side Effects

- Filesystem writes in the target directory: `observations.csv`, `findings.csv`, `losses.csv`, `contracts/<instrument>.json`. Files are overwritten, not appended.
- Mutex-guarded in-memory state. No network, clock or crypto.
- I/O failures surface as `DataPlatformError::Backend`.

## Verification

- Run: `cargo test -p fieldseal-adapters-landing-files` (repo-wide: `just test`). `export_readback` (read-back equivalence, guard, order, manifest), `export_privacy` (excluded rows, pseudonyms, key file rules), `snapshot` (read-only snapshot, strict reader, the `DataPlatform` contract) and `duckdb_recipe` (reports `skipped: duckdb not on PATH` when the tool is absent).
