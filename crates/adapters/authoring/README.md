# fieldseal-adapters-authoring

## Overview

Strict decoding of YAML and JSON authoring documents into the canonical data model (`fieldseal_kernel::Value`; WIRE §5.1, see [wire-formats.md](../../../docs/reference/spec/wire-formats.md)). Instruments, layouts and policies are written by people in YAML or JSON and converted before they are validated, signed or hashed. The decoder is deliberately stricter than general-purpose libraries, because what a reviewer reads must be exactly what is signed. It also expands the compact authoring dialect (ADR 0040) into canonical documents.

Layer: adapter. Depends only on `fieldseal-kernel` (plus `saphyr-parser`, `thiserror`, `base64`, `unicode-normalization`). The schema of the compact dialect lives in the kernel (`fieldseal_kernel::schema`), not here: this crate decodes, records positions, calls the kernel's validator and expands. It implements no context port: it is a pure decoding utility used by tools and bindings.

## Interface

Crate root (`src/lib.rs`):

- `Format { Yaml, Json }` with `Format::from_extension(&str) -> Option<Format>` (`yaml`, `yml`, `json`, case-insensitive).
- `decode(bytes, format) -> Result<Value, AuthoringError>`: decode, check a compact document against the kernel's schema, then expand it. A schema failure is one error whose `findings` lists every problem.
- `decode_with_spans(text, format) -> Result<(Value, Spans), AuthoringError>`: decode (no check, no expansion) and record where each key and value is.
- `decode_raw(bytes, format)`: decode without compact expansion.
- `decode_path(path) -> Result<Value, AuthoringError>`: format from the extension; if the document is compact, merges gettext catalogues from `i18n/<file stem>/<lang>.po` beside it.
- `Spans` (`get`, `key`, `value`, `nearest`; by RFC 6901 JSON Pointer) and `Span { key, value }`.
- `Position { line, column }` and `LocatedFinding { file, pointer, position, kind, message }` (`kind` is one of the six WIRE-211 kinds, `fieldseal_kernel::schema::SchemaErrorKind`; `Display` prints `file:line:column: kind: pointer: message`).
- Re-exports `Value`, `AuthoringError { kind, line, column, message, position, findings }` and `ErrorKind` (non-exhaustive: `Encoding`, `Syntax`, `EmptyDocument`, `MultipleDocuments`, `DuplicateKey`, `NonStringKey`, `Null`, `Float`, `Number`, `AmbiguousBoolean`, `Alias`, `Anchor`, `MergeKey`, `Tag`, `Binary`, `NotNfc`, `TooDeep`, `Compact`).

`pub mod compact` (ADR 0040): `Catalogues` (`BTreeMap<lang, BTreeMap<path, text>>`), `is_compact(&Value)`, `expand(Value)`, `expand_with(Value, &Catalogues)` (the legacy catalogue form), `expand_with_entries(Value, &EntryCatalogues)` (the survey-folder form), `slug(&str)`, and `parse_po(&str)`, which stays as an adapter over `po::parse_po` and returns `msgctxt` to `msgstr` without the empty entries.

`pub mod po` (ADR 0041): `PoEntry { msgctxt, msgid, msgstr, line }`, `EntryCatalogues` (language, then `msgctxt`), `parse_po(&str)` (keeps an empty `msgstr` as missing, rejects a repeated `msgctxt` with the line of the second one, accepts any `msgctxt`) and `check_context(&str) -> Result<ContextKind, String>`, the `msgctxt` grammar: `instrument/<path>` or `layout/<window>/<authored id>`. Only the resolver calls `check_context`.

`pub mod survey` (ADR 0041), the only code that knows the survey folder shape (`instrument.yaml`, `layouts/<window>.yaml`, `i18n/<lang>.po`, `README.md`):

- `SurveyTree::open(root)` lists the survey folders (a name that begins with a dot is not one); `survey(name) -> SurveyRef` lists a folder's files and the stray ones; `SurveyRef::load() -> LoadedSurvey { instrument, layouts, translation_report, warnings }` decodes and expands every document with the folder's catalogues and applies the folder rules. `LoadedSurvey::strict()` turns the warnings and findings into errors.
- `ResolveError { file, pointer, line, column, kind, message }` with `ResolveKind` `io`, `no-instrument`, `name-mismatch`, `window-mismatch`, `missing-layout-id`, `duplicate-layout-id`, `stray-file`, `po-syntax`, `po-duplicate-context`, `po-bad-context`, the six schema kinds passed through, `decode` for a syntax error, and `translation` under `strict()`.
- `Finding { kind, language, file, line, msgctxt, old_msgid, new_text }` with `FindingKind` `Missing`, `Orphaned`, `Stale` and `NoCatalogue`. A stale entry (its `msgid` is not the current English text) is treated as missing at expansion: the English text is used and the stale `msgstr` is not applied. The report is built once per survey over the instrument and layout texts together.
- `RosterSet::open(dir)` reads the roster files directly in `dir` (no recursion) for their `cohort` and `version`, never for their file name; `latest(cohort)` and `cohorts()`.
- `legacy_translation_report` reports on the catalogues of the unmigrated `examples/` tree. It goes with them in Phase 4.

Layout steps, cards and tabs may carry an `id:` (the schema key is optional until Phase 4; the resolver requires it on steps and cards). An id keys the title as `layout/<window>/<id>` and never reaches the expanded document.

Private modules (besides `po` and `survey` above): `yaml` (event-based decoder over `saphyr-parser`), `json` (hand-written RFC 8259 parser), `scalar` (number, NFC and depth rules), `spans`, `error`. Both decoders track the JSON Pointer of the node they read.

## Invariants

- No duplicate keys; map keys are strings; no null (`null`, `~`, empty YAML value).
- No floats: fractions become `Decimal` keeping every written digit (`1.10` stays `1.10`); `1e3`, `.inf`, `.nan` are errors. Integers are limited to -2^64 ..= 2^64-1.
- Text must already be NFC (WIRE-004); non-NFC text is rejected, not normalised.
- Nesting is limited to 128 levels. Every error carries a 1-based line and column.
- A leading UTF-8 BOM is ignored; invalid UTF-8 is `ErrorKind::Encoding`. The format is chosen by the caller and never sniffed.
- YAML only: YAML 1.2; `yes/no/on/off/y/n` are text; `True/TRUE/False/FALSE` are errors; non-canonical number-like scalars (`007`, `0x1F`, `+1`, `1_000`, `.5`, `5.`) are errors; quoted and block scalars are text; no anchors, aliases, merge keys or tags except `!!binary` (base64 to `Value::Bytes`); one document per file.
- Compact expansion is deterministic and closed: each authoring key is declared once, in the kernel's schema table (WIRE-209), and `compact.rs` reads keys only through `schema::Reader`. An unknown, missing or ill-typed key is a finding (`ErrorKind::Compact`) with a JSON Pointer; nothing is parsed out of free text. Ordered content is a sequence of single-key maps. The rules the table cannot say (a name that resolves to nothing, the number of operands) stay in `compact.rs` and report their path.
- Errors carry real positions: every error from text has `position: Some(..)` equal to `line` and `column`. A repeated key (`DuplicateKey`) and a refused value (`CoercionRefused`: null, float, bad number, ambiguous boolean) carry their one finding. `findings` is otherwise empty except for a schema failure, sorted in file order, where `line`, `column` and `message` are the first finding's.

## Side Effects

- `decode` and `decode_raw` are pure.
- `decode_path` reads the document file and, for a compact document, lists and reads `*.po` files in `<dir>/i18n/<stem>/` (sorted by name). `SurveyTree`, `SurveyRef::load` and `RosterSet` list directories and read the files of a survey folder or roster directory; they write nothing and print nothing. Unreadable files are reported as `ErrorKind::Encoding` with line 0, column 0 and `position: None`; the message names the file. No writes, network or clock.

## Verification

- Run: `cargo test -p fieldseal-adapters-authoring` (repo-wide: `just test`). `tests/schema_differential.rs` checks the decoder and the generated JSON Schema (a dev-dependency, `jsonschema`) accept and reject the same documents: every example, mutations of every declared key, and the invalid-document corpus `tests/schema-corpus/` (WIRE-213). `tests/error_positions.rs` checks the reported line and column against `tests/fixtures/errors/`. `tests/survey_resolver.rs`, `tests/translation_report.rs` and `tests/po_entries.rs` cover the resolver, the report and the catalogue entries on `tests/fixtures/surveys/` and `tests/fixtures/rosters/`; `ins_260_the_example_catalogues_have_no_stale_entries` runs the report over the current examples. The `strict-schema` conformance suite runs the corpus too: `fieldseal conformance run --suite strict-schema`.
