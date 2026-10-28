# fieldseal-adapters-authoring

## Overview

Strict decoding of YAML and JSON authoring documents into the canonical data model (`fieldseal_kernel::Value`; WIRE §5.1, see [wire-formats.md](../../../docs/reference/spec/wire-formats.md)). Instruments, layouts and policies are written by people in YAML or JSON and converted before they are validated, signed or hashed. The decoder is deliberately stricter than general-purpose libraries, because what a reviewer reads must be exactly what is signed. It also expands the compact authoring dialect (ADR 0040) into canonical documents.

Layer: adapter. Depends only on `fieldseal-kernel` (plus `saphyr-parser`, `thiserror`). It implements no context port: it is a pure decoding utility used by tools and bindings.

## Interface

Crate root (`src/lib.rs`):

- `Format { Yaml, Json }` with `Format::from_extension(&str) -> Option<Format>` (`yaml`, `yml`, `json`, case-insensitive).
- `decode(bytes, format) -> Result<Value, AuthoringError>`: decode, then expand a compact document.
- `decode_raw(bytes, format)`: decode without compact expansion.
- `decode_path(path) -> Result<Value, AuthoringError>`: format from the extension; if the document is compact, merges gettext catalogues from `i18n/<file stem>/<lang>.po` beside it.
- Re-exports `Value`, `AuthoringError { kind, line, column, message }` and `ErrorKind` (non-exhaustive: `Encoding`, `Syntax`, `EmptyDocument`, `MultipleDocuments`, `DuplicateKey`, `NonStringKey`, `Null`, `Float`, `Number`, `AmbiguousBoolean`, `Alias`, `Anchor`, `MergeKey`, `Tag`, `Binary`, `NotNfc`, `TooDeep`, `Compact`).

`pub mod compact` (ADR 0040): `Catalogues` (`BTreeMap<lang, BTreeMap<path, text>>`), `is_compact(&Value)`, `expand(Value)`, `expand_with(Value, &Catalogues)`, `slug(&str)`, `parse_po(&str)`.

Private modules: `yaml` (event-based decoder over `saphyr-parser`), `json` (hand-written RFC 8259 parser), `scalar` (number, NFC and depth rules), `error`.

## Invariants

- No duplicate keys; map keys are strings; no null (`null`, `~`, empty YAML value).
- No floats: fractions become `Decimal` keeping every written digit (`1.10` stays `1.10`); `1e3`, `.inf`, `.nan` are errors. Integers are limited to -2^64 ..= 2^64-1.
- Text must already be NFC (WIRE-004); non-NFC text is rejected, not normalised.
- Nesting is limited to 128 levels. Every error carries a 1-based line and column.
- A leading UTF-8 BOM is ignored; invalid UTF-8 is `ErrorKind::Encoding`. The format is chosen by the caller and never sniffed.
- YAML only: YAML 1.2; `yes/no/on/off/y/n` are text; `True/TRUE/False/FALSE` are errors; non-canonical number-like scalars (`007`, `0x1F`, `+1`, `1_000`, `.5`, `5.`) are errors; quoted and block scalars are text; no anchors, aliases, merge keys or tags except `!!binary` (base64 to `Value::Bytes`); one document per file.
- Compact expansion is deterministic and closed: unknown or ill-typed keys are errors (`ErrorKind::Compact`) naming their path; nothing is parsed out of free text. Ordered content is a sequence of single-key maps.

## Side Effects

- `decode` and `decode_raw` are pure.
- `decode_path` reads the document file and, for a compact document, lists and reads `*.po` files in `<dir>/i18n/<stem>/` (sorted by name). Unreadable files are reported as `ErrorKind::Encoding` with line 0, column 0. No writes, network or clock.

## Verification

- Run: `cargo test -p fieldseal-adapters-authoring` (repo-wide: `just test`)
