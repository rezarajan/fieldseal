# fieldseal-uniffi (UniFFI bindings)

## Overview

UniFFI bindings of the Fieldseal core for platform runtimes (Kotlin, Swift). An interface adapter
(ADR 0028): it only converts types and errors; rules live in the context crates. It currently depends on
[fieldseal-kernel](../../kernel/README.md), [fieldseal-instrument](../../contexts/instrument/README.md) and `thiserror`. Cargo package `fieldseal-uniffi`; library
name `fieldseal_uniffi` (`cdylib` and `lib`).

## Interface

- `core_version() -> String` (`#[uniffi::export]`): the version of the core the library was built from.
- `runtime_profile() -> RuntimeProfile { instrument_schema: String, catalogue_reference: Option<String> }`
  (`#[uniffi::export]`, with `RuntimeProfile` a `uniffi::Record`): the instrument-schema version the core
  implements (`1.0.0`) and no catalogue version. A native app puts these into the `schema` and `catalogue`
  fields of the registration request it builds (WIRE-130), adding its own catalogue version when its build
  has one. Use cases are to be added as contexts are implemented.
- `src/bin/uniffi-bindgen.rs`: the `uniffi-bindgen` binary, which calls `uniffi::uniffi_bindgen_main()`
  to generate foreign-language sources from the built library.

## Invariants

- Scaffolding is set up with `uniffi::setup_scaffolding!()` in `src/lib.rs`; exported items must go
  through UniFFI attributes.
- No business logic belongs here.

## Side Effects

None at runtime. Build outputs (from `tools/build.sh`, when the Android host tools are present): native
libraries for `arm64-v8a` and `x86_64` in `dist/android/jniLibs`, and Kotlin bindings generated with
`cargo run --release --locked -p fieldseal-uniffi --bin uniffi-bindgen -- generate --library
target/release/libfieldseal_uniffi.so --language kotlin --no-format --out-dir dist/android/kotlin`.

## Verification

- Run: `cargo test -p fieldseal-uniffi`
