# bindings

## Overview

Foreign-language bindings over the Rust core. Bindings convert types and errors only and hold no business logic. They may depend on the kernel, contexts and adapters ([ADR 0028](../../docs/explanation/adr/0028-clean-architecture.md)). Build outputs are produced by [`tools/build.sh`](../../tools/README.md) and the Nix flake.

## Subdirectories & Boundaries

- python: [./python/README.md](./python/README.md) - `fieldseal-py`: a PyO3 abi3 module `fieldseal` for authority-side tools (content addresses, key ids, fingerprints, canonical CBOR).
- uniffi: [./uniffi/README.md](./uniffi/README.md) - `fieldseal-uniffi`: UniFFI scaffolding for the Kotlin/Swift runtimes, plus the `uniffi-bindgen` binary.
- wasm: [./wasm/README.md](./wasm/README.md) - `fieldseal-wasm`: wasm-bindgen exports of the instrument `Workbench` and the browser `Device`.
