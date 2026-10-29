# crates

## Overview

Every crate in the Cargo workspace, grouped by architectural layer. Source dependencies point inward only, as declared in [`architecture.toml`](../architecture.toml) and checked by `tools/check-architecture.py`:

```text
kernel  <-  contexts  <-  adapters  <-  bindings, apps
```

## Subdirectories & Boundaries

- kernel: [./kernel/README.md](./kernel/README.md) - `fieldseal-kernel`, the pure format core: deterministic CBOR, ids and digests, domain-tagged P-256 signatures, HPKE seals, journal frames and hash chains, export files with Reed-Solomon parity, PoP tokens, QR sequences and fingerprint words.
- contexts: [./contexts/README.md](./contexts/README.md) - The ten pure bounded contexts and the driven ports they declare.
- adapters: [./adapters/README.md](./adapters/README.md) - Port implementations and driving adapters; all real I/O lives here.
- bindings: [./bindings/README.md](./bindings/README.md) - Python, UniFFI (Kotlin/Swift) and WebAssembly bindings.
- apps: [./apps/README.md](./apps/README.md) - The `fieldseal` CLI, factory, intake app, transparency log and web app binaries, the development identity provider, and the e2e and security test harnesses.
