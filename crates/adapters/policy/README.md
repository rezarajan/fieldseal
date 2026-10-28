# fieldseal-adapters-policy

## Overview

Adapters for the Policy context's driven ports ([policy spec](../../../docs/reference/spec/policy.md) section 4): sources of published policy layers and a durable decision log.

## Interface

| Symbol | File | Port | Role |
|---|---|---|---|
| `RegistryPolicySource<'a>` | `src/registry.rs` | `PolicySource` | Reads the named policies from an `ArtefactRegistry`. `new(registry, trust, publishing, names)`, `with_provenance_check(ProvenanceCheck)` (default `Full`). |
| `BundlePolicySource` | `src/bundle.rs` | `PolicySource` | Serves the policy layers of one verified bundle. `new(layers)`, `from_verified(&VerifiedBundle)`. |
| `FileDecisionLog` | `src/file_log.rs` | `DecisionLog` | Append-only, hash-chained decision log in one file. `open(path)`, `verify()`, `head()`, `verify_against(&Head)`; `append`, `read`, `len` from the port. |
| `Head` | `src/file_log.rs` | | `{ len, hash }`: chain length and last hash (zeros when empty). |
| `IntegrityError` | `src/file_log.rs` | | `Unreadable`, `Malformed`, `WrongIndex`, `BrokenChain`, `BadHash` (each naming the first bad entry) and `HeadMismatch`. |

`src/lib.rs` also holds the private `in_scope` helper both sources use: it keeps the deployment layer, the selected programme and the selected instrument, outermost layer first.

Decision-log file format: one JSON object per line, `{"index","prev","record","hash"}`, where `record` is the hex of the canonical CBOR record and `hash` is SHA-256 over `"fieldseal.policy.decision-log.v1\0" || index (8 bytes BE) || prev (32 bytes) || record`; the first `prev` is 32 zero bytes.

## Invariants

- `RegistryPolicySource` uses, per configured name, the highest version that verifies via `VerifyPublication` (signatures, provenance, log inclusion, no valid withdrawal; POL-004). Failing versions are skipped; if a name has publications and none verifies the result is `PolicySourceError::Unverified`, never less policy silently.
- `BundlePolicySource::from_verified` returns `Unverified` if the bundle's publications and documents differ in count (POL-050, POL-051). `new` trusts the caller's already-verified layers.
- The chain makes edits, removals, insertions and reordering evident. It cannot show truncation of the tail on its own; record `head()` out of the writer's reach and check with `verify_against`.
- `FileDecisionLog::open` verifies the whole file and fails if it does not verify, including a cut-short last line. Each append refuses if the file size differs from what this process last left (outside modification).
- Reads verify the chain up to the returned entry; a bad earlier entry is an error, not "not found".

## Side Effects

- `FileDecisionLog`: creates the file if absent; reads the whole file on open, verify and read; appends a line and `sync_data()` before `append` returns; guarded by an in-process `Mutex` only (no cross-process lock).
- Registry and bundle sources: reads from the injected registry (whatever I/O it does); no filesystem, network or clock access of their own.

## Verification

- Run: `cargo test -p fieldseal-adapters-policy`. Repo-wide: `just test`.
