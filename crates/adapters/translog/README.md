# fieldseal-adapters-translog

## Overview

A self-hosted transparency log for the Publishing context's `TransparencyLog` port ([ADR 0030](../../../docs/explanation/adr/0030-public-transparency-log.md), PUB-100 to PUB-106; see [publishing spec](../../../docs/reference/spec/publishing.md)). It provides a file-backed RFC 9162 Merkle log, an HTTP client for a log server, and the server side as a pure function. The `fieldseal-translog` binary that wraps `handle` in an HTTP/1.1 server lives in `crates/apps/translog`, not here.

Source files: `src/store.rs` (log store), `src/client.rs` (client adapter), `src/http.rs` (transports), `src/wire.rs` (request rendering, server handler, proof codecs), `src/lib.rs` (docs and re-exports).

## Interface

| Symbol | Role |
|---|---|
| `FileLogStore` | File-backed append-only log. `open(dir, origin, SigningKey) -> Result<_, StoreError>`; `pin() -> LogPin`, `origin()`, `size()`, `append_entry(&LogEntry)`, `latest_checkpoint()`, `inclusion_at(leaf_index, tree_size)`, `consistency_between(old, new)`. Implements `TransparencyLog` for in-process use. Logs the `LeafFormat::Fieldseal` leaf, signs C2SP checkpoints with the supplied P-256 key. |
| `StoreError` | `Io`, `Locked`, `Corrupt`, `Origin`. |
| `HttpTranslog<T: LogTransport>` | `TransparencyLog` client: `new(transport)`, `pinned(LogPin)` (every checkpoint must verify under the pinned key). |
| `HttpLogTransport` | `LogTransport` over HTTP(S) with `ureq`: `new(base_url)` (30 s timeout), `with_timeout(base_url, timeout)`. |
| `HandlerTransport<S>` | `LogTransport` that calls `handle` in-process on a `FileLogStore` (`S: Deref<Target = FileLogStore>`). |
| `handle(store, method, path, body, max_body) -> Response` | Server side, no sockets. |
| `render`, `interpret` | Transmission to `HttpRequest`; status and body to payload or `LogError`. |
| `encode_inclusion`, `encode_consistency`, `decode_inclusion`, `decode_consistency`, `decode_checkpoint`, `decode_append` | Proof and note codecs. |
| `HttpRequest`, `Response`, `DEFAULT_MAX_BODY` (4096), `MAX_RESPONSE` (1 MiB) | Wire types and limits. |

HTTP API served by `handle`:

| Request | Success body |
|---|---|
| `POST /append` (canonical CBOR entry, WIRE-191) | `u32` note length, checkpoint note, inclusion proof |
| `GET /checkpoint` | signed C2SP checkpoint note |
| `GET /inclusion/<leaf_index>/<tree_size>` | inclusion proof |
| `GET /consistency/<old_size>/<new_size>` | consistency proof |

Errors: `404` for unknown entry, size or route, `400` for a malformed request, `413` for an oversized body, `500` for other store errors.

## Invariants

- On-disk layout in the log directory: `log.dat` (magic `FSTLOG01`, then records of 4-byte length, canonical CBOR entry and 32-byte chain hash), `head` (latest signed checkpoint note) and `lock`. Records over 1024 bytes are refused.
- Appends are written in one `write` and `fsync`ed before acknowledgement; `head` is replaced atomically (temp file, fsync, rename, directory fsync) after every append.
- Opening replays and verifies everything. A torn tail (incomplete record, or a last record with a bad chain hash that no signed checkpoint covers) is cut off. Any other mismatch (bad chain before the end, non-canonical entry, head the entries cannot reproduce, head signed by another key) makes `open` fail closed.
- One writer at a time: an exclusive advisory lock on `lock`, released by the OS when the process dies.
- The server cannot verify entry signatures (it receives only digests); it records what it is given and consumers verify publisher signatures. Leaf hashes are held in memory and the root is recomputed per checkpoint (linear in log size).
- Clients refuse bodies over 1 MiB, proofs whose length disagrees with the header, paths over 128 hashes and unparseable notes; responses are cross-checked against the request (proof verifies against the returned checkpoint, sizes match). Redirects are not followed.
- An append transmits exactly the entry's four fields; lookups transmit only sizes and indices.

## Side Effects

- Filesystem (`FileLogStore::open`): creates the directory, `log.dat`, `head` and `lock`; fsyncs file and directory; truncates a torn tail.
- Network (`HttpLogTransport` only): blocking HTTP(S) via `ureq` (rustls); `POST` uses `Content-Type: application/cbor`.
- Crypto: signs checkpoints with the supplied P-256 key; verifies checkpoints and Merkle proofs.
- No clock access in this crate.

## Verification

- Run: `cargo test -p fieldseal-adapters-translog`. Repo-wide: `just test`.
