# fieldseal-translog

## Overview
The Fieldseal transparency-log server (issue #82, [ADR 0030](../../../docs/explanation/adr/0030-public-transparency-log.md)): a self-hosted, append-only RFC 9162 Merkle log behind a small HTTP/1.1 API. The log and API semantics live in `fieldseal_adapters_translog`; this crate adds environment configuration (`config`), a blocking server (`http`) and the `fieldseal-translog` binary that wires them.

## Interface
- Binary `fieldseal-translog`; library `fieldseal_translog`.
- `config`: `Config` (`dir`, `origin`, `key_file`, `generate_key`, `bind`, `max_body`) with `Config::from_lookup`; `ConfigError` (`Missing`, `Invalid`, `Key`); `check_names`, `parse_key`, `load_key`; constants `DIR_VAR`, `ORIGIN_VAR`, `KEY_FILE_VAR`, `GENERATE_VAR`, `BIND_VAR`, `MAX_BODY_VAR`, `KNOWN_VARS`, `OWN_PREFIX`, `DEFAULT_BIND`, `DEFAULT_MAX_BODY`, `MAX_BODY_LIMIT`.
- `http`: `Server` (`bind`, `local_addr`, `shutdown_handle`, `run`), `ShutdownHandle::shutdown`, `Head`, `parse_head`, constants `MAX_HEAD` (8 KiB), `MAX_CONNECTIONS` (64), `IO_TIMEOUT` (10 s).
- Environment:

| Variable | Meaning |
|---|---|
| `FIELDSEAL_TRANSLOG_DIR` | Data directory (required) |
| `FIELDSEAL_TRANSLOG_ORIGIN` | Origin line, no whitespace (required) |
| `FIELDSEAL_TRANSLOG_KEY_FILE` | File with the 32-byte P-256 private scalar as hex (required) |
| `FIELDSEAL_TRANSLOG_GENERATE_KEY` | `1` creates the key file once if missing; `0` (default) does not |
| `FIELDSEAL_TRANSLOG_BIND` | Listen address, default `127.0.0.1:8080` |
| `FIELDSEAL_TRANSLOG_MAX_BODY` | Largest request body in bytes, default 4096, at most 1 MiB |

- HTTP API (handled by `fieldseal_adapters_translog::handle`): `POST /append`, `GET /checkpoint`, `GET /inclusion/<leaf_index>/<tree_size>`, `GET /consistency/<old_size>/<new_size>`. Responses carry `Cache-Control: no-store` and `Connection: close`.
- Exit codes: `78` unusable configuration or key; `69` failure to open the log or bind.

## Invariants
- Any `FIELDSEAL_TRANSLOG_*` variable not in `KNOWN_VARS` is refused; a set-but-empty variable or one with surrounding whitespace is refused, not treated as unset (CLI-030).
- The server never derives its key: a missing key file is an error unless `FIELDSEAL_TRANSLOG_GENERATE_KEY=1`.
- One request per connection; request head capped at 8 KiB, body at `max_body`; `Transfer-Encoding` is rejected (501); only HTTP/1.0 and 1.1; connections beyond 64 get `503`.
- Appends are `fsync`ed before acknowledgement; a torn tail is cut off on the next start (in the adapter). SIGTERM is not handled; the process exits immediately.
- Plain HTTP only; put a TLS-terminating proxy in front. Checkpoints are signed so clients verify them offline against the pin.

## Side Effects
- Binds a TCP listener and spawns one thread per connection.
- Creates/reads/appends files under `FIELDSEAL_TRANSLOG_DIR` (log store with a single-writer lock).
- May create the key file once (exclusive create, mode `0600` on Unix, parent directories created, `fsync`ed).
- Reads OS randomness for key generation.
- Prints one `development-adapters` event (JSON, built by the Deployment context's shared function; the file-held signing key is the log's `Signer`, DEP-051) before a structured `event=started` line (origin, public key, format, bind, size) to stderr, and `event=error` lines on failure.

## Verification
- Run: `cargo test -p fieldseal-translog` (repo-wide: `just test`)
