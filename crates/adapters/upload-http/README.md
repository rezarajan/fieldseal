# fieldseal-adapters-upload-http

## Overview

The HTTP upload adapter ([ADR 0021](../../../docs/explanation/adr/0021-export-upload-receipts.md); [delivery spec](../../../docs/reference/spec/delivery.md)). Two halves of one protocol live in `src/lib.rs`, plus a development server binary in `src/bin/server.rs`.

## Interface

Library (`src/lib.rs`):

| Symbol | Role |
|---|---|
| `HttpUploadTransport` | Implements Delivery's `UploadTransport` for the runtime: answers the receiver challenge and sends uploads with a proof-of-possession token. `new(ClientConfig)`; `upload_outbox(base_url, export) -> Result<Vec<Vec<u8>>, UploadError>`. Holds no base URL; every address is an untrusted hint (DEL-060, DEL-061). |
| `ClientConfig` | `allow_http` (default false) and `timeout` (default 60 s). |
| `UploadHttp<'a, 'g>` | Serves Intake's `UploadService` over HTTP. `new(service, now, ServerConfig)`, `run(&tiny_http::Server)` (one request at a time), `handle(&Request) -> Response`. |
| `ServerConfig` | `max_body` (default 64 MiB). |
| `Request`, `Response` | HTTP types decoupled from the server library. |
| `MAX_ANSWER` | 1 MiB limit on answers the client reads. |

Routes: `POST /v1/challenge` (no auth; CBOR challenge in, receiver answer out), `POST /v1/upload` (`Fieldseal-PoP` token; export file without parity in, CBOR array of receipts out), `POST /v1/upload/outbox` (no token; closing manifests are verified), `GET /healthz` (200, no auth). Refusals are JSON: `401` token, `422` gate refusal (stage and code, no personal data), `400` malformed, `404` unknown path, `405` wrong method, `413` body too large, `503` backing-service failure.

Binary `fieldseal-upload-server` (`src/bin/server.rs`): a development and conformance intake endpoint. Default mode (`FIELDSEAL_UPLOAD_AUTHORITY=practice`) serves the gate over in-memory ports with the practice authority's software keys and registers one practice device per `--device` label. Mode `stack` serves a real authority with development custody.

| Variable | Flag | Meaning |
|---|---|---|
| `FIELDSEAL_UPLOAD_LISTEN` | `--listen` | bind address, default `127.0.0.1:8480` |
| `FIELDSEAL_UPLOAD_PUBLIC_URLS` | `--public-url` (repeatable) | base URLs tokens may be bound to |
| `FIELDSEAL_UPLOAD_SEED` | `--seed` | practice authority seed, default 7 |
| `FIELDSEAL_UPLOAD_MAX_BODY` | `--max-body` | largest body in bytes |
| `FIELDSEAL_UPLOAD_AUTHORITY` | | `practice` (default) or `stack` |
| `FIELDSEAL_CUSTODY_DIR`, `FIELDSEAL_TRUST_BUNDLE`, `FIELDSEAL_TENANCY_DIR` | | required for `stack` |
| `FIELDSEAL_LANDING_DIR`, `FIELDSEAL_INTAKE_PUBLISHED_DIR`, `FIELDSEAL_INTAKE_ROSTERS_DIR`, `FIELDSEAL_INTAKE_SUBMISSIONS_DIR` | | optional for `stack`; each falls back to an empty in-memory port |
| `FIELDSEAL_INTAKE_ALLOWED_BUILDERS`, `FIELDSEAL_INTAKE_ALLOWED_SOURCES` | | comma-separated publishing policy for instruments |

## Invariants

- Plain `http://` addresses are refused by the client unless `ClientConfig::allow_http` is set. TLS is terminated in front of the server.
- The server enforces `max_body` while reading (413) and requires a valid PoP token only on `/v1/upload`; the outbox route relies on manifest verification in Intake.
- `/healthz` reveals only that the process is serving.
- The server binary in `stack` mode reads the tenancy directory read-only, and replays stored submissions through the gate at start-up so landed and duplicate state survives a restart (INT-013). Keys are development custody, never production.

## Side Effects

- Client: blocking HTTP(S) via `ureq` (rustls), whole-request timeout.
- Server: binds a TCP socket (`tiny_http`); reads request bodies into memory.
- Binary: reads environment and arguments; in `stack` mode reads the trust bundle and custody keys, reads or writes the configured landing, rosters and submissions directories (via the file adapters), reads the system clock and uses OS randomness; writes JSON event lines (`listening`, `submission`, `landed`, `replayed`, `replay-failed`) to stderr. Practice mode uses fixed seeds and a fixed clock (practice epoch plus 20 days).

## Verification

- Run: `cargo test -p fieldseal-adapters-upload-http`. Repo-wide: `just test`.
