# fieldseal-adapters-rekor

## Overview

Sigstore Rekor adapter for the Publishing context's `TransparencyLog` port ([ADR 0030](../../../docs/explanation/adr/0030-public-transparency-log.md), PUB-100 to PUB-106; see [publishing spec](../../../docs/reference/spec/publishing.md)). Every `LogEntry` is logged as a minimal hash-only `hashedrekord` v0.0.1 entry. The request body is exactly the leaf Rekor logs, so a consumer can recompute the leaf (`LeafFormat::HashedRekord`) and verify the inclusion proof offline. All code is in `src/lib.rs`.

The adapter has two parts so that what leaves the process can be recorded: `RekorLog` builds `Transmission`s and checks answers; `HttpTransport` renders each transmission to exactly one HTTP request and sends it.

## Interface

| Symbol | Role |
|---|---|
| `RekorLog<T: LogTransport>` | Implements `TransparencyLog` over any transport: `new(transport)`; append, checkpoint, inclusion and consistency lookups. |
| `HttpTransport` | Implements `LogTransport` over `ureq`: `new(RekorConfig)`. |
| `RekorConfig` | `new(base_url)`, `from_lookup(fn)`, `from_env()`; fields `timeout`, `max_response`; `base_url()`. |
| `ConfigError` | `Missing`, `Invalid(String)`. |
| `URL_VAR` | `"FIELDSEAL_REKOR_URL"`. |
| `DEFAULT_MAX_RESPONSE` | 1 MiB. |
| `render(base_url, &Transmission)` | Pure function producing one `HttpRequest`; `Method` is `Get` or `Post`. |

Requests rendered (Rekor v1 API): append is `POST /api/v1/log/entries`; checkpoint is `GET /api/v1/log`; inclusion is `GET /api/v1/log/entries?logIndex=N`; consistency is `GET /api/v1/log/proof?firstSize=A&lastSize=B`.

## Invariants

- An append carries exactly the fields `digest` (64 lowercase hex), `signature` (DER) and `publicKey` (PEM); no optional field is set. Lookups carry no fields. Anything else is `LogError::Malformed`.
- Only fixed protocol headers are sent (`Accept`, `Content-Type` on appends, `User-Agent: fieldseal`); nothing about the artefact is in a header, path or query.
- Answers are checked: the logged body must equal the `hashedrekord` leaf for the entry, the proof and checkpoint must agree on size and root, and the inclusion proof must reach the root. Proof paths are bounded by `MAX_PATH`; response size is bounded (`LogError::Oversized`).
- Redirects are not followed.
- On `409 Conflict` the existing entry is fetched by the UUID in the `Location` header (or a 64 to 80 hex-digit word in the error body) and is accepted only if it passes the same checks, so a 409 is success only if the log really holds this entry.
- No URL is built in; the base URL comes from configuration.

## Side Effects

- Network: blocking HTTP(S) to the configured Rekor instance (rustls, no async runtime).
- Environment: `RekorConfig::from_env` reads `FIELDSEAL_REKOR_URL`.
- No filesystem access. Tests run against a local mock server on `127.0.0.1` and never contact a public log.

## Verification

- Run: `cargo test -p fieldseal-adapters-rekor`. Repo-wide: `just test`.
