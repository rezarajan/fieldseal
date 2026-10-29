# fieldseal-adapters-factory-http

## Overview

The factory's HTTP adapter. It drives the Registration use cases (`fieldseal_registration::application::Factory`) from HTTP and ships a small blocking client for the runtime API. Two surfaces:

- **Runtime API** (JSON responses, CBOR request bodies).
- **Portal**: server-rendered HTML without scripts for sign-in, tokens, pending requests, devices and the air-gapped route.

Layer: adapter. Depends on `fieldseal-kernel`, `fieldseal-trust`, `fieldseal-registration`, `fieldseal-adapters-portal` (sessions, CSRF and the HTTP types), `tiny_http` (server), `ureq` with rustls (client), `qrcode`, `serde_json`. See [registration.md](../../../docs/reference/spec/registration.md) for the requirements (REG-*).

## Interface

Crate root:

- `FactoryHttp<'a>::new(&Factory, &dyn IdentityProvider, HttpConfig)`; `run(&tiny_http::Server)` (serves until the server closes); `handle(&Request) -> Response` (framework-free, testable without sockets).
- `HttpConfig { public_url, session_ttl_ms }`.
- `Request`, `Response`, `parse_form`, `multipart_field`: re-exported from `fieldseal-adapters-portal`.
- `iso8601(AuthorityTime)`, `error_code(&RegistrationError)`.
- Consts `MAX_BODY` (1 MiB) and `SESSION_COOKIE` (`fs_session`).

Routes served by `handle`:

| Method and path | Auth | Use case |
| --- | --- | --- |
| `POST /v1/registrations` | none (request is sealed and proves possession) | `SubmitRequest`, `RollKey` |
| `GET /v1/registrations/{tenancy}` | none; state only | status polling |
| `GET /v1/certificate` | `Fieldseal-PoP` | `GetCertificate` (CBOR) |
| `POST /v1/api-token` | `Fieldseal-PoP` | `IssueApiToken` |
| `POST /v1/posture/nonce`, `POST /v1/posture` | `Fieldseal-PoP` | `CheckPosture` |

The portal covers sign-in via the `IdentityProvider` port, tokens as text and QR (REG-007), pending requests with fingerprint words and indices (REG-021, REG-023), devices with mark-lost and retire (REG-043), request-file upload and certificate download for the air-gapped route (REG-053, REG-054).

Modules:

- `client`: `FactoryHttpClient::new(base_url)`, `base()`, `submit(request_file)`, `status(tenancy_hex)`, `certificate(pop_header)`; `Answer { status, body }`; `ClientError { BadUrl, Unreachable }`; `MAX_ANSWER` (1 MiB). Returns bytes and status; the caller interprets them.
- `html`: `escape`, `page(title_id, body, csrf)`, `words(&FingerprintWords)`, `qr_svg(text, label)` (inline SVG).
- `messages`: `CATALOGUE` (stable message ID to English text), `text`, `format(id, args)` (named `{placeholders}`, values HTML-escaped), `t`.

Sessions, the pending sign-in map, the session cookie and the CSRF check come from `fieldseal-adapters-portal` (`PortalSessions`, cookie name `fs_session`); this crate keeps the pages and passes its own content-security policy to `Response::html`.

Ports consumed: `fieldseal_registration::ports::IdentityProvider` (and its `PendingSignIn`); the `Factory` use-case object is supplied by the caller.

## Invariants

- Bodies larger than `MAX_BODY` are answered `413` with `{"error": "too-large"}`.
- Requests are handled one at a time by `run`. TLS is terminated in front of the adapter.
- PoP-protected endpoints take the WIRE-170 token in the `Fieldseal-PoP` header; when an access token is used, `Authorization: FieldsealPoP <base64url>`.
- Sessions are server-side, behind an `HttpOnly`, `SameSite=Lax` cookie (`Secure` only when `public_url` starts with `https://`); every portal form carries a CSRF token, checked before the action runs.
- Every portal string comes from `messages`; pages never build sentences by concatenation. A translated catalogue must replace `CATALOGUE` entry for entry, keeping every placeholder.
- `run` adds `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` to every response.
- The client accepts only `http://` or `https://` base URLs and caps answers at `MAX_ANSWER`.

## Side Effects

- Network: `run` listens on the supplied `tiny_http::Server`; `FactoryHttpClient` makes outbound HTTP(S) calls with a 30 s global timeout (plain `http://` allowed for the loopback local stack).
- Randomness: session ids and CSRF tokens come from the OS through `fieldseal-adapters-portal`, which panics if it is unavailable.
- State: the in-memory session and pending-sign-in maps of `PortalSessions` (lost on restart). Registry changes happen through the injected `Factory`.
- No direct filesystem access.

## Verification

- Run: `cargo test -p fieldseal-adapters-factory-http` (repo-wide: `just test`)
