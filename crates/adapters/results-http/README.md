# fieldseal-adapters-results-http

## Overview
The results reader: the intake app's staff portal (Technical Plan 7.2). A signed-in person with the reader role sees the results export of the landing as it stands and downloads its files. It builds the export with the same functions as `fieldseal intake results` (`fieldseal-adapters-landing-files`), so the bytes are the same. Sessions come from `fieldseal-adapters-portal`.

## Interface
- `ResultsHttp::new(sessions, provider, export_key, clock, ResultsConfig)`, `handle(&Request) -> Response`, `serve_one(tiny_http::Request)` (reads the body itself) and `answer(&tiny_http::Request, Option<Vec<u8>>)` (for a caller that reads the body elsewhere, under a deadline); `with_held_bytes` sets the byte budget.
- `ResultsConfig`: landing and published directories, trust bundle, publishing policy, reader role, phishing-resistant requirement, public URL, CSP, development adapters, replay gap.

| Route | Auth | Result |
|---|---|---|
| `GET /` | none | to `/results` when signed in, else a sign-in page |
| `GET /sign-in`, `GET /sign-in/callback` | none | identity-provider flow |
| `POST /sign-out` | session and CSRF | ends the session |
| `GET /results` | session and role | paged table, manifest, contracts, download links |
| `GET /results/exports/{mark}/{path}` | session and role | one file of the export held for `mark` |

A request whose `Host` is not the host (and port) of the public URL is `400 bad-host`. No session: `302` to `/sign-in` for a page, `401 sign-in-required` for a download. No role or a weak method: `403`. A path outside the fixed list or a contract not in the export is `404 not-found`; a mark not held is `404 unknown-mark`.

## Invariants
- Nothing is written to disk; the built export is kept in memory for the last four landing marks, within a 256 MiB budget (the oldest goes first, the newest stays), and never changes. A page number past the end is the last page, and a page parses only its own rows.
- The page computes nothing from the answers (INT-092); every page carries the reader's own CSP.
- The CSV guard has no switch; events carry no personal data of the account.

## Verification
- Run: `cargo test -p fieldseal-adapters-results-http`.
