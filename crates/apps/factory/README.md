# fieldseal-factory

## Overview
The factory service's composition root (ADR 0028). The binary `fieldseal-factory` reads its configuration from the environment only (twelve-factor III, ADR 0025), wires adapters to the Registration use cases (`Factory`) and serves the registration API and the sign-in portal through `FieldsealHttp`'s `FactoryHttp` adapter. It has no library target; all code is in `src/main.rs`. See the [registration spec](../../../docs/reference/spec/registration.md) and [ADR 0013](../../../docs/explanation/adr/0013-registration-via-authority-tokens.md).

## Interface
- Binary `fieldseal-factory` (package `fieldseal-factory`). No command-line arguments; configuration is environment variables (all strict: a set variable must be non-empty with no surrounding whitespace; flags are exactly `true` or `false`).
- Exit codes: `2` for unusable configuration, `1` for a start-up or runtime failure (messages on stderr prefixed `fieldseal-factory:`).

| Variable | Meaning |
|---|---|
| `FIELDSEAL_ENVIRONMENT` | `development`, `staging`, `test` or `production` (required; only `production` is treated as production) |
| `FIELDSEAL_FACTORY_BIND` | `ip:port` to listen on (required) |
| `FIELDSEAL_FACTORY_URL` | Public base URL, written into tokens and checked in PoP tokens (required; https, http only for loopback, at most 256 bytes) |
| `FIELDSEAL_IDENTITY` | `oidc`, or `dev` (non-production only) (required) |
| `FIELDSEAL_OIDC_ISSUER`, `FIELDSEAL_OIDC_CLIENT_ID` | OIDC issuer and client (for `oidc`; client id may instead come from `FIELDSEAL_OIDC_CLIENT_ID_REF`) |
| `FIELDSEAL_OIDC_CLIENT_SECRET` / `_REF` | Client secret, or a secret-store reference resolved at start-up from `FIELDSEAL_SECRET_<REFERENCE>` (upper-cased, non-alphanumerics as `_`) |
| `FIELDSEAL_OIDC_SCOPES`, `FIELDSEAL_OIDC_ROLES_CLAIM`, `FIELDSEAL_OIDC_ACR_VALUES` | Extra scopes (space-separated), roles claim, `acr_values` to request |
| `FIELDSEAL_OIDC_PHISHING_RESISTANT_AMR`, `FIELDSEAL_OIDC_PHISHING_RESISTANT_ACR` | Comma-separated extra values the issuer uses for phishing-resistant (default none) |
| `FIELDSEAL_OIDC_ASSERTED_METHODS` | `true` for a broker that may alter `amr`/`acr` |
| `FIELDSEAL_DEV_USERS` | For `dev` identity: `login=role+role:amr+amr,...` |
| `FIELDSEAL_CUSTODY` | `memory-dev` (keys and authority generated in memory, lost on restart) or `file-dev` (keys in `FIELDSEAL_CUSTODY_DIR`, trust bundle read from `FIELDSEAL_TRUST_BUNDLE`); both non-production only |
| `FIELDSEAL_CUSTODY_DIR` | Key directory for `file-dev` |
| `FIELDSEAL_TRUST_BUNDLE` | `memory-dev`: path to write the development trust bundle (optional). `file-dev`: path to read (required) |
| `FIELDSEAL_STATE_DIR` | Directory for a file-backed registry journal (non-production only); otherwise in memory |
| `FIELDSEAL_COHORTS` | `cohort:generation,...` assigned to every new tenancy (default none) |
| `FIELDSEAL_ALLOW_UNATTESTED` | `true` to accept software keys (non-production only, REG-017) |

- HTTP routes (served by `fieldseal_adapters_factory_http::FactoryHttp`, tiny_http):
  - Runtime API: `GET /healthz`, `GET /readyz`, `POST /v1/registrations`, `GET /v1/registrations/<id>`, and proof-of-possession routes `GET /v1/certificate`, `POST /v1/api-token`, `POST /v1/posture/nonce`, `POST /v1/posture`.
  - Portal: `GET /`, `GET /sign-in`, `GET /sign-in/callback`, `POST /sign-out`, `POST /tokens`, `POST /pending/<id>/confirm`, `POST /devices/<id>/lost|retire`, `POST /uploads`, `GET /tenancies/<id>/certificate.cbor`.
- Internal types: `Config` (`from_lookup`), `Identity` (`Oidc`/`Dev`), `Custody` (`MemoryDev`/`FileDev`), `Authority`, `SystemClock`, `OsRandom`.
- `fieldseal deployment render` writes exactly these variables from the deployment manifest (DEP-012).

## Invariants
- Production refuses to start with `dev` identity, `memory-dev`/`file-dev` custody, `FIELDSEAL_STATE_DIR` or `FIELDSEAL_ALLOW_UNATTESTED`: there is no production custody adapter or state store yet.
- `FIELDSEAL_COHORTS` entries are unique, non-empty and `cohort:generation` with an unsigned decimal generation without leading zeros; dev users and list entries must be unique and trimmed.
- Unattested keys are refused unless explicitly allowed outside production.
- Default tenancy window is 180 days from start (`memory-dev`); for `file-dev` it follows the first record-key certificate's period. Grace is 30 days. Posture-nonce and API-token TTL are 10 minutes; portal session TTL is 8 hours.
- Policy is the schema defaults until published layers are loaded (POL-022).

## Side Effects
- Binds a TCP listener on `FIELDSEAL_FACTORY_BIND` and serves until killed.
- `memory-dev` with `FIELDSEAL_TRUST_BUNDLE`: writes the generated trust bundle to that path.
- `file-dev`: reads the trust bundle and uses key files in `FIELDSEAL_CUSTODY_DIR`.
- `FIELDSEAL_STATE_DIR`: opens and appends to the file-backed registry journal.
- `oidc`: outbound HTTP to the OIDC issuer during sign-in.
- Reads the system clock and OS random source; logs start-up lines to stderr.

## Verification
- Run: `cargo test -p fieldseal-factory` (repo-wide: `just test`)
