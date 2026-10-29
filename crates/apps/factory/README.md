# fieldseal-factory

## Overview
The factory service's composition root (ADR 0028). The binary `fieldseal-factory` reads its configuration from the environment only (twelve-factor III, ADR 0025), wires adapters to the Registration use cases (`Factory`) and serves the registration API and the sign-in portal through `FieldsealHttp`'s `FactoryHttp` adapter. It also builds bundles: a reconciler on its own thread builds and stores each registered tenancy's bundle, and `GET /v1/bundle` and the portal serve what is stored. The library target (`config`, `inputs`, `reconciler`) is there so tests start the reconciler in process; the composition root is `src/main.rs`. See the [registration spec](../../../docs/reference/spec/registration.md) and [ADR 0013](../../../docs/explanation/adr/0013-registration-via-authority-tokens.md).

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
| `FIELDSEAL_STATE_DIR` | The directory of the file-backed registry journal (required; non-production only). The runtime profiles and roster source read it |
| `FIELDSEAL_OIDC_API_AUDIENCE`, `FIELDSEAL_OIDC_CLI_CLIENT_ID` | Audience of the operator API's access tokens and the public client that may call it; without both no access token is accepted |
| `FIELDSEAL_OIDC_ACCEPT_TYP_JWT` | `true` to accept a plain `JWT` header type with the payload type `Bearer` (Keycloak) |
| `FIELDSEAL_FACTORY_POLICY_DIGEST` | The content address of the `deployment-policy` the factory trusts (required in staging and production; any other policy is refused) |
| `FIELDSEAL_FACTORY_ALLOWED_BUILDERS`, `_ALLOWED_SOURCES` | Development only, without a digest: the builders and sources the release policy is verified under, with the schema defaults (comma-separated; default none) |
| `FIELDSEAL_FACTORY_REGISTRY_DIR` | The artefact registry directory, read to check that a survey is published (required; development adapter) |
| `FIELDSEAL_ROSTER_DIR` | The roster store, written by `IssueRoster` (required; development adapter; owner-only) |
| `FIELDSEAL_BUNDLE_DIR` | Stored bundles, one directory per tenancy, with `inputs.sha256` beside them (required; development adapter) |
| `FIELDSEAL_ISSUED_ROSTERS_DIR` | Where the issued rosters are recorded for intake (required; development adapter; intake reads it as `FIELDSEAL_INTAKE_ROSTERS_DIR`) |
| `FIELDSEAL_FACTORY_BUILD_INTERVAL_S` | Seconds between scans of the artefact registry directory, 1 to 3600 (default 5 in development, 60 elsewhere; outside the range exits `2`) |
| `FIELDSEAL_FACTORY_MAX_ANCHOR_AGE_S` | A stored bundle whose anchor is older is rebuilt, 60 to 604800 (default 86400) |
| `FIELDSEAL_ALLOW_UNATTESTED` | `true` to accept software keys (non-production only, REG-017) |

- HTTP routes (served by `fieldseal_adapters_factory_http::FactoryHttp`, tiny_http):
  - Runtime API: `GET /healthz`, `GET /readyz`, `POST /v1/registrations`, `GET /v1/registrations/<id>`, and proof-of-possession routes `GET /v1/certificate`, `GET /v1/bundle` (the stored bundle; it never builds), `POST /v1/api-token`, `POST /v1/posture/nonce`, `POST /v1/posture`.
  - Operator API (Bearer access token, operator role, phishing-resistant sign-in): `POST /v1/rosters`, `POST /v1/assignments`, `GET /v1/assignments`. Events `assignment-made` and `roster-issued` carry no roster value and no account subject.
  - Portal: `GET /`, `GET /sign-in`, `GET /sign-in/callback`, `POST /sign-out`, `POST /tokens`, `POST /pending/<id>/confirm`, `POST /devices/<id>/lost|retire`, `POST /uploads`, `GET /tenancies/<id>/certificate.cbor`, `GET /devices/<id>/bundle.fsb`.
- Library: `config::Config` (`from_lookup`), `Identity`, `Custody`; `inputs::BuildInputs` (`collect`, `digest`, `request_for`); `reconciler::Reconciler` (`run_once`, `reconcile_all`, `spawn`), `BuildWriteHook`, `WriteStep`, `ReconcileEvent`.
- Internal types of the binary: `Authority`, `SystemClock`, `OsRandom`.

### The reconciler and its events

For each tenancy of an account that has an assignment, the reconciler compares the digest of the build inputs with the one stored beside the last bundle, and the age of that bundle's anchor with `FIELDSEAL_FACTORY_MAX_ANCHOR_AGE_S`; it builds when either says so. The inputs are the instrument each assigned survey selects (the highest non-withdrawn semver the tenancy's reported schema can run, DIS-012), its bound layouts (`factory.release.layouts`; layouts are found by the name `<survey>-<window>`), the withdrawals, the current roster of each assigned cohort, the stored certificate, the agreement key, the reported profile and the release policy. It finds the policy as the published `deployment-policy` artefact (highest non-withdrawn version); with none published nothing is built. Writes go in a fixed order: issued rosters recorded for intake and synced, the bundle, then the digest, so a crash leaves the previous bundle and the next pass rebuilds. A build that fails keeps the previous bundle.

Triggers: a tenancy registering, an assignment and a roster issue tell the thread at once (`ReconcileNotify`); the scan at `FIELDSEAL_FACTORY_BUILD_INTERVAL_S` is only for publications the CLI writes as files (a production adapter would trigger by event and the poll would go); a restart builds nothing unless the digest differs or the anchor is too old.

Events on stderr, with no subject data (a tenancy is its first 16 hex digits): `bundle-built` (`sequence`, `address`, counts), `bundle-withheld` (`reason`: `no-policy`, `no-assignments`, `instrument-incompatible`, `instrument-unavailable`, `runtime-profile-unknown`, `tenancy-<state>`, or the policy's reasons) and `bundle-failed` (`reason`: a code). A reason that persists is told once.
- `fieldseal deployment render` writes exactly these variables from the deployment manifest (DEP-012).

## Invariants
- Production refuses to start with the bundle, issued-roster and state directories, `dev` identity, `memory-dev`/`file-dev` custody, `FIELDSEAL_STATE_DIR` `FIELDSEAL_ALLOW_UNATTESTED`, `FIELDSEAL_FACTORY_REGISTRY_DIR` or `FIELDSEAL_ROSTER_DIR`: there is no production custody adapter or state store yet.
- A bundle is built only for a registered tenancy (never for a lost, closing, closed, retired, flagged, pending or held one), and eligibility is checked again at every fetch. Rosters are recorded as issued only after `bundle.release` allows the bundle.
- Cohorts reach tenancies through assignments, never configuration; `FIELDSEAL_COHORTS` is gone. Dev users and list entries must be unique and trimmed.
- Unattested keys are refused unless explicitly allowed outside production.
- Default tenancy window is 180 days from start (`memory-dev`); for `file-dev` it follows the first record-key certificate's period. Grace is 30 days. Posture-nonce and API-token TTL are 10 minutes; portal session TTL is 8 hours.
- Registration uses the schema-default policy (POL-022); bundle release uses the published `deployment-policy`.

## Side Effects
- Binds a TCP listener on `FIELDSEAL_FACTORY_BIND` and serves until killed.
- `memory-dev` with `FIELDSEAL_TRUST_BUNDLE`: writes the generated trust bundle to that path.
- `file-dev`: reads the trust bundle and uses key files in `FIELDSEAL_CUSTODY_DIR`.
- `FIELDSEAL_STATE_DIR`: opens and appends to the file-backed registry journal; the reconciler reads it back.
- Writes bundles and `inputs.sha256` under `FIELDSEAL_BUNDLE_DIR` and the issued rosters under `FIELDSEAL_ISSUED_ROSTERS_DIR`; reads the artefact registry directory on every scan.
- `oidc`: outbound HTTP to the OIDC issuer during sign-in.
- Reads the system clock and OS random source; logs start-up lines to stderr.

## Verification
- Run: `cargo test -p fieldseal-factory` (repo-wide: `just test`)
