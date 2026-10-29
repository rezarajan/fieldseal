# fieldseal-dev-idp

## Overview

A development tool that stands where Keycloak stands in `just web`: a small OpenID Connect provider with fixed logins and no passwords. The factory, the intake app and the CLI run the same `oidc` adapter against it as against Keycloak or a real provider, so there is no second sign-in code path. It is not an adapter (the production client in `crates/adapters/oidc` holds no token-issuing code), it is built by Cargo in the dev shell only, and it is in no image, compose file or deployment manifest. Spec: REG-002 and REG-070a ([registration spec](../../../docs/reference/spec/registration.md)); design: the developer-experience design, Technical Plan §7.5.

## Interface

Binary `fieldseal-dev-idp`; library `fieldseal_dev_idp` (`DevIdp::start(config, bind)`, `DevIdp::issuer`, `parse_bind`, and the modules `config`, `server`, `tokens`).

| Flag | Meaning |
|---|---|
| `--development-tool` | required |
| `--config <file>` | logins, clients and the API audience (default `examples/deployments/dev-idp.yaml`) |
| `--bind <addr:port>` | where to listen (default `localhost:8180`); loopback hosts only |

The issuer is `http://<bind>/realms/fieldseal`, so the default is the issuer the stack's Keycloak uses. `FIELDSEAL_ENVIRONMENT` must be `development`.

Routes, on Keycloak's paths, so discovery is the only thing a client reads:

| Route | |
|---|---|
| `GET /realms/fieldseal/.well-known/openid-configuration` | discovery |
| `GET /realms/fieldseal/protocol/openid-connect/auth` | authorization code with PKCE `S256` (required). `login_hint` names a login and approves at once; otherwise a page lists the logins. The redirect URI must be registered for the client, or, for the public client, `http://127.0.0.1:<any port>/...` (RFC 8252). The callback carries `code`, `state` and `iss` |
| `POST /realms/fieldseal/protocol/openid-connect/token` | the code exchange. A confidential client authenticates with HTTP Basic; the public client sends `client_id` only. A code is used once and lasts 60 s |
| `GET /realms/fieldseal/protocol/openid-connect/certs` | the ES256 public key |

Tokens are signed ES256 with a key generated at start. The ID token carries `iss`, `aud` (the client), `azp`, `sub`, `nonce`, `roles`, `amr`, `acr`, `iat`, `exp`. The access token has the header type `at+jwt` and carries `iss`, `sub`, `aud` (the API audience), `client_id`, `scope`, `jti`, `roles`, `amr`, `acr`, `iat`, `exp`, and never a `nonce`. Both last 5 minutes.

Configuration file (`examples/deployments/dev-idp.yaml`, strict: an unknown key is an error): `apiAudience`; `logins` (`login`, `subject`, `roles`, `amr`, `acr`); `clients` (`id`, and either `public: true` or `secretRef` with `redirectUris`). The logins are `presenter` (subject `00000000-0000-4000-8000-000000000001`; roles `collector`, `operator`, `results-reader`) `collector1` (`00000000-0000-4000-8000-000000000002`; role `collector`) and `collector2` (`00000000-0000-4000-8000-000000000003`; role `collector`; the survey picker test's account), all with `acr: phr`. A confidential client's secret is read at start-up from `FIELDSEAL_SECRET_<REFERENCE>` (reference upper-cased, non-alphanumerics as `_`).

Exit codes: `0` for `--help`; `2` when it refuses to start or the configuration is unusable.

## Invariants

- It starts only with `--development-tool`, with `FIELDSEAL_ENVIRONMENT=development` (any other value or none exits `2`) and on a loopback address (`localhost`, `127.0.0.1`, `[::1]`). A listener that could be reached from another machine never opens.
- It prints a banner, one `development-adapters` event (built by the shared function of the Deployment context, DEP-051) and a line with its issuer and address.
- No secret is in the configuration file. The public client has no secret and never accepts one.
- The access token's audience is the API, never the client; the ID token's audience is the client, never the API. A portal client's access token has `client_id` of that client, which the verifier refuses for the operator API.
- An unregistered client or redirect URI gets an error page and never a redirect.
- The signing key is generated at start and lost on exit.
- It is named in no `flake.nix`, compose file or deployment manifest (`tests/refusals.rs` greps for that).

## Side Effects

- Binds one loopback TCP listener and serves with four threads.
- Reads the configuration file and the `FIELDSEAL_SECRET_*` variables once at start-up.
- Reads OS randomness for the signing key, codes and token ids.
- Keeps unexchanged authorization codes in memory. Writes nothing to disk.

## Verification

- Run: `cargo test -p fieldseal-dev-idp`. `tests/flows.rs` drives it with the production `OidcIdentityProvider` (the factory's sign-in, the CLI's sign-in with `verify_access_token`) and with plain requests; `tests/refusals.rs` runs the binary and checks that it exits `2` and that no image or manifest names it. Repo-wide: `just test`.
