# fieldseal-adapters-oidc

## Overview

OpenID Connect adapter for the Registration context's `IdentityProvider` port (REG-002, REG-002a; see [registration spec](../../../docs/reference/spec/registration.md)). Sign-in uses the authorization code flow with PKCE (`S256`) against any OIDC issuer. The adapter verifies the ID token before reading anything from it and derives the person's authentication methods from the token's own `amr` and `acr` claims. It also verifies the Bearer access tokens that operator API calls carry (REG-070a). All code is in `src/lib.rs`.

## Interface

Implements `fieldseal_registration::ports::IdentityProvider` for `OidcIdentityProvider`:

- `start_sign_in(redirect_uri)` returns a `SignInStart`: the authorization URL (fresh `state`, `nonce`, PKCE `code_challenge`, optional `acr_values`) and a `PendingSignIn` whose secret is JSON `{verifier, nonce, redirect_uri}`.
- `finish_sign_in(pending, callback)` checks the callback (`error`, `state`, optional `iss`, `code`), exchanges the code at the token endpoint, verifies the ID token and returns an `AuthenticatedPerson`.

Not part of that trait, and used by the operator path (REG-070a, Technical Plan §7.5 of the developer-experience design):

- `verify_access_token(token)` verifies a JWT access token for the factory API (RFC 9068 profile) and returns the `AuthenticatedPerson`. It needs `api_audience` and `cli_client_id` in the config and refuses every token without them. It checks the signature (`RS256` or `ES256`), `iss`, an `aud` that contains the API audience, `exp`, `iat` and `nbf` (with leeway), a non-empty `sub`, the header `typ` (`at+jwt`; a plain `JWT` only with `accept_typ_jwt`, and then only with the payload `typ: Bearer`), the absence of any `nonce` claim, and the client (`client_id`, or `azp` when `client_id` is absent, equals `cli_client_id`). Whether the person is an operator with a phishing-resistant method is the caller's decision.
- `finish_sign_in_raw(pending, callback)` takes the arguments of `finish_sign_in`, does the same checks on the ID token (the `nonce` included) and returns a `RawSignIn { person, access_token, id_token_nonce_checked }`, so the CLI has the raw access token next to the verified person. It does not verify the access token: the API does.

Public symbols:

| Symbol | Role |
|---|---|
| `OidcConfig` | Issuer, client id, optional client secret, extra scopes, `roles_claim`, `acr_values`, `asserted_methods`, `phishing_resistant_amr`, `phishing_resistant_acr`, `api_audience`, `cli_client_id`, `accept_typ_jwt`, `leeway`, `timeout`. `OidcConfig::new(issuer, client_id)` defaults: `roles` claim, 60 s leeway, 10 s timeout, strict (no extra phishing-resistant values, no access tokens accepted, `at+jwt` only). |
| `OidcSetupError` | `InsecureIssuer(String)`. |
| `OidcIdentityProvider` | `new(config) -> Result<_, OidcSetupError>`; `verify_id_token(id_token, nonce) -> Result<serde_json::Value, IdentityError>` (public for adapter tests); `verify_access_token`; `finish_sign_in_raw`. |
| `RawSignIn` | `person`, `access_token`, `id_token_nonce_checked`. |
| `percent_encode` | Percent-encodes a query or form component (RFC 3986 unreserved characters kept). |

## Invariants

- The issuer must be `https`; plain `http` is accepted only for `localhost`, `127.0.0.1` and `::1`. Discovery endpoints (`authorization_endpoint`, `token_endpoint`, `jwks_uri`) are held to the same rule, and the discovery `issuer` must equal the configured one.
- ID-token signatures are accepted only as `RS256` (ring, 2048 to 8192 bit keys) or `ES256` (P-256, `s` normalised). `none`, symmetric algorithms and any header naming critical extensions are refused.
- After the signature, the adapter checks `iss`, `aud` (and `azp` when there are several audiences), `exp` (with leeway), `iat` not in the future (with leeway), `nonce` and a non-empty subject. Claims of the wrong type are refused rather than partly read.
- Configuration never raises the strength of a sign-in. The only strength-related setting, `asserted_methods`, marks every method `asserted` for a broker issuer, which factory policy then refuses unless it accepts asserted methods (REG-002a). Extra `amr`/`acr` values only count if the token itself carries them.
- `state`, `nonce` (16 bytes each) and the PKCE verifier (32 bytes) come from the operating system CSPRNG. The pending secret must contain exactly the three expected fields.
- Responses are capped at 1 MiB; redirects are not followed; HTTP status is not treated as a transport error.
- A key set is cached and refetched once when a `kid` is unknown (key rotation). ID tokens and access tokens share this code.
- An access token is never an ID token: a token that carries a `nonce` is refused, a `JWT` header needs the payload `typ: Bearer`, and its `aud` must hold the API audience. The ID-token checks do not apply to it and the access-token checks do not apply to an ID token.
- No token is cached. Each call verifies the token it is given, and the access token's lifetime is the provider's.
- `acr`, `amr` and the roles of an access-token person come from the access token and from no second source (no ID token, no user-info call), with the mapping ID tokens use.

## Side Effects

- Network (blocking `ureq`, rustls): GET `{issuer}/.well-known/openid-configuration` on first use (lazy, so a provider that is down at start-up does not block the factory), GET the JWKS, and POST the code (form-encoded, HTTP Basic when a client secret is configured) to the token endpoint. Per-request timeout is `OidcConfig::timeout`.
- Randomness: `getrandom` for `state`, `nonce` and the verifier.
- Clock: reads `SystemTime` for `exp`/`iat` checks.
- In-memory state: discovery and JWKS caches behind `Mutex`. No filesystem access.

## Verification

- Run: `cargo test -p fieldseal-adapters-oidc`. `tests/access_token.rs` runs `verify_access_token` against a mock identity provider (a `tiny_http` server on loopback that serves discovery and a key set) and signs its tokens with the PKCS#1 RSA key in `tests/fixtures/test-rsa-2048.der` (ring's `RsaKeyPair::from_der`) and a fixed P-256 key. The ID-token path and the sign-in finish are exercised end to end by `crates/apps/dev-idp/tests/flows.rs`. Repo-wide: `just test`.
