# fieldseal-adapters-oidc

## Overview

OpenID Connect adapter for the Registration context's `IdentityProvider` port (REG-002, REG-002a; see [registration spec](../../../docs/reference/spec/registration.md)). Sign-in uses the authorization code flow with PKCE (`S256`) against any OIDC issuer. The adapter verifies the ID token before reading anything from it and derives the person's authentication methods from the token's own `amr` and `acr` claims. All code is in `src/lib.rs`.

## Interface

Implements `fieldseal_registration::ports::IdentityProvider` for `OidcIdentityProvider`:

- `start_sign_in(redirect_uri)` returns a `SignInStart`: the authorization URL (fresh `state`, `nonce`, PKCE `code_challenge`, optional `acr_values`) and a `PendingSignIn` whose secret is JSON `{verifier, nonce, redirect_uri}`.
- `finish_sign_in(pending, callback)` checks the callback (`error`, `state`, optional `iss`, `code`), exchanges the code at the token endpoint, verifies the ID token and returns an `AuthenticatedPerson`.

Public symbols:

| Symbol | Role |
|---|---|
| `OidcConfig` | Issuer, client id, optional client secret, extra scopes, `roles_claim`, `acr_values`, `asserted_methods`, `phishing_resistant_amr`, `phishing_resistant_acr`, `leeway`, `timeout`. `OidcConfig::new(issuer, client_id)` defaults: `roles` claim, 60 s leeway, 10 s timeout, strict (no extra phishing-resistant values). |
| `OidcSetupError` | `InsecureIssuer(String)`. |
| `OidcIdentityProvider` | `new(config) -> Result<_, OidcSetupError>`; `verify_id_token(id_token, nonce) -> Result<serde_json::Value, IdentityError>` (public for adapter tests). |
| `percent_encode` | Percent-encodes a query or form component (RFC 3986 unreserved characters kept). |

## Invariants

- The issuer must be `https`; plain `http` is accepted only for `localhost`, `127.0.0.1` and `::1`. Discovery endpoints (`authorization_endpoint`, `token_endpoint`, `jwks_uri`) are held to the same rule, and the discovery `issuer` must equal the configured one.
- ID-token signatures are accepted only as `RS256` (ring, 2048 to 8192 bit keys) or `ES256` (P-256, `s` normalised). `none`, symmetric algorithms and any header naming critical extensions are refused.
- After the signature, the adapter checks `iss`, `aud` (and `azp` when there are several audiences), `exp` (with leeway), `iat` not in the future (with leeway), `nonce` and a non-empty subject. Claims of the wrong type are refused rather than partly read.
- Configuration never raises the strength of a sign-in. The only strength-related setting, `asserted_methods`, marks every method `asserted` for a broker issuer, which factory policy then refuses unless it accepts asserted methods (REG-002a). Extra `amr`/`acr` values only count if the token itself carries them.
- `state`, `nonce` (16 bytes each) and the PKCE verifier (32 bytes) come from the operating system CSPRNG. The pending secret must contain exactly the three expected fields.
- Responses are capped at 1 MiB; redirects are not followed; HTTP status is not treated as a transport error.
- A key set is cached and refetched once when a `kid` is unknown (key rotation).

## Side Effects

- Network (blocking `ureq`, rustls): GET `{issuer}/.well-known/openid-configuration` on first use (lazy, so a provider that is down at start-up does not block the factory), GET the JWKS, and POST the code (form-encoded, HTTP Basic when a client secret is configured) to the token endpoint. Per-request timeout is `OidcConfig::timeout`.
- Randomness: `getrandom` for `state`, `nonce` and the verifier.
- Clock: reads `SystemTime` for `exp`/`iat` checks.
- In-memory state: discovery and JWKS caches behind `Mutex`. No filesystem access.

## Verification

- Run: `cargo test -p fieldseal-adapters-oidc` (tests use an in-test mock identity provider on loopback). Repo-wide: `just test`.
