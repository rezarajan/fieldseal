# fieldseal-adapters-portal

## Overview

Portal sessions for the apps that serve pages to signed-in people. The factory's portal uses it today; the results reader will use it next. It holds the server-side session store, the pending sign-in map, the session cookie and the per-session CSRF check, plus the framework-free HTTP `Request` and `Response` types and the form and multipart decoders.

Layer: adapter. Depends on `fieldseal-kernel` (`AuthorityTime`), `fieldseal-registration` (`AuthenticatedPerson`, `IdentityProvider`, `PendingSignIn`), `getrandom`, `serde_json` and `thiserror`. No HTTP server dependency. See [registration.md](../../../docs/reference/spec/registration.md) (REG-092, REG-002).

## Interface

- `PortalSessions::new(cookie_name, secure, ttl_ms)`.
  - `begin(&dyn IdentityProvider, callback_url, now) -> Result<(String, String), PortalError>`: the URL to send the person to and the `Set-Cookie` value of the pre-auth cookie; keeps the pending sign-in by its state for ten minutes (at most 1000; the oldest is dropped first).
  - `finish(&dyn IdentityProvider, &query, cookie_header, now) -> Result<(SessionId, String), PortalError>`: takes the callback's whole decoded query and the request's `Cookie` header, which must carry the pre-auth cookie; returns the new session and the `Set-Cookie` value. The caller also sends `clear_pre_auth_cookie()`. A callback with `error=` is refused with a fixed message, never the provider's text.
  - `session(cookie_header, now) -> Option<SessionView { id, person, csrf }>`: drops expired sessions first.
  - `check_csrf(&SessionView, submitted) -> bool`, `end(&SessionId)`, `clear_cookie() -> String`.
- `Request` (`method`, `path`, `query`, `headers`, `body`; `new`, `header`, `cookie`, `form`) and `Response` (`status`, `headers`, `body`; `new`, `json`, `html(status, body, csp)`, `redirect`, `with`). The content-security policy is the caller's, because each app has its own.
- `parse_form`, `multipart_field`.

## Invariants

- The session cookie is `HttpOnly`, `SameSite=Lax`, `Path=/`, and `Secure` when the store was built with `secure`.
- Session ids and CSRF tokens are 32 bytes from the operating system's CSPRNG, base64url-encoded; each session has its own CSRF token.
- A pending sign-in is removed when its callback arrives, so it is usable once, and only within ten minutes.
- A sign-in is bound to the browser that started it: `begin` sets a pre-auth cookie (`<name>_pre`, `HttpOnly`, `SameSite=Lax`, `Path=/sign-in`, ten minutes) that holds a hash of the state, and `finish` refuses a callback that does not bring it back (login CSRF).
- An expired session is never returned. The store has no clock: every call that depends on time takes the caller's `now`.
- The cookie name is a parameter, so two portals on one host do not read each other's sessions.

## Side Effects

- Randomness: reads the operating system's random source; panics if it is unavailable.
- State: in-memory, mutex-guarded session and pending-sign-in maps (lost on restart).
- No network, no filesystem.

## What it does not do

- No pages and no messages: the app renders its own.
- No role policy: the app decides what a signed-in person may do.

## Verification

- Run: `cargo test -p fieldseal-adapters-portal` (repo-wide: `just test`). The factory's behaviour through this crate is pinned by `cargo test -p fieldseal-adapters-factory-http --test portal_session`.
