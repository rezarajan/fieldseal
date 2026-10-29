//! Portal sessions shared by the apps that serve pages to signed-in people: the factory's
//! portal today, the results reader next.
//!
//! - [`PortalSessions`] keeps server-side sessions and pending sign-ins, builds the session
//!   cookie and checks the per-session CSRF token. It has no clock of its own: every call
//!   that depends on time takes the caller's `now`.
//! - [`front`] serves a `tiny_http` listener without its thread ever waiting on a client: bodies
//!   are read, and answers written, on threads of their own, under a byte-rate floor and a cap.
//! - [`http`] holds the framework-free [`Request`] and [`Response`] types and the form and
//!   multipart decoders, so a portal can be tested without sockets.
//!
//! Invariants: cookies are `HttpOnly`, `SameSite=Lax` and `Secure` when the public URL is
//! https; session ids and CSRF tokens come from the operating system's CSPRNG; a
//! state-changing request needs the session's CSRF token (REG-092). The crate serves no
//! pages and applies no role policy.

pub mod front;
pub mod http;
pub mod sessions;

pub use http::{Request, Response, multipart_field, parse_form};
pub use sessions::{PortalError, PortalSessions, SessionId, SessionView};
