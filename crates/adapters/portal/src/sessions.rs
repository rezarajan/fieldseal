//! Server-side portal sessions: the session store, the pending sign-ins, the session
//! cookie and the per-session CSRF token (REG-092).

use std::collections::BTreeMap;
use std::sync::Mutex;

use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_registration::domain::AuthenticatedPerson;
use fieldseal_registration::domain::wire::base64url_encode;
use fieldseal_registration::ports::{IdentityProvider, PendingSignIn};

use crate::http::cookie_value;

/// Why a sign-in did not start or did not finish. The text is the reason shown to the person.
#[derive(Debug, thiserror::Error)]
pub enum PortalError {
    /// The identity provider could not start a sign-in.
    #[error("{0}")]
    Start(String),
    /// The callback was refused: an unknown or used state, or the provider said no.
    #[error("{0}")]
    Refused(String),
}

/// A session's identifier: the value of the session cookie.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct SessionId(pub String);

/// A live session as a request sees it.
#[derive(Clone)]
pub struct SessionView {
    /// The session's identifier.
    pub id: SessionId,
    /// Who signed in.
    pub person: AuthenticatedPerson,
    /// The session's CSRF token, which every state-changing request must carry.
    pub csrf: String,
}

/// How long a started sign-in may wait for its callback.
const PENDING_TTL_MS: u64 = 10 * 60 * 1000;

/// How many sign-ins may wait at once; past it the oldest is dropped.
const PENDING_CAP: usize = 1000;

/// What the callback of one started sign-in is checked against.
struct Pending {
    sign_in: PendingSignIn,
    expires_at: AuthorityTime,
    /// Start order, to find the oldest.
    seq: u64,
}

struct Session {
    person: AuthenticatedPerson,
    csrf: String,
    expires_at: AuthorityTime,
}

/// The sessions and pending sign-ins of one portal. In memory: lost on restart.
pub struct PortalSessions {
    cookie_name: String,
    secure: bool,
    ttl_ms: u64,
    sessions: Mutex<BTreeMap<String, Session>>,
    pending: Mutex<BTreeMap<String, Pending>>,
    next_seq: Mutex<u64>,
}

impl PortalSessions {
    /// A store whose sessions live `ttl_ms` milliseconds, in a cookie called `cookie_name`
    /// (`Secure` when `secure`). Two portals on one host use two names so their cookies do
    /// not mix.
    pub fn new(cookie_name: &str, secure: bool, ttl_ms: u64) -> Self {
        Self { cookie_name: cookie_name.to_owned(), secure, ttl_ms, sessions: Mutex::default(), pending: Mutex::default(), next_seq: Mutex::default() }
    }

    /// Starts a sign-in with `provider`. Returns the URL to send the person to and the
    /// `Set-Cookie` value of the pre-auth cookie, which binds the sign-in to this browser:
    /// it holds a hash of the state, and [`finish`](Self::finish) needs it back. The pending
    /// sign-in is kept by its state for ten minutes, and at most 1000 are kept (the oldest
    /// is dropped first).
    pub fn begin(&self, provider: &dyn IdentityProvider, callback_url: &str, now: AuthorityTime) -> Result<(String, String), PortalError> {
        let start = provider.start_sign_in(callback_url).map_err(|e| PortalError::Start(e.to_string()))?;
        let cookie = self.pre_auth_cookie(&state_hash(&start.pending.state), PENDING_TTL_MS / 1000);
        let seq = {
            let mut n = self.next_seq.lock().expect("lock");
            *n += 1;
            *n
        };
        let mut pending = self.pending.lock().expect("lock");
        pending.retain(|_, p| p.expires_at >= now);
        while pending.len() >= PENDING_CAP {
            let Some(oldest) = pending.iter().min_by_key(|(_, p)| p.seq).map(|(k, _)| k.clone()) else { break };
            pending.remove(&oldest);
        }
        let expires_at = now.checked_add(PENDING_TTL_MS).unwrap_or(AuthorityTime(u64::MAX));
        pending.insert(start.pending.state.clone(), Pending { sign_in: start.pending, expires_at, seq });
        Ok((start.redirect_to, cookie))
    }

    /// Finishes a sign-in from the callback's whole query and the request's `Cookie` header,
    /// which must carry the pre-auth cookie that [`begin`](Self::begin) set for this state.
    /// A pending sign-in is usable once and only within ten minutes. A callback that carries
    /// `error` is refused with a fixed message, never the provider's text. Returns the new
    /// session and the `Set-Cookie` value that carries it; the caller also sends
    /// [`clear_pre_auth_cookie`](Self::clear_pre_auth_cookie).
    pub fn finish(
        &self,
        provider: &dyn IdentityProvider,
        query: &BTreeMap<String, String>,
        cookie_header: Option<&str>,
        now: AuthorityTime,
    ) -> Result<(SessionId, String), PortalError> {
        let unknown = || PortalError::Refused("unknown or expired sign-in".to_owned());
        let state = query.get("state").ok_or_else(unknown)?;
        let bound = cookie_header.and_then(|h| cookie_value(h, &self.pre_auth_name())).is_some_and(|c| c == state_hash(state));
        if !bound {
            return Err(PortalError::Refused("this sign-in was not started in this browser".to_owned()));
        }
        let pending = self.pending.lock().expect("lock").remove(state).filter(|p| p.expires_at >= now).ok_or_else(unknown)?;
        if query.contains_key("error") {
            return Err(PortalError::Refused("the identity provider did not complete the sign-in".to_owned()));
        }
        let person = provider.finish_sign_in(&pending.sign_in, query).map_err(|e| PortalError::Refused(e.to_string()))?;
        let id = random_token();
        let expires_at = now.checked_add(self.ttl_ms).unwrap_or(AuthorityTime(u64::MAX));
        self.sessions.lock().expect("lock").insert(id.clone(), Session { person, csrf: random_token(), expires_at });
        let cookie = self.cookie(&id, self.ttl_ms / 1000);
        Ok((SessionId(id), cookie))
    }

    /// The session named by the request's `Cookie` header, after dropping expired ones.
    pub fn session(&self, cookie_header: Option<&str>, now: AuthorityTime) -> Option<SessionView> {
        let id = cookie_value(cookie_header?, &self.cookie_name)?;
        let mut sessions = self.sessions.lock().expect("lock");
        sessions.retain(|_, s| s.expires_at >= now);
        sessions.get(&id).map(|s| SessionView { id: SessionId(id.clone()), person: s.person.clone(), csrf: s.csrf.clone() })
    }

    /// Whether `submitted` is the session's CSRF token.
    pub fn check_csrf(&self, session: &SessionView, submitted: &str) -> bool {
        submitted == session.csrf
    }

    /// Ends a session.
    pub fn end(&self, id: &SessionId) {
        self.sessions.lock().expect("lock").remove(&id.0);
    }

    /// The `Set-Cookie` value that removes the session cookie.
    pub fn clear_cookie(&self) -> String {
        self.cookie("", 0)
    }

    /// The `Set-Cookie` value that removes the pre-auth cookie once a sign-in has finished.
    pub fn clear_pre_auth_cookie(&self) -> String {
        self.pre_auth_cookie("", 0)
    }

    fn pre_auth_name(&self) -> String {
        format!("{}_pre", self.cookie_name)
    }

    /// The pre-auth cookie: only the sign-in routes see it.
    fn pre_auth_cookie(&self, value: &str, max_age_s: u64) -> String {
        let secure = if self.secure { "; Secure" } else { "" };
        format!("{}={value}; Path=/sign-in; HttpOnly; SameSite=Lax; Max-Age={max_age_s}{secure}", self.pre_auth_name())
    }

    fn cookie(&self, value: &str, max_age_s: u64) -> String {
        let secure = if self.secure { "; Secure" } else { "" };
        format!("{}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_s}{secure}", self.cookie_name)
    }
}

/// The hash of a state, as the pre-auth cookie holds it.
fn state_hash(state: &str) -> String {
    base64url_encode(sha256(state.as_bytes()).as_bytes())
}

/// 32 random bytes from the operating system, base64url-encoded.
fn random_token() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("the operating system's random source");
    base64url_encode(&b)
}
