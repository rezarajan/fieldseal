//! Server-side portal sessions: the session store, the pending sign-ins, the session
//! cookie and the per-session CSRF token (REG-092).

use std::collections::BTreeMap;
use std::sync::Mutex;

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
    pending: Mutex<BTreeMap<String, PendingSignIn>>,
}

impl PortalSessions {
    /// A store whose sessions live `ttl_ms` milliseconds, in a cookie called `cookie_name`
    /// (`Secure` when `secure`). Two portals on one host use two names so their cookies do
    /// not mix.
    pub fn new(cookie_name: &str, secure: bool, ttl_ms: u64) -> Self {
        Self { cookie_name: cookie_name.to_owned(), secure, ttl_ms, sessions: Mutex::default(), pending: Mutex::default() }
    }

    /// Starts a sign-in with `provider` and returns the URL to send the person to. The
    /// pending sign-in is kept by its state until the callback arrives.
    pub fn begin(&self, provider: &dyn IdentityProvider, callback_url: &str) -> Result<String, PortalError> {
        let start = provider.start_sign_in(callback_url).map_err(|e| PortalError::Start(e.to_string()))?;
        self.pending.lock().expect("lock").insert(start.pending.state.clone(), start.pending);
        Ok(start.redirect_to)
    }

    /// Finishes a sign-in from the callback's whole query. A pending sign-in is usable once.
    /// Returns the new session and the `Set-Cookie` value that carries it.
    pub fn finish(
        &self,
        provider: &dyn IdentityProvider,
        query: &BTreeMap<String, String>,
        now: AuthorityTime,
    ) -> Result<(SessionId, String), PortalError> {
        let pending = query.get("state").and_then(|s| self.pending.lock().expect("lock").remove(s));
        let person = match pending {
            Some(p) => provider.finish_sign_in(&p, query).map_err(|e| PortalError::Refused(e.to_string()))?,
            None => return Err(PortalError::Refused("unknown or expired sign-in".to_owned())),
        };
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

    fn cookie(&self, value: &str, max_age_s: u64) -> String {
        let secure = if self.secure { "; Secure" } else { "" };
        format!("{}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_s}{secure}", self.cookie_name)
    }
}

/// 32 random bytes from the operating system, base64url-encoded.
fn random_token() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("the operating system's random source");
    base64url_encode(&b)
}
