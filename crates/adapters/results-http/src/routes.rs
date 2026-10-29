//! The routes, and who may use them.

use fieldseal_adapters_portal::{Request, Response, SessionView};
use fieldseal_registration::domain::MethodAssurance;
use serde_json::json;

use crate::pages::{self, escape};
use crate::ResultsHttp;

impl ResultsHttp<'_> {
    /// Handles one request.
    pub fn handle(&self, req: &Request) -> Response {
        // A request for any other host (DNS rebinding, a stray proxy) is refused before a route.
        if !self.host_matches(req) {
            return Response::json(400, json!({ "error": "bad-host" }));
        }
        let get = req.method == "GET";
        let path = req.path.as_str();
        match (req.method.as_str(), path) {
            ("GET", "/") => self.home(req),
            ("GET", "/sign-in") => self.sign_in(),
            ("GET", "/sign-in/callback") => self.sign_in_callback(req),
            ("POST", "/sign-out") => self.sign_out(req),
            ("GET", "/results") => self.reader(req, true, |s, _| self.results_page(req, s)),
            ("GET", p) if p.starts_with("/results/exports/") => self.reader(req, false, |_, _| self.download(&p["/results/exports/".len()..])),
            _ if get => self.page(404, "Not found", "<p>There is no such page.</p>".into()),
            _ => Response::json(405, json!({ "error": "method-not-allowed" })),
        }
    }

    /// Whether the `Host` header names the host and port of the portal's public URL.
    fn host_matches(&self, req: &Request) -> bool {
        let (scheme, rest) = self.cfg.public_url.split_once("://").unwrap_or(("http", &self.cfg.public_url));
        let default_port = if scheme == "https" { 443 } else { 80 };
        let expected = rest.split('/').next().unwrap_or("");
        req.header("host").is_some_and(|h| host_port(h, default_port) == host_port(expected, default_port))
    }

    fn session(&self, req: &Request) -> Option<SessionView> {
        self.sessions.session(req.header("cookie"), self.clock.now())
    }

    pub(crate) fn page(&self, status: u16, title: &str, body: String) -> Response {
        Response::html(status, pages::shell(title, &body, None), &self.cfg.csp)
    }

    /// Runs `f` for a session that holds the reader role, with a phishing-resistant method
    /// when the settings ask for one. No session is a redirect to sign-in for a page and `401
    /// sign-in-required` for a download; a session that is not allowed is `403`.
    fn reader(&self, req: &Request, is_page: bool, f: impl FnOnce(&SessionView, &Request) -> Response) -> Response {
        let Some(session) = self.session(req) else {
            return if is_page {
                Response::new(302, "text/plain", vec![]).with("Location", "/sign-in".into())
            } else {
                Response::json(401, json!({ "error": "sign-in-required" }))
            };
        };
        let person = &session.person;
        if !person.role_names.contains(&self.cfg.reader_role) {
            return self.refusal("not-authorised", "Your account may not read results.");
        }
        let a = &person.authentication;
        if self.cfg.require_phishing_resistant && !(a.phishing_resistant && a.assurance == MethodAssurance::FromProvider) {
            return self.refusal("phishing-resistant-auth-required", "Results need a phishing-resistant sign-in, such as a passkey.");
        }
        f(&session, req)
    }

    fn refusal(&self, code: &str, why: &str) -> Response {
        let mut r = self.page(403, "Not allowed", format!("<p>{}</p><p><code>{}</code></p>", escape(why), escape(code)));
        // The body of a refusal is a page, but its code is also in a header for scripts.
        r.headers.push(("X-Fieldseal-Error".into(), code.into()));
        r
    }

    fn home(&self, req: &Request) -> Response {
        if self.session(req).is_some() {
            return Response::new(302, "text/plain", vec![]).with("Location", "/results".into());
        }
        self.page(200, "Results", "<p>Sign in to read the results of this authority.</p><p><a href=\"/sign-in\">Sign in</a></p>".into())
    }

    fn sign_in(&self) -> Response {
        let callback = format!("{}/sign-in/callback", self.cfg.public_url.trim_end_matches('/'));
        match self.sessions.begin(self.provider, &callback, self.clock.now()) {
            Ok((to, pre_auth)) => Response::new(302, "text/plain", vec![]).with("Location", to).with("Set-Cookie", pre_auth),
            Err(e) => self.page(503, "Sign-in unavailable", format!("<p>Sign-in could not start: {}</p>", escape(&e.to_string()))),
        }
    }

    fn sign_in_callback(&self, req: &Request) -> Response {
        match self.sessions.finish(self.provider, &req.query, req.header("cookie"), self.clock.now()) {
            Ok((_, cookie)) => {
                eprintln!("{{\"event\":\"results-sign-in\",\"ok\":true}}");
                Response::new(302, "text/plain", vec![]).with("Location", "/results".into()).with("Set-Cookie", cookie).with("Set-Cookie", self.sessions.clear_pre_auth_cookie())
            }
            Err(e) => {
                eprintln!("{{\"event\":\"results-sign-in\",\"ok\":false}}");
                self.page(401, "Sign-in failed", format!("<p>Sign-in failed: {}</p>", escape(&e.to_string())))
            }
        }
    }

    /// Ends the session of a request that carries the session's CSRF token (REG-092).
    fn sign_out(&self, req: &Request) -> Response {
        let Some(session) = self.session(req) else { return Response::new(302, "text/plain", vec![]).with("Location", "/".into()) };
        if !req.form().get("csrf").is_some_and(|c| self.sessions.check_csrf(&session, c)) {
            return self.page(403, "Not allowed", "<p>The sign-out request did not carry the session's token.</p>".into());
        }
        self.sessions.end(&session.id);
        Response::new(302, "text/plain", vec![]).with("Location", "/".into()).with("Set-Cookie", self.sessions.clear_cookie())
    }
}

/// The lower-cased host and the port of an authority (`host`, `host:port` or `[v6]:port`),
/// the port being `default_port` when it names none.
fn host_port(authority: &str, default_port: u16) -> (String, u16) {
    let a = authority.to_ascii_lowercase();
    match a.rsplit_once(':') {
        Some((host, port)) if !port.contains(']') => (host.to_owned(), port.parse().unwrap_or(0)),
        _ => (a, default_port),
    }
}
