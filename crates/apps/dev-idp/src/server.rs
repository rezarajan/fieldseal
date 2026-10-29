//! The four routes, on Keycloak's paths under `/realms/fieldseal`, so that a client reads
//! only the discovery document and its configuration is the same against this provider and
//! against Keycloak:
//!
//! | Route | |
//! |---|---|
//! | `GET  /realms/fieldseal/.well-known/openid-configuration` | discovery |
//! | `GET  /realms/fieldseal/protocol/openid-connect/auth` | authorization code with PKCE `S256` |
//! | `POST /realms/fieldseal/protocol/openid-connect/token` | the code exchange |
//! | `GET  /realms/fieldseal/protocol/openid-connect/certs` | the key set |
//!
//! There is no password and no consent: the person picks a login on a page, or `login_hint`
//! names one and approves at once. That is the only thing that differs from a real provider.

use std::collections::{BTreeMap, HashMap};
use std::io::{Cursor, Read as _};
use std::sync::Mutex;

use base64::Engine as _;
use fieldseal_kernel::base64url::base64url_encode;
use fieldseal_kernel::digest::sha256;
use serde_json::{Value, json};
use tiny_http::{Header, Method, Request, Response};

use crate::config::{Client, Config, Login};
use crate::tokens::{LIFETIME, Signer, now, random_b64};

type Reply = Response<Cursor<Vec<u8>>>;

/// The largest request body read at the token endpoint.
const MAX_BODY: u64 = 16 * 1024;
/// How long an authorization code can be exchanged, in seconds.
const CODE_LIFETIME: u64 = 60;

/// An authorization code that was issued and not yet exchanged.
struct Grant {
    client: String,
    redirect_uri: String,
    challenge: String,
    nonce: Option<String>,
    scope: String,
    login: usize,
    expires: u64,
}

/// What the routes share.
pub struct Provider {
    issuer: String,
    config: Config,
    signer: Signer,
    grants: Mutex<HashMap<String, Grant>>,
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("a valid header")
}

fn reply(status: u16, content_type: &str, body: String) -> Reply {
    Response::from_string(body)
        .with_status_code(status)
        .with_header(header("Content-Type", content_type))
        .with_header(header("Cache-Control", "no-store"))
}

fn json_reply(status: u16, body: &Value) -> Reply {
    reply(status, "application/json", body.to_string())
}

fn page(status: u16, title: &str, body: &str) -> Reply {
    let html = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>{t}</title></head><body>\n<h1>{t}</h1>\n{body}\n<p><small>Development identity provider. Not for production.</small></p>\n</body></html>\n",
        t = html_escape(title)
    );
    reply(status, "text/html; charset=utf-8", html)
}

fn redirect(to: &str) -> Reply {
    reply(302, "text/plain", String::new()).with_header(header("Location", to))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// Percent-encodes a query or form component (RFC 3986 unreserved characters kept).
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Decodes a query or form component (`+` is a space). `None` for a bad escape.
fn decode(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = s.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// Reads `a=b&c=d`. A repeated name or a bad escape is `None`.
fn parse_form(s: &str) -> Option<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for pair in s.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if map.insert(decode(k)?, decode(v)?).is_some() {
            return None;
        }
    }
    Some(map)
}

fn query_string(params: &[(&str, &str)]) -> String {
    params.iter().map(|(k, v)| format!("{}={}", encode(k), encode(v))).collect::<Vec<_>>().join("&")
}

fn append_query(uri: &str, params: &[(&str, &str)]) -> String {
    format!("{uri}{}{}", if uri.contains('?') { '&' } else { '?' }, query_string(params))
}

/// Whether two secrets are equal, without stopping at the first difference.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// `http://127.0.0.1:<port>/...`: the loopback redirect a native app uses (RFC 8252 section 7.3).
fn loopback_redirect(uri: &str) -> bool {
    let Some(rest) = uri.strip_prefix("http://127.0.0.1:") else { return false };
    let Some((port, path)) = rest.split_once('/') else { return false };
    !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit()) && !path.contains('#')
}

impl Provider {
    /// A provider for `issuer` with a new signing key.
    pub fn new(issuer: String, config: Config) -> Self {
        Self { issuer, config, signer: Signer::generate(), grants: Mutex::new(HashMap::new()) }
    }

    /// The issuer URL.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    fn endpoint(&self, name: &str) -> String {
        format!("{}/protocol/openid-connect/{name}", self.issuer)
    }

    /// Answers one request.
    pub fn handle(&self, request: &mut Request) -> Reply {
        let url = request.url().to_owned();
        let (path, query) = url.split_once('?').unwrap_or((&url, ""));
        let Some(route) = path.strip_prefix("/realms/fieldseal/") else {
            return page(404, "Not found", "<p>This development provider serves the realm <code>fieldseal</code> only.</p>");
        };
        match (request.method(), route) {
            (Method::Get, ".well-known/openid-configuration") => self.discovery(),
            (Method::Get, "protocol/openid-connect/certs") => json_reply(200, &json!({ "keys": [self.signer.jwk()] })),
            (Method::Get, "protocol/openid-connect/auth") => match parse_form(query) {
                Some(params) => self.authorize(&params),
                None => page(400, "Bad request", "<p>The query is not valid.</p>"),
            },
            (Method::Post, "protocol/openid-connect/token") => {
                let authorization = request.headers().iter().find(|h| h.field.equiv("Authorization")).map(|h| h.value.as_str().to_owned());
                let mut body = Vec::new();
                if request.as_reader().take(MAX_BODY + 1).read_to_end(&mut body).is_err() || body.len() as u64 > MAX_BODY {
                    return json_reply(400, &json!({ "error": "invalid_request", "error_description": "the body is unreadable or too large" }));
                }
                match std::str::from_utf8(&body).ok().and_then(parse_form) {
                    Some(form) => self.token(&form, authorization.as_deref()),
                    None => json_reply(400, &json!({ "error": "invalid_request", "error_description": "the body is not a form" })),
                }
            }
            _ => page(404, "Not found", "<p>No such route.</p>"),
        }
    }

    fn discovery(&self) -> Reply {
        json_reply(
            200,
            &json!({
                "issuer": self.issuer,
                "authorization_endpoint": self.endpoint("auth"),
                "token_endpoint": self.endpoint("token"),
                "jwks_uri": self.endpoint("certs"),
                "response_types_supported": ["code"],
                "response_modes_supported": ["query"],
                "grant_types_supported": ["authorization_code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["ES256"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
                "scopes_supported": ["openid"],
                "authorization_response_iss_parameter_supported": true,
            }),
        )
    }

    fn client(&self, id: &str) -> Option<&Client> {
        self.config.clients.iter().find(|c| c.id == id)
    }

    /// The authorization endpoint. A client or redirect URI that is not registered gets an
    /// error page and no redirect; any other problem goes back to the client as `error`.
    fn authorize(&self, params: &BTreeMap<String, String>) -> Reply {
        let get = |k: &str| params.get(k).map(String::as_str).unwrap_or("");
        let Some(client) = self.client(get("client_id")) else {
            return page(400, "Unknown client", "<p>The client id is not registered.</p>");
        };
        let redirect_uri = get("redirect_uri");
        if !(client.redirect_uris.iter().any(|u| u == redirect_uri) || client.is_public() && loopback_redirect(redirect_uri)) {
            return page(400, "Unregistered redirect URI", "<p>The redirect URI is not registered for this client.</p>");
        }
        let state = get("state");
        let fail = |error: &str, why: &str| redirect(&append_query(redirect_uri, &[("error", error), ("error_description", why), ("state", state), ("iss", &self.issuer)]));
        if get("response_type") != "code" {
            return fail("unsupported_response_type", "only the authorization code flow is served");
        }
        if get("code_challenge").is_empty() || get("code_challenge_method") != "S256" {
            return fail("invalid_request", "PKCE with code_challenge_method=S256 is required");
        }
        let hint = get("login_hint");
        let Some(login) = self.config.logins.iter().position(|l| l.login == hint) else {
            return self.login_page(params);
        };
        let code = random_b64(24);
        let mut grants = self.grants.lock().expect("lock");
        grants.retain(|_, g| g.expires > now());
        grants.insert(
            code.clone(),
            Grant {
                client: client.id.clone(),
                redirect_uri: redirect_uri.to_owned(),
                challenge: get("code_challenge").to_owned(),
                nonce: params.get("nonce").cloned(),
                scope: if get("scope").is_empty() { "openid".to_owned() } else { get("scope").to_owned() },
                login,
                expires: now() + CODE_LIFETIME,
            },
        );
        redirect(&append_query(redirect_uri, &[("code", &code), ("state", state), ("iss", &self.issuer)]))
    }

    /// The page that lists the logins; each link repeats the request with `login_hint`.
    fn login_page(&self, params: &BTreeMap<String, String>) -> Reply {
        let rest: Vec<(&str, &str)> = params.iter().filter(|(k, _)| *k != "login_hint").map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let items: String = self
            .config
            .logins
            .iter()
            .map(|l: &Login| {
                let mut with_hint = rest.clone();
                with_hint.push(("login_hint", &l.login));
                format!(
                    "<li><a href=\"{}\">{}</a> (roles: {})</li>",
                    html_escape(&format!("{}?{}", self.endpoint("auth"), query_string(&with_hint))),
                    html_escape(&l.login),
                    html_escape(&l.roles.join(", "))
                )
            })
            .collect();
        page(200, "Sign in", &format!("<p>Choose a login. There is no password.</p>\n<ul>\n{items}\n</ul>"))
    }

    fn invalid_client() -> Reply {
        json_reply(401, &json!({ "error": "invalid_client" })).with_header(header("WWW-Authenticate", "Basic realm=\"fieldseal\""))
    }

    /// The token endpoint: the code exchange. A code is used once, whether or not the
    /// exchange succeeds.
    fn token(&self, form: &BTreeMap<String, String>, authorization: Option<&str>) -> Reply {
        let get = |k: &str| form.get(k).map(String::as_str).unwrap_or("");
        let (id, secret) = match authorization {
            Some(a) => {
                let credentials = a
                    .strip_prefix("Basic ")
                    .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b.trim()).ok())
                    .and_then(|b| String::from_utf8(b).ok())
                    .and_then(|c| c.split_once(':').and_then(|(i, s)| Some((decode(i)?, decode(s)?))));
                let Some((id, secret)) = credentials else { return Self::invalid_client() };
                if form.get("client_id").is_some_and(|c| *c != id) {
                    return Self::invalid_client();
                }
                (id, Some(secret))
            }
            None => (get("client_id").to_owned(), None),
        };
        let Some(client) = self.client(&id) else { return Self::invalid_client() };
        match (&client.secret, &secret) {
            (Some(expected), Some(given)) if same(expected, given) => {}
            (None, None) => {}
            _ => return Self::invalid_client(),
        }
        let grant = self.grants.lock().expect("lock").remove(get("code"));
        if get("grant_type") != "authorization_code" {
            return json_reply(400, &json!({ "error": "unsupported_grant_type" }));
        }
        let invalid_grant = |why: &str| json_reply(400, &json!({ "error": "invalid_grant", "error_description": why }));
        let Some(grant) = grant.filter(|g| g.expires > now()) else { return invalid_grant("the code is unknown, used or expired") };
        if grant.client != client.id || grant.redirect_uri != get("redirect_uri") {
            return invalid_grant("the code was issued to another client or redirect URI");
        }
        let verifier = get("code_verifier");
        if verifier.is_empty() || !same(&base64url_encode(sha256(verifier.as_bytes()).as_bytes()), &grant.challenge) {
            return invalid_grant("the code verifier does not match the code challenge");
        }
        let login = &self.config.logins[grant.login];
        json_reply(
            200,
            &json!({
                "access_token": self.signer.access_token(&self.issuer, &self.config.api_audience, &client.id, login, &grant.scope),
                "token_type": "Bearer",
                "expires_in": LIFETIME,
                "id_token": self.signer.id_token(&self.issuer, &client.id, login, grant.nonce.as_deref()),
                "scope": grant.scope,
            }),
        )
        .with_header(header("Pragma", "no-cache"))
    }
}
