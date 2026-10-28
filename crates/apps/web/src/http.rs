//! A tiny request/response model decoupled from the server library (so every route is tested
//! without sockets), the security headers, and the reverse proxy to the other services.

use std::collections::BTreeMap;
use std::time::Duration;

/// The largest request body accepted.
pub const MAX_BODY: usize = 1024 * 1024;

/// The largest body accepted by `POST /intake/ingest`, where a whole export file arrives.
/// The server loop should use this limit for that route and [`MAX_BODY`] elsewhere.
pub const MAX_INGEST_BODY: usize = 32 * 1024 * 1024;

/// The Content-Security-Policy of the app's own pages. The instrument page in the frame
/// carries its own `<meta>` policy and gets no header.
pub const PAGE_CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src 'self'; form-action 'self'; base-uri 'none'";

/// An HTTP request.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Request {
    /// Upper-case method.
    pub method: String,
    /// The path, without the query.
    pub path: String,
    /// The query exactly as received (no leading `?`).
    pub raw_query: String,
    /// Decoded query parameters.
    pub query: BTreeMap<String, String>,
    /// Headers, names lower-cased.
    pub headers: BTreeMap<String, String>,
    /// The body.
    pub body: Vec<u8>,
}

impl Request {
    /// Parses a request target into path and query.
    pub fn new(method: &str, target: &str, headers: BTreeMap<String, String>, body: Vec<u8>) -> Self {
        let (path, q) = target.split_once('?').unwrap_or((target, ""));
        Self { method: method.to_ascii_uppercase(), path: path.to_owned(), raw_query: q.to_owned(), query: parse_query(q), headers, body }
    }

    /// A `GET` of `target`, for tests and internal use.
    pub fn get(target: &str) -> Self {
        Self::new("GET", target, BTreeMap::new(), Vec::new())
    }

    /// The non-empty query parameter `name`.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(String::as_str).filter(|v| !v.is_empty())
    }
}

/// Decodes `a=b&c=d` (percent-escapes and `+`).
pub fn parse_query(s: &str) -> BTreeMap<String, String> {
    s.split('&').filter(|kv| !kv.is_empty()).map(|kv| kv.split_once('=').unwrap_or((kv, ""))).map(|(k, v)| (unescape(k), unescape(v))).collect()
}

fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if b.len() >= i + 3 => match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                Ok(v) => {
                    out.push(v);
                    i += 2;
                }
                Err(_) => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encodes `s` for a query value.
pub fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for &c in s.as_bytes() {
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~') {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

/// An HTTP response.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Headers.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl Response {
    /// A response with a content type.
    pub fn new(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Self { status, headers: vec![("Content-Type".into(), content_type.into())], body }
    }

    /// An app page: HTML with the page policy.
    pub fn page(status: u16, body: String) -> Self {
        Self::new(status, "text/html; charset=utf-8", body.into_bytes()).with("Content-Security-Policy", PAGE_CSP)
    }

    /// An HTML document that carries its own policy (the instrument page): bytes untouched,
    /// no header policy.
    pub fn document(body: String) -> Self {
        Self::new(200, "text/html; charset=utf-8", body.into_bytes())
    }

    /// Plain text.
    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Self::new(status, "text/plain; charset=utf-8", body.into().into_bytes())
    }

    /// JSON text.
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self::new(status, "application/json", body.into().into_bytes())
    }

    /// A redirect to `location`.
    pub fn redirect(location: &str) -> Self {
        Self::new(303, "text/plain; charset=utf-8", Vec::new()).with("Location", location)
    }

    /// Adds a header.
    pub fn with(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// The first header called `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The body as text.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Adds the headers every response carries.
    pub fn secured(mut self) -> Self {
        for (k, v) in [("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"), ("Cache-Control", "no-store")] {
            if self.header(k).is_none() {
                self.headers.push((k.to_owned(), v.to_owned()));
            }
        }
        self
    }
}

/// Forwards `req` to `upstream_base`, with the part of the path after `prefix` and the query.
/// Only `Content-Type`, `Fieldseal-PoP` and `Authorization` are forwarded; the status, body
/// and content type come back. An unreachable upstream is a 502 with a plain JSON error.
pub fn proxy(upstream_base: &str, req: &Request, prefix: &str) -> Response {
    let suffix = req.path.strip_prefix(prefix).unwrap_or("");
    let mut url = format!("{}{}", upstream_base.trim_end_matches('/'), suffix);
    if !req.raw_query.is_empty() {
        url.push('?');
        url.push_str(&req.raw_query);
    }
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(15))).build().into();
    let mut builder = ureq::http::Request::builder().method(req.method.as_str()).uri(url.as_str());
    for name in ["content-type", "fieldseal-pop", "authorization"] {
        if let Some(v) = req.headers.get(name) {
            builder = builder.header(name, v.as_str());
        }
    }
    let unreachable = || Response::json(502, "{\"error\":\"upstream-unreachable\"}");
    let Ok(request) = builder.body(req.body.clone()) else { return unreachable() };
    match agent.run(request) {
        Ok(mut resp) => {
            let status = resp.status().as_u16();
            let content_type = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("application/octet-stream").to_owned();
            match resp.body_mut().read_to_vec() {
                Ok(body) => Response::new(status, &content_type, body),
                Err(_) => unreachable(),
            }
        }
        Err(_) => unreachable(),
    }
}

