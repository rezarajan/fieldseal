//! An HTTP request and response, decoupled from the server library, and the decoders for
//! form and multipart bodies.

use std::collections::BTreeMap;

use serde_json::Value as Json;

/// An HTTP request, decoupled from the server library.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Request {
    /// Upper-case method.
    pub method: String,
    /// The path, without the query.
    pub path: String,
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
        Self { method: method.to_ascii_uppercase(), path: path.to_owned(), query: parse_form(q), headers, body }
    }

    /// The header `name` (lower-case), if present.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// The value of cookie `name`, if the request carries it.
    pub fn cookie(&self, name: &str) -> Option<String> {
        cookie_value(self.header("cookie")?, name)
    }

    /// The body decoded as `application/x-www-form-urlencoded`.
    pub fn form(&self) -> BTreeMap<String, String> {
        parse_form(&String::from_utf8_lossy(&self.body))
    }
}

/// The value of cookie `name` in a `Cookie` header.
pub(crate) fn cookie_value(header: &str, name: &str) -> Option<String> {
    header.split(';').filter_map(|c| c.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.to_owned())
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
    /// A response with a content type and a body.
    pub fn new(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Self { status, headers: vec![("Content-Type".into(), content_type.into())], body }
    }

    /// A JSON response.
    pub fn json(status: u16, value: Json) -> Self {
        Self::new(status, "application/json", value.to_string().into_bytes())
    }

    /// An HTML page, never cached, with the app's own content-security policy `csp`.
    pub fn html(status: u16, body: String, csp: &str) -> Self {
        let mut r = Self::new(status, "text/html; charset=utf-8", body.into_bytes());
        r.headers.push(("Content-Security-Policy".into(), csp.into()));
        r.headers.push(("Cache-Control".into(), "no-store".into()));
        r
    }

    /// A `303 See Other` to `location`.
    pub fn redirect(location: &str) -> Self {
        let mut r = Self::new(303, "text/plain", vec![]);
        r.headers.push(("Location".into(), location.into()));
        r
    }

    /// The response with one more header.
    pub fn with(mut self, name: &str, value: String) -> Self {
        self.headers.push((name.into(), value));
        self
    }
}

/// Decodes `application/x-www-form-urlencoded` (also used for query strings).
pub fn parse_form(s: &str) -> BTreeMap<String, String> {
    s.split('&').filter(|kv| !kv.is_empty()).map(|kv| kv.split_once('=').unwrap_or((kv, ""))).map(|(k, v)| (unescape(k), unescape(v))).collect()
}

fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The bytes of form field `name` in a `multipart/form-data` body.
pub fn multipart_field(req: &Request, name: &str) -> Option<Vec<u8>> {
    let ct = req.header("content-type")?;
    let boundary = ct.split(';').find_map(|p| p.trim().strip_prefix("boundary="))?.trim_matches('"');
    let delimiter = format!("--{boundary}").into_bytes();
    let body = &req.body;
    let mut parts = Vec::new();
    let mut start = 0;
    while let Some(pos) = find(&body[start..], &delimiter) {
        parts.push(start + pos);
        start += pos + delimiter.len();
    }
    for w in parts.windows(2) {
        let part = &body[w[0] + delimiter.len()..w[1]];
        let part = part.strip_prefix(b"\r\n").unwrap_or(part);
        let split = find(part, b"\r\n\r\n")?;
        let head = String::from_utf8_lossy(&part[..split]);
        let content = &part[split + 4..];
        let content = content.strip_suffix(b"\r\n").unwrap_or(content);
        let named = head.lines().any(|l| {
            l.to_ascii_lowercase().starts_with("content-disposition:") && l.contains(&format!("name=\"{name}\""))
        });
        if named {
            return Some(content.to_vec());
        }
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
