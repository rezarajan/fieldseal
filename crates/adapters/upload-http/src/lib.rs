//! The HTTP upload adapter (ADR 0021, `docs/reference/spec/delivery.md`).
//!
//! Two halves of one protocol:
//!
//! - [`HttpUploadTransport`] is the runtime's [`UploadTransport`]: it asks an address to
//!   answer the receiver challenge and sends uploads with a proof-of-possession token. It
//!   has no base URL of its own. Every address it is given is an untrusted hint, and the
//!   caller decides whether to trust what answered (DEL-060, DEL-061).
//! - [`UploadHttp`] serves Intake's [`UploadService`] over HTTP. The endpoint's own base
//!   URLs, its receiver key and its limits come from the environment (factor III).
//!
//! | Method and path | Auth | Body | Answer |
//! |---|---|---|---|
//! | `POST /v1/challenge` | none | the challenge (WIRE-180, CBOR) | the receiver's answer (WIRE-181, CBOR) |
//! | `POST /v1/upload` | `Fieldseal-PoP` | an export file without parity | a CBOR array of receipts |
//! | `POST /v1/upload/outbox` | none; closing manifests are verified | an export file without parity | a CBOR array of receipts |
//!
//! `GET /healthz` and `GET /readyz` answer `200` with no authentication, for orchestrators; they
//! say the process is serving and nothing about its contents. The handler is built only after
//! the intake app's start-up replay, so `/readyz` is never `200` before replay has finished.
//!
//! Refusals are JSON: `401` for a token (DEL-003), `422` for a body the gate refused (with
//! its stage and code, no personal data), `400` for a malformed request, `503` when a
//! backing service failed and a retry may work (DEL-005). TLS is terminated in front.

use std::io::Read as _;
use std::time::Duration;

use fieldseal_collection::domain::ReceiptClaim;
use fieldseal_delivery::checks::receipts_from_response;
use fieldseal_delivery::domain::{AddressHint, AuthorisedDestination, POP_HEADER, ReceiverChallenge, ReceiverProof, UploadRequest, UploadRoute};
use fieldseal_delivery::ports::{UploadError, UploadTransport};
use fieldseal_intake::upload::{UploadRefusal, UploadService};
use fieldseal_kernel::time::AuthorityTime;

/// The largest answer the client reads from an endpoint.
pub const MAX_ANSWER: u64 = 1024 * 1024;

/// An HTTP request, decoupled from the server library.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Request {
    /// Upper-case method.
    pub method: String,
    /// The path, without the query.
    pub path: String,
    /// Headers, names lower-cased.
    pub headers: std::collections::BTreeMap<String, String>,
    /// The body.
    pub body: Vec<u8>,
}

/// An HTTP response.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Content type.
    pub content_type: &'static str,
    /// Body.
    pub body: Vec<u8>,
}

impl Response {
    fn cbor(body: Vec<u8>) -> Self {
        Self { status: 200, content_type: "application/cbor", body }
    }

    fn error(status: u16, error: &str, fields: &[(&str, &str)]) -> Self {
        let mut json = format!("{{\"error\":{}", quote(error));
        for (k, v) in fields {
            json.push_str(&format!(",{}:{}", quote(k), quote(v)));
        }
        json.push('}');
        Self { status, content_type: "application/json", body: json.into_bytes() }
    }
}

fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The endpoint's limits, from its environment.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ServerConfig {
    /// The largest request body accepted, in bytes.
    pub max_body: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { max_body: 64 * 1024 * 1024 }
    }
}

/// The upload endpoint over HTTP.
pub struct UploadHttp<'a, 'g> {
    service: &'a UploadService<'a, 'g>,
    now: Box<dyn Fn() -> AuthorityTime + 'a>,
    config: ServerConfig,
}

impl<'a, 'g> UploadHttp<'a, 'g> {
    /// The adapter over `service`, whose clock reads `now`.
    pub fn new(service: &'a UploadService<'a, 'g>, now: impl Fn() -> AuthorityTime + 'a, config: ServerConfig) -> Self {
        Self { service, now: Box::new(now), config }
    }

    /// Serves requests from `server` until it is closed, one at a time.
    pub fn run(&self, server: &tiny_http::Server) {
        for req in server.incoming_requests() {
            self.serve_one(req);
        }
    }

    /// Answers one request that `server` handed out, reading its body here. A process that
    /// must not wait on a slow client on its serving thread (the intake app) reads the body
    /// elsewhere, under a deadline, and calls [`answer`](Self::answer) instead.
    pub fn serve_one(&self, mut req: tiny_http::Request) {
        let mut body = Vec::new();
        let too_big = req.as_reader().take(self.config.max_body as u64 + 1).read_to_end(&mut body).is_err() || body.len() > self.config.max_body;
        let out = self.answer(&req, (!too_big).then_some(body));
        let _ = req.respond(out);
    }

    /// The largest request body this endpoint accepts.
    pub fn max_body(&self) -> usize {
        self.config.max_body
    }

    /// The answer to `req`, whose body was read already: `None` is a body that was too big.
    /// Does no I/O on `req`.
    pub fn answer(&self, req: &tiny_http::Request, body: Option<Vec<u8>>) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
        let headers = req.headers().iter().map(|h| (h.field.as_str().as_str().to_ascii_lowercase(), h.value.as_str().to_owned())).collect();
        let target = req.url().to_owned();
        let path = target.split('?').next().unwrap_or("").to_owned();
        let response = match body {
            None => Response::error(413, "too-large", &[]),
            Some(body) => self.handle(&Request { method: req.method().as_str().to_ascii_uppercase(), path, headers, body }),
        };
        let mut out = tiny_http::Response::from_data(response.body).with_status_code(response.status);
        for (k, v) in [("Content-Type", response.content_type), ("X-Content-Type-Options", "nosniff"), ("Cache-Control", "no-store")] {
            if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
                out.add_header(h);
            }
        }
        out
    }

    /// Handles one request.
    pub fn handle(&self, req: &Request) -> Response {
        if req.method == "GET" && req.path == "/healthz" {
            return Response { status: 200, content_type: "application/json", body: br#"{"status":"ok"}"#.to_vec() };
        }
        // The handler exists only after start-up replay has finished, so answering means ready.
        if req.method == "GET" && req.path == "/readyz" {
            return Response { status: 200, content_type: "application/json", body: br#"{"status":"ready"}"#.to_vec() };
        }
        let route = [UploadRoute::Challenge, UploadRoute::Tenancy, UploadRoute::Outbox].into_iter().find(|r| r.path() == req.path.trim_end_matches('/'));
        let Some(route) = route else { return Response::error(404, "not-found", &[]) };
        if req.method != "POST" {
            return Response::error(405, "method-not-allowed", &[]);
        }
        let now = (self.now)();
        let outcome = match route {
            UploadRoute::Challenge => self.service.answer_challenge(&req.body),
            UploadRoute::Tenancy => self
                .service
                .authenticate(req.headers.get("fieldseal-pop").map(String::as_str), &req.method, route, now)
                .and_then(|_| self.service.receive(&req.body, now)),
            UploadRoute::Outbox => self.service.receive(&req.body, now),
        };
        match outcome {
            Ok(body) => Response::cbor(body),
            Err(UploadRefusal::BadRequest(m)) => Response::error(400, "bad-request", &[("detail", &m)]),
            Err(UploadRefusal::TokenRejected(why)) => Response::error(401, "token-rejected", &[("detail", why)]),
            Err(UploadRefusal::Rejected { stage, code, detail }) => Response::error(422, "rejected", &[("stage", &stage), ("code", &code), ("detail", &detail)]),
            Err(UploadRefusal::Backend(_)) => Response::error(503, "unavailable", &[]),
        }
    }
}

/// How the client behaves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClientConfig {
    /// Whether plain `http://` addresses may be used. Off by default: an address is an
    /// untrusted hint, and the receiver challenge authorises the receiver, but carrying
    /// records over cleartext is still refused unless the deployment allows it (tests and
    /// loopback only).
    pub allow_http: bool,
    /// The whole-request timeout.
    pub timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self { allow_http: false, timeout: Duration::from_secs(60) }
    }
}

/// The runtime's [`UploadTransport`] over HTTP.
pub struct HttpUploadTransport {
    agent: ureq::Agent,
    config: ClientConfig,
}

impl HttpUploadTransport {
    /// A client with `config`.
    pub fn new(config: ClientConfig) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(config.timeout)).build().into();
        Self { agent, config }
    }

    fn post(&self, url: &str, pop: Option<&str>, body: &[u8]) -> Result<(u16, Vec<u8>), UploadError> {
        if url.starts_with("http://") && !self.config.allow_http {
            return Err(UploadError::Unreachable);
        }
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(UploadError::Unreachable);
        }
        let mut request = self.agent.post(url).header("Content-Type", "application/cbor");
        if let Some(p) = pop {
            request = request.header(POP_HEADER, p);
        }
        let mut response = request.send(body).map_err(|_| UploadError::Unreachable)?;
        let status = response.status().as_u16();
        let body = response.body_mut().with_config().limit(MAX_ANSWER).read_to_vec().map_err(|_| UploadError::Malformed("answer too large or cut off".into()))?;
        Ok((status, body))
    }
}

impl HttpUploadTransport {
    /// Uploads an export file (without parity) to the outbox route of the endpoint at
    /// `base_url` (`POST /v1/upload/outbox`: no token; the closing manifests are verified by
    /// the endpoint) and returns the receipts exactly as the endpoint signed them, one byte
    /// string each. The caller verifies them against its trust bundle (DEL-007).
    pub fn upload_outbox(&self, base_url: &str, export: &[u8]) -> Result<Vec<Vec<u8>>, UploadError> {
        let (status, body) = self.post(&UploadRoute::Outbox.url(base_url), None, export)?;
        match status {
            200 => match fieldseal_kernel::cbor::decode_limited(&body, MAX_ANSWER as usize) {
                Ok(fieldseal_kernel::Value::Array(items)) => items
                    .into_iter()
                    .map(|v| match v {
                        fieldseal_kernel::Value::Bytes(b) => Ok(b),
                        _ => Err(UploadError::Malformed("a receipt is a byte string".into())),
                    })
                    .collect(),
                _ => Err(UploadError::Malformed("an upload response is an array".into())),
            },
            502..=504 => Err(UploadError::Unreachable),
            s => Err(UploadError::Rejected(format!("status {s}: {}", String::from_utf8_lossy(&body)))),
        }
    }
}

impl UploadTransport for HttpUploadTransport {
    fn challenge(&self, address: &AddressHint, challenge: &ReceiverChallenge) -> Result<ReceiverProof, UploadError> {
        let (status, body) = self.post(&UploadRoute::Challenge.url(&address.address), None, &challenge.encode())?;
        match status {
            200 => ReceiverProof::decode(&body).map_err(|e| UploadError::Malformed(e.to_string())),
            502..=504 => Err(UploadError::Unreachable),
            s => Err(UploadError::Rejected(format!("status {s}"))),
        }
    }

    fn upload(&self, destination: &AuthorisedDestination, request: &UploadRequest) -> Result<Vec<ReceiptClaim>, UploadError> {
        let url = request.route.url(&destination.address().address);
        let header = request.pop.as_ref().map(|p| p.to_header());
        let (status, body) = self.post(&url, header.as_deref(), &request.body)?;
        match status {
            200 => receipts_from_response(&body).map_err(|e| UploadError::Malformed(e.to_string())),
            401 => Err(UploadError::TokenRejected),
            502..=504 => Err(UploadError::Unreachable),
            s => Err(UploadError::Rejected(format!("status {s}: {}", String::from_utf8_lossy(&body)))),
        }
    }
}
