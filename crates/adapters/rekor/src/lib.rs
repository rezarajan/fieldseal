//! A Sigstore Rekor adapter for the Publishing context's [`TransparencyLog`] port
//! (ADR 0030, PUB-100–106).
//!
//! Every [`LogEntry`] is logged as a Rekor `hashedrekord` v0.0.1 entry, the minimal
//! hash-only type (PUB-105): the statement digest as `sha256` hex, the signature as base64
//! DER and the publisher key as base64 PEM. No optional field is set; the entry type is
//! not sent (it is inside the statement the digest commits to). The request body is
//! exactly the leaf Rekor logs, so a consumer recomputes the leaf from the entry with
//! [`LeafFormat::HashedRekord`] and verifies the inclusion proof offline against the
//! checkpoint signed by the log key pinned in its trust bundle.
//!
//! The adapter has two parts, so that what leaves the process can be recorded:
//! - [`RekorLog`] builds one [`Transmission`] per request and parses and checks the
//!   answers (body, proof and checkpoint must agree, sizes are bounded);
//! - [`HttpTransport`] renders a transmission to exactly one HTTP request with
//!   [`render`], adding nothing but fixed protocol constants, and sends it.
//!
//! **Configuration** (twelve-factor III): the log's base URL comes from configuration,
//! `FIELDSEAL_REKOR_URL` through [`RekorConfig::from_env`]. No URL is built in.
//!
//! **Tests never contact a public log.** This crate's tests run against a local mock HTTP
//! server on `127.0.0.1`; nothing in them reaches the network.
//!
//! The HTTP client is `ureq`: a small, blocking, pure-Rust HTTP/1.1 client with rustls,
//! and no async runtime, which suits the synchronous CLI that drives publishing. Redirects
//! are not followed, so a request is never re-sent somewhere else.

use std::time::Duration;

use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::id::Digest;
use fieldseal_publishing::domain::encoding::{base64_decode, base64_encode, hex_decode, p256_pem};
use fieldseal_publishing::domain::merkle::{MAX_PATH, leaf_hash, verify_inclusion};
use fieldseal_publishing::domain::statement::entry_signature_der;
use fieldseal_publishing::domain::{
    ConsistencyProof, InclusionProof, LeafFormat, LogEntry, SignedCheckpoint, hashedrekord_json,
};
use fieldseal_publishing::ports::{LogError, LogRequest, LogTransport, LoggedEntry, Transmission, TransparencyLog};
use serde_json::Value as Json;

/// The environment variable holding the Rekor base URL.
pub const URL_VAR: &str = "FIELDSEAL_REKOR_URL";

/// The largest response accepted by default: 1 MiB.
pub const DEFAULT_MAX_RESPONSE: u64 = 1024 * 1024;

/// Why a [`RekorConfig`] couldn't be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The base URL is not set.
    #[error("{URL_VAR} is not set")]
    Missing,
    /// The base URL is not an `http` or `https` URL without a query or fragment.
    #[error("invalid Rekor base URL: {0}")]
    Invalid(String),
}

/// How to reach a Rekor instance.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RekorConfig {
    base_url: String,
    /// The timeout for one whole request.
    pub timeout: Duration,
    /// The largest response body accepted.
    pub max_response: u64,
}

impl RekorConfig {
    /// A configuration for `base_url` (for example `https://rekor.example.org`), with a
    /// 30-second timeout and [`DEFAULT_MAX_RESPONSE`].
    pub fn new(base_url: &str) -> Result<Self, ConfigError> {
        let url = base_url.trim().trim_end_matches('/');
        let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"));
        match rest {
            Some(host) if !host.is_empty() && !host.contains(['?', '#', ' ', '@']) => {}
            _ => return Err(ConfigError::Invalid(base_url.to_owned())),
        }
        Ok(Self { base_url: url.to_owned(), timeout: Duration::from_secs(30), max_response: DEFAULT_MAX_RESPONSE })
    }

    /// Reads [`URL_VAR`] through `lookup` (the environment, or a test's map).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        Self::new(&lookup(URL_VAR).ok_or(ConfigError::Missing)?)
    }

    /// Reads [`URL_VAR`] from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// The base URL, without a trailing slash.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

/// An HTTP method.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Method {
    /// `GET`
    Get,
    /// `POST`
    Post,
}

/// One HTTP request, as [`render`] builds it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HttpRequest {
    /// The method.
    pub method: Method,
    /// The full URL.
    pub url: String,
    /// The JSON body, for `POST`.
    pub body: Option<Vec<u8>>,
}

fn field<'t>(t: &'t Transmission, name: &str) -> Result<&'t [u8], LogError> {
    let mut values = t.fields.iter().filter(|(n, _)| n == name);
    match (values.next(), values.next()) {
        (Some((_, v)), None) => Ok(v),
        _ => Err(LogError::Malformed(format!("transmission needs exactly one `{name}` field"))),
    }
}

/// Renders a transmission as exactly one HTTP request to Rekor's v1 API. An append must
/// carry exactly the fields `digest` (lowercase hex), `signature` (DER) and `publicKey`
/// (PEM), which become the `hashedrekord` body; every other request carries no fields.
pub fn render(base_url: &str, t: &Transmission) -> Result<HttpRequest, LogError> {
    let get = |path: String| {
        if t.fields.is_empty() {
            Ok(HttpRequest { method: Method::Get, url: format!("{base_url}{path}"), body: None })
        } else {
            Err(LogError::Malformed("lookups carry no fields".into()))
        }
    };
    match t.request {
        LogRequest::Append => {
            if t.fields.len() != 3 {
                return Err(LogError::Malformed("an append carries exactly three fields".into()));
            }
            let digest = field(t, "digest")?;
            if digest.len() != 64 || hex_decode(core::str::from_utf8(digest).unwrap_or("")).is_none() {
                return Err(LogError::Malformed("digest must be 64 lowercase hex digits".into()));
            }
            let body = format!(
                concat!(
                    r#"{{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{{"data":{{"hash":{{"algorithm":"sha256","value":"{}"}}}},"#,
                    r#""signature":{{"content":"{}","publicKey":{{"content":"{}"}}}}}}}}"#
                ),
                core::str::from_utf8(digest).expect("checked above"),
                base64_encode(field(t, "signature")?),
                base64_encode(field(t, "publicKey")?),
            );
            Ok(HttpRequest {
                method: Method::Post,
                url: format!("{base_url}/api/v1/log/entries"),
                body: Some(body.into_bytes()),
            })
        }
        LogRequest::Checkpoint => get("/api/v1/log".into()),
        LogRequest::Inclusion { leaf_index, .. } => get(format!("/api/v1/log/entries?logIndex={leaf_index}")),
        LogRequest::Consistency { old_size, new_size } => {
            get(format!("/api/v1/log/proof?firstSize={old_size}&lastSize={new_size}"))
        }
        LogRequest::Entries { .. } => Err(LogError::Unavailable("Rekor lists entries through its own API".into())),
    }
}

/// A [`LogTransport`] that sends each transmission to Rekor over HTTP(S).
///
/// Headers are fixed: `Accept: application/json`, `Content-Type: application/json` on
/// appends, and `User-Agent: fieldseal`; nothing about the artefact is ever in a header,
/// path or query.
pub struct HttpTransport {
    config: RekorConfig,
    agent: ureq::Agent,
}

impl HttpTransport {
    /// A transport for `config`.
    pub fn new(config: RekorConfig) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(config.timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent("fieldseal")
            .build()
            .into();
        Self { config, agent }
    }
}

/// The UUID of the entry a `409 Conflict` names: the last segment of its `Location` header,
/// or else the last hexadecimal word of the error message. Only 64 to 80 hex digits are
/// accepted, so nothing else can reach the follow-up request's path.
fn existing_uuid(location: Option<&str>, body: &[u8]) -> Option<String> {
    let is_uuid = |s: &str| (64..=80).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit());
    let from_location = location.and_then(|l| l.rsplit('/').next()).filter(|s| is_uuid(s));
    let from_body = || {
        let text = core::str::from_utf8(body).ok()?;
        text.split(|c: char| !c.is_ascii_hexdigit()).rfind(|w| is_uuid(w)).map(str::to_owned)
    };
    from_location.map(str::to_owned).or_else(from_body)
}

/// One HTTP answer: status, `Location` header and body.
type Answer = (u16, Option<String>, Vec<u8>);

impl HttpTransport {
    fn read(&self, mut response: ureq::http::Response<ureq::Body>) -> Result<Answer, LogError> {
        let status = response.status().as_u16();
        let location = response.headers().get("location").and_then(|v| v.to_str().ok()).map(str::to_owned);
        let body = response.body_mut().with_config().limit(self.config.max_response).read_to_vec().map_err(|e| match e {
            ureq::Error::BodyExceedsLimit(_) => LogError::Oversized,
            e => LogError::Unavailable(e.to_string()),
        })?;
        Ok((status, location, body))
    }

    fn get(&self, url: &str) -> Result<Answer, LogError> {
        let response =
            self.agent.get(url).header("Accept", "application/json").call().map_err(|e| LogError::Unavailable(e.to_string()))?;
        self.read(response)
    }
}

impl LogTransport for HttpTransport {
    fn send(&self, transmission: &Transmission) -> Result<Vec<u8>, LogError> {
        let request = render(self.config.base_url(), transmission)?;
        let (status, location, body) = match (request.method, request.body) {
            (Method::Post, Some(body)) => {
                let response = self
                    .agent
                    .post(&request.url)
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .send(&body[..])
                    .map_err(|e| LogError::Unavailable(e.to_string()))?;
                self.read(response)?
            }
            _ => self.get(&request.url)?,
        };
        if status == 409 && request.method == Method::Post {
            // Already logged: fetch the existing entry. `RekorLog` checks it is this entry
            // (body and inclusion proof) exactly as it does a fresh answer, so a 409 is
            // success only if the log really holds this entry.
            let uuid = existing_uuid(location.as_deref(), &body)
                .ok_or_else(|| LogError::Malformed("HTTP 409 without the existing entry's UUID".into()))?;
            let (status, _, body) = self.get(&format!("{}/api/v1/log/entries/{uuid}", self.config.base_url()))?;
            if status != 200 {
                return Err(LogError::Unavailable(format!("HTTP {status} fetching the existing entry")));
            }
            return Ok(body);
        }
        if !(200..300).contains(&status) {
            return Err(LogError::Unavailable(format!("HTTP {status}")));
        }
        Ok(body)
    }
}

/// Rekor's v1 API as a [`TransparencyLog`], over any [`LogTransport`].
pub struct RekorLog<T: LogTransport> {
    transport: T,
}

fn malformed(why: impl Into<String>) -> LogError {
    LogError::Malformed(why.into())
}

fn json(bytes: &[u8]) -> Result<Json, LogError> {
    serde_json::from_slice(bytes).map_err(|_| malformed("response is not JSON"))
}

fn uint(v: &Json, key: &str) -> Result<u64, LogError> {
    v.get(key).and_then(Json::as_u64).ok_or_else(|| malformed(format!("`{key}` is not an unsigned integer")))
}

fn text<'j>(v: &'j Json, key: &str) -> Result<&'j str, LogError> {
    v.get(key).and_then(Json::as_str).ok_or_else(|| malformed(format!("`{key}` is not a string")))
}

fn hash(text: &str) -> Result<Digest, LogError> {
    hex_decode(text).and_then(|b| Digest::from_bytes(&b).ok()).ok_or_else(|| malformed("not a 32-byte hex hash"))
}

fn hashes(v: &Json) -> Result<Vec<Digest>, LogError> {
    let list = v.get("hashes").and_then(Json::as_array).ok_or_else(|| malformed("`hashes` is not a list"))?;
    if list.len() > MAX_PATH {
        return Err(malformed("proof too long"));
    }
    list.iter().map(|h| h.as_str().ok_or_else(|| malformed("hash is not a string")).and_then(hash)).collect()
}

fn checkpoint(note: &str) -> Result<SignedCheckpoint, LogError> {
    SignedCheckpoint::parse(note.as_bytes()).map_err(|e| malformed(e.to_string()))
}

/// The one entry of a Rekor entries response, checked against `entry`: its logged body
/// must be exactly the `hashedrekord` leaf for `entry`, and its inclusion proof must agree
/// with its checkpoint and reach its root.
fn logged_entry(response: &[u8], entry: &LogEntry) -> Result<LoggedEntry, LogError> {
    let v = json(response)?;
    let map = v.as_object().ok_or_else(|| malformed("response is not an object"))?;
    let [(_, e)] = <[(&String, &Json); 1]>::try_from(map.iter().collect::<Vec<_>>()).map_err(|_| malformed("expected exactly one entry"))?;
    let body = base64_decode(text(e, "body")?).ok_or_else(|| malformed("body is not base64"))?;
    let leaf = LeafFormat::HashedRekord.leaf(entry);
    if body != leaf {
        return Err(malformed("the logged body is not this entry"));
    }
    let proof = e
        .get("verification")
        .and_then(|v| v.get("inclusionProof"))
        .ok_or_else(|| malformed("no inclusion proof"))?;
    let leaf_index = uint(proof, "logIndex")?;
    let tree_size = uint(proof, "treeSize")?;
    let root = hash(text(proof, "rootHash")?)?;
    let cp = checkpoint(text(proof, "checkpoint")?)?;
    if cp.size() != tree_size || cp.root() != &root {
        return Err(malformed("the proof and its checkpoint disagree"));
    }
    let inclusion = InclusionProof { leaf_index, tree_size, path: hashes(proof)? };
    if !verify_inclusion(&leaf_hash(&leaf), &inclusion, &root) {
        return Err(malformed("the inclusion proof does not reach the root"));
    }
    Ok(LoggedEntry { entry: entry.clone(), leaf: LeafFormat::HashedRekord, inclusion, checkpoint: cp })
}

impl<T: LogTransport> RekorLog<T> {
    /// Rekor reached through `transport`.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    fn send(&self, request: LogRequest, fields: Vec<(String, Vec<u8>)>) -> Result<Vec<u8>, LogError> {
        self.transport.send(&Transmission { request, fields })
    }

    /// The latest tree head, and the global index of the active shard's first entry (the
    /// sizes of the inactive shards before it).
    fn head(&self) -> Result<(SignedCheckpoint, u64), LogError> {
        let v = json(&self.send(LogRequest::Checkpoint, Vec::new())?)?;
        let cp = checkpoint(text(&v, "signedTreeHead")?)?;
        if cp.size() != uint(&v, "treeSize")? || cp.root() != &hash(text(&v, "rootHash")?)? {
            return Err(malformed("the tree head and its checkpoint disagree"));
        }
        let mut offset = 0u64;
        if let Some(shards) = v.get("inactiveShards") {
            for s in shards.as_array().ok_or_else(|| malformed("`inactiveShards` is not a list"))? {
                offset = offset.checked_add(uint(s, "treeSize")?).ok_or_else(|| malformed("shard sizes overflow"))?;
            }
        }
        Ok((cp, offset))
    }
}

impl<T: LogTransport> TransparencyLog for RekorLog<T> {
    fn append(&self, entry: &LogEntry) -> Result<LoggedEntry, LogError> {
        let fields = vec![
            ("digest".to_owned(), lower_hex(entry.digest().as_bytes()).into_bytes()),
            ("signature".to_owned(), entry_signature_der(entry)),
            ("publicKey".to_owned(), p256_pem(entry.public_key()).into_bytes()),
        ];
        debug_assert_eq!(
            render("", &Transmission { request: LogRequest::Append, fields: fields.clone() }).ok().and_then(|r| r.body),
            Some(hashedrekord_json(entry).into_bytes()),
            "the request body is the leaf"
        );
        logged_entry(&self.send(LogRequest::Append, fields)?, entry)
    }

    fn checkpoint(&self) -> Result<SignedCheckpoint, LogError> {
        Ok(self.head()?.0)
    }

    fn prove_inclusion(&self, leaf_index: u64, checkpoint: &SignedCheckpoint) -> Result<InclusionProof, LogError> {
        if leaf_index >= checkpoint.size() {
            return Err(LogError::OutOfRange);
        }
        let (_, offset) = self.head()?;
        let global = offset.checked_add(leaf_index).ok_or(LogError::OutOfRange)?;
        let response = self.send(LogRequest::Inclusion { leaf_index: global, tree_size: checkpoint.size() }, Vec::new())?;
        let v = json(&response)?;
        let map = v.as_object().ok_or_else(|| malformed("response is not an object"))?;
        let [(_, e)] = <[(&String, &Json); 1]>::try_from(map.iter().collect::<Vec<_>>()).map_err(|_| malformed("expected exactly one entry"))?;
        let body = base64_decode(text(e, "body")?).ok_or_else(|| malformed("body is not base64"))?;
        let proof = e.get("verification").and_then(|v| v.get("inclusionProof")).ok_or_else(|| malformed("no inclusion proof"))?;
        if uint(proof, "logIndex")? != leaf_index {
            return Err(malformed("the proof is for another entry"));
        }
        if uint(proof, "treeSize")? != checkpoint.size() || &hash(text(proof, "rootHash")?)? != checkpoint.root() {
            return Err(LogError::Unavailable("Rekor proves inclusion only against its latest tree head".into()));
        }
        let inclusion = InclusionProof { leaf_index, tree_size: checkpoint.size(), path: hashes(proof)? };
        if !verify_inclusion(&leaf_hash(&body), &inclusion, checkpoint.root()) {
            return Err(malformed("the inclusion proof does not reach the root"));
        }
        Ok(inclusion)
    }

    fn prove_consistency(&self, old_size: u64, checkpoint: &SignedCheckpoint) -> Result<ConsistencyProof, LogError> {
        let new_size = checkpoint.size();
        if old_size > new_size {
            return Err(LogError::OutOfRange);
        }
        if old_size == 0 || old_size == new_size {
            return Ok(ConsistencyProof { old_size, new_size, path: Vec::new() });
        }
        let v = json(&self.send(LogRequest::Consistency { old_size, new_size }, Vec::new())?)?;
        if &hash(text(&v, "rootHash")?)? != checkpoint.root() {
            return Err(malformed("the proof is for another tree head"));
        }
        Ok(ConsistencyProof { old_size, new_size, path: hashes(&v)? })
    }
}
