//! The HTTP client for the factory's runtime API (the same routes [`crate::FactoryHttp`]
//! serves): submit a sealed registration request, read a tenancy's status, and fetch the
//! tenancy certificate with a proof-of-possession token.
//!
//! It speaks bytes and returns the status code and body; the caller decides what they mean.
//! Plain `http://` is allowed (the local stack runs on loopback); `https://` uses rustls.

use std::time::Duration;

/// The largest answer read.
pub const MAX_ANSWER: u64 = 1024 * 1024;

/// What the factory answered.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Answer {
    /// The HTTP status.
    pub status: u16,
    /// The body.
    pub body: Vec<u8>,
}

/// Why no answer came back.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ClientError {
    /// The address isn't an `http://` or `https://` URL.
    #[error("not an http(s) URL: {0}")]
    BadUrl(String),
    /// The factory couldn't be reached, or the answer was cut off or too large.
    #[error("{0}")]
    Unreachable(String),
}

/// A blocking client for one factory.
pub struct FactoryHttpClient {
    agent: ureq::Agent,
    base: String,
}

impl FactoryHttpClient {
    /// A client for the factory at `base_url` (for example `http://localhost:8080`).
    pub fn new(base_url: &str) -> Result<Self, ClientError> {
        if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
            return Err(ClientError::BadUrl(base_url.to_owned()));
        }
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(30))).build().into();
        Ok(Self { agent, base: base_url.trim_end_matches('/').to_owned() })
    }

    /// The base URL, without a trailing slash.
    pub fn base(&self) -> &str {
        &self.base
    }

    fn answer(&self, mut response: ureq::http::Response<ureq::Body>) -> Result<Answer, ClientError> {
        let status = response.status().as_u16();
        let body = response.body_mut().with_config().limit(MAX_ANSWER).read_to_vec().map_err(|e| ClientError::Unreachable(e.to_string()))?;
        Ok(Answer { status, body })
    }

    /// `POST /v1/registrations`: a sealed registration request file.
    pub fn submit(&self, request_file: &[u8]) -> Result<Answer, ClientError> {
        let r = self
            .agent
            .post(format!("{}/v1/registrations", self.base))
            .header("Content-Type", "application/cbor")
            .send(request_file)
            .map_err(|e| ClientError::Unreachable(e.to_string()))?;
        self.answer(r)
    }

    /// `GET /v1/registrations/{tenancy}`: the state of a tenancy (64 hex digits).
    pub fn status(&self, tenancy_hex: &str) -> Result<Answer, ClientError> {
        let r = self.agent.get(format!("{}/v1/registrations/{tenancy_hex}", self.base)).call().map_err(|e| ClientError::Unreachable(e.to_string()))?;
        self.answer(r)
    }

    /// `GET /v1/certificate` with a `Fieldseal-PoP` header: the tenancy certificate (CBOR).
    pub fn certificate(&self, pop_header: &str) -> Result<Answer, ClientError> {
        let r = self
            .agent
            .get(format!("{}/v1/certificate", self.base))
            .header(fieldseal_kernel::pop::POP_HEADER, pop_header)
            .call()
            .map_err(|e| ClientError::Unreachable(e.to_string()))?;
        self.answer(r)
    }
}
