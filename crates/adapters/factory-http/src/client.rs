//! The HTTP client for the factory's runtime API (the same routes [`crate::FactoryHttp`]
//! serves): submit a sealed registration request, read a tenancy's status, and fetch the
//! tenancy certificate and the stored bundle with a proof-of-possession token. The operator calls (`assign`,
//! `assignments`, `issue_roster`) send an access token as `Authorization: Bearer`.
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

/// What `GET /v1/bundle` answered (CLI-049).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BundleAnswer {
    /// `200`: the latest bundle, exactly as stored, and its sequence number.
    Bundle {
        /// The `FSB1` file.
        bytes: Vec<u8>,
        /// The `Fieldseal-Bundle-Sequence` header.
        sequence: u64,
        /// The DIS-023 file name from `Content-Disposition`; `None` when the header is missing
        /// or does not hold a plain `fieldseal-bundle-<date>-<n>.fsb` name.
        file_name: Option<String>,
    },
    /// `304`: the bundle the caller holds is the latest.
    Current,
    /// `401`, `403` or `404`: the factory said no, with its error code and any reasons.
    Refused {
        /// The HTTP status.
        status: u16,
        /// The `error` code, for example `withheld` or `no-bundle`.
        code: String,
        /// The `reasons` of a `withheld` answer.
        reasons: Vec<String>,
    },
    /// `5xx`, or an answer that is not the contract.
    Unavailable,
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

    /// `GET /v1/bundle` with a `Fieldseal-PoP` header. `held` is the sequence number of the
    /// bundle the caller holds; it is sent as a query and is not part of the token (WIRE-171).
    /// The answer may be as large as a bundle ([`crate::BUNDLE_LIMIT`]).
    pub fn bundle(&self, pop_header: &str, held: Option<u64>) -> Result<BundleAnswer, ClientError> {
        let url = match held {
            Some(h) => format!("{}/v1/bundle?held={h}", self.base),
            None => format!("{}/v1/bundle", self.base),
        };
        let mut response = self.agent.get(url).header(fieldseal_kernel::pop::POP_HEADER, pop_header).call().map_err(|e| ClientError::Unreachable(e.to_string()))?;
        let status = response.status().as_u16();
        let sequence = response.headers().get("Fieldseal-Bundle-Sequence").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
        let file_name = response
            .headers()
            .get("Content-Disposition")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_once("filename=\""))
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(name, _)| name)
            .filter(|n| n.starts_with("fieldseal-bundle-") && n.ends_with(".fsb") && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'))
            .map(str::to_owned);
        let body = response.body_mut().with_config().limit(crate::BUNDLE_LIMIT as u64).read_to_vec().map_err(|e| ClientError::Unreachable(e.to_string()))?;
        Ok(match (status, sequence) {
            (200, Some(sequence)) => BundleAnswer::Bundle { bytes: body, sequence, file_name },
            (304, _) => BundleAnswer::Current,
            (401 | 403 | 404, _) => {
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let code = json.get("error").and_then(|c| c.as_str()).unwrap_or_default().to_owned();
                let reasons = json.get("reasons").and_then(|r| r.as_array()).map(|a| a.iter().filter_map(|r| r.as_str().map(str::to_owned)).collect()).unwrap_or_default();
                BundleAnswer::Refused { status, code, reasons }
            }
            _ => BundleAnswer::Unavailable,
        })
    }

    /// `POST /v1/assignments`: assign `cohort` of `survey` to `account` (an OIDC subject).
    pub fn assign(&self, bearer: &str, account: &str, survey: &str, cohort: &str) -> Result<Answer, ClientError> {
        use fieldseal_kernel::{Value, cbor};
        let body = cbor::encode(&cbor::map([
            ("account", Value::Text(account.to_owned())),
            ("survey", Value::Text(survey.to_owned())),
            ("cohort", Value::Text(cohort.to_owned())),
        ]))
        .map_err(|e| ClientError::Unreachable(e.to_string()))?;
        let r = self
            .agent
            .post(format!("{}/v1/assignments", self.base))
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Content-Type", "application/cbor")
            .send(&body[..])
            .map_err(|e| ClientError::Unreachable(e.to_string()))?;
        self.answer(r)
    }

    /// `GET /v1/assignments`: the journaled assignments.
    pub fn assignments(&self, bearer: &str) -> Result<Answer, ClientError> {
        let r = self
            .agent
            .get(format!("{}/v1/assignments", self.base))
            .header("Authorization", format!("Bearer {bearer}"))
            .call()
            .map_err(|e| ClientError::Unreachable(e.to_string()))?;
        self.answer(r)
    }

    /// `POST /v1/rosters`: a roster in canonical CBOR (the issue form of WIRE-198).
    pub fn issue_roster(&self, bearer: &str, canonical_roster: &[u8]) -> Result<Answer, ClientError> {
        let r = self
            .agent
            .post(format!("{}/v1/rosters", self.base))
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Content-Type", "application/cbor")
            .send(canonical_roster)
            .map_err(|e| ClientError::Unreachable(e.to_string()))?;
        self.answer(r)
    }
}
