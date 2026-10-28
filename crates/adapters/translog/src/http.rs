//! Transports for [`crate::HttpTranslog`]: [`HttpLogTransport`] over the network (ureq) and
//! [`HandlerTransport`], which calls the server handler in-process.

use std::time::Duration;

use fieldseal_publishing::ports::{LogError, LogTransport, Transmission};

use crate::store::FileLogStore;
use crate::wire::{DEFAULT_MAX_BODY, MAX_RESPONSE, handle, interpret, render};

/// Sends transmissions to a log server over plain HTTP or HTTPS.
///
/// Each transmission is one request built by [`render`]. Redirects are not followed;
/// responses larger than [`MAX_RESPONSE`] are refused with [`LogError::Oversized`]; the
/// timeout covers a whole request.
pub struct HttpLogTransport {
    base: String,
    max_response: u64,
    agent: ureq::Agent,
}

impl HttpLogTransport {
    /// A transport for the log at `base_url` (for example `http://127.0.0.1:8080`), with a
    /// 30-second timeout. Fails unless the URL is `http` or `https` with no query or fragment.
    pub fn new(base_url: &str) -> Result<Self, LogError> {
        Self::with_timeout(base_url, Duration::from_secs(30))
    }

    /// As [`Self::new`], with the given whole-request timeout.
    pub fn with_timeout(base_url: &str, timeout: Duration) -> Result<Self, LogError> {
        let url = base_url.trim().trim_end_matches('/');
        let host = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"));
        match host {
            Some(h) if !h.is_empty() && !h.contains(['?', '#', ' ', '@']) => {}
            _ => return Err(LogError::Unavailable(format!("invalid log base URL: {base_url}"))),
        }
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent("fieldseal")
            .build()
            .into();
        Ok(Self { base: url.to_owned(), max_response: MAX_RESPONSE as u64, agent })
    }
}

impl LogTransport for HttpLogTransport {
    fn send(&self, transmission: &Transmission) -> Result<Vec<u8>, LogError> {
        let request = render(transmission)?;
        let url = format!("{}{}", self.base, request.path);
        let response = if request.method == "POST" {
            self.agent.post(&url).header("Content-Type", "application/cbor").send(&request.body[..])
        } else {
            self.agent.get(&url).call()
        }
        .map_err(|e| LogError::Unavailable(e.to_string()))?;
        let status = response.status().as_u16();
        let mut response = response;
        let body = response.body_mut().with_config().limit(self.max_response).read_to_vec().map_err(|e| match e {
            ureq::Error::BodyExceedsLimit(_) => LogError::Oversized,
            e => LogError::Unavailable(e.to_string()),
        })?;
        interpret(status, body)
    }
}

/// Answers transmissions by calling [`handle`] on a store in this process: the same
/// rendering and interpretation as the network path, without a socket.
pub struct HandlerTransport<S: std::ops::Deref<Target = FileLogStore>> {
    store: S,
}

impl<S: std::ops::Deref<Target = FileLogStore>> HandlerTransport<S> {
    /// A transport serving `store` (a reference, `Arc` or the like).
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

impl<S: std::ops::Deref<Target = FileLogStore>> LogTransport for HandlerTransport<S> {
    fn send(&self, transmission: &Transmission) -> Result<Vec<u8>, LogError> {
        let request = render(transmission)?;
        let response = handle(&self.store, request.method, &request.path, &request.body, DEFAULT_MAX_BODY);
        interpret(response.status, response.body)
    }
}
