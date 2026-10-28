//! The upload endpoint's use cases (`docs/reference/spec/delivery.md` §5, DEL-002, DEL-003,
//! DEL-006, DEL-008, DEL-052, DEL-062, WIRE-170, WIRE-171, WIRE-180–WIRE-182).
//!
//! [`UploadService`] is transport-free: an HTTP adapter (or an in-process one) hands it the
//! bytes of a request and gets bytes or a typed refusal back. It does three things:
//!
//! 1. answers the receiver challenge with the authority's `receiver` key, so a runtime
//!    can authorise this destination at whatever address it reached it by;
//! 2. authenticates an active tenancy's request by its proof-of-possession token;
//! 3. runs the verification gate on the body and returns the receipts it issues.

use fieldseal_delivery::domain::{POP_HEADER, PopToken, ReceiverChallenge, ReceiverProof, UploadRoute};
use fieldseal_kernel::crypto::{Purpose, tags};
use fieldseal_kernel::id::{KeyId, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, cbor};
use fieldseal_trust::domain::{KeyCertificate, KeyRole};

use crate::application::IntakeError;
use crate::domain::{GateState, SubmissionSource};
use crate::gate::IntakeService;
use crate::ports::PopLedger;

/// How far a token's `iat` may be from the server's clock (WIRE-171), in milliseconds.
pub const POP_WINDOW_MS: u64 = 300_000;

/// The largest challenge body accepted.
pub const MAX_CHALLENGE: usize = 256;

/// Why an upload request was refused. None of these lands anything.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UploadRefusal {
    /// The request isn't well formed.
    #[error("bad request: {0}")]
    BadRequest(String),
    /// The token is missing, expired, replayed, bound to another request or signed by a
    /// key that isn't registered and unrevoked (DEL-003).
    #[error("token rejected: {0}")]
    TokenRejected(&'static str),
    /// The gate refused the body: nothing was landed.
    #[error("submission rejected at {stage} with {code}")]
    Rejected {
        /// The stage that refused it.
        stage: String,
        /// The error code.
        code: String,
        /// What failed, without personal data.
        detail: String,
    },
    /// A backing service failed; nothing was landed and the request may be retried.
    #[error("backend: {0}")]
    Backend(String),
}

/// The upload endpoint over Intake's gate.
pub struct UploadService<'a, 'g> {
    /// The verification gate, which also holds the registry, custody and trust bundle.
    pub intake: &'a IntakeService<'g>,
    /// Replay protection for token identifiers.
    pub ledger: &'a dyn PopLedger,
    /// The key in custody that answers receiver challenges.
    pub receiver_key: KeyId,
    /// Its certificate, which chains to the authority root.
    pub receiver_certificate: &'a KeyCertificate,
    /// The external base URLs this endpoint answers at: a token is bound to
    /// `<base><path>` for one of them. An authority adds a host name here, not in any
    /// runtime or bundle (DEL-066, ADR 0021).
    pub public_urls: &'a [String],
}

impl UploadService<'_, '_> {
    /// Answers a receiver challenge (WIRE-180, WIRE-181): the `receiver` certificate and the
    /// receiver key's signature over the canonical challenge. The answer doesn't depend on
    /// the address, the TLS certificate or anything else the caller reached us by (WIRE-182).
    pub fn answer_challenge(&self, body: &[u8]) -> Result<Vec<u8>, UploadRefusal> {
        if body.len() > MAX_CHALLENGE {
            return Err(UploadRefusal::BadRequest("challenge too large".into()));
        }
        let challenge = ReceiverChallenge::decode(body).map_err(|e| UploadRefusal::BadRequest(format!("challenge: {}", e.code)))?;
        let signature = self
            .intake
            .custody
            .sign(&self.receiver_key, KeyRole::Purpose(Purpose::Receiver), &tags::RECEIVER_CHALLENGE, &challenge.to_value(), self.intake.caller)
            .map_err(|e| UploadRefusal::Backend(e.to_string()))?;
        Ok(ReceiverProof { certificate: self.receiver_certificate.clone(), signature }.encode())
    }

    /// Authenticates a tenancy-route request by its `Fieldseal-PoP` header value (DEL-002,
    /// DEL-003, WIRE-171): the token must name a registered tenancy that isn't deny-listed,
    /// match `method` and `<public_url><path>`, be within 300 s of `now`, carry an unseen
    /// `jti`, and be signed by the tenancy's current signing key. The runtime's
    /// identity-provider tokens are never accepted (DEL-004): there is no other credential.
    pub fn authenticate(&self, header: Option<&str>, method: &str, route: UploadRoute, now: AuthorityTime) -> Result<TenancyId, UploadRefusal> {
        let header = header.ok_or(UploadRefusal::TokenRejected("no proof-of-possession token"))?;
        let token = PopToken::from_header(header).map_err(|_| UploadRefusal::TokenRejected("unreadable token"))?;
        let view = self
            .intake
            .registry
            .by_id(&token.tenancy)
            .map_err(|e| UploadRefusal::Backend(e.to_string()))?
            .ok_or(UploadRefusal::TokenRejected("unknown tenancy"))?;
        if view.deny_listed {
            return Err(UploadRefusal::TokenRejected("tenancy revoked"));
        }
        if !token.method.eq_ignore_ascii_case(method) || !self.public_urls.iter().any(|base| token.url == route.url(base)) {
            return Err(UploadRefusal::TokenRejected("token bound to another request"));
        }
        if now.0.abs_diff(token.iat.0) > POP_WINDOW_MS {
            return Err(UploadRefusal::TokenRejected("token expired"));
        }
        let key = view.signing_keys.iter().enumerate().rev().find(|(i, _)| !view.key_revoked_from.contains_key(&(*i as u64))).map(|(_, k)| k);
        let key = key.ok_or(UploadRefusal::TokenRejected("no current signing key"))?;
        token.verify_signature(key).map_err(|_| UploadRefusal::TokenRejected("bad token signature"))?;
        let until = AuthorityTime(now.0.saturating_add(POP_WINDOW_MS));
        if !self.ledger.first_use(&token.tenancy, &token.jti, now, until).map_err(UploadRefusal::Backend)? {
            return Err(UploadRefusal::TokenRejected("token replayed"));
        }
        Ok(token.tenancy)
    }

    /// Runs the gate on an upload body and returns the receipts, as canonical CBOR: an
    /// array with one receipt per tenancy part acknowledged (DEL-006). A body the gate
    /// refuses lands nothing and is reported with its stage and code. Re-sending a body
    /// returns an equivalent receipt (DEL-008, INT-013).
    pub fn receive(&self, body: &[u8], now: AuthorityTime) -> Result<Vec<u8>, UploadRefusal> {
        let report = self.intake.ingest(body, SubmissionSource::Upload, now).map_err(|e| match e {
            IntakeError::Backend(b) => UploadRefusal::Backend(b),
            e => UploadRefusal::BadRequest(e.to_string()),
        })?;
        if report.submission.state() == GateState::Rejected {
            let r = report.submission.rejection();
            return Err(UploadRefusal::Rejected {
                stage: r.map_or_else(String::new, |r| format!("{:?}", r.stage)),
                code: r.map_or_else(String::new, |r| r.code.to_string()),
                detail: r.map_or_else(String::new, |r| r.detail.clone()),
            });
        }
        let receipts = report.receipts.iter().map(|r| Value::Bytes(r.bytes.clone())).collect();
        cbor::encode(&Value::Array(receipts)).map_err(|e| UploadRefusal::Backend(e.to_string()))
    }
}

/// The header carrying the token (WIRE-172), re-exported for adapters.
pub const TOKEN_HEADER: &str = POP_HEADER;
