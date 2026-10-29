//! Transport-neutral clients for the services the CLI talks to (ADR 0035): the factory
//! (submit a sealed registration request, read its status, fetch the tenancy certificate)
//! and the upload endpoint (upload an export, receive receipts). The transparency log is
//! reached through the Publishing context's own `TransparencyLog` port (see
//! [`crate::stores::remote_translog`]).
//!
//! Commands depend on the traits here and never on a transport. The transport is chosen by
//! the URL scheme in one place per service: `http://` and `https://` are built in;
//! `grpc://` and `grpcs://` are recognised and refused with a clear message until the gRPC
//! adapters exist (exit 3), so a command line written for them today fails loudly.

use fieldseal_adapters_factory_http::client::{BundleAnswer, FactoryHttpClient};
use fieldseal_adapters_upload_http::{ClientConfig, HttpUploadTransport};
use fieldseal_delivery::ports::UploadError;
use serde_json::Value as Json;

/// Why a call to a service failed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ClientError {
    /// The address has a scheme no adapter is built for (`grpc`, `grpcs`).
    NotBuilt(String),
    /// The address isn't a URL with a known scheme.
    BadUrl,
    /// An operator call was pointed at an `http://` address that isn't on this machine: the
    /// access token would cross the network in clear.
    Cleartext,
    /// The service couldn't be reached, or its answer was cut off.
    Unreachable(String),
    /// The service refused: the HTTP status and the machine-readable error code.
    Refused { status: u16, code: String },
    /// The service answered something that isn't the contract.
    Malformed(String),
}

/// The scheme of `url` (`http`, `https`, `grpc`, `grpcs`), if it has one.
pub fn scheme(url: &str) -> Option<&str> {
    url.split_once("://").map(|(s, _)| s).filter(|s| !s.is_empty())
}

/// What the factory says about a registration.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RegistrationStatus {
    /// The tenancy (64 hex digits), when the answer names it.
    pub tenancy: String,
    /// The state: `pending`, `held`, `rejected`, `registered`, ...
    pub state: String,
    /// The fingerprint words, when the answer carries them (a submission does).
    pub words: String,
    /// Policy reasons for the state.
    pub reasons: Vec<String>,
}

/// What `AssignCohort` answered.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AssignAnswer {
    /// `assigned`, or `unchanged` when the same assignment was already journaled.
    pub status: String,
    /// The generation recorded for the cohort.
    pub generation: u32,
}

/// One journaled assignment, as `ListAssignments` returns it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AssignmentRow {
    /// The journal position.
    pub seq: u64,
    /// The account the assignment targets: the collector's OIDC subject.
    pub account: String,
    /// The survey.
    pub survey: String,
    /// The cohort.
    pub cohort: String,
    /// The generation.
    pub generation: u32,
    /// The operator's account.
    pub by: String,
    /// When it was made, as the factory printed it.
    pub at: String,
}

/// What `IssueRoster` answered.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IssueAnswer {
    /// `issued`, or `unchanged` when the same roster was already stored.
    pub status: String,
    /// The stored version.
    pub version: u64,
    /// `sha256:` and the digest of the stored roster.
    pub digest: String,
}

/// What `GET /v1/bundle` answered (CLI-049).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BundleReply {
    /// The latest bundle, exactly as stored.
    Bundle {
        /// The `FSB1` file.
        bytes: Vec<u8>,
        /// Its sequence number.
        sequence: u64,
        /// Its DIS-023 file name, when the factory sent a usable one.
        file_name: Option<String>,
    },
    /// The bundle the caller holds is the latest.
    Current,
}

/// The factory's runtime API, as the CLI uses it. The last three calls are the operator API:
/// they send the access token as `Authorization: Bearer` and nothing else.
pub trait FactoryClient {
    /// Submits a sealed registration request file (REG-050).
    fn submit(&self, request_file: &[u8]) -> Result<RegistrationStatus, ClientError>;
    /// The state of a tenancy (64 hex digits).
    fn status(&self, tenancy: &str) -> Result<RegistrationStatus, ClientError>;
    /// The tenancy certificate (CBOR), with a `Fieldseal-PoP` header made by the tenancy's key.
    fn certificate(&self, pop_header: &str) -> Result<Vec<u8>, ClientError>;
    /// The latest bundle of the tenancy, with a `Fieldseal-PoP` header made by the tenancy's key.
    /// `held` is the sequence number of the bundle the caller holds (not part of the token).
    fn bundle(&self, pop_header: &str, held: Option<u64>) -> Result<BundleReply, ClientError>;
    /// Assigns `cohort` of `survey` to `account`, an OIDC subject (REG-046).
    fn assign(&self, bearer: &str, account: &str, survey: &str, cohort: &str) -> Result<AssignAnswer, ClientError>;
    /// The journaled assignments, oldest first.
    fn assignments(&self, bearer: &str) -> Result<Vec<AssignmentRow>, ClientError>;
    /// Adds a roster in canonical CBOR as a new version (REG-047).
    fn issue_roster(&self, bearer: &str, canonical_roster: &[u8]) -> Result<IssueAnswer, ClientError>;
}

/// The upload endpoint, as the CLI uses it.
pub trait UploadClient {
    /// Uploads an export file (without parity) and returns the receipts, as signed.
    fn upload(&self, export: &[u8]) -> Result<Vec<Vec<u8>>, ClientError>;
}

fn check_scheme(url: &str) -> Result<(), ClientError> {
    match scheme(url) {
        Some("http" | "https") => Ok(()),
        Some(s @ ("grpc" | "grpcs")) => Err(ClientError::NotBuilt(s.to_owned())),
        _ => Err(ClientError::BadUrl),
    }
}

/// Connects to the factory at `url`, choosing the transport by scheme.
pub fn connect_factory(url: &str) -> Result<Box<dyn FactoryClient>, ClientError> {
    check_scheme(url)?;
    Ok(Box::new(HttpFactory(FactoryHttpClient::new(url).map_err(|_| ClientError::BadUrl)?)))
}

/// Whether the host of an `http://` or `https://` address is `localhost` or a loopback address.
fn is_loopback_host(url: &str) -> bool {
    let rest = url.split_once("://").map_or("", |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // What follows the last `@` is the host; anything before it is user information.
    let host_port = authority.rsplit('@').next().unwrap_or("");
    let host = match host_port.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => host_port.split(':').next().unwrap_or(""),
    };
    host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Connects to the factory at `url` for an operator call (`roster issue`, `roster assign`),
/// which sends a Bearer access token. An `http://` address is refused unless its host is a
/// loopback name or address; use `https://` for any other.
pub fn connect_operator(url: &str) -> Result<Box<dyn FactoryClient>, ClientError> {
    check_scheme(url)?;
    if scheme(url) == Some("http") && !is_loopback_host(url) {
        return Err(ClientError::Cleartext);
    }
    connect_factory(url)
}

/// Connects to the upload endpoint at `url`, choosing the transport by scheme.
pub fn connect_upload(url: &str) -> Result<Box<dyn UploadClient>, ClientError> {
    check_scheme(url)?;
    // Cleartext is allowed here because the operator chose the address; the receipts are
    // verified against the trust bundle whatever the route (DEL-064).
    Ok(Box::new(HttpUpload { transport: HttpUploadTransport::new(ClientConfig { allow_http: true, ..ClientConfig::default() }), base: url.to_owned() }))
}

// ---- the HTTP adapters ---------------------------------------------------------------------------

struct HttpFactory(FactoryHttpClient);

fn refusal(status: u16, body: &[u8]) -> ClientError {
    let code = serde_json::from_slice::<Json>(body).ok().and_then(|j| j.get("error").and_then(Json::as_str).map(str::to_owned)).unwrap_or_default();
    ClientError::Refused { status, code }
}

fn status_of(answer: &fieldseal_adapters_factory_http::client::Answer, ok: &[u16]) -> Result<RegistrationStatus, ClientError> {
    if !ok.contains(&answer.status) {
        return Err(refusal(answer.status, &answer.body));
    }
    let j: Json = serde_json::from_slice(&answer.body).map_err(|e| ClientError::Malformed(e.to_string()))?;
    let text = |k: &str| j.get(k).and_then(Json::as_str).unwrap_or_default().to_owned();
    Ok(RegistrationStatus {
        tenancy: text("tenancy"),
        state: j.get("state").and_then(Json::as_str).ok_or_else(|| ClientError::Malformed("no state".into()))?.to_owned(),
        words: text("words"),
        reasons: j.get("reasons").and_then(Json::as_array).map(|a| a.iter().filter_map(|r| r.as_str().map(str::to_owned)).collect()).unwrap_or_default(),
    })
}

fn unreachable(e: fieldseal_adapters_factory_http::client::ClientError) -> ClientError {
    ClientError::Unreachable(e.to_string())
}

impl FactoryClient for HttpFactory {
    fn submit(&self, request_file: &[u8]) -> Result<RegistrationStatus, ClientError> {
        status_of(&self.0.submit(request_file).map_err(unreachable)?, &[200, 202])
    }

    fn status(&self, tenancy: &str) -> Result<RegistrationStatus, ClientError> {
        let mut s = status_of(&self.0.status(tenancy).map_err(unreachable)?, &[200])?;
        if s.tenancy.is_empty() {
            s.tenancy = tenancy.to_owned();
        }
        Ok(s)
    }

    fn certificate(&self, pop_header: &str) -> Result<Vec<u8>, ClientError> {
        let a = self.0.certificate(pop_header).map_err(unreachable)?;
        if a.status == 200 { Ok(a.body) } else { Err(refusal(a.status, &a.body)) }
    }

    fn bundle(&self, pop_header: &str, held: Option<u64>) -> Result<BundleReply, ClientError> {
        match self.0.bundle(pop_header, held).map_err(unreachable)? {
            BundleAnswer::Bundle { bytes, sequence, file_name } => Ok(BundleReply::Bundle { bytes, sequence, file_name }),
            BundleAnswer::Current => Ok(BundleReply::Current),
            BundleAnswer::Refused { status, code, .. } => Err(ClientError::Refused { status, code }),
            BundleAnswer::Unavailable => Err(ClientError::Unreachable("the factory could not serve the bundle".into())),
        }
    }

    fn assign(&self, bearer: &str, account: &str, survey: &str, cohort: &str) -> Result<AssignAnswer, ClientError> {
        self.assign_impl(bearer, account, survey, cohort)
    }

    fn assignments(&self, bearer: &str) -> Result<Vec<AssignmentRow>, ClientError> {
        let j = json_of(&self.0.assignments(bearer).map_err(unreachable)?)?;
        let rows = j.get("assignments").and_then(Json::as_array).ok_or_else(|| ClientError::Malformed("no assignments".into()))?;
        rows.iter()
            .map(|r| {
                Ok(AssignmentRow {
                    seq: number_of(r, "seq")?,
                    account: text_of(r, "account")?,
                    survey: text_of(r, "survey")?,
                    cohort: text_of(r, "cohort")?,
                    generation: u32::try_from(number_of(r, "generation")?).map_err(|_| ClientError::Malformed("generation".into()))?,
                    by: text_of(r, "by")?,
                    at: text_of(r, "at")?,
                })
            })
            .collect()
    }

    fn issue_roster(&self, bearer: &str, canonical_roster: &[u8]) -> Result<IssueAnswer, ClientError> {
        let j = json_of(&self.0.issue_roster(bearer, canonical_roster).map_err(unreachable)?)?;
        Ok(IssueAnswer { status: text_of(&j, "status")?, version: number_of(&j, "version")?, digest: text_of(&j, "digest")? })
    }
}

fn json_of(a: &fieldseal_adapters_factory_http::client::Answer) -> Result<Json, ClientError> {
    if a.status != 200 {
        return Err(refusal(a.status, &a.body));
    }
    serde_json::from_slice(&a.body).map_err(|e| ClientError::Malformed(e.to_string()))
}

fn text_of(j: &Json, key: &str) -> Result<String, ClientError> {
    j.get(key).and_then(Json::as_str).map(str::to_owned).ok_or_else(|| ClientError::Malformed(format!("no {key}")))
}

fn number_of(j: &Json, key: &str) -> Result<u64, ClientError> {
    j.get(key).and_then(Json::as_u64).ok_or_else(|| ClientError::Malformed(format!("no {key}")))
}

impl HttpFactory {
    fn assign_impl(&self, bearer: &str, account: &str, survey: &str, cohort: &str) -> Result<AssignAnswer, ClientError> {
        let j = json_of(&self.0.assign(bearer, account, survey, cohort).map_err(unreachable)?)?;
        Ok(AssignAnswer { status: text_of(&j, "status")?, generation: u32::try_from(number_of(&j, "generation")?).map_err(|_| ClientError::Malformed("generation".into()))? })
    }
}

struct HttpUpload {
    transport: HttpUploadTransport,
    base: String,
}

impl UploadClient for HttpUpload {
    fn upload(&self, export: &[u8]) -> Result<Vec<Vec<u8>>, ClientError> {
        self.transport.upload_outbox(&self.base, export).map_err(|e| match e {
            UploadError::Unreachable => ClientError::Unreachable("no answer".into()),
            UploadError::Malformed(m) => ClientError::Malformed(m),
            UploadError::Rejected(m) => {
                let status = m.strip_prefix("status ").and_then(|r| r.split(':').next()).and_then(|n| n.parse().ok()).unwrap_or(0);
                let body = m.split_once(": ").map_or("", |x| x.1);
                ClientError::Refused { status, code: serde_json::from_str::<Json>(body).ok().and_then(|j| j.get("code").or(j.get("error")).and_then(Json::as_str).map(str::to_owned)).unwrap_or_else(|| body.chars().take(120).collect()) }
            }
            other => ClientError::Malformed(format!("{other:?}")),
        })
    }
}

/// Records a client failure on `out` with the right exit code: an unreachable or unbuilt
/// transport is a configuration or adapter error (3), a refusal or a malformed answer a
/// failure (1).
pub fn report(out: &mut crate::outcome::Outcome, url: &str, e: &ClientError) {
    use crate::outcome::exit;
    use crate::support::fail;
    match e {
        ClientError::NotBuilt(s) => fail(out, exit::CONFIG, "transport-not-built", &[("url", url), ("scheme", s)]),
        ClientError::BadUrl => fail(out, exit::CONFIG, "bad-scheme", &[("url", url)]),
        ClientError::Cleartext => fail(out, exit::USAGE, "operator-cleartext", &[("url", url)]),
        ClientError::Unreachable(r) => fail(out, exit::CONFIG, "service-unreachable", &[("url", url), ("reason", r)]),
        ClientError::Refused { status, code } => fail(out, exit::FAILED, "service-refused", &[("url", url), ("status", &status.to_string()), ("code", code)]),
        ClientError::Malformed(r) => fail(out, exit::FAILED, "service-malformed", &[("url", url), ("reason", r)]),
    }
}
