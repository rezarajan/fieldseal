//! The factory's HTTP adapter: drives the Registration use cases
//! ([`fieldseal_registration::application::Factory`]) from HTTP.
//!
//! **Runtime API** (JSON responses, CBOR request bodies):
//!
//! | Method and path | Auth | Use case |
//! |---|---|---|
//! | `POST /v1/registrations` | none (the request is sealed and proves possession) | `SubmitRequest`, `RollKey` |
//! | `GET /v1/registrations/{tenancy}` | none; returns the state only | status polling |
//! | `GET /v1/certificate` | `Fieldseal-PoP` | `GetCertificate` (CBOR) |
//! | `GET /v1/bundle?held=<n>` | `Fieldseal-PoP` | `FetchBundle` (the stored `FSB1` bytes) |
//! | `POST /v1/api-token` | `Fieldseal-PoP` | `IssueApiToken` |
//! | `POST /v1/posture/nonce`, `POST /v1/posture` | `Fieldseal-PoP` | `CheckPosture` |
//!
//! **Operator API** (JSON responses, canonical CBOR request bodies, `Authorization: Bearer`):
//!
//! | Method and path | Use case |
//! |---|---|
//! | `POST /v1/rosters` | `IssueRoster` |
//! | `POST /v1/assignments` | `AssignCohort` |
//! | `GET /v1/assignments` | `ListAssignments` |
//!
//! A route verifies the Bearer access token with the [`BearerVerifier`], then the use case
//! requires the `operator` role and a phishing-resistant sign-in. These routes read no
//! cookie, and the portal pages read no Bearer token. No roster body is logged.
//!
//! PoP-protected endpoints take the WIRE-170 token in the `Fieldseal-PoP` header and, when
//! an access token is used, `Authorization: FieldsealPoP <base64url>`. The token's `url` is
//! the request URL without its query (WIRE-171): a query such as `held` only narrows the
//! answer and is not signed.
//!
//! **Bundles.** `GET /v1/bundle` and the portal's `GET /devices/{device}/bundle.fsb` serve
//! the bundle the factory has already stored ([`BundleRoutes`]). They never build one
//! (DIS-084) and check the tenancy's state at every request (DIS-003).
//!
//! **Portal** (server-rendered HTML, no scripts): sign-in through the `IdentityProvider`
//! port, tokens as text and QR (REG-007), pending requests with fingerprint words and
//! indices (REG-021, REG-023), devices with mark-lost and retire (REG-043), request-file
//! upload and certificate and bundle download for the air-gapped route (REG-053, REG-054,
//! DIS-041). Every string comes from [`messages`]. Sessions are server-side, behind an `HttpOnly`,
//! `SameSite=Lax` cookie; every form carries a CSRF token.
//!
//! Requests are handled one at a time ([`FactoryHttp::run`]); [`FactoryHttp::handle`] is
//! framework-free so it can be tested without sockets. TLS is terminated in front.

pub mod client;
pub mod html;
pub mod messages;

use std::sync::Arc;

use fieldseal_distribution::application::{BundleFetchResponse, DownloadBundle, FetchBundle};
use fieldseal_distribution::domain::{BundleSeq, DistributionError, SealedBundle, file_name};
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::Value;
use fieldseal_kernel::cbor;
use fieldseal_kernel::id::{CohortId, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_registration::application::{Factory, RegistrationError, Submission};
use fieldseal_registration::domain::wire::{POP_HEADER, base64url_decode, base64url_encode, decode_request_file};
use fieldseal_registration::domain::{AccountId, AuthenticatedPerson, DeviceId, RegistrationRoute, Role, TenancyRecord, TenancyState};
use fieldseal_registration::ports::IdentityProvider;
use serde_json::{Value as Json, json};

pub use fieldseal_adapters_portal::{Request, Response, multipart_field, parse_form};
use fieldseal_adapters_portal::front::{self, BodyLimits, Reply};
use fieldseal_adapters_portal::{PortalSessions, SessionId, SessionView};

use crate::html::{escape, page, qr_svg, words};
use crate::messages::{format as fmt, t};

/// The largest request body accepted.
pub const MAX_BODY: usize = 1024 * 1024;
/// The largest bundle the factory builds and its client reads (Distribution open question 2:
/// a lower limit than the 64 MiB of the wire). It is the answer limit of `GET /v1/bundle`,
/// not the 1 MiB of the other calls.
pub const BUNDLE_LIMIT: usize = 8 * 1024 * 1024;
/// The session cookie's name.
pub const SESSION_COOKIE: &str = "fs_session";

/// The content-security policy of every portal page: no scripts, nothing from elsewhere.
const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// An HTML page with the portal's content-security policy.
fn html(status: u16, body: String) -> Response {
    Response::html(status, body, CSP)
}

/// Why a Bearer access token was refused.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum BearerError {
    /// The token is not valid: a bad signature, issuer, audience, type or client, a `nonce`,
    /// or expired. The reason is for the factory's own log and is never sent to the caller.
    #[error("token invalid: {0}")]
    Invalid(String),
    /// The identity provider's keys could not be fetched.
    #[error("identity provider unavailable: {0}")]
    Unavailable(String),
}

/// Verifies the access token of an operator API call (Technical Plan 7.5). The implementation
/// returns who the token names; it does not decide whether that person may operate: the use
/// case requires the `operator` role and a phishing-resistant method.
pub trait BearerVerifier {
    /// Verifies `token`, the text after `Bearer `.
    fn verify(&self, token: &str) -> Result<AuthenticatedPerson, BearerError>;

    /// The account a person with the identity provider subject `sub` signs in as. It is the
    /// rule the sign-in uses to build `AuthenticatedPerson::account`, so that an assignment
    /// made for a subject reaches that person's tenancies. The operator sends the bare
    /// subject and the factory maps it here.
    fn account_for_subject(&self, sub: &str) -> AccountId;

    /// The inverse of `account_for_subject`: the bare subject of an account id this verifier
    /// built, or `None` when the id does not carry this verifier's prefix.
    fn subject_of_account(&self, account: &AccountId) -> Option<String>;
}

/// Told which tenancies' bundles must be rebuilt after a journaled change: an assignment, a
/// roster issue or a registration. It only tells; the rebuild happens on the reconciler's own
/// thread, so a request never waits for a build.
pub type ReconcileNotify = Arc<dyn Fn(TenancyId) + Send + Sync>;

/// A [`ReconcileNotify`] that does nothing.
pub fn no_reconcile() -> ReconcileNotify {
    Arc::new(|_| {})
}

/// What the operator API tells the factory's event log. It carries no roster value and no
/// account subject (DEP-051).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum OperatorEvent {
    /// A cohort was assigned (`assignment-made`).
    AssignmentMade {
        /// The survey.
        survey: String,
        /// The cohort.
        cohort: String,
        /// The generation recorded.
        generation: u32,
    },
    /// A roster version was stored (`roster-issued`).
    RosterIssued {
        /// The cohort.
        cohort: String,
        /// The version.
        version: u64,
        /// SHA-256 of the stored roster, in lower-case hex.
        digest: String,
    },
}

/// Receives the [`OperatorEvent`]s.
pub type OperatorEvents = Arc<dyn Fn(&OperatorEvent) + Send + Sync>;

/// The operator API's collaborators.
struct OperatorApi<'a> {
    bearer: &'a dyn BearerVerifier,
    notify: ReconcileNotify,
    events: OperatorEvents,
}

/// The stored bundles the runtime and portal routes serve. The factory builds both from
/// Distribution's `BundleDelivery`, which implements both traits (that name is taken).
#[derive(Clone, Copy)]
pub struct BundleRoutes<'a> {
    /// `FetchBundle`, for `GET /v1/bundle`.
    pub fetch: &'a dyn FetchBundle,
    /// `DownloadBundle`, for the portal's `GET /devices/{device}/bundle.fsb`.
    pub download: &'a dyn DownloadBundle,
}

/// The largest operator request body read (assignments are three short texts; rosters use
/// [`MAX_BODY`]).
const MAX_ASSIGNMENT_BODY: usize = 4096;

/// The adapter's settings, from the environment.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HttpConfig {
    /// The externally visible base URL (for example `https://factory.example.org`): PoP
    /// tokens are checked against it and sign-in returns to it.
    pub public_url: String,
    /// Portal session lifetime, in milliseconds.
    pub session_ttl_ms: u64,
}

impl HttpConfig {
    fn secure_cookies(&self) -> bool {
        self.public_url.starts_with("https://")
    }
}

/// Authority time as ISO 8601 UTC, to the second.
pub fn iso8601(t: AuthorityTime) -> String {
    let secs = t.0 / 1000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil from days (H. Hinnant).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// A stable, machine-readable code for each error, for API clients and support.
pub fn error_code(e: &RegistrationError) -> &'static str {
    use fieldseal_registration::ports::TokenError;
    match e {
        RegistrationError::PolicyDenied(_) => "policy-denied",
        RegistrationError::DeviceLimitReached => "device-limit-reached",
        RegistrationError::Authentication(_) => "authentication-too-weak",
        RegistrationError::NotAuthorised(_) => "not-authorised",
        RegistrationError::Token(TokenError::Unknown) => "token-invalid",
        RegistrationError::Token(TokenError::Used) => "token-used",
        RegistrationError::Token(TokenError::Expired) => "token-expired",
        RegistrationError::RouteMismatch => "route-mismatch",
        RegistrationError::WrongAccount => "wrong-account",
        RegistrationError::NonceMismatch => "nonce-mismatch",
        RegistrationError::ProofInvalid => "proof-invalid",
        RegistrationError::EvidenceRejected(_) => "evidence-rejected",
        RegistrationError::Malformed(_) => "malformed",
        RegistrationError::Replay => "replay",
        RegistrationError::NotPending => "not-pending",
        RegistrationError::NotHeld => "not-held",
        RegistrationError::ConfirmationExpired => "confirmation-expired",
        RegistrationError::NotRegistered => "not-registered",
        RegistrationError::Revoked => "revoked",
        RegistrationError::NotFound => "not-found",
        RegistrationError::TenancyExists => "tenancy-exists",
        RegistrationError::UnknownSurvey => "unknown-survey",
        RegistrationError::UnknownCohort => "unknown-cohort",
        RegistrationError::RosterInvalid(_) => "roster-invalid",
        RegistrationError::VersionTaken => "version-taken",
        RegistrationError::NotNewer => "not-newer",
        RegistrationError::Port(_) => "unavailable",
    }
}

fn status_of(e: &RegistrationError) -> u16 {
    match e {
        RegistrationError::ProofInvalid | RegistrationError::Replay => 401,
        RegistrationError::PolicyDenied(_)
        | RegistrationError::Authentication(_)
        | RegistrationError::NotAuthorised(_)
        | RegistrationError::WrongAccount
        | RegistrationError::Revoked
        | RegistrationError::NotRegistered => 403,
        RegistrationError::NotFound | RegistrationError::UnknownSurvey | RegistrationError::UnknownCohort => 404,
        RegistrationError::RosterInvalid(_) => 422,
        RegistrationError::VersionTaken
        | RegistrationError::NotNewer
        | RegistrationError::DeviceLimitReached
        | RegistrationError::NotPending
        | RegistrationError::NotHeld
        | RegistrationError::TenancyExists
        | RegistrationError::Token(_)
        | RegistrationError::ConfirmationExpired => 409,
        RegistrationError::Port(_) => 503,
        _ => 400,
    }
}

fn api_error(e: &RegistrationError) -> Response {
    let mut body = json!({ "error": error_code(e) });
    if let RegistrationError::PolicyDenied(reasons) = e {
        body["reasons"] = json!(reasons);
    }
    if let RegistrationError::RosterInvalid(reason) = e {
        // Paths and messages of the closed-schema check name a subject by position, never by id.
        body["reason"] = json!(reason);
    }
    if matches!(e, RegistrationError::UnknownSurvey | RegistrationError::UnknownCohort | RegistrationError::VersionTaken | RegistrationError::NotNewer) {
        body["message"] = json!(messages::text(&format!("api.{}", error_code(e))));
    }
    Response::json(status_of(e), body)
}

/// How many bundle responses are written to clients at once. Each is written on its own
/// thread, so that a client that stops reading cannot stall the serving thread; past this
/// many the factory answers `503 unavailable` instead of starting another.
pub const MAX_BUNDLE_WRITERS: usize = 32;

/// One of the [`MAX_BUNDLE_WRITERS`] places; giving it back is the drop, so a writer that
/// fails or panics still frees it.
struct WriterSlot(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl WriterSlot {
    /// A place, or `None` when all of them are taken.
    fn take(count: &std::sync::Arc<std::sync::atomic::AtomicUsize>) -> Option<Self> {
        use std::sync::atomic::Ordering;
        if count.fetch_add(1, Ordering::SeqCst) >= MAX_BUNDLE_WRITERS {
            count.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Self(count.clone()))
    }
}

impl Drop for WriterSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The response with `Cache-Control: no-store`: a bundle answer is never cached, whatever it says.
fn no_store(response: Response) -> Response {
    response.with("Cache-Control", "no-store".into())
}

/// `200` with the stored `FSB1` bytes, the sequence number and the DIS-023 file name.
fn bundle_response(bundle: &SealedBundle) -> Response {
    Response::new(200, "application/octet-stream", bundle.bytes.clone())
        .with("Fieldseal-Bundle-Sequence", bundle.seq.0.to_string())
        .with("Content-Disposition", format!("attachment; filename=\"{}\"", file_name(bundle.issued.0, bundle.seq.0)))
}

/// The answer to a bundle call that Distribution refused. Only the reasons of a withheld
/// tenancy are sent: they are codes, never subject data.
fn bundle_error(e: &DistributionError) -> Response {
    match e {
        DistributionError::NotRegistered => Response::json(403, json!({ "error": "not-registered" })),
        DistributionError::Withheld(reasons) => Response::json(403, json!({ "error": "withheld", "reasons": reasons })),
        _ => Response::json(503, json!({ "error": "unavailable" })),
    }
}

/// The subject an operator sent for an account, which the bearer verifier strips from the
/// account id it built (`{issuer}|{subject}`). A subject may hold `|` (Auth0 uses
/// `auth0|123`), so the id is never split on one. The journal keeps only the account id; the
/// subject is derived here, so no second copy can disagree with it. An id that does not carry
/// the verifier's prefix is shown whole.
fn subject_of(bearer: &dyn BearerVerifier, account: &AccountId) -> String {
    bearer.subject_of_account(account).unwrap_or_else(|| account.0.clone())
}

fn parse_tenancy(hex: &str) -> Option<TenancyId> {
    if hex.len() != 64 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..64).step_by(2).map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()).collect();
    TenancyId::from_bytes(&bytes?).ok()
}

fn tenancy_json(t: &TenancyRecord) -> Json {
    json!({
        "tenancy": lower_hex(t.id.as_bytes()),
        "state": t.state.as_str(),
        "reasons": t.reasons,
        "words": t.words.joined(),
        "indices": t.words.indices().to_vec(),
    })
}

/// The wire form of `response`, with the headers every answer carries.
fn into_answer(response: Response) -> front::Answer {
    let mut out = tiny_http::Response::from_data(response.body).with_status_code(response.status);
    for (k, v) in response.headers.iter().chain(&[
        ("X-Content-Type-Options".to_owned(), "nosniff".to_owned()),
        ("Referrer-Policy".to_owned(), "no-referrer".to_owned()),
    ]) {
        if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            out.add_header(h);
        }
    }
    out
}

/// The HTTP adapter over one [`Factory`] and one [`IdentityProvider`].
pub struct FactoryHttp<'a> {
    factory: &'a Factory<'a>,
    idp: &'a dyn IdentityProvider,
    config: HttpConfig,
    sessions: PortalSessions,
    operator: Option<OperatorApi<'a>>,
    bundles: Option<BundleRoutes<'a>>,
    registered: Option<ReconcileNotify>,
}

impl<'a> FactoryHttp<'a> {
    /// The adapter.
    pub fn new(factory: &'a Factory<'a>, idp: &'a dyn IdentityProvider, config: HttpConfig) -> Self {
        let sessions = PortalSessions::new(SESSION_COOKIE, config.secure_cookies(), config.session_ttl_ms);
        Self { factory, idp, config, sessions, operator: None, bundles: None, registered: None }
    }

    /// Serves the operator API: Bearer tokens are verified by `bearer`, `notify` is told
    /// which tenancies a journaled change touched, and `events` receives `assignment-made`
    /// and `roster-issued`. Without this the operator routes answer `503 unavailable`.
    #[must_use]
    pub fn with_operator_api(mut self, bearer: &'a dyn BearerVerifier, notify: ReconcileNotify, events: OperatorEvents) -> Self {
        self.operator = Some(OperatorApi { bearer, notify, events });
        self
    }

    /// Serves the stored bundle at `GET /v1/bundle` and in the portal. Without this both
    /// answer `503 unavailable`.
    #[must_use]
    pub fn with_bundle_routes(mut self, routes: BundleRoutes<'a>) -> Self {
        self.bundles = Some(routes);
        self
    }

    /// Tells `notify` which tenancy has just registered (or rolled its key), so its bundle is
    /// built without waiting for the next scan.
    #[must_use]
    pub fn with_registration_notify(mut self, notify: ReconcileNotify) -> Self {
        self.registered = Some(notify);
        self
    }

    /// Serves requests from `server` for as long as the process lives. The serving thread only runs
    /// [`handle`](Self::handle) over a request whose body is complete and in memory: bodies are
    /// read, and answers written, on threads of their own under the shared front end's limits
    /// (SR-2), so a client that stalls or never reads holds nothing here.
    pub fn run(&self, server: &tiny_http::Server) {
        self.run_until(server, &|| false, BodyLimits::default());
    }

    /// [`run`](Self::run) that returns once `stopped` says so, with the body limits given.
    pub fn run_until(&self, server: &tiny_http::Server, stopped: &dyn Fn() -> bool, limits: BodyLimits) {
        let writers = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // The operator routes authorise before any of the body is read, so that only a
        // verified operator can make the factory read it.
        let screen = |req: &tiny_http::Request| {
            let head = Self::head_of(req, Vec::new());
            if Self::is_operator_route(&head) { self.operator(&head).err().map(into_answer) } else { None }
        };
        let answer = |req: &tiny_http::Request, body: Option<Vec<u8>>| {
            let Some(body) = body else { return into_answer(Response::json(413, json!({ "error": "too-large" }))).into() };
            let request = Self::head_of(req, body);
            let mut response = self.handle(&request);
            // Only a bundle that is about to be sent holds a writer place.
            let mut slot = None;
            if Self::is_bundle_route(&request) && response.status == 200 {
                slot = WriterSlot::take(&writers);
                if slot.is_none() {
                    response = Response::json(503, json!({ "error": "unavailable" }));
                }
            }
            Reply { answer: into_answer(response), guard: slot.map(|s| Box::new(s) as Box<dyn Send>) }
        };
        front::serve_screened(server, MAX_BODY, limits, stopped, &screen, &answer);
    }

    /// The request as the handler sees it, with `body`.
    fn head_of(req: &tiny_http::Request, body: Vec<u8>) -> Request {
        let headers = req.headers().iter().map(|h| (h.field.as_str().as_str().to_ascii_lowercase(), h.value.as_str().to_owned())).collect();
        Request::new(req.method().as_str(), req.url(), headers, body)
    }

    /// Whether `req` asks for a bundle, whose body can be large: `GET /v1/bundle` and the
    /// portal's download.
    fn is_bundle_route(req: &Request) -> bool {
        let segments: Vec<&str> = req.path.trim_matches('/').split('/').collect();
        matches!((req.method.as_str(), segments.as_slice()), ("GET", ["v1", "bundle"] | ["devices", _, "bundle.fsb"]))
    }

    /// Whether `req` is one of the operator routes, which verify a Bearer token.
    fn is_operator_route(req: &Request) -> bool {
        let segments: Vec<&str> = req.path.trim_matches('/').split('/').collect();
        matches!((req.method.as_str(), segments.as_slice()), ("POST", ["v1", "rosters" | "assignments"]) | ("GET", ["v1", "assignments"]))
    }

    /// Handles one request.
    pub fn handle(&self, req: &Request) -> Response {
        let segments: Vec<&str> = req.path.trim_matches('/').split('/').collect();
        match (req.method.as_str(), segments.as_slice()) {
            // Orchestrator probes: no authentication, no data. The factory is constructed
            // (its trust bundle and keys checked) before the server listens, so being able
            // to answer means it is ready; the identity provider is contacted lazily.
            ("GET", ["healthz"]) => Response::json(200, json!({ "status": "ok" })),
            ("GET", ["readyz"]) => Response::json(200, json!({ "status": "ready" })),
            // Runtime API.
            ("POST", ["v1", "registrations"]) => self.api_submit(req),
            ("GET", ["v1", "registrations", id]) => self.api_status(id),
            ("GET", ["v1", "certificate"]) => self.with_pop(req, |r| match self.factory.certificate(&r.id) {
                Ok(c) => Response::new(200, "application/cbor", c.encode()),
                Err(e) => api_error(&e),
            }),
            ("GET", ["v1", "bundle"]) => self.api_bundle(req),
            ("POST", ["v1", "api-token"]) => self.with_pop(req, |r| match self.factory.issue_api_token(&r) {
                Ok(a) => Response::json(200, json!({ "access_token": base64url_encode(&a.value), "expires": a.expires_at.0 })),
                Err(e) => api_error(&e),
            }),
            ("POST", ["v1", "posture", "nonce"]) => self.with_pop(req, |r| match self.factory.posture_nonce(&r.id) {
                Ok(n) => Response::json(200, json!({ "nonce": base64url_encode(n.as_bytes()) })),
                Err(e) => api_error(&e),
            }),
            ("POST", ["v1", "posture"]) => self.with_pop(req, |_| match self.factory.check_posture(&req.body) {
                Ok(o) => Response::json(200, json!({ "ok": o.ok, "reasons": o.reasons })),
                Err(e) => api_error(&e),
            }),
            // Operator API: Bearer access token only.
            ("POST", ["v1", "rosters"]) => self.api_issue_roster(req),
            ("POST", ["v1", "assignments"]) => self.api_assign(req),
            ("GET", ["v1", "assignments"]) => self.api_assignments(req),
            // Portal.
            ("GET", [""]) => self.portal_home(req),
            ("GET", ["sign-in"]) => self.sign_in(),
            ("GET", ["sign-in", "callback"]) => self.sign_in_callback(req),
            ("POST", ["sign-out"]) => self.portal_post(req, |_, sid| {
                self.sessions.end(sid);
                Response::redirect("/").with("Set-Cookie", self.sessions.clear_cookie())
            }),
            ("POST", ["tokens"]) => self.portal_post(req, |person, _| self.portal_token(req, person)),
            ("POST", ["pending", id, "confirm"]) => self.portal_post(req, |person, _| {
                match parse_tenancy(id).ok_or(RegistrationError::NotFound).and_then(|t| self.factory.confirm(&person.account, &t)) {
                    Ok(record) => {
                        self.registered(&record);
                        Response::redirect("/")
                    }
                    Err(e) => self.portal_error(&e, Some(&person.account.0)),
                }
            }),
            ("POST", ["devices", id, action @ ("lost" | "retire")]) => self.portal_post(req, |person, _| {
                let device = DeviceId((*id).to_owned());
                let result = if *action == "lost" { self.factory.mark_lost(person, &device) } else { self.factory.retire(person, &device) };
                match result {
                    Ok(cert) => self.portal_close(&cert, person),
                    Err(e) => self.portal_error(&e, Some(&person.account.0)),
                }
            }),
            ("POST", ["uploads"]) => self.portal_post(req, |person, _| self.portal_upload(req, person)),
            ("GET", ["tenancies", id, "certificate.cbor"]) => self.portal_download(req, id),
            ("GET", ["devices", id, "bundle.fsb"]) => self.portal_bundle(req, id),
            _ => self.not_found(req),
        }
    }

    fn not_found(&self, req: &Request) -> Response {
        if req.path.starts_with("/v1/") {
            Response::json(404, json!({ "error": "not-found" }))
        } else {
            html(404, page("portal.error.heading", &format!("<p>{}</p>", t("portal.error.notfound")), None))
        }
    }

    // -----------------------------------------------------------------------------------
    // Runtime API.

    fn api_submit(&self, req: &Request) -> Response {
        let sealed = match decode_request_file(&req.body) {
            Ok(s) => s,
            Err(e) => return api_error(&RegistrationError::Malformed(e)),
        };
        match self.factory.submit(&sealed, Submission::Online) {
            Ok(s) => {
                self.registered(&s.tenancy);
                Response::json(202, tenancy_json(&s.tenancy))
            }
            Err(e) => api_error(&e),
        }
    }

    /// Tells the reconciler about a tenancy that is now registered.
    fn registered(&self, tenancy: &TenancyRecord) {
        if tenancy.state == TenancyState::Registered
            && let Some(notify) = &self.registered
        {
            notify(tenancy.id);
        }
    }

    fn api_status(&self, id: &str) -> Response {
        match parse_tenancy(id).ok_or(RegistrationError::NotFound).and_then(|t| self.factory.status(&t)) {
            Ok(t) => Response::json(200, json!({ "state": t.state.as_str(), "reasons": t.reasons })),
            Err(e) => api_error(&e),
        }
    }

    fn with_pop(&self, req: &Request, f: impl FnOnce(TenancyRecord) -> Response) -> Response {
        let Some(pop) = req.header(&POP_HEADER.to_ascii_lowercase()) else {
            return Response::json(401, json!({ "error": "pop-required" })).with("WWW-Authenticate", "FieldsealPoP".into());
        };
        let access = match req.header("authorization").and_then(|a| a.strip_prefix("FieldsealPoP ")) {
            None => None,
            Some(v) => match base64url_decode(v.trim()).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) {
                Some(a) => Some(a),
                None => return api_error(&RegistrationError::ProofInvalid),
            },
        };
        let url = format!("{}{}", self.config.public_url.trim_end_matches('/'), req.path);
        match self.factory.authenticate_api(pop, &req.method, &url, access.as_ref()) {
            Ok(record) => f(record),
            Err(e) => api_error(&e),
        }
    }

    /// `GET /v1/bundle`: the stored bundle, `304` when `held` is the latest, `404` when none is
    /// stored. The query is not part of the proof of possession (WIRE-171); a `held` that is
    /// not a whole number is ignored, which gives the full bundle, as a rewritten one would.
    fn api_bundle(&self, req: &Request) -> Response {
        let held = req.query.get("held").and_then(|h| h.parse().ok()).map(BundleSeq);
        no_store(self.with_pop(req, |record| {
            let Some(routes) = &self.bundles else { return Response::json(503, json!({ "error": "unavailable" })) };
            match routes.fetch.fetch(&record.id, held) {
                Ok(BundleFetchResponse::Bundle(b)) => bundle_response(&b),
                Ok(BundleFetchResponse::Current) => {
                    // No sequence header: the device already knows what it holds.
                    Response { status: 304, headers: vec![], body: vec![] }
                }
                Ok(BundleFetchResponse::NoBundle) => Response::json(404, json!({ "error": "no-bundle", "message": messages::text("api.no-bundle") })),
                Err(e) => bundle_error(&e),
            }
        }))
    }

    // -----------------------------------------------------------------------------------
    // Operator API.

    /// Verifies the Bearer access token of `req` and makes the operator checks. [`Self::run`]
    /// calls it with the headers alone, before it reads the body of an operator route, so a
    /// body is read only for a person who may send it (the use case checks again). Only the
    /// `Authorization` header is read: a portal session cookie is never accepted here.
    fn operator<'s>(&'s self, req: &Request) -> Result<(&'s OperatorApi<'a>, AuthenticatedPerson), Response> {
        let Some(api) = &self.operator else {
            return Err(api_error(&RegistrationError::Port("the operator API is not wired".into())));
        };
        let bearer_required = || Response::json(401, json!({ "error": "bearer-required" })).with("WWW-Authenticate", "Bearer".into());
        let Some(token) = req.header("authorization").and_then(|a| a.strip_prefix("Bearer ")).map(str::trim).filter(|t| !t.is_empty()) else {
            return Err(bearer_required());
        };
        let person = match api.bearer.verify(token) {
            Ok(p) => p,
            Err(BearerError::Invalid(_)) => {
                return Err(Response::json(401, json!({ "error": "token-invalid" })).with("WWW-Authenticate", "Bearer error=\"invalid_token\"".into()));
            }
            Err(BearerError::Unavailable(_)) => return Err(Response::json(503, json!({ "error": "unavailable" }))),
        };
        self.factory.authorise_operator(&person).map_err(|e| api_error(&e))?;
        Ok((api, person))
    }

    /// The `cohort` text of a canonical CBOR roster body, and nothing else of it: the issuer
    /// checks the rest.
    fn roster_cohort(body: &[u8]) -> Option<CohortId> {
        match cbor::decode_limited(body, MAX_BODY).ok()? {
            Value::Map(m) => match m.get("cohort")? {
                Value::Text(t) => CohortId::new(t.as_str()).ok(),
                _ => None,
            },
            _ => None,
        }
    }

    fn api_issue_roster(&self, req: &Request) -> Response {
        let (api, person) = match self.operator(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let Some(cohort) = Self::roster_cohort(&req.body) else {
            return api_error(&RegistrationError::RosterInvalid("the roster body is not a canonical CBOR map with a cohort".into()));
        };
        match self.factory.issue_roster(&person, &cohort, &req.body) {
            Ok(done) => {
                let digest = format!("sha256:{}", lower_hex(done.digest.as_bytes()));
                if !done.unchanged {
                    (api.events)(&OperatorEvent::RosterIssued { cohort: cohort.as_str().to_owned(), version: done.version, digest: lower_hex(done.digest.as_bytes()) });
                    for t in done.affected {
                        (api.notify)(t);
                    }
                }
                let status = if done.unchanged { "unchanged" } else { "issued" };
                Response::json(200, json!({ "status": status, "cohort": cohort.as_str(), "version": done.version, "digest": digest }))
            }
            Err(e) => api_error(&e),
        }
    }

    /// The three texts of an assignment body: `account` (the bare subject), `survey` and
    /// `cohort`. A subject that is empty, longer than 255 bytes, or holds `|` or a control
    /// character is refused: `|` is the separator of the account id the sign-in builds, so a
    /// subject with one could name another issuer's account.
    fn assignment_body(body: &[u8]) -> Option<(String, String, CohortId)> {
        let Value::Map(m) = cbor::decode_limited(body, MAX_ASSIGNMENT_BODY).ok()? else { return None };
        if m.len() != 3 {
            return None;
        }
        let text = |k: &str| match m.get(k) {
            Some(Value::Text(t)) if !t.is_empty() => Some(t.clone()),
            _ => None,
        };
        let subject = text("account")?;
        if subject.len() > 255 || subject.chars().any(char::is_control) {
            return None;
        }
        Some((subject, text("survey")?, CohortId::new(text("cohort")?).ok()?))
    }

    fn api_assign(&self, req: &Request) -> Response {
        let (api, person) = match self.operator(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let Some((subject, survey, cohort)) = Self::assignment_body(&req.body) else {
            return api_error(&RegistrationError::Malformed(fieldseal_kernel::WireError::new(fieldseal_kernel::ErrorCode::UnknownField, 0, "an assignment is {account, survey, cohort}")));
        };
        let account = api.bearer.account_for_subject(&subject);
        match self.factory.assign_cohort(&person, &account, &survey, &cohort) {
            Ok(done) => {
                if !done.unchanged {
                    (api.events)(&OperatorEvent::AssignmentMade { survey: survey.clone(), cohort: cohort.as_str().to_owned(), generation: done.assignment.generation.0 });
                }
                for t in done.changed {
                    (api.notify)(t);
                }
                let status = if done.unchanged { "unchanged" } else { "assigned" };
                Response::json(
                    200,
                    json!({ "status": status, "account": subject, "survey": survey, "cohort": cohort.as_str(), "generation": done.assignment.generation.0 }),
                )
            }
            Err(e) => api_error(&e),
        }
    }

    fn api_assignments(&self, req: &Request) -> Response {
        let (api, person) = match self.operator(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        match self.factory.list_assignments(&person) {
            Ok(list) => {
                let rows: Vec<Json> = list
                    .iter()
                    .map(|a| {
                        json!({
                            "seq": a.seq.0, "account": subject_of(api.bearer, &a.account), "survey": a.survey, "cohort": a.cohort.as_str(),
                            "generation": a.generation.0, "by": a.by.0, "roles": a.roles, "methods": a.methods,
                            "at": iso8601(a.at),
                        })
                    })
                    .collect();
                Response::json(200, json!({ "assignments": rows }))
            }
            Err(e) => api_error(&e),
        }
    }

    // -----------------------------------------------------------------------------------
    // Sessions and sign-in.

    fn session(&self, req: &Request) -> Option<SessionView> {
        self.sessions.session(req.header("cookie"), self.factory.now())
    }

    fn sign_in(&self) -> Response {
        let callback = format!("{}/sign-in/callback", self.config.public_url.trim_end_matches('/'));
        match self.sessions.begin(self.idp, &callback, self.factory.now()) {
            Ok((redirect_to, pre_auth)) => Response::redirect(&redirect_to).with("Set-Cookie", pre_auth),
            Err(e) => html(503, page("portal.error.heading", &format!("<p>{}</p>", fmt("portal.signin.failed", &[("reason", &e.to_string())])), None)),
        }
    }

    fn sign_in_callback(&self, req: &Request) -> Response {
        match self.sessions.finish(self.idp, &req.query, req.header("cookie"), self.factory.now()) {
            Ok((_, set_cookie)) => Response::redirect("/").with("Set-Cookie", set_cookie).with("Set-Cookie", self.sessions.clear_pre_auth_cookie()),
            Err(e) => html(401, page("portal.error.heading", &format!("<p>{}</p>", fmt("portal.signin.failed", &[("reason", &e.to_string())])), None)),
        }
    }

    /// Runs `f` for a signed-in person after checking the form's CSRF token.
    fn portal_post(&self, req: &Request, f: impl FnOnce(&AuthenticatedPerson, &SessionId) -> Response) -> Response {
        let Some(session) = self.session(req) else { return Response::redirect("/") };
        let form_csrf = if req.header("content-type").is_some_and(|c| c.starts_with("multipart/form-data")) {
            multipart_field(req, "csrf").map(|b| String::from_utf8_lossy(&b).into_owned())
        } else {
            req.form().get("csrf").cloned()
        };
        if !form_csrf.is_some_and(|c| self.sessions.check_csrf(&session, &c)) {
            return html(403, page("portal.error.heading", &format!("<p>{}</p>", t("portal.error.csrf")), None));
        }
        f(&session.person, &session.id)
    }

    fn portal_error(&self, e: &RegistrationError, _account: Option<&str>) -> Response {
        let reason = match e {
            RegistrationError::DeviceLimitReached => t("portal.devices.limit"),
            RegistrationError::Authentication(_) => t("portal.signin.weak"),
            other => fmt("portal.error.denied", &[("reason", &other.to_string())]),
        };
        html(status_of(e), page("portal.error.heading", &format!("<p>{reason}</p><p><a href=\"/\">{}</a></p>", t("portal.token.back")), None))
    }

    // -----------------------------------------------------------------------------------
    // Portal pages.

    fn csrf_field(csrf: &str) -> String {
        format!("<input type=\"hidden\" name=\"csrf\" value=\"{}\">", escape(csrf))
    }

    fn portal_home(&self, req: &Request) -> Response {
        let Some(SessionView { person, csrf, .. }) = self.session(req) else {
            let body = format!(
                "<p>{}</p><p><a href=\"/sign-in\">{}</a></p>",
                t("portal.signin.intro"),
                t("portal.signin.button")
            );
            return html(200, page("portal.signin.heading", &body, None));
        };
        let mut body = format!("<p>{}</p>", fmt("portal.signedin", &[("account", &person.account.0)]));
        let operator = person.has(Role::Operator);
        // Token form.
        body.push_str(&format!(
            "<section aria-labelledby=\"tok\"><h2 id=\"tok\">{}</h2><form method=\"post\" action=\"/tokens\">{}\
<fieldset><legend>{}</legend>\
<p><input type=\"radio\" id=\"r-online\" name=\"route\" value=\"online\" checked> <label for=\"r-online\">{}</label></p>\
<p><input type=\"radio\" id=\"r-air\" name=\"route\" value=\"air-gapped\"> <label for=\"r-air\">{}</label></p></fieldset>{}\
<p><button type=\"submit\">{}</button></p></form></section>",
            t("portal.token.heading"),
            Self::csrf_field(&csrf),
            t("portal.token.route"),
            t("portal.token.route.online"),
            t("portal.token.route.airgapped"),
            if operator {
                format!("<p><label for=\"uses\">{}</label> <input id=\"uses\" name=\"uses\" type=\"number\" min=\"1\" max=\"1000\" value=\"1\"></p>", t("portal.token.uses"))
            } else {
                String::new()
            },
            t("portal.token.button"),
        ));
        // Pending requests.
        body.push_str(&format!("<section aria-labelledby=\"pend\"><h2 id=\"pend\">{}</h2>", t("portal.pending.heading")));
        let pending = self.factory.pending(&person.account).unwrap_or_default();
        if pending.is_empty() {
            body.push_str(&format!("<p>{}</p>", t("portal.pending.none")));
        } else {
            body.push_str(&format!("<p>{}</p><ul>", t("portal.pending.compare")));
            for p in &pending {
                body.push_str(&format!(
                    "<li><p>{} {}</p><form method=\"post\" action=\"/pending/{}/confirm\">{}<button type=\"submit\">{}</button></form></li>",
                    if p.batch { format!("<strong>{}</strong>:", t("portal.pending.batch")) } else { String::new() },
                    words(&p.words),
                    lower_hex(p.id.as_bytes()),
                    Self::csrf_field(&csrf),
                    t("portal.pending.confirm"),
                ));
            }
            body.push_str("</ul>");
        }
        body.push_str("</section>");
        // Devices.
        body.push_str(&format!("<section aria-labelledby=\"dev\"><h2 id=\"dev\">{}</h2>", t("portal.devices.heading")));
        let devices = self.factory.list_devices(&person.account).unwrap_or_default();
        if devices.is_empty() {
            body.push_str(&format!("<p>{}</p>", t("portal.devices.none")));
        } else {
            body.push_str(&format!(
                "<table><thead><tr><th scope=\"col\">{}</th><th scope=\"col\">{}</th><th scope=\"col\">{}</th><th scope=\"col\">{}</th><th scope=\"col\">{}</th></tr></thead><tbody>",
                t("portal.devices.nickname"),
                t("portal.devices.words"),
                t("portal.devices.state"),
                t("portal.devices.lastseen"),
                t("portal.devices.actions"),
            ));
            for d in &devices {
                let state = d.tenancy.as_ref().map(|t| t.state).unwrap_or(TenancyState::Pending);
                let last = d.tenancy.as_ref().and_then(|t| t.last_seen).map(iso8601).unwrap_or_else(|| messages::text("portal.never").to_owned());
                let live = matches!(state, TenancyState::Registered | TenancyState::Flagged | TenancyState::Held | TenancyState::Pending);
                let mut actions = String::new();
                if live {
                    for (action, label) in [("lost", "portal.devices.lost"), ("retire", "portal.devices.retire")] {
                        actions.push_str(&format!(
                            "<form method=\"post\" action=\"/devices/{}/{action}\">{}<button type=\"submit\">{}</button></form>",
                            escape(&d.device.id.0),
                            Self::csrf_field(&csrf),
                            t(label)
                        ));
                    }
                }
                if let Some(tn) = d.tenancy.as_ref().filter(|t| t.certificate.is_some()) {
                    actions.push_str(&format!(
                        "<p><a href=\"/tenancies/{}/certificate.cbor\" download>{}</a></p>",
                        lower_hex(tn.id.as_bytes()),
                        t("portal.devices.certificate")
                    ));
                    actions.push_str(&format!("<p><a href=\"/devices/{}/bundle.fsb\" download>{}</a></p>", escape(&d.device.id.0), t("portal.devices.bundle")));
                }
                body.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{actions}</td></tr>",
                    escape(&d.device.nickname),
                    words(&d.device.words),
                    t(&format!("state.{}", state.as_str())),
                    escape(&last),
                ));
            }
            body.push_str(&format!("</tbody></table><p>{}</p>", t("portal.devices.roll")));
        }
        body.push_str("</section>");
        // Upload.
        body.push_str(&format!(
            "<section aria-labelledby=\"up\"><h2 id=\"up\">{}</h2><p>{}</p><form method=\"post\" action=\"/uploads\" enctype=\"multipart/form-data\">{}\
<p><label for=\"file\">{}</label> <input id=\"file\" name=\"request\" type=\"file\" required></p><p><button type=\"submit\">{}</button></p></form></section>",
            t("portal.upload.heading"),
            t("portal.upload.intro"),
            Self::csrf_field(&csrf),
            t("portal.upload.file"),
            t("portal.upload.button"),
        ));
        html(200, page("portal.title", &body, Some(&csrf)))
    }

    fn portal_token(&self, req: &Request, person: &AuthenticatedPerson) -> Response {
        let form = req.form();
        let route = match form.get("route").map(String::as_str) {
            Some("air-gapped") => RegistrationRoute::AirGapped,
            _ => RegistrationRoute::Online,
        };
        let uses = form.get("uses").and_then(|u| u.parse().ok()).unwrap_or(1);
        let issued = match self.factory.issue_token(person, route, uses) {
            Ok(t) => t,
            Err(e) => return self.portal_error(&e, Some(&person.account.0)),
        };
        let text = match issued.token.to_text() {
            Ok(t) => t,
            Err(e) => return self.portal_error(&RegistrationError::Malformed(e), None),
        };
        let csrf = self.session(req).map(|s| s.csrf).unwrap_or_default();
        let body = format!(
            "<p class=\"warning\" role=\"alert\">{}</p><p>{}</p><h2>{}</h2>{}<h2>{}</h2><p class=\"token\">{}</p><p><a href=\"/\">{}</a></p>",
            t("portal.token.warning"),
            fmt("portal.token.expires", &[("expires", &iso8601(issued.expires_at))]),
            t("portal.token.qr"),
            qr_svg(&text, messages::text("portal.token.qr")),
            t("portal.token.text"),
            escape(&text),
            t("portal.token.back"),
        );
        html(200, page("portal.token.issued.heading", &body, Some(&csrf)))
    }

    fn portal_close(&self, cert: &fieldseal_registration::domain::wire::CloseCertificate, _person: &AuthenticatedPerson) -> Response {
        let text = cert.to_text().unwrap_or_default();
        let body = format!(
            "<p>{}</p>{}<p class=\"token\">{}</p><p><a href=\"/\">{}</a></p>",
            fmt("portal.close.intro", &[("cutoff", &cert.cutoff.0.to_string())]),
            qr_svg(&text, messages::text("portal.close.heading")),
            escape(&text),
            t("portal.token.back"),
        );
        html(200, page("portal.close.heading", &body, None))
    }

    fn portal_upload(&self, req: &Request, person: &AuthenticatedPerson) -> Response {
        let Some(file) = multipart_field(req, "request") else {
            return self.portal_error(&RegistrationError::Malformed(fieldseal_kernel::WireError::new(fieldseal_kernel::ErrorCode::FrameMagic, 0, "no file")), None);
        };
        let result = decode_request_file(&file)
            .map_err(RegistrationError::Malformed)
            .and_then(|s| self.factory.submit(&s, Submission::Upload(person.account.clone())));
        match result {
            Ok(s) => {
                let csrf = self.session(req).map(|s| s.csrf).unwrap_or_default();
                let body = format!(
                    "<p>{}</p><p>{}</p><form method=\"post\" action=\"/pending/{}/confirm\">{}<button type=\"submit\">{}</button></form>",
                    t("portal.upload.done"),
                    words(&s.words),
                    lower_hex(s.tenancy.id.as_bytes()),
                    Self::csrf_field(&csrf),
                    t("portal.pending.confirm"),
                );
                html(200, page("portal.upload.heading", &body, Some(&csrf)))
            }
            Err(e) => self.portal_error(&e, Some(&person.account.0)),
        }
    }

    fn portal_download(&self, req: &Request, id: &str) -> Response {
        let Some(SessionView { person, .. }) = self.session(req) else { return Response::redirect("/") };
        let result = parse_tenancy(id).ok_or(RegistrationError::NotFound).and_then(|t| {
            let record = self.factory.status(&t)?;
            if record.account != person.account {
                return Err(RegistrationError::WrongAccount);
            }
            self.factory.certificate(&t)
        });
        match result {
            Ok(c) => Response::new(200, "application/cbor", c.encode())
                .with("Content-Disposition", "attachment; filename=\"tenancy-certificate.cbor\"".into()),
            Err(e) => self.portal_error(&e, None),
        }
    }

    /// `GET /devices/{device}/bundle.fsb`: the stored bundle for a signed-in collector's own
    /// device (REG-043, DIS-041). It changes nothing, so it takes no CSRF token.
    fn portal_bundle(&self, req: &Request, device: &str) -> Response {
        let Some(SessionView { person, .. }) = self.session(req) else { return Response::redirect("/") };
        let device = DeviceId(device.to_owned());
        let own = self.factory.list_devices(&person.account).map(|all| all.iter().any(|d| d.device.id == device));
        match own {
            Ok(true) => {}
            Ok(false) => return self.portal_error(&RegistrationError::WrongAccount, None),
            Err(e) => return self.portal_error(&e, None),
        }
        let Some(routes) = &self.bundles else { return self.portal_page(503, "portal.bundle.unavailable") };
        match routes.download.download(&device) {
            Ok((name, bundle)) => no_store(
                Response::new(200, "application/octet-stream", bundle.bytes)
                    .with("Fieldseal-Bundle-Sequence", bundle.seq.0.to_string())
                    .with("Content-Disposition", format!("attachment; filename=\"{name}\"")),
            ),
            // The one reason that means "nothing built yet" (DIS-041).
            Err(DistributionError::Withheld(reasons)) if reasons == ["no-bundle-built"] => self.portal_page(404, "portal.bundle.none"),
            Err(DistributionError::NotRegistered | DistributionError::Withheld(_)) => self.portal_page(403, "portal.bundle.withheld"),
            Err(_) => self.portal_page(503, "portal.bundle.unavailable"),
        }
    }

    /// A portal page that says one message and links back.
    fn portal_page(&self, status: u16, message: &str) -> Response {
        html(status, page("portal.error.heading", &format!("<p>{}</p><p><a href=\"/\">{}</a></p>", t(message), t("portal.token.back")), None))
    }
}
