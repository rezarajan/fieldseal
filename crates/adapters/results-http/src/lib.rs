//! The results reader: the intake app's staff portal (Technical Plan 7.2, INT-085 to INT-092).
//!
//! A signed-in person with the `results-reader` role sees the results export of the landing
//! as it stands, and downloads its files. The export is built by the same functions as
//! `fieldseal intake results` (`fieldseal-adapters-landing-files`), so the bytes are the same.
//!
//! | Route | Auth | Result |
//! |---|---|---|
//! | `GET /` | none | to `/results` when signed in, else a sign-in page |
//! | `GET /sign-in`, `GET /sign-in/callback` | none | the identity-provider flow |
//! | `POST /sign-out` | session and CSRF token | ends the session |
//! | `GET /results` | session and role | the results table, contracts and manifest, with links |
//! | `GET /results/exports/{mark}/{path}` | session and role | one file of the export held for `mark` |
//!
//! Invariants: the reader writes nothing to disk (the built export is kept in memory for the
//! last four landing marks, within a byte budget, and never changes); it derives nothing from the answers; the only
//! routes that change state are sign-in and sign-out; every page carries the reader's own
//! content-security policy; log events carry no personal data of the account.

mod downloads;
mod pages;
mod routes;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fieldseal_adapters_landing_files::export::{ExportKey, RenderedExport};
use fieldseal_adapters_portal::{PortalSessions, Request, Response};
use fieldseal_policy::domain::PublishingPolicy;
use fieldseal_registration::ports::IdentityProvider;
use fieldseal_trust::domain::TrustBundle;
use fieldseal_trust::ports::AuthorityClock;

pub use downloads::{HELD_BYTES, HELD_MARKS};

/// The reader's content-security policy: the factory's, without `img-src`, because the reader
/// shows no images.
pub const DEFAULT_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// The largest request body the reader reads: sign-out is the only route with one.
pub const MAX_BODY: usize = 64 * 1024;

/// The reader's settings, from the intake app's configuration.
#[derive(Clone)]
pub struct ResultsConfig {
    /// The landing directory the intake app writes; opened as a snapshot for each new view.
    pub landing_dir: PathBuf,
    /// The directory of `*.published` files, verified against `trust` and `policy`.
    pub published_dir: PathBuf,
    /// The trust bundle publications are verified against.
    pub trust: TrustBundle,
    /// The publishing policy publications are verified under. It is the policy the CLI uses
    /// for `fieldseal intake results`, or the files are not the same.
    pub policy: PublishingPolicy,
    /// The role that may read results.
    pub reader_role: String,
    /// Whether a phishing-resistant sign-in is needed (REG-002); on by default.
    pub require_phishing_resistant: bool,
    /// The portal's public base URL: the sign-in callback follows it.
    pub public_url: String,
    /// The `Content-Security-Policy` of every page.
    pub csp: String,
    /// The development adapters the app reports, as (port, adapter), shown on the page.
    pub development_adapters: Vec<(String, String)>,
    /// How many stored submissions start-up replay could not land. Start-up stops on any, so
    /// this is zero in a running app; the page shows it (INT-013a).
    pub replay_gap: u64,
}

/// A built export held in memory for one landing mark.
pub(crate) struct Held {
    pub mark: u64,
    pub export: RenderedExport,
}

/// The results reader over one identity provider.
pub struct ResultsHttp<'a> {
    sessions: PortalSessions,
    provider: &'a dyn IdentityProvider,
    key: ExportKey,
    clock: &'a dyn AuthorityClock,
    cfg: ResultsConfig,
    held: Mutex<VecDeque<Arc<Held>>>,
    held_bytes: usize,
}

impl<'a> ResultsHttp<'a> {
    /// The reader. `sessions` is the portal's session store (the intake app names its cookie
    /// `fs_intake_session`); every call that depends on time reads `clock`.
    pub fn new(sessions: PortalSessions, provider: &'a dyn IdentityProvider, export_key: ExportKey, clock: &'a dyn AuthorityClock, cfg: ResultsConfig) -> Self {
        Self { sessions, provider, key: export_key, clock, cfg, held: Mutex::default(), held_bytes: HELD_BYTES }
    }

    /// The same reader with another byte budget for the built exports it holds (the default is
    /// [`HELD_BYTES`]).
    pub fn with_held_bytes(mut self, bytes: usize) -> Self {
        self.held_bytes = bytes;
        self
    }

    /// Answers one request from `server`, reading its body here (at most 64 KiB). A process
    /// that must not wait on a slow client on its serving thread (the intake app) reads the
    /// body elsewhere, under a deadline, and calls [`answer`](Self::answer) instead.
    pub fn serve_one(&self, mut req: tiny_http::Request) {
        use std::io::Read as _;
        let mut body = Vec::new();
        let too_big = req.as_reader().take(MAX_BODY as u64 + 1).read_to_end(&mut body).is_err() || body.len() > MAX_BODY;
        let out = self.answer(&req, (!too_big).then_some(body));
        let _ = req.respond(out);
    }

    /// The answer to `req`, whose body was read already: `None` is a body that was too big.
    /// Does no I/O on `req`.
    pub fn answer(&self, req: &tiny_http::Request, body: Option<Vec<u8>>) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
        let headers = req.headers().iter().map(|h| (h.field.as_str().as_str().to_ascii_lowercase(), h.value.as_str().to_owned())).collect();
        let response = match body {
            None => Response::json(413, serde_json::json!({ "error": "too-large" })),
            Some(body) => self.handle(&Request::new(req.method().as_str(), req.url(), headers, body)),
        };
        let mut out = tiny_http::Response::from_data(response.body).with_status_code(response.status);
        for (k, v) in response.headers.iter().chain(&[("X-Content-Type-Options".to_owned(), "nosniff".to_owned()), ("Referrer-Policy".to_owned(), "no-referrer".to_owned())]) {
            if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
                out.add_header(h);
            }
        }
        out
    }
}
