//! `fieldseal-web`: the showcase web app (ADR 0036). A plain, server-rendered viewer for
//! instruments with live rule evaluation in the browser through the WebAssembly core, and
//! pages for the other services. It reads its configuration from the environment
//! (twelve-factor III) and serves everything it needs itself. Development only.
//!
//! | Variable | Meaning |
//! |---|---|
//! | `FIELDSEAL_ENVIRONMENT` | `development`, `staging` or `test` (required); `production` is refused |
//! | `FIELDSEAL_WEB_BIND` | Address to listen on (default `127.0.0.1:8090`; port `0` picks a free one) |
//! | `FIELDSEAL_WEB_EXAMPLES_DIR` | A directory with `surveys/` and `rosters/` (required) |
//! | `FIELDSEAL_WEB_ROSTER_DIR` | The factory's roster store, read only: when set, the roster page reads the latest stored version of the survey's cohort (from `FIELDSEAL_WEB_SURVEY_COHORTS`) there and shows counts only; a directory that does not exist yet means no roster. Unset: `rosters/` of the examples directory |
//! | `FIELDSEAL_WEB_SURVEY_COHORTS` | `survey=cohort,...`: the cohort whose roster each survey's pages use (default none; a survey with no entry has no roster). The factory's `cohorts` setting is a different thing |
//! | `FIELDSEAL_WEB_WASM_DIR` | The directory with `fieldseal_wasm.js` and `fieldseal_wasm_bg.wasm` from `wasm-bindgen --target web` (optional; without it live evaluation is off) |
//! | `FIELDSEAL_FACTORY_URL` | The factory's base URL, for links and `/proxy/factory/*` (optional) |
//! | `FIELDSEAL_UPLOAD_URL` | The intake upload endpoint, for `/proxy/upload/*` (optional) |
//! | `FIELDSEAL_LOG_URL` | The transparency log, for `/proxy/log/*` (optional) |
//! | `FIELDSEAL_WEB_PUBLIC_URL` | This app's own public URL (optional) |
//! | `FIELDSEAL_WEB_RESULTS_URL` | The intake app's results reader, linked from every page's footer (optional); the app shows no results itself |
//! | `FIELDSEAL_WEB_STACK` | `true`: run as a service of the compose stack: provisioning from `/authority/trust-bundle.bundle` and the surveys published in `/published`; the device gets its bundle from the factory |
//! | `FIELDSEAL_WEB_AUTHORITY_DIR` | In stack mode, the authority's directory (default `/authority`); `just web` points it at `deploy/local/.state/dev-web/authority` |
//! | `FIELDSEAL_WEB_PUBLISHED_DIR` | In stack mode, the directory of the `*.published` files (default `/published`, mounted read only); a survey is listed when the log (`FIELDSEAL_LOG_URL`) holds the entry its file carries |
//! | `FIELDSEAL_WEB_ALLOWED_BUILDERS`, `FIELDSEAL_WEB_ALLOWED_SOURCES` | In stack mode, the comma-separated builders and sources the device's publishing policy accepts, copied from `FIELDSEAL_INTAKE_ALLOWED_BUILDERS` and `_ALLOWED_SOURCES` of the intake environment |
//! | `FIELDSEAL_WEB_REGISTRY_DIR` | In stack mode, the CLI's artefact registry (`<state>/registry`, `*.publication` files) that the Publishing page lists (default none) |
//! | `FIELDSEAL_WEB_PROVISIONING_FILE` | A provisioning JSON for the Device page against a real authority: `trustBundle` (base64url), `allowedBuilders`, `allowedSources`, `provisionalRecordKey`, `buildAnchor`, `authority` (optional) |

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::Arc;

use fieldseal_web::http::{MAX_BODY, Request, Response};
use fieldseal_web::routes::dispatch;
use fieldseal_web::state::AppState;

/// The number of worker threads taking requests.
const WORKERS: usize = 4;

const HELP: &str = "fieldseal-web: the Fieldseal showcase web app (development only)\n\nUsage: fieldseal-web [--help]\n\nConfiguration is read from the environment:\n  FIELDSEAL_ENVIRONMENT        development, staging or test (required; production is refused)\n  FIELDSEAL_WEB_BIND           address to listen on (default 127.0.0.1:8090; port 0 picks a free one)\n  FIELDSEAL_WEB_EXAMPLES_DIR   directory with surveys/ and rosters/ (required)\n  FIELDSEAL_WEB_SURVEY_COHORTS survey=cohort,... : the cohort whose roster each survey uses (optional)\n  FIELDSEAL_WEB_ROSTER_DIR     the factory's roster store, read only (optional; unset: rosters/ of the examples directory)\n  FIELDSEAL_WEB_WASM_DIR       directory with fieldseal_wasm.js and fieldseal_wasm_bg.wasm (optional)\n  FIELDSEAL_FACTORY_URL        the factory's base URL (optional)\n  FIELDSEAL_UPLOAD_URL         the intake upload endpoint (optional)\n  FIELDSEAL_LOG_URL            the transparency log (optional)\n  FIELDSEAL_WEB_PUBLIC_URL     this app's public URL (optional)\n  FIELDSEAL_WEB_RESULTS_URL    the intake app's results reader, linked in the footer (optional)\n  FIELDSEAL_WEB_STACK          true: run as a service of the stack (or of `just web`)\n  FIELDSEAL_WEB_AUTHORITY_DIR  stack mode: the authority's directory (default /authority)\n  FIELDSEAL_WEB_PUBLISHED_DIR  stack mode: the directory of the *.published files (default /published)\n  FIELDSEAL_WEB_REGISTRY_DIR   stack mode: the CLI's artefact registry, listed on the Publishing page (optional)\n  FIELDSEAL_WEB_ALLOWED_BUILDERS, FIELDSEAL_WEB_ALLOWED_SOURCES  stack mode: comma-separated builders and sources the device's publishing policy accepts\n";

/// The app's configuration, from the environment.
#[derive(Debug, PartialEq, Eq)]
struct Config {
    bind: String,
    examples_dir: PathBuf,
    survey_cohorts: BTreeMap<String, String>,
    roster_dir: Option<PathBuf>,
    wasm_dir: Option<PathBuf>,
    factory_url: Option<String>,
    upload_url: Option<String>,
    log_url: Option<String>,
    public_url: Option<String>,
    results_url: Option<String>,
    provisioning_file: Option<PathBuf>,
    stack: bool,
    authority_dir: Option<PathBuf>,
    published_dir: Option<PathBuf>,
    registry_dir: Option<PathBuf>,
    allowed_builders: Vec<String>,
    allowed_sources: Vec<String>,
}

/// Reads `survey=cohort,...`.
fn survey_cohorts(list: Option<&str>) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    for pair in list.unwrap_or_default().split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (survey, cohort) = pair.split_once('=').filter(|(s, c)| !s.is_empty() && !c.is_empty()).ok_or_else(|| format!("FIELDSEAL_WEB_SURVEY_COHORTS: `{pair}` is not survey=cohort"))?;
        if map.insert(survey.to_owned(), cohort.to_owned()).is_some() {
            return Err(format!("FIELDSEAL_WEB_SURVEY_COHORTS: survey `{survey}` is listed twice"));
        }
    }
    Ok(map)
}

/// Reads `a,b,...`.
fn list(text: Option<String>) -> Vec<String> {
    text.unwrap_or_default().split(',').map(str::trim).filter(|v| !v.is_empty()).map(str::to_owned).collect()
}

impl Config {
    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let opt = |k: &str| get(k).filter(|v| !v.is_empty());
        let environment = opt("FIELDSEAL_ENVIRONMENT").ok_or("FIELDSEAL_ENVIRONMENT must be set")?;
        match environment.as_str() {
            "production" => return Err("FIELDSEAL_ENVIRONMENT=production: this is a development-only showcase and refuses to start in production".into()),
            "development" | "staging" | "test" => {}
            other => return Err(format!("FIELDSEAL_ENVIRONMENT={other}: use development, staging or test")),
        }
        let examples_dir = PathBuf::from(opt("FIELDSEAL_WEB_EXAMPLES_DIR").ok_or("FIELDSEAL_WEB_EXAMPLES_DIR must be set")?);
        if !examples_dir.is_dir() {
            return Err(format!("FIELDSEAL_WEB_EXAMPLES_DIR={}: not a directory", examples_dir.display()));
        }
        let survey_cohorts = survey_cohorts(opt("FIELDSEAL_WEB_SURVEY_COHORTS").as_deref())?;
        let url = |k: &str| match opt(k) {
            Some(v) if v.starts_with("http://") || v.starts_with("https://") => Ok(Some(v)),
            Some(_) => Err(format!("{k} must be an http or https URL")),
            None => Ok(None),
        };
        Ok(Self {
            bind: opt("FIELDSEAL_WEB_BIND").unwrap_or_else(|| "127.0.0.1:8090".to_owned()),
            examples_dir,
            survey_cohorts,
            roster_dir: opt("FIELDSEAL_WEB_ROSTER_DIR").map(PathBuf::from),
            wasm_dir: opt("FIELDSEAL_WEB_WASM_DIR").map(PathBuf::from),
            factory_url: url("FIELDSEAL_FACTORY_URL")?,
            upload_url: url("FIELDSEAL_UPLOAD_URL")?,
            log_url: url("FIELDSEAL_LOG_URL")?,
            public_url: url("FIELDSEAL_WEB_PUBLIC_URL")?,
            results_url: url("FIELDSEAL_WEB_RESULTS_URL")?,
            provisioning_file: opt("FIELDSEAL_WEB_PROVISIONING_FILE").map(PathBuf::from),
            stack: opt("FIELDSEAL_WEB_STACK").is_some_and(|v| v == "true"),
            authority_dir: opt("FIELDSEAL_WEB_AUTHORITY_DIR").map(PathBuf::from),
            published_dir: opt("FIELDSEAL_WEB_PUBLISHED_DIR").map(PathBuf::from),
            registry_dir: opt("FIELDSEAL_WEB_REGISTRY_DIR").map(PathBuf::from),
            allowed_builders: list(opt("FIELDSEAL_WEB_ALLOWED_BUILDERS")),
            allowed_sources: list(opt("FIELDSEAL_WEB_ALLOWED_SOURCES")),
        })
    }
}

fn main() {
    if std::env::args().skip(1).any(|a| a == "--help" || a == "-h") {
        print!("{HELP}");
        return;
    }
    let config = match Config::from_lookup(|k| std::env::var(k).ok()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fieldseal-web: {e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(config) {
        eprintln!("fieldseal-web: {e}");
        std::process::exit(1);
    }
}

fn run(config: Config) -> Result<(), String> {
    let server = Arc::new(tiny_http::Server::http(&config.bind).map_err(|e| format!("{}: {e}", config.bind))?);
    let addr = server.server_addr().to_ip().map(|a| a.to_string()).unwrap_or_else(|| config.bind.clone());
    let state = Arc::new(AppState {
        examples_dir: config.examples_dir,
        survey_cohorts: config.survey_cohorts,
        roster_dir: config.roster_dir,
        wasm_dir: config.wasm_dir,
        factory_url: config.factory_url,
        upload_url: config.upload_url,
        log_url: config.log_url,
        public_url: config.public_url,
        results_url: config.results_url,
        provisioning_file: config.provisioning_file,
        stack: config.stack,
        authority_dir: config.authority_dir,
        published_dir: config.published_dir,
        registry_dir: config.registry_dir,
        allowed_builders: config.allowed_builders,
        allowed_sources: config.allowed_sources,
        ..AppState::default()
    });
    eprintln!("{{\"event\":\"listening\",\"addr\":\"{addr}\",\"wasm\":{}}}", state.wasm_available());
    let workers: Vec<_> = (0..WORKERS)
        .map(|_| {
            let (server, state) = (Arc::clone(&server), Arc::clone(&state));
            std::thread::spawn(move || {
                while let Ok(request) = server.recv() {
                    serve(&state, request);
                }
            })
        })
        .collect();
    for w in workers {
        let _ = w.join();
    }
    Ok(())
}

fn serve(state: &AppState, mut request: tiny_http::Request) {
    let mut body = Vec::new();
    let too_big = request.as_reader().take(MAX_BODY as u64 + 1).read_to_end(&mut body).is_err() || body.len() > MAX_BODY;
    let headers = request.headers().iter().map(|h| (h.field.as_str().as_str().to_ascii_lowercase(), h.value.as_str().to_owned())).collect();
    let response = if too_big { Response::text(413, "The request body is too large.").secured() } else { dispatch(state, &Request::new(request.method().as_str(), request.url(), headers, body)) };
    let mut out = tiny_http::Response::from_data(response.body).with_status_code(response.status);
    for (k, v) in &response.headers {
        if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            out.add_header(h);
        }
    }
    let _ = request.respond(out);
}

