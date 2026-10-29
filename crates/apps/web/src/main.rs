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
//! | `FIELDSEAL_WEB_SURVEY_COHORTS` | `survey=cohort,...`: the cohort whose roster each survey's pages use (default none; a survey with no entry has no roster). The factory's `cohorts` setting is a different thing |
//! | `FIELDSEAL_WEB_WASM_DIR` | The directory with `fieldseal_wasm.js` and `fieldseal_wasm_bg.wasm` from `wasm-bindgen --target web` (optional; without it live evaluation is off) |
//! | `FIELDSEAL_FACTORY_URL` | The factory's base URL, for links and `/proxy/factory/*` (optional) |
//! | `FIELDSEAL_UPLOAD_URL` | The intake upload endpoint, for `/proxy/upload/*` (optional) |
//! | `FIELDSEAL_LOG_URL` | The transparency log, for `/proxy/log/*` (optional) |
//! | `FIELDSEAL_WEB_PUBLIC_URL` | This app's own public URL (optional) |
//! | `FIELDSEAL_WEB_DEMO_AUTHORITY` | `true` starts an embedded demo authority (practice factory with a dev sign-in, intake upload endpoint, transparency log) over in-memory ports with development keys, so the app works with no other service; non-production only (optional, default `false`) |
//! | `FIELDSEAL_WEB_DEMO_FACTORY_BIND`, `FIELDSEAL_WEB_DEMO_UPLOAD_BIND` | Where the embedded factory and upload endpoint listen (defaults `127.0.0.1:8091`, `127.0.0.1:8092`); with the demo authority these also become `FIELDSEAL_FACTORY_URL` and `FIELDSEAL_UPLOAD_URL` |
//! | `FIELDSEAL_WEB_STACK` | `true`: run as a service of the compose stack: provisioning from `/authority/trust-bundle.bundle`, the surveys published in `/published`, bundles built by the stack's authority with `FIELDSEAL_WEB_CLI` (default `fieldseal`) from the factory's records in `/factory-state` |
//! | `FIELDSEAL_WEB_AUTHORITY_DIR` | In stack mode, the authority's directory (default `/authority`); `just web` points it at `deploy/local/.state/dev-web/authority` |
//! | `FIELDSEAL_WEB_PUBLISHED_DIR` | In stack mode, the directory of the `*.published` files (default `/published`) |
//! | `FIELDSEAL_WEB_REGISTRY_DIR` | In stack mode, the CLI's artefact registry (`<state>/registry`, `*.publication` files) that the Publishing page lists (default none) |
//! | `FIELDSEAL_WEB_PROVISIONING_FILE` | A provisioning JSON for the Device page against a real authority: `trustBundle` (base64url), `allowedBuilders`, `allowedSources`, `provisionalRecordKey`, `buildAnchor`, `authority` (optional) |

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::Arc;

use fieldseal_web::http::{MAX_BODY, MAX_INGEST_BODY, Request, Response};
use fieldseal_web::routes::dispatch;
use fieldseal_web::state::AppState;

/// The number of worker threads taking requests.
const WORKERS: usize = 4;

const HELP: &str = "fieldseal-web: the Fieldseal showcase web app (development only)\n\nUsage: fieldseal-web [--help]\n\nConfiguration is read from the environment:\n  FIELDSEAL_ENVIRONMENT        development, staging or test (required; production is refused)\n  FIELDSEAL_WEB_BIND           address to listen on (default 127.0.0.1:8090; port 0 picks a free one)\n  FIELDSEAL_WEB_EXAMPLES_DIR   directory with surveys/ and rosters/ (required)\n  FIELDSEAL_WEB_SURVEY_COHORTS survey=cohort,... : the cohort whose roster each survey uses (optional)\n  FIELDSEAL_WEB_WASM_DIR       directory with fieldseal_wasm.js and fieldseal_wasm_bg.wasm (optional)\n  FIELDSEAL_FACTORY_URL        the factory's base URL (optional)\n  FIELDSEAL_UPLOAD_URL         the intake upload endpoint (optional)\n  FIELDSEAL_LOG_URL            the transparency log (optional)\n  FIELDSEAL_WEB_PUBLIC_URL     this app's public URL (optional)\n  FIELDSEAL_WEB_STACK          true: run as a service of the stack (or of `just web`)\n  FIELDSEAL_WEB_AUTHORITY_DIR  stack mode: the authority's directory (default /authority)\n  FIELDSEAL_WEB_PUBLISHED_DIR  stack mode: the directory of the *.published files (default /published)\n  FIELDSEAL_WEB_REGISTRY_DIR   stack mode: the CLI's artefact registry, listed on the Publishing page (optional)\n";

/// The app's configuration, from the environment.
#[derive(Debug, PartialEq, Eq)]
struct Config {
    bind: String,
    examples_dir: PathBuf,
    survey_cohorts: BTreeMap<String, String>,
    wasm_dir: Option<PathBuf>,
    factory_url: Option<String>,
    upload_url: Option<String>,
    log_url: Option<String>,
    public_url: Option<String>,
    demo: bool,
    demo_factory_bind: String,
    demo_upload_bind: String,
    provisioning_file: Option<PathBuf>,
    stack: Option<String>,
    authority_dir: Option<PathBuf>,
    published_dir: Option<PathBuf>,
    registry_dir: Option<PathBuf>,
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
            wasm_dir: opt("FIELDSEAL_WEB_WASM_DIR").map(PathBuf::from),
            factory_url: url("FIELDSEAL_FACTORY_URL")?,
            upload_url: url("FIELDSEAL_UPLOAD_URL")?,
            log_url: url("FIELDSEAL_LOG_URL")?,
            public_url: url("FIELDSEAL_WEB_PUBLIC_URL")?,
            demo: opt("FIELDSEAL_WEB_DEMO_AUTHORITY").is_some_and(|v| v == "true"),
            demo_factory_bind: opt("FIELDSEAL_WEB_DEMO_FACTORY_BIND").unwrap_or_else(|| "127.0.0.1:8091".to_owned()),
            demo_upload_bind: opt("FIELDSEAL_WEB_DEMO_UPLOAD_BIND").unwrap_or_else(|| "127.0.0.1:8092".to_owned()),
            provisioning_file: opt("FIELDSEAL_WEB_PROVISIONING_FILE").map(PathBuf::from),
            stack: opt("FIELDSEAL_WEB_STACK").is_some_and(|v| v == "true").then(|| opt("FIELDSEAL_WEB_CLI").unwrap_or_else(|| "fieldseal".to_owned())),
            authority_dir: opt("FIELDSEAL_WEB_AUTHORITY_DIR").map(PathBuf::from),
            published_dir: opt("FIELDSEAL_WEB_PUBLISHED_DIR").map(PathBuf::from),
            registry_dir: opt("FIELDSEAL_WEB_REGISTRY_DIR").map(PathBuf::from),
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
    let (mut factory_url, mut upload_url) = (config.factory_url, config.upload_url);
    let demo = if config.demo {
        let mut dc = fieldseal_adapters_web_demo::DemoConfig::new(&config.examples_dir);
        dc.now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_millis() as u64;
        dc.factory_bind = config.demo_factory_bind;
        dc.upload_bind = config.demo_upload_bind;
        let d = fieldseal_adapters_web_demo::Demo::start(dc)?;
        factory_url = Some(d.factory_url().to_owned());
        upload_url = Some(d.upload_url().to_owned());
        eprintln!("{{\"event\":\"demo-authority\",\"factory\":\"{}\",\"upload\":\"{}\",\"keys\":\"development, unattested\"}}", d.factory_url(), d.upload_url());
        Some(fieldseal_web::state::DemoHandle(d))
    } else {
        None
    };
    let state = Arc::new(AppState {
        examples_dir: config.examples_dir,
        survey_cohorts: config.survey_cohorts,
        wasm_dir: config.wasm_dir,
        factory_url,
        upload_url,
        log_url: config.log_url,
        public_url: config.public_url,
        demo,
        provisioning_file: config.provisioning_file,
        stack: config.stack,
        authority_dir: config.authority_dir,
        published_dir: config.published_dir,
        registry_dir: config.registry_dir,
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
    let limit = if request.method().as_str() == "POST" && request.url() == "/intake/ingest" { MAX_INGEST_BODY } else { MAX_BODY };
    let too_big = request.as_reader().take(limit as u64 + 1).read_to_end(&mut body).is_err() || body.len() > limit;
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

