//! The operator's sign-in for `roster issue` and `roster assign` (Technical Plan 7.5, CLI-051,
//! CLI-055): OIDC authorization code with PKCE on a loopback redirect (RFC 8252), as `gh auth
//! login` does it. Only those two commands call this module; no device command does (REG-001).
//!
//! The steps are the plan's: listen on `127.0.0.1` on an ephemeral port, start the sign-in
//! with the redirect `http://127.0.0.1:<port>/callback` (state, nonce, PKCE `S256` verifier),
//! open the browser, take the one callback, close the listener, exchange the code and check the
//! ID token's `nonce`, and return the access token. The token lives in memory until the command
//! ends; nothing is written to disk.
//!
//! The listener serves one purpose and trusts nothing: it answers only `GET /callback` for the
//! `Host` it was opened on (a page that tricks the browser into another host name, as in DNS
//! rebinding, gets a `400`), it echoes no query value, and it accepts the first callback that
//! carries a `state` or an `error`. A callback with the wrong state ends the command as a
//! refusal (the adapter checks the state), so a stray request cannot be mistaken for the sign-in.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use fieldseal_adapters_factory_http::parse_form;
use fieldseal_adapters_oidc::{OidcConfig, OidcIdentityProvider, percent_encode};
use fieldseal_registration::ports::{IdentityError, IdentityProvider};
use zeroize::Zeroizing;

use crate::args::Args;
use crate::messages::msg;
use crate::support::{Res, setting, usage};

/// How long the command waits for the person to sign in.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(180);

/// The `acr_values` the CLI asks for. Asking proves nothing: the factory reads the access
/// token's own `acr` and `amr` and requires a phishing-resistant method (REG-002a).
const ACR_REQUESTED: &str = "phr";

/// The largest callback request read.
const MAX_REQUEST: usize = 8 * 1024;

/// Where the identity provider is and how the person reaches it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Settings {
    /// The issuer URL.
    pub issuer: String,
    /// The public client id (`fieldseal-cli`).
    pub client_id: String,
    /// The command that opens the authorisation URL: `--browser`, else `$FIELDSEAL_BROWSER`.
    /// `none`, or nothing, prints the URL and waits.
    pub browser: Option<String>,
    /// A login for the identity provider to approve at once (`login_hint`), for a development
    /// identity provider; with `--browser none` the command follows the redirect itself.
    pub login: Option<String>,
}

/// Why the sign-in did not give a token.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SignInError {
    /// The identity provider showed a page for a person where `--browser none --login` needed
    /// a redirect.
    NeedsPerson,
    /// The sign-in was refused: a wrong state, an error from the identity provider, a token
    /// that does not verify.
    Refused(String),
    /// The identity provider, the listener or the browser command could not be used.
    Unavailable(String),
    /// No callback arrived in time.
    TimedOut,
}

/// Reads the sign-in settings from the flags `--issuer`, `--client-id`, `--browser` and
/// `--login`, and from `FIELDSEAL_OIDC_ISSUER`, `FIELDSEAL_OIDC_CLIENT_ID` and
/// `FIELDSEAL_BROWSER`. Neither an issuer nor a client id is a usage error (exit 2).
pub fn settings(args: &Args, command: &str) -> Res<Settings> {
    let non_empty = |v: Option<String>| v.filter(|s| !s.is_empty());
    let (Some(issuer), Some(client_id)) = (
        non_empty(setting(args, "--issuer", "FIELDSEAL_OIDC_ISSUER")),
        non_empty(setting(args, "--client-id", "FIELDSEAL_OIDC_CLIENT_ID")),
    ) else {
        return Err(usage("oidc-missing", &[("command", command)]));
    };
    Ok(Settings {
        issuer,
        client_id,
        browser: non_empty(setting(args, "--browser", "FIELDSEAL_BROWSER")).filter(|b| b != "none"),
        login: args.value("--login").map(str::to_owned),
    })
}

/// Signs the operator in and returns the access token for the factory API.
pub fn sign_in(settings: &Settings) -> Result<Zeroizing<String>, SignInError> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| SignInError::Unavailable(format!("cannot listen on 127.0.0.1: {e}")))?;
    listener.set_nonblocking(true).map_err(|e| SignInError::Unavailable(e.to_string()))?;
    let port = listener.local_addr().map_err(|e| SignInError::Unavailable(e.to_string()))?.port();
    let redirect = format!("http://127.0.0.1:{port}/callback");

    let mut config = OidcConfig::new(settings.issuer.clone(), settings.client_id.clone());
    config.acr_values = Some(ACR_REQUESTED.to_owned());
    let provider = OidcIdentityProvider::new(config).map_err(|e| SignInError::Unavailable(e.to_string()))?;
    let start = provider.start_sign_in(&redirect).map_err(identity_error)?;
    let url = match &settings.login {
        Some(login) => format!("{}&login_hint={}", start.redirect_to, percent_encode(login)),
        None => start.redirect_to.clone(),
    };

    let deadline = Instant::now() + SIGN_IN_TIMEOUT;
    let cancel = AtomicBool::new(false);
    let callback = match (&settings.browser, &settings.login) {
        // No browser and a login: ask the identity provider ourselves and follow its redirect to
        // the listener. The listener runs beside, so the request below can reach it.
        (None, Some(_)) => std::thread::scope(|scope| {
            let waiting = scope.spawn(|| await_callback(&listener, port, &start.pending.state, deadline, &cancel));
            let followed = follow_login(&url, &redirect);
            if followed.is_err() {
                cancel.store(true, Ordering::SeqCst);
            }
            let callback = waiting.join().unwrap_or(Err(SignInError::Unavailable("the listener stopped".into())));
            followed.and(callback)
        })?,
        (None, None) => {
            eprintln!("{}", msg("sign-in-open-url", &[("redirect", &redirect), ("url", &url)]));
            await_callback(&listener, port, &start.pending.state, deadline, &cancel)?
        }
        (Some(command), _) => {
            let mut child = std::process::Command::new(command)
                .arg(&url)
                .stdin(std::process::Stdio::null())
                .spawn()
                .map_err(|e| SignInError::Unavailable(msg("browser-failed", &[("command", command), ("reason", &e.to_string())])))?;
            let callback = await_callback(&listener, port, &start.pending.state, deadline, &cancel);
            // The opener is done once the redirect has arrived; give it a moment, then leave it.
            for _ in 0..100 {
                if !matches!(child.try_wait(), Ok(None)) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            callback?
        }
    };
    // The listener closes here, before the code is exchanged.
    drop(listener);
    provider.finish_sign_in_raw(&start.pending, &callback).map(|raw| Zeroizing::new(raw.access_token)).map_err(identity_error)
}

fn identity_error(e: IdentityError) -> SignInError {
    match e {
        IdentityError::NotAuthenticated(reason) => SignInError::Refused(reason),
        IdentityError::Unavailable(reason) => SignInError::Unavailable(reason),
    }
}

/// Requests the authorisation URL with the login hint and, if the identity provider answers
/// with a redirect to the listener, follows it. Any other answer needs a person. A redirect to
/// anywhere but the listener is not followed.
fn follow_login(url: &str, redirect: &str) -> Result<(), SignInError> {
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).max_redirects(0).timeout_global(Some(Duration::from_secs(10))).build().into();
    let answer = agent.get(url).call().map_err(|e| SignInError::Unavailable(e.to_string()))?;
    let location = answer.headers().get("location").and_then(|l| l.to_str().ok()).map(str::to_owned);
    match (answer.status().as_u16(), location) {
        (301 | 302 | 303 | 307 | 308, Some(location)) if location.starts_with(&format!("{redirect}?")) => {
            let landed = agent.get(&location).call().map_err(|e| SignInError::Unavailable(e.to_string()))?;
            if landed.status().is_success() { Ok(()) } else { Err(SignInError::Refused(format!("the listener answered HTTP {}", landed.status().as_u16()))) }
        }
        (301 | 302 | 303 | 307 | 308, Some(_)) => Err(SignInError::Refused("the identity provider redirected somewhere other than the CLI's listener".into())),
        _ => Err(SignInError::NeedsPerson),
    }
}

/// Waits for the one callback that carries `state`. Other requests, including a callback with
/// another state and an `error` without the state, are answered and ignored, so that a page the
/// person has open cannot end the sign-in; the wait ends at the deadline.
fn await_callback(listener: &TcpListener, port: u16, state: &str, deadline: Instant, cancel: &AtomicBool) -> Result<BTreeMap<String, String>, SignInError> {
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err(SignInError::Refused("the sign-in was abandoned".into()));
        }
        if Instant::now() >= deadline {
            return Err(SignInError::TimedOut);
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(params) = serve(stream, port, state) {
                    return Ok(params);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => return Err(SignInError::Unavailable(e.to_string())),
        }
    }
}

/// Answers one connection; returns the query of a callback whose `state` is `state`.
fn serve(mut stream: TcpStream, port: u16, state: &str) -> Option<BTreeMap<String, String>> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < MAX_REQUEST {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = text.split("\r\n");
    let mut request_line = lines.next().unwrap_or("").split(' ');
    let (method, target) = (request_line.next().unwrap_or(""), request_line.next().unwrap_or(""));
    let host = lines.find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.trim().to_owned()));
    if method != "GET" || host.as_deref() != Some(&format!("127.0.0.1:{port}")) {
        respond(&mut stream, 400, "Bad request.");
        return None;
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != "/callback" {
        respond(&mut stream, 404, "Not found.");
        return None;
    }
    let params = parse_form(query);
    if !params.get("state").is_some_and(|got| same_text(got, state)) {
        respond(&mut stream, 400, "This is not a sign-in response.");
        return None;
    }
    respond(&mut stream, 200, "Signed in. You can close this window and return to the terminal.");
    Some(params)
}

/// Whether two texts are equal, in time that depends on their length only.
fn same_text(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

fn respond(stream: &mut TcpStream, status: u16, text: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Not Found",
    };
    let body = format!("<!doctype html><meta charset=\"utf-8\"><title>Fieldseal</title><p>{text}</p>");
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(body.as_bytes()));
}
