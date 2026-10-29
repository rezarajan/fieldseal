//! `roster assign` and the operator sign-in (CLI-055, REG-001): the loopback redirect, PKCE,
//! one sign-in per command, no token on disk. The identity provider and the factory are
//! `tiny_http` stand-ins; the CLI verifies the stand-in's real ES256 tokens with its own adapter.

mod common;

use std::path::Path;

use common::standin::{Authorize, Factory, Idp, OPERATOR_SUBJECT, accepting_factory};
use common::{Sandbox, repo};

const SURVEY_A: &str = "household-water-access=village-a";
const SURVEY_B: &str = "school-meals-baseline=cohort-a";

/// A browser command that does what a person's browser does: opens the URL it is given and
/// follows the redirects, here with Python's standard library.
fn opener(sb: &Sandbox) -> String {
    let script = sb.write("opener.sh", "#!/bin/sh\nexec python3 -I -c 'import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=10).read()' \"$1\"\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("executable");
    }
    script
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Runs the CLI with the identity provider's issuer and the client id in the environment, and
/// `HOME` and `TMPDIR` inside the sandbox so that a file written anywhere the CLI might write
/// is found by [`files_hold`].
fn run(sb: &Sandbox, idp: &Idp, args: &[&str], extra: &[(&str, &str)]) -> Run {
    std::fs::create_dir_all(sb.path("home")).expect("home");
    std::fs::create_dir_all(sb.path("tmp")).expect("tmp");
    let (home, tmp) = (sb.path("home"), sb.path("tmp"));
    let mut env: Vec<(&str, &str)> = vec![("FIELDSEAL_OIDC_ISSUER", &idp.issuer), ("FIELDSEAL_OIDC_CLIENT_ID", "fieldseal-cli"), ("HOME", &home), ("TMPDIR", &tmp)];
    env.extend_from_slice(extra);
    let o = sb.run_with(args, &env);
    Run { code: o.status.code().expect("exit code"), stdout: String::from_utf8_lossy(&o.stdout).into_owned(), stderr: String::from_utf8_lossy(&o.stderr).into_owned() }
}

/// Whether any file under `dir` contains one of `needles`.
fn files_hold(dir: &Path, needles: &[String]) -> Option<String> {
    for e in std::fs::read_dir(dir).expect("directory").flatten() {
        let p = e.path();
        if p.is_dir() {
            if let Some(found) = files_hold(&p, needles) {
                return Some(found);
            }
        } else if let Ok(bytes) = std::fs::read(&p) {
            let text = String::from_utf8_lossy(&bytes);
            if needles.iter().any(|n| !n.is_empty() && text.contains(n.as_str())) {
                return Some(p.to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn assign_args<'a>(factory: &'a Factory, browser: &'a str, pairs: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec!["roster", "assign", "--factory-url", &factory.url, "--browser", browser, "--account", OPERATOR_SUBJECT];
    for p in pairs {
        args.extend(["--assign", p]);
    }
    args
}

#[test]
fn cli_055_assign_signs_in_through_a_loopback_redirect_and_sends_the_access_token() {
    let sb = Sandbox::new("assign-loopback");
    let idp = Idp::start(Authorize::Auto);
    let factory = accepting_factory();
    let opener = opener(&sb);
    let r = run(&sb, &idp, &assign_args(&factory, &opener, &[SURVEY_A]), &[]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    // The authorisation request: loopback redirect, PKCE S256, state, nonce, the public client.
    let auth = idp.authorize_requests();
    assert_eq!(auth.len(), 1);
    let q = &auth[0];
    assert!(q["redirect_uri"].starts_with("http://127.0.0.1:") && q["redirect_uri"].ends_with("/callback"), "{q:?}");
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["client_id"], "fieldseal-cli");
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["acr_values"], "phr");
    assert!(!q["state"].is_empty() && !q["nonce"].is_empty() && !q["code_challenge"].is_empty());
    // The code was exchanged with the verifier, and the access token went to the factory.
    let token = idp.token_requests();
    assert_eq!((token.len(), token[0].get("grant_type").map(String::as_str)), (1, Some("authorization_code")));
    assert!(token[0].contains_key("code_verifier"));
    let issued = idp.issued_access_tokens();
    let posts: Vec<_> = factory.seen().into_iter().filter(|s| s.method == "POST").collect();
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].path, "/v1/assignments");
    assert_eq!(posts[0].authorization.as_deref(), Some(format!("Bearer {}", issued[0]).as_str()));
    let body = fieldseal_kernel::cbor::decode(&posts[0].body).expect("canonical CBOR");
    let m = body.as_map().expect("a map");
    assert_eq!((m["account"].as_text(), m["survey"].as_text(), m["cohort"].as_text()), (Some(OPERATOR_SUBJECT), Some("household-water-access"), Some("village-a")));
}

#[test]
fn cli_055_one_sign_in_serves_several_assign_options() {
    let sb = Sandbox::new("assign-several");
    let idp = Idp::start(Authorize::Auto);
    let factory = accepting_factory();
    let opener = opener(&sb);
    let r = run(&sb, &idp, &assign_args(&factory, &opener, &[SURVEY_A, SURVEY_B]), &[]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!((idp.authorize_requests().len(), idp.token_requests().len()), (1, 1), "one sign-in");
    let posts: Vec<_> = factory.seen().into_iter().filter(|s| s.method == "POST").collect();
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0].authorization, posts[1].authorization, "the same token for both");
}

#[test]
fn cli_055_no_token_is_written_to_disk() {
    let sb = Sandbox::new("assign-no-token-on-disk");
    let idp = Idp::start(Authorize::Auto);
    let factory = accepting_factory();
    let opener = opener(&sb);
    let r = run(&sb, &idp, &assign_args(&factory, &opener, &[SURVEY_A]), &[]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    let secrets = idp.secrets();
    assert!(secrets.len() >= 4);
    // The sandbox is under the temp directory and holds HOME and TMPDIR for the process.
    assert_eq!(files_hold(&sb.dir, &secrets), None);
    // Nor does the CLI print it.
    for text in [&r.stdout, &r.stderr] {
        assert!(secrets.iter().all(|s| !text.contains(s.as_str())), "a secret is in the output: {text}");
    }
}

#[test]
fn cli_055_login_with_browser_none_completes_without_a_person_when_the_idp_redirects() {
    let sb = Sandbox::new("assign-login-none");
    let idp = Idp::start(Authorize::Auto);
    let factory = accepting_factory();
    let r = run(&sb, &idp, &["roster", "assign", "--factory-url", &factory.url, "--browser", "none", "--login", "presenter", "--account", OPERATOR_SUBJECT, "--assign", SURVEY_A], &[]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(idp.authorize_requests()[0].get("login_hint").map(String::as_str), Some("presenter"));
    assert_eq!(factory.seen().len(), 1);
}

#[test]
fn cli_055_a_login_page_makes_it_fail_with_needs_a_person() {
    let sb = Sandbox::new("assign-needs-person");
    let idp = Idp::start(Authorize::LoginPage);
    let factory = accepting_factory();
    let r = run(&sb, &idp, &["roster", "assign", "--factory-url", &factory.url, "--browser", "none", "--login", "presenter", "--account", OPERATOR_SUBJECT, "--assign", SURVEY_A], &[]);
    assert_eq!(r.code, 1, "{}\n{}", r.stdout, r.stderr);
    assert!(r.stderr.contains("needs a person"), "{}", r.stderr);
    assert!(factory.seen().is_empty(), "nothing is sent without a token");
    assert!(idp.token_requests().is_empty());
}

#[test]
fn cli_055_a_removal_request_names_reg_045() {
    let sb = Sandbox::new("assign-removal");
    let idp = Idp::start(Authorize::Auto);
    let factory = accepting_factory();
    for flag in ["--remove", "--unassign"] {
        let r = run(&sb, &idp, &["roster", "assign", "--factory-url", &factory.url, "--account", OPERATOR_SUBJECT, flag, SURVEY_A], &[]);
        assert_eq!(r.code, 2, "{}", r.stderr);
        assert!(r.stderr.contains("REG-045"), "{}", r.stderr);
    }
    assert_eq!(idp.requests(), 0, "nobody is signed in to be refused");
    assert!(factory.seen().is_empty());
}

#[test]
fn cli_055_state_mismatch_is_refused() {
    let sb = Sandbox::new("assign-state");
    let idp = Idp::start(Authorize::WrongState);
    let factory = accepting_factory();
    let r = run(&sb, &idp, &["roster", "assign", "--factory-url", &factory.url, "--browser", "none", "--login", "presenter", "--account", OPERATOR_SUBJECT, "--assign", SURVEY_A], &[]);
    assert_eq!(r.code, 1, "{}\n{}", r.stdout, r.stderr);
    assert!(r.stderr.contains("listener answered HTTP 400"), "the listener refused the callback: {}", r.stderr);
    assert!(idp.token_requests().is_empty(), "the code is not exchanged for a callback that is not ours");
    assert!(factory.seen().is_empty());
}

#[test]
fn cli_055_a_callback_with_another_state_or_an_error_without_ours_is_ignored() {
    let sb = Sandbox::new("assign-state-ignored");
    let idp = Idp::start(Authorize::Auto);
    let factory = accepting_factory();
    // A browser that first sends the listener a callback with the wrong state, one that is an
    // error without any state, and an error with the wrong state, and then does the sign-in.
    let script = r#"import sys, urllib.parse, urllib.request, urllib.error
url = sys.argv[1]
redirect = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)['redirect_uri'][0]
for extra in ['state=not-ours&code=x', 'error=access_denied', 'error=access_denied&state=not-ours', 'state=&code=x']:
    try:
        urllib.request.urlopen(redirect + '?' + extra, timeout=10).read()
        sys.exit('the listener accepted ' + extra)
    except urllib.error.HTTPError as e:
        assert e.code == 400, e.code
urllib.request.urlopen(url, timeout=10).read()
"#;
    let py = sb.write("hostile.py", script);
    let browser = sb.write("hostile.sh", &format!("#!/bin/sh\nexec python3 -I {py} \"$1\"\n"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&browser, std::fs::Permissions::from_mode(0o755)).expect("executable");
    }
    let r = run(&sb, &idp, &assign_args(&factory, &browser, &[SURVEY_A]), &[]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(idp.token_requests().len(), 1, "only the callback with our state was exchanged");
    assert_eq!(factory.seen().iter().filter(|s| s.method == "POST").count(), 1);
}

#[test]
fn cli_055_the_output_shows_the_account_the_cohort_and_the_survey() {
    let sb = Sandbox::new("assign-output");
    let idp = Idp::start(Authorize::Auto);
    let factory = accepting_factory();
    let opener = opener(&sb);
    let r = run(&sb, &idp, &assign_args(&factory, &opener, &[SURVEY_A, SURVEY_B]), &[]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    for needle in [OPERATOR_SUBJECT, "household-water-access", "village-a", "school-meals-baseline", "cohort-a", "assigned"] {
        assert!(r.stdout.contains(needle), "`{needle}` is missing from:\n{}", r.stdout);
    }
    // The history lists what the factory journaled.
    let listed = run(&sb, &idp, &["roster", "assign", "--list", "--factory-url", &factory.url, "--browser", &opener], &[]);
    assert_eq!(listed.code, 0, "{}\n{}", listed.stdout, listed.stderr);
    assert!(listed.stdout.contains("#1") && listed.stdout.contains("#2") && listed.stdout.contains("village-a"), "{}", listed.stdout);
}

#[test]
fn cli_055_missing_issuer_and_client_id_exit_2() {
    let sb = Sandbox::new("assign-missing-oidc");
    let factory = accepting_factory();
    let base = ["roster", "assign", "--factory-url", factory.url.as_str(), "--browser", "none", "--account", OPERATOR_SUBJECT, "--assign", SURVEY_A];
    for extra in [vec![], vec![("FIELDSEAL_OIDC_ISSUER", "http://127.0.0.1:1/realms/x")], vec![("FIELDSEAL_OIDC_CLIENT_ID", "fieldseal-cli")]] {
        let o = sb.run_with(&base, &extra);
        assert_eq!(o.status.code(), Some(2), "{}", String::from_utf8_lossy(&o.stderr));
        assert!(String::from_utf8_lossy(&o.stderr).contains("FIELDSEAL_OIDC_ISSUER"));
    }
    // The flags stand in for the variables.
    let o = sb.run_with(&["roster", "assign", "--factory-url", &factory.url, "--browser", "none", "--issuer", "http://127.0.0.1:1/realms/x", "--client-id", "fieldseal-cli", "--account", OPERATOR_SUBJECT, "--assign", SURVEY_A], &[]);
    assert_eq!(o.status.code(), Some(3), "an unreachable identity provider is a configuration error: {}", String::from_utf8_lossy(&o.stderr));
    assert!(factory.seen().is_empty());
}

#[test]
fn reg_001_device_commands_never_call_the_oidc_client_or_read_its_variables() {
    let sb = Sandbox::new("device-no-oidc");
    let idp = Idp::start(Authorize::Auto);
    let marker = sb.path("browser-ran");
    let browser = sb.write("browser.sh", &format!("#!/bin/sh\ntouch {marker}\n"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&browser, std::fs::Permissions::from_mode(0o755)).expect("executable");
    }
    // The registration commands and the device simulator, run with the operator variables set.
    let factory = accepting_factory();
    for args in [
        vec!["registration", "status", "00", "--factory-url", factory.url.as_str()],
        vec!["registration", "submit", "no-such-request", "--factory-url", factory.url.as_str()],
        vec!["registration", "wait", "00", "--factory-url", factory.url.as_str(), "--timeout", "1"],
        vec!["registration", "token", "--account", "someone"],
        vec!["registration", "request", "--token", "not-a-token"],
        vec!["registration", "inspect", "no-such-request"],
        vec!["registration", "approve", "no-such-request"],
        vec!["device", "simulate", "--script", "no-such-script"],
        vec!["device", "export", "--device-dir", "no-such-dir", "--trust-bundle", "none", "--out", "no-such-out"],
        vec!["bundle", "build"],
        vec!["bundle", "inspect", "no-such-bundle"],
        vec!["bundle", "verify", "no-such-bundle"],
        vec!["bundle", "open", "no-such-bundle", "--key", "none", "--trust", "none"],
        vec!["export", "upload", "no-such-export", "--to", factory.url.as_str(), "--trust-bundle", "none"],
        vec!["receipt", "verify", "no-such-receipt"],
    ] {
        let _ = run(&sb, &idp, &args, &[("FIELDSEAL_BROWSER", &browser)]);
    }
    assert_eq!(idp.requests(), 0, "no device command called the identity provider");
    assert!(!Path::new(&marker).exists(), "no device command ran the browser command");
    // And the only sources that name the sign-in module or its variables are the module and the
    // two commands that use it, wherever they sit under the CLI's `src`.
    fn sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).expect("source directory").flatten() {
            let p = e.path();
            if p.is_dir() {
                sources(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let src = repo().join("crates/apps/cli/src");
    let mut files = Vec::new();
    sources(&src, &mut files);
    let mut users = Vec::new();
    for p in files {
        let text = std::fs::read_to_string(&p).expect("source");
        if text.contains("FIELDSEAL_OIDC") || text.contains("FIELDSEAL_BROWSER") || text.contains("oidc_login") || text.contains("fieldseal_adapters_oidc") {
            users.push(p.strip_prefix(&src).expect("under src").to_string_lossy().into_owned());
        }
    }
    users.sort();
    assert_eq!(users, ["main.rs", "messages.rs", "oidc_login.rs", "roster_cmd.rs"], "who touches the sign-in");
}

#[test]
fn cli_055_a_cleartext_factory_url_is_refused_unless_it_is_loopback() {
    let sb = Sandbox::new("assign-cleartext");
    let idp = Idp::start(Authorize::Auto);
    for url in ["http://factory.example.org", "http://factory.example.org:8080/x", "http://localhost.example.org:8080", "http://127.0.0.1@factory.example.org", "http://10.0.0.5:8080", "http://[2001:db8::1]:8080"] {
        for args in [
            vec!["roster", "assign", "--factory-url", url, "--browser", "none", "--login", "presenter", "--account", OPERATOR_SUBJECT, "--assign", SURVEY_A],
            vec!["roster", "assign", "--list", "--factory-url", url, "--browser", "none", "--login", "presenter"],
        ] {
            let r = run(&sb, &idp, &args, &[]);
            assert_eq!(r.code, 2, "{url}: {}\n{}", r.stdout, r.stderr);
            assert!(r.stderr.contains("https://") && r.stderr.contains(url), "{url}: {}", r.stderr);
        }
    }
    assert_eq!(idp.requests(), 0, "nobody is signed in to send a token nowhere");
    // Loopback names and addresses pass the check (and then fail to reach anything: exit 3).
    for url in ["http://localhost:1", "http://LOCALHOST:1", "http://127.0.0.1:1", "http://127.1.2.3:1/", "http://[::1]:1"] {
        let r = run(&sb, &idp, &["roster", "assign", "--list", "--factory-url", url, "--browser", "none", "--login", "presenter"], &[]);
        assert_eq!(r.code, 3, "{url}: {}\n{}", r.stdout, r.stderr);
    }
}
