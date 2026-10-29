//! Who may use the results reader (INT-089, INT-090): the five-control tests of Technical Plan 7.2
//! that belong to this adapter.

mod support;

use support::*;

// covers: INT-089
#[test]
fn int_089_no_session_redirects_a_page_and_gives_401_for_a_download() {
    let w = world("noses");
    let h = reader(&w, config(&w));
    let page = h.handle(&get("/results", None));
    assert_eq!(page.status, 302);
    assert_eq!(header(&page, "Location"), Some("/sign-in"));
    let dl = h.handle(&get("/results/exports/3/results.csv", None));
    assert_eq!(dl.status, 401);
    assert!(text(&dl).contains("sign-in-required"));
}

// covers: INT-089
#[test]
fn int_089_a_collector_without_the_role_gets_403_not_authorised() {
    let w = world("norole");
    let h = reader(&w, config(&w));
    let cookie = sign_in(&h, &w, "collector");
    for path in ["/results", "/results/exports/3/results.csv"] {
        let r = h.handle(&get(path, Some(&cookie)));
        assert_eq!(r.status, 403, "{path}");
        assert!(text(&r).contains("not-authorised"));
    }
}

// covers: INT-089
#[test]
fn int_089_a_reader_with_a_weak_method_is_refused() {
    let w = world("weak");
    let h = reader(&w, config(&w));
    let cookie = sign_in(&h, &w, "weak");
    let r = h.handle(&get("/results", Some(&cookie)));
    assert_eq!(r.status, 403);
    assert!(text(&r).contains("phishing-resistant-auth-required"));
    let mut cfg = config(&w);
    cfg.require_phishing_resistant = false;
    let h = reader(&w, cfg);
    let cookie = sign_in(&h, &w, "weak");
    assert_eq!(h.handle(&get("/results", Some(&cookie))).status, 200);
}

// covers: INT-089
#[test]
fn int_089_a_reader_with_the_role_and_a_passkey_sees_the_page_with_the_statement() {
    let w = world("ok");
    let h = reader(&w, config(&w));
    let cookie = sign_in(&h, &w, "reader");
    let r = h.handle(&get("/results", Some(&cookie)));
    assert_eq!(r.status, 200);
    assert_eq!(header(&r, "Content-Security-Policy"), Some(fieldseal_adapters_results_http::DEFAULT_CSP));
    assert!(text(&r).contains("outside Fieldseal&#39;s protection"));
    assert_eq!(h.handle(&get("/", Some(&cookie))).status, 302);
}

// covers: INT-089
#[test]
fn int_089_sign_out_without_the_csrf_token_gets_403() {
    let w = world("csrf");
    let h = reader(&w, config(&w));
    let cookie = sign_in(&h, &w, "reader");
    assert_eq!(h.handle(&post("/sign-out", &cookie, "")).status, 403);
    assert_eq!(h.handle(&post("/sign-out", &cookie, "csrf=wrong")).status, 403);
    assert_eq!(h.handle(&get("/results", Some(&cookie))).status, 200, "the session is still live");
}

// covers: INT-089
#[test]
fn int_089_sign_out_ends_the_session() {
    let w = world("signout");
    let h = reader(&w, config(&w));
    let cookie = sign_in(&h, &w, "reader");
    let page = text(&h.handle(&get("/results", Some(&cookie))));
    let csrf = page.split("name=\"csrf\" value=\"").nth(1).and_then(|r| r.split('"').next()).expect("a token in the form").to_owned();
    let out = h.handle(&post("/sign-out", &cookie, &format!("csrf={csrf}")));
    assert_eq!(out.status, 302);
    assert!(header(&out, "Set-Cookie").is_some_and(|c| c.contains("Max-Age=0")));
    assert_eq!(h.handle(&get("/results", Some(&cookie))).status, 302, "the old cookie no longer works");
}

// covers: INT-089
#[test]
fn int_089_the_cookie_is_named_fs_intake_session() {
    let w = world("cookie");
    let h = reader(&w, config(&w));
    w.idp.set_default(Some("reader"));
    let start = h.handle(&get("/sign-in", None));
    let target = header(&start, "Location").unwrap().strip_prefix("http://localhost:8481").unwrap().to_owned();
    let done = h.handle(&get(&target, Some(&pre_auth_pair(&start))));
    let set = header(&done, "Set-Cookie").expect("a cookie");
    assert!(set.starts_with("fs_intake_session="), "{set}");
    assert!(set.contains("HttpOnly") && set.contains("SameSite=Lax"));
}

// covers: INT-089
#[test]
fn int_089_only_sign_in_and_sign_out_change_state() {
    let w = world("methods");
    let h = reader(&w, config(&w));
    let cookie = sign_in(&h, &w, "reader");
    for path in ["/results", "/results/exports/3/results.csv", "/", "/sign-in"] {
        assert_eq!(h.handle(&post(path, &cookie, "csrf=x")).status, 405, "{path}");
    }
}

// covers: INT-090
#[test]
fn int_090_events_carry_no_account_personal_data() {
    // The events are single lines of fixed fields (`results-sign-in` with `ok`, `results-download`
    // with the mark and a file from the fixed list). None reads the account from the session.
    let src = include_str!("../src/routes.rs").to_owned() + include_str!("../src/downloads.rs");
    for line in src.lines().filter(|l| l.contains("eprintln!")) {
        assert!(!line.contains("person") && !line.contains("account") && !line.contains("login"), "{line}");
    }
}

// covers: INT-089
#[test]
fn int_089_a_request_for_another_host_is_refused_before_any_route() {
    let w = world("host");
    let h = reader(&w, config(&w));
    for host in [Some("evil.example"), Some("localhost:9999"), Some("localhost"), Some(""), None] {
        let mut r = get("/", None);
        r.headers.remove("host");
        if let Some(host) = host {
            r.headers.insert("host".into(), host.into());
        }
        let answer = h.handle(&r);
        assert_eq!(answer.status, 400, "{host:?}");
        assert!(text(&answer).contains("bad-host"));
    }
    // The host of the public URL passes, in any case; so does its default port when the URL names none.
    let mut r = get("/", None);
    r.headers.insert("host".into(), "LocalHost:8481".into());
    assert_eq!(h.handle(&r).status, 200);
    let mut cfg = config(&w);
    cfg.public_url = "https://results.example.org".into();
    let h = reader(&w, cfg);
    for (host, status) in [("results.example.org", 200), ("results.example.org:443", 200), ("results.example.org:8443", 400), ("other.example.org", 400)] {
        let mut r = get("/", None);
        r.headers.insert("host".into(), host.into());
        assert_eq!(h.handle(&r).status, status, "{host}");
    }
}

// covers: INT-089
#[test]
fn int_089_a_callback_without_the_browsers_pre_auth_cookie_signs_nobody_in() {
    let w = world("preauth");
    let h = reader(&w, config(&w));
    w.idp.set_default(Some("reader"));
    let start = h.handle(&get("/sign-in", None));
    let pre = header(&start, "Set-Cookie").expect("a pre-auth cookie");
    assert!(pre.starts_with("fs_intake_session_pre=") && pre.contains("HttpOnly") && pre.contains("SameSite=Lax"), "{pre}");
    let target = header(&start, "Location").unwrap().strip_prefix("http://localhost:8481").unwrap().to_owned();
    let refused = h.handle(&get(&target, None));
    assert_eq!(refused.status, 401);
    assert!(header(&refused, "Set-Cookie").is_none());
    // A provider error shows a fixed message, not the provider's text.
    let with_error = h.handle(&get("/sign-in/callback?state=x&error=access_denied&error_description=%3Cb%3Eleak", Some(&pre_auth_pair(&start))));
    assert!(!text(&with_error).contains("leak"));
    let done = h.handle(&get(&target, Some(&pre_auth_pair(&start))));
    assert_eq!(done.status, 302);
    assert!(done.headers.iter().filter(|(k, _)| k == "Set-Cookie").count() == 2, "the session cookie and the cleared pre-auth cookie");
}
