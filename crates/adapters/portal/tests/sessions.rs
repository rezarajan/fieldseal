//! The portal session store, driven with the in-memory identity provider.

use std::collections::BTreeMap;

use fieldseal_adapters_memory::registration::MemoryIdentityProvider;
use fieldseal_adapters_portal::{PortalSessions, SessionId, SessionView, parse_form};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_registration::domain::MethodAssurance;

const NOW: AuthorityTime = AuthorityTime(1_800_000_000_000);
const TTL_MS: u64 = 60_000;
const CALLBACK: &str = "https://portal.example.org/sign-in/callback";

fn provider() -> MemoryIdentityProvider {
    let idp = MemoryIdentityProvider::new();
    idp.add("alice", "sub-alice", &["collector"], &["hwk"], MethodAssurance::FromProvider);
    idp.set_default(Some("alice"));
    idp
}

/// Starts a sign-in at `now` and returns the callback's query, as the provider would send the
/// person back, and the pre-auth cookie pair the browser sends with it.
fn begin_at(sessions: &PortalSessions, idp: &MemoryIdentityProvider, now: AuthorityTime) -> (BTreeMap<String, String>, String) {
    let (redirect, pre_auth) = sessions.begin(idp, CALLBACK, now).expect("sign-in starts");
    (parse_form(redirect.split_once('?').expect("a query").1), cookie_pair(&pre_auth).to_owned())
}

fn begin(sessions: &PortalSessions, idp: &MemoryIdentityProvider) -> (BTreeMap<String, String>, String) {
    begin_at(sessions, idp, NOW)
}

fn sign_in(sessions: &PortalSessions, idp: &MemoryIdentityProvider, now: AuthorityTime) -> (SessionId, String) {
    let (query, pre_auth) = begin_at(sessions, idp, now);
    sessions.finish(idp, &query, Some(&pre_auth), now).expect("sign-in finishes")
}

/// The `name=value` pair of a `Set-Cookie` value, as a request would send it back.
fn cookie_pair(set_cookie: &str) -> &str {
    set_cookie.split(';').next().expect("name=value")
}

fn view(sessions: &PortalSessions, set_cookie: &str, now: AuthorityTime) -> Option<SessionView> {
    sessions.session(Some(cookie_pair(set_cookie)), now)
}

#[test]
fn reg_092_ids_and_tokens_are_unique_and_unguessable_length() {
    let (sessions, idp) = (PortalSessions::new("fs_session", true, TTL_MS), provider());
    let (a, cookie_a) = sign_in(&sessions, &idp, NOW);
    let (b, cookie_b) = sign_in(&sessions, &idp, NOW);
    assert_ne!(a, b);
    // 32 random bytes, base64url without padding.
    assert_eq!(a.0.len(), 43);
    let (va, vb) = (view(&sessions, &cookie_a, NOW).expect("a"), view(&sessions, &cookie_b, NOW).expect("b"));
    assert_ne!(va.csrf, vb.csrf);
    assert_eq!(va.csrf.len(), 43);
    assert_ne!(va.csrf, a.0);
}

#[test]
fn reg_092_cookie_attributes() {
    let idp = provider();
    let secure = PortalSessions::new("fs_session", true, TTL_MS);
    let (id, cookie) = sign_in(&secure, &idp, NOW);
    assert_eq!(cookie, format!("fs_session={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=60; Secure", id.0));
    let plain = PortalSessions::new("fs_session", false, TTL_MS);
    let (id, cookie) = sign_in(&plain, &idp, NOW);
    assert_eq!(cookie, format!("fs_session={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=60", id.0));
    assert_eq!(plain.clear_cookie(), "fs_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
}

#[test]
fn reg_092_csrf_is_per_session() {
    let (sessions, idp) = (PortalSessions::new("fs_session", true, TTL_MS), provider());
    let (_, cookie_a) = sign_in(&sessions, &idp, NOW);
    let (_, cookie_b) = sign_in(&sessions, &idp, NOW);
    let (a, b) = (view(&sessions, &cookie_a, NOW).expect("a"), view(&sessions, &cookie_b, NOW).expect("b"));
    assert!(sessions.check_csrf(&a, &a.csrf));
    assert!(!sessions.check_csrf(&a, &b.csrf));
    assert!(!sessions.check_csrf(&a, ""));
}

#[test]
fn reg_002_pending_sign_ins_are_single_use() {
    let (sessions, idp) = (PortalSessions::new("fs_session", true, TTL_MS), provider());
    let (query, pre_auth) = begin(&sessions, &idp);
    assert!(sessions.finish(&idp, &query, Some(&pre_auth), NOW).is_ok());
    assert!(sessions.finish(&idp, &query, Some(&pre_auth), NOW).is_err());
    let mut unknown = query;
    unknown.insert("state".into(), "never-started".into());
    assert!(sessions.finish(&idp, &unknown, Some(&pre_auth), NOW).is_err());
    assert!(sessions.finish(&idp, &BTreeMap::new(), Some(&pre_auth), NOW).is_err());
}

#[test]
fn reg_002_a_sign_in_is_bound_to_the_browser_that_started_it() {
    let (sessions, idp) = (PortalSessions::new("fs_session", true, TTL_MS), provider());
    let (query, pre_auth) = begin(&sessions, &idp);
    // A callback from a browser that never started the sign-in (login CSRF) has no cookie, or
    // another sign-in's cookie, and does not use the pending sign-in up.
    assert!(sessions.finish(&idp, &query, None, NOW).is_err());
    let (_, other) = begin(&sessions, &idp);
    assert!(sessions.finish(&idp, &query, Some(&other), NOW).is_err());
    assert!(sessions.finish(&idp, &query, Some("fs_session_pre=forged"), NOW).is_err());
    assert!(sessions.finish(&idp, &query, Some(&pre_auth), NOW).is_ok(), "the right browser still finishes");
}

#[test]
fn reg_002_the_pre_auth_cookie_is_short_lived_httponly_and_holds_no_state() {
    let (secure, plain, idp) = (PortalSessions::new("fs_session", true, TTL_MS), PortalSessions::new("fs_session", false, TTL_MS), provider());
    let (redirect, cookie) = secure.begin(&idp, CALLBACK, NOW).expect("starts");
    assert!(cookie.starts_with("fs_session_pre="));
    for attribute in ["Path=/sign-in", "HttpOnly", "SameSite=Lax", "Max-Age=600", "Secure"] {
        assert!(cookie.contains(attribute), "{attribute} missing from {cookie}");
    }
    let state = &parse_form(redirect.split_once('?').expect("a query").1)["state"];
    assert!(!cookie.contains(state.as_str()), "the cookie holds a hash of the state, not the state");
    let (_, cookie) = plain.begin(&idp, CALLBACK, NOW).expect("starts");
    assert!(!cookie.contains("Secure"), "{cookie}");
    assert_eq!(plain.clear_pre_auth_cookie(), "fs_session_pre=; Path=/sign-in; HttpOnly; SameSite=Lax; Max-Age=0");
}

#[test]
fn reg_002_a_pending_sign_in_expires_after_ten_minutes() {
    let (sessions, idp) = (PortalSessions::new("fs_session", true, TTL_MS), provider());
    let (query, pre_auth) = begin(&sessions, &idp);
    assert!(sessions.finish(&idp, &query, Some(&pre_auth), AuthorityTime(NOW.0 + 10 * 60 * 1000 + 1)).is_err());
    let (query, pre_auth) = begin(&sessions, &idp);
    assert!(sessions.finish(&idp, &query, Some(&pre_auth), AuthorityTime(NOW.0 + 10 * 60 * 1000)).is_ok());
}

#[test]
fn reg_002_pending_sign_ins_are_capped_and_the_oldest_is_dropped() {
    let (sessions, idp) = (PortalSessions::new("fs_session", true, TTL_MS), provider());
    let (first_query, first_cookie) = begin(&sessions, &idp);
    let started: Vec<_> = (0..999).map(|_| begin(&sessions, &idp)).collect();
    // 1000 are waiting; the next start drops the first.
    let (last_query, last_cookie) = begin(&sessions, &idp);
    assert!(sessions.finish(&idp, &first_query, Some(&first_cookie), NOW).is_err(), "the oldest was evicted");
    assert!(sessions.finish(&idp, &started[0].0, Some(&started[0].1), NOW).is_ok(), "the second-oldest is still there");
    assert!(sessions.finish(&idp, &last_query, Some(&last_cookie), NOW).is_ok());
}

#[test]
fn reg_002_a_provider_error_shows_a_fixed_message_not_the_providers_text() {
    let (sessions, idp) = (PortalSessions::new("fs_session", true, TTL_MS), provider());
    let (mut query, pre_auth) = begin(&sessions, &idp);
    query.insert("error".into(), "access_denied".into());
    query.insert("error_description".into(), "<script>alert(1)</script> secret detail".into());
    let e = sessions.finish(&idp, &query, Some(&pre_auth), NOW).expect_err("refused").to_string();
    assert_eq!(e, "the identity provider did not complete the sign-in");
    assert!(sessions.finish(&idp, &query, Some(&pre_auth), NOW).is_err(), "and the sign-in is used up");
}

#[test]
fn reg_092_end_removes_the_session() {
    let (sessions, idp) = (PortalSessions::new("fs_session", true, TTL_MS), provider());
    let (id, cookie) = sign_in(&sessions, &idp, NOW);
    assert!(view(&sessions, &cookie, NOW).is_some());
    sessions.end(&id);
    assert!(view(&sessions, &cookie, NOW).is_none());
}

#[test]
fn reg_092_an_expired_session_is_not_returned() {
    let (sessions, idp) = (PortalSessions::new("fs_session", true, TTL_MS), provider());
    let (_, cookie) = sign_in(&sessions, &idp, NOW);
    assert!(view(&sessions, &cookie, AuthorityTime(NOW.0 + TTL_MS)).is_some());
    assert!(view(&sessions, &cookie, AuthorityTime(NOW.0 + TTL_MS + 1)).is_none());
    // Dropped for good, even if the clock were to go back.
    assert!(view(&sessions, &cookie, NOW).is_none());
}

#[test]
fn reg_092_a_cookie_name_is_configurable_so_two_portals_do_not_mix() {
    let idp = provider();
    let (factory, reader) = (PortalSessions::new("fs_session", true, TTL_MS), PortalSessions::new("fs_reader", true, TTL_MS));
    let (_, cookie) = sign_in(&factory, &idp, NOW);
    assert!(cookie.starts_with("fs_session="));
    assert!(view(&factory, &cookie, NOW).is_some());
    assert!(view(&reader, &cookie, NOW).is_none());
    let renamed = cookie.replacen("fs_session=", "fs_reader=", 1);
    assert!(view(&reader, &renamed, NOW).is_none(), "the same id under another name is not a session");
    assert!(reader.clear_cookie().starts_with("fs_reader=;"));
}
