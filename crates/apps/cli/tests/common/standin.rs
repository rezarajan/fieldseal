//! Stand-ins for the identity provider and the factory that the operator commands talk to:
//! `tiny_http` servers on loopback. The identity provider signs ES256 ID and access tokens and
//! checks PKCE, so the CLI's own adapter verifies real tokens; the factory records what it is
//! sent and answers what the test says.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use fieldseal_kernel::digest::sha256;
use fieldseal_registration::domain::wire::base64url_encode;
use p256::ecdsa::signature::Signer as _;
use serde_json::{Value as Json, json};

pub const API_AUDIENCE: &str = "fieldseal-factory-api";
pub const OPERATOR_SUBJECT: &str = "00000000-0000-4000-8000-000000000001";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs()
}

fn key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).expect("scalar")
}

fn jwt(typ: &str, claims: &Json) -> String {
    let header = json!({ "alg": "ES256", "typ": typ, "kid": "k1" });
    let signing_input = format!("{}.{}", base64url_encode(header.to_string().as_bytes()), base64url_encode(claims.to_string().as_bytes()));
    let signature: p256::ecdsa::Signature = key().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", base64url_encode(&signature.to_bytes()))
}

/// How the authorisation endpoint answers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Authorize {
    /// Redirects at once, as an identity provider does for a person who is already signed in.
    Auto,
    /// Always shows a login page.
    LoginPage,
    /// Redirects with a state that is not the request's.
    WrongState,
}

#[derive(Default)]
struct IdpState {
    /// code -> (nonce, code_challenge, redirect_uri)
    codes: HashMap<String, (String, String, String)>,
    authorize: Vec<HashMap<String, String>>,
    token: Vec<HashMap<String, String>>,
    issued: Vec<String>,
    id_tokens: Vec<String>,
}

/// The identity provider.
pub struct Idp {
    pub issuer: String,
    mode: Arc<Mutex<Authorize>>,
    state: Arc<Mutex<IdpState>>,
}

fn form(body: &str) -> HashMap<String, String> {
    fieldseal_adapters_factory_http::parse_form(body).into_iter().collect()
}

impl Idp {
    pub fn start(mode: Authorize) -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
        let port = server.server_addr().to_ip().expect("ip").port();
        let issuer = format!("http://127.0.0.1:{port}/realms/fieldseal");
        let state = Arc::new(Mutex::new(IdpState::default()));
        let mode = Arc::new(Mutex::new(mode));
        let (iss, st, md) = (issuer.clone(), state.clone(), mode.clone());
        std::thread::spawn(move || {
            let mut counter = 0u32;
            for mut request in server.incoming_requests() {
                let (path, query) = request.url().split_once('?').map_or((request.url().to_owned(), String::new()), |(p, q)| (p.to_owned(), q.to_owned()));
                let mut body = String::new();
                let _ = request.as_reader().read_to_string(&mut body);
                let json_response = |j: Json| tiny_http::Response::from_string(j.to_string()).with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").expect("header"));
                if path.ends_with("/.well-known/openid-configuration") {
                    let _ = request.respond(json_response(json!({
                        "issuer": iss,
                        "authorization_endpoint": format!("{iss}/protocol/openid-connect/auth"),
                        "token_endpoint": format!("{iss}/protocol/openid-connect/token"),
                        "jwks_uri": format!("{iss}/protocol/openid-connect/certs"),
                    })));
                } else if path.ends_with("/certs") {
                    let point = key().verifying_key().to_sec1_point(false);
                    let jwk = json!({ "kty": "EC", "kid": "k1", "alg": "ES256", "use": "sig", "crv": "P-256", "x": base64url_encode(point.x().expect("x")), "y": base64url_encode(point.y().expect("y")) });
                    let _ = request.respond(json_response(json!({ "keys": [jwk] })));
                } else if path.ends_with("/auth") {
                    let q = form(&query);
                    st.lock().expect("lock").authorize.push(q.clone());
                    let mode = *md.lock().expect("lock");
                    let redirect = q.get("redirect_uri").cloned().unwrap_or_default();
                    if mode == Authorize::LoginPage {
                        let _ = request.respond(tiny_http::Response::from_string("<html><form>log in</form></html>").with_header(tiny_http::Header::from_bytes("Content-Type", "text/html").expect("header")));
                        continue;
                    }
                    counter += 1;
                    let code = format!("code-{counter}");
                    st.lock().expect("lock").codes.insert(code.clone(), (q.get("nonce").cloned().unwrap_or_default(), q.get("code_challenge").cloned().unwrap_or_default(), redirect.clone()));
                    let state_param = if mode == Authorize::WrongState { "forged".to_owned() } else { q.get("state").cloned().unwrap_or_default() };
                    let location = format!("{redirect}?code={code}&state={state_param}&iss={}", fieldseal_adapters_oidc::percent_encode(&iss));
                    let _ = request.respond(tiny_http::Response::empty(302).with_header(tiny_http::Header::from_bytes("Location", location).expect("header")));
                } else if path.ends_with("/token") {
                    let f = form(&body);
                    st.lock().expect("lock").token.push(f.clone());
                    let entry = f.get("code").and_then(|c| st.lock().expect("lock").codes.remove(c));
                    let pkce_ok = entry.as_ref().is_some_and(|(_, challenge, _)| f.get("code_verifier").is_some_and(|v| base64url_encode(sha256(v.as_bytes()).as_bytes()) == *challenge));
                    let Some((nonce, _, redirect)) = entry.filter(|_| pkce_ok) else {
                        let _ = request.respond(json_response(json!({ "error": "invalid_grant" })).with_status_code(400));
                        continue;
                    };
                    if f.get("redirect_uri") != Some(&redirect) {
                        let _ = request.respond(json_response(json!({ "error": "invalid_grant" })).with_status_code(400));
                        continue;
                    }
                    let client = f.get("client_id").cloned().unwrap_or_default();
                    let t = now();
                    counter += 1;
                    let id_token = jwt("JWT", &json!({ "iss": iss, "aud": client, "sub": OPERATOR_SUBJECT, "nonce": nonce, "roles": ["collector", "operator"], "amr": ["hwk"], "acr": "phr", "iat": t, "exp": t + 300 }));
                    let access = jwt(
                        "at+jwt",
                        &json!({ "iss": iss, "sub": OPERATOR_SUBJECT, "aud": [API_AUDIENCE], "client_id": client, "scope": "openid", "jti": format!("jti-{counter}"), "roles": ["collector", "operator"], "acr": "phr", "amr": ["hwk"], "iat": t, "exp": t + 300 }),
                    );
                    {
                        let mut s = st.lock().expect("lock");
                        s.issued.push(access.clone());
                        s.id_tokens.push(id_token.clone());
                    }
                    let _ = request.respond(json_response(json!({ "token_type": "Bearer", "access_token": access, "id_token": id_token, "expires_in": 300 })));
                } else {
                    let _ = request.respond(tiny_http::Response::empty(404));
                }
            }
        });
        Self { issuer, mode, state }
    }

    pub fn set_mode(&self, mode: Authorize) {
        *self.mode.lock().expect("lock") = mode;
    }

    /// The query of each authorisation request.
    pub fn authorize_requests(&self) -> Vec<HashMap<String, String>> {
        self.state.lock().expect("lock").authorize.clone()
    }

    /// The form of each token request.
    pub fn token_requests(&self) -> Vec<HashMap<String, String>> {
        self.state.lock().expect("lock").token.clone()
    }

    /// The access tokens issued, oldest first.
    pub fn issued_access_tokens(&self) -> Vec<String> {
        self.state.lock().expect("lock").issued.clone()
    }

    /// Everything a leak would show: the access and ID tokens and the codes.
    pub fn secrets(&self) -> Vec<String> {
        let s = self.state.lock().expect("lock");
        s.issued.iter().chain(&s.id_tokens).cloned().chain(s.token.iter().filter_map(|t| t.get("code").cloned())).chain(s.token.iter().filter_map(|t| t.get("code_verifier").cloned())).collect()
    }

    /// How many requests of any kind the identity provider has received.
    pub fn requests(&self) -> usize {
        let s = self.state.lock().expect("lock");
        s.authorize.len() + s.token.len()
    }
}

/// One request the factory stand-in received.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub body: Vec<u8>,
}

type Answer = Box<dyn Fn(&Seen) -> (u16, String) + Send + Sync>;

/// The factory.
pub struct Factory {
    pub url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Factory {
    /// A factory that answers every request with `answer`.
    pub fn start(answer: impl Fn(&Seen) -> (u16, String) + Send + Sync + 'static) -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
        let url = format!("http://127.0.0.1:{}", server.server_addr().to_ip().expect("ip").port());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (log, answer): (_, Answer) = (seen.clone(), Box::new(answer));
        std::thread::spawn(move || {
            for mut request in server.incoming_requests() {
                let mut body = Vec::new();
                let _ = request.as_reader().read_to_end(&mut body);
                let authorization = request.headers().iter().find(|h| h.field.equiv("Authorization")).map(|h| h.value.as_str().to_owned());
                let s = Seen { method: request.method().as_str().to_owned(), path: request.url().to_owned(), authorization, body };
                let (status, text) = answer(&s);
                log.lock().expect("lock").push(s);
                let _ = request.respond(tiny_http::Response::from_string(text).with_status_code(status).with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").expect("header")));
            }
        });
        Self { url, seen }
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("lock").clone()
    }
}

/// A factory that accepts every assignment and roster issue.
pub fn accepting_factory() -> Factory {
    let versions: Mutex<BTreeMap<String, u64>> = Mutex::default();
    Factory::start(move |s| match (s.method.as_str(), s.path.as_str()) {
        ("POST", "/v1/assignments") => (200, json!({ "status": "assigned", "generation": 1 }).to_string()),
        ("GET", "/v1/assignments") => (200, json!({ "assignments": [
            { "seq": 1, "account": OPERATOR_SUBJECT, "survey": "household-water-access", "cohort": "village-a", "generation": 1, "by": "ops", "roles": ["operator"], "methods": ["hwk"], "at": "2026-01-01T00:00:00Z" },
            { "seq": 2, "account": OPERATOR_SUBJECT, "survey": "school-meals-baseline", "cohort": "cohort-a", "generation": 1, "by": "ops", "roles": ["operator"], "methods": ["hwk"], "at": "2026-01-01T00:00:01Z" },
        ] }).to_string()),
        ("POST", "/v1/rosters") => {
            let value = fieldseal_kernel::cbor::decode(&s.body).ok();
            let (cohort, version) = value
                .as_ref()
                .and_then(|v| v.as_map())
                .map(|m| (m["cohort"].as_text().unwrap_or("").to_owned(), u64::try_from(m["version"].as_int().unwrap_or(0)).unwrap_or(0)))
                .unwrap_or_default();
            versions.lock().expect("lock").insert(cohort, version);
            (200, json!({ "status": "issued", "version": version, "digest": format!("sha256:{}", "ab".repeat(32)) }).to_string())
        }
        _ => (404, json!({ "error": "not-found" }).to_string()),
    })
}
