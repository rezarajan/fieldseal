//! `OidcIdentityProvider::verify_access_token` against a mock identity provider (REG-070a).
//!
//! The mock serves discovery and a key set on loopback. Tokens are signed here, so each test
//! builds exactly the token it wants to refuse or accept. The RSA key is the PKCS#1 fixture,
//! which ring reads with `RsaKeyPair::from_der`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fieldseal_adapters_oidc::{OidcConfig, OidcIdentityProvider};
use fieldseal_registration::domain::wire::base64url_encode;
use fieldseal_registration::ports::IdentityError;
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair, RsaPublicKeyComponents};
use serde_json::{Value as Json, json};

const RSA_KEY: &[u8] = include_bytes!("fixtures/test-rsa-2048.der");
const API: &str = "fieldseal-factory-api";
const CLI: &str = "fieldseal-cli";
const ISSUER_PATH: &str = "/realms/fieldseal";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn rsa_key() -> RsaKeyPair {
    RsaKeyPair::from_der(RSA_KEY).expect("the fixture is a PKCS#1 RSAPrivateKey")
}

fn rsa_jwk(kid: &str) -> Json {
    let key = rsa_key();
    let public = RsaPublicKeyComponents::<Vec<u8>>::from(key.public());
    json!({ "kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": base64url_encode(&public.n), "e": base64url_encode(&public.e) })
}

/// A P-256 key from a fixed scalar, for the second key of a rotation.
fn ec_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap()
}

fn ec_jwk(kid: &str) -> Json {
    let point = ec_key().verifying_key().to_sec1_point(false);
    json!({ "kty": "EC", "kid": kid, "alg": "ES256", "crv": "P-256", "x": base64url_encode(point.x().unwrap()), "y": base64url_encode(point.y().unwrap()) })
}

/// A mock identity provider: discovery and a key set, and a count of key-set requests.
struct Mock {
    issuer: String,
    keys: Arc<Mutex<Vec<Json>>>,
    jwks_requests: Arc<AtomicUsize>,
}

impl Mock {
    fn start() -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let issuer = format!("http://127.0.0.1:{port}{ISSUER_PATH}");
        let keys = Arc::new(Mutex::new(vec![rsa_jwk("rsa-1")]));
        let jwks_requests = Arc::new(AtomicUsize::new(0));
        let (iss, k, n) = (issuer.clone(), keys.clone(), jwks_requests.clone());
        std::thread::spawn(move || {
            for request in server.incoming_requests() {
                let body = if request.url().ends_with("/.well-known/openid-configuration") {
                    json!({
                        "issuer": iss,
                        "authorization_endpoint": format!("{iss}/protocol/openid-connect/auth"),
                        "token_endpoint": format!("{iss}/protocol/openid-connect/token"),
                        "jwks_uri": format!("{iss}/protocol/openid-connect/certs"),
                    })
                } else if request.url().ends_with("/certs") {
                    n.fetch_add(1, Ordering::SeqCst);
                    json!({ "keys": *k.lock().unwrap() })
                } else {
                    let _ = request.respond(tiny_http::Response::empty(404));
                    continue;
                };
                let response = tiny_http::Response::from_string(body.to_string())
                    .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap());
                let _ = request.respond(response);
            }
        });
        Self { issuer, keys, jwks_requests }
    }

    fn config(&self) -> OidcConfig {
        let mut c = OidcConfig::new(&self.issuer, "fieldseal-factory");
        c.api_audience = Some(API.into());
        c.cli_client_id = Some(CLI.into());
        c
    }

    fn provider(&self) -> OidcIdentityProvider {
        OidcIdentityProvider::new(self.config()).unwrap()
    }

    /// The claims of a good access token, for the test to change.
    fn claims(&self) -> Json {
        json!({
            "iss": self.issuer, "sub": "00000000-0000-4000-8000-000000000001", "aud": API, "client_id": CLI,
            "scope": "openid", "jti": "t-1", "roles": ["collector", "operator"], "acr": "phr",
            "iat": now(), "exp": now() + 300,
        })
    }
}

fn sign_rsa(header: &Json, claims: &Json) -> String {
    let signing_input = format!("{}.{}", base64url_encode(header.to_string().as_bytes()), base64url_encode(claims.to_string().as_bytes()));
    let key = rsa_key();
    let mut sig = vec![0u8; key.public().modulus_len()];
    key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), signing_input.as_bytes(), &mut sig).unwrap();
    format!("{signing_input}.{}", base64url_encode(&sig))
}

fn sign_ec(header: &Json, claims: &Json) -> String {
    use p256::ecdsa::signature::Signer as _;
    let signing_input = format!("{}.{}", base64url_encode(header.to_string().as_bytes()), base64url_encode(claims.to_string().as_bytes()));
    let sig: p256::ecdsa::Signature = ec_key().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", base64url_encode(&sig.to_bytes()))
}

fn at_header() -> Json {
    json!({ "alg": "RS256", "typ": "at+jwt", "kid": "rsa-1" })
}

fn good(m: &Mock) -> String {
    sign_rsa(&at_header(), &m.claims())
}

fn refusal(result: Result<impl std::fmt::Debug, IdentityError>) -> String {
    match result {
        Err(IdentityError::NotAuthenticated(why)) => why,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn reg_070a_a_valid_token_yields_the_person_roles_and_methods() {
    let m = Mock::start();
    let person = m.provider().verify_access_token(&good(&m)).unwrap();
    assert_eq!(person.account.0, format!("{}|00000000-0000-4000-8000-000000000001", m.issuer));
    assert_eq!(person.role_names, ["collector", "operator"]);
    assert_eq!(person.roles.len(), 2);
    assert!(person.authentication.phishing_resistant);
    assert_eq!(person.authentication.methods, ["acr:phr"]);
}

#[test]
fn reg_070a_a_bad_signature_is_refused() {
    let m = Mock::start();
    let token = good(&m);
    let (head, sig) = token.rsplit_once('.').unwrap();
    let mut bytes = fieldseal_registration::domain::wire::base64url_decode(sig).unwrap();
    bytes[10] ^= 0x01;
    refusal(m.provider().verify_access_token(&format!("{head}.{}", base64url_encode(&bytes))));
    // A payload changed after signing is also a bad signature.
    let forged = sign_rsa(&at_header(), &m.claims());
    let other = sign_rsa(&at_header(), &json!({ "sub": "someone-else" }));
    let spliced = format!("{}.{}.{}", forged.split('.').next().unwrap(), other.split('.').nth(1).unwrap(), forged.split('.').nth(2).unwrap());
    refusal(m.provider().verify_access_token(&spliced));
}

#[test]
fn reg_070a_alg_none_and_hs256_are_refused() {
    let m = Mock::start();
    let p = m.provider();
    for alg in ["none", "HS256", "HS384", "PS256", "RS512"] {
        let header = json!({ "alg": alg, "typ": "at+jwt", "kid": "rsa-1" });
        let input = format!("{}.{}", base64url_encode(header.to_string().as_bytes()), base64url_encode(m.claims().to_string().as_bytes()));
        refusal(p.verify_access_token(&format!("{input}.{}", base64url_encode(b"signature"))));
        refusal(p.verify_access_token(&format!("{input}.")));
    }
}

#[test]
fn reg_070a_a_wrong_issuer_is_refused() {
    let m = Mock::start();
    let mut claims = m.claims();
    claims["iss"] = json!("http://127.0.0.1:1/realms/other");
    refusal(m.provider().verify_access_token(&sign_rsa(&at_header(), &claims)));
}

#[test]
fn reg_070a_a_token_without_the_api_audience_is_refused() {
    let m = Mock::start();
    let p = m.provider();
    for aud in [json!("fieldseal-factory"), json!(["fieldseal-factory", "fieldseal-intake"]), json!([])] {
        let mut claims = m.claims();
        claims["aud"] = aud;
        refusal(p.verify_access_token(&sign_rsa(&at_header(), &claims)));
    }
    let mut claims = m.claims();
    claims.as_object_mut().unwrap().remove("aud");
    refusal(p.verify_access_token(&sign_rsa(&at_header(), &claims)));
    // The API audience among several is enough.
    let mut claims = m.claims();
    claims["aud"] = json!(["account", API]);
    p.verify_access_token(&sign_rsa(&at_header(), &claims)).unwrap();
}

#[test]
fn reg_070a_an_id_token_is_refused_as_an_access_token() {
    let m = Mock::start();
    let mut claims = m.claims();
    claims["aud"] = json!(CLI);
    claims["typ"] = json!("ID");
    claims["nonce"] = json!("n-1");
    let id_token = sign_rsa(&json!({ "alg": "RS256", "typ": "JWT", "kid": "rsa-1" }), &claims);
    refusal(m.provider().verify_access_token(&id_token));
    // Not even when the deployment accepts a JWT header.
    let mut config = m.config();
    config.accept_typ_jwt = true;
    refusal(OidcIdentityProvider::new(config).unwrap().verify_access_token(&id_token));
}

#[test]
fn reg_070a_an_expired_token_is_refused() {
    let m = Mock::start();
    let p = m.provider();
    let mut claims = m.claims();
    claims["exp"] = json!(now() - 3600);
    refusal(p.verify_access_token(&sign_rsa(&at_header(), &claims)));
    // Inside the leeway it still counts.
    claims["exp"] = json!(now() - 10);
    p.verify_access_token(&sign_rsa(&at_header(), &claims)).unwrap();
    claims.as_object_mut().unwrap().remove("exp");
    refusal(p.verify_access_token(&sign_rsa(&at_header(), &claims)));
}

#[test]
fn reg_070a_iat_or_nbf_in_the_future_is_refused() {
    let m = Mock::start();
    let p = m.provider();
    for claim in ["iat", "nbf"] {
        let mut claims = m.claims();
        claims[claim] = json!(now() + 3600);
        refusal(p.verify_access_token(&sign_rsa(&at_header(), &claims)));
        claims[claim] = json!(now() - 5);
        p.verify_access_token(&sign_rsa(&at_header(), &claims)).unwrap();
    }
}

#[test]
fn reg_070a_a_missing_sub_is_refused() {
    let m = Mock::start();
    let p = m.provider();
    let mut claims = m.claims();
    claims["sub"] = json!("");
    refusal(p.verify_access_token(&sign_rsa(&at_header(), &claims)));
    claims.as_object_mut().unwrap().remove("sub");
    refusal(p.verify_access_token(&sign_rsa(&at_header(), &claims)));
}

#[test]
fn reg_070a_typ_at_jwt_is_accepted() {
    let m = Mock::start();
    for typ in ["at+jwt", "AT+JWT"] {
        let header = json!({ "alg": "RS256", "typ": typ, "kid": "rsa-1" });
        m.provider().verify_access_token(&sign_rsa(&header, &m.claims())).unwrap();
    }
}

#[test]
fn reg_070a_typ_jwt_is_refused_unless_configured() {
    let m = Mock::start();
    let header = json!({ "alg": "RS256", "typ": "JWT", "kid": "rsa-1" });
    let mut claims = m.claims();
    claims["typ"] = json!("Bearer");
    let token = sign_rsa(&header, &claims);
    refusal(m.provider().verify_access_token(&token));
    let mut config = m.config();
    config.accept_typ_jwt = true;
    OidcIdentityProvider::new(config).unwrap().verify_access_token(&token).unwrap();
}

#[test]
fn reg_070a_typ_jwt_is_accepted_only_with_the_payload_typ_bearer() {
    let m = Mock::start();
    let mut config = m.config();
    config.accept_typ_jwt = true;
    let p = OidcIdentityProvider::new(config).unwrap();
    let header = json!({ "alg": "RS256", "typ": "JWT", "kid": "rsa-1" });
    for payload_typ in [json!("ID"), json!("Refresh"), json!("bearer"), json!(null)] {
        let mut claims = m.claims();
        claims["typ"] = payload_typ;
        refusal(p.verify_access_token(&sign_rsa(&header, &claims)));
    }
    refusal(p.verify_access_token(&sign_rsa(&header, &m.claims())));
}

#[test]
fn reg_070a_a_token_carrying_a_nonce_is_refused() {
    let m = Mock::start();
    let p = m.provider();
    for nonce in [json!("n-1"), json!(""), json!(null)] {
        let mut claims = m.claims();
        claims["nonce"] = nonce;
        let why = refusal(p.verify_access_token(&sign_rsa(&at_header(), &claims)));
        assert!(why.contains("nonce"), "{why}");
    }
}

#[test]
fn reg_070a_an_id_token_from_the_cli_client_that_carries_the_api_audience_is_refused() {
    let m = Mock::start();
    let mut config = m.config();
    config.accept_typ_jwt = true;
    let p = OidcIdentityProvider::new(config).unwrap();
    // Keycloak's ID token: header `JWT`, payload `ID`, the CLI as client, and (by a realm
    // mistake) the API audience. The nonce rule and the payload type rule each close it.
    let header = json!({ "alg": "RS256", "typ": "JWT", "kid": "rsa-1" });
    let mut claims = m.claims();
    claims["aud"] = json!([CLI, API]);
    claims["azp"] = json!(CLI);
    claims["typ"] = json!("ID");
    claims["nonce"] = json!("n-1");
    claims.as_object_mut().unwrap().remove("client_id");
    refusal(p.verify_access_token(&sign_rsa(&header, &claims)));
    claims.as_object_mut().unwrap().remove("nonce");
    refusal(p.verify_access_token(&sign_rsa(&header, &claims)));
    claims["typ"] = json!("Bearer");
    claims["nonce"] = json!("n-1");
    refusal(p.verify_access_token(&sign_rsa(&header, &claims)));
}

#[test]
fn reg_070a_another_typ_is_refused() {
    let m = Mock::start();
    let mut config = m.config();
    config.accept_typ_jwt = true;
    let p = OidcIdentityProvider::new(config).unwrap();
    for typ in [json!("jwt+at"), json!("JWS"), json!("application/at+jwt"), json!("id+jwt"), json!("")] {
        let mut claims = m.claims();
        claims["typ"] = json!("Bearer");
        refusal(p.verify_access_token(&sign_rsa(&json!({ "alg": "RS256", "typ": typ, "kid": "rsa-1" }), &claims)));
    }
    // No header type at all.
    refusal(p.verify_access_token(&sign_rsa(&json!({ "alg": "RS256", "kid": "rsa-1" }), &m.claims())));
}

#[test]
fn reg_070a_a_token_for_another_client_is_refused() {
    let m = Mock::start();
    let p = m.provider();
    for client in ["fieldseal-factory", "fieldseal-intake", "fieldseal-cli-2", ""] {
        let mut claims = m.claims();
        claims["client_id"] = json!(client);
        refusal(p.verify_access_token(&sign_rsa(&at_header(), &claims)));
    }
    // `client_id` wins: a matching `azp` does not rescue another `client_id`.
    let mut claims = m.claims();
    claims["client_id"] = json!("fieldseal-intake");
    claims["azp"] = json!(CLI);
    refusal(p.verify_access_token(&sign_rsa(&at_header(), &claims)));
    // No client claim at all, or one of the wrong type.
    let mut claims = m.claims();
    claims.as_object_mut().unwrap().remove("client_id");
    refusal(p.verify_access_token(&sign_rsa(&at_header(), &claims)));
    claims["client_id"] = json!(7);
    refusal(p.verify_access_token(&sign_rsa(&at_header(), &claims)));
}

#[test]
fn reg_070a_azp_stands_in_when_client_id_is_absent() {
    let m = Mock::start();
    let p = m.provider();
    let mut claims = m.claims();
    claims.as_object_mut().unwrap().remove("client_id");
    claims["azp"] = json!(CLI);
    p.verify_access_token(&sign_rsa(&at_header(), &claims)).unwrap();
    claims["azp"] = json!("fieldseal-intake");
    refusal(p.verify_access_token(&sign_rsa(&at_header(), &claims)));
}

#[test]
fn reg_070a_acr_without_amr_is_phishing_resistant_by_acr() {
    let m = Mock::start();
    let p = m.provider();
    let mut claims = m.claims();
    claims["acr"] = json!("phr");
    assert!(p.verify_access_token(&sign_rsa(&at_header(), &claims)).unwrap().authentication.phishing_resistant);
    // A password sign-in is not, and `amr` is read from the access token only.
    claims["acr"] = json!("1");
    claims["amr"] = json!(["pwd"]);
    let person = p.verify_access_token(&sign_rsa(&at_header(), &claims)).unwrap();
    assert!(!person.authentication.phishing_resistant);
    assert_eq!(person.authentication.methods, ["pwd", "acr:1"]);
    // No `acr` and no `amr`: not phishing-resistant.
    claims.as_object_mut().unwrap().remove("acr");
    claims.as_object_mut().unwrap().remove("amr");
    assert!(!p.verify_access_token(&sign_rsa(&at_header(), &claims)).unwrap().authentication.phishing_resistant);
}

#[test]
fn reg_070a_the_key_set_is_refetched_once_on_an_unknown_kid() {
    let m = Mock::start();
    // No minimum interval here, so that the rotation is seen at once.
    let mut config = m.config();
    config.jwks_min_refetch = Duration::ZERO;
    let p = OidcIdentityProvider::new(config).unwrap();
    p.verify_access_token(&good(&m)).unwrap();
    assert_eq!(m.jwks_requests.load(Ordering::SeqCst), 1);
    // A known kid is served from the held key set.
    p.verify_access_token(&good(&m)).unwrap();
    assert_eq!(m.jwks_requests.load(Ordering::SeqCst), 1);
    // The issuer rotates: a new key under a new kid. One refetch finds it.
    m.keys.lock().unwrap().push(ec_jwk("ec-2"));
    let rotated = sign_ec(&json!({ "alg": "ES256", "typ": "at+jwt", "kid": "ec-2" }), &m.claims());
    p.verify_access_token(&rotated).unwrap();
    assert_eq!(m.jwks_requests.load(Ordering::SeqCst), 2);
    // A kid that is still unknown is refused after exactly one refetch.
    let unknown = sign_ec(&json!({ "alg": "ES256", "typ": "at+jwt", "kid": "ec-3" }), &m.claims());
    refusal(p.verify_access_token(&unknown));
    assert_eq!(m.jwks_requests.load(Ordering::SeqCst), 3);
}

#[test]
fn reg_070a_without_an_api_audience_and_cli_client_no_access_token_is_accepted() {
    let m = Mock::start();
    let mut config = m.config();
    config.api_audience = None;
    refusal(OidcIdentityProvider::new(config).unwrap().verify_access_token(&good(&m)));
    let mut config = m.config();
    config.cli_client_id = None;
    refusal(OidcIdentityProvider::new(config).unwrap().verify_access_token(&good(&m)));
}

#[test]
fn reg_070a_unknown_kids_inside_the_interval_cause_at_most_one_fetch() {
    let m = Mock::start();
    let p = m.provider();
    p.verify_access_token(&good(&m)).unwrap();
    assert_eq!(m.jwks_requests.load(Ordering::SeqCst), 1);
    // Many tokens with distinct unknown kids: refused against the held set, no network call.
    for i in 0..20 {
        let forged = sign_rsa(&json!({ "alg": "RS256", "typ": "at+jwt", "kid": format!("forged-{i}") }), &m.claims());
        refusal(p.verify_access_token(&forged));
    }
    assert_eq!(m.jwks_requests.load(Ordering::SeqCst), 1);
    // Concurrent misses on a fresh provider share one fetch.
    let m = Mock::start();
    let p = Arc::new(m.provider());
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let (p, token) = (p.clone(), sign_rsa(&json!({ "alg": "RS256", "typ": "at+jwt", "kid": format!("forged-{i}") }), &m.claims()));
            std::thread::spawn(move || p.verify_access_token(&token).is_err())
        })
        .collect();
    for t in threads {
        assert!(t.join().unwrap());
    }
    assert_eq!(m.jwks_requests.load(Ordering::SeqCst), 1);
}

#[test]
fn reg_070a_a_refused_header_costs_no_key_set_fetch() {
    let m = Mock::start();
    let p = m.provider();
    refusal(p.verify_access_token(&sign_rsa(&json!({ "alg": "HS256", "typ": "at+jwt", "kid": "rsa-1" }), &m.claims())));
    refusal(p.verify_access_token(&sign_rsa(&json!({ "alg": "RS256", "typ": "JWT", "kid": "rsa-1" }), &m.claims())));
    refusal(p.verify_access_token(&sign_rsa(&json!({ "alg": "RS256", "kid": "rsa-1" }), &m.claims())));
    assert_eq!(m.jwks_requests.load(Ordering::SeqCst), 0);
}

#[test]
fn reg_070a_client_id_and_azp_must_agree_when_both_are_present() {
    let m = Mock::start();
    let p = m.provider();
    let mut claims = m.claims();
    claims["azp"] = json!(CLI);
    p.verify_access_token(&sign_rsa(&at_header(), &claims)).unwrap();
    claims["azp"] = json!("fieldseal-intake");
    assert!(refusal(p.verify_access_token(&sign_rsa(&at_header(), &claims))).contains("azp"));
}

#[test]
fn reg_070a_an_encryption_key_or_one_for_another_algorithm_never_verifies() {
    let m = Mock::start();
    // The only key is marked for encryption, although the token verifies against it.
    let mut enc = rsa_jwk("rsa-1");
    enc["use"] = json!("enc");
    *m.keys.lock().unwrap() = vec![enc];
    refusal(m.provider().verify_access_token(&good(&m)));
    // A signing key that names another algorithm than the token's header.
    let mut other = rsa_jwk("rsa-1");
    other["alg"] = json!("RS512");
    *m.keys.lock().unwrap() = vec![other];
    refusal(m.provider().verify_access_token(&good(&m)));
    // An `enc` key ahead of the signing key with the same kid is skipped, not fatal.
    let mut enc = rsa_jwk("rsa-1");
    enc["use"] = json!("enc");
    *m.keys.lock().unwrap() = vec![enc, rsa_jwk("rsa-1")];
    m.provider().verify_access_token(&good(&m)).unwrap();
}
