//! OpenID Connect adapter for the Registration context's [`IdentityProvider`] port
//! (REG-002, REG-002a).
//!
//! Sign-in uses the authorization code flow with PKCE (`S256`) against any OIDC issuer:
//! discovery from `{issuer}/.well-known/openid-configuration`, a fresh `state`, `nonce`
//! and code verifier per sign-in, and the code exchanged at the token endpoint. The ID
//! token is verified before anything is read from it: the JWS signature against the
//! issuer's JWKS (`RS256` or `ES256` only; `none` and symmetric algorithms are refused),
//! then `iss`, `aud` (and `azp` when several audiences), `exp` and `nonce`.
//!
//! An operator API call carries a Bearer access token instead ([`OidcIdentityProvider::verify_access_token`],
//! REG-070a): the same signature and key-set code, a different claim checklist. The token must
//! be an access token for the factory API, issued to the CLI's public client, and it can never
//! be an ID token. Nothing is cached: each call verifies the token it was given.
//!
//! The authentication methods come from the token's own `amr` and `acr` claims, mapped by
//! `phishing_resistant_with`: the built-in values, plus any the deployment names for this
//! issuer ([`OidcConfig::phishing_resistant_amr`], [`OidcConfig::phishing_resistant_acr`]).
//! Configuration can never make a sign-in stronger:
//! the only setting that touches strength, [`OidcConfig::asserted_methods`], marks every
//! method as `asserted` for an issuer that is a broker not known to pass the upstream
//! provider's claims through unchanged (REG-002a), which factory policy then refuses
//! unless it accepts asserted methods.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fieldseal_kernel::digest::sha256;
use fieldseal_registration::domain::auth::phishing_resistant_with;
use fieldseal_registration::domain::wire::{base64url_decode, base64url_encode};
use fieldseal_registration::domain::{AccountId, AuthenticatedPerson, AuthenticationMethods, MethodAssurance, Role};
use fieldseal_registration::ports::{IdentityError, IdentityProvider, PendingSignIn, SignInStart};
use serde_json::{Value as Json, json};

/// The largest response accepted from the identity provider.
const MAX_RESPONSE: u64 = 1024 * 1024;

/// How an OIDC client is configured. Every value comes from the environment (twelve-factor
/// III); nothing here can raise the strength of a sign-in.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OidcConfig {
    /// The issuer identifier; must match the discovery document and every ID token's `iss`.
    pub issuer: String,
    /// The client ID registered with the provider; every ID token's `aud` must contain it.
    pub client_id: String,
    /// The client secret, for confidential clients (sent with HTTP Basic).
    pub client_secret: Option<String>,
    /// Extra scopes besides `openid`.
    pub scopes: Vec<String>,
    /// The claim that carries role or group names (for example `roles` or `groups`).
    pub roles_claim: String,
    /// `acr_values` to request, if any. Requesting is not proof: only the token's `acr` and
    /// `amr` count.
    pub acr_values: Option<String>,
    /// The issuer is an identity broker that may not pass the upstream provider's `amr`
    /// and `acr` through unchanged: report every method as `asserted` (REG-002a).
    pub asserted_methods: bool,
    /// Extra `amr` values this issuer uses to mean phishing-resistant, beyond the built-in
    /// `hwk`, `swk`, `fido` and `sc`. Empty by default (strict). A token still has to carry one.
    pub phishing_resistant_amr: Vec<String>,
    /// Extra `acr` values this issuer uses to mean phishing-resistant, beyond `phr` and
    /// `phrh`. Empty by default (strict). A token still has to carry one.
    pub phishing_resistant_acr: Vec<String>,
    /// The audience of the factory API's access tokens (`verify_access_token`). Without it no
    /// access token is accepted.
    pub api_audience: Option<String>,
    /// The public client that may call the operator API (`verify_access_token`): an access
    /// token's `client_id`, or its `azp` when `client_id` is absent, must equal it. Without it
    /// no access token is accepted.
    pub cli_client_id: Option<String>,
    /// Accept an access token whose header `typ` is a plain `JWT` (Keycloak's), and then only
    /// with the payload `typ: Bearer`. By default only `at+jwt` is accepted.
    pub accept_typ_jwt: bool,
    /// The shortest time between two fetches of the issuer's key set, whatever the first one
    /// returned. A token with an unknown `kid` inside this interval is refused against the held key
    /// set without a network call, so a stream of forged `kid`s cannot make the factory hammer the
    /// issuer. Key rotation is picked up at the first unknown `kid` after the interval.
    pub jwks_min_refetch: Duration,
    /// Allowed clock skew when checking `exp`, `iat` and `nbf`.
    pub leeway: Duration,
    /// Network timeout for each request.
    pub timeout: Duration,
}

impl OidcConfig {
    /// A configuration with the usual defaults: `roles` claim, 60 s leeway, 10 s timeout.
    pub fn new(issuer: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            client_id: client_id.into(),
            client_secret: None,
            scopes: vec![],
            roles_claim: "roles".into(),
            acr_values: None,
            asserted_methods: false,
            phishing_resistant_amr: vec![],
            phishing_resistant_acr: vec![],
            api_audience: None,
            cli_client_id: None,
            accept_typ_jwt: false,
            jwks_min_refetch: Duration::from_secs(60),
            leeway: Duration::from_secs(60),
            timeout: Duration::from_secs(10),
        }
    }
}

/// Why the adapter couldn't be set up.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OidcSetupError {
    /// The issuer URL isn't `https` (plain `http` is allowed for loopback only).
    #[error("issuer must be an https URL: {0}")]
    InsecureIssuer(String),
}

fn secure_url(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    let Some(rest) = url.strip_prefix("http://") else { return false };
    let host_port = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match host_port.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => host_port.split(':').next().unwrap_or(""),
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

#[derive(Clone, Debug)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

/// The OIDC [`IdentityProvider`].
pub struct OidcIdentityProvider {
    config: OidcConfig,
    agent: ureq::Agent,
    discovery: Mutex<Option<Discovery>>,
    jwks: Mutex<Jwks>,
    /// Held while the key set is fetched, so that concurrent misses wait for one fetch.
    jwks_fetch: Mutex<()>,
}

/// The held key set and when it was last fetched (successfully or not).
#[derive(Default)]
struct Jwks {
    set: Option<Json>,
    last_fetch: Option<Instant>,
}

fn unavailable(e: impl std::fmt::Display) -> IdentityError {
    IdentityError::Unavailable(e.to_string())
}

fn refused(why: impl Into<String>) -> IdentityError {
    IdentityError::NotAuthenticated(why.into())
}

fn random_b64(len: usize) -> Result<String, IdentityError> {
    let mut b = vec![0u8; len];
    getrandom::getrandom(&mut b).map_err(unavailable)?;
    Ok(base64url_encode(&b))
}

/// Percent-encodes a query or form component (RFC 3986 unreserved characters kept).
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl OidcIdentityProvider {
    /// An adapter for `config`. Discovery happens on first use, so a provider that is down
    /// at start-up doesn't stop the factory.
    pub fn new(config: OidcConfig) -> Result<Self, OidcSetupError> {
        if !secure_url(&config.issuer) {
            return Err(OidcSetupError::InsecureIssuer(config.issuer.clone()));
        }
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(config.timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent("fieldseal")
            .build()
            .into();
        Ok(Self { config, agent, discovery: Mutex::new(None), jwks: Mutex::new(Jwks::default()), jwks_fetch: Mutex::new(()) })
    }

    fn get_json(&self, url: &str) -> Result<Json, IdentityError> {
        let mut r = self.agent.get(url).header("Accept", "application/json").call().map_err(unavailable)?;
        let status = r.status();
        let body = r.body_mut().with_config().limit(MAX_RESPONSE).read_to_vec().map_err(unavailable)?;
        if !status.is_success() {
            return Err(unavailable(format!("{url}: HTTP {}", status.as_u16())));
        }
        serde_json::from_slice(&body).map_err(|_| unavailable(format!("{url}: not JSON")))
    }

    fn discovery(&self) -> Result<Discovery, IdentityError> {
        if let Some(d) = self.discovery.lock().expect("lock").clone() {
            return Ok(d);
        }
        let url = format!("{}/.well-known/openid-configuration", self.config.issuer.trim_end_matches('/'));
        let doc = self.get_json(&url)?;
        let field = |k: &str| doc[k].as_str().map(str::to_owned).ok_or_else(|| unavailable(format!("discovery lacks {k}")));
        if field("issuer")? != self.config.issuer {
            return Err(unavailable("discovery issuer does not match the configured issuer"));
        }
        let d = Discovery {
            authorization_endpoint: field("authorization_endpoint")?,
            token_endpoint: field("token_endpoint")?,
            jwks_uri: field("jwks_uri")?,
        };
        for u in [&d.authorization_endpoint, &d.token_endpoint, &d.jwks_uri] {
            if !secure_url(u) {
                return Err(unavailable(format!("insecure endpoint {u}")));
            }
        }
        *self.discovery.lock().expect("lock") = Some(d.clone());
        Ok(d)
    }

    /// The signing JWK with `kid` for `alg`. A key whose `use` is present and not `sig`, or whose
    /// `alg` is present and differs from the token's, is never a match. An unknown `kid` refetches
    /// the key set (key rotation), at most once per `jwks_min_refetch` and by one caller at a time;
    /// inside the interval it is refused against the held set with no network call.
    fn jwk(&self, kid: Option<&str>, kty: &str, alg: &str) -> Result<Json, IdentityError> {
        let find = |set: &Json| {
            set["keys"].as_array().and_then(|keys| {
                keys.iter()
                    .find(|k| {
                        k["kty"].as_str() == Some(kty)
                            && (kid.is_none() || k["kid"].as_str() == kid)
                            && k.get("use").is_none_or(|u| u.as_str() == Some("sig"))
                            && k.get("alg").is_none_or(|a| a.as_str() == Some(alg))
                    })
                    .cloned()
            })
        };
        let held = |jwks: &Jwks| jwks.set.as_ref().and_then(&find);
        if let Some(k) = held(&self.jwks.lock().expect("lock")) {
            return Ok(k);
        }
        let _one_fetch = self.jwks_fetch.lock().expect("lock");
        {
            // Another caller may have fetched while this one waited.
            let jwks = self.jwks.lock().expect("lock");
            if let Some(k) = held(&jwks) {
                return Ok(k);
            }
            if jwks.last_fetch.is_some_and(|t| t.elapsed() < self.config.jwks_min_refetch) {
                return Err(refused("no key in the issuer's JWKS matches the token"));
            }
        }
        let fetched = self.discovery().and_then(|d| self.get_json(&d.jwks_uri));
        let mut jwks = self.jwks.lock().expect("lock");
        jwks.last_fetch = Some(Instant::now());
        let set = fetched?;
        let found = find(&set);
        jwks.set = Some(set);
        found.ok_or_else(|| refused("no key in the issuer's JWKS matches the token"))
    }

    fn verify_signature(&self, header: &Json, signing_input: &[u8], sig: &[u8]) -> Result<(), IdentityError> {
        let kid = header["kid"].as_str();
        let b64 = |k: &Json, f: &str| {
            k[f].as_str().ok_or_else(|| refused(format!("JWK lacks {f}"))).and_then(|s| base64url_decode(s).map_err(|_| refused("bad JWK")))
        };
        match header["alg"].as_str() {
            Some("RS256") => {
                let k = self.jwk(kid, "RSA", "RS256")?;
                let (n, e) = (b64(&k, "n")?, b64(&k, "e")?);
                ring::signature::RsaPublicKeyComponents { n: &n, e: &e }
                    .verify(&ring::signature::RSA_PKCS1_2048_8192_SHA256, signing_input, sig)
                    .map_err(|_| refused("token signature does not verify"))
            }
            Some("ES256") => {
                use p256::ecdsa::signature::Verifier as _;
                let k = self.jwk(kid, "EC", "ES256")?;
                if k["crv"].as_str() != Some("P-256") {
                    return Err(refused("JWK is not P-256"));
                }
                let (x, y) = (b64(&k, "x")?, b64(&k, "y")?);
                if x.len() != 32 || y.len() != 32 {
                    return Err(refused("bad P-256 JWK"));
                }
                let mut sec1 = vec![0x04];
                sec1.extend_from_slice(&x);
                sec1.extend_from_slice(&y);
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| refused("bad P-256 JWK"))?;
                let sig = p256::ecdsa::Signature::from_slice(sig).map_err(|_| refused("bad ES256 signature"))?;
                let sig = sig.normalize_s();
                key.verify(signing_input, &sig).map_err(|_| refused("token signature does not verify"))
            }
            other => Err(refused(format!("token algorithm {other:?} is not accepted"))),
        }
    }

    /// Checks the compact JWS of `token` (shape, header, signature) and returns its header and
    /// claims. Nothing in the claims is trusted yet.
    /// `header_ok` judges the header before any key is looked up, so a token that is refused for its
    /// header costs no network call.
    fn verify_jws(&self, token: &str, what: &str, header_ok: &dyn Fn(&Json) -> Result<(), IdentityError>) -> Result<(Json, Json), IdentityError> {
        let parts: Vec<&str> = token.split('.').collect();
        let [h, p, s] = parts[..] else { return Err(refused(format!("{what} is not a compact JWS"))) };
        let header: Json = serde_json::from_slice(&base64url_decode(h).map_err(|_| refused("bad header"))?)
            .map_err(|_| refused("bad header"))?;
        check_header(&header)?;
        match header["alg"].as_str() {
            Some("RS256" | "ES256") => {}
            other => return Err(refused(format!("token algorithm {other:?} is not accepted"))),
        }
        header_ok(&header)?;
        let sig = base64url_decode(s).map_err(|_| refused("bad signature encoding"))?;
        self.verify_signature(&header, format!("{h}.{p}").as_bytes(), &sig)?;
        let claims: Json = serde_json::from_slice(&base64url_decode(p).map_err(|_| refused("bad payload"))?)
            .map_err(|_| refused("bad payload"))?;
        if !claims.is_object() {
            return Err(refused(format!("{what} claims are not an object")));
        }
        Ok((header, claims))
    }

    /// `exp` (required), `iat` and, for an access token, `nbf`, each with the configured leeway.
    fn check_times(&self, claims: &Json, what: &str, nbf: bool) -> Result<(), IdentityError> {
        let now = now_secs();
        let leeway = self.config.leeway.as_secs();
        let exp = claims["exp"].as_u64().ok_or_else(|| refused("no exp"))?;
        if now > exp.saturating_add(leeway) {
            return Err(refused(format!("{what} expired")));
        }
        match &claims["iat"] {
            Json::Null => {}
            v => match v.as_u64() {
                Some(iat) if iat > now.saturating_add(leeway) => return Err(refused(format!("{what} issued in the future"))),
                Some(_) => {}
                None => return Err(refused("iat is not a whole number of seconds")),
            },
        }
        if nbf {
            match &claims["nbf"] {
                Json::Null => {}
                v => match v.as_u64() {
                    Some(nbf) if nbf > now.saturating_add(leeway) => return Err(refused(format!("{what} is not valid yet"))),
                    Some(_) => {}
                    None => return Err(refused("nbf is not a whole number of seconds")),
                },
            }
        }
        Ok(())
    }

    /// Verifies an ID token and returns its claims (exposed for tests of the adapter).
    pub fn verify_id_token(&self, id_token: &str, nonce: &str) -> Result<Json, IdentityError> {
        let (_, claims) = self.verify_jws(id_token, "ID token", &|_| Ok(()))?;
        if claims["iss"].as_str() != Some(self.config.issuer.as_str()) {
            return Err(refused("wrong issuer"));
        }
        let audiences = audiences(&claims)?;
        if !audiences.contains(&self.config.client_id.as_str()) {
            return Err(refused("wrong audience"));
        }
        if audiences.len() > 1 && claims["azp"].as_str() != Some(self.config.client_id.as_str()) {
            return Err(refused("several audiences and azp is not this client"));
        }
        self.check_times(&claims, "ID token", false)?;
        if !matches!(claims["azp"], Json::Null | Json::String(_)) {
            return Err(refused("azp is not a string"));
        }
        if claims["nonce"].as_str() != Some(nonce) {
            return Err(refused("nonce does not match"));
        }
        if claims["sub"].as_str().is_none_or(str::is_empty) {
            return Err(refused("no subject"));
        }
        Ok(claims)
    }

    /// Verifies a Bearer access token for the factory API (REG-070a, RFC 9068 profile) and
    /// returns the person it was issued to. The roles, `acr` and `amr` are read from this
    /// token and from no other source, with the mapping the ID-token sign-in uses. Whether the
    /// person may do what they ask (the `operator` role, a phishing-resistant method) is the
    /// caller's decision. The token is not cached.
    ///
    /// Refused: a missing `api_audience` or `cli_client_id` setting; a bad signature or an
    /// algorithm other than `RS256` and `ES256`; the wrong `iss`; an `aud` without the API
    /// audience; an expired token, or one with `iat` or `nbf` in the future; no `sub`; a header
    /// `typ` other than `at+jwt` (a plain `JWT` only with `accept_typ_jwt` and the payload
    /// `typ: Bearer`); any token that carries a `nonce`, because only ID tokens do; and a
    /// `client_id` (or `azp` when there is no `client_id`) other than the CLI client, or a `client_id` and an
    /// `azp` that differ.
    pub fn verify_access_token(&self, token: &str) -> Result<AuthenticatedPerson, IdentityError> {
        let (Some(api_audience), Some(cli_client)) = (&self.config.api_audience, &self.config.cli_client_id) else {
            return Err(refused("access tokens are not accepted: no API audience and CLI client are configured"));
        };
        let header_typ = |h: &Json| match h["typ"].as_str() {
            Some(t) if t.eq_ignore_ascii_case("at+jwt") => Ok(()),
            Some("JWT") if self.config.accept_typ_jwt => Ok(()),
            other => Err(refused(format!("access token header type {other:?} is not accepted"))),
        };
        let (header, claims) = self.verify_jws(token, "access token", &header_typ)?;
        if header["typ"].as_str() == Some("JWT") && claims["typ"].as_str() != Some("Bearer") {
            return Err(refused("a JWT header type needs the payload type Bearer"));
        }
        if claims.get("nonce").is_some() {
            return Err(refused("a token with a nonce is an ID token, not an access token"));
        }
        if claims["iss"].as_str() != Some(self.config.issuer.as_str()) {
            return Err(refused("wrong issuer"));
        }
        if !audiences(&claims)?.contains(&api_audience.as_str()) {
            return Err(refused("the token is not for the factory API"));
        }
        self.check_times(&claims, "access token", true)?;
        if claims["sub"].as_str().is_none_or(str::is_empty) {
            return Err(refused("no subject"));
        }
        let client = match (&claims["client_id"], &claims["azp"]) {
            (Json::String(c), Json::Null) | (Json::Null, Json::String(c)) => c,
            (Json::String(c), Json::String(a)) if c == a => c,
            (Json::String(_), Json::String(_)) => return Err(refused("client_id and azp name different clients")),
            (Json::Null, Json::Null) => return Err(refused("the token names no client")),
            _ => return Err(refused("client_id or azp is not a string")),
        };
        if client != cli_client {
            return Err(refused("the token was issued to another client"));
        }
        self.person(&claims)
    }

    /// The account a person with subject `sub` signs in as: `{issuer}|{sub}`. The sign-in and
    /// the operator API's `account_for_subject` both use this, so an assignment made for a
    /// subject lands on the account that person signs in to.
    pub fn account_for_subject(&self, sub: &str) -> AccountId {
        AccountId(format!("{}|{sub}", self.config.issuer))
    }

    /// The subject `account_for_subject` put after the issuer, or `None` for an id built
    /// otherwise. The subject may hold `|`, so the issuer prefix is stripped, not split on.
    pub fn subject_of_account(&self, account: &AccountId) -> Option<String> {
        account.0.strip_prefix(&format!("{}|", self.config.issuer)).map(str::to_owned)
    }

    fn person(&self, claims: &Json) -> Result<AuthenticatedPerson, IdentityError> {
        let amr = strings(claims, "amr")?;
        let acr = match &claims["acr"] {
            Json::Null => None,
            Json::String(a) => Some(a.as_str()),
            _ => return Err(refused("acr is not a string")),
        };
        let role_names = strings(claims, self.config.roles_claim.as_str())?;
        let mut methods = amr.clone();
        if let Some(a) = acr {
            methods.push(format!("acr:{a}"));
        }
        Ok(AuthenticatedPerson {
            account: self.account_for_subject(claims["sub"].as_str().unwrap_or_default()),
            roles: role_names.iter().filter_map(|r| Role::parse(r)).collect(),
            role_names,
            authentication: AuthenticationMethods {
                phishing_resistant: phishing_resistant_with(&amr, acr, &self.config.phishing_resistant_amr, &self.config.phishing_resistant_acr),
                methods,
                assurance: if self.config.asserted_methods { MethodAssurance::Asserted } else { MethodAssurance::FromProvider },
            },
        })
    }
}

/// A claim that is a list of strings, or one space-separated string (the forms providers use
/// for `amr`, `scope` and role claims). Absent is empty; any other shape, or a list holding
/// anything but strings, is refused rather than partly read.
fn strings(claims: &Json, name: &str) -> Result<Vec<String>, IdentityError> {
    match &claims[name] {
        Json::Null => Ok(vec![]),
        Json::String(s) => Ok(s.split_whitespace().map(str::to_owned).collect()),
        Json::Array(a) => a
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or_else(|| refused(format!("{name} lists a non-string"))))
            .collect(),
        _ => Err(refused(format!("{name} is not a list of strings"))),
    }
}

/// The `aud` claim as a list: one string, or a list of strings. Absent is empty.
fn audiences(claims: &Json) -> Result<Vec<&str>, IdentityError> {
    match &claims["aud"] {
        Json::String(a) => Ok(vec![a.as_str()]),
        Json::Array(a) => a.iter().map(|v| v.as_str().ok_or_else(|| refused("aud lists a non-string"))).collect(),
        _ => Ok(vec![]),
    }
}

/// The JOSE header: an object whose `alg` is a string, whose `kid` and `typ` are strings when
/// present, and with no `crit` (RFC 7515 §4.1.11: an extension this adapter does not
/// understand must be refused, and it understands none).
fn check_header(header: &Json) -> Result<(), IdentityError> {
    let Some(h) = header.as_object() else { return Err(refused("header is not an object")) };
    if h.contains_key("crit") {
        return Err(refused("header names critical extensions"));
    }
    for name in ["alg", "kid", "typ"] {
        if h.get(name).is_some_and(|v| !v.is_string()) {
            return Err(refused(format!("header {name} is not a string")));
        }
    }
    Ok(())
}

impl IdentityProvider for OidcIdentityProvider {
    fn start_sign_in(&self, redirect_uri: &str) -> Result<SignInStart, IdentityError> {
        let d = self.discovery()?;
        let (state, nonce, verifier) = (random_b64(16)?, random_b64(16)?, random_b64(32)?);
        let challenge = base64url_encode(sha256(verifier.as_bytes()).as_bytes());
        let mut scope = vec!["openid".to_owned()];
        scope.extend(self.config.scopes.iter().cloned());
        let mut params = vec![
            ("response_type", "code".to_owned()),
            ("client_id", self.config.client_id.clone()),
            ("redirect_uri", redirect_uri.to_owned()),
            ("scope", scope.join(" ")),
            ("state", state.clone()),
            ("nonce", nonce.clone()),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256".to_owned()),
        ];
        if let Some(acr) = &self.config.acr_values {
            params.push(("acr_values", acr.clone()));
        }
        let query: Vec<String> = params.iter().map(|(k, v)| format!("{k}={}", percent_encode(v))).collect();
        let sep = if d.authorization_endpoint.contains('?') { '&' } else { '?' };
        let secret = json!({ "verifier": verifier, "nonce": nonce, "redirect_uri": redirect_uri }).to_string().into_bytes();
        Ok(SignInStart {
            redirect_to: format!("{}{sep}{}", d.authorization_endpoint, query.join("&")),
            pending: PendingSignIn { state, secret },
        })
    }

    fn finish_sign_in(
        &self,
        pending: &PendingSignIn,
        callback: &BTreeMap<String, String>,
    ) -> Result<AuthenticatedPerson, IdentityError> {
        self.finish_sign_in_raw(pending, callback).map(|raw| raw.person)
    }
}

/// A finished sign-in with the raw access token next to the verified person.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RawSignIn {
    /// The person the ID token names, verified as for [`IdentityProvider::finish_sign_in`].
    pub person: AuthenticatedPerson,
    /// The access token as the token endpoint returned it, to be sent as a Bearer token. It
    /// has not been verified here: the API that receives it does that (REG-070a).
    pub access_token: String,
    /// The ID token's `nonce` matched this sign-in's own; a sign-in that returns at all has it.
    pub id_token_nonce_checked: bool,
}

impl OidcIdentityProvider {
    /// Finishes a sign-in like [`IdentityProvider::finish_sign_in`] (same arguments, same
    /// checks on the ID token) and also returns the access token, so that the operator CLI can
    /// call the factory API. The token response must carry one.
    pub fn finish_sign_in_raw(
        &self,
        pending: &PendingSignIn,
        callback: &BTreeMap<String, String>,
    ) -> Result<RawSignIn, IdentityError> {
        if let Some(e) = callback.get("error") {
            return Err(refused(format!("identity provider returned {e}")));
        }
        if callback.get("state") != Some(&pending.state) {
            return Err(refused("state does not match the pending sign-in"));
        }
        if callback.get("iss").is_some_and(|i| *i != self.config.issuer) {
            return Err(refused("callback from another issuer"));
        }
        let code = callback.get("code").ok_or_else(|| refused("no code"))?;
        let secret: Json = serde_json::from_slice(&pending.secret).map_err(|_| refused("bad pending sign-in"))?;
        let closed = secret.as_object().is_some_and(|o| o.len() == 3);
        let (verifier, nonce, redirect_uri) = match (secret["verifier"].as_str(), secret["nonce"].as_str(), secret["redirect_uri"].as_str()) {
            (Some(v), Some(n), Some(r)) if closed => (v, n, r),
            _ => return Err(refused("bad pending sign-in")),
        };
        let d = self.discovery()?;
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri),
            ("client_id", self.config.client_id.as_str()),
            ("code_verifier", verifier),
        ];
        let mut req = self.agent.post(&d.token_endpoint).header("Accept", "application/json");
        if let Some(s) = &self.config.client_secret {
            let basic = format!("{}:{}", percent_encode(&self.config.client_id), percent_encode(s));
            req = req.header("Authorization", &format!("Basic {}", std_base64(basic.as_bytes())));
        }
        let mut r = req.send_form(form).map_err(unavailable)?;
        let status = r.status();
        let body = r.body_mut().with_config().limit(MAX_RESPONSE).read_to_vec().map_err(unavailable)?;
        if !status.is_success() {
            return Err(refused(format!("token endpoint refused the code: HTTP {}", status.as_u16())));
        }
        let tokens: Json = serde_json::from_slice(&body).map_err(|_| unavailable("token response is not JSON"))?;
        let id_token = tokens["id_token"].as_str().ok_or_else(|| refused("no ID token"))?;
        let claims = self.verify_id_token(id_token, nonce)?;
        let access_token = tokens["access_token"].as_str().filter(|t| !t.is_empty()).ok_or_else(|| refused("no access token"))?;
        Ok(RawSignIn { person: self.person(&claims)?, access_token: access_token.to_owned(), id_token_nonce_checked: true })
    }
}

/// Standard base64 with padding, for HTTP Basic credentials.
fn std_base64(input: &[u8]) -> String {
    let mut s = base64url_encode(input).replace('-', "+").replace('_', "/");
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }
    s
}
