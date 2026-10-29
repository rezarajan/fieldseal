//! ES256 signing with a key generated at start, and the two tokens the provider issues.
//!
//! The ID token says who signed in to a client: `aud` is the client and it carries the
//! sign-in's `nonce`. The access token says what a client may call: `aud` is the API
//! audience, the header type is `at+jwt` (RFC 9068), it names the client in `client_id`, and
//! it never carries a `nonce` or the client as its audience. Both carry `roles`, `acr` and
//! `amr`; a verifier reads them from the access token alone.

use std::time::{SystemTime, UNIX_EPOCH};

use fieldseal_kernel::base64url::base64url_encode;
use fieldseal_kernel::digest::sha256;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};

use crate::config::Login;

/// How long a token is valid, in seconds (the Keycloak realm's access-token lifetime).
pub const LIFETIME: u64 = 300;

/// Random bytes as base64url text.
pub fn random_b64(len: usize) -> String {
    let mut b = vec![0u8; len];
    getrandom::getrandom(&mut b).expect("the operating system has randomness");
    base64url_encode(&b)
}

/// The seconds since the Unix epoch.
pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The signing key and its key id.
pub struct Signer {
    key: SigningKey,
    kid: String,
}

impl Signer {
    /// A new key from the operating system's randomness. It lives as long as the process, so
    /// tokens from an earlier run no longer verify.
    pub fn generate() -> Self {
        let key = loop {
            let mut scalar = [0u8; 32];
            getrandom::getrandom(&mut scalar).expect("the operating system has randomness");
            if let Ok(k) = SigningKey::from_slice(&scalar) {
                break k;
            }
        };
        let point = key.verifying_key().to_sec1_point(false);
        let kid = base64url_encode(&sha256(point.as_bytes()).as_bytes()[..12]);
        Self { key, kid }
    }

    /// The public key as the JWK in the key set.
    pub fn jwk(&self) -> Value {
        let point = self.key.verifying_key().to_sec1_point(false);
        let (x, y) = (point.x().expect("an uncompressed point"), point.y().expect("an uncompressed point"));
        json!({ "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": self.kid, "x": base64url_encode(x), "y": base64url_encode(y) })
    }

    fn sign(&self, typ: &str, claims: &Value) -> String {
        let header = json!({ "alg": "ES256", "typ": typ, "kid": self.kid });
        let input = format!("{}.{}", base64url_encode(header.to_string().as_bytes()), base64url_encode(claims.to_string().as_bytes()));
        let sig: Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", base64url_encode(&sig.to_bytes()))
    }

    /// The ID token of a sign-in at `client`. `nonce` is the one the client asked with.
    pub fn id_token(&self, issuer: &str, client: &str, login: &Login, nonce: Option<&str>) -> String {
        let iat = now();
        let mut claims = json!({
            "iss": issuer, "aud": client, "azp": client, "sub": login.subject, "typ": "ID",
            "roles": login.roles, "amr": login.amr, "acr": login.acr,
            "auth_time": iat, "iat": iat, "exp": iat + LIFETIME,
        });
        if let Some(n) = nonce {
            claims["nonce"] = json!(n);
        }
        self.sign("JWT", &claims)
    }

    /// The access token for the API `audience`, issued to `client`. It has no `nonce`.
    pub fn access_token(&self, issuer: &str, audience: &str, client: &str, login: &Login, scope: &str) -> String {
        let iat = now();
        let claims = json!({
            "iss": issuer, "sub": login.subject, "aud": audience, "client_id": client, "scope": scope,
            "jti": random_b64(16), "roles": login.roles, "amr": login.amr, "acr": login.acr,
            "iat": iat, "exp": iat + LIFETIME,
        });
        self.sign("at+jwt", &claims)
    }
}
