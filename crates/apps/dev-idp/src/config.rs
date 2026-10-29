//! The development IdP's configuration file (`examples/deployments/dev-idp.yaml`): the API
//! audience, the logins and the clients. Strict like the other configuration: an unknown key,
//! a wrong type or a missing secret is an error that names where.
//!
//! ```yaml
//! apiAudience: fieldseal-factory-api
//! logins:
//!   - { login: presenter, subject: <uuid>, roles: [operator], amr: [hwk], acr: phr }
//! clients:
//!   - { id: fieldseal-factory, secretRef: factory-oidc-client-secret, redirectUris: [http://localhost:8080/sign-in/callback] }
//!   - { id: fieldseal-cli, public: true }
//! ```
//!
//! A confidential client names its secret by reference. The value is read at start-up from
//! `FIELDSEAL_SECRET_<REFERENCE>` (reference upper-cased, non-alphanumerics as `_`), as the
//! factory resolves its own (DEP-012). The file never holds a secret.

use std::collections::BTreeMap;

use fieldseal_adapters_authoring::{Format, Value, decode_raw};

/// One person who can sign in.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Login {
    /// The name the login page shows and `login_hint` selects.
    pub login: String,
    /// The fixed `sub` of this login.
    pub subject: String,
    /// The `roles` claim.
    pub roles: Vec<String>,
    /// The `amr` claim.
    pub amr: Vec<String>,
    /// The `acr` claim.
    pub acr: String,
}

/// One registered client.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Client {
    /// The client id.
    pub id: String,
    /// The secret of a confidential client; `None` for a public client.
    pub secret: Option<String>,
    /// Redirect URIs, matched exactly. A public client may also use a loopback redirect on
    /// any port (RFC 8252 section 7.3).
    pub redirect_uris: Vec<String>,
}

impl Client {
    /// Whether the client has no secret.
    pub fn is_public(&self) -> bool {
        self.secret.is_none()
    }
}

/// The whole configuration.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Config {
    /// The audience of every access token.
    pub api_audience: String,
    /// The logins, in the order the login page lists them.
    pub logins: Vec<Login>,
    /// The clients.
    pub clients: Vec<Client>,
}

/// The environment variable that holds the secret a reference names.
pub fn secret_variable(reference: &str) -> String {
    format!("FIELDSEAL_SECRET_{}", reference.to_ascii_uppercase().replace(|c: char| !c.is_ascii_alphanumeric(), "_"))
}

fn map<'a>(v: &'a Value, at: &str, allowed: &[&str]) -> Result<&'a BTreeMap<String, Value>, String> {
    let m = v.as_map().ok_or_else(|| format!("{at}: expected a map, found {}", v.kind()))?;
    if let Some(unknown) = m.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("{at}: unknown key `{unknown}`"));
    }
    Ok(m)
}

fn text(m: &BTreeMap<String, Value>, key: &str, at: &str) -> Result<String, String> {
    match m.get(key) {
        Some(Value::Text(t)) if !t.is_empty() && t == t.trim() => Ok(t.clone()),
        Some(_) => Err(format!("{at}.{key}: expected non-empty text with no surrounding whitespace")),
        None => Err(format!("{at}.{key}: missing")),
    }
}

fn texts(m: &BTreeMap<String, Value>, key: &str, at: &str) -> Result<Vec<String>, String> {
    let Some(v) = m.get(key) else { return Ok(vec![]) };
    v.as_array()
        .and_then(|a| a.iter().map(|e| e.as_text().filter(|t| !t.is_empty()).map(str::to_owned)).collect())
        .ok_or_else(|| format!("{at}.{key}: expected a list of non-empty text"))
}

fn list<'a>(m: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a [Value], String> {
    m.get(key).and_then(Value::as_array).filter(|a| !a.is_empty()).ok_or_else(|| format!("{key}: expected a non-empty list"))
}

impl Config {
    /// Reads the configuration from the text of the file; `get` reads the environment.
    pub fn parse(file: &str, get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let doc = decode_raw(file.as_bytes(), Format::Yaml).map_err(|e| e.to_string())?;
        let top = map(&doc, "the file", &["apiAudience", "logins", "clients"])?;
        let api_audience = text(top, "apiAudience", "the file")?;
        let mut logins: Vec<Login> = vec![];
        for (i, v) in list(top, "logins")?.iter().enumerate() {
            let at = format!("logins[{i}]");
            let m = map(v, &at, &["login", "subject", "roles", "amr", "acr"])?;
            let login = Login {
                login: text(m, "login", &at)?,
                subject: text(m, "subject", &at)?,
                roles: texts(m, "roles", &at)?,
                amr: texts(m, "amr", &at)?,
                acr: text(m, "acr", &at)?,
            };
            if logins.iter().any(|l| l.login == login.login || l.subject == login.subject) {
                return Err(format!("{at}: login or subject is listed twice"));
            }
            logins.push(login);
        }
        let mut clients: Vec<Client> = vec![];
        for (i, v) in list(top, "clients")?.iter().enumerate() {
            let at = format!("clients[{i}]");
            let m = map(v, &at, &["id", "public", "secretRef", "redirectUris"])?;
            let id = text(m, "id", &at)?;
            let public = match m.get("public") {
                None => false,
                Some(Value::Bool(b)) => *b,
                Some(_) => return Err(format!("{at}.public: expected true or false")),
            };
            let secret = match (public, m.get("secretRef")) {
                (true, None) => None,
                (true, Some(_)) => return Err(format!("{at}: a public client has no secretRef")),
                (false, None) => return Err(format!("{at}: a confidential client needs a secretRef (or public: true)")),
                (false, Some(_)) => {
                    let reference = text(m, "secretRef", &at)?;
                    let var = secret_variable(&reference);
                    Some(get(&var).filter(|v| !v.is_empty()).ok_or_else(|| format!("{at}.secretRef={reference}: {var} is not set"))?)
                }
            };
            if clients.iter().any(|c| c.id == id) {
                return Err(format!("{at}: client `{id}` is listed twice"));
            }
            clients.push(Client { id, secret, redirect_uris: texts(m, "redirectUris", &at)? });
        }
        Ok(Self { api_audience, logins, clients })
    }
}
