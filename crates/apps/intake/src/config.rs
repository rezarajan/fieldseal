//! The intake app's configuration: environment only, strict (twelve-factor III, Technical
//! Plan 7.6). A set variable is non-empty and trimmed, a flag is `true` or `false`, and
//! unusable configuration is exit `2`.

use std::path::PathBuf;

use fieldseal_adapters_oidc::OidcConfig;

/// How people sign in to the results reader.
#[derive(Debug, PartialEq, Eq)]
pub enum Identity {
    /// An OpenID Connect provider.
    Oidc(Box<OidcConfig>),
    /// A fixed development login and no identity provider (non-production only).
    Dev,
}

/// Where the authority's keys come from.
#[derive(Debug, PartialEq, Eq)]
pub enum Custody {
    /// A development authority in memory, with fixed seeds: lost with the process, the same
    /// on every start (non-production only).
    MemoryDev,
    /// A key directory and a trust bundle file (non-production only).
    FileDev {
        /// The key directory.
        dir: String,
    },
}

/// The intake app's configuration.
#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    /// `FIELDSEAL_ENVIRONMENT` is `production`.
    pub production: bool,
    /// The upload listener (devices).
    pub bind: String,
    /// Base URLs device tokens may be bound to; empty means the bind address.
    pub public_urls: Vec<String>,
    /// The largest upload body.
    pub max_body: Option<usize>,
    /// The portal listener (authority staff).
    pub portal_bind: String,
    /// The portal's public base URL.
    pub portal_url: String,
    /// How people sign in.
    pub identity: Identity,
    /// The role that may read results.
    pub reader_role: String,
    /// Where the authority's keys come from.
    pub custody: Custody,
    /// The trust bundle file (read for `file-dev`, written for `memory-dev` when set).
    pub trust_bundle: Option<String>,
    /// The factory's state directory, read-only.
    pub tenancy_dir: PathBuf,
    /// Landing files.
    pub landing_dir: PathBuf,
    /// Accepted submissions, for start-up replay; without it they are kept in memory.
    pub submissions_dir: Option<PathBuf>,
    /// Published instruments.
    pub published_dir: PathBuf,
    /// Issued rosters; without it the history is in memory.
    pub rosters_dir: Option<PathBuf>,
    /// The publishing policy's allowed builders.
    pub allowed_builders: Vec<String>,
    /// The publishing policy's allowed sources.
    pub allowed_sources: Vec<String>,
    /// The directory that holds `export.key`.
    pub export_key_dir: PathBuf,
}

/// A comma-separated list in which every entry is non-empty, trimmed and unique.
fn entries(text: &str, sep: char, what: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for e in text.split(sep) {
        if e.is_empty() || e != e.trim() {
            return Err(format!("{what}: an entry is empty or has surrounding whitespace in `{text}`"));
        }
        if out.iter().any(|x| x == e) {
            return Err(format!("{what}: `{e}` is listed twice"));
        }
        out.push(e.to_owned());
    }
    Ok(out)
}

/// A value that may be given directly (`NAME`) or by secret-store reference (`NAME_REF`),
/// the reference resolving to `FIELDSEAL_SECRET_<REFERENCE>` (DEP-012).
fn secret(get: &impl Fn(&str) -> Option<String>, name: &str) -> Result<Option<String>, String> {
    if let Some(v) = get(name).filter(|v| !v.is_empty()) {
        return Ok(Some(v));
    }
    let Some(reference) = get(&format!("{name}_REF")).filter(|v| !v.is_empty()) else { return Ok(None) };
    let var = format!("FIELDSEAL_SECRET_{}", reference.to_ascii_uppercase().replace(|c: char| !c.is_ascii_alphanumeric(), "_"));
    get(&var).filter(|v| !v.is_empty()).map(Some).ok_or_else(|| format!("{name}_REF={reference}: {var} is not set"))
}

impl Config {
    /// Reads the configuration through `get`, which looks a variable up.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let opt = |k: &str| -> Result<Option<String>, String> {
            match get(k) {
                None => Ok(None),
                Some(v) if v.is_empty() || v != v.trim() => Err(format!("{k} is set but empty or has surrounding whitespace")),
                Some(v) => Ok(Some(v)),
            }
        };
        let need = |k: &str| opt(k)?.ok_or_else(|| format!("{k} must be set"));
        let flag = |k: &str| -> Result<bool, String> {
            match opt(k)?.as_deref() {
                None | Some("false") => Ok(false),
                Some("true") => Ok(true),
                Some(other) => Err(format!("{k}={other}: use true or false")),
            }
        };
        let production = match need("FIELDSEAL_ENVIRONMENT")?.as_str() {
            "production" => true,
            "development" | "staging" | "test" => false,
            other => return Err(format!("FIELDSEAL_ENVIRONMENT={other}: use development, staging or production")),
        };
        let addr = |k: &str, default: &str| -> Result<String, String> {
            let v = opt(k)?.unwrap_or_else(|| default.to_owned());
            v.parse::<std::net::SocketAddr>().map_err(|_| format!("{k}={v}: expected ip:port, for example {default}"))?;
            Ok(v)
        };
        let bind = addr("FIELDSEAL_INTAKE_BIND", "0.0.0.0:8480")?;
        let portal_bind = addr("FIELDSEAL_INTAKE_PORTAL_BIND", "127.0.0.1:8481")?;
        let portal_url = need("FIELDSEAL_INTAKE_PORTAL_URL")?;
        if !(portal_url.starts_with("https://") || portal_url.starts_with("http://")) {
            return Err("FIELDSEAL_INTAKE_PORTAL_URL must be an http or https URL".into());
        }
        let public_urls = opt("FIELDSEAL_INTAKE_PUBLIC_URLS")?.map(|s| entries(&s, ',', "FIELDSEAL_INTAKE_PUBLIC_URLS")).transpose()?.unwrap_or_default();
        let max_body = opt("FIELDSEAL_INTAKE_MAX_BODY")?
            .map(|v| v.parse::<usize>().ok().filter(|n| *n > 0 && !v.starts_with('0')).ok_or_else(|| format!("FIELDSEAL_INTAKE_MAX_BODY={v}: expected a positive whole number")))
            .transpose()?;
        let identity = match need("FIELDSEAL_IDENTITY")?.as_str() {
            "oidc" => {
                let mut c = OidcConfig::new(need("FIELDSEAL_OIDC_ISSUER")?, secret(&get, "FIELDSEAL_OIDC_CLIENT_ID")?.ok_or("FIELDSEAL_OIDC_CLIENT_ID must be set")?);
                c.client_secret = secret(&get, "FIELDSEAL_OIDC_CLIENT_SECRET")?;
                c.scopes = opt("FIELDSEAL_OIDC_SCOPES")?.map(|s| entries(&s, ' ', "FIELDSEAL_OIDC_SCOPES")).transpose()?.unwrap_or_default();
                if let Some(r) = opt("FIELDSEAL_OIDC_ROLES_CLAIM")? {
                    c.roles_claim = r;
                }
                c.acr_values = opt("FIELDSEAL_OIDC_ACR_VALUES")?;
                let list = |k: &str| -> Result<Vec<String>, String> { opt(k)?.map(|s| entries(&s, ',', k)).transpose().map(Option::unwrap_or_default) };
                c.phishing_resistant_amr = list("FIELDSEAL_OIDC_PHISHING_RESISTANT_AMR")?;
                c.phishing_resistant_acr = list("FIELDSEAL_OIDC_PHISHING_RESISTANT_ACR")?;
                c.asserted_methods = flag("FIELDSEAL_OIDC_ASSERTED_METHODS")?;
                Identity::Oidc(Box::new(c))
            }
            "dev" => Identity::Dev,
            other => return Err(format!("FIELDSEAL_IDENTITY={other}: use oidc or dev")),
        };
        let custody = match need("FIELDSEAL_CUSTODY")?.as_str() {
            "memory-dev" => Custody::MemoryDev,
            "file-dev" => {
                if opt("FIELDSEAL_TRUST_BUNDLE")?.is_none() {
                    return Err("FIELDSEAL_TRUST_BUNDLE must be set to the trust bundle file for FIELDSEAL_CUSTODY=file-dev".into());
                }
                Custody::FileDev { dir: need("FIELDSEAL_CUSTODY_DIR")? }
            }
            other => return Err(format!("FIELDSEAL_CUSTODY={other}: use memory-dev or file-dev")),
        };
        let list = |k: &str| -> Result<Vec<String>, String> { opt(k)?.map(|s| entries(&s, ',', k)).transpose().map(Option::unwrap_or_default) };
        Ok(Self {
            production,
            bind,
            public_urls,
            max_body,
            portal_bind,
            portal_url,
            identity,
            reader_role: opt("FIELDSEAL_INTAKE_READER_ROLE")?.unwrap_or_else(|| "results-reader".into()),
            custody,
            trust_bundle: opt("FIELDSEAL_TRUST_BUNDLE")?,
            tenancy_dir: need("FIELDSEAL_TENANCY_DIR")?.into(),
            landing_dir: need("FIELDSEAL_LANDING_DIR")?.into(),
            submissions_dir: opt("FIELDSEAL_INTAKE_SUBMISSIONS_DIR")?.map(Into::into),
            published_dir: need("FIELDSEAL_INTAKE_PUBLISHED_DIR")?.into(),
            rosters_dir: opt("FIELDSEAL_INTAKE_ROSTERS_DIR")?.map(Into::into),
            allowed_builders: list("FIELDSEAL_INTAKE_ALLOWED_BUILDERS")?,
            allowed_sources: list("FIELDSEAL_INTAKE_ALLOWED_SOURCES")?,
            export_key_dir: need("FIELDSEAL_EXPORT_KEY_DIR")?.into(),
        })
    }

    /// The publishing policy that instruments are verified under: the defaults with the
    /// configured builders and sources. The CLI's `fieldseal intake results` builds the same
    /// policy from the same two lists when it is given the stack's values.
    pub fn publishing_policy(&self) -> fieldseal_policy::domain::PublishingPolicy {
        let mut p = fieldseal_policy::domain::Controls::defaults().publishing();
        p.allowed_builders = self.allowed_builders.clone();
        p.allowed_sources = self.allowed_sources.clone();
        p
    }
}
