//! The factory's configuration, from the environment only (twelve-factor III, ADR 0025). A
//! set variable is non-empty and trimmed, a flag is exactly `true` or `false`, and anything
//! unusable is refused with a message (the binary exits `2`). The variables are listed in the
//! crate's README and in Technical Plan section 7.6; `fieldseal deployment render` writes
//! them from the deployment manifest (DEP-012).

use fieldseal_adapters_oidc::OidcConfig;
use fieldseal_kernel::id::ContentAddress;
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::domain::wire::factory_url_ok;

/// How people sign in.
#[derive(Debug, PartialEq, Eq)]
pub enum Identity {
    /// An OpenID Connect issuer.
    Oidc(Box<OidcConfig>),
    /// Development users: login, roles, amr.
    Dev(Vec<DevUser>),
}

/// Where the authority's keys come from.
#[derive(Debug, PartialEq, Eq)]
pub enum Custody {
    /// Generated in memory at start-up.
    MemoryDev,
    /// A key directory and a trust bundle file.
    FileDev {
        /// The key directory.
        dir: String,
    },
}

/// What the factory trusts to verify the release policy (`deployment-policy`) before it reads
/// a value from it. The policy is itself a publication, so it cannot be verified under the
/// publishing policy it carries: a publisher key could publish a policy that lowers its own
/// threshold.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PolicyTrust {
    /// Staging and production: the one policy whose content address the operator pinned.
    /// Any other policy is refused.
    Pinned(ContentAddress),
    /// Development: a policy is accepted when it verifies under the schema defaults with
    /// these builders and sources.
    Allowlists {
        /// Builder identities whose provenance is accepted.
        builders: Vec<String>,
        /// Source repositories whose revisions may be published.
        sources: Vec<String>,
    },
}

/// The factory's configuration, from the environment.
#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    /// Whether the environment is `production`, which refuses every development adapter.
    pub production: bool,
    /// What the release policy is verified against.
    pub policy_trust: PolicyTrust,
    /// The address to listen on.
    pub bind: String,
    /// The public base URL.
    pub public_url: String,
    /// How people sign in.
    pub identity: Identity,
    /// Where the authority's keys come from.
    pub custody: Custody,
    /// The trust bundle file, if one is named.
    pub trust_bundle: Option<String>,
    /// The tenancy registry journal directory, which the runtime profiles and roster source read.
    pub state_dir: String,
    /// The artefact registry directory.
    pub registry_dir: String,
    /// The roster store.
    pub roster_dir: String,
    /// Where the stored bundles are kept, one directory per tenancy.
    pub bundle_dir: String,
    /// Where the issued rosters are recorded for intake.
    pub issued_rosters_dir: String,
    /// Seconds between scans of the artefact registry directory.
    pub build_interval_s: u64,
    /// A stored bundle whose anchor is older than this many seconds is rebuilt.
    pub max_anchor_age_s: u64,
    /// Whether unattested keys may register.
    pub unattested: UnattestedKeys,
}

/// A development user: login, role names, `amr` values.
pub type DevUser = (String, Vec<String>, Vec<String>);

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

fn parse_dev_users(spec: &str) -> Result<Vec<DevUser>, String> {
    let mut seen: Vec<&str> = Vec::new();
    entries(spec, ',', "FIELDSEAL_DEV_USERS")?
        .iter()
        .map(|entry| {
            let (login, rest) = entry.split_once('=').ok_or_else(|| format!("FIELDSEAL_DEV_USERS: `{entry}` is not login=roles:amr"))?;
            if login.is_empty() || seen.contains(&login) {
                return Err(format!("FIELDSEAL_DEV_USERS: `{entry}` has an empty or repeated login"));
            }
            seen.push(Box::leak(login.to_owned().into_boxed_str()));
            let (roles, amr) = rest.split_once(':').unwrap_or((rest, ""));
            let split = |s: &str| if s.is_empty() { Ok(Vec::new()) } else { entries(s, '+', "FIELDSEAL_DEV_USERS") };
            Ok((login.to_owned(), split(roles)?, split(amr)?))
        })
        .collect()
}

/// A value that may be given directly (`NAME`) or by secret-store reference (`NAME_REF`),
/// the reference resolving to `FIELDSEAL_SECRET_<REFERENCE>` in the environment the platform
/// injects at run time (DEP-012).
fn secret(get: &impl Fn(&str) -> Option<String>, name: &str) -> Result<Option<String>, String> {
    if let Some(v) = get(name).filter(|v| !v.is_empty()) {
        return Ok(Some(v));
    }
    let Some(reference) = get(&format!("{name}_REF")).filter(|v| !v.is_empty()) else { return Ok(None) };
    let var = format!("FIELDSEAL_SECRET_{}", reference.to_ascii_uppercase().replace(|c: char| !c.is_ascii_alphanumeric(), "_"));
    get(&var).filter(|v| !v.is_empty()).map(Some).ok_or_else(|| format!("{name}_REF={reference}: {var} is not set"))
}

impl Config {
    /// The configuration in the environment `get` reads, or what is wrong with it.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        // Strict (twelve-factor III): a variable that is set must hold a value, with no
        // surrounding whitespace; a flag is exactly `true` or `false`.
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
        let environment = need("FIELDSEAL_ENVIRONMENT")?;
        let production = match environment.as_str() {
            "production" => true,
            "development" | "staging" | "test" => false,
            other => return Err(format!("FIELDSEAL_ENVIRONMENT={other}: use development, staging, test or production")),
        };
        let non_production = |what: &str| if production { Err(format!("{what} is not allowed in production")) } else { Ok(()) };
        let bind = need("FIELDSEAL_FACTORY_BIND")?;
        bind.parse::<std::net::SocketAddr>().map_err(|_| format!("FIELDSEAL_FACTORY_BIND={bind}: expected ip:port, for example 0.0.0.0:8080"))?;
        let public_url = need("FIELDSEAL_FACTORY_URL")?;
        if !factory_url_ok(&public_url) {
            return Err("FIELDSEAL_FACTORY_URL must be an https URL (http only for a loopback host), at most 256 bytes".into());
        }
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
                c.api_audience = opt("FIELDSEAL_OIDC_API_AUDIENCE")?;
                c.cli_client_id = opt("FIELDSEAL_OIDC_CLI_CLIENT_ID")?;
                c.accept_typ_jwt = flag("FIELDSEAL_OIDC_ACCEPT_TYP_JWT")?;
                Identity::Oidc(Box::new(c))
            }
            "dev" => {
                non_production("FIELDSEAL_IDENTITY=dev")?;
                Identity::Dev(parse_dev_users(&need("FIELDSEAL_DEV_USERS")?)?)
            }
            other => return Err(format!("FIELDSEAL_IDENTITY={other}: use oidc or dev")),
        };
        let custody = match need("FIELDSEAL_CUSTODY")?.as_str() {
            "memory-dev" => {
                non_production("FIELDSEAL_CUSTODY=memory-dev (no production custody adapter exists yet)")?;
                Custody::MemoryDev
            }
            "file-dev" => {
                non_production("FIELDSEAL_CUSTODY=file-dev (no production custody adapter exists yet)")?;
                if opt("FIELDSEAL_TRUST_BUNDLE")?.is_none() {
                    return Err("FIELDSEAL_TRUST_BUNDLE must be set to the trust bundle file for FIELDSEAL_CUSTODY=file-dev".into());
                }
                Custody::FileDev { dir: need("FIELDSEAL_CUSTODY_DIR")? }
            }
            other => return Err(format!("FIELDSEAL_CUSTODY={other}: use memory-dev or file-dev")),
        };
        // The runtime profiles and the roster source read the tenancy registry journal, so the
        // journal is required; it is a file store and there is no production one yet.
        let state_dir = need("FIELDSEAL_STATE_DIR")?;
        non_production("FIELDSEAL_STATE_DIR (the file-backed state store is for development)")?;
        // The operator API reads the artefact registry and writes the roster store, and the
        // reconciler builds from them and stores bundles. All are file adapters, and there is
        // no production adapter for any of them yet.
        let registry_dir = need("FIELDSEAL_FACTORY_REGISTRY_DIR")?;
        non_production("FIELDSEAL_FACTORY_REGISTRY_DIR (the file artefact registry)")?;
        let roster_dir = need("FIELDSEAL_ROSTER_DIR")?;
        non_production("FIELDSEAL_ROSTER_DIR (the file roster store)")?;
        let bundle_dir = need("FIELDSEAL_BUNDLE_DIR")?;
        non_production("FIELDSEAL_BUNDLE_DIR (the file bundle store)")?;
        let issued_rosters_dir = need("FIELDSEAL_ISSUED_ROSTERS_DIR")?;
        non_production("FIELDSEAL_ISSUED_ROSTERS_DIR (the file store of issued rosters)")?;
        // Whole seconds within a range; a value outside it is a configuration error (exit 2).
        let seconds = |k: &str, default: u64, min: u64, max: u64| -> Result<u64, String> {
            match opt(k)? {
                None => Ok(default),
                Some(v) => v.parse::<u64>().ok().filter(|n| (min..=max).contains(n)).ok_or_else(|| format!("{k}={v}: use a whole number of seconds from {min} to {max}")),
            }
        };
        let build_interval_s = seconds("FIELDSEAL_FACTORY_BUILD_INTERVAL_S", if environment == "development" { 5 } else { 60 }, 1, 3600)?;
        let max_anchor_age_s = seconds("FIELDSEAL_FACTORY_MAX_ANCHOR_AGE_S", 86_400, 60, 604_800)?;
        let unattested = if flag("FIELDSEAL_ALLOW_UNATTESTED")? {
            non_production("FIELDSEAL_ALLOW_UNATTESTED")?;
            UnattestedKeys::AllowNonProduction
        } else {
            UnattestedKeys::Refuse
        };
        // Outside development the release policy must be the one the operator pinned; in
        // development it is verified under the defaults with the configured allow-lists.
        let list = |k: &str| -> Result<Vec<String>, String> { opt(k)?.map(|s| entries(&s, ',', k)).transpose().map(Option::unwrap_or_default) };
        let pinned = opt("FIELDSEAL_FACTORY_POLICY_DIGEST")?
            .map(|d| ContentAddress::parse_text(&d).map_err(|_| format!("FIELDSEAL_FACTORY_POLICY_DIGEST={d}: expected sha256: and 64 lowercase hex digits")))
            .transpose()?;
        let policy_trust = match pinned {
            Some(address) => PolicyTrust::Pinned(address),
            None if matches!(environment.as_str(), "staging" | "production") => {
                return Err("FIELDSEAL_FACTORY_POLICY_DIGEST must be set outside development: the release policy is the one published at that content address".into());
            }
            None => PolicyTrust::Allowlists { builders: list("FIELDSEAL_FACTORY_ALLOWED_BUILDERS")?, sources: list("FIELDSEAL_FACTORY_ALLOWED_SOURCES")? },
        };
        Ok(Self {
            production,
            policy_trust,
            bind,
            public_url,
            identity,
            custody,
            trust_bundle: opt("FIELDSEAL_TRUST_BUNDLE")?,
            state_dir,
            registry_dir,
            roster_dir,
            bundle_dir,
            issued_rosters_dir,
            build_interval_s,
            max_anchor_age_s,
            unattested,
        })
    }
}
