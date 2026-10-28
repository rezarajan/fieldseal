//! `fieldseal-factory`: the factory service's composition root (ADR 0028). It reads its
//! configuration from the environment (twelve-factor III, ADR 0025), wires adapters to the
//! Registration use cases and serves the registration API and portal.
//!
//! | Variable | Meaning |
//! |---|---|
//! | `FIELDSEAL_ENVIRONMENT` | `development`, `staging` or `production` (required) |
//! | `FIELDSEAL_FACTORY_BIND` | Address to listen on, for example `127.0.0.1:8080` (required) |
//! | `FIELDSEAL_FACTORY_URL` | The public base URL, written into tokens and checked in PoP tokens (required) |
//! | `FIELDSEAL_IDENTITY` | `oidc`, or `dev` (non-production only) |
//! | `FIELDSEAL_OIDC_ISSUER`, `FIELDSEAL_OIDC_CLIENT_ID` | The OIDC issuer and client (for `oidc`) |
//! | `FIELDSEAL_OIDC_CLIENT_SECRET` | The client secret, for confidential clients |
//! | `FIELDSEAL_OIDC_CLIENT_ID_REF`, `FIELDSEAL_OIDC_CLIENT_SECRET_REF` | Instead of the values: the secret-store reference, resolved at start-up from `FIELDSEAL_SECRET_<REFERENCE>` (reference upper-cased, non-alphanumerics as `_`) |
//! | `FIELDSEAL_OIDC_SCOPES`, `FIELDSEAL_OIDC_ROLES_CLAIM`, `FIELDSEAL_OIDC_ACR_VALUES` | Extra scopes, the roles claim (default `roles`), `acr_values` to request |
//! | `FIELDSEAL_OIDC_PHISHING_RESISTANT_AMR`, `FIELDSEAL_OIDC_PHISHING_RESISTANT_ACR` | Comma-separated extra `amr`/`acr` values this issuer uses to mean phishing-resistant (default none: strict). A token must still carry one (REG-002a) |
//! | `FIELDSEAL_OIDC_ASSERTED_METHODS` | `true` when the issuer is a broker that may alter `amr`/`acr` (REG-002a) |
//! | `FIELDSEAL_DEV_USERS` | For `dev` identity: `login=role+role:amr+amr,…` |
//! | `FIELDSEAL_CUSTODY` | `memory-dev`: keys and a development authority generated in memory, lost on restart (non-production only). `file-dev`: the authority's keys in a key directory and its trust bundle in a file (non-production only) |
//! | `FIELDSEAL_CUSTODY_DIR` | For `file-dev`: the key directory (the `registration` P-256 and X25519 keys, the `record` key) |
//! | `FIELDSEAL_TRUST_BUNDLE` | `memory-dev`: where to write the development trust bundle that devices are provisioned with. `file-dev`: the trust bundle to read (required) |
//! | `FIELDSEAL_STATE_DIR` | A directory for the factory's state (tokens, accounts, tenancies, devices, nonces) as a journal, so a restart keeps registered devices (non-production only). Without it the state is in memory |
//! | `FIELDSEAL_COHORTS` | Cohorts every new tenancy is assigned at registration, `cohort:generation,...` (default none) |
//! | `FIELDSEAL_ALLOW_UNATTESTED` | `true` to accept software keys (non-production only, REG-017) |
//!
//! `fieldseal deployment render` writes exactly these variables from the deployment manifest
//! (DEP-012); the test `dep_012_the_rendered_environment_configures_the_factory` checks that
//! it does.
//!
//! There is no production key-custody adapter yet (HSM or KMS) and no production state store,
//! so a production environment refuses to start rather than run with keys in memory or in
//! files.

use std::time::{SystemTime, UNIX_EPOCH};

use fieldseal_adapters_factory_http::{FactoryHttp, HttpConfig};
use fieldseal_adapters_file::custody::DirCustody;
use fieldseal_adapters_file::store::FileRegistryStore;
use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog};
use fieldseal_adapters_memory::registration::{MemoryIdentityProvider, MemoryReceivedProgress, MemoryRegistryStore, dev_authority};
use fieldseal_adapters_memory::trust::SoftwareAttestationVerifier;
use fieldseal_adapters_oidc::{OidcConfig, OidcIdentityProvider};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::domain::{Controls, EffectivePolicy};
use fieldseal_registration::application::{Factory, FactoryConfig, FactoryPorts};
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::domain::wire::factory_url_ok;
use fieldseal_registration::domain::{CohortAssignment, MethodAssurance, TenancyTerms, Window};
use fieldseal_registration::ports::{IdentityProvider, RegistryStore};
use fieldseal_kernel::crypto::Purpose;
use fieldseal_trust::domain::{AuthorityPublicKey, TrustBundle};
use fieldseal_trust::ports::{AuthorityClock, KeyCustody, RandomSource};

/// The operating system's clock as authority time.
struct SystemClock;

impl AuthorityClock for SystemClock {
    fn now(&self) -> AuthorityTime {
        AuthorityTime(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0))
    }
}

/// The operating system's CSPRNG.
struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("the operating system's random source");
    }
}

/// How people sign in.
#[derive(Debug, PartialEq, Eq)]
enum Identity {
    Oidc(Box<OidcConfig>),
    /// Development users: login, roles, amr.
    Dev(Vec<DevUser>),
}

/// Where the authority's keys come from.
#[derive(Debug, PartialEq, Eq)]
enum Custody {
    /// Generated in memory at start-up.
    MemoryDev,
    /// A key directory and a trust bundle file.
    FileDev {
        /// The key directory.
        dir: String,
    },
}

/// The factory's configuration, from the environment.
#[derive(Debug, PartialEq, Eq)]
struct Config {
    production: bool,
    bind: String,
    public_url: String,
    identity: Identity,
    custody: Custody,
    trust_bundle: Option<String>,
    state_dir: Option<String>,
    cohorts: Vec<CohortAssignment>,
    unattested: UnattestedKeys,
}

/// A development user: login, role names, `amr` values.
type DevUser = (String, Vec<String>, Vec<String>);

/// An unsigned decimal number: digits only, no sign, no whitespace, no leading zero.
fn uint(text: &str, what: &str) -> Result<u64, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) || (text.len() > 1 && text.starts_with('0')) {
        return Err(format!("{what}: `{text}` is not a whole number"));
    }
    text.parse().map_err(|_| format!("{what}: `{text}` is out of range"))
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
    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
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
            other => return Err(format!("FIELDSEAL_ENVIRONMENT={other}: use development, staging or production")),
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
        let cohorts = match opt("FIELDSEAL_COHORTS")? {
            None => Vec::new(),
            Some(text) => entries(&text, ',', "FIELDSEAL_COHORTS")?
                .iter()
                .map(|c| {
                    let (name, generation) = c.split_once(':').ok_or_else(|| format!("FIELDSEAL_COHORTS: `{c}` is not cohort:generation"))?;
                    let generation = u32::try_from(uint(generation, "FIELDSEAL_COHORTS generation")?).map_err(|_| format!("FIELDSEAL_COHORTS: `{c}` has a generation out of range"))?;
                    Ok(CohortAssignment {
                        cohort: fieldseal_kernel::id::CohortId::new(name).map_err(|_| format!("FIELDSEAL_COHORTS: `{c}` has an empty cohort"))?,
                        generation: fieldseal_kernel::id::Generation(generation),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
        };
        if let Some(dup) = cohorts.iter().enumerate().find(|(i, c)| cohorts[..*i].iter().any(|d| d.cohort == c.cohort)) {
            return Err(format!("FIELDSEAL_COHORTS: cohort `{}` is listed twice", dup.1.cohort.as_str()));
        }
        let state_dir = opt("FIELDSEAL_STATE_DIR")?;
        if state_dir.is_some() {
            non_production("FIELDSEAL_STATE_DIR (the file-backed state store is for development)")?;
        }
        let unattested = if flag("FIELDSEAL_ALLOW_UNATTESTED")? {
            non_production("FIELDSEAL_ALLOW_UNATTESTED")?;
            UnattestedKeys::AllowNonProduction
        } else {
            UnattestedKeys::Refuse
        };
        Ok(Self { production, bind, public_url, identity, custody, trust_bundle: opt("FIELDSEAL_TRUST_BUNDLE")?, state_dir, cohorts, unattested })
    }
}

fn main() {
    let config = match Config::from_lookup(|k| std::env::var(k).ok()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fieldseal-factory: {e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(config) {
        eprintln!("fieldseal-factory: {e}");
        std::process::exit(1);
    }
}

/// The authority the factory acts for: where its keys are and what it signs with.
struct Authority {
    custody: Box<dyn KeyCustody>,
    bundle: TrustBundle,
    signing: fieldseal_kernel::id::KeyId,
    sealing: fieldseal_kernel::id::KeyId,
    record: fieldseal_kernel::id::KeyId,
    window: Window,
}

fn load_authority(config: &Config, now: AuthorityTime) -> Result<Authority, String> {
    let default_window = Window { not_before: now, not_after: AuthorityTime(now.0 + 180 * AuthorityTime::DAY), grace_ms: 30 * AuthorityTime::DAY };
    match &config.custody {
        Custody::MemoryDev => {
            let a = dev_authority(OsRandom, now, &["fieldseal-simulator"]).map_err(|e| e.to_string())?;
            if let Some(path) = &config.trust_bundle {
                std::fs::write(path, a.bundle.encode().map_err(|e| e.to_string())?).map_err(|e| format!("{path}: {e}"))?;
                eprintln!("fieldseal-factory: wrote the development trust bundle to {path}");
            }
            Ok(Authority { signing: *a.signing.key_id(), sealing: *a.sealing.key_id(), record: *a.record.key_id(), custody: Box::new(a.custody), bundle: a.bundle, window: default_window })
        }
        Custody::FileDev { dir } => {
            let path = config.trust_bundle.as_deref().ok_or("FIELDSEAL_TRUST_BUNDLE is not set")?;
            let bundle = TrustBundle::decode(&std::fs::read(path).map_err(|e| format!("{path}: {e}"))?).map_err(|e| format!("{path}: {e}"))?;
            let reg = |p256: bool| {
                bundle
                    .certificates()
                    .iter()
                    .find(|c| c.purpose() == Some(Purpose::Registration) && matches!(c.public_key(), AuthorityPublicKey::P256(_)) == p256)
                    .ok_or_else(|| format!("{path}: no registration {} certificate", if p256 { "signing" } else { "sealing" }))
            };
            let (signing, sealing) = (reg(true)?, reg(false)?);
            let mut records = bundle.certificates().iter().filter(|c| c.purpose() == Some(Purpose::Record));
            let record = records.next().ok_or_else(|| format!("{path}: no record key certificate"))?;
            // The tenancy window is the record key's collection period, from now on.
            let window = Window { not_before: AuthorityTime(now.0.max(record.not_before().0)), not_after: record.not_after(), grace_ms: 30 * AuthorityTime::DAY };
            eprintln!("fieldseal-factory: authority from {dir} and {path} (development custody)");
            Ok(Authority { signing: *signing.key_id(), sealing: *sealing.key_id(), record: *record.key_id(), custody: Box::new(DirCustody::new(dir)), bundle, window })
        }
    }
}

fn run(config: Config) -> Result<(), String> {
    let clock = SystemClock;
    let now = clock.now();
    let authority = load_authority(&config, now)?;
    let factory_config = FactoryConfig {
        factory_url: config.public_url.clone(),
        signing_key: authority.signing,
        sealing_key: authority.sealing,
        terms: TenancyTerms { record_key: authority.record, window: authority.window, cohorts: config.cohorts.clone() },
        unattested: config.unattested,
        posture_nonce_ttl_ms: 10 * 60 * 1000,
        access_token_ttl_ms: 10 * 60 * 1000,
    };
    // Schema defaults until policy is loaded from published layers (POL-022).
    let policy = EffectivePolicy { sources: vec![fieldseal_kernel::id::ContentAddress::of(b"schema-defaults")], controls: Controls::defaults() };
    let store: Box<dyn RegistryStore> = match &config.state_dir {
        Some(dir) => {
            eprintln!("fieldseal-factory: state in {dir} (file-backed, development)");
            Box::new(FileRegistryStore::open(dir).map_err(|e| format!("{dir}: {e}"))?)
        }
        None => Box::new(MemoryRegistryStore::new()),
    };
    let (verifier, engine, log, random, progress) = (SoftwareAttestationVerifier, BuiltInPolicyEngine, MemoryDecisionLog::new(), OsRandom, MemoryReceivedProgress::new());
    let idp: Box<dyn IdentityProvider> = match &config.identity {
        Identity::Oidc(c) => Box::new(OidcIdentityProvider::new(c.as_ref().clone()).map_err(|e| e.to_string())?),
        Identity::Dev(users) => {
            let idp = MemoryIdentityProvider::new();
            for (login, roles, amr) in users {
                let roles: Vec<&str> = roles.iter().map(String::as_str).collect();
                let amr: Vec<&str> = amr.iter().map(String::as_str).collect();
                idp.add(login, &format!("dev|{login}"), &roles, &amr, MethodAssurance::FromProvider);
            }
            idp.set_default(users.first().map(|u| u.0.as_str()));
            Box::new(idp)
        }
    };
    let factory = Factory::new(
        FactoryPorts {
            store: store.as_ref(),
            custody: authority.custody.as_ref(),
            verifiers: vec![&verifier],
            engine: &engine,
            log: &log,
            clock: &clock,
            random: &random,
            progress: &progress,
            fleet: None,
            notifier: None,
        },
        &authority.bundle,
        &policy,
        &factory_config,
    )
    .map_err(|e| e.to_string())?;
    let http = FactoryHttp::new(&factory, idp.as_ref(), HttpConfig { public_url: config.public_url.clone(), session_ttl_ms: 8 * 3600 * 1000 });
    let server = tiny_http::Server::http(&config.bind).map_err(|e| format!("{}: {e}", config.bind))?;
    eprintln!("fieldseal-factory: listening on {} as {} (production: {})", config.bind, config.public_url, config.production);
    http.run(&server);
    Ok(())
}

