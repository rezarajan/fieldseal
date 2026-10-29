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
//! | `FIELDSEAL_OIDC_API_AUDIENCE`, `FIELDSEAL_OIDC_CLI_CLIENT_ID` | The audience of the access tokens of the operator API and the public client that may call it. Without both, no access token is accepted (REG-070a) |
//! | `FIELDSEAL_OIDC_ACCEPT_TYP_JWT` | `true` to accept an access token whose header type is a plain `JWT` (Keycloak's), with the payload type `Bearer` (default `false`) |
//! | `FIELDSEAL_FACTORY_REGISTRY_DIR` | The artefact registry directory `artefact publish` writes, read by the survey lookup of `AssignCohort` (required; a development adapter) |
//! | `FIELDSEAL_ROSTER_DIR` | The roster store: `IssueRoster` writes it and `AssignCohort` checks cohorts against it (required; a development adapter; owner-only permissions) |
//! | `FIELDSEAL_DEV_USERS` | For `dev` identity: `login=role+role:amr+amr,…` |
//! | `FIELDSEAL_CUSTODY` | `memory-dev`: keys and a development authority generated in memory, lost on restart (non-production only). `file-dev`: the authority's keys in a key directory and its trust bundle in a file (non-production only) |
//! | `FIELDSEAL_CUSTODY_DIR` | For `file-dev`: the key directory (the `registration` P-256 and X25519 keys, the `record` key) |
//! | `FIELDSEAL_TRUST_BUNDLE` | `memory-dev`: where to write the development trust bundle that devices are provisioned with. `file-dev`: the trust bundle to read (required) |
//! | `FIELDSEAL_STATE_DIR` | A directory for the factory's state (tokens, accounts, tenancies, devices, nonces) as a journal, so a restart keeps registered devices (non-production only). Without it the state is in memory |
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

use fieldseal_adapters_factory_http::{BearerError, BearerVerifier, FactoryHttp, HttpConfig, OperatorEvent, OperatorEvents, no_reconcile};
use fieldseal_adapters_file::custody::DirCustody;
use fieldseal_adapters_file::directories::{PublishedSurveys, StoredCohorts};
use fieldseal_adapters_file::registry::FileRegistry;
use fieldseal_adapters_file::roster_issuer::FileRosterIssuer;
use fieldseal_adapters_file::roster_store::RosterStore;
use fieldseal_adapters_file::store::FileRegistryStore;
use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog};
use fieldseal_adapters_memory::registration::{MemoryIdentityProvider, MemoryReceivedProgress, MemoryRegistryStore, dev_authority};
use fieldseal_adapters_memory::trust::SoftwareAttestationVerifier;
use fieldseal_deployment::events::development_adapters_event;
use fieldseal_adapters_oidc::{OidcConfig, OidcIdentityProvider};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::domain::{Controls, EffectivePolicy};
use fieldseal_registration::application::{Factory, FactoryConfig, FactoryPorts, OperatorPorts};
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::domain::wire::factory_url_ok;
use fieldseal_registration::domain::{MethodAssurance, TenancyTerms, Window};
use fieldseal_registration::ports::{IdentityError, IdentityProvider, PendingSignIn, RegistryStore, SignInStart};
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

/// The OIDC adapter, shared by the portal's sign-in and the operator API's Bearer check, so
/// the two read one key set and one configuration.
#[derive(Clone)]
struct SharedOidc(std::sync::Arc<OidcIdentityProvider>);

impl IdentityProvider for SharedOidc {
    fn start_sign_in(&self, redirect_uri: &str) -> Result<SignInStart, IdentityError> {
        self.0.start_sign_in(redirect_uri)
    }

    fn finish_sign_in(&self, pending: &PendingSignIn, callback: &std::collections::BTreeMap<String, String>) -> Result<fieldseal_registration::domain::AuthenticatedPerson, IdentityError> {
        self.0.finish_sign_in(pending, callback)
    }
}

impl BearerVerifier for SharedOidc {
    fn account_for_subject(&self, sub: &str) -> fieldseal_registration::domain::AccountId {
        self.0.account_for_subject(sub)
    }

    fn subject_of_account(&self, account: &fieldseal_registration::domain::AccountId) -> Option<String> {
        self.0.subject_of_account(account)
    }

    fn verify(&self, token: &str) -> Result<fieldseal_registration::domain::AuthenticatedPerson, BearerError> {
        self.0.verify_access_token(token).map_err(|e| match e {
            IdentityError::NotAuthenticated(reason) => {
                // The reason names the check that failed and never holds the token.
                eprintln!("fieldseal-factory: operator token refused: {reason:?}");
                BearerError::Invalid(reason)
            }
            IdentityError::Unavailable(reason) => BearerError::Unavailable(reason),
        })
    }
}

/// With the development identity there is no identity provider to issue access tokens, so the
/// operator API answers `503`.
struct NoBearer;

impl BearerVerifier for NoBearer {
    /// The development identity's rule (`dev|{login}`, see the users wired in `run`).
    fn account_for_subject(&self, sub: &str) -> fieldseal_registration::domain::AccountId {
        fieldseal_registration::domain::AccountId(format!("dev|{sub}"))
    }

    fn subject_of_account(&self, account: &fieldseal_registration::domain::AccountId) -> Option<String> {
        account.0.strip_prefix("dev|").map(str::to_owned)
    }

    fn verify(&self, _: &str) -> Result<fieldseal_registration::domain::AuthenticatedPerson, BearerError> {
        Err(BearerError::Unavailable("FIELDSEAL_IDENTITY=dev has no access tokens".into()))
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
    registry_dir: String,
    roster_dir: String,
    unattested: UnattestedKeys,
}

/// A development user: login, role names, `amr` values.
type DevUser = (String, Vec<String>, Vec<String>);

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
        let state_dir = opt("FIELDSEAL_STATE_DIR")?;
        if state_dir.is_some() {
            non_production("FIELDSEAL_STATE_DIR (the file-backed state store is for development)")?;
        }
        // The operator API reads the artefact registry and writes the roster store; both are
        // file adapters, and there is no production adapter for either yet.
        let registry_dir = need("FIELDSEAL_FACTORY_REGISTRY_DIR")?;
        non_production("FIELDSEAL_FACTORY_REGISTRY_DIR (the file artefact registry)")?;
        let roster_dir = need("FIELDSEAL_ROSTER_DIR")?;
        non_production("FIELDSEAL_ROSTER_DIR (the file roster store)")?;
        let unattested = if flag("FIELDSEAL_ALLOW_UNATTESTED")? {
            non_production("FIELDSEAL_ALLOW_UNATTESTED")?;
            UnattestedKeys::AllowNonProduction
        } else {
            UnattestedKeys::Refuse
        };
        Ok(Self { production, bind, public_url, identity, custody, trust_bundle: opt("FIELDSEAL_TRUST_BUNDLE")?, state_dir, registry_dir, roster_dir, unattested })
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

/// Every port of this configuration that is bound to a development adapter, as (port, adapter)
/// (DEP-051). The factory refuses to start in production with any of them.
fn development_adapters(config: &Config) -> Vec<(&'static str, &'static str)> {
    let mut out = vec![("Signer", match config.custody {
        Custody::MemoryDev => "memory-dev",
        Custody::FileDev { .. } => "file-dev",
    })];
    out.push(("TenancyRegistry", if config.state_dir.is_some() { "file-dev" } else { "memory" }));
    if config.unattested == UnattestedKeys::AllowNonProduction {
        out.push(("AttestationVerifier", "software"));
    }
    if matches!(config.identity, Identity::Dev(_)) {
        out.push(("IdentityProvider", "memory-dev"));
    }
    out.push(("ArtefactRegistry", "file-dev"));
    out.push(("RosterSource", "file-dev"));
    out
}

/// The event line for a change the operator API made. It carries no roster value and no
/// account subject (DEP-051).
fn operator_event(e: &OperatorEvent) -> String {
    match e {
        OperatorEvent::AssignmentMade { survey, cohort, generation } => {
            format!("{{\"event\":\"assignment-made\",\"survey\":{survey:?},\"cohort\":{cohort:?},\"generation\":{generation}}}")
        }
        OperatorEvent::RosterIssued { cohort, version, digest } => {
            format!("{{\"event\":\"roster-issued\",\"cohort\":{cohort:?},\"version\":{version},\"digest\":{digest:?}}}")
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
        terms: TenancyTerms { record_key: authority.record, window: authority.window, cohorts: vec![] },
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
    let (idp, bearer): (Box<dyn IdentityProvider>, Box<dyn BearerVerifier>) = match &config.identity {
        Identity::Oidc(c) => {
            let oidc = SharedOidc(std::sync::Arc::new(OidcIdentityProvider::new(c.as_ref().clone()).map_err(|e| e.to_string())?));
            (Box::new(oidc.clone()), Box::new(oidc))
        }
        Identity::Dev(users) => {
            let idp = MemoryIdentityProvider::new();
            for (login, roles, amr) in users {
                let roles: Vec<&str> = roles.iter().map(String::as_str).collect();
                let amr: Vec<&str> = amr.iter().map(String::as_str).collect();
                idp.add(login, &format!("dev|{login}"), &roles, &amr, MethodAssurance::FromProvider);
            }
            idp.set_default(users.first().map(|u| u.0.as_str()));
            (Box::new(idp), Box::new(NoBearer))
        }
    };
    // The operator API's ports: the artefact registry (read) and the roster store (read and
    // write). Phase 13 builds bundles from the same two.
    let open_rosters = || RosterStore::open(&config.roster_dir).map_err(|e| format!("{}: {e}", config.roster_dir));
    let roster_issuer = FileRosterIssuer::new(open_rosters()?);
    let surveys = PublishedSurveys(FileRegistry::new(&config.registry_dir));
    let cohorts = StoredCohorts(open_rosters()?);
    eprintln!("{}", development_adapters_event("fieldseal-factory", &development_adapters(&config)));
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
    .map_err(|e| e.to_string())?
    .with_operator_ports(OperatorPorts { rosters: &roster_issuer, surveys: &surveys, cohorts: &cohorts });
    let events: OperatorEvents = std::sync::Arc::new(|e| eprintln!("{}", operator_event(e)));
    let http = FactoryHttp::new(&factory, idp.as_ref(), HttpConfig { public_url: config.public_url.clone(), session_ttl_ms: 8 * 3600 * 1000 })
        .with_operator_api(bearer.as_ref(), no_reconcile(), events);
    let server = tiny_http::Server::http(&config.bind).map_err(|e| format!("{}: {e}", config.bind))?;
    eprintln!("fieldseal-factory: listening on {} as {} (production: {})", config.bind, config.public_url, config.production);
    http.run(&server);
    Ok(())
}

