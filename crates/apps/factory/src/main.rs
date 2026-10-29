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
//! | `FIELDSEAL_FACTORY_POLICY_DIGEST` | The content address (`sha256:` and 64 hex digits) of the `deployment-policy` the factory trusts. Required in staging and production, where any other policy is refused; in development it pins the policy when set |
//! | `FIELDSEAL_FACTORY_ALLOWED_BUILDERS`, `FIELDSEAL_FACTORY_ALLOWED_SOURCES` | Development only, without a pinned digest: comma-separated builders and sources the release policy is verified under (with the schema defaults) before any value is read from it. Default none |
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

use fieldseal_adapters_factory_http::{BearerError, BearerVerifier, BundleRoutes, FactoryHttp, HttpConfig, OperatorEvent, OperatorEvents};
use fieldseal_adapters_file::bundles::FileBundleStore;
use fieldseal_adapters_file::custody::DirCustody;
use fieldseal_adapters_file::directories::{PublishedSurveys, StoredCohorts};
use fieldseal_adapters_file::profiles::FileRuntimeProfiles;
use fieldseal_adapters_file::registry::FileRegistry;
use fieldseal_adapters_file::roster_issuer::FileRosterIssuer;
use fieldseal_adapters_file::roster_store::{FileRosterSource, RosterStore};
use fieldseal_adapters_file::store::FileRegistryStore;
use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog};
use fieldseal_adapters_memory::registration::{MemoryIdentityProvider, MemoryReceivedProgress, dev_authority};
use fieldseal_adapters_memory::trust::SoftwareAttestationVerifier;
use fieldseal_adapters_oidc::OidcIdentityProvider;
use fieldseal_deployment::events::development_adapters_event;
use fieldseal_distribution::application::{BundleDelivery, FactoryIdentity};
use fieldseal_factory::config::{Config, Custody, Identity};
use fieldseal_factory::reconciler::{ReconcileEvent, Reconciler, ReconcilerConfig, ReconcilerPorts};
use fieldseal_kernel::crypto::Purpose;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::domain::{Controls, EffectivePolicy};
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::application::{Factory, FactoryConfig, FactoryPorts, OperatorPorts};
use fieldseal_registration::domain::{MethodAssurance, TenancyTerms, Window};
use fieldseal_registration::ports::{IdentityError, IdentityProvider, PendingSignIn, RegistryStore, SignInStart};
use fieldseal_trust::domain::{AuthorityPublicKey, KeyCertificate, TrustBundle};
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
    custody: Box<dyn KeyCustody + Send + Sync>,
    bundle: TrustBundle,
    /// The `factory` key's certificate (it signs bundles) and the `receipt` key (it signs anchors).
    factory: KeyCertificate,
    receipt: fieldseal_kernel::id::KeyId,
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
            Ok(Authority {
                signing: *a.signing.key_id(),
                sealing: *a.sealing.key_id(),
                record: *a.record.key_id(),
                receipt: *a.receipt.key_id(),
                factory: a.factory,
                custody: Box::new(a.custody),
                bundle: a.bundle,
                window: default_window,
            })
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
            // The newest certificate that is valid now, not the first one found: after a key
            // roll the bundle holds both.
            let purpose = |p: Purpose, what: &str| {
                bundle
                    .certificates()
                    .iter()
                    .filter(|c| c.purpose() == Some(p) && c.not_before() <= now && now < c.not_after())
                    .max_by_key(|c| (c.not_before(), c.not_after()))
                    .cloned()
                    .ok_or_else(|| format!("{path}: no currently valid {what} key certificate"))
            };
            let (factory, receipt) = (purpose(Purpose::Factory, "factory")?, purpose(Purpose::Receipt, "receipt")?);
            eprintln!("fieldseal-factory: authority from {dir} and {path} (development custody)");
            Ok(Authority {
                signing: *signing.key_id(),
                sealing: *sealing.key_id(),
                record: *record.key_id(),
                receipt: *receipt.key_id(),
                factory,
                custody: Box::new(DirCustody::new(dir)),
                bundle,
                window,
            })
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
    out.push(("TenancyRegistry", "file-dev"));
    if config.unattested == UnattestedKeys::AllowNonProduction {
        out.push(("AttestationVerifier", "software"));
    }
    if matches!(config.identity, Identity::Dev(_)) {
        out.push(("IdentityProvider", "memory-dev"));
    }
    out.push(("ArtefactRegistry", "file-dev"));
    out.push(("RosterSource", "file-dev"));
    out.push(("RuntimeProfiles", "file-dev"));
    out.push(("BundleStore", "file-dev"));
    out
}

/// The event line for what the reconciler did. A tenancy is named by the first 16 hex digits
/// of its identifier; nothing here is subject data (DEP-051).
fn reconcile_event(e: &ReconcileEvent) -> String {
    let name = |t: &fieldseal_kernel::id::TenancyId| fieldseal_kernel::digest::lower_hex(&t.as_bytes()[..8]);
    match e {
        ReconcileEvent::Built { tenancy, seq, address, instruments, layouts, rosters } => serde_json::json!({
            "event": "bundle-built", "tenancy": name(tenancy), "sequence": seq, "address": address.to_text(),
            "instruments": instruments, "layouts": layouts, "rosters": rosters,
        }),
        ReconcileEvent::Withheld { tenancy, reason, survey } => {
            serde_json::json!({ "event": "bundle-withheld", "tenancy": name(tenancy), "reason": reason, "survey": survey })
        }
        ReconcileEvent::Failed { tenancy, reason } => serde_json::json!({ "event": "bundle-failed", "tenancy": name(tenancy), "reason": reason }),
        ReconcileEvent::Skipped { kind, name, version, reason } => {
            serde_json::json!({ "event": "artefact-skipped", "kind": kind, "name": name, "version": version, "reason": reason })
        }
        ReconcileEvent::PassFailed { reason } => serde_json::json!({ "event": "reconcile-failed", "reason": reason }),
    }
    .to_string()
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
    // Custody must hold the keys the factory signs with. Asked by key identifier only; nothing is signed.
    for (what, id) in [("factory", authority.factory.key_id()), ("receipt", &authority.receipt)] {
        authority.custody.public_key(id).map_err(|e| format!("custody holds no {what} key {}: {e}", fieldseal_kernel::digest::lower_hex(id.as_bytes())))?;
    }
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
    eprintln!("fieldseal-factory: state in {} (file-backed, development)", config.state_dir);
    let store: Box<dyn RegistryStore + Send + Sync> = Box::new(FileRegistryStore::open(&config.state_dir).map_err(|e| format!("{}: {e}", config.state_dir))?);
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
    // The artefact registry (read) and the roster store (read and write): the operator API
    // uses them, and the reconciler builds bundles from the same two.
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
    // The reconciler runs on its own thread over ports shared with this one; every request
    // handler only tells it what changed.
    let artefacts = FileRegistry::new(&config.registry_dir);
    let roster_source = FileRosterSource::new(open_rosters()?, &config.state_dir);
    let profiles = FileRuntimeProfiles::new(&config.state_dir);
    let bundles = FileBundleStore::new(&config.bundle_dir);
    let reconciler = Reconciler::new(
        ReconcilerPorts {
            registry: store.as_ref(),
            artefacts: &artefacts,
            rosters: &roster_source,
            profiles: &profiles,
            bundles: &bundles,
            custody: authority.custody.as_ref(),
            random: &random,
            clock: &clock,
        },
        ReconcilerConfig {
            trust: authority.bundle.clone(),
            identity: FactoryIdentity { signer: *authority.factory.key_id(), chain: vec![authority.factory.clone()], caller: "fieldseal-factory".into(), unattested: config.unattested },
            receipt: authority.receipt,
            bundle_dir: config.bundle_dir.clone().into(),
            issued_rosters_dir: config.issued_rosters_dir.clone().into(),
            max_anchor_age_ms: config.max_anchor_age_s * 1000,
            policy_trust: config.policy_trust.clone(),
            state_dir: Some(config.state_dir.clone().into()),
            // What the reconciler reads: the artefact registry (publications, and withdrawals
            // in their own directory), the roster store, and the registry journal and its directory.
            watch: vec![
                config.registry_dir.clone().into(),
                std::path::Path::new(&config.registry_dir).join("withdrawals"),
                config.roster_dir.clone().into(),
                config.state_dir.clone().into(),
                std::path::Path::new(&config.state_dir).join(fieldseal_adapters_file::store::JOURNAL),
            ],
        },
        std::sync::Arc::new(|e| eprintln!("{}", reconcile_event(e))),
    );
    let delivery = BundleDelivery::new(store.as_ref(), &bundles);
    let server = tiny_http::Server::http(&config.bind).map_err(|e| format!("{}: {e}", config.bind))?;
    std::thread::scope(|scope| {
        let spawned = reconciler.spawn(scope, std::time::Duration::from_secs(config.build_interval_s));
        let http = FactoryHttp::new(&factory, idp.as_ref(), HttpConfig { public_url: config.public_url.clone(), session_ttl_ms: 8 * 3600 * 1000 })
            .with_operator_api(bearer.as_ref(), spawned.notify(), events)
            .with_bundle_routes(BundleRoutes { fetch: &delivery, download: &delivery })
            .with_registration_notify(spawned.notify());
        eprintln!("fieldseal-factory: listening on {} as {} (production: {})", config.bind, config.public_url, config.production);
        http.run(&server);
    });
    Ok(())
}
