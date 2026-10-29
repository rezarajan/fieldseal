//! The intake app: the composition root of the intake service (ADR 0028). It reads its
//! configuration from the environment only, wires adapters to the gate, replays what it
//! stored before it serves, and then serves two listeners: the device-facing upload endpoint
//! and the authority-staff portal with the results reader.
//!
//! [`IntakeApp::build`] checks the configuration (exit `2`), loads the export key (exit `2`),
//! builds the gate and replays stored submissions (a failed replay is exit `1`).
//! [`IntakeApp::listen`] then binds both listeners, and [`IntakeApp::serve`] answers on them,
//! each on its own thread, so that a slow client of one never holds up the other (see [`front`]).

pub mod config;
pub mod dev_adapters;
pub mod front;
pub mod replay;
pub mod wiring;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fieldseal_adapters_file::custody::DirCustody;
use fieldseal_adapters_file::instruments::PublishedInstruments;
use fieldseal_adapters_file::rosters::FileRosterHistory;
use fieldseal_adapters_file::submissions::FileSubmissionStore;
use fieldseal_adapters_file::tenancy::FileTenancyRegistry;
use fieldseal_adapters_landing_files::FileDataPlatform;
use fieldseal_adapters_landing_files::export::ExportKey;
use fieldseal_adapters_memory::delivery::MemoryPopLedger;
use fieldseal_adapters_memory::intake::practice::PracticeAuthority;
use fieldseal_adapters_memory::intake::{MemoryRosterHistory, MemorySubmissionStore};
use fieldseal_adapters_memory::policy::BuiltInPolicyEngine;
use fieldseal_adapters_memory::registration::MemoryIdentityProvider;
use fieldseal_adapters_memory::trust::SeededRandom;
use fieldseal_adapters_oidc::OidcIdentityProvider;
use fieldseal_adapters_portal::PortalSessions;
use fieldseal_adapters_results_http::{DEFAULT_CSP, MAX_BODY, ResultsConfig, ResultsHttp};
use fieldseal_adapters_upload_http::{ServerConfig, UploadHttp};
use fieldseal_intake::gate::IntakeService;
use fieldseal_intake::ports::{DataPlatform, InstrumentSource, RosterHistory, SubmissionStore, TenancyRegistry};
use fieldseal_intake::upload::UploadService;
use fieldseal_kernel::crypto::Purpose;
use fieldseal_kernel::id::KeyId;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::fixtures::effective_default;
use fieldseal_registration::domain::MethodAssurance;
use fieldseal_registration::ports::IdentityProvider;
use fieldseal_trust::domain::{AuthorityPublicKey, KeyCertificate, TrustBundle};
use fieldseal_trust::ports::{AuthorityClock, KeyCustody, RandomSource};

use crate::config::{Config, Custody, Identity};
use crate::front::{BodyLimits, HaltOnDrop};
use crate::replay::ReplaySummary;
use crate::wiring::{EventPlatform, EventStore, OsRandom, Replaying};

/// Why the app did not start.
#[derive(Debug, PartialEq, Eq)]
pub enum AppError {
    /// Unusable configuration or key: exit `2`.
    Config(String),
    /// A start-up or runtime failure, including a failed replay: exit `1`.
    Failed(String),
}

impl AppError {
    /// The process exit code.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) => 2,
            Self::Failed(_) => 1,
        }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(m) | Self::Failed(m) => f.write_str(m),
        }
    }
}

/// The operating system's clock as authority time.
pub struct SystemClock;

impl AuthorityClock for SystemClock {
    fn now(&self) -> AuthorityTime {
        AuthorityTime(SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64))
    }
}

/// Stored submissions to replay: arrival milliseconds and bytes.
type Stored = Vec<(u64, Vec<u8>)>;

/// The authority's keys: custody, trust bundle, receipt key, receiver certificate, randomness.
type Authority = (Box<dyn KeyCustody>, TrustBundle, KeyId, KeyCertificate, Box<dyn RandomSource>);

/// The bound listeners.
pub struct Live {
    upload: tiny_http::Server,
    portal: tiny_http::Server,
}

impl Live {
    /// The address the upload listener is bound to.
    pub fn upload_addr(&self) -> Option<SocketAddr> {
        self.upload.server_addr().to_ip()
    }

    /// The address the portal listener is bound to.
    pub fn portal_addr(&self) -> Option<SocketAddr> {
        self.portal.server_addr().to_ip()
    }
}

/// The wired intake service, replayed and ready to listen.
pub struct IntakeApp {
    config: Config,
    custody: Box<dyn KeyCustody>,
    bundle: TrustBundle,
    receipt_key: KeyId,
    receiver_key: KeyId,
    receiver_certificate: KeyCertificate,
    registry: Box<dyn TenancyRegistry>,
    platform: EventPlatform,
    store: Box<dyn SubmissionStore>,
    rosters: Box<dyn RosterHistory>,
    instruments: Box<dyn InstrumentSource>,
    random: Box<dyn RandomSource>,
    clock: Box<dyn AuthorityClock + Send + Sync>,
    identity: Box<dyn IdentityProvider + Send + Sync>,
    export_key: ExportKey,
    replay: ReplaySummary,
    limits: BodyLimits,
}

fn read_bundle(path: &str) -> Result<TrustBundle, AppError> {
    let bytes = std::fs::read(path).map_err(|e| AppError::Config(format!("{path}: {e}")))?;
    TrustBundle::decode(&bytes).map_err(|e| AppError::Config(format!("{path}: {e}")))
}

fn certificate(bundle: &TrustBundle, path: &str, purpose: Purpose) -> Result<KeyCertificate, AppError> {
    bundle
        .certificates()
        .iter()
        .find(|c| c.purpose() == Some(purpose) && matches!(c.public_key(), AuthorityPublicKey::P256(_)))
        .cloned()
        .ok_or_else(|| AppError::Config(format!("{path}: no P-256 {purpose:?} certificate")))
}

impl IntakeApp {
    /// Builds the app on the system clock.
    pub fn build(config: Config) -> Result<Self, AppError> {
        Self::build_with_clock(config, Box::new(SystemClock))
    }

    /// Builds the app on `clock`. Tests that use the memory-dev authority, whose keys are
    /// valid at a fixed time, pass a fixed clock.
    pub fn build_with_clock(config: Config, clock: Box<dyn AuthorityClock + Send + Sync>) -> Result<Self, AppError> {
        dev_adapters::refuse_in_production(&config).map_err(AppError::Config)?;
        dev_adapters::refuse_exposed_dev_login(&config).map_err(AppError::Config)?;
        // The export key is made by the authority's set-up step, never here.
        let export_key = ExportKey::load(&config.export_key_dir).map_err(|e| AppError::Config(e.to_string()))?;
        eprintln!("{}", dev_adapters::event(&config));
        let (custody, bundle, receipt_key, receiver, random): Authority = match &config.custody {
            Custody::FileDev { dir } => {
                let path = config.trust_bundle.as_deref().ok_or_else(|| AppError::Config("FIELDSEAL_TRUST_BUNDLE is not set".into()))?;
                let bundle = read_bundle(path)?;
                let (receipt, receiver) = (certificate(&bundle, path, Purpose::Receipt)?, certificate(&bundle, path, Purpose::Receiver)?);
                (Box::new(DirCustody::new(dir)), bundle, *receipt.key_id(), receiver, Box::new(OsRandom))
            }
            Custody::MemoryDev => {
                // The development authority with fixed seeds (the practice authority's keys).
                let a = PracticeAuthority::new(7);
                if let Some(path) = &config.trust_bundle {
                    std::fs::write(path, a.bundle.encode().map_err(|e| AppError::Failed(e.to_string()))?).map_err(|e| AppError::Config(format!("{path}: {e}")))?;
                }
                (Box::new(a.custody), a.bundle, a.receipt_key, a.receiver_certificate, Box::new(SeededRandom::new(99)))
            }
        };
        let replaying: Replaying = Arc::new(AtomicBool::new(true));
        let landing: Box<dyn DataPlatform> = Box::new(FileDataPlatform::new(&config.landing_dir).map_err(|e| AppError::Config(format!("{}: {e}", config.landing_dir.display())))?);
        let platform = EventPlatform::new(landing, replaying.clone());
        let now_ms = || SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
        let (store, stored): (Box<dyn SubmissionStore>, Stored) = match &config.submissions_dir {
            Some(d) => {
                let s = FileSubmissionStore::open(d, now_ms).map_err(|e| AppError::Config(format!("{}: {e}", d.display())))?;
                let stored = s.stored();
                (Box::new(EventStore { inner: s, replaying: replaying.clone() }), stored)
            }
            None => (Box::new(EventStore { inner: MemorySubmissionStore::new(), replaying: replaying.clone() }), Vec::new()),
        };
        let rosters: Box<dyn RosterHistory> = match &config.rosters_dir {
            Some(d) => Box::new(FileRosterHistory::new(d)),
            None => Box::new(MemoryRosterHistory::new()),
        };
        let instruments: Box<dyn InstrumentSource> = Box::new(PublishedInstruments::new(&config.published_dir, bundle.clone(), config.publishing_policy()));
        let identity: Box<dyn IdentityProvider + Send + Sync> = match &config.identity {
            Identity::Oidc(c) => Box::new(OidcIdentityProvider::new(c.as_ref().clone()).map_err(|e| AppError::Config(e.to_string()))?),
            Identity::Dev => {
                // One fixed login, as the factory's `memory-dev` identity signs in.
                let idp = MemoryIdentityProvider::new();
                idp.add("presenter", "dev|presenter", &["collector", "operator", &config.reader_role], &["hwk"], MethodAssurance::FromProvider);
                idp.set_default(Some("presenter"));
                Box::new(idp)
            }
        };
        let mut app = Self {
            registry: Box::new(FileTenancyRegistry::new(&config.tenancy_dir)),
            config,
            custody,
            bundle,
            receipt_key,
            receiver_key: *receiver.key_id(),
            receiver_certificate: receiver,
            platform,
            store,
            rosters,
            instruments,
            random,
            clock,
            identity,
            export_key,
            replay: ReplaySummary::default(),
            limits: BodyLimits::default(),
        };
        // Rebuild what has landed from the submissions kept from earlier runs, before any
        // listener exists (INT-013a).
        let (engine, effective) = (BuiltInPolicyEngine, effective_default());
        let summary = {
            let gate = app.gate(&engine, &effective);
            replay::run(&gate, &stored)
        };
        replaying.store(false, Ordering::SeqCst);
        app.replay = summary;
        if summary.failed > 0 {
            return Err(AppError::Failed(format!("{} stored submission(s) failed replay (replay-failed); start-up stops so that no accepted submission is dropped", summary.failed)));
        }
        Ok(app)
    }

    fn gate<'a>(&'a self, engine: &'a BuiltInPolicyEngine, effective: &'a fieldseal_policy::domain::EffectivePolicy) -> IntakeService<'a> {
        IntakeService {
            store: self.store.as_ref(),
            registry: self.registry.as_ref(),
            rosters: self.rosters.as_ref(),
            instruments: self.instruments.as_ref(),
            platform: &self.platform,
            custody: self.custody.as_ref(),
            policy: engine,
            effective,
            random: self.random.as_ref(),
            trust: &self.bundle,
            revocations: vec![],
            receipt_key: self.receipt_key,
            caller: "intake",
        }
    }

    /// The same app with other floors for how fast a request body must arrive.
    pub fn with_body_limits(mut self, limits: BodyLimits) -> Self {
        self.limits = limits;
        self
    }

    /// What start-up replay did.
    pub fn replay(&self) -> ReplaySummary {
        self.replay
    }

    /// The trust bundle the app serves the authority of.
    pub fn trust_bundle(&self) -> &TrustBundle {
        &self.bundle
    }

    /// Binds both listeners. The upload listener is bound only now, after replay.
    pub fn listen(&self) -> Result<Live, AppError> {
        let bind = |addr: &str| tiny_http::Server::http(addr).map_err(|e| AppError::Failed(format!("cannot bind {addr}: {e}")));
        Ok(Live { upload: bind(&self.config.bind)?, portal: bind(&self.config.portal_bind)? })
    }

    /// Answers on both listeners until the process ends.
    pub fn serve(&self, live: &Live) {
        self.serve_until(live, &AtomicBool::new(false));
    }

    /// Answers on both listeners until `stop` is set: the upload listener on this thread and
    /// the portal on a thread of its own. If either ends (it panicked), the other stops too.
    pub fn serve_until(&self, live: &Live, stop: &AtomicBool) {
        let halt = AtomicBool::new(false);
        let stopped = || stop.load(Ordering::SeqCst) || halt.load(Ordering::SeqCst);
        // The portal needs only these, all of them shareable; its reader and sessions are built
        // on its own thread.
        let (config, clock, identity) = (&self.config, self.clock.as_ref(), self.identity.as_ref());
        let (export_key, bundle, replay_gap, limits) = (self.export_key.clone(), self.bundle.clone(), self.replay.failed as u64, self.limits);
        let portal = &live.portal;
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let _halt = HaltOnDrop(&halt);
                let results = ResultsHttp::new(
                    PortalSessions::new("fs_intake_session", config.portal_url.starts_with("https://"), 8 * 3600 * 1000),
                    identity,
                    export_key,
                    clock,
                    ResultsConfig {
                        landing_dir: config.landing_dir.clone(),
                        published_dir: config.published_dir.clone(),
                        trust: bundle,
                        policy: config.publishing_policy(),
                        reader_role: config.reader_role.clone(),
                        require_phishing_resistant: true,
                        public_url: config.portal_url.clone(),
                        csp: DEFAULT_CSP.into(),
                        development_adapters: dev_adapters::list(config).into_iter().map(|(p, a)| (p.to_owned(), a.to_owned())).collect(),
                        replay_gap,
                    },
                );
                front::serve(portal, MAX_BODY, limits, &stopped, &|req, body| results.answer(req, body));
            });
            let _halt = HaltOnDrop(&halt);
            let (engine, effective, ledger) = (BuiltInPolicyEngine, effective_default(), MemoryPopLedger::new());
            let gate = self.gate(&engine, &effective);
            let urls: Vec<String> = if config.public_urls.is_empty() { vec![format!("http://{}", config.bind)] } else { config.public_urls.clone() };
            let service = UploadService { intake: &gate, ledger: &ledger, receiver_key: self.receiver_key, receiver_certificate: &self.receiver_certificate, public_urls: &urls };
            let upload = UploadHttp::new(&service, || clock.now(), ServerConfig { max_body: config.max_body.unwrap_or(ServerConfig::default().max_body) });
            eprintln!("{{\"event\":\"listening\",\"upload\":\"{}\",\"portal\":\"{}\"}}", config.bind, config.portal_bind);
            front::serve(&live.upload, upload.max_body(), limits, &stopped, &|req, body| upload.answer(req, body));
        });
    }
}
