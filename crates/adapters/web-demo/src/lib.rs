//! A demo authority for the showcase web app (development only, unattested).
//!
//! The web app must work standalone, with no other service running. This crate embeds the
//! parts of a Fieldseal deployment a browser device needs to register, receive a bundle,
//! capture, export, upload and verify receipts:
//!
//! | Piece | What it is |
//! |---|---|
//! | World | The root ceremony, purpose keys, trust bundle and transparency log of [`fieldseal_adapters_memory::demo::DemoWorld`], with a start time two days before `now_ms` so every certificate and signature is already valid and nothing lies in the future |
//! | Published content | Every valid instrument in `examples_dir/instruments`, every layout in `examples_dir/layouts` that names one of them, a release policy: each reviewed twice, signed by both publishers and logged |
//! | Factory | The real registration [`fieldseal_registration::application::Factory`] and the real portal and API in [`fieldseal_adapters_factory_http`], served on [`Demo::factory_url`] |
//! | Bundles | The real `BuildBundle` under the real release policy, sealed to the registered device's agreement key ([`Demo::build_bundle`]) |
//! | Intake | The real verification gate and upload service over a live view of the factory's registry ([`IntakeWorld`]), served on [`Demo::upload_url`] by [`fieldseal_adapters_upload_http::UploadHttp`] |
//! | Reports | Plain-data views of publications, the log, registrations and landed data for the web app to render |
//!
//! # Starting
//!
//! ```no_run
//! use fieldseal_adapters_web_demo::{Demo, DemoConfig};
//! let mut config = DemoConfig::new("examples");
//! config.now_ms = 1_800_000_000_000; // the real wall clock, in milliseconds
//! let demo = Demo::start(config).expect("the demo authority starts");
//! println!("portal: {}  upload: {}", demo.factory_url(), demo.upload_url());
//! ```
//!
//! # Signing in to the factory portal
//!
//! The portal runs with a development identity provider (what `FIELDSEAL_IDENTITY=dev`
//! gives the factory service), not a real one. There is no login form: opening
//! `{factory_url}/sign-in` signs the visitor in at once as the provider's current login,
//! which is `alice` (role `collector`, method assurance `FromProvider`) unless
//! [`Demo::set_portal_login`] chose `bob`. Once signed in, the portal's "new token" form
//! issues a registration token, as text and as a QR code. [`Demo::issue_registration_token`]
//! does the same without the browser round trip.
//!
//! # Honest limits
//!
//! - **Development only.** Every key is a software key held in process memory, derived from
//!   `DemoConfig::seed`: anyone who knows the seed can derive the authority's keys. The root
//!   ceremony is simulated. Nothing here may run in production.
//! - **Unattested devices.** A browser has no hardware key store. Its registration evidence
//!   is software evidence, accepted only because the factory runs with
//!   `UnattestedKeys::AllowNonProduction`. Production policy never accepts it (REG-017,
//!   TRU-061).
//! - **Rosters are released under the development allowance.** The release policy denies
//!   rosters to keys without hardware attestation (DIS-002, INV-10) unless the factory runs
//!   with the non-production allowance for unattested keys (REG-017). With
//!   [`DemoConfig::release_rosters_to_unattested`] set (the default) the factory does, and
//!   policy releases the rosters with a flag in its decision log. **Nothing about the
//!   device's attestation is changed**: it stays unattested (software evidence) in the
//!   registry and everywhere else (TRU-061, TRU-063). Production never sets the allowance.
//! - **State is lost on restart.** The registry, the transparency log, the submission store
//!   and the data platform are in memory.
//! - **Serving is simple.** Each HTTP server handles one request at a time on its own
//!   thread, over plain HTTP (loopback only for the factory, see `factory_url_ok`).
//! - **Intake sees the registry live.** The upload endpoint looks tenancies up in the
//!   factory's registry on every request, so devices registered after start-up upload
//!   without a restart, and a tenancy that changes later is seen as changed.
//! - **Runtime builds.** The factory's software attestation verifier accepts builds whose
//!   identity begins `fieldseal-simulator` or `fieldseal-web`.
//! - **Instruments in a bundle.** [`Demo::build_bundle`] includes every published instrument;
//!   [`Demo::build_bundle_for`] names the ones to include. The runtime holds all of them.
//!   Every bundle carries the rosters of every certified cohort, because the builder
//!   refuses to omit the roster of an assigned cohort.

mod content;
mod intake_world;
mod reports;
mod support;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fieldseal_adapters_factory_http::{FactoryHttp, HttpConfig};
use fieldseal_adapters_memory::demo::{DEMO_SCHEMA, DemoWorld, EdgeServices};
use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog, MemoryPolicySource};
use fieldseal_adapters_memory::registration::{MemoryIdentityProvider, MemoryReceivedProgress};
use fieldseal_adapters_memory::trust::SoftwareAttestationVerifier;
use fieldseal_adapters_upload_http::{ServerConfig, UploadHttp};
use fieldseal_distribution::application::BuildRequest;
use fieldseal_distribution::domain::{BundleAssignment, Roster, RuntimeProfile, artefacts_of, check_composition};
use fieldseal_intake::domain::{IssuedConsent, IssuedRoster};
use fieldseal_kernel::base64url::base64url_encode;
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::id::{CohortId, ContentAddress, Digest, Fingerprint, Generation, SubjectId, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::application::PolicyService;
use fieldseal_policy::domain::{EffectivePolicy, PublishedPolicy, PublishingPolicy, decode_document};
use fieldseal_policy::fixtures::{DocBuilder, effective, int};
use fieldseal_publishing::domain::{ArtefactKind, Publication};
use fieldseal_registration::application::{Factory, FactoryConfig, FactoryPorts};
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::domain::{CohortAssignment, MethodAssurance, RegistrationRoute, TenancyState, TenancyTerms, Window};
use fieldseal_registration::ports::RegistryStore;
use fieldseal_trust::domain::AuthorityPublicKey;
use fieldseal_trust::ports::AuthorityClock;

pub use intake_world::{IngestReport, IntakeReport, IntakeWorld, LongRow, LossReport, RecordingStore, SubmissionReport, is_landed};
pub use reports::{
    BuildReport, CheckpointReport, InclusionReport, LogEntryReport, PublicationReport, RegistrationReport, ReviewerReport, SignatureReport, ThresholdReport,
};
pub use support::LiveRegistry;

use content::Content;
use support::{OsRandom, RealClock, TrackingStore};

/// How to start the demo authority.
#[derive(Clone, Debug)]
pub struct DemoConfig {
    /// Seeds every key and salt. Anyone who knows it can derive the authority's keys.
    pub seed: u64,
    /// The real wall-clock time, in milliseconds since the epoch. The world starts two days
    /// before it, so every certificate and signature is already valid and nothing lies in
    /// the future. Factory and intake clocks run from here.
    pub now_ms: u64,
    /// The address the factory portal and API bind, for example `127.0.0.1:0`. Port `0`
    /// picks a free port, which [`Demo::factory_url`] reports.
    pub factory_bind: String,
    /// The address the upload endpoint binds, for example `127.0.0.1:0`.
    pub upload_bind: String,
    /// The repository's `examples/` directory: `surveys/` (a folder for each survey) and `rosters/`.
    pub examples_dir: PathBuf,
    /// The base URL devices reach the factory at, when it differs from the bound address
    /// (behind a proxy). Defaults to the bound address. PoP tokens are checked against it.
    pub factory_public_url: Option<String>,
    /// The base URL devices reach the upload endpoint at, when it differs from the bound
    /// address.
    pub upload_public_url: Option<String>,
    /// The development allowance: the factory runs with `UnattestedKeys::AllowNonProduction`
    /// for bundle release (REG-017), so policy releases rosters to the unattested device with a
    /// flag. Nothing about the device's attestation is changed. See the crate docs.
    pub release_rosters_to_unattested: bool,
}

impl DemoConfig {
    /// A configuration with seed `1`, time `0` (set `now_ms`!), both servers on free
    /// loopback ports, and rosters released to unattested devices.
    pub fn new(examples_dir: impl Into<PathBuf>) -> Self {
        Self {
            seed: 1,
            now_ms: 0,
            factory_bind: "127.0.0.1:0".into(),
            upload_bind: "127.0.0.1:0".into(),
            examples_dir: examples_dir.into(),
            factory_public_url: None,
            upload_public_url: None,
            release_rosters_to_unattested: true,
        }
    }
}

/// A sealed bundle and what it holds.
#[derive(Clone, Debug)]
pub struct BundleReport {
    /// The bundle file (FSB1), sealed to the device's agreement key.
    pub bytes: Vec<u8>,
    /// Whether the rosters were released to an unattested device under the development
    /// allowance (REG-017). The device is still unattested; production policy refuses.
    pub development_allowance: bool,
    /// Instruments in the bundle.
    pub instruments: usize,
    /// Layouts in the bundle.
    pub layouts: usize,
    /// Rosters in the bundle.
    pub rosters: usize,
}

/// The factory-side state the HTTP servers and methods share.
struct Shared {
    verifier: SoftwareAttestationVerifier,
    engine: BuiltInPolicyEngine,
    log: MemoryDecisionLog,
    progress: MemoryReceivedProgress,
    random: OsRandom,
    clock: RealClock,
    policy: EffectivePolicy,
    config: FactoryConfig,
    idp: MemoryIdentityProvider,
    store: TrackingStore,
}

/// A published artefact, as the demo keeps it.
struct Published {
    publication: Publication,
}

/// The demo authority. Obtain it with [`Demo::start`]; it lives for the rest of the process.
pub struct Demo {
    world: &'static DemoWorld,
    edge: EdgeServices,
    shared: &'static Shared,
    release: PublishedPolicy,
    content: Content,
    published: Vec<Published>,
    intake: IntakeWorld,
    config: DemoConfig,
    factory_url: String,
    upload_url: String,
    build_lock: Mutex<()>,
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn profile() -> RuntimeProfile {
    RuntimeProfile { instrument_schema: DEMO_SCHEMA, localisation_reference: None }
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 || !s.is_ascii() {
        return Err("a tenancy identifier is 64 hex digits".into());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| "a tenancy identifier is 64 hex digits".to_owned())?;
    }
    Ok(out)
}

fn base_url(bind: &std::net::SocketAddr, configured: &str) -> String {
    let host = configured.rsplit_once(':').map_or(configured, |(h, _)| h);
    let host = if host.is_empty() || host == "0.0.0.0" || host == "[::]" { "127.0.0.1" } else { host };
    format!("http://{host}:{}", bind.port())
}

impl Demo {
    /// Builds the world, publishes the examples, binds both servers and starts serving each
    /// on its own thread. The demo is leaked: it lives until the process ends.
    pub fn start(config: DemoConfig) -> Result<&'static Demo, String> {
        // Bind first: the factory URL must equal the externally visible base URL, and PoP
        // tokens are checked against it, so the real port is needed before the factory exists.
        let factory_server = tiny_http::Server::http(&config.factory_bind).map_err(|e| format!("{}: {e}", config.factory_bind))?;
        let upload_server = tiny_http::Server::http(&config.upload_bind).map_err(|e| format!("{}: {e}", config.upload_bind))?;
        let addr = |s: &tiny_http::Server| s.server_addr().to_ip().ok_or_else(|| "the server did not bind an IP address".to_owned());
        let factory_url = config.factory_public_url.clone().unwrap_or(base_url(&addr(&factory_server)?, &config.factory_bind));
        let upload_url = config.upload_public_url.clone().unwrap_or(base_url(&addr(&upload_server)?, &config.upload_bind));
        if !fieldseal_registration::domain::wire::factory_url_ok(&factory_url) {
            return Err(format!("{factory_url} is not a usable factory URL (https, or http on a loopback host)"));
        }

        let demo: &'static Demo = Box::leak(Box::new(Self::build(config, factory_url, upload_url)?));
        let factory_server = Arc::new(factory_server);
        let upload_server = Arc::new(upload_server);
        std::thread::Builder::new().name("demo-factory".into()).spawn(move || demo.serve_factory(&factory_server)).map_err(err)?;
        std::thread::Builder::new().name("demo-upload".into()).spawn(move || demo.serve_upload(&upload_server)).map_err(err)?;
        Ok(demo)
    }

    fn build(config: DemoConfig, factory_url: String, upload_url: String) -> Result<Self, String> {
        let t0 = AuthorityTime(config.now_ms.checked_sub(2 * AuthorityTime::DAY).ok_or("now_ms must be a real time, at least two days after the epoch")?);
        let mut world = DemoWorld::new(config.seed, t0)?;
        let edge = world.add_edge_services(&["fieldseal-simulator", "fieldseal-web"])?;

        let content = Content::publish(&world, &config.examples_dir);
        if content.instruments.is_empty() {
            return Err(format!("no instrument could be published from {}/instruments: {}", config.examples_dir.display(), content.warnings.join("; ")));
        }

        // The release policy: published like any artefact; as many devices on a cohort as a
        // showcase visitor may register.
        let release_value = DocBuilder::deployment("web-demo-release", "1.0.0").set("factory.cohorts.maxActiveTenanciesPerCohort", int(1000)).build();
        let release_publication = world.publish(ArtefactKind::Policy, "web-demo-release", "1.0.0", fieldseal_kernel::cbor::encode(&release_value).map_err(err)?, None)?;
        let release = PublishedPolicy {
            address: *release_publication.address(),
            document: decode_document(&release_value).document.ok_or("the release policy document is invalid")?,
        };

        let mut published = vec![Published { publication: world.policy.publication.clone() }, Published { publication: release_publication }];
        published.extend(content.instruments.iter().map(|i| Published { publication: i.publication.clone() }));
        published.extend(content.layouts.iter().map(|l| Published { publication: l.publication.clone() }));

        // Registrations certify every roster cohort at generation 1.
        let record_certificate = world.trust.certificates().iter().find(|c| c.key_id() == &world.record.id).ok_or("the record key is not certified")?.clone();
        let cohorts: Vec<CohortAssignment> = {
            let mut seen = BTreeSet::new();
            content.rosters.iter().filter(|(_, r)| seen.insert(r.cohort.clone())).map(|(_, r)| CohortAssignment { cohort: r.cohort.clone(), generation: Generation(1) }).collect()
        };
        let factory_config = FactoryConfig {
            factory_url: factory_url.clone(),
            signing_key: world.registration,
            sealing_key: edge.sealing.id,
            terms: TenancyTerms {
                record_key: world.record.id,
                window: Window { not_before: record_certificate.not_before(), not_after: record_certificate.not_after(), grace_ms: 30 * AuthorityTime::DAY },
                cohorts,
            },
            unattested: UnattestedKeys::AllowNonProduction,
            posture_nonce_ttl_ms: 10 * 60_000,
            access_token_ttl_ms: 10 * 60_000,
        };
        let idp = MemoryIdentityProvider::new();
        idp.add("alice", "sub-alice", &["collector"], &["hwk", "user"], MethodAssurance::FromProvider);
        idp.add("bob", "sub-bob", &["collector"], &["hwk", "user"], MethodAssurance::FromProvider);
        idp.set_default(Some("alice"));

        // Leak the world: the servers and the registry views hold references to it.
        let world: &'static DemoWorld = Box::leak(Box::new(world));
        let shared: &'static Shared = Box::leak(Box::new(Shared {
            verifier: SoftwareAttestationVerifier,
            engine: BuiltInPolicyEngine,
            log: MemoryDecisionLog::new(),
            progress: MemoryReceivedProgress::new(),
            random: OsRandom,
            clock: RealClock::new(config.now_ms),
            policy: effective(&[DocBuilder::deployment("web-demo", "1.0.0").set("factory.registration.maxDevicesPerAccount", int(100)).build()]),
            config: factory_config,
            idp,
            store: TrackingStore::new(&world.registry),
        }));

        let named = content.instruments.iter().map(|i| (i.fingerprint, i.name.clone())).collect();
        let intake = IntakeWorld::new(world, vec![upload_url.clone()], config.now_ms, named);
        for i in &content.instruments {
            intake.instruments.add(i.fingerprint, i.model.clone());
        }
        // The factory-side check that the keys are in the trust bundle runs here, once.
        Self::factory_over(world, shared).map_err(|e| format!("the factory could not start: {e}"))?;

        Ok(Self {
            world,
            edge,
            shared,
            release,
            content,
            published,
            intake,
            config,
            factory_url,
            upload_url,
            build_lock: Mutex::default(),
        })
    }

    fn factory_over(world: &'static DemoWorld, shared: &'static Shared) -> Result<Factory<'static>, String> {
        Factory::new(
            FactoryPorts {
                store: &shared.store,
                custody: &world.custody,
                verifiers: vec![&shared.verifier],
                engine: &shared.engine,
                log: &shared.log,
                clock: &shared.clock,
                random: &shared.random,
                progress: &shared.progress,
                fleet: None,
                notifier: None,
            },
            &world.trust,
            &shared.policy,
            &shared.config,
        )
        .map_err(err)
    }

    fn serve_factory(&'static self, server: &tiny_http::Server) {
        let Ok(factory) = Self::factory_over(self.world, self.shared) else { return };
        let http = FactoryHttp::new(&factory, &self.shared.idp, HttpConfig { public_url: self.factory_url.clone(), session_ttl_ms: 8 * 3600 * 1000 });
        http.run(server);
    }

    fn serve_upload(&'static self, server: &tiny_http::Server) {
        let gate = self.intake.gate();
        let service = self.intake.upload(&gate, &self.edge);
        let http = UploadHttp::new(&service, || self.intake.now(), ServerConfig::default());
        http.run(server);
    }

    /// The factory's registration factory, over the demo's registry, for callers that want
    /// to act as the portal does (for example, confirming a pending registration).
    pub fn factory(&'static self) -> Factory<'static> {
        Self::factory_over(self.world, self.shared).expect("the factory started once, so it starts again")
    }

    /// The base URL of the factory portal and registration API. PoP tokens are bound to it.
    pub fn factory_url(&self) -> &str {
        &self.factory_url
    }

    /// The base URL of the upload endpoint.
    pub fn upload_url(&self) -> &str {
        &self.upload_url
    }

    /// The names of the published instruments.
    pub fn examples(&self) -> Vec<String> {
        self.content.instruments.iter().map(|i| i.name.clone()).collect()
    }

    /// Anything that was skipped while publishing the examples, and why.
    pub fn warnings(&self) -> &[String] {
        &self.content.warnings
    }

    /// The demo's trust bundle.
    pub fn trust_bundle(&self) -> &fieldseal_trust::domain::TrustBundle {
        &self.world.trust
    }

    /// The publishing policy the world verifies publications under.
    pub fn publishing_policy(&self) -> &PublishingPolicy {
        &self.world.publishing
    }

    /// The record key (X25519) that records seal to before a tenancy certificate names it.
    pub fn provisional_record_key(&self) -> [u8; 32] {
        match &self.world.record.public_key {
            AuthorityPublicKey::X25519(k) => *k,
            _ => [0; 32],
        }
    }

    /// Confirms a pending registration as the portal's "confirm" button does, once the
    /// collector has checked that both screens show the same four words (REG-021). The
    /// tenancy becomes registered.
    pub fn confirm_registration(&self, tenancy_hex: &str) -> Result<(), String> {
        let tenancy = TenancyId::from(parse_hex32(tenancy_hex)?);
        let record = self.world.registry.tenancy(&tenancy).map_err(err)?.ok_or("no such tenancy")?;
        Self::factory_over(self.world, self.shared)?.confirm(&record.account, &tenancy).map_err(err)?;
        Ok(())
    }

    /// The current time on the demo's clocks, in milliseconds since the epoch.
    pub fn now(&self) -> AuthorityTime {
        self.shared.clock.now()
    }

    /// Chooses who the portal's development sign-in signs in as: `alice` or `bob`.
    pub fn set_portal_login(&self, login: &str) -> Result<(), String> {
        self.shared.idp.person(login).ok_or_else(|| format!("{login} is not a development person (use alice or bob)"))?;
        self.shared.idp.set_default(Some(login));
        Ok(())
    }

    /// Issues an online registration token to `login` (`alice` or `bob`), as the portal's
    /// "new token" form does, and returns its text form (the string a QR code carries).
    pub fn issue_registration_token(&self, login: &str) -> Result<String, String> {
        let person = self.shared.idp.person(login).ok_or_else(|| format!("{login} is not a development person (use alice or bob)"))?;
        let factory = Self::factory_over(self.world, self.shared)?;
        let issued = factory.issue_token(&person, RegistrationRoute::Online, 1).map_err(err)?;
        issued.token.to_text().map_err(err)
    }

    /// The JSON a browser device is provisioned with. See the field names in the crate's
    /// tests; `trustBundle` is the encoded trust bundle in base64url.
    pub fn provisioning_json(&self) -> String {
        let record_key = lower_hex(&self.provisional_record_key());
        let bundle = self.world.trust.encode().map(|b| base64url_encode(&b)).unwrap_or_default();
        serde_json::json!({
            "authority": self.world.trust.name(),
            "environment": "development",
            "trustBundle": bundle,
            "allowedBuilders": self.world.publishing.allowed_builders,
            "allowedSources": self.world.publishing.allowed_sources,
            "provisionalRecordKey": record_key,
            "buildAnchor": lower_hex(Digest::from([0xbb; 32]).as_bytes()),
            "schema": format!("{}.{}.{}", DEMO_SCHEMA.major, DEMO_SCHEMA.minor, DEMO_SCHEMA.patch),
            "factoryUrl": self.factory_url,
            "uploadUrl": self.upload_url,
            "unattested": true,
        })
        .to_string()
    }

    // -----------------------------------------------------------------------------------
    // Bundles.

    /// Builds and seals the next bundle for a registered tenancy, with every published
    /// instrument, their layouts and the rosters. See [`Demo::build_bundle_for`].
    pub fn build_bundle(&self, tenancy_hex: &str) -> Result<BundleReport, String> {
        self.build_bundle_for(tenancy_hex, &[])
    }

    /// Like [`Demo::build_bundle`], restricted to the named instruments (all of them when
    /// `instruments` is empty). The real `BuildBundle` runs under the real release policy.
    /// If [`DemoConfig::release_rosters_to_unattested`] is set, release policy runs with the
    /// development allowance (REG-017); the device's attestation is never touched.
    /// The rosters issued are recorded in intake's roster history.
    pub fn build_bundle_for(&self, tenancy_hex: &str, instruments: &[&str]) -> Result<BundleReport, String> {
        let tenancy = TenancyId::from(parse_hex32(tenancy_hex)?);
        let _one_at_a_time = self.build_lock.lock().expect("lock");
        let record = self.world.registry.tenancy(&tenancy).map_err(err)?.ok_or("no such tenancy")?;
        if record.state != TenancyState::Registered {
            return Err(format!("the tenancy is {}, not registered", record.state.as_str()));
        }
        // The device stays unattested: nothing here writes or alters attestation claims. When
        // the development allowance is set, the release policy lets rosters reach an
        // unattested key with a flag (REG-017); otherwise the real policy refuses (INV-10).
        let development_allowance = self.config.release_rosters_to_unattested && !record.keys_attested();
        let unattested = if self.config.release_rosters_to_unattested { UnattestedKeys::AllowNonProduction } else { UnattestedKeys::Refuse };
        let chosen: Vec<&content::PublishedInstrument> = self.content.instruments.iter().filter(|i| instruments.is_empty() || instruments.contains(&i.name.as_str())).collect();
        if chosen.is_empty() {
            return Err("no such instrument".into());
        }
        let addresses: Vec<ContentAddress> = chosen.iter().map(|i| *i.publication.address()).collect();
        let layouts: Vec<&content::PublishedLayout> = self.content.layouts.iter().filter(|l| addresses.contains(&l.instrument)).collect();

        // The rosters of every certified cohort, at the generation the tenancy holds.
        let rosters: Vec<Roster> = record
            .cohorts
            .iter()
            .filter_map(|c| self.content.rosters.iter().find(|(_, r)| r.cohort == c.cohort).map(|(_, r)| Roster { generation: c.generation, ..r.clone() }))
            .collect();
        self.world.profiles.record(tenancy, profile());
        self.world.rosters.assign(tenancy, rosters.clone());

        let mut request = BuildRequest::new(tenancy, addresses);
        request.layouts = layouts.iter().map(|l| *l.publication.address()).collect();
        // Each survey is assigned to the cohort whose roster it uses, as the factory's journal would say.
        request.assignments = chosen
            .iter()
            .filter_map(|i| {
                let (_, roster) = self.content.rosters.iter().find(|(stem, _)| *stem == i.stem)?;
                let held = record.cohorts.iter().find(|c| c.cohort == roster.cohort)?;
                Some(BundleAssignment { survey: i.name.clone(), instrument: *i.publication.address(), cohort: roster.cohort.clone(), generation: held.generation })
            })
            .collect();
        let service = PolicyService::new(MemoryPolicySource::new(vec![self.release.clone()]), BuiltInPolicyEngine, MemoryDecisionLog::new());
        let built = self.world.build_with(&service, &request, unattested).map_err(err)?;

        // Intake learns which roster versions were issued, with their consent states.
        let inst_pubs: Vec<Publication> = chosen.iter().map(|i| i.publication.clone()).collect();
        let layout_pubs: Vec<Publication> = layouts.iter().map(|l| l.publication.clone()).collect();
        let referenced = check_composition(&artefacts_of(&inst_pubs), &artefacts_of(&layout_pubs), &[], &profile()).map_err(err)?;
        let already = fieldseal_intake::ports::RosterHistory::issued(&self.intake.rosters, &tenancy).map_err(err)?;
        for r in &rosters {
            let sent = r.restricted_to(&referenced);
            let address = Digest::from(*ContentAddress::of(&sent.encode()).as_bytes());
            if already.iter().any(|a| a.cohort == sent.cohort && a.version == sent.version && a.address == address) {
                continue;
            }
            self.intake.rosters.record(
                tenancy,
                IssuedRoster {
                    cohort: sent.cohort.clone(),
                    version: sent.version,
                    address,
                    issued_at: built.manifest.issued,
                    consent: sent
                        .entries
                        .iter()
                        .map(|e| {
                            let consent = match e.consent {
                                fieldseal_distribution::domain::ConsentState::Granted => IssuedConsent::Granted,
                                fieldseal_distribution::domain::ConsentState::Refused => IssuedConsent::Refused,
                                fieldseal_distribution::domain::ConsentState::Unknown => IssuedConsent::Unknown,
                            };
                            (intake_subject(e.subject.as_str()), consent)
                        })
                        .collect(),
                    covers: sent.consent_covers.iter().cloned().collect(),
                },
            );
        }
        Ok(BundleReport {
            bytes: built.sealed.bytes,
            development_allowance,
            instruments: built.manifest.instruments.len(),
            layouts: built.manifest.layouts.len(),
            rosters: built.manifest.rosters.len(),
        })
    }

    // -----------------------------------------------------------------------------------
    // Reports.

    /// Every published artefact (the baseline and release policies, the instruments and
    /// the layouts), each verified offline through the publishing context against the
    /// world's trust store and publishing policy.
    pub fn publications(&self) -> Vec<PublicationReport> {
        self.published.iter().map(|p| reports::publication_report(self.world, &p.publication)).collect()
    }

    /// The log's latest checkpoint and whether it verifies against the pinned log key.
    pub fn checkpoint(&self) -> CheckpointReport {
        let latest = self.published.iter().map(|p| &p.publication.checkpoint).max_by_key(|c| c.size()).expect("the demo publishes at least a policy");
        reports::checkpoint_report(self.world, latest)
    }

    /// Every log leaf and the artefact it logs, by leaf index.
    pub fn entries(&self) -> Vec<LogEntryReport> {
        let mut out: Vec<LogEntryReport> = Vec::new();
        for p in self.published.iter().map(|p| &p.publication) {
            for r in &p.log {
                if out.iter().any(|e| e.index == r.inclusion.leaf_index) {
                    continue;
                }
                out.push(LogEntryReport {
                    index: r.inclusion.leaf_index,
                    leaf_hash: lower_hex(fieldseal_publishing::domain::merkle::leaf_hash(&r.leaf.leaf(&r.entry)).as_bytes()),
                    kind: p.artefact.kind().as_str().to_owned(),
                    name: p.artefact.name().to_owned(),
                    version: p.artefact.version().to_owned(),
                    address: lower_hex(p.address().as_bytes()),
                    signer_key_id: lower_hex(r.entry.key_id().as_bytes()),
                });
            }
        }
        out.sort_by_key(|e| e.index);
        out
    }

    /// The tenancies in the demo registry, in identifier order.
    pub fn registrations(&self) -> Vec<RegistrationReport> {
        self.shared
            .store
            .known()
            .iter()
            .filter_map(|id| self.world.registry.tenancy(id).ok().flatten())
            .map(|r| RegistrationReport {
                tenancy: lower_hex(r.id.as_bytes()),
                state: r.state.as_str().to_owned(),
                keys_attested: r.keys_attested(),
                words: (r.state == TenancyState::Pending).then(|| r.words.joined()),
                label: self.world.registry.device(&r.device).ok().flatten().map(|d| d.nickname).filter(|n| !n.is_empty()),
                account: r.account.0.clone(),
                cohorts: r.cohorts.iter().map(|c| c.cohort.as_str().to_owned()).collect(),
                reasons: r.reasons.clone(),
                certificate: r.certificate.is_some(),
            })
            .collect()
    }

    /// Intake's side: the submission store, the data platform and the real gate.
    pub fn intake(&self) -> &IntakeWorld {
        &self.intake
    }

    /// The world's trust-anchored fingerprint of a published instrument, by name.
    pub fn fingerprint_of(&self, instrument: &str) -> Option<Fingerprint> {
        self.content.instruments.iter().find(|i| i.name == instrument).map(|i| i.fingerprint)
    }

    /// The cohort names the demo certifies for every registration.
    pub fn cohorts(&self) -> Vec<CohortId> {
        self.shared.config.terms.cohorts.iter().map(|c| c.cohort.clone()).collect()
    }
}

/// A subject as intake names it: the lower-case hex of the roster identifier's bytes, which
/// is how a record carries it on the wire (WIRE-050).
pub fn intake_subject(roster_id: &str) -> SubjectId {
    SubjectId::new(lower_hex(roster_id.as_bytes())).expect("hex is a valid subject ID")
}

const _: fn() = || {
    fn sync<T: Sync>() {}
    sync::<Demo>();
};
