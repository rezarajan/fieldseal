//! Test support for the end-to-end and fault-injection suites (issues #61 and #58).
//!
//! One authority ([`Site`]) stands up everything a deployment's factory side holds: the
//! root ceremony and purpose keys, a transparency log, the sample instrument published with
//! threshold signatures, the registration factory, the bundle builder and the registry. A
//! [`Phone`] is a simulated device (the in-memory platform adapters; Android is out of
//! scope). An [`Intake`] is the gate, the upload endpoint and a data platform over the same
//! keys. Everything is in process; every key is a software key and **unattested**, which the
//! tests say out loud wherever it matters.
//!
//! The pieces are the real ones: registration requests are built from the runtime's own
//! keys and answered by the real factory, bundles are sealed to the device and opened by the
//! runtime's opener, exports are signed by the runtime's key store and checked by the real
//! gate. Only the platform underneath (storage, clocks, key store, network) is simulated.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use fieldseal_adapters_authoring::{LoadedSurvey, SurveyTree};
use fieldseal_adapters_memory::bundle_opener::FileBundleOpener;
use fieldseal_adapters_memory::collection::{SIMULATION_T0, SimulatedDevice};
use fieldseal_adapters_memory::delivery::{MemoryFileAccess, MemoryPopLedger, MemoryPrivateStorage, MemoryRegistrationRecords, MemoryShareTarget};
use fieldseal_adapters_memory::demo::{DEMO_SCHEMA, DemoWorld, EdgeServices};
use fieldseal_adapters_memory::intake::{MemoryDataPlatform, MemoryInstrumentSource, MemoryRosterHistory, MemorySubmissionStore, MemoryTenancyRegistry};
use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog, MemoryPolicySource};
use fieldseal_adapters_memory::registration::{MemoryIdentityProvider, MemoryReceivedProgress, software_evidence};
use fieldseal_adapters_memory::trust::{FixedClock, SeededRandom, SoftwareAttestationVerifier};
use fieldseal_collection::application::{Platform, Provisioning, Runtime};
use fieldseal_collection::domain::bundle::{HeldRoster, OpenedBundle};
use fieldseal_collection::domain::RuntimePin;
use fieldseal_collection::domain::WindowId;
use fieldseal_collection::ports::{BundleOpenError, BundleOpener};
use fieldseal_delivery::domain::DestinationClass;
use fieldseal_delivery::ports::ShareOutcome;
use fieldseal_distribution::application::BuildRequest;
use fieldseal_distribution::domain::{ConsentState, Roster, RosterEntry, RuntimeProfile};
use fieldseal_instrument::application::validate_instrument;
use fieldseal_instrument::domain::Instrument;
use fieldseal_intake::domain::{IssuedConsent, IssuedRoster, TenancyView};
use fieldseal_intake::gate::IntakeService;
use fieldseal_intake::upload::UploadService;
use fieldseal_kernel::cbor;
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::crypto::P256PublicKey;
use fieldseal_kernel::id::{CohortId, Digest, Fingerprint, Generation, Salt, SubjectId, TenancyId};
use fieldseal_kernel::seal::SealedBox;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::Value;
use fieldseal_policy::application::PolicyService;
use fieldseal_policy::domain::{EffectivePolicy, PublishedPolicy, decode_document};
use fieldseal_policy::fixtures::{DocBuilder, effective, int};
use fieldseal_publishing::domain::{ArtefactKind, Publication};
use fieldseal_registration::application::{Factory, FactoryConfig, FactoryPorts, Submission};
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::domain::wire::{RequestBody, factory_sealing_key};
use fieldseal_registration::domain::{
    AuthenticatedPerson, CohortAssignment, FingerprintWords, KeyEvidence, MethodAssurance, NonceSource, RegistrationRoute, RegistrationToken, TenancyRecord, TenancyState, TenancyTerms, Window,
};
use fieldseal_registration::ports::RegistryStore;
use fieldseal_trust::domain::{AttestationClaims, AuthorityPublicKey, BootState, DeviceKeyKind, SecurityLevel};
use fieldseal_trust::ports::{SecureKeyStore, SourceRng};

/// The collector's PIN in every scenario.
pub const PIN: &str = "246810";

/// The root of the repository's survey folders, `examples/surveys/`.
pub fn examples() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples/surveys")
}

/// Loads the example survey `name` through the resolver: its expanded instrument and layouts.
pub fn survey(name: &str) -> LoadedSurvey {
    let tree = SurveyTree::open(&examples()).unwrap_or_else(|e| panic!("{e}"));
    let found = tree.survey(name).unwrap_or_else(|e| panic!("{e}"));
    found.load().unwrap_or_else(|errors| panic!("{name}: {}", errors.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n")))
}

/// The expanded layout of the example survey `name` for the window class `window`.
pub fn survey_layout(name: &str, window: &str) -> Value {
    survey(name).layouts.into_iter().find(|(w, _)| w == window).unwrap_or_else(|| panic!("{name} has no {window} layout")).1
}

/// The salt a survey is published with in the migration gate and the demo: a fixed function of
/// its name, so the salted fingerprint of an example is the same on every run.
pub fn pinned_salt(name: &str) -> Salt {
    DemoWorld::salt_for(name)
}

/// An expanded document as pretty-printed canonical JSON: keys sorted, two-space indent, a
/// final newline, bytes as lowercase hex text, decimals with every written digit.
pub fn expanded_json(value: &Value) -> String {
    fn text(out: &mut String, t: &str) {
        out.push('"');
        for c in t.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    fn write(out: &mut String, v: &Value, depth: usize) {
        let pad = |out: &mut String, d: usize| out.push_str(&"  ".repeat(d));
        match v {
            Value::Int(i) => out.push_str(&i.to_string()),
            Value::Decimal(d) => out.push_str(&d.to_string()),
            Value::Bytes(b) => text(out, &lower_hex(b)),
            Value::Text(t) => text(out, t),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Array(a) if a.is_empty() => out.push_str("[]"),
            Value::Array(a) => {
                out.push_str("[\n");
                for (i, e) in a.iter().enumerate() {
                    pad(out, depth + 1);
                    write(out, e, depth + 1);
                    out.push_str(if i + 1 < a.len() { ",\n" } else { "\n" });
                }
                pad(out, depth);
                out.push(']');
            }
            Value::Map(m) if m.is_empty() => out.push_str("{}"),
            Value::Map(m) => {
                out.push_str("{\n");
                for (i, (k, e)) in m.iter().enumerate() {
                    pad(out, depth + 1);
                    text(out, k);
                    out.push_str(": ");
                    write(out, e, depth + 1);
                    out.push_str(if i + 1 < m.len() { ",\n" } else { "\n" });
                }
                pad(out, depth);
                out.push('}');
            }
        }
    }
    let mut out = String::new();
    write(&mut out, value, 0);
    out.push('\n');
    out
}

/// The software profile every device reports: schema 1.0, no localisation.
pub fn profile() -> RuntimeProfile {
    RuntimeProfile { instrument_schema: DEMO_SCHEMA, localisation_reference: None }
}

/// The sample instrument: the household water-access example with consent required (so the
/// flow can exercise attestation), published once per [`Site`]. Languages are `en` and `es`.
pub fn sample_instrument_document() -> Value {
    let mut doc = survey("household-water-access").instrument;
    let meals = survey("school-meals-baseline").instrument;
    let consent = meals.as_map().and_then(|m| m.get("spec")).and_then(Value::as_map).and_then(|m| m.get("consent")).cloned().expect("school meals consent block");
    // The statement is shown in both languages the instrument is complete in.
    let consent = match consent {
        Value::Map(mut c) => {
            if let Some(Value::Map(s)) = c.get_mut("statement")
                && let Some(Value::Map(t)) = s.get_mut("text")
            {
                t.insert("es".into(), Value::Text("Confirmo que se dio el consentimiento para esta persona.".into()));
            }
            if let Some(Value::Array(bases)) = c.get_mut("bases") {
                for b in bases.iter_mut() {
                    if let Value::Map(b) = b
                        && let Some(Value::Map(l)) = b.get_mut("label")
                    {
                        l.insert("es".into(), Value::Text("Formulario firmado visto".into()));
                    }
                }
            }
            Value::Map(c)
        }
        other => other,
    };
    let Value::Map(root) = &mut doc else { panic!("an instrument is a map") };
    let Some(Value::Map(spec)) = root.get_mut("spec") else { panic!("a spec") };
    spec.insert("consent".into(), consent);
    doc
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// The factory side of a deployment, over in-memory adapters.
pub struct Site {
    /// Root, purpose keys, trust bundle, log, registry, builder.
    pub world: DemoWorld,
    /// The registration sealing key and the receiver.
    pub edge: EdgeServices,
    /// The sample instrument, published with both publishers' signatures and logged.
    pub instrument: Publication,
    /// Its compact layout.
    pub layout: Publication,
    /// The instrument as intake holds it.
    pub model: Instrument,
    /// The factory's effective policy.
    pub policy: EffectivePolicy,
    /// The release policy bundles are built under: published like any artefact, and
    /// allowing as many devices on a cohort as an account may register.
    pub release: PublishedPolicy,
    /// The factory's configuration (the cohorts it assigns to the next registration).
    pub config: FactoryConfig,
    /// The factory's clock; tokens expire on it (REG-006).
    pub clock: FixedClock,
    /// The people who may sign in.
    pub idp: MemoryIdentityProvider,
    verifier: SoftwareAttestationVerifier,
    engine: BuiltInPolicyEngine,
    log: MemoryDecisionLog,
    progress: MemoryReceivedProgress,
    random: SeededRandom,
}

impl Site {
    /// A site derived from `seed`, with at most `max_devices` devices per account.
    pub fn new(seed: u64, max_devices: i128) -> Self {
        let mut world = DemoWorld::new(seed, SIMULATION_T0).expect("the root ceremony and purpose keys");
        let edge = world.add_edge_services(&["fieldseal-simulator"]).expect("edge services");

        let doc = sample_instrument_document();
        validate_instrument(&doc).unwrap_or_else(|f| panic!("the sample instrument is valid: {:?}", f.iter().collect::<Vec<_>>()));
        let model = validate_instrument(&doc).expect("valid").instrument;
        let meta = |d: &Value, k: &str| d.as_map().and_then(|m| m.get("metadata")).and_then(Value::as_map).and_then(|m| m.get(k)).and_then(Value::as_text).expect("metadata").to_owned();
        let instrument = world
            .publish(ArtefactKind::Instrument, &meta(&doc, "name"), &meta(&doc, "version"), cbor::encode(&doc).expect("encodes"), Some(DemoWorld::salt_for(&meta(&doc, "name"))))
            .expect("the instrument publishes with both publishers' signatures");
        // A layout names its instrument by fingerprint once canonicalised (INS-200).
        let mut layout_doc = survey_layout("household-water-access", "compact");
        if let Value::Map(root) = &mut layout_doc
            && let Some(Value::Map(spec)) = root.get_mut("spec")
        {
            spec.insert("instrument".into(), Value::Bytes(instrument.address().as_bytes().to_vec()));
        }
        let layout = world
            .publish(ArtefactKind::Layout, &meta(&layout_doc, "name"), &meta(&layout_doc, "version"), cbor::encode(&layout_doc).expect("encodes"), None)
            .expect("the layout publishes");

        let release_value = DocBuilder::deployment("e2e-release", "1.0.0").set("factory.cohorts.maxActiveTenanciesPerCohort", int(max_devices)).build();
        let release_publication = world
            .publish(ArtefactKind::Policy, "e2e-release", "1.0.0", cbor::encode(&release_value).expect("encodes"), None)
            .expect("the release policy publishes");
        let release = PublishedPolicy { address: *release_publication.address(), document: {
                let decoded = decode_document(&release_value);
                decoded.document.unwrap_or_else(|| panic!("a valid policy document: {:?}", decoded.findings))
            },
        };

        let policy = effective(&[DocBuilder::deployment("e2e", "1.0.0").set("factory.registration.maxDevicesPerAccount", int(max_devices)).build()]);
        let record_certificate = world.trust.certificates().iter().find(|c| c.key_id() == &world.record.id).expect("the record key is certified").clone();
        let config = FactoryConfig {
            factory_url: "https://factory.example.org".into(),
            signing_key: world.registration,
            sealing_key: edge.sealing.id,
            terms: TenancyTerms {
                record_key: world.record.id,
                window: Window { not_before: record_certificate.not_before(), not_after: record_certificate.not_after(), grace_ms: 30 * AuthorityTime::DAY },
                cohorts: vec![],
            },
            unattested: UnattestedKeys::AllowNonProduction,
            posture_nonce_ttl_ms: 10 * 60_000,
            access_token_ttl_ms: 10 * 60_000,
        };
        let idp = MemoryIdentityProvider::new();
        idp.add("alice", "sub-alice", &["collector"], &["hwk", "user"], MethodAssurance::FromProvider);
        idp.add("bob", "sub-bob", &["collector"], &["hwk", "user"], MethodAssurance::FromProvider);
        let clock = FixedClock::new(world.now);
        Self {
            world,
            edge,
            instrument,
            layout,
            model,
            policy,
            release,
            config,
            clock,
            idp,
            verifier: SoftwareAttestationVerifier,
            engine: BuiltInPolicyEngine,
            log: MemoryDecisionLog::new(),
            progress: MemoryReceivedProgress::new(),
            random: SeededRandom::new(seed ^ 0xfac7),
        }
    }

    /// The instrument's fingerprint, as intake and records name it.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from(*self.instrument.address().as_bytes())
    }

    /// Sets the cohorts (each at the given generation) the next registrations are certified for.
    pub fn set_cohorts(&mut self, cohorts: &[(&str, u32)]) {
        self.config.terms.cohorts =
            cohorts.iter().map(|(c, g)| CohortAssignment { cohort: CohortId::new(*c).expect("cohort"), generation: Generation(*g) }).collect();
    }

    /// Online registration, end to end: the portal issues a token to `login`, the phone builds
    /// its request from the runtime's keys, the factory accepts it as pending, the
    /// collector confirms the same four words on both screens (REG-021) and the tenancy is
    /// registered. Marks the keys attested (see [`Site::simulate_attestation`]).
    pub fn register_online(&self, phone: &Phone, rt: &Runtime<'_>, login: &str, label: &str) -> TenancyRecord {
        let person = self.person(login);
        let token = self.factory().issue_token(&person, RegistrationRoute::Online, 1).expect("a token");
        let (sealed, words) = phone.registration_request(self, rt, &token.token, label).expect("a request");
        let submitted = self.factory().submit(&sealed, Submission::Online).expect("the factory accepts the request");
        assert_eq!(submitted.words, words, "REG-020: both sides show the same four words");
        assert_eq!(submitted.tenancy.state, TenancyState::Pending, "REG-021: nothing registers before the words are confirmed");
        let record = self.factory().confirm(&person.account, &submitted.tenancy.id).expect("the words are confirmed");
        assert_eq!(record.state, TenancyState::Registered);
        self.simulate_attestation(&record.id);
        self.record(&record.id)
    }

    /// Everything between a fresh phone and a registered device holding its bundle: the
    /// runtime creates its tenancy, registers online as `login` (words confirmed), receives
    /// `rosters`, and imports the bundle the factory builds and seals to it. Call
    /// [`Site::set_cohorts`] first: the registration certifies those cohorts.
    pub fn enrol<'a>(&'a self, phone: &'a Phone, opener: &'a Opener<'a>, login: &str, label: &str, rosters: Vec<Roster>) -> Runtime<'a> {
        let site = self;
        let mut rt = phone.runtime(site, opener);
        rt.create_tenancy(&RuntimePin::new(PIN).expect("pin")).expect("create tenancy");
        let tenancy = rt.tenancy().expect("tenancy");
        opener.tenancy.set(Some(tenancy));
        site.register_online(phone, &rt, login, label);
        site.assign(tenancy, rosters);
        rt.import_bundle(&site.build_bundle(tenancy).expect("the bundle builds")).expect("the device imports its bundle");
        rt
    }

    /// The registration factory over the site's registry, custody and trust bundle.
    pub fn factory(&self) -> Factory<'_> {
        Factory::new(
            FactoryPorts {
                store: &self.world.registry,
                custody: &self.world.custody,
                verifiers: vec![&self.verifier],
                engine: &self.engine,
                log: &self.log,
                clock: &self.clock,
                random: &self.random,
                progress: &self.progress,
                fleet: None,
                notifier: None,
            },
            &self.world.trust,
            &self.policy,
            &self.config,
        )
        .expect("the factory's keys are in the trust bundle")
    }

    /// A signed-in collector.
    pub fn person(&self, login: &str) -> AuthenticatedPerson {
        self.idp.person(login).expect("a known person")
    }

    /// Issues a registration token on the online or air-gapped route (REG-004).
    pub fn token(&self, login: &str, route: RegistrationRoute) -> Result<fieldseal_registration::domain::IssuedToken, fieldseal_registration::application::RegistrationError> {
        self.factory().issue_token(&self.person(login), route, 1)
    }

    /// Gives the tenancy's keys hardware-attestation claims in the registry, as `bundle build
    /// --simulated-attestation` does: the software keys are unattested, and the release
    /// policy withholds rosters from unattested keys (DIS-002), so a scenario that needs
    /// rosters marks them. Production policy never accepts this (TRU-061).
    pub fn simulate_attestation(&self, tenancy: &TenancyId) {
        let mut record = self.world.registry.tenancy(tenancy).expect("registry").expect("a tenancy");
        for key in &mut record.keys {
            key.claims = Some(AttestationClaims {
                security_level: SecurityLevel::Tee,
                origin_generated: true,
                kind: key.kind,
                unlocked_required: Some(true),
                challenge: fieldseal_kernel::id::Nonce::from([0; 32]),
                app_id: Some("fieldseal-simulator".to_owned()),
                app_version: Some("1.0.0".to_owned()),
                os_patch_level: None,
                boot_state: Some(BootState::Verified),
                bootloader_locked: Some(true),
                device_serial: None,
            });
        }
        self.world.registry.put_tenancy(&record).expect("registry");
    }

    /// What the registry holds for a tenancy.
    pub fn record(&self, tenancy: &TenancyId) -> TenancyRecord {
        self.world.registry.tenancy(tenancy).expect("registry").expect("a tenancy")
    }

    /// Declares what the runtime reported and which rosters the tenancy is to receive.
    pub fn assign(&self, tenancy: TenancyId, rosters: Vec<Roster>) {
        self.world.profiles.record(tenancy, profile());
        self.world.rosters.assign(tenancy, rosters);
    }

    /// The request that builds the next bundle: the sample instrument and its layout.
    pub fn bundle_request(&self, tenancy: TenancyId) -> BuildRequest {
        let mut request = BuildRequest::new(tenancy, vec![*self.instrument.address()]);
        request.layouts = vec![*self.layout.address()];
        request
    }

    /// Builds and seals the next bundle for the tenancy; the bytes are the file.
    pub fn build_bundle(&self, tenancy: TenancyId) -> Result<Vec<u8>, fieldseal_distribution::domain::DistributionError> {
        let service = PolicyService::new(MemoryPolicySource::new(vec![self.release.clone()]), BuiltInPolicyEngine, MemoryDecisionLog::new());
        self.world.build(&service, &self.bundle_request(tenancy)).map(|b| b.sealed.bytes)
    }

    /// The runtime's provisional record key: what records seal to before a certificate names
    /// the real one.
    fn record_key(&self) -> [u8; 32] {
        let AuthorityPublicKey::X25519(k) = self.world.record.public_key.clone() else { panic!("an X25519 record key") };
        k
    }

    /// The time a device opens bundles at: two days after the world's present, inside every
    /// factory signature's validity.
    pub fn device_now(&self) -> AuthorityTime {
        AuthorityTime(self.world.now.0 + 2 * AuthorityTime::DAY)
    }
}

/// A roster of two or more subjects in one cohort. `attributes` carries `head_name`, the
/// roster field the instrument reads.
pub fn roster(cohort: &str, version: u64, generation: u32, subjects: &[(&str, ConsentState)]) -> Roster {
    Roster {
        cohort: CohortId::new(cohort).expect("cohort"),
        version,
        generation: Generation(generation),
        entries: subjects
            .iter()
            .enumerate()
            .map(|(i, (s, consent))| RosterEntry {
                ordinal: i as u32 + 1,
                subject: SubjectId::new(*s).expect("subject"),
                display: format!("Household {}", i + 1),
                attributes: BTreeMap::from([("head_name".to_owned(), Value::Text(format!("Head {}", i + 1))), ("internal_note".to_owned(), Value::Text("never reaches a device".into()))]),
                consent: *consent,
                prior_status: None,
            })
            .collect(),
    }
}

/// Opens bundles for one simulated device. The tenancy is known once the runtime has made
/// it; `extra_withdrawals` lets a test play "a later bundle carries a withdrawal".
pub struct Opener<'a> {
    site: &'a Site,
    device: &'a SimulatedDevice,
    /// The tenancy the runtime created.
    pub tenancy: Cell<Option<TenancyId>>,
    /// Withdrawals to add to whatever the bundle carries.
    pub extra_withdrawals: RefCell<Vec<fieldseal_publishing::domain::Withdrawal>>,
    /// A change applied to every bundle after it is opened: what a hostile or faulty
    /// factory could have put in a bundle that still verifies as a file.
    #[allow(clippy::type_complexity)]
    pub tamper: RefCell<Option<Box<dyn Fn(&mut OpenedBundle)>>>,
}

impl<'a> Opener<'a> {
    /// An opener for `device`, whose tenancy is not yet known.
    pub fn new(site: &'a Site, device: &'a SimulatedDevice) -> Self {
        Self { site, device, tenancy: Cell::new(None), extra_withdrawals: RefCell::default(), tamper: RefCell::new(None) }
    }
}

impl BundleOpener for Opener<'_> {
    fn open(&self, file: &[u8]) -> Result<OpenedBundle, BundleOpenError> {
        let key = self.device.keys.agreement_key().ok_or_else(|| BundleOpenError::Rejected("no agreement key yet".into()))?;
        let now = || self.site.device_now();
        let tenancy = self.tenancy.get().ok_or_else(|| BundleOpenError::Rejected("no tenancy yet".into()))?;
        let mut opened = FileBundleOpener::new(&self.site.world.trust, &self.site.world.publishing, &key, tenancy, profile(), &now).open(file)?;
        opened.withdrawals.extend(self.extra_withdrawals.borrow().iter().cloned());
        if let Some(f) = self.tamper.borrow().as_ref() {
            f(&mut opened);
        }
        Ok(opened)
    }
}

/// A simulated device and the windows its shell shows.
pub struct Phone {
    /// The platform adapters, with their fault-injection hooks.
    pub device: SimulatedDevice,
    windows: Vec<WindowId>,
}

impl Phone {
    /// A fresh phone whose keys and randomness come from `seed`.
    pub fn new(seed: u64) -> Self {
        Self { device: SimulatedDevice::new(seed), windows: vec![WindowId("capture".into()), WindowId("review".into()), WindowId("delivery".into())] }
    }

    /// What provisioning gives the runtime.
    pub fn provisioning<'a>(&'a self, site: &'a Site) -> Provisioning<'a> {
        Provisioning {
            trust: &site.world.trust,
            publishing: &site.world.publishing,
            build_anchor: Digest::from([0xbb; 32]),
            provisional_record_key: site.record_key(),
            windows: &self.windows,
        }
    }

    /// Loads (or reloads after a restart) the runtime over the phone's storage.
    pub fn runtime<'a>(&'a self, site: &'a Site, opener: &'a Opener<'a>) -> Runtime<'a> {
        let platform = Platform { bundles: opener, ..self.device.platform() };
        Runtime::load(platform, self.provisioning(site)).expect("the runtime loads")
    }

    /// Builds the registration request for `token` from the runtime's own keys, signs the
    /// proof of possession in the key store and seals it to the factory's registration key
    /// (WIRE-130..134). The words the collector confirms are returned with it.
    pub fn registration_request(&self, site: &Site, rt: &Runtime<'_>, token: &RegistrationToken, label: &str) -> Result<(SealedBox, FingerprintWords), String> {
        token.verify(&site.world.trust).map_err(err)?;
        let sign_pub = rt.key_history().remove(0);
        let agree_pub = self.device.keys.agreement_public().ok_or("the device has no agreement key yet")?;
        let body = RequestBody {
            token: token.secret,
            nonce: token.nonce,
            nonce_source: NonceSource::Factory,
            sign_pub: sign_pub.clone(),
            agree_pub: agree_pub.clone(),
            evidence: vec![
                KeyEvidence { kind: DeviceKeyKind::Signing, evidence: software_evidence(DeviceKeyKind::Signing, true, &token.nonce, &sign_pub) },
                KeyEvidence { kind: DeviceKeyKind::Agreement, evidence: software_evidence(DeviceKeyKind::Agreement, true, &token.nonce, &agree_pub) },
            ],
            build: "fieldseal-simulator/0.1.0".into(),
            prev_closing: None,
            label: Some(label.to_owned()),
        };
        let handle = self.device.keys.signing_handle(&sign_pub).ok_or("the signing key is not in the key store")?;
        let pop = self.device.keys.sign(&handle, &body.pop_message()).map_err(err)?;
        let factory = factory_sealing_key(&site.world.trust, token.issued_at).ok_or("the trust bundle certifies no registration key")?;
        let sealed = body.seal(&mut SourceRng(&self.device.random), &factory, &pop, None).map_err(err)?;
        let words = FingerprintWords::from_body_digest(&body.digest());
        Ok((sealed, words))
    }
}

/// The gate, the upload endpoint and a data platform over a [`Site`]'s keys.
pub struct Intake {
    /// Raw submissions, write-once.
    pub store: MemorySubmissionStore,
    /// Registered tenancies.
    pub registry: MemoryTenancyRegistry,
    /// Rosters as issued.
    pub rosters: MemoryRosterHistory,
    /// Published instruments.
    pub instruments: MemoryInstrumentSource,
    /// Where landed data goes: raw envelopes and the long-format observations.
    pub platform: MemoryDataPlatform,
    /// Token replay protection.
    pub ledger: MemoryPopLedger,
    engine: BuiltInPolicyEngine,
    effective: EffectivePolicy,
    random: SeededRandom,
    names: Vec<String>,
}

/// What intake is told about one registered device: the registry's view plus the rosters
/// the device holds.
pub struct Enrolled {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The signing key history.
    pub keys: Vec<P256PublicKey>,
    /// The rosters held, with their consent states.
    pub rosters: Vec<HeldRoster>,
    /// The tenancy this one succeeds, if the collector replaced a device (INT-054).
    pub predecessor: Option<TenancyId>,
}

impl Enrolled {
    /// What intake learns about the device behind `rt`: its tenancy, key history and the
    /// rosters it holds.
    pub fn of(rt: &Runtime<'_>) -> Self {
        Self { tenancy: rt.tenancy().expect("a tenancy"), keys: rt.key_history(), rosters: rt.held().map(|h| h.rosters.clone()).unwrap_or_default(), predecessor: None }
    }
}

impl Intake {
    /// An intake that knows `devices`, with the sample instrument published.
    pub fn new(site: &Site, devices: &[Enrolled]) -> Self {
        let views = devices
            .iter()
            .map(|d| {
                let mut view = TenancyView::new(d.tenancy, site.record(&d.tenancy).handle, d.keys.clone());
                view.predecessor = d.predecessor;
                view
            })
            .collect();
        let instruments = MemoryInstrumentSource::new();
        instruments.add(site.fingerprint(), site.model.clone());
        let rosters = MemoryRosterHistory::new();
        for d in devices {
            for r in &d.rosters {
                rosters.record(
                    d.tenancy,
                    IssuedRoster {
                        cohort: r.cohort.clone(),
                        version: r.version,
                        address: r.address,
                        issued_at: site.world.now,
                        consent: r
                            .subjects
                            .iter()
                            .map(|s| {
                                (
                                    intake_subject(s.subject.as_str()),
                                    match s.consent {
                                        ConsentState::Granted => IssuedConsent::Granted,
                                        ConsentState::Refused => IssuedConsent::Refused,
                                        ConsentState::Unknown => IssuedConsent::Unknown,
                                    },
                                )
                            })
                            .collect(),
                    },
                );
            }
        }
        Self {
            store: MemorySubmissionStore::new(),
            registry: MemoryTenancyRegistry::new(views),
            rosters,
            instruments,
            platform: MemoryDataPlatform::new(),
            ledger: MemoryPopLedger::new(),
            engine: BuiltInPolicyEngine,
            effective: fieldseal_policy::fixtures::effective_default(),
            random: SeededRandom::new(99),
            names: ["http://intake.loopback", "https://intake.authority.example"].iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    /// The verification gate.
    pub fn gate<'a>(&'a self, site: &'a Site) -> IntakeService<'a> {
        IntakeService {
            store: &self.store,
            registry: &self.registry,
            rosters: &self.rosters,
            instruments: &self.instruments,
            platform: &self.platform,
            custody: &site.world.custody,
            policy: &self.engine,
            effective: &self.effective,
            random: &self.random,
            trust: &site.world.trust,
            revocations: vec![],
            receipt_key: site.world.receipt,
            caller: "intake-upload",
        }
    }

    /// The upload endpoint over `gate`: receiver challenge, proof-of-possession tokens, then
    /// the gate (DEL-002, DEL-062).
    pub fn upload<'a>(&'a self, site: &'a Site, gate: &'a IntakeService<'a>) -> UploadService<'a, 'a> {
        UploadService {
            intake: gate,
            ledger: &self.ledger,
            receiver_key: site.edge.receiver,
            receiver_certificate: &site.edge.receiver_certificate,
            public_urls: &self.names,
        }
    }
}

/// What a device can write to and hand over to, for delivery tests.
pub struct Couriers {
    /// A removable disk.
    pub removable: MemoryFileAccess,
    /// The system share sheet.
    pub share: MemoryShareTarget,
    /// The app's private storage, where exports are built.
    pub storage: MemoryPrivateStorage,
    /// The registration documents a manifest carries.
    pub records: MemoryRegistrationRecords,
}

impl Couriers {
    /// Fresh destinations.
    pub fn new() -> Self {
        Self {
            removable: MemoryFileAccess::new(DestinationClass::Removable),
            share: MemoryShareTarget(ShareOutcome::Shared),
            storage: MemoryPrivateStorage::new(),
            records: MemoryRegistrationRecords::new(),
        }
    }
}

impl Default for Couriers {
    fn default() -> Self {
        Self::new()
    }
}

/// The time the delivery side runs at: twenty days after the epoch, as the phone's wall
/// clock reads.
pub fn now() -> AuthorityTime {
    AuthorityTime(SIMULATION_T0.0 + 20 * AuthorityTime::DAY)
}

/// A delivery service over `$transport` and the courier destinations `$files`, trusting the
/// site's receiver and receipt keys. Binds `$svc`.
#[macro_export]
macro_rules! delivery {
    ($site:expr, $phone:expr, $couriers:expr, $files:expr, $policy:expr, $transport:expr, $svc:ident) => {
        let receiver = ::fieldseal_delivery::checks::TrustReceiverCheck::new(::fieldseal_trust::domain::TrustStore::new(&$site.world.trust), $crate::now());
        let receipts = ::fieldseal_delivery::checks::TrustReceiptCheck::new(::fieldseal_trust::domain::TrustStore::new(&$site.world.trust));
        let mut $svc = ::fieldseal_delivery::application::DeliveryService::new(
            ::fieldseal_delivery::application::Ports {
                keys: &$phone.device.keys,
                random: &$phone.device.random,
                wall: &$phone.device.wall,
                transport: $transport,
                receiver: &receiver,
                receipts: &receipts,
                files: $files,
                share: &$couriers.share,
                storage: &$couriers.storage,
                records: &$couriers.records,
            },
            &$policy,
        );
    };
}

/// A text value.
pub fn text(s: &str) -> Value {
    Value::Text(s.into())
}

/// A nonresponse answer: the subject refused or didn't know (INS-072).
pub fn nr(code: &str) -> Value {
    cbor::map([("nr", text(code))])
}

/// The answers a complete household visit gives, in the order they are entered.
pub fn household_answers(members: i128) -> Vec<(&'static str, Value)> {
    vec![
        ("household.members", Value::Int(members)),
        ("water.source", text("standpipe")),
        ("water.minutes_to_source", Value::Int(20)),
        ("water.litres_per_day", Value::Int(150)),
        ("water.treatments", Value::Array(vec![text("boil")])),
        ("water.monthly_cost", nr("refused")),
        ("sanitation.toilet.type", text("pit_slab")),
        ("sanitation.toilet.sharing.shared", Value::Bool(false)),
        ("hygiene.handwashing_place", text("fixed")),
        ("hygiene.soap_seen", Value::Bool(true)),
    ]
}

/// Captures a full first visit to `subject` (consent already on record or not required),
/// acknowledges what was left unanswered and seals it; returns the record's `seq`.
pub fn capture_household(rt: &mut Runtime<'_>, subject: &str, members: i128) -> fieldseal_kernel::id::Seq {
    use fieldseal_collection::application::CaptureMode;
    rt.start_capture(&SubjectId::new(subject).expect("subject"), CaptureMode::First).expect("start");
    for (p, v) in household_answers(members) {
        rt.set_value(&fieldseal_kernel::id::ItemPath::new(p).expect("path"), v).unwrap_or_else(|e| panic!("{p}: {e}"));
    }
    let n = rt.capture_view().expect("view").unanswered.len();
    rt.acknowledge_incomplete(n).expect("ack");
    rt.seal().expect("seal")
}

/// A subject as intake names it: the lower-case hex of the ID's bytes, which is how a record
/// carries it on the wire (WIRE-050). The roster's `h-002` is `682d303032` at intake.
pub fn intake_subject(roster_id: &str) -> SubjectId {
    SubjectId::new(fieldseal_kernel::digest::lower_hex(roster_id.as_bytes())).expect("hex is a valid subject ID")
}

/// The roster every scenario uses: `village-a` with one subject whose consent is unknown, two
/// who agreed and one who refused.
pub fn village_a() -> Roster {
    roster("village-a", 1, 1, &[("h-001", ConsentState::Unknown), ("h-002", ConsentState::Granted), ("h-003", ConsentState::Refused), ("h-004", ConsentState::Granted)])
}

/// A scratch directory that disappears with the test: the "files" of the air-gapped flow
/// are real files.
pub struct Scratch(std::path::PathBuf);

impl Scratch {
    /// A fresh directory named for the test.
    pub fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("fieldseal-e2e-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        Self(dir)
    }

    /// Writes `bytes` to `name` and returns the path.
    pub fn write(&self, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, bytes).expect("write");
        p
    }

    /// Reads `name` back.
    pub fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.0.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Sets up one registered device in the caller's scope: a site with one cohort, a phone, the
/// phone's opener and a runtime holding its bundle. Binds `$site`, `$phone`, `$opener`,
/// `$rt`.
#[macro_export]
macro_rules! device {
    ($seed:expr => $site:ident, $phone:ident, $opener:ident, $rt:ident) => {
        let mut $site = $crate::Site::new($seed, 2);
        $site.set_cohorts(&[("village-a", 1)]);
        let $phone = $crate::Phone::new($seed + 1000);
        let $opener = $crate::Opener::new(&$site, &$phone.device);
        #[allow(unused_mut)]
        let mut $rt = $site.enrol(&$phone, &$opener, "alice", "phone", vec![$crate::village_a()]);
    };
}

/// Runs `run(k)` for every `k` in `0..steps`, spread over the machine's cores. Each call
/// builds its own world, so nothing is shared between threads; a failure in any of them
/// fails the test. Fault injection at every storage step is many whole flows, and in an
/// unoptimised build the cryptography makes each one slow.
pub fn every_cut(steps: u64, run: impl Fn(u64) + Sync) {
    let workers = std::thread::available_parallelism().map_or(2, |n| n.get()).min(8) as u64;
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|w| {
                let run = &run;
                scope.spawn(move || {
                    let mut k = w;
                    while k < steps {
                        run(k);
                        k += workers;
                    }
                })
            })
            .collect();
        for h in handles {
            if let Err(panic) = h.join() {
                std::panic::resume_unwind(panic);
            }
        }
    });
}
