//! A factory world for the reconciler tests: the in-memory demo authority (memory-dev
//! custody), file stores for bundles and issued rosters in a scratch directory, and helpers
//! that publish artefacts, register devices, assign surveys and open what was built.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fieldseal_adapters_file::bundles::FileBundleStore;
use fieldseal_adapters_memory::demo::{DEMO_SCHEMA, DemoDevice, DemoWorld};
use fieldseal_adapters_memory::trust::FixedClock;
use fieldseal_distribution::domain::{BundleContent, BundleFile, ConsentState, MAX_BUNDLE_FILE, Roster, RosterEntry, RuntimeProfile, SealedBundle};
use fieldseal_distribution::ports::{AgreementKey, BundleStore};
use fieldseal_factory::config::PolicyTrust;
use fieldseal_factory::reconciler::{BuildWriteHook, ReconcileEvent, Reconciler, ReconcilerConfig, ReconcilerPorts};
use fieldseal_instrument::domain::SchemaVersion;
use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::tags;
use fieldseal_kernel::id::{CohortId, ContentAddress, Generation, SubjectId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::value::Value;
use fieldseal_policy::fixtures::{DocBuilder, words};
use fieldseal_publishing::domain::{ArtefactKind, Publication};
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_kernel::id::Seq;
use fieldseal_registration::domain::{AccountId, Assignment};
use fieldseal_registration::ports::RegistryStore;

pub const T0: AuthorityTime = AuthorityTime(1_800_000_000_000);
pub const HOUR: u64 = 3_600_000;

pub struct Env {
    pub world: DemoWorld,
    pub clock: FixedClock,
    pub dir: PathBuf,
    pub bundles: FileBundleStore,
    pub events: Arc<Mutex<Vec<ReconcileEvent>>>,
    /// The first `deployment-policy` published.
    pub policy: Publication,
    /// Paths the reconciler watches (none unless a test names them).
    pub watch: Vec<PathBuf>,
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// An instrument that needs schema range `schema` and reads the roster field `age`.
pub fn instrument_bytes(name: &str, version: &str, schema: &str) -> Vec<u8> {
    cbor::encode(&cbor::map([
        ("apiVersion", text("fieldseal.dev/v1alpha1")),
        ("kind", text("Instrument")),
        ("metadata", cbor::map([("name", text(name)), ("version", text(version))])),
        (
            "spec",
            cbor::map([
                ("schema", text(schema)),
                ("items", Value::Array(vec![cbor::map([("label", text("Age {$roster.age}")), ("from", text("roster.age"))])])),
            ]),
        ),
    ]))
    .expect("encodes")
}

pub fn layout_bytes(instrument: &ContentAddress, class: &str, version: &str) -> Vec<u8> {
    cbor::encode(&cbor::map([
        ("kind", text("Layout")),
        ("metadata", cbor::map([("version", text(version))])),
        ("spec", cbor::map([("instrument", Value::Bytes(instrument.as_bytes().to_vec())), ("schema", text("^1.0")), ("windowClass", text(class))])),
    ]))
    .expect("encodes")
}

pub fn roster(cohort: &str, version: u64, generation: u32) -> Roster {
    let entry = |ordinal: u32, subject: &str, consent| RosterEntry {
        ordinal,
        subject: SubjectId::new(subject).expect("id"),
        display: format!("Person {ordinal}"),
        attributes: BTreeMap::from([("age".to_owned(), Value::Int(9)), ("district".to_owned(), text("North"))]),
        consent,
        prior_status: None,
    };
    Roster {
        cohort: CohortId::new(cohort).expect("id"),
        version,
        generation: Generation(generation),
        entries: vec![entry(1, "s-001", ConsentState::Granted), entry(2, "s-002", ConsentState::Unknown)],
        consent_covers: vec!["survey-a".to_owned()],
    }
}

pub fn profile(schema: SchemaVersion) -> RuntimeProfile {
    RuntimeProfile { instrument_schema: schema, localisation_reference: None }
}

impl Env {
    /// A world with the deployment policy published (layouts `bound`).
    pub fn new(name: &str) -> Self {
        Self::with_layouts(name, None)
    }

    pub fn with_layouts(name: &str, layouts: Option<&str>) -> Self {
        let dir = std::env::temp_dir().join(format!("fieldseal-factory-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let world = DemoWorld::new(1, T0).expect("world");
        let policy = Self::policy_bytes(&world, "1.0.0", layouts);
        Self {
            world,
            policy,
            clock: FixedClock::new(AuthorityTime(T0.0 + 24 * HOUR)),
            bundles: FileBundleStore::new(dir.join("bundles")),
            dir,
            events: Arc::default(),
            watch: Vec::new(),
        }
    }

    /// Publishes the `deployment-policy` the factory reads. The demo world's builder and
    /// source are the ones its publications carry.
    pub fn publish_policy(&self, version: &str, layouts: Option<&str>) -> Publication {
        Self::policy_bytes(&self.world, version, layouts)
    }

    fn policy_bytes(world: &DemoWorld, version: &str, layouts: Option<&str>) -> Publication {
        let mut doc = DocBuilder::deployment("deployment-policy", version)
            .set("publishing.allowedBuilders", words(&["https://ci.example.org/builders/fieldseal-demo"]))
            .set("publishing.allowedSources", words(&["https://git.example.org/authority/artefacts"]));
        if let Some(l) = layouts {
            doc = doc.set("factory.release.layouts", Value::Text(l.into()));
        }
        world.publish(ArtefactKind::Policy, "deployment-policy", version, cbor::encode(&doc.build()).expect("encodes"), None).expect("publishes")
    }

    pub fn instrument(&self, survey: &str, version: &str, schema: &str) -> Publication {
        self.world.publish(ArtefactKind::Instrument, survey, version, instrument_bytes(survey, version, schema), Some(DemoWorld::salt_for(survey))).expect("publishes")
    }

    pub fn layout(&self, survey: &str, window: &str, version: &str, instrument: &Publication) -> Publication {
        self.world.publish(ArtefactKind::Layout, &format!("{survey}-{window}"), version, layout_bytes(instrument.address(), window, version), None).expect("publishes")
    }

    /// Registers a device (attested, so policy releases rosters) that reports `schema`.
    pub fn device(&self, label: &str, cohorts: &[(&str, u32)], schema: SchemaVersion) -> DemoDevice {
        self.world.register(label, cohorts, true, profile(schema)).expect("registers")
    }

    pub fn account(label: &str) -> AccountId {
        AccountId(format!("account-{label}"))
    }

    /// Journals an assignment of `survey` to the device's account.
    pub fn assign(&self, label: &str, survey: &str, cohort: &str, generation: u32) {
        self.world
            .registry
            .put_assignment(&Assignment {
                seq: Seq(0),
                account: Self::account(label),
                survey: survey.into(),
                cohort: CohortId::new(cohort).expect("cohort"),
                generation: Generation(generation),
                by: AccountId("operator".into()),
                roles: vec!["operator".into()],
                methods: vec!["phr".into()],
                at: AuthorityTime(0),
            })
            .expect("journal");
    }

    pub fn reconciler(&self) -> Reconciler<'_> {
        self.reconciler_with(None)
    }

    /// A reconciler of a factory that does not allow unattested keys (the production setting).
    pub fn reconciler_strict(&self) -> Reconciler<'_> {
        self.build_reconciler(None, UnattestedKeys::Refuse)
    }

    pub fn reconciler_with(&self, hook: Option<Box<dyn BuildWriteHook>>) -> Reconciler<'_> {
        self.build_reconciler(hook, UnattestedKeys::AllowNonProduction)
    }

    fn build_reconciler(&self, hook: Option<Box<dyn BuildWriteHook>>, unattested: UnattestedKeys) -> Reconciler<'_> {
        let w = &self.world;
        let identity = w.identity();
        let events = self.events.clone();
        let r = Reconciler::new(
            ReconcilerPorts {
                registry: &w.registry,
                artefacts: &w.artefacts,
                rosters: &w.rosters,
                profiles: &w.profiles,
                bundles: &self.bundles,
                custody: &w.custody,
                random: &w.random,
                clock: &self.clock,
            },
            ReconcilerConfig {
                trust: w.trust.clone(),
                identity: fieldseal_distribution::application::FactoryIdentity { unattested, ..identity },
                receipt: w.receipt,
                bundle_dir: self.dir.join("bundles"),
                issued_rosters_dir: self.dir.join("issued"),
                max_anchor_age_ms: 24 * HOUR,
                policy_trust: PolicyTrust::Allowlists { builders: w.publishing.allowed_builders.clone(), sources: w.publishing.allowed_sources.clone() },
                state_dir: None,
                watch: self.watch.clone(),
            },
            Arc::new(move |e| events.lock().expect("lock").push(e.clone())),
        );
        match hook {
            Some(h) => r.with_hook(h),
            None => r,
        }
    }

    pub fn latest(&self, device: &DemoDevice) -> Option<SealedBundle> {
        self.bundles.latest(&device.tenancy).expect("store")
    }

    /// Opens a stored bundle as its device would.
    pub fn open(&self, device: &DemoDevice, bundle: &SealedBundle) -> BundleContent {
        let file = BundleFile::decode(&bundle.bytes, MAX_BUNDLE_FILE).expect("a bundle file");
        let plain = device.agreement_key().open(&tags::BUNDLE_SEAL, device.tenancy.as_bytes(), &file.sealed).expect("opens");
        BundleContent::decode(&plain).expect("content")
    }

    pub fn events(&self) -> Vec<ReconcileEvent> {
        self.events.lock().expect("lock").clone()
    }

    pub fn digest_file(&self, device: &DemoDevice) -> PathBuf {
        self.dir.join("bundles").join(fieldseal_kernel::digest::lower_hex(device.tenancy.as_bytes())).join("inputs.sha256")
    }

    pub fn issued_file(&self, device: &DemoDevice) -> PathBuf {
        self.dir.join("issued").join(format!("{}.rosters", fieldseal_kernel::digest::lower_hex(device.tenancy.as_bytes())))
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub const SCHEMA_1_0: SchemaVersion = DEMO_SCHEMA;
