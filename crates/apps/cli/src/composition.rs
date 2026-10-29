//! The composition root (ADR 0028): the only place that chooses adapters.
//!
//! Which adapter set is used comes from the environment (`FIELDSEAL_ADAPTERS`),
//! following the twelve-factor config rule (ADR 0025). Only the in-memory set
//! exists so far; real adapters are added by the buildout issues (#43–#55) and
//! registered here.

use std::fmt;

use fieldseal_adapters_memory as mem;
use fieldseal_kernel::time::AuthorityTime;

/// The environment variable that selects the adapter set.
pub const ADAPTERS_ENV: &str = "FIELDSEAL_ADAPTERS";

/// The environment variable that selects the stderr event format (CLI §5, ADR 0025).
pub const LOG_FORMAT_ENV: &str = "FIELDSEAL_LOG_FORMAT";

/// Every environment variable the CLI reads. One that is set but empty is refused, never
/// treated as unset (CLI-030). Unknown `FIELDSEAL_*` names are not refused: the prefix is
/// shared with the other binaries of a deployment, which the CLI cannot tell from a typo.
pub const KNOWN_ENV: &[&str] = &[
    ADAPTERS_ENV,
    LOG_FORMAT_ENV,
    "FIELDSEAL_STATE_DIR",
    "FIELDSEAL_LOG_ORIGIN",
    "FIELDSEAL_SOURCE_URI",
    "FIELDSEAL_BUILDER",
    "FIELDSEAL_NOW",
    "FIELDSEAL_POLICY",
    "FIELDSEAL_SIGNER",
    "FIELDSEAL_TRUST_BUNDLE",
    "FIELDSEAL_FACTORY_URL",
    "FIELDSEAL_TRANSLOG_URL",
    "FIELDSEAL_REKOR_URL",
];

/// How structured events are written to stderr.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    /// One JSON object per line (the default).
    Json,
    /// `event key=value …`.
    Text,
}

/// An adapter set the composition root can wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterSet {
    /// Deterministic in-memory adapters: tests, simulation, conformance.
    Memory,
    /// The in-memory set, with the transparency log and artefact registry kept in local files
    /// (`FIELDSEAL_STATE_DIR`) so separate invocations share them.
    Files,
}

/// Configuration read from the environment.
#[derive(Debug)]
pub struct Config {
    /// The adapter set to wire.
    pub adapters: AdapterSet,
    /// The stderr event format.
    pub log_format: LogFormat,
}

/// The configuration was invalid.
#[derive(Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Config {
    /// Reads configuration from an environment lookup (`std::env::var` in `main`).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        if let Some(name) = KNOWN_ENV.iter().find(|n| lookup(n).is_some_and(|v| v.is_empty())) {
            return Err(ConfigError(format!("{name} is set but empty: give it a value or unset it")));
        }
        let adapters = match lookup(ADAPTERS_ENV).as_deref() {
            None | Some("memory") => AdapterSet::Memory,
            Some("files") => AdapterSet::Files,
            Some(other) => {
                return Err(ConfigError(format!(
                    "{ADAPTERS_ENV}={other}: unknown adapter set (available: memory, files)"
                )));
            }
        };
        let log_format = match lookup(LOG_FORMAT_ENV).as_deref() {
            None | Some("json") => LogFormat::Json,
            Some("text") => LogFormat::Text,
            Some(other) => {
                return Err(ConfigError(format!("{LOG_FORMAT_ENV}={other}: expected json or text")));
            }
        };
        Ok(Self { adapters, log_format })
    }
}

/// The authoring and presentation adapters the `instrument` and `layout` commands drive the
/// Instrument context with: strict YAML/JSON decoding into the canonical data model, the
/// format core's canonical encoding and hashes, and the HTML page that draws a render plan.
/// They hold no state, so every adapter set uses the same ones.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthoringTools;

impl AuthoringTools {
    /// Decodes the authoring document at `path` (`fieldseal-adapters-authoring`), expanding a
    /// compact one (ADR 0040) with its translation catalogues.
    pub fn decode_path(&self, path: &std::path::Path) -> Result<fieldseal_kernel::Value, fieldseal_adapters_authoring::AuthoringError> {
        fieldseal_adapters_authoring::decode_path(path)
    }

    /// Canonical CBOR bytes of a value (WIRE §5.1).
    pub fn canonical(&self, value: &fieldseal_kernel::Value) -> Result<Vec<u8>, fieldseal_kernel::WireError> {
        fieldseal_kernel::cbor::encode(value)
    }

    /// SHA-256, for media digests (INS-180).
    pub fn sha256(&self, bytes: &[u8]) -> [u8; 32] {
        *fieldseal_kernel::digest::sha256(bytes).as_bytes()
    }

    /// Draws a render plan as an HTML page (`fieldseal-adapters-html`).
    pub fn render_html(&self, page: &fieldseal_adapters_html::Page<'_>) -> String {
        fieldseal_adapters_html::render_html(page)
    }
}

/// The authoring tools, for `fieldseal adapters`.
pub fn authoring_bindings() -> Vec<Binding> {
    vec![
        Binding { context: "instrument", port: "AuthoringDecoder", adapter: "StrictYamlJson" },
        Binding { context: "instrument", port: "RenderPlanView", adapter: "HtmlPage" },
    ]
}

/// One port bound to one adapter.
#[derive(Clone, Copy, Debug)]
pub struct Binding {
    /// The bounded context that owns the port.
    pub context: &'static str,
    /// The port.
    pub port: &'static str,
    /// The adapter bound to it.
    pub adapter: &'static str,
}

/// Every adapter, wired. Holding them together proves each can be constructed
/// from configuration alone; use cases take them by reference as they are built.
#[allow(dead_code)]
pub struct MemoryAdapters {
    pub key_custody: mem::trust::MemoryKeyCustody,
    pub secure_key_store: mem::trust::MemorySecureKeyStore,
    pub attestation_verifier: mem::trust::SoftwareAttestationVerifier,
    pub revocation_source: mem::trust::MemoryRevocationSource,
    pub authority_clock: mem::trust::FixedClock,
    pub random_source: mem::trust::SeededRandom,
    pub key_holder_registry: mem::trust::MemoryKeyHolderRegistry,
    pub policy_engine: mem::policy::BuiltInPolicyEngine,
    pub policy_source: mem::policy::MemoryPolicySource,
    pub decision_log: mem::policy::MemoryDecisionLog,
    pub control_catalogue: mem::instrument::FullCatalogue,
    pub source_repository: mem::publishing::MemorySourceRepository,
    pub review_system: mem::publishing::MemoryReviewSystem,
    pub builder: mem::publishing::PassThroughBuilder,
    pub transparency_log: mem::publishing::MemoryTransparencyLog<fieldseal_publishing::contract::RecordingTransport>,
    pub artefact_registry: mem::publishing::MemoryArtefactRegistry,
    pub build_registry: mem::deployment::MemoryBuildRegistry,
    pub secret_store: mem::deployment::MemorySecretStore,
    pub documentation_sink: mem::deployment::MemoryDocumentationSink,
    pub identity_provider: mem::registration::MemoryIdentityProvider,
    pub registry_store: mem::registration::MemoryRegistryStore,
    pub notifier: mem::registration::MemoryNotifier,
    pub roster_source: mem::distribution::MemoryRosterSource,
    /// The demo factory that holds the keys `anchor_source` and `trust_store` need.
    pub demo_factory: mem::demo::DemoWorld,
    pub trust_store: mem::distribution::MemoryTrustStore,
    pub runtime_profiles: mem::distribution::MemoryRuntimeProfiles,
    pub bundle_store: mem::distribution::MemoryBundleStore,
    pub elapsed_clock: mem::collection::MemoryElapsedClock,
    pub secure_storage: mem::collection::MemorySecureStorage,
    pub secure_display: mem::collection::MemorySecureDisplay,
    pub device_policy: mem::collection::MemoryDevicePolicy,
    pub camera: mem::collection::MemoryCamera,
    pub memory_hard_hash: mem::collection::ToyMemoryHardHash,
    pub receipt_check: mem::collection::ToyReceiptAuthority,
    pub file_access: mem::delivery::MemoryFileAccess,
    pub share_target: mem::delivery::MemoryShareTarget,
    pub private_storage: mem::delivery::MemoryPrivateStorage,
    pub qr_scanner: mem::delivery::MemoryQrScanner,
    pub submission_store: mem::intake::MemorySubmissionStore,
    pub tenancy_registry: mem::intake::MemoryTenancyRegistry,
    pub roster_history: mem::intake::MemoryRosterHistory,
    pub data_platform: mem::intake::MemoryDataPlatform,
}

/// Seed for every deterministic memory adapter.
const SEED: &[u8] = b"fieldseal-memory";

impl MemoryAdapters {
    /// Wires the in-memory adapter set.
    pub fn wire() -> Self {
        let epoch = AuthorityTime(0);
        let demo_factory = mem::demo::DemoWorld::new(1, mem::collection::SIMULATION_T0).expect("the demo factory builds");
        Self {
            key_custody: mem::trust::MemoryKeyCustody::new(mem::trust::SeededRandom::new(1)),
            secure_key_store: mem::trust::MemorySecureKeyStore::new(),
            attestation_verifier: mem::trust::SoftwareAttestationVerifier,
            revocation_source: mem::trust::MemoryRevocationSource::new(epoch),
            authority_clock: mem::trust::FixedClock::new(epoch),
            random_source: mem::trust::SeededRandom::new(0),
            key_holder_registry: mem::trust::MemoryKeyHolderRegistry::new(),
            policy_engine: mem::policy::BuiltInPolicyEngine,
            policy_source: mem::policy::MemoryPolicySource::new(Vec::new()),
            decision_log: mem::policy::MemoryDecisionLog::new(),
            control_catalogue: mem::instrument::FullCatalogue,
            source_repository: mem::publishing::MemorySourceRepository::new(),
            review_system: mem::publishing::MemoryReviewSystem::new(),
            builder: mem::publishing::PassThroughBuilder::new("memory-builder"),
            transparency_log: mem::publishing::MemoryTransparencyLog::new(
                "memory-log",
                fieldseal_publishing::contract::RecordingTransport::default(),
            ),
            artefact_registry: mem::publishing::MemoryArtefactRegistry::new(),
            build_registry: mem::deployment::MemoryBuildRegistry::new(),
            secret_store: mem::deployment::MemorySecretStore::new(Default::default()),
            documentation_sink: mem::deployment::MemoryDocumentationSink::new(),
            identity_provider: mem::registration::MemoryIdentityProvider::new(),
            registry_store: mem::registration::MemoryRegistryStore::new(),
            notifier: mem::registration::MemoryNotifier::new(),
            roster_source: mem::distribution::MemoryRosterSource::new(),
            trust_store: mem::distribution::MemoryTrustStore::new(demo_factory.trust.clone()),
            runtime_profiles: mem::distribution::MemoryRuntimeProfiles::new(),
            demo_factory,
            bundle_store: mem::distribution::MemoryBundleStore::new(),
            elapsed_clock: mem::collection::MemoryElapsedClock::new(),
            secure_storage: mem::collection::MemorySecureStorage::new(),
            secure_display: mem::collection::MemorySecureDisplay::new(),
            device_policy: mem::collection::MemoryDevicePolicy::self_managed(),
            camera: mem::collection::MemoryCamera,
            memory_hard_hash: mem::collection::ToyMemoryHardHash,
            receipt_check: mem::collection::ToyReceiptAuthority::new(SEED),
            file_access: mem::delivery::MemoryFileAccess::new(fieldseal_delivery::domain::DestinationClass::Local),
            share_target: mem::delivery::MemoryShareTarget(fieldseal_delivery::ports::ShareOutcome::Shared),
            private_storage: mem::delivery::MemoryPrivateStorage::new(),
            qr_scanner: mem::delivery::MemoryQrScanner::default(),
            submission_store: mem::intake::MemorySubmissionStore::new(),
            tenancy_registry: mem::intake::MemoryTenancyRegistry::new(Vec::new()),
            roster_history: mem::intake::MemoryRosterHistory::new(),
            data_platform: mem::intake::MemoryDataPlatform::new(),
        }
    }
}

/// The bindings the in-memory set provides, for `fieldseal adapters`.
pub fn memory_bindings() -> Vec<Binding> {
    macro_rules! b {
        ($c:literal, $p:literal, $a:literal) => {
            Binding { context: $c, port: $p, adapter: $a }
        };
    }
    vec![
        b!("trust", "KeyCustody", "MemoryKeyCustody"),
        b!("trust", "SecureKeyStore", "MemorySecureKeyStore"),
        b!("trust", "Attestor", "MemorySecureKeyStore"),
        b!("trust", "AttestationVerifier", "SoftwareAttestationVerifier"),
        b!("trust", "RevocationSource", "MemoryRevocationSource"),
        b!("trust", "AuthorityClock", "FixedClock"),
        b!("trust", "RandomSource", "SeededRandom"),
        b!("trust", "KeyHolderRegistry", "MemoryKeyHolderRegistry"),
        b!("policy", "PolicyEngine", "BuiltInPolicyEngine"),
        b!("policy", "PolicySource", "MemoryPolicySource"),
        b!("policy", "DecisionLog", "MemoryDecisionLog"),
        b!("instrument", "ControlCatalogue", "FullCatalogue"),
        b!("publishing", "SourceRepository", "MemorySourceRepository"),
        b!("publishing", "ReviewSystem", "MemoryReviewSystem"),
        b!("publishing", "Builder", "PassThroughBuilder"),
        b!("publishing", "TransparencyLog", "MemoryTransparencyLog"),
        b!("publishing", "LogTransport", "RecordingTransport"),
        b!("publishing", "ArtefactRegistry", "MemoryArtefactRegistry"),
        b!("deployment", "BuildRegistry", "MemoryBuildRegistry"),
        b!("deployment", "SecretStore", "MemorySecretStore"),
        b!("deployment", "DocumentationSink", "MemoryDocumentationSink"),
        b!("registration", "IdentityProvider", "MemoryIdentityProvider"),
        b!("registration", "RegistryStore", "MemoryRegistryStore"),
        b!("registration", "Notifier", "MemoryNotifier"),
        b!("distribution", "RosterSource", "MemoryRosterSource"),
        b!("distribution", "AnchorSource", "MemoryAnchorSource"),
        b!("distribution", "AnchorSource", "ClockAnchorSource"),
        b!("distribution", "RuntimeProfiles", "MemoryRuntimeProfiles"),
        b!("distribution", "AgreementKey", "SoftwareAgreementKey"),
        b!("collection", "BundleOpener", "FileBundleOpener"),
        b!("distribution", "TrustStore", "MemoryTrustStore"),
        b!("distribution", "BundleStore", "MemoryBundleStore"),
        b!("collection", "ElapsedClock", "MemoryElapsedClock"),
        b!("collection", "SecureStorage", "MemorySecureStorage"),
        b!("collection", "SecureDisplay", "MemorySecureDisplay"),
        b!("collection", "DevicePolicy", "MemoryDevicePolicy"),
        b!("collection", "Camera", "MemoryCamera"),
        b!("collection", "MemoryHardHash", "ToyMemoryHardHash"),
        b!("collection", "ReceiptCheck", "ToyReceiptAuthority"),
        b!("delivery", "FileAccess", "MemoryFileAccess"),
        b!("delivery", "ShareTarget", "MemoryShareTarget"),
        b!("delivery", "PrivateStorage", "MemoryPrivateStorage"),
        b!("delivery", "QrScanner", "MemoryQrScanner"),
        b!("delivery", "UploadTransport", "LoopbackTransport"),
        b!("delivery", "ReceiverCheck", "TrustReceiverCheck"),
        b!("delivery", "RegistrationRecords", "MemoryRegistrationRecords"),
        b!("intake", "PopLedger", "MemoryPopLedger"),
        b!("intake", "SubmissionStore", "MemorySubmissionStore"),
        b!("intake", "TenancyRegistry", "MemoryTenancyRegistry"),
        b!("intake", "RosterHistory", "MemoryRosterHistory"),
        b!("intake", "DataPlatform", "MemoryDataPlatform"),
    ]
}
