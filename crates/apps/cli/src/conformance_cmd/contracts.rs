//! The port contract suites (#57): every contract function against every adapter, with the
//! catalogue the documentation table is generated from.

use std::sync::atomic::{AtomicU64, Ordering};

use fieldseal_adapters_memory::conformance::{ContractCase, contract_cases};
use fieldseal_publishing::contract::{self as publishing, RecordingTransport};
use fieldseal_trust::contract as tru;
use fieldseal_trust::ports::SourceRng;

use super::Unit;
use super::harness::{Collector, Status};
use crate::custody::{DirCustody, OsRandom};
use crate::registration_cmd::TokenFiles;
use crate::stores::{FileRegistry, LOCAL_LOG_ORIGIN};
use crate::transport::NullTransport;

/// Where a contract runs.
#[derive(Clone, Copy)]
pub enum Location {
    /// In the `fieldseal` binary.
    Here(fn()),
    /// Under `cargo test`, because the adapter needs a fixture the binary doesn't carry.
    CargoTest(&'static str),
}

/// One contract against one adapter.
#[derive(Clone, Copy)]
pub struct Entry {
    /// The owning context.
    pub context: &'static str,
    /// The port.
    pub port: &'static str,
    /// The contract function.
    pub contract: &'static str,
    /// The adapter.
    pub adapter: &'static str,
    /// Requirements it helps to verify.
    pub requirements: &'static [&'static str],
    /// Where it runs.
    pub location: Location,
}

fn scratch() -> std::path::PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!("fieldseal-conformance-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

macro_rules! local {
    ($ctx:literal, $port:literal, $contract:literal, $adapter:literal, [$($req:literal),*], $run:expr) => {
        Entry { context: $ctx, port: $port, contract: $contract, adapter: $adapter, requirements: &[$($req),*], location: Location::Here($run) }
    };
}

macro_rules! external {
    ($ctx:literal, $port:literal, $contract:literal, $adapter:literal, [$($req:literal),*], $how:literal) => {
        Entry { context: $ctx, port: $port, contract: $contract, adapter: $adapter, requirements: &[$($req),*], location: Location::CargoTest($how) }
    };
}

fn from_memory(c: ContractCase) -> Entry {
    Entry { context: c.context, port: c.port, contract: c.contract, adapter: c.adapter, requirements: c.requirements, location: Location::Here(c.run) }
}

/// Every contract entry: the in-memory adapters, the CLI's own adapters, the file adapters
/// and the adapters whose contract needs `cargo test`.
pub fn entries() -> Vec<Entry> {
    let mut all: Vec<Entry> = contract_cases().into_iter().map(from_memory).collect();
    all.extend([
        local!("trust", "KeyCustody", "key_custody_contract", "DirCustody", ["TRU-003", "TRU-011", "TRU-016"], || {
            let dir = scratch();
            let sender = fieldseal_adapters_memory::trust::SeededRandom::new(2);
            tru::key_custody_contract(|| DirCustody::new(dir.clone()), &mut SourceRng(&sender));
            let _ = std::fs::remove_dir_all(dir);
        }),
        local!("trust", "RandomSource", "random_source_contract", "OsRandom", [], || tru::random_source_contract(|| OsRandom)),
        local!("publishing", "LogTransport", "log_transport_contract", "NullTransport", ["PUB-104"], || {
            publishing::log_transport_contract(|| NullTransport);
        }),
        local!("publishing", "ArtefactValidator", "artefact_validator_contract", "KindValidator", ["PUB-003"], || {
            let artefact = publishing::sample_publication("health-check", "1.0.0", b"bytes").artefact;
            publishing::artefact_validator_contract(|| crate::artefact_cmd::KindValidator, &artefact);
        }),
        local!("publishing", "TransparencyLog", "transparency_log_contract", "FileLog", ["PUB-102", "PUB-104", "PUB-106"], || {
            // The file-backed store, driven through the translog client over an in-process
            // handler so the contract can record every transmission.
            let dir = scratch();
            let store = std::sync::Arc::new(crate::stores::file_log_store(LOCAL_LOG_ORIGIN, &dir).expect("log"));
            let pin = store.pin();
            let transport = RecordingTransport::forwarding(fieldseal_adapters_translog::HandlerTransport::new(store.clone()));
            publishing::transparency_log_contract(
                transport,
                |t| fieldseal_adapters_translog::HttpTranslog::new(t).pinned(pin.clone()),
                &pin,
            );
            let _ = std::fs::remove_dir_all(dir);
        }),
        local!("publishing", "ArtefactRegistry", "artefact_registry_contract", "FileRegistry", ["PUB-060", "PUB-062"], || {
            let dir = scratch();
            publishing::artefact_registry_contract(|| FileRegistry::new(dir.clone()));
            let _ = std::fs::remove_dir_all(dir);
        }),
        local!("registration", "RegistryStore", "registry_store_contract", "TokenFiles", ["REG-005", "REG-006"], || {
            let dir = scratch();
            fieldseal_registration::contract::registry_store_contract(|| TokenFiles::open(dir.join(format!("{}", rand_suffix())), false));
            let _ = std::fs::remove_dir_all(dir);
        }),
        local!("registration", "RegistryStore", "registry_store_contract", "FileRegistryStore", ["REG-005", "REG-006"], || {
            let dir = scratch();
            fieldseal_registration::contract::registry_store_contract(|| {
                fieldseal_adapters_file::store::FileRegistryStore::open(dir.join(format!("{}", rand_suffix()))).expect("dir")
            });
            let _ = std::fs::remove_dir_all(dir);
        }),
        external!("intake", "TenancyRegistry", "tenancy_registry_contract", "FileTenancyRegistry", ["INT-006"], "cargo test -p fieldseal-adapters-file del_071"),
        external!("intake", "DataPlatform", "data_platform_contract", "EventPlatform", ["INT-011"], "cargo test -p fieldseal-adapters-upload-http --bin fieldseal-upload-server int_011"),
        external!("intake", "SubmissionStore", "submission_store_contract", "FileSubmissionStore", ["INT-013"], "cargo test -p fieldseal-adapters-file int_013"),
        external!("intake", "RosterHistory", "roster_history_contract", "FileRosterHistory", ["INT-040"], "cargo test -p fieldseal-adapters-file int_040"),
        external!("intake", "InstrumentSource", "instrument_source_contract", "PublishedInstruments", ["INT-070"], "cargo test -p fieldseal-adapters-file int_070"),
        local!("intake", "DataPlatform", "data_platform_contract", "FileDataPlatform", ["INT-011"], || {
            let dir = scratch();
            fieldseal_intake::contract::data_platform_contract(|| {
                fieldseal_adapters_landing_files::FileDataPlatform::new(dir.join(format!("{}", rand_suffix()))).expect("dir")
            });
            let _ = std::fs::remove_dir_all(dir);
        }),
        external!("publishing", "TransparencyLog", "transparency_log_contract", "RekorLog", ["PUB-102", "PUB-104", "PUB-105", "PUB-106"], "cargo test -p fieldseal-adapters-rekor --test rekor pub_104_rekor_passes"),
        external!("publishing", "LogTransport", "log_transport_contract", "HttpTransport (Rekor)", ["PUB-104"], "cargo test -p fieldseal-adapters-rekor --test rekor pub_104_rekor_http"),
        external!("publishing", "TransparencyLog", "transparency_log_contract", "FileLogStore", ["PUB-100", "PUB-104"], "cargo test -p fieldseal-adapters-translog pub_100_104_http_client_over_the_handler_passes_the_contract"),
        external!("publishing", "LogTransport", "transparency_log_contract", "HttpLogTransport", ["PUB-100", "PUB-104"], "cargo test -p fieldseal-translog --test end_to_end pub_100_104_the_http_client_passes_the_contract_against_a_running_server"),
        external!("policy", "PolicyEngine", "engine_cases", "OpaEngine", ["POL-032", "POL-034"], "cargo test -p fieldseal-adapters-opa --test engine pol_032_opa_passes_the_engine_contract"),
        external!("policy", "PolicySource", "policy_source_contract", "BundlePolicySource", ["POL-004"], "cargo test -p fieldseal-adapters-policy --test sources the_bundle_source_meets_the_policy_source_contract"),
        external!("policy", "PolicySource", "registry verification tests (no shared contract run yet)", "RegistryPolicySource", ["POL-004"], "cargo test -p fieldseal-adapters-policy --test sources pol_004"),
        external!("policy", "DecisionLog", "decision_log_contract", "FileDecisionLog", ["POL-040"], "cargo test -p fieldseal-adapters-policy --test decision_log pol_040_the_file_log_meets_the_decision_log_contract"),
        external!("registration", "IdentityProvider", "identity_provider_contract", "OidcIdentityProvider", ["REG-002"], "cargo test -p fieldseal-adapters-oidc"),
        external!("delivery", "UploadTransport", "upload_transport_contract", "LoopbackTransport", ["DEL-062", "DEL-064", "WIRE-182"], "cargo test -p fieldseal-adapters-memory --test delivery"),
        external!("delivery", "UploadTransport", "upload_transport_contract", "HttpUploadTransport", ["DEL-062", "DEL-064", "WIRE-182"], "cargo test -p fieldseal-adapters-upload-http --test http del_062_064_http"),
        external!("delivery", "ReceiverCheck", "receiver_check_contract", "TrustReceiverCheck", ["DEL-062"], "cargo test -p fieldseal-adapters-memory --test delivery"),
        external!("collection", "ReceiptCheck", "receipt_check_contract", "TrustReceiptCheck", ["DEL-064"], "cargo test -p fieldseal-adapters-memory --test delivery"),
        external!("collection", "BundleOpener", "bundle_opener_contract", "FileBundleOpener", ["DIS-042"], "cargo test -p fieldseal-adapters-memory --test bundle_import"),
        external!("intake", "InstrumentSource", "instrument_source_contract", "MemoryInstrumentSource", [], "cargo test -p fieldseal-adapters-memory --test landing"),
        external!("trust", "AuthorityClock", "authority_clock_contract", "SystemClock (factory)", [], "cargo test -p fieldseal-factory"),
        external!("trust", "AttestationVerifier", "attestation_verifier_contract", "Tpm2CertifyVerifier", ["TRU-062", "TRU-063", "TRU-110"], "cargo test -p fieldseal-adapters-attestation --test tpm2 tru_110"),
        external!("trust", "RandomSource", "random_source_contract", "OsRandom (factory)", [], "cargo test -p fieldseal-factory"),
        external!("collection", "SecureStorage", "secure_storage_contract", "WebStorage", ["PLAT-101"], "cargo test -p fieldseal-adapters-web --test platform plat_101"),
        external!("collection", "ElapsedClock", "elapsed_clock_contract", "WebElapsed", ["PLAT-104"], "cargo test -p fieldseal-adapters-web --test platform plat_104"),
        external!("collection", "WallClock", "wall_clock_contract", "WebWall", ["PLAT-104"], "cargo test -p fieldseal-adapters-web --test platform plat_104"),
        external!("collection", "MemoryHardHash", "memory_hard_hash_contract", "ArgonHash", ["PLAT-103"], "cargo test -p fieldseal-adapters-web --test platform plat_103"),
        external!("collection", "SecureDisplay", "secure_display_contract", "WebDisplay", ["PLAT-104", "PLAT-108"], "cargo test -p fieldseal-adapters-web --test platform plat_104"),
        external!("collection", "DevicePolicy", "(web profile: every restriction unknown; no shared contract applies)", "WebDevicePolicy", ["PLAT-105"], "cargo test -p fieldseal-adapters-web --test device_flow"),
        external!("collection", "Camera", "(web profile: always unavailable; no shared contract applies)", "WebCamera", [], "cargo test -p fieldseal-adapters-web --test device_flow"),
        external!("collection", "BundleOpener", "bundle_opener_contract", "WebBundleOpener", ["PLAT-110", "PLAT-112"], "cargo test -p fieldseal-adapters-web --test device_flow"),
        external!("delivery", "FileAccess", "file_access_contract", "WebDownloads", ["PLAT-104"], "cargo test -p fieldseal-adapters-web --test platform plat_104"),
        external!("delivery", "ShareTarget", "(web profile: no share sheet; no shared contract applies)", "NoShare", [], "cargo test -p fieldseal-adapters-web --test device_flow"),
        external!("delivery", "UploadTransport", "upload_transport_contract", "BrowserTransport", ["PLAT-116", "DEL-062"], "cargo test -p fieldseal-adapters-web --test device_flow"),
        external!("trust", "SecureKeyStore", "secure_key_store_contract", "WebKeyStore", ["PLAT-102"], "cargo test -p fieldseal-adapters-web --test platform plat_102"),
        external!("trust", "Attestor", "(software evidence only; no shared contract applies)", "WebKeyStore (Attestor)", ["PLAT-106"], "cargo test -p fieldseal-adapters-web --test device_flow"),
        external!("trust", "RandomSource", "random_source_contract", "WebRandom", [], "cargo test -p fieldseal-adapters-web --test device_flow"),
        external!("trust", "AuthorityClock", "(demo authority clock; no shared contract applies)", "RealClock (web demo)", [], "cargo test -p fieldseal-adapters-web-demo"),
        external!("registration", "RegistryStore", "(wraps the in-memory store to track changes)", "TrackingStore (web demo)", [], "cargo test -p fieldseal-adapters-web-demo"),
        external!("intake", "TenancyRegistry", "(a live view of the demo registry)", "LiveRegistry (web demo)", [], "cargo test -p fieldseal-adapters-web-demo"),
        external!("intake", "SubmissionStore", "(records what the gate stored for the Intake page)", "RecordingStore (web demo)", [], "cargo test -p fieldseal-adapters-web-demo"),
    ]);
    all
}

fn rand_suffix() -> u64 {
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::SeqCst)
}

/// The id of the unit that runs `e`.
pub fn unit_id(e: &Entry) -> String {
    format!("contract:{}:{}:{}", e.context, e.port, e.adapter)
}

/// The contract units, one per in-process entry. Each runs in its own process because a
/// failed contract panics.
pub fn units() -> Vec<Unit> {
    entries()
        .into_iter()
        .filter_map(|e| {
            let Location::Here(run) = e.location else { return None };
            let mut suites = vec!["contracts", e.context];
            if e.port == "TransparencyLog" {
                suites.push("transparency-log");
            }
            Some(Unit::contract(unit_id(&e), suites, e.requirements, e.contract, run))
        })
        .collect()
}

/// Reports a panicking contract as a single result (used by the child process).
pub fn run_contract(unit: &str, requirements: &[&str], contract: &str, run: fn()) -> Collector {
    let mut c = Collector::new(unit);
    run();
    let reqs: Vec<String> = requirements.iter().map(|r| (*r).to_owned()).collect();
    c.results.push(super::harness::CheckResult { unit: unit.to_owned(), name: contract.to_owned(), requirements: reqs, status: Status::Pass });
    c
}
