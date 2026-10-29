//! `fieldseal-upload-server`: a practice intake upload endpoint for development and
//! conformance runs. It serves Intake's gate over the in-memory ports with the practice
//! authority's keys (software keys, never attested), registering one practice device per
//! `--device` label so `fieldseal intake practice` exports can be uploaded to it.
//!
//! Configuration comes from the environment (factor III); flags override it:
//!
//! | Variable | Flag | Meaning |
//! |---|---|---|
//! | `FIELDSEAL_UPLOAD_LISTEN` | `--listen` | address to bind, default `127.0.0.1:8480` |
//! | `FIELDSEAL_UPLOAD_PUBLIC_URLS` | `--public-url` (repeatable) | base URLs tokens may be bound to |
//! | `FIELDSEAL_UPLOAD_SEED` | `--seed` | the practice authority's seed, default 7 |
//! | `FIELDSEAL_UPLOAD_MAX_BODY` | `--max-body` | largest body in bytes |
//! | `FIELDSEAL_UPLOAD_AUTHORITY` | | `practice` (default) or `stack` |
//!
//! With `FIELDSEAL_UPLOAD_AUTHORITY=stack` the endpoint serves a real authority instead of
//! the practice one (development custody, never production): it unseals records and signs
//! receipts and its receiver answer with the keys in `FIELDSEAL_CUSTODY_DIR`, trusts the
//! bundle in `FIELDSEAL_TRUST_BUNDLE`, resolves the devices the factory registered from the
//! factory's state directory `FIELDSEAL_TENANCY_DIR` (read-only), reads the system clock and,
//! when `FIELDSEAL_LANDING_DIR` is set, lands long-format files there. Three more directories
//! make the gate whole (all optional; each falls back to an empty in-memory port):
//! `FIELDSEAL_INTAKE_PUBLISHED_DIR` (the `*.published` instruments it validates answers
//! against), `FIELDSEAL_INTAKE_ROSTERS_DIR` (the rosters issued to each tenancy, for consent)
//! and `FIELDSEAL_INTAKE_SUBMISSIONS_DIR` (every submission it accepted: at start-up they are
//! run through the gate again, so what has landed, and so what is a duplicate, survives a
//! restart, INT-013). `FIELDSEAL_INTAKE_ALLOWED_BUILDERS` and `FIELDSEAL_INTAKE_ALLOWED_SOURCES`
//! (comma-separated) set the publishing policy instruments are verified under.

use std::process::ExitCode;

use fieldseal_adapters_file::custody::DirCustody;
use fieldseal_adapters_file::instruments::PublishedInstruments;
use fieldseal_adapters_file::rosters::FileRosterHistory;
use fieldseal_adapters_file::submissions::FileSubmissionStore;
use fieldseal_adapters_file::tenancy::FileTenancyRegistry;
use fieldseal_adapters_landing_files::FileDataPlatform;
use fieldseal_adapters_memory::delivery::MemoryPopLedger;
use fieldseal_adapters_memory::intake::practice::{PracticeAuthority, PracticeDevice, at};
use fieldseal_adapters_memory::intake::{MemoryDataPlatform, MemoryInstrumentSource, MemoryRosterHistory, MemorySubmissionStore, MemoryTenancyRegistry};
use fieldseal_adapters_memory::policy::BuiltInPolicyEngine;
use fieldseal_adapters_memory::trust::SeededRandom;
use fieldseal_adapters_upload_http::{ServerConfig, UploadHttp};
use fieldseal_intake::domain::TenancyView;
use fieldseal_intake::gate::IntakeService;
use fieldseal_intake::upload::UploadService;
use fieldseal_intake::domain::SubmissionSource;
use fieldseal_intake::ports::{DataPlatform, InstrumentSource, RosterHistory, SubmissionStore, SubmissionStoreError, TenancyRegistry};
use fieldseal_kernel::crypto::Purpose;
use fieldseal_kernel::id::KeyId;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::fixtures::effective_default;
use fieldseal_trust::domain::{AuthorityPublicKey, KeyCertificate, TrustBundle};
use fieldseal_trust::ports::{KeyCustody, RandomSource};

/// Randomness from the operating system.
struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("the operating system's random source");
    }
}

/// The keys and views one authority gives the endpoint.
struct World {
    custody: Box<dyn KeyCustody>,
    bundle: TrustBundle,
    receipt_key: KeyId,
    receiver_key: KeyId,
    receiver_certificate: KeyCertificate,
    registry: Box<dyn TenancyRegistry>,
    platform: Box<dyn DataPlatform>,
    random: Box<dyn RandomSource>,
    clock: Box<dyn Fn() -> AuthorityTime>,
    store: Box<dyn SubmissionStore>,
    /// Submissions kept from earlier runs, to run through the gate again before serving.
    replay: Vec<(u64, Vec<u8>)>,
    rosters: Box<dyn RosterHistory>,
    instruments: Box<dyn InstrumentSource>,
}

/// Says in an event whether a stored submission was new or one the endpoint already held.
struct EventStore<S: SubmissionStore> {
    inner: S,
}

/// Set while stored submissions are run through the gate again at start-up (no events then).
static REPLAYING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl<S: SubmissionStore> SubmissionStore for EventStore<S> {
    fn put(&self, bytes: &[u8]) -> Result<fieldseal_intake::domain::SubmissionId, SubmissionStoreError> {
        let id = fieldseal_intake::domain::SubmissionId(fieldseal_kernel::digest::sha256(bytes));
        let known = self.inner.get(&id)?.is_some();
        let id = self.inner.put(bytes)?;
        if !REPLAYING.load(std::sync::atomic::Ordering::SeqCst) {
            eprintln!("{{\"event\":\"submission\",\"id\":\"{}\",\"new\":{},\"bytes\":{}}}", &fieldseal_kernel::digest::lower_hex(id.0.as_bytes())[..16], !known, bytes.len());
        }
        Ok(id)
    }

    fn get(&self, id: &fieldseal_intake::domain::SubmissionId) -> Result<Option<Vec<u8>>, SubmissionStoreError> {
        self.inner.get(id)
    }
}

/// Says in an event what each submission landed: records that were already landed are
/// duplicates (INT-013) and add nothing, so a repeat shows `envelopes: 0`.
struct EventPlatform(Box<dyn DataPlatform>);

impl DataPlatform for EventPlatform {
    fn land(&self, batch: &fieldseal_intake::ports::LandingBatch) -> Result<(), fieldseal_intake::ports::DataPlatformError> {
        self.0.land(batch)?;
        if !REPLAYING.load(std::sync::atomic::Ordering::SeqCst) {
            eprintln!("{{\"event\":\"landed\",\"envelopes\":{},\"observations\":{},\"findings\":{}}}", batch.envelopes.len(), batch.observations.len(), batch.findings.len());
        }
        Ok(())
    }

    fn exclude(&self, sources: &[fieldseal_kernel::id::RecordId], reason: &str) -> Result<(), fieldseal_intake::ports::DataPlatformError> {
        self.0.exclude(sources, reason)
    }

    fn reinstate(&self, sources: &[fieldseal_kernel::id::RecordId]) -> Result<(), fieldseal_intake::ports::DataPlatformError> {
        self.0.reinstate(sources)
    }

    fn instruments(&self) -> Result<Vec<fieldseal_kernel::id::Fingerprint>, fieldseal_intake::ports::DataPlatformError> {
        self.0.instruments()
    }

    fn observations(&self, i: &fieldseal_kernel::id::Fingerprint) -> Result<Vec<fieldseal_intake::domain::LandedObservation>, fieldseal_intake::ports::DataPlatformError> {
        self.0.observations(i)
    }

    fn envelopes(&self, t: &fieldseal_kernel::id::TenancyId) -> Result<Vec<fieldseal_intake::domain::LandedEnvelope>, fieldseal_intake::ports::DataPlatformError> {
        self.0.envelopes(t)
    }

    fn evidence(&self, b: &[u8; 16]) -> Result<Option<fieldseal_kernel::id::Digest>, fieldseal_intake::ports::DataPlatformError> {
        self.0.evidence(b)
    }

    fn consent_case(&self, t: &fieldseal_kernel::id::TenancyId, s: &fieldseal_kernel::id::SubjectId, i: &fieldseal_kernel::id::Fingerprint) -> Result<Option<fieldseal_intake::domain::ConsentCase>, fieldseal_intake::ports::DataPlatformError> {
        self.0.consent_case(t, s, i)
    }

    fn consent_cases(&self) -> Result<Vec<fieldseal_intake::domain::ConsentCase>, fieldseal_intake::ports::DataPlatformError> {
        self.0.consent_cases()
    }

    fn losses(&self) -> Result<Vec<fieldseal_intake::domain::LossLedgerEntry>, fieldseal_intake::ports::DataPlatformError> {
        self.0.losses()
    }

    fn findings(&self) -> Result<Vec<(fieldseal_intake::domain::SubmissionId, fieldseal_intake::domain::Finding)>, fieldseal_intake::ports::DataPlatformError> {
        self.0.findings()
    }
}

/// Journal entries to replay at start-up: (sequence, entry bytes).
type Replay = Vec<(u64, Vec<u8>)>;

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).ok().filter(|v| !v.is_empty()).ok_or_else(|| format!("{name} must be set for FIELDSEAL_UPLOAD_AUTHORITY=stack"))
}

/// The stack's authority: keys in a key directory, a trust bundle, the factory's tenancies.
fn stack_world() -> Result<World, String> {
    let (dir, bundle_path, tenancies) = (env("FIELDSEAL_CUSTODY_DIR")?, env("FIELDSEAL_TRUST_BUNDLE")?, env("FIELDSEAL_TENANCY_DIR")?);
    let bundle = TrustBundle::decode(&std::fs::read(&bundle_path).map_err(|e| format!("{bundle_path}: {e}"))?).map_err(|e| format!("{bundle_path}: {e}"))?;
    let cert = |purpose: Purpose| {
        bundle
            .certificates()
            .iter()
            .find(|c| c.purpose() == Some(purpose) && matches!(c.public_key(), AuthorityPublicKey::P256(_)))
            .cloned()
            .ok_or_else(|| format!("{bundle_path}: no P-256 {purpose:?} certificate"))
    };
    let (receipt, receiver) = (cert(Purpose::Receipt)?, cert(Purpose::Receiver)?);
    let platform: Box<dyn DataPlatform> = match std::env::var("FIELDSEAL_LANDING_DIR").ok().filter(|v| !v.is_empty()) {
        Some(d) => Box::new(FileDataPlatform::new(&d).map_err(|e| format!("{d}: {e}"))?),
        None => Box::new(MemoryDataPlatform::new()),
    };
    let mut policy = fieldseal_policy::domain::Controls::defaults().publishing();
    let list = |name: &str| var(name).map(|v| v.split(',').map(str::to_owned).collect::<Vec<_>>());
    policy.allowed_builders = list("FIELDSEAL_INTAKE_ALLOWED_BUILDERS").unwrap_or_default();
    policy.allowed_sources = list("FIELDSEAL_INTAKE_ALLOWED_SOURCES").unwrap_or_default();
    let now_ms = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    let (store, replay): (Box<dyn SubmissionStore>, Replay) = match var("FIELDSEAL_INTAKE_SUBMISSIONS_DIR") {
        Some(d) => {
            let s = FileSubmissionStore::open(&d, now_ms).map_err(|e| format!("{d}: {e}"))?;
            let replay = s.stored();
            (Box::new(EventStore { inner: s }), replay)
        }
        None => (Box::new(EventStore { inner: MemorySubmissionStore::new() }), Vec::new()),
    };
    let rosters: Box<dyn RosterHistory> = match var("FIELDSEAL_INTAKE_ROSTERS_DIR") {
        Some(d) => Box::new(FileRosterHistory::new(d)),
        None => Box::new(MemoryRosterHistory::new()),
    };
    let instruments: Box<dyn InstrumentSource> = match var("FIELDSEAL_INTAKE_PUBLISHED_DIR") {
        Some(d) => Box::new(PublishedInstruments::new(d, bundle.clone(), policy)),
        None => Box::new(MemoryInstrumentSource::new()),
    };
    Ok(World {
        store,
        replay,
        rosters,
        instruments,
        custody: Box::new(DirCustody::new(dir)),
        receipt_key: *receipt.key_id(),
        receiver_key: *receiver.key_id(),
        receiver_certificate: receiver,
        bundle,
        registry: Box::new(FileTenancyRegistry::new(tenancies)),
        platform: Box::new(EventPlatform(platform)),
        random: Box::new(OsRandom),
        clock: Box::new(|| AuthorityTime(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64))),
    })
}

/// The practice authority and its practice devices (fixed seeds, in-memory ports).
fn practice_world(seed: u64, devices: &[String]) -> World {
    let practice = PracticeAuthority::new(seed);
    let views: Vec<TenancyView> = devices.iter().map(|l| PracticeDevice::new(l)).map(|d| TenancyView::new(d.tenancy, d.handle, vec![d.public_key()])).collect();
    World {
        store: Box::new(MemorySubmissionStore::new()),
        replay: Vec::new(),
        rosters: Box::new(MemoryRosterHistory::new()),
        instruments: Box::new(MemoryInstrumentSource::new()),
        receipt_key: practice.receipt_key,
        receiver_key: practice.receiver_key,
        receiver_certificate: practice.receiver_certificate.clone(),
        bundle: practice.bundle.clone(),
        custody: Box::new(practice.custody),
        registry: Box::new(MemoryTenancyRegistry::new(views)),
        platform: Box::new(MemoryDataPlatform::new()),
        random: Box::new(SeededRandom::new(99)),
        // The practice authority's clock: its epoch plus 20 days, fixed, so practice exports
        // made at that time are in their collection window.
        clock: Box::new(|| AuthorityTime(at(20).0)),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut listen = std::env::var("FIELDSEAL_UPLOAD_LISTEN").unwrap_or_else(|_| "127.0.0.1:8480".into());
    let mut urls: Vec<String> = std::env::var("FIELDSEAL_UPLOAD_PUBLIC_URLS").map(|v| v.split(',').map(str::to_owned).collect()).unwrap_or_default();
    let mut seed: u64 = std::env::var("FIELDSEAL_UPLOAD_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(7);
    let mut max_body = std::env::var("FIELDSEAL_UPLOAD_MAX_BODY").ok().and_then(|v| v.parse().ok()).unwrap_or(ServerConfig::default().max_body);
    let mut devices: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().cloned().ok_or_else(|| format!("{name} needs a value"));
        let result: Result<(), String> = (|| {
            match a.as_str() {
                "--listen" => listen = value("--listen")?,
                "--public-url" => urls.push(value("--public-url")?),
                "--seed" => seed = value("--seed")?.parse().map_err(|_| "--seed is a number".to_owned())?,
                "--max-body" => max_body = value("--max-body")?.parse().map_err(|_| "--max-body is a number".to_owned())?,
                "--device" => devices.push(value("--device")?),
                other => return Err(format!("unknown option {other}")),
            }
            Ok(())
        })();
        if let Err(e) = result {
            eprintln!("fieldseal-upload-server: {e}");
            return ExitCode::from(2);
        }
    }
    let server = match tiny_http::Server::http(&listen) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fieldseal-upload-server: cannot bind {listen}: {e}");
            return ExitCode::from(3);
        }
    };
    if urls.is_empty() {
        urls.push(format!("http://{listen}"));
    }
    let stack = std::env::var("FIELDSEAL_UPLOAD_AUTHORITY").map(|v| v == "stack").unwrap_or(false);
    let world = if stack {
        match stack_world() {
            Ok(w) => w,
            Err(e) => {
                eprintln!("fieldseal-upload-server: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        practice_world(seed, &devices)
    };
    let (engine, effective, ledger) = (BuiltInPolicyEngine, effective_default(), MemoryPopLedger::new());
    let gate = IntakeService {
        store: world.store.as_ref(),
        registry: world.registry.as_ref(),
        rosters: world.rosters.as_ref(),
        instruments: world.instruments.as_ref(),
        platform: world.platform.as_ref(),
        custody: world.custody.as_ref(),
        policy: &engine,
        effective: &effective,
        random: world.random.as_ref(),
        trust: &world.bundle,
        revocations: vec![],
        receipt_key: world.receipt_key,
        caller: "upload-server",
    };
    // Rebuild what has landed from the submissions kept from earlier runs (INT-013).
    REPLAYING.store(true, std::sync::atomic::Ordering::SeqCst);
    for (ms, bytes) in &world.replay {
        match gate.ingest(bytes, SubmissionSource::Upload, AuthorityTime(*ms)) {
            Ok(r) => eprintln!("{{\"event\":\"replayed\",\"state\":\"{:?}\",\"landed\":{},\"duplicates\":{}}}", r.submission.state(), r.summary.landed, r.summary.duplicates),
            Err(e) => eprintln!("{{\"event\":\"replay-failed\",\"detail\":{:?}}}", e.to_string()),
        }
    }
    REPLAYING.store(false, std::sync::atomic::Ordering::SeqCst);
    let service = UploadService { intake: &gate, ledger: &ledger, receiver_key: world.receiver_key, receiver_certificate: &world.receiver_certificate, public_urls: &urls };
    let http = UploadHttp::new(&service, &world.clock, ServerConfig { max_body });
    eprintln!("{{\"event\":\"listening\",\"listen\":{:?},\"authority\":{:?},\"devices\":{}}}", listen, if stack { "stack" } else { "practice" }, devices.len());
    http.run(&server);
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    // covers: INT-091
    #[test]
    fn int_011_the_event_platform_satisfies_the_data_platform_contract() {
        fieldseal_intake::contract::data_platform_contract(|| EventPlatform(Box::new(MemoryDataPlatform::new())));
    }
}
