//! `fieldseal-upload-practice`: a practice intake upload endpoint for development and
//! conformance runs (DEL-071). It serves Intake's gate over the in-memory ports with the
//! practice authority's keys (software keys, never attested), registering one practice device
//! per `--device` label so `fieldseal intake practice` exports can be uploaded to it.
//!
//! It is not the intake app: it holds nothing between runs, has no results reader and appears
//! in no image, compose file or deployment manifest. It refuses `FIELDSEAL_ENVIRONMENT=production`.
//!
//! Configuration comes from flags; the first three also from the environment:
//!
//! | Variable | Flag | Meaning |
//! |---|---|---|
//! | `FIELDSEAL_UPLOAD_LISTEN` | `--listen` | address to bind, default `127.0.0.1:8480` |
//! | `FIELDSEAL_UPLOAD_PUBLIC_URLS` | `--public-url` (repeatable) | base URLs tokens may be bound to |
//! | `FIELDSEAL_UPLOAD_SEED` | `--seed` | the practice authority's seed, default 7 |
//! | `FIELDSEAL_UPLOAD_MAX_BODY` | `--max-body` | largest body in bytes |
//! | | `--device` (repeatable) | a practice device label |

use std::process::ExitCode;

use fieldseal_adapters_memory::delivery::MemoryPopLedger;
use fieldseal_adapters_memory::intake::practice::{PracticeAuthority, PracticeDevice, at};
use fieldseal_adapters_memory::intake::{MemoryDataPlatform, MemoryInstrumentSource, MemoryRosterHistory, MemorySubmissionStore, MemoryTenancyRegistry};
use fieldseal_adapters_memory::policy::BuiltInPolicyEngine;
use fieldseal_adapters_memory::trust::SeededRandom;
use fieldseal_adapters_upload_http::{ServerConfig, UploadHttp};
use fieldseal_intake::domain::TenancyView;
use fieldseal_intake::gate::IntakeService;
use fieldseal_intake::upload::UploadService;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::fixtures::effective_default;

fn main() -> ExitCode {
    if std::env::var("FIELDSEAL_ENVIRONMENT").is_ok_and(|v| v == "production") {
        eprintln!("fieldseal-upload-practice: the practice authority is not allowed in production");
        return ExitCode::from(2);
    }
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
            eprintln!("fieldseal-upload-practice: {e}");
            return ExitCode::from(2);
        }
    }
    let server = match tiny_http::Server::http(&listen) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fieldseal-upload-practice: cannot bind {listen}: {e}");
            return ExitCode::from(3);
        }
    };
    if urls.is_empty() {
        urls.push(format!("http://{listen}"));
    }
    let practice = PracticeAuthority::new(seed);
    let views: Vec<TenancyView> = devices.iter().map(|l| PracticeDevice::new(l)).map(|d| TenancyView::new(d.tenancy, d.handle, vec![d.public_key()])).collect();
    let (store, rosters, instruments, registry, platform, random) =
        (MemorySubmissionStore::new(), MemoryRosterHistory::new(), MemoryInstrumentSource::new(), MemoryTenancyRegistry::new(views), MemoryDataPlatform::new(), SeededRandom::new(99));
    let (engine, effective, ledger) = (BuiltInPolicyEngine, effective_default(), MemoryPopLedger::new());
    let gate = IntakeService {
        store: &store,
        registry: &registry,
        rosters: &rosters,
        instruments: &instruments,
        platform: &platform,
        custody: &practice.custody,
        policy: &engine,
        effective: &effective,
        random: &random,
        trust: &practice.bundle,
        revocations: vec![],
        receipt_key: practice.receipt_key,
        caller: "upload-practice",
    };
    let service = UploadService { intake: &gate, ledger: &ledger, receiver_key: practice.receiver_key, receiver_certificate: &practice.receiver_certificate, public_urls: &urls };
    // The practice authority's clock: its epoch plus 20 days, fixed, so practice exports made
    // at that time are in their collection window.
    let http = UploadHttp::new(&service, || AuthorityTime(at(20).0), ServerConfig { max_body });
    eprintln!("{{\"event\":\"listening\",\"listen\":{:?},\"authority\":\"practice\",\"devices\":{}}}", listen, devices.len());
    http.run(&server);
    ExitCode::SUCCESS
}
