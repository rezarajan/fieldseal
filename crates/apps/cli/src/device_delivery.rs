//! The export and upload steps of `fieldseal device simulate` (CLI §device, DEL §8).
//!
//! The simulated device's records are sealed to the practice authority's record key, so the
//! real intake gate opens them. Steps:
//!
//! ```yaml
//!   - export: { parity: on, to: removable, ingest: true, out: build.fieldseal }
//!   - export: { outbox: true }        # after `close`: one part per closed tenancy
//!   - import-receipt: {}              # the receipt of the last `ingest`, as if from a file
//!   - upload: {}                      # background upload to the in-process intake
//!   - upload: { outbox: true }
//! ```
//!
//! `to` is `removable` (default), `local`, `cloud` or `share`. Output never contains names,
//! roster contents or item values (CLI-008): only counts, seq ranges and labels.

use fieldseal_adapters_memory::delivery::{LoopbackTransport, MemoryFileAccess, MemoryPrivateStorage, MemoryShareTarget};
use fieldseal_adapters_memory::delivery_world::{Bench, Enrolled, IntakeSide};
use fieldseal_collection::application::Runtime;
use fieldseal_collection::domain::ReceiptCoverage;
use fieldseal_delivery::application::{DeliveryError, DeliveryService, Ports};
use fieldseal_delivery::checks::{TrustReceiptCheck, TrustReceiverCheck};
use fieldseal_delivery::domain::{AddressHint, DestinationClass, Export, HintSource};
use fieldseal_delivery::ports::{FileAccess, PrivateStorage, ShareOutcome};
use fieldseal_instrument::domain::Instrument;
use fieldseal_intake::domain::{GateState, SubmissionSource};
use fieldseal_kernel::Value;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::domain::RuntimeEvaluator;
use fieldseal_trust::domain::TrustStore;

/// The address the in-process intake answers at. It is an untrusted hint like any other:
/// the device authorises the endpoint by its receiver key (DEL-062).
const LOOPBACK: &str = "https://intake.simulator.invalid";

/// The simulator's delivery side: the intake the device uploads to, and the device's
/// private storage and file destinations.
pub struct DeliveryBench<'b> {
    bench: &'b Bench,
    side: IntakeSide,
    storage: MemoryPrivateStorage,
    policy: RuntimeEvaluator,
    files: [MemoryFileAccess; 3],
    share: MemoryShareTarget,
    urls: Vec<String>,
    last_receipt: Option<Vec<u8>>,
}

fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.as_map().and_then(|m| m.get(key)).and_then(Value::as_text)
}

fn flag(v: &Value, key: &str) -> bool {
    v.as_map().and_then(|m| m.get(key)) == Some(&Value::Bool(true))
}

impl<'b> DeliveryBench<'b> {
    /// The delivery side for an enrolled device.
    pub fn new(bench: &'b Bench, enrolled: &Enrolled, instrument: Instrument) -> Result<Self, String> {
        Ok(Self {
            bench,
            side: bench.intake(enrolled, instrument),
            storage: MemoryPrivateStorage::new(),
            policy: RuntimeEvaluator::from_effective(&fieldseal_policy::fixtures::effective_default()).map_err(|f| format!("runtime policy: {f:?}"))?,
            files: [
                MemoryFileAccess::new(DestinationClass::Removable),
                MemoryFileAccess::new(DestinationClass::Local),
                MemoryFileAccess::new(DestinationClass::Cloud),
            ],
            share: MemoryShareTarget(ShareOutcome::Shared),
            urls: vec![LOOPBACK.to_owned()],
            last_receipt: None,
        })
    }

    fn now() -> AuthorityTime {
        AuthorityTime(fieldseal_adapters_memory::collection::SIMULATION_T0.0 + 20 * AuthorityTime::DAY)
    }

    fn file_access(&self, to: &str) -> Result<&MemoryFileAccess, String> {
        match to {
            "removable" => Ok(&self.files[0]),
            "local" => Ok(&self.files[1]),
            "cloud" => Ok(&self.files[2]),
            other => Err(format!("unknown destination `{other}` (removable, local, cloud, share)")),
        }
    }

    fn describe(export: &Export) -> String {
        format!(
            "{} ({} record(s), seq {}-{}, {} bytes, parity {})",
            export.name,
            export.records,
            export.from.0,
            export.through.0,
            export.size,
            if export.parity { "on" } else { "off" }
        )
    }

    /// The `export` step.
    pub fn export(&mut self, rt: &mut Runtime<'_>, body: &Value) -> Result<String, String> {
        let policy = &self.policy;
        let gate = self.side.service(&self.bench.practice);
        let upload = self.side.upload(&self.bench.practice, &gate, &self.urls);
        let transport = LoopbackTransport::new(&upload, Self::now);
        let to = text(body, "to").unwrap_or("removable");
        let files = if to == "share" { &self.files[0] } else { self.file_access(to)? };
        let receiver = TrustReceiverCheck::new(TrustStore::new(&self.bench.practice.bundle), Self::now());
        let receipts = TrustReceiptCheck::new(TrustStore::new(&self.bench.practice.bundle));
        let mut svc = DeliveryService::new(
            Ports {
                keys: &self.bench.device.keys,
                random: &self.bench.device.random,
                wall: &self.bench.device.wall,
                transport: &transport,
                receiver: &receiver,
                receipts: &receipts,
                files,
                share: &self.share,
                storage: &self.storage,
                records: &self.bench.records,
            },
            policy,
        );
        let parity = match text(body, "parity") {
            Some("on") => Some(true),
            Some("off") => Some(false),
            Some(other) => return Err(format!("parity is `on` or `off`, not `{other}`")),
            None => None,
        };
        let export = if flag(body, "outbox") { svc.build_outbox_export(rt, parity) } else { svc.build_export(rt, parity) }.map_err(describe_error)?;
        let bytes = self.storage.get(&export.id).map_err(|e| e.to_string())?.ok_or("the export vanished from private storage")?;
        let mut line = format!("export {}", Self::describe(&export));
        let attempt = if to == "share" {
            svc.deliver_share(rt, &export, &[])
        } else {
            let handle = files.pick_destination().map_err(|e| e.to_string())?;
            svc.deliver_file(rt, &export, &handle)
        }
        .map_err(describe_error)?;
        line.push_str(&format!(": {}", attempt.label.text()));
        if let Some(path) = text(body, "out") {
            std::fs::write(path, &bytes).map_err(|e| format!("{path}: {e}"))?;
            line.push_str(&format!("; wrote {path}"));
        }
        if flag(body, "ingest") {
            let report = gate.ingest(&bytes, SubmissionSource::File, Self::now()).map_err(|e| e.to_string())?;
            let state = report.submission.state();
            line.push_str(&format!("; intake gate: {state:?}"));
            if let Some(r) = report.submission.rejection() {
                return Err(format!("{line}; rejected at {:?} with {}: {}", r.stage, r.code, r.detail));
            }
            self.last_receipt = report.receipts.first().map(|r| r.bytes.clone());
            if matches!(state, GateState::Landed | GateState::Flagged) {
                line.push_str(&format!(", {} receipt(s)", report.receipts.len()));
            }
        }
        Ok(line)
    }

    /// The `import-receipt` step: the receipt of the last `ingest`, as if it came from a file.
    pub fn import_receipt(&mut self, rt: &mut Runtime<'_>) -> Result<String, String> {
        let bytes = self.last_receipt.take().ok_or("no receipt to import: run `export` with `ingest: true` first")?;
        let policy = &self.policy;
        let gate = self.side.service(&self.bench.practice);
        let upload = self.side.upload(&self.bench.practice, &gate, &self.urls);
        let transport = LoopbackTransport::new(&upload, Self::now);
        let receiver = TrustReceiverCheck::new(TrustStore::new(&self.bench.practice.bundle), Self::now());
        let receipts = TrustReceiptCheck::new(TrustStore::new(&self.bench.practice.bundle));
        let mut svc = DeliveryService::new(
            Ports {
                keys: &self.bench.device.keys,
                random: &self.bench.device.random,
                wall: &self.bench.device.wall,
                transport: &transport,
                receiver: &receiver,
                receipts: &receipts,
                files: &self.files[0],
                share: &self.share,
                storage: &self.storage,
                records: &self.bench.records,
            },
            policy,
        );
        let outcome = svc.import_receipt(rt, &bytes).map_err(describe_error)?;
        Ok(format!(
            "receipt imported and verified: {} cleared frame(s) deleted{}",
            outcome.journal_deleted,
            outcome.offer_clear_through.map_or(String::new(), |s| format!(", clear offered through {}", s.0))
        ))
    }

    /// The `upload` step. Returns the line to print and the coverage the receipt gave, for a
    /// following `clear`.
    pub fn upload(&mut self, rt: &mut Runtime<'_>, body: &Value) -> Result<(String, Option<ReceiptCoverage>), String> {
        let policy = &self.policy;
        let gate = self.side.service(&self.bench.practice);
        let upload = self.side.upload(&self.bench.practice, &gate, &self.urls);
        let transport = LoopbackTransport::new(&upload, Self::now);
        let receiver = TrustReceiverCheck::new(TrustStore::new(&self.bench.practice.bundle), Self::now());
        let receipts = TrustReceiptCheck::new(TrustStore::new(&self.bench.practice.bundle));
        let mut svc = DeliveryService::new(
            Ports {
                keys: &self.bench.device.keys,
                random: &self.bench.device.random,
                wall: &self.bench.device.wall,
                transport: &transport,
                receiver: &receiver,
                receipts: &receipts,
                files: &self.files[0],
                share: &self.share,
                storage: &self.storage,
                records: &self.bench.records,
            },
            policy,
        );
        let hints = [AddressHint { address: LOOPBACK.to_owned(), source: HintSource::DeviceConfiguration }];
        if flag(body, "outbox") {
            let results = svc.upload_outbox(rt, &hints).map_err(describe_error)?;
            let last = results.last().map(|r| r.coverage.clone());
            return Ok((format!("upload of {} outbox part(s): {}", results.len(), results.first().map_or("nothing", |r| r.attempt.label.text())), last));
        }
        let r = svc.upload(rt, &hints).map_err(describe_error)?;
        Ok((
            format!(
                "upload: {}, receipt covers seq {}{}",
                r.attempt.label.text(),
                r.covered_through.0,
                r.receipt.offer_clear_through.map_or(String::new(), |s| format!(", clear offered through {}", s.0))
            ),
            Some(r.coverage),
        ))
    }
}

fn describe_error(e: DeliveryError) -> String {
    match e {
        DeliveryError::VerificationFailed(findings) => {
            format!("export failed verification: {}", findings.iter().map(|f| format!("{} {}", f.code, f.message)).collect::<Vec<_>>().join("; "))
        }
        e => e.to_string(),
    }
}
