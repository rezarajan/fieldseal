//! `fieldseal device capture` (CLI §5 `device`, COL, DEL): the runtime of a device that
//! registered with the local stack's factory, capturing for real.
//!
//! It is the same runtime `device simulate` drives, on the same simulated platform, with three
//! differences: the device's keys are the ones it registered with (`registration request
//! --device-dir`), the bundle it imports is a real sealed bundle the device gets from the
//! factory (`bundle fetch`) and opens with its agreement key, and the
//! export is sealed to the stack's record key and carries the factory's certificate, so the
//! stack's intake endpoint accepts it. The scenario file holds a `pin` and `steps`
//! (`capture`, `status`, `consent`, `review`); the instrument and roster come from the bundle.
//! The device is a software device and unattested (CLI-007).

use std::process::ExitCode;

use fieldseal_adapters_authoring::{Format, decode};
use fieldseal_adapters_memory::collection::SimulatedDevice;
use fieldseal_adapters_memory::delivery::{MemoryFileAccess, MemoryPrivateStorage, MemoryRegistrationRecords, MemoryShareTarget};
use fieldseal_adapters_memory::bundle_opener::FileBundleOpener;
use fieldseal_adapters_memory::distribution::SoftwareAgreementKey;
use fieldseal_adapters_upload_http::{ClientConfig, HttpUploadTransport};
use fieldseal_collection::application::{Provisioning, ReviewFilter, Runtime};
use fieldseal_collection::domain::WindowId;
use fieldseal_delivery::application::{DeliveryService, Ports};
use fieldseal_delivery::checks::{TrustReceiptCheck, TrustReceiverCheck};
use fieldseal_delivery::domain::DestinationClass;
use fieldseal_delivery::ports::{PrivateStorage, ShareOutcome};
use fieldseal_distribution::domain::RuntimeProfile;
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::seal::{RecipientSecret, Suite};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::domain::RuntimeEvaluator;
use fieldseal_registration::domain::wire::TenancyCertificate;
use fieldseal_trust::domain::{AuthorityPublicKey, TrustBundle, TrustStore};
use fieldseal_trust::ports::RandomSource;

use super::{list, review_lines, step_capture, step_consent, step_status, text};
use crate::custody::OsRandom;
use crate::device_dir::DeviceDir;

/// The closed flag set of `device capture` (CLI-030, CLI-031): every valued flag at most once,
/// no unknown flag, no stray argument.
fn check_flags(args: &[String]) -> Result<(), String> {
    const VALUED: [&str; 5] = ["--device-dir", "--trust-bundle", "--bundle", "--script", "--export"];
    let mut seen: Vec<&str> = Vec::new();
    let mut i = 2;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--json" || a == "--no-parity" {
            i += 1;
            continue;
        }
        if !VALUED.contains(&a) {
            return Err(format!("`device capture` doesn't take `{a}`"));
        }
        if seen.contains(&a) {
            return Err(format!("`device capture`: {a} given more than once"));
        }
        let Some(v) = args.get(i + 1) else { return Err(format!("`device capture`: {a} needs a value")) };
        if v.starts_with("--") {
            return Err(format!("`device capture`: {a} needs a value, not `{v}`"));
        }
        seen.push(a);
        i += 2;
    }
    Ok(())
}

fn now() -> AuthorityTime {
    AuthorityTime(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64))
}

/// Runs `device capture`; `args` are all the arguments after the binary name.
pub fn run(args: &[String], json: bool) -> ExitCode {
    if let Err(m) = check_flags(args) {
        eprintln!("fieldseal: {m}");
        return ExitCode::from(2);
    }
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let need = |name: &str| flag(name).ok_or_else(|| format!("device capture needs {name}"));
    let result = (|| -> Result<(Vec<String>, Vec<String>), String> {
        let dir = DeviceDir::new(need("--device-dir")?);
        let trust = TrustBundle::decode(&std::fs::read(need("--trust-bundle")?).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let bundle_bytes = std::fs::read(need("--bundle")?).map_err(|e| e.to_string())?;
        let script_path = need("--script")?;
        let script = decode(&std::fs::read(&script_path).map_err(|e| format!("{script_path}: {e}"))?, Format::Yaml).map_err(|e| format!("{script_path}: {e}"))?;
        let (sign, agree) = dir.keys().ok_or("the device directory has no keys")?;
        let cert = TenancyCertificate::decode(&dir.certificate().ok_or("the device is not registered (no tenancy.certificate): run `registration wait --device-dir`")?).map_err(|e| e.to_string())?;
        let AuthorityPublicKey::X25519(record_pub) = trust.certificates_for(&cert.record_key).next().map(|c| c.public_key().clone()).ok_or("the trust bundle has no record key for the certificate's period")? else {
            return Err("the record key is not an X25519 key".into());
        };
        let publishing = crate::policy_support::publishing_policy();
        let scalar: [u8; 32] = agree.secret_bytes().try_into().map_err(|_| "agree.key is not a 32-byte key")?;
        let mut entropy = [0u8; 8];
        OsRandom.fill(&mut entropy);
        let device = SimulatedDevice::with_keys(u64::from_be_bytes(entropy), sign.signing().ok_or("sign.key is not a signing key")?, scalar);
        let key = SoftwareAgreementKey::new(RecipientSecret::from_bytes(Suite::Fs1P, &scalar).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let profile = RuntimeProfile { instrument_schema: fieldseal_adapters_memory::demo::DEMO_SCHEMA, localisation_reference: None };
        let clock = now;
        let opener = FileBundleOpener::new(&trust, &publishing, &key, cert.tenancy, profile, &clock);
        let mut platform = device.platform();
        platform.bundles = &opener;
        let windows = [WindowId("capture".into()), WindowId("review".into()), WindowId("delivery".into())];
        let build_anchor = sha256(b"fieldseal-simulator");
        let provisioning = Provisioning { trust: &trust, publishing: &publishing, build_anchor, provisional_record_key: record_pub, windows: &windows };
        let mut rt = Runtime::load(platform, provisioning).map_err(|e| e.to_string())?;
        let pin_text = text(&script, "pin").ok_or("the script needs `pin`")?;
        rt.create_tenancy(&crate::device::pin(pin_text)?).map_err(|e| e.to_string())?;
        if rt.tenancy() != Some(cert.tenancy) {
            return Err("the runtime's tenancy is not the one the factory registered".into());
        }
        let mut lines = vec![format!("tenancy {} resumed with its registered keys (software keys, unattested)", &fieldseal_kernel::digest::lower_hex(cert.tenancy.as_bytes())[..16])];
        rt.import_bundle(&bundle_bytes).map_err(|e| format!("the bundle was refused: {e}"))?;
        lines.push("bundle imported: opened with the device's agreement key, verified against the stack's trust bundle".into());
        let mut failures = Vec::new();
        for (n, step) in list(&script, "steps").iter().enumerate() {
            let Some((kind, body)) = step.as_map().and_then(|m| m.iter().next()) else { return Err(format!("step {} is not a map", n + 1)) };
            let result = match kind.as_str() {
                "capture" => step_capture(&mut rt, body),
                "status" => step_status(&mut rt, body),
                "consent" => step_consent(&mut rt, body),
                "review" => rt.review(&ReviewFilter::default()).map(|r| {
                    let mut l = vec![format!("review: {} subject(s), {} field check(s) raised", r.subjects.len(), r.checks.len())];
                    l.extend(review_lines(&r));
                    l.join("\n")
                }),
                other => Err(fieldseal_collection::application::CollectionError::NotAllowed(format!("`{other}` is not a step of device capture"))),
            };
            match result {
                Ok(line) => lines.push(format!("step {}: {line}", n + 1)),
                Err(e) => {
                    lines.push(format!("step {}: {kind} failed: {e}", n + 1));
                    failures.push(format!("step {} ({kind}): {e}", n + 1));
                }
            }
        }
        // The export, built and self-verified by the delivery code the runtime uses.
        let policy = RuntimeEvaluator::from_effective(&fieldseal_policy::fixtures::effective_default()).map_err(|f| format!("runtime policy: {f:?}"))?;
        let transport = HttpUploadTransport::new(ClientConfig { allow_http: true, ..ClientConfig::default() });
        let receiver = TrustReceiverCheck::new(TrustStore::new(&trust), now());
        let receipts = TrustReceiptCheck::new(TrustStore::new(&trust));
        let (files, share, storage, records) = (MemoryFileAccess::new(DestinationClass::Removable), MemoryShareTarget(ShareOutcome::Shared), MemoryPrivateStorage::new(), MemoryRegistrationRecords::new());
        let mut svc = DeliveryService::new(
            Ports { keys: &device.keys, random: &device.random, wall: &device.wall, transport: &transport, receiver: &receiver, receipts: &receipts, files: &files, share: &share, storage: &storage, records: &records },
            &policy,
        );
        let parity = Some(!args.iter().any(|a| a == "--no-parity"));
        let export = svc.build_export(&mut rt, parity).map_err(|e| format!("the export was not built: {e}"))?;
        let bytes = storage.get(&export.id).map_err(|e| e.to_string())?.ok_or("the export vanished from private storage")?;
        if let Some(path) = flag("--export") {
            std::fs::write(&path, &bytes).map_err(|e| format!("{path}: {e}"))?;
            lines.push(format!("export: {} record(s), seq {}-{}, {} bytes, parity {}; wrote {path}", export.records, export.from.0, export.through.0, export.size, if export.parity { "on" } else { "off" }));
        }
        Ok((lines, failures))
    })();
    match result {
        Ok((lines, failures)) => {
            if json {
                println!("{{\"ok\":{},\"command\":\"device capture\"}}", failures.is_empty());
            } else {
                lines.iter().for_each(|l| println!("{l}"));
            }
            if failures.is_empty() {
                ExitCode::SUCCESS
            } else {
                failures.iter().for_each(|f| eprintln!("fieldseal: {f}"));
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("fieldseal: {e}");
            ExitCode::from(3)
        }
    }
}
