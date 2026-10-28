//! `fieldseal device export` (CLI §5 `device`): the export file of a device that registered
//! with a factory (`registration request --device-dir`, `registration wait --device-dir`).
//!
//! It is written with the device's own signing key, carries the tenancy certificate the
//! factory issued, and seals its records and manifest to the record key in the trust bundle,
//! so only that authority's intake can open it. The records are the minimal real journal of a
//! tenancy: `open` (the keys, WIRE-062) and an `anchor` at the time of export (WIRE-057); the
//! capture content comes from `device simulate`. The device is a software device and
//! unattested (CLI-007).

use fieldseal_adapters_memory::intake::practice::{ExportSpec, PracticeDevice, manifest_for, tick};
use fieldseal_intake::wire::{AnchorKind, Payload, TenancyCertificate as IntakeCertificate};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::Digest;
use fieldseal_kernel::seal::RecipientKey;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, cbor};
use fieldseal_registration::domain::wire::TenancyCertificate;
use fieldseal_trust::domain::AuthorityPublicKey;
use fieldseal_trust::ports::RandomSource;

use crate::args::Args;
use crate::custody::OsRandom;
use crate::device_dir::DeviceDir;
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::support::{Res, fail, hex, now, run_command, write};
use crate::trust_cmd::load_bundle;

/// Runs `device export`.
pub fn run(raw: &[String]) -> u8 {
    run_command("device export", raw, &["--device-dir", "--trust-bundle", "--out", "-o", "--at"], &["--no-parity"], export)
}

fn export(args: &Args, out: &mut Outcome) -> Res {
    let dir = DeviceDir::new(args.required("device export", "--device-dir")?);
    let dir_name = dir.path().to_string_lossy().into_owned();
    let at = now(args)?;
    let Some(bundle) = load_bundle(args, out) else { return Ok(()) };
    let (Some((sign, _)), Some(cert_bytes)) = (dir.keys(), dir.certificate()) else {
        fail(out, exit::NOT_FOUND, "device-not-registered", &[("dir", &dir_name)]);
        return Ok(());
    };
    let Some(signing) = sign.signing() else {
        fail(out, exit::NOT_FOUND, "device-not-registered", &[("dir", &dir_name)]);
        return Ok(());
    };
    let (factory_cert, intake_cert) = match (TenancyCertificate::decode(&cert_bytes), cbor::decode(&cert_bytes).map_err(|e| e.to_string()).and_then(|v| IntakeCertificate::from_value(v).map_err(|e| e.to_string()))) {
        (Ok(f), Ok(i)) => (f, i),
        (Err(e), _) => {
            out.raw_finding("WIRE-130", "error", &dir_name, "", &e.to_string());
            return Ok(());
        }
        (_, Err(e)) => {
            out.raw_finding("WIRE-130", "error", &dir_name, "", &e);
            return Ok(());
        }
    };
    // Records and the manifest are sealed to the certificate's record key, as the bundle certifies it.
    let record = bundle.certificates_for(&factory_cert.record_key).next().cloned();
    let Some(AuthorityPublicKey::X25519(record_pub)) = record.as_ref().map(|c| c.public_key().clone()) else {
        out.raw_finding("TRU-020", "error", &dir_name, "period", "the trust bundle has no record key for the certificate's collection period");
        return Ok(());
    };
    let mut entropy = [0u8; 8];
    OsRandom.fill(&mut entropy);
    let device = PracticeDevice::registered(signing, factory_cert.handle, u64::from_be_bytes(entropy));
    if device.tenancy != factory_cert.tenancy {
        out.raw_finding("REG-033", "error", &dir_name, "tenancy", "the certificate is for another tenancy than the device's key");
        return Ok(());
    }
    let build = sha256(b"fieldseal-simulator");
    let mut jb = device.journal(RecipientKey::X25519(record_pub), factory_cert.record_key);
    let open = Payload::Open {
        tick: tick(build, 1),
        tenancy: Digest::from(*device.tenancy.as_bytes()),
        sign_pub: device.public_key(),
        agree_pub: factory_cert.agreement_key.clone(),
        evidence: vec![],
        build_anchor: build,
    };
    jb.push(&open);
    jb.push(&Payload::Anchor { tick: tick(build, 2), kind: AnchorKind::TimeToken, address: sha256(format!("anchor {}", at.0).as_bytes()), authority_time: AuthorityTime(at.0) });
    let journal = jb.journal();
    let mut manifest = manifest_for(&device, jb.records(), &journal, build);
    manifest.certificate = Some(intake_cert);
    let records = jb.records().len();
    let seal_to = RecipientKey::X25519(match record.map(|c| c.public_key().clone()) {
        Some(AuthorityPublicKey::X25519(k)) => k,
        _ => unreachable!("checked above"),
    });
    let spec = ExportSpec { device: &device, manifest, journal, seal_to, key_index: 0, parity: !args.has("--no-parity") };
    let bytes = match spec.build() {
        Ok(b) => b,
        Err(e) => {
            out.raw_finding("WIRE-100", "error", &dir_name, "", &e.to_string());
            return Ok(());
        }
    };
    let path = args.value("--out").or_else(|| args.value("-o")).map_or_else(|| std::path::PathBuf::from("export.fieldseal"), std::path::PathBuf::from);
    if write(&path, &bytes, false, out) {
        let file = path.to_string_lossy().into_owned();
        out.lines.push(msg("device-exported", &[("file", &file), ("tenancy", &hex(device.tenancy.as_bytes())), ("records", &records.to_string()), ("period", &hex(factory_cert.record_key.as_bytes()))]));
        out.lines.push(msg("unattested-keys", &[]));
        out.set("file", Value::Text(file));
        out.set("tenancy", Value::Text(hex(device.tenancy.as_bytes())));
        out.set("records", Value::Int(records as i128));
        out.set("attested", Value::Bool(false));
        out.set("keys", Value::Text("software".into()));
    }
    Ok(())
}
