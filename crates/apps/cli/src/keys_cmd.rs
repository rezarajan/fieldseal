//! `fieldseal keys generate` for authority purposes (CLI §5 `keys`): generates a key in the
//! development custody and exports only its certificate signing request (TRU-016, TRU-091),
//! the step "an operator generates the key in the key custody" of the trust-hierarchy guide.
//! The key is a software key, so the output says it is unattested (CLI-007).
//!
//! `--purpose sign|agree` generates a device-style software key pair into a key file (the
//! handle) and `keys roll <handle>` writes a successor key and a roll request: the old key's
//! endorsement of the new public key (REG-060). Both are unattested (CLI-007).

use std::path::Path;

use fieldseal_kernel::Value;
use fieldseal_kernel::crypto::Purpose;
use fieldseal_trust::application::Authority;
use fieldseal_trust::domain::{KeyAlgorithm, KeyRole};
use fieldseal_trust::ports::KeyCustody;

use crate::args::Args;
use crate::custody::OsRandom;
use crate::device_keys::{DeviceKey, DevicePurpose, roll_message};
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::support::{Res, fail, hex, read, run_command, setting, usage, write};
use crate::trust_cmd::{custody_dir, use_case_failed};

/// Runs `keys <verb>`; `None` if the verb is not one of these.
pub fn run(verb: &str, raw: &[String]) -> Option<u8> {
    match verb {
        "generate" => Some(run_command("keys generate", raw, &["--purpose", "--custody", "--csr", "--caller", "--algorithm", "--out", "--state"], &[], generate)),
        "roll" => Some(run_command("keys roll", raw, &["--out", "--new-out", "--sign-key", "--state"], &[], roll)),
        _ => None,
    }
}

fn generate(args: &Args, out: &mut Outcome) -> Res {
    let name = args.required("keys generate", "--purpose")?;
    if let Some(purpose) = DevicePurpose::parse(name) {
        return generate_device(args, purpose, out);
    }
    let purpose = Purpose::parse(name).ok_or_else(|| usage("unknown-purpose", &[("value", name)]))?;
    let csr_path = args.required("keys generate", "--csr")?;
    let Some(custody) = custody_dir(args, out) else { return Ok(()) };
    let role = KeyRole::Purpose(purpose);
    // `registration` keys may be either; every other role has one algorithm.
    let algorithm = match args.value("--algorithm") {
        Some("p256") => KeyAlgorithm::P256,
        Some("x25519") => KeyAlgorithm::X25519,
        Some(other) => return Err(usage("bad-algorithm", &[("value", other)])),
        None if role.allows(KeyAlgorithm::P256) => KeyAlgorithm::P256,
        None => KeyAlgorithm::X25519,
    };
    let caller = args.value("--caller").unwrap_or("fieldseal-cli");
    let key = match custody.generate(role, algorithm) {
        Ok(k) => k,
        Err(e) => {
            out.raw_finding("TRU-001", "error", name, "", &e.to_string());
            return Ok(());
        }
    };
    match Authority::new(&custody, caller).request(&key.id, Some(purpose)).and_then(|r| r.encode().map_err(|e| fieldseal_trust::application::UseCaseError::Trust(e.into()))) {
        Ok(bytes) => {
            if write(Path::new(csr_path), &bytes, false, out) {
                let id = hex(key.id.as_bytes());
                out.lines.push(msg("key-generated", &[("purpose", name), ("key", &id), ("file", csr_path)]));
                out.lines.push(msg("dev-custody", &[]));
                out.set("keyId", Value::Text(id));
                out.set("purpose", Value::Text(name.into()));
                out.set("csr", Value::Text(csr_path.into()));
                out.set("custody", Value::Text("development-software".into()));
                out.set("attested", Value::Bool(false));
            }
        }
        Err(e) => use_case_failed(out, csr_path, &e),
    }
    Ok(())
}

fn marks(out: &mut Outcome) {
    out.lines.push(msg("unattested-key", &[]));
    out.set("custody", Value::Text("software".into()));
    out.set("attested", Value::Bool(false));
}

fn key_dir(args: &Args) -> std::path::PathBuf {
    Path::new(&setting(args, "--state", "FIELDSEAL_STATE_DIR").unwrap_or_else(|| ".fieldseal".into())).join("keys")
}

fn generate_device(args: &Args, purpose: DevicePurpose, out: &mut Outcome) -> Res {
    let key = DeviceKey::generate(purpose, &OsRandom);
    let id = hex(key.id().as_bytes());
    let path = args.value("--out").map_or_else(|| key_dir(args).join(format!("{id}.key")), std::path::PathBuf::from);
    if write(&path, key.to_file().as_bytes(), true, out) {
        let handle = path.to_string_lossy().into_owned();
        out.lines.push(msg("device-key-generated", &[("purpose", purpose.as_str()), ("key", &id), ("handle", &handle)]));
        out.set("handle", Value::Text(handle));
        out.set("keyId", Value::Text(id));
        out.set("purpose", Value::Text(purpose.as_str().into()));
        out.set("publicKey", Value::Text(hex(&key.public())));
        marks(out);
    }
    Ok(())
}

fn load_key(handle: &str, out: &mut Outcome) -> Option<DeviceKey> {
    let bytes = read(handle, out)?;
    match DeviceKey::from_file(&String::from_utf8_lossy(&bytes)) {
        Ok(k) => Some(k),
        Err(e) => {
            out.raw_finding("REG", "error", handle, "", &e);
            None
        }
    }
}

fn roll(args: &Args, out: &mut Outcome) -> Res {
    let handle = args.file("keys roll")?;
    let Some(old) = load_key(handle, out) else { return Ok(()) };
    // A signing key endorses its own successor; an agreement key can't sign, so the device's
    // current signing key does (REG-060: the request is signed by the current signing key).
    let endorser = match old.purpose {
        DevicePurpose::Sign => None,
        DevicePurpose::Agree => {
            let path = args.value("--sign-key").ok_or_else(|| usage("roll-needs-sign-key", &[]))?;
            match load_key(path, out) {
                Some(k) if k.purpose == DevicePurpose::Sign => Some(k),
                Some(_) => return Err(usage("roll-sign-key-purpose", &[("file", path)])),
                None => return Ok(()),
            }
        }
    };
    let new = DeviceKey::generate(old.purpose, &OsRandom);
    let new_id = hex(new.id().as_bytes());
    let message = roll_message(old.purpose, &old.public(), &new.public());
    let signer = endorser.as_ref().unwrap_or(&old);
    let Some(endorsement) = signer.sign_message(&message) else {
        fail(out, exit::INTERNAL, "encode-failed", &[]);
        return Ok(());
    };
    let mut fields = vec![
        ("v", Value::Int(1)),
        ("purpose", Value::Text(old.purpose.as_str().into())),
        ("old", Value::Bytes(old.public())),
        ("new", Value::Bytes(new.public())),
        ("endorsed_by", Value::Bytes(signer.public())),
        ("endorsement", Value::Bytes(endorsement.0)),
    ];
    if let Some(pop) = new.sign_message(&message) {
        fields.push(("pop", Value::Bytes(pop.0)));
    }
    let request = match fieldseal_kernel::cbor::encode(&fieldseal_kernel::cbor::map(fields)) {
        Ok(b) => b,
        Err(_) => {
            fail(out, exit::INTERNAL, "encode-failed", &[]);
            return Ok(());
        }
    };
    let new_path = args.value("--new-out").map_or_else(|| Path::new(handle).with_file_name(format!("{new_id}.key")), std::path::PathBuf::from);
    let req_path = args.value("--out").map_or_else(|| new_path.with_extension("roll"), std::path::PathBuf::from);
    if write(&new_path, new.to_file().as_bytes(), true, out) && write(&req_path, &request, false, out) {
        let (h, r) = (new_path.to_string_lossy().into_owned(), req_path.to_string_lossy().into_owned());
        out.lines.push(msg("key-rolled", &[("old", handle), ("handle", &h), ("file", &r)]));
        out.set("handle", Value::Text(h));
        out.set("keyId", Value::Text(new_id));
        out.set("previous", Value::Text(hex(old.id().as_bytes())));
        out.set("publicKey", Value::Text(hex(&new.public())));
        out.set("rollRequest", Value::Text(r));
        out.set("purpose", Value::Text(old.purpose.as_str().into()));
        marks(out);
    }
    Ok(())
}
