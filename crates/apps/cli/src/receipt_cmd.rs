//! `fieldseal receipt issue|verify` (CLI §5 `receipt`, DEL-006, DEL-007, DEL-043, DEL-044,
//! INT-014): issue a receipt the way Intake does, signed by the `receipt` purpose key in the
//! development custody, and verify one against a trust bundle.
//!
//! The receipt is Intake's own `Receipt` (WIRE-142), signed through the same `KeyCustody` port
//! and domain tag, so it verifies wherever an Intake receipt does. The key is a software key
//! in a local directory: the output says it is unattested (CLI-007, CLI-019).

use std::path::{Path, PathBuf};

use fieldseal_delivery::checks::{TrustReceiptCheck, receipt_claim, receipt_qr_text};
use fieldseal_collection::ports::{ReceiptCheck, ReceiptCheckError};
use fieldseal_intake::wire::Receipt;
use fieldseal_kernel::Value;
use fieldseal_kernel::crypto::{Purpose, tags};
use fieldseal_kernel::id::{Digest, KeyId, TenancyId};
use fieldseal_trust::domain::{KeyRole, TrustStore};
use fieldseal_trust::ports::KeyCustody;

use crate::args::Args;
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::support::{Res, fail, hex, now, read, run_command, unhex, usage, write};
use crate::trust_cmd::{custody_dir, load_bundle};

/// Runs `receipt <verb>`; `None` if the verb is not one of these.
pub fn run(verb: &str, raw: &[String]) -> Option<u8> {
    Some(match verb {
        "issue" => run_command(
            "receipt issue",
            raw,
            &["--tenancy", "--last-seq", "--journal-hash", "--of", "--custody", "--key", "--at", "--out", "-o", "--qr", "--caller"],
            &[],
            issue,
        ),
        "verify" => run_command("receipt verify", raw, &["--trust-bundle", "--tenancy", "--journal-hash"], &[], verify),
        _ => return None,
    })
}

fn hex32(args: &Args, flag: &str) -> Res<[u8; 32]> {
    let v = args.required("receipt", flag)?;
    unhex(v).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or_else(|| usage("bad-hex32", &[("flag", flag), ("value", v)]))
}

fn issue(args: &Args, out: &mut Outcome) -> Res {
    let tenancy = TenancyId::from(hex32(args, "--tenancy")?);
    let hash_at = Digest::from(hex32(args, "--journal-hash")?);
    let seq_text = args.required("receipt issue", "--last-seq")?;
    let last_seq: u64 = crate::support::parse_uint(seq_text).ok_or_else(|| usage("bad-number", &[("flag", "--last-seq"), ("value", seq_text)]))?;
    // What the receipt acknowledges: the export or upload's content address; the journal hash
    // when none is given.
    let of = match args.value("--of") {
        Some(_) => Digest::from(hex32(args, "--of")?),
        None => hash_at,
    };
    let received = now(args)?;
    let Some(custody) = custody_dir(args, out) else { return Ok(()) };
    let role = KeyRole::Purpose(Purpose::Receipt);
    let key = match args.value("--key") {
        Some(k) => unhex(k).and_then(|b| KeyId::from_bytes(&b).ok()),
        None => custody.sole_key(role),
    };
    let Some(key) = key.filter(|k| custody.holds(k)) else {
        fail(out, exit::CONFIG, "no-receipt-key", &[]);
        return Ok(());
    };
    let structure = Receipt::unsigned_structure(&tenancy, last_seq, &hash_at, received, &of, &key);
    let caller = args.value("--caller").unwrap_or("fieldseal-cli");
    let sig = match custody.sign(&key, role, &tags::RECEIPT, &structure, caller) {
        Ok(s) => s,
        Err(e) => {
            out.raw_finding("TRU-001", "error", "(receipt)", "", &e.to_string());
            return Ok(());
        }
    };
    let receipt = Receipt { tenancy, last_seq, hash_at, received, of, signer: key, sig };
    let bytes = match receipt.encode() {
        Ok(b) => b,
        Err(e) => {
            out.raw_finding("WIRE-144", "error", "(receipt)", "", e.detail);
            return Ok(());
        }
    };
    let path = args.value("--out").or_else(|| args.value("-o")).map_or_else(|| PathBuf::from("receipt.fsr"), PathBuf::from);
    if !write(&path, &bytes, false, out) {
        return Ok(());
    }
    if let Some(qr) = args.value("--qr") {
        let Some(svg) = receipt_qr_text(&bytes).and_then(|t| crate::registration_cmd::qr_svg(&t)) else {
            fail(out, exit::INTERNAL, "qr-failed", &[]);
            return Ok(());
        };
        if !write(Path::new(qr), svg.as_bytes(), false, out) {
            return Ok(());
        }
        out.set("qr", Value::Text(qr.into()));
    }
    out.lines.push(msg("receipt-issued", &[("tenancy", &hex(tenancy.as_bytes())), ("seq", &last_seq.to_string()), ("file", &path.to_string_lossy())]));
    out.lines.push(msg("dev-custody", &[]));
    out.set("tenancy", Value::Text(hex(tenancy.as_bytes())));
    out.set("lastSeq", Value::Int(i128::from(last_seq)));
    out.set("signer", Value::Text(hex(key.as_bytes())));
    out.set("file", Value::Text(path.to_string_lossy().into_owned()));
    out.set("custody", Value::Text("development-software".into()));
    out.set("attested", Value::Bool(false));
    Ok(())
}

fn verify(args: &Args, out: &mut Outcome) -> Res {
    let file = args.file("receipt verify")?;
    let expect_tenancy = args.value("--tenancy").map(|_| hex32(args, "--tenancy")).transpose()?;
    let expect_hash = args.value("--journal-hash").map(|_| hex32(args, "--journal-hash")).transpose()?;
    let Some(bundle) = load_bundle(args, out) else { return Ok(()) };
    let Some(bytes) = read(file, out) else { return Ok(()) };
    let claim = match receipt_claim(&bytes) {
        Ok(c) => c,
        Err(e) => {
            out.raw_finding("WIRE-142", "error", file, "", e.detail);
            return Ok(());
        }
    };
    let mut ok = true;
    // DEL-007: signature, tenancy and journal hash, all before any delivery state changes.
    match TrustReceiptCheck::new(TrustStore::new(&bundle)).verify(&claim) {
        Ok(()) => {}
        Err(e) => {
            ok = false;
            let why = match e {
                ReceiptCheckError::BadSignature => "the receipt's signature is invalid",
                _ => "the receipt's signer is not a trusted receipt key",
            };
            out.raw_finding("DEL-007", "error", file, "", why);
        }
    }
    if expect_tenancy.is_some_and(|t| t != *claim.tenancy.as_bytes()) {
        ok = false;
        out.raw_finding("DEL-007", "error", file, "tenancy", "the receipt is for another tenancy");
    }
    if expect_hash.is_some_and(|h| h != *claim.journal_hash.as_bytes()) {
        ok = false;
        out.raw_finding("DEL-007", "error", file, "hash_at", "the receipt's journal hash is not the expected one");
    }
    out.set("tenancy", Value::Text(hex(claim.tenancy.as_bytes())));
    out.set("lastSeq", Value::Int(i128::from(claim.last_seq.0)));
    out.set("signer", Value::Text(hex(claim.signer.as_bytes())));
    out.set("verified", Value::Bool(ok));
    if ok {
        out.lines.push(msg("receipt-verified", &[("file", file), ("seq", &claim.last_seq.0.to_string())]));
    }
    Ok(())
}
