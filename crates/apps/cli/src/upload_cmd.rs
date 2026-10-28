//! `fieldseal export upload` (CLI §5 `export`, DEL-006, DEL-007, DEL-052): upload an export
//! file to an upload endpoint and keep the receipts it returns, each verified against the
//! trust bundle before anything is stored (DEL-064: a receipt counts only if it verifies,
//! whatever route it came by).
//!
//! The endpoint is `--to` or `FIELDSEAL_INTAKE_URL`; its scheme selects the transport (see
//! [`crate::clients`]). The export is sent without parity (DEL-016); a file with parity is
//! reduced to the form the endpoint takes before it is sent.

use std::path::PathBuf;

use fieldseal_collection::ports::ReceiptCheck;
use fieldseal_delivery::checks::{TrustReceiptCheck, receipt_claim};
use fieldseal_kernel::Value;
use fieldseal_trust::domain::TrustStore;

use crate::args::Args;
use crate::clients::{connect_upload, report};
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::support::{Res, fail, hex, read, run_command, setting, write};
use crate::trust_cmd::load_bundle;

/// Runs `export upload`.
pub fn run(raw: &[String]) -> u8 {
    run_command("export upload", raw, &["--to", "--trust-bundle", "--receipts-dir"], &[], upload)
}

fn upload(args: &Args, out: &mut Outcome) -> Res {
    let file = args.file("export upload")?;
    let Some(url) = setting(args, "--to", "FIELDSEAL_INTAKE_URL") else {
        fail(out, exit::CONFIG, "no-intake-url", &[]);
        return Ok(());
    };
    // The address first: an unbuilt or unknown transport is refused before anything is read (CLI-023).
    let client = match connect_upload(&url) {
        Ok(c) => c,
        Err(e) => {
            report(out, &url, &e);
            return Ok(());
        }
    };
    let Some(bundle) = load_bundle(args, out) else { return Ok(()) };
    let Some(bytes) = read(file, out) else { return Ok(()) };
    let body = match fieldseal_kernel::export::ExportFile::decode(&bytes).and_then(|f| f.encode(false)) {
        Ok(b) => b,
        Err(e) => {
            out.raw_finding("WIRE-100", "error", file, "", &e.to_string());
            return Ok(());
        }
    };
    let receipts = match client.upload(&body) {
        Ok(r) => r,
        Err(e) => {
            report(out, &url, &e);
            return Ok(());
        }
    };
    if receipts.is_empty() {
        fail(out, exit::FAILED, "export-no-receipts", &[("url", &url)]);
        return Ok(());
    }
    let check = TrustReceiptCheck::new(TrustStore::new(&bundle));
    let dir = PathBuf::from(args.value("--receipts-dir").unwrap_or("receipts"));
    let mut saved = Vec::new();
    for (i, raw) in receipts.iter().enumerate() {
        let verdict = receipt_claim(raw).map_err(|e| e.to_string()).and_then(|c| check.verify(&c).map(|()| c).map_err(|e| format!("{e:?}")));
        match verdict {
            Ok(claim) => {
                let path = dir.join(format!("receipt-{}-{}.fsr", i + 1, &hex(claim.tenancy.as_bytes())[..8]));
                if !write(&path, raw, false, out) {
                    return Ok(());
                }
                saved.push(Value::Map(
                    [
                        ("file".to_owned(), Value::Text(path.to_string_lossy().into_owned())),
                        ("tenancy".to_owned(), Value::Text(hex(claim.tenancy.as_bytes()))),
                        ("lastSeq".to_owned(), Value::Int(i128::from(claim.last_seq.0))),
                    ]
                    .into(),
                ));
            }
            Err(reason) => {
                fail(out, exit::FAILED, "export-bad-receipt", &[("index", &(i + 1).to_string()), ("url", &url), ("reason", &reason)]);
                out.raw_finding("DEL-007", "error", file, "", &reason);
                return Ok(());
            }
        }
    }
    out.lines.push(msg("export-uploaded", &[("file", file), ("url", &url), ("count", &saved.len().to_string()), ("dir", &dir.to_string_lossy())]));
    out.set("receipts", Value::Array(saved));
    out.set("url", Value::Text(url));
    Ok(())
}
