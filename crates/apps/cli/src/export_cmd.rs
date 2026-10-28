//! `fieldseal export build|inspect|verify|repair` (docs/reference/spec/cli.md §export,
//! issue #52).
//!
//! ```text
//! fieldseal export build (--scenario <name> | --script <file>) -o <file> [--no-parity] [--upload]
//! fieldseal export inspect <file>
//! fieldseal export verify  <file> [--seed <n>]
//! fieldseal export repair  <file> -o <out> [--seed <n>]
//! ```
//!
//! `build` runs a simulator scenario and writes the final export of its tenancy, built and
//! self-verified as the runtime does (DEL-010–DEL-016). `verify` checks as DEL-012 does;
//! with `--seed` it opens the sealed manifest with the practice authority's record key so the
//! signatures, record signatures and chain are checked too, otherwise it checks the envelope,
//! CRCs, section order and parity only and says so. `repair` rebuilds up to four damaged
//! shards per part from the parity section and writes nothing else (CLI-016).

use std::process::ExitCode;

use fieldseal_adapters_memory::intake::practice::PracticeAuthority;
use fieldseal_delivery::export::{self, PartContext, VerifyReport, manifest_keys};
use fieldseal_intake::wire::Payload;
use fieldseal_kernel::crypto::{Purpose, tags};
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::export::ExportFile;
use fieldseal_kernel::frame::read_frames;
use fieldseal_kernel::record::Record;
use fieldseal_kernel::seal::SealedBox;
use fieldseal_kernel::{Value, cbor};
use fieldseal_trust::ports::KeyCustody;

use crate::outcome::{Outcome, exit};

struct Opts {
    positional: Vec<String>,
    out: Option<String>,
    seed: Option<u64>,
}

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts { positional: vec![], out: None, seed: None };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" | "-o" if o.out.is_some() => return Err("-o was given more than once".into()),
            "--seed" if o.seed.is_some() => return Err("--seed was given more than once".into()),
            "--json" | "--no-parity" | "--upload" | "--review" => {}
            "--out" | "-o" => o.out = Some(it.next().filter(|v| !v.starts_with("--")).cloned().ok_or("-o needs a file")?),
            "--seed" => o.seed = Some(it.next().and_then(|v| crate::support::parse_uint(v)).ok_or("--seed is a whole number")?),
            "--scenario" | "--script" => {
                it.next();
            }
            s if s.starts_with('-') => return Err(format!("unknown option {s}")),
            s => o.positional.push(s.to_owned()),
        }
    }
    Ok(o)
}

fn usage() -> u8 {
    eprintln!(
        "usage: fieldseal export build (--scenario <name> | --script <file>) -o <file> [--no-parity] [--upload]\n\
         \x20      fieldseal export inspect <file>\n\
         \x20      fieldseal export verify <file> [--seed <n>]\n\
         \x20      fieldseal export repair <file> -o <out> [--seed <n>]"
    );
    exit::USAGE
}

/// Runs `fieldseal export …`; `args` start at `export`.
pub fn run(args: &[String], json: bool) -> ExitCode {
    let Some(verb) = args.get(1).map(String::as_str) else { return ExitCode::from(usage()) };
    let rest = &args[2..];
    let opts = match parse(rest) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("fieldseal: {e}");
            return ExitCode::from(exit::USAGE);
        }
    };
    let code = match verb {
        "build" => return build(rest, &opts, json),
        "inspect" => inspect(&opts, json),
        "verify" => verify(&opts, json),
        "repair" => repair(&opts, json),
        _ => usage(),
    };
    ExitCode::from(code)
}

fn build(rest: &[String], opts: &Opts, json: bool) -> ExitCode {
    let Some(out) = &opts.out else {
        eprintln!("fieldseal: export build needs -o <file>");
        return ExitCode::from(exit::USAGE);
    };
    let flag = |name: &str| rest.iter().position(|a| a == name).and_then(|i| rest.get(i + 1)).cloned();
    let mut args = vec!["device".to_owned(), "simulate".to_owned(), "--export".to_owned(), out.clone()];
    match (flag("--script"), flag("--scenario")) {
        (Some(s), None) => args.extend(["--script".to_owned(), s]),
        (None, Some(s)) => args.extend(["--scenario".to_owned(), s]),
        _ => {
            eprintln!("fieldseal: export build needs --scenario <name> or --script <file>");
            return ExitCode::from(exit::USAGE);
        }
    }
    for f in ["--no-parity", "--upload"] {
        if rest.iter().any(|a| a == f) {
            args.push(f.to_owned());
        }
    }
    crate::device::run(&args, json)
}

fn read(opts: &Opts, o: &mut Outcome) -> Option<(String, Vec<u8>)> {
    let Some(path) = opts.positional.first() else {
        o.error(exit::USAGE, "an export file is needed".into());
        return None;
    };
    match std::fs::read(path) {
        Ok(b) => Some((path.clone(), b)),
        Err(e) => {
            o.error(exit::NOT_FOUND, format!("{path}: {e}"));
            None
        }
    }
}

fn inspect(opts: &Opts, as_json: bool) -> u8 {
    let mut o = Outcome::new("export inspect");
    let Some((path, bytes)) = read(opts, &mut o) else { return o.emit(as_json) };
    match export::inspect(&bytes) {
        Err(e) => {
            o.raw_finding(&e.code.to_string(), "error", &path, &format!("offset {}", e.offset), e.detail);
            o.fail(exit::FAILED);
        }
        Ok(info) => {
            o.lines.push(format!("{path}: {} bytes, {} part(s), handle {}", info.size, info.parts.len(), lower_hex(&info.handle)));
            let mut parts = Vec::new();
            for (i, p) in info.parts.iter().enumerate() {
                o.lines.push(format!(
                    "  part {i}: {} record(s){}, journal {} bytes, sealed manifest {} bytes, parity {}, signed with key {}",
                    p.records,
                    p.seq_range.map_or(String::new(), |(a, z)| format!(" (seq {a}-{z})")),
                    p.journal_bytes,
                    p.manifest_bytes,
                    if p.parity { "present" } else { "absent" },
                    p.signature_key
                ));
                parts.push(cbor::map([
                    ("records", Value::Int(i128::from(p.records))),
                    ("firstSeq", p.seq_range.map_or(Value::Text(String::new()), |r| Value::Int(i128::from(r.0)))),
                    ("lastSeq", p.seq_range.map_or(Value::Text(String::new()), |r| Value::Int(i128::from(r.1)))),
                    ("journalBytes", Value::Int(p.journal_bytes as i128)),
                    ("manifestBytes", Value::Int(p.manifest_bytes as i128)),
                    ("parity", Value::Bool(p.parity)),
                    ("signatureKey", Value::Int(i128::from(p.signature_key))),
                ]));
            }
            o.lines.push("  sealed manifests stay sealed".into());
            o.set("size", Value::Int(info.size as i128));
            o.set("handle", Value::Text(lower_hex(&info.handle)));
            o.set("parts", Value::Array(parts));
        }
    }
    o.emit(as_json)
}

/// What the practice authority can tell about each part: its key history, checkpoints and
/// the record key the manifest is sealed to.
fn contexts(bytes: &[u8], seed: u64) -> Vec<Option<PartContext>> {
    let Ok(file) = ExportFile::decode(bytes) else { return Vec::new() };
    let authority = PracticeAuthority::new(seed);
    file.parts
        .iter()
        .map(|part| {
            let sealed = SealedBox::decode(&part.manifest).ok()?;
            let plain = [Purpose::Record, Purpose::Registration]
                .into_iter()
                .find_map(|p| authority.custody.open(&sealed.recipient, p, &tags::EXPORT_MANIFEST_SEAL, &sealed, "fieldseal-cli").ok())?;
            let manifest = cbor::decode(&plain).ok()?;
            let mut checkpoints = Vec::new();
            for f in read_frames(&part.journal).frames {
                let Ok(record) = Record::decode(f.body) else { continue };
                let Ok(opened) = authority.custody.open(&record.payload.recipient, Purpose::Record, &tags::RECORD_SEAL, &record.payload, "fieldseal-cli") else { continue };
                if let Some(Payload::Checkpoint { cleared_through, hash_at, .. }) = cbor::decode(&opened).ok().and_then(|v| Payload::from_value(v).ok()) {
                    checkpoints.push((cleared_through, hash_at));
                }
            }
            Some(PartContext { keys: manifest_keys(&manifest), checkpoints, recipient: Some(sealed.recipient), manifest: Some(manifest) })
        })
        .collect()
}

fn report(o: &mut Outcome, path: &str, r: &VerifyReport) {
    for f in &r.findings {
        let (id, severity) = if f.error { ("DEL-012", "error") } else { ("DEL-012", "warning") };
        let at = match (f.offset, f.seq) {
            (Some(off), _) => format!("offset {off}"),
            (None, Some(seq)) => format!("seq {seq}"),
            _ => String::new(),
        };
        o.raw_finding(id, severity, path, &at, &format!("{}: {}", f.code, f.message));
    }
    o.lines.push(format!(
        "{path}: {} part(s), {} record(s) read, parity on {} part(s), signature {}",
        r.parts,
        r.records,
        r.parity_parts,
        if r.signature_checked { "checked" } else { "not checked (the manifest is sealed; pass --seed to open it)" }
    ));
    o.set("parts", Value::Int(r.parts as i128));
    o.set("records", Value::Int(i128::from(r.records)));
    o.set("signatureChecked", Value::Bool(r.signature_checked));
}

fn verify(opts: &Opts, as_json: bool) -> u8 {
    let mut o = Outcome::new("export verify");
    let Some((path, bytes)) = read(opts, &mut o) else { return o.emit(as_json) };
    let ctx = opts.seed.map(|s| contexts(&bytes, s)).unwrap_or_default();
    let r = export::verify(&bytes, &ctx);
    report(&mut o, &path, &r);
    o.emit(as_json)
}

fn repair(opts: &Opts, as_json: bool) -> u8 {
    let mut o = Outcome::new("export repair");
    let Some((path, bytes)) = read(opts, &mut o) else { return o.emit(as_json) };
    let Some(out) = &opts.out else {
        o.error(exit::USAGE, "export repair needs -o <out>".into());
        return o.emit(as_json);
    };
    match export::repair(&bytes) {
        Err(e) => {
            o.raw_finding("DEL-014", "error", &path, &format!("offset {}", e.offset), &format!("{}: {}", e.code, e.detail));
            let salvaged = fieldseal_kernel::export::salvage_frames(&bytes).len();
            o.lines.push(format!("{path}: damage exceeds the parity; {salvaged} intact record frame(s) can still be salvaged"));
            o.set("salvagedFrames", Value::Int(salvaged as i128));
            o.fail(exit::FAILED);
        }
        Ok(fixed) => {
            let shards: Vec<String> = fixed.damaged.iter().map(|(p, s)| format!("part {p} shard {s}")).collect();
            o.lines.push(format!("{path}: rebuilt {} shard(s) from parity{}", fixed.shards_rebuilt, if shards.is_empty() { String::new() } else { format!(": {}", shards.join(", ")) }));
            o.set("shardsRebuilt", Value::Int(fixed.shards_rebuilt as i128));
            o.set("rebuilt", Value::Array(shards.iter().map(|s| Value::Text(s.clone())).collect()));
            // Parity is not signed (WIRE-108): the repaired file is verified against the signed hashes.
            let ctx = opts.seed.map(|s| contexts(&fixed.bytes, s)).unwrap_or_default();
            let r = export::verify(&fixed.bytes, &ctx);
            report(&mut o, out, &r);
            if r.ok() {
                match std::fs::write(out, &fixed.bytes) {
                    Ok(()) => o.lines.push(format!("wrote {out}")),
                    Err(e) => o.error(exit::NOT_FOUND, format!("{out}: {e}")),
                }
            } else {
                o.lines.push("the repaired file does not verify; nothing was written".into());
            }
        }
    }
    o.emit(as_json)
}
