//! `fieldseal intake`: run exports through the gate, replay them, show a data contract and
//! write a practice export (docs/reference/spec/cli.md §intake, issue #53).
//!
//! The authority here is the practice authority (fixed seed, software keys, never attested):
//! the commands exercise the real gate with real signatures, seals and receipts against
//! in-memory ports, or against a landing directory with `--out`.

use std::process::ExitCode;

use fieldseal_adapters_landing_files::export::reader::{Published, export_table};
use fieldseal_adapters_landing_files::export::{ExportKey, ExportOptions, Format, KeyedSubject, write_export};
use fieldseal_adapters_landing_files::{FileDataPlatform, json};
use fieldseal_adapters_memory::intake::practice::{PracticeAuthority, PracticeDevice, at, manifest_for, tick};
use fieldseal_adapters_memory::intake::{MemoryDataPlatform, MemoryInstrumentSource, MemoryRosterHistory, MemorySubmissionStore, MemoryTenancyRegistry};
use fieldseal_adapters_memory::policy::BuiltInPolicyEngine;
use fieldseal_adapters_memory::trust::SeededRandom;
use fieldseal_instrument::application::validate_instrument;
use fieldseal_intake::data_contract::generate_data_contract;
use fieldseal_intake::domain::{FindingKind, GateState, SubmissionSource, TenancyView};
use fieldseal_intake::gate::{IngestReport, IntakeService};
use fieldseal_intake::ports::DataPlatform;
use fieldseal_intake::wire::Payload;
use fieldseal_kernel::digest::{instrument_fingerprint, lower_hex, sha256};
use fieldseal_kernel::id::Salt;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, cbor};

use crate::messages::msg;

struct Opts {
    positional: Vec<String>,
    json: bool,
    seed: u64,
    salt: [u8; 32],
    instruments: Vec<String>,
    devices: Vec<String>,
    out: Option<String>,
    reveal: bool,
    now: AuthorityTime,
    /// `practice --no-parity`: the form the upload endpoint takes (parity is for storage and transfer by file).
    no_parity: bool,
    /// `results`: the intake app's landing directory.
    landing: Option<String>,
    /// `results`: the directory of `*.published` files.
    published: Option<String>,
    /// `results`: the export pseudonymisation key file.
    export_key: Option<String>,
    /// `results`: the trust bundle that the publications are verified against.
    trust_bundle: Option<String>,
    /// `results --format`: `jsonl`, `csv` or both.
    format: Option<String>,
}

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts { positional: vec![], json: false, seed: 7, salt: [0; 32], instruments: vec![], devices: vec![], out: None, reveal: false, now: at(20), no_parity: false, landing: None, published: None, export_key: None, trust_bundle: None, format: None };
    let mut seen = std::collections::BTreeSet::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().filter(|v| !v.starts_with("--")).cloned().ok_or_else(|| format!("{name} needs a value"));
        let flag = a.as_str();
        if matches!(flag, "--seed" | "--now" | "--salt" | "--out" | "-o" | "--landing" | "--published" | "--export-key" | "--trust-bundle" | "--format") && !seen.insert(if flag == "-o" { "--out" } else { flag }) {
            return Err(format!("{flag} was given more than once"));
        }
        match flag {
            "--json" => o.json = true,
            "--reveal" => o.reveal = true,
            "--no-parity" => o.no_parity = true,
            "--seed" => o.seed = crate::support::parse_uint(&value("--seed")?).ok_or_else(|| "--seed is a whole number".to_owned())?,
            "--now" => o.now = AuthorityTime(crate::support::parse_uint(&value("--now")?).ok_or_else(|| "--now is milliseconds".to_owned())?),
            "--salt" => {
                let h = value("--salt")?;
                o.salt = crate::support::unhex(&h).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or_else(|| "--salt is 64 hex digits".to_owned())?;
            }
            "--instrument" => o.instruments.push(value("--instrument")?),
            "--device" => o.devices.push(value("--device")?),
            "--out" | "-o" => o.out = Some(value("--out")?),
            "--landing" => o.landing = Some(value("--landing")?),
            "--published" => o.published = Some(value("--published")?),
            "--export-key" => o.export_key = Some(value("--export-key")?),
            "--trust-bundle" => o.trust_bundle = Some(value("--trust-bundle")?),
            "--format" => o.format = Some(value("--format")?),
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            s => o.positional.push(s.to_owned()),
        }
    }
    Ok(o)
}

fn load_instrument(path: &str) -> Result<fieldseal_instrument::domain::Instrument, String> {
    let doc = fieldseal_adapters_authoring::decode_path(std::path::Path::new(path)).map_err(|e| format!("{path}: {e}"))?;
    validate_instrument(&doc).map(|v| v.instrument).map_err(|f| format!("{path}: the instrument is invalid ({} finding(s)); run `instrument validate`", f.iter().count()))
}

fn fingerprint(i: &fieldseal_instrument::domain::Instrument, salt: [u8; 32]) -> Result<fieldseal_kernel::id::Fingerprint, String> {
    let canonical = cbor::encode(&i.to_value()).map_err(|e| e.to_string())?;
    Ok(instrument_fingerprint(&Salt::from(salt), &canonical))
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: fieldseal intake contract <instrument> [--salt <64 hex>] [--out <dir>] [--json]\n\
         \x20      fieldseal intake run <export>... [--instrument <file>]... [--device <label>]... [--seed <n>] [--now <ms>] [--out <dir>] [--json]\n\
         \x20      fieldseal intake replay <export> [same options as run]\n\
         \x20      fieldseal intake practice --out <file> [--device <label>] [--seed <n>] [--no-parity]\n\
         \x20      fieldseal intake results --landing <dir> --published <dir> --export-key <file> --trust-bundle <file> --out <dir> [--format jsonl,csv] [--json]"
    );
    ExitCode::from(2)
}

/// Runs `fieldseal intake …`; `args` start at `intake`.
pub fn run(args: &[String]) -> ExitCode {
    let Some(sub) = args.get(1) else { return usage() };
    let opts = match parse(&args[2..]) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("fieldseal: {e}");
            return ExitCode::from(2);
        }
    };
    let result = match sub.as_str() {
        "contract" => contract(&opts),
        "run" => gate(&opts, false),
        "replay" => gate(&opts, true),
        "practice" => practice(&opts),
        "results" => results(&opts),
        _ => return usage(),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("fieldseal: {e}");
            ExitCode::from(2)
        }
    }
}

fn contract(o: &Opts) -> Result<ExitCode, String> {
    let path = o.positional.first().ok_or("intake contract needs an instrument file")?;
    let inst = load_instrument(path)?;
    let fp = fingerprint(&inst, o.salt)?;
    let c = generate_data_contract(fp, &inst);
    if let Some(dir) = &o.out {
        let p = FileDataPlatform::new(dir).map_err(|e| e.to_string())?;
        let written = p.write_contract(&c).map_err(|e| e.to_string())?;
        eprintln!("wrote {}", written.display());
    }
    if o.json {
        println!("{}", json(&c.to_value()));
    } else {
        println!("instrument {} ({})", lower_hex(fp.as_bytes()), fp.short_form());
        println!("languages: {} (default {})", c.languages.join(", "), c.default_language);
        println!("{:<44} {:<8} {:<10} {:<5} nonresponse", "item", "type", "unit", "req");
        for i in &c.items {
            let unit = i.unit.clone().unwrap_or_default();
            println!("{:<44} {:<8} {:<10} {:<5} {}", i.path, i.value_type, unit, if i.required { "yes" } else { "" }, i.nonresponse.join(","));
        }
        println!("{} code list(s), {} expectation(s)", c.code_lists.len(), c.expectations.len());
    }
    Ok(ExitCode::SUCCESS)
}

fn report_value(file: &str, r: &IngestReport) -> Value {
    let text = |s: &str| Value::Text(s.to_owned());
    let mut m = vec![("file", text(file)), ("state", text(&format!("{:?}", r.submission.state())))];
    if let Some(rej) = r.submission.rejection() {
        m.push((
            "rejection",
            cbor::map([("stage", text(&format!("{:?}", rej.stage))), ("code", text(&rej.code.to_string())), ("detail", text(&rej.detail))]),
        ));
    }
    m.push((
        "findings",
        Value::Array(
            r.submission
                .findings()
                .iter()
                .map(|f| cbor::map([("kind", text(&format!("{:?}", f.kind))), ("rule", text(&f.rule)), ("detail", text(&f.detail))]))
                .collect(),
        ),
    ));
    m.push((
        "receipts",
        Value::Array(
            r.receipts
                .iter()
                .map(|x| {
                    cbor::map([
                        ("tenancy", text(&lower_hex(x.receipt.tenancy.as_bytes()))),
                        ("last_seq", Value::Int(i128::from(x.receipt.last_seq))),
                        ("bytes", Value::Bytes(x.bytes.clone())),
                    ])
                })
                .collect(),
        ),
    ));
    let s = &r.summary;
    m.push((
        "summary",
        cbor::map([
            ("landed", Value::Int(s.landed as i128)),
            ("duplicates", Value::Int(s.duplicates as i128)),
            ("held", Value::Int(s.held as i128)),
            ("conflicts", Value::Int(s.conflicts as i128)),
            ("observations", Value::Int(s.observations as i128)),
        ]),
    ));
    cbor::map(m)
}

fn gate(o: &Opts, dry: bool) -> Result<ExitCode, String> {
    if o.positional.is_empty() {
        return Err("intake run needs at least one export file".into());
    }
    let authority = PracticeAuthority::new(o.seed);
    let devices: Vec<PracticeDevice> = o.devices.iter().map(|l| PracticeDevice::new(l)).collect();
    let registry = MemoryTenancyRegistry::new(devices.iter().map(|d| TenancyView::new(d.tenancy, d.handle, vec![d.public_key()])).collect());
    let instruments = MemoryInstrumentSource::new();
    let mut fingerprints = Vec::new();
    for path in &o.instruments {
        let inst = load_instrument(path)?;
        let fp = fingerprint(&inst, o.salt)?;
        fingerprints.push(fp);
        instruments.add(fp, inst);
    }
    // `replay --reveal` lands into a scratch in-memory platform (never `--out`) so the decrypted
    // observations can be shown; without `--reveal` a replay writes nothing and prints no
    // subject data (CLI-008).
    let reveal = dry && o.reveal;
    if reveal {
        eprintln!("warning: --reveal prints decrypted subject data to stdout; handle the output as personal data (CLI-008)");
    }
    let platform: Box<dyn DataPlatform> = match &o.out {
        _ if reveal => Box::new(MemoryDataPlatform::new()),
        Some(dir) => Box::new(FileDataPlatform::new(dir).map_err(|e| e.to_string())?),
        None => Box::new(MemoryDataPlatform::new()),
    };
    let store = MemorySubmissionStore::new();
    let rosters = MemoryRosterHistory::new();
    let engine = BuiltInPolicyEngine;
    let effective = fieldseal_policy::fixtures::effective_default();
    let random = SeededRandom::new(o.seed);
    let svc = IntakeService {
        store: &store,
        registry: &registry,
        rosters: &rosters,
        instruments: &instruments,
        platform: &*platform,
        custody: &authority.custody,
        policy: &engine,
        effective: &effective,
        random: &random,
        trust: &authority.bundle,
        revocations: vec![],
        receipt_key: authority.receipt_key,
        caller: "fieldseal-cli",
    };
    let mut failed = false;
    let mut all = vec![];
    for file in &o.positional {
        let bytes = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
        let report = if dry && !reveal { svc.dry_run(&bytes, SubmissionSource::File, o.now) } else { svc.ingest(&bytes, SubmissionSource::File, o.now) }
            .map_err(|e| format!("{file}: {e}"))?;
        failed |= matches!(report.submission.state(), GateState::Rejected | GateState::Quarantined);
        if o.json {
            all.push(report_value(file, &report));
        } else {
            println!("{file}: {:?}", report.submission.state());
            if let Some(r) = report.submission.rejection() {
                println!("  rejected at {:?} with {}: {}", r.stage, r.code, r.detail);
            }
            for f in report.submission.findings().iter().filter(|f| f.kind != FindingKind::Rejection) {
                println!("  [{:?}] {}: {}", f.kind, f.rule, f.detail);
            }
            for x in &report.receipts {
                println!("  receipt: last_seq {} ({} bytes)", x.receipt.last_seq, x.bytes.len());
            }
            let s = &report.summary;
            println!("  landed {}, duplicate {}, held {}, conflicts {}, observations {}", s.landed, s.duplicates, s.held, s.conflicts, s.observations);
        }
    }
    if reveal {
        let mut rows = Vec::new();
        for fp in &fingerprints {
            for l in platform.observations(fp).map_err(|e| e.to_string())? {
                let ob = &l.observation;
                rows.push((lower_hex(fp.as_bytes()), ob.subject.as_str().to_owned(), format!("{:?}", ob.item), format!("{:?}", ob.reading)));
            }
        }
        if o.json {
            let observations = rows
                .iter()
                .map(|(i, s, it, r)| cbor::map([("instrument", Value::Text(i.clone())), ("subject", Value::Text(s.clone())), ("item", Value::Text(it.clone())), ("reading", Value::Text(r.clone()))]))
                .collect();
            all.push(cbor::map([("revealed", Value::Bool(true)), ("observations", Value::Array(observations))]));
        } else {
            for (i, s, it, r) in &rows {
                println!("  observation {} subject {s} {it} = {r}", &i[..8]);
            }
        }
    }
    if o.json {
        println!("{}", json(&Value::Array(all)));
    }
    Ok(if failed { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

/// `intake results`: the results export of a landing directory (INT-085 to INT-088).
///
/// The landing is read through the landing-files adapter as one snapshot, and the instruments
/// and layouts come from the published directory, verified against the trust bundle. The key
/// is the file the intake app uses; this command never creates or derives one.
fn results(o: &Opts) -> Result<ExitCode, String> {
    let need = |v: &Option<String>, flag: &str| v.clone().ok_or_else(|| format!("intake results needs {flag}"));
    let (landing, published, key_file) = (need(&o.landing, "--landing <dir>")?, need(&o.published, "--published <dir>")?, need(&o.export_key, "--export-key <file>")?);
    let (trust_file, out) = (need(&o.trust_bundle, "--trust-bundle <file>")?, need(&o.out, "--out <dir>")?);
    let mut formats = std::collections::BTreeSet::new();
    for f in o.format.as_deref().unwrap_or("jsonl,csv").split(',') {
        formats.insert(match f {
            "jsonl" => Format::Jsonl,
            "csv" => Format::Csv,
            other => return Err(format!("--format is jsonl, csv or both, not `{other}`")),
        });
    }
    let key = ExportKey::load_file(std::path::Path::new(&key_file)).map_err(|e| e.to_string())?;
    let bundle_bytes = std::fs::read(&trust_file).map_err(|e| format!("{trust_file}: {e}"))?;
    let bundle = fieldseal_trust::domain::TrustBundle::decode(&bundle_bytes).map_err(|e| format!("{trust_file}: {e}"))?;
    let published = Published::read(std::path::Path::new(&published), &bundle, &crate::policy_support::publishing_policy()).map_err(|e| e.to_string())?;
    let snapshot = FileDataPlatform::open_read_only(&landing).map_err(|e| e.to_string())?;
    let mapper = KeyedSubject::new(key);
    let table = export_table(&snapshot, &published, &mapper).map_err(|e| e.to_string())?;
    let result = write_export(&table, &ExportOptions { formats, subject: Box::new(mapper) }, std::path::Path::new(&out)).map_err(|e| e.to_string())?;
    if o.json {
        let files = result
            .files
            .iter()
            .map(|f| {
                let mut e = vec![("name", Value::Text(f.name.clone())), ("sha256", Value::Text(f.sha256.clone())), ("bytes", Value::Int(i128::from(f.bytes)))];
                if let Some(rows) = f.rows {
                    e.push(("rows", Value::Int(i128::from(rows))));
                }
                cbor::map(e)
            })
            .collect();
        println!(
            "{}",
            json(&cbor::map([
                ("files", Value::Array(files)),
                ("landing_mark", Value::Int(i128::from(table.landing_mark()))),
                ("manifest_sha256", Value::Text(result.manifest_sha256.clone())),
            ]))
        );
    } else {
        println!("{}", msg("results-written", &[("dir", &out), ("count", &result.files.len().to_string()), ("mark", &table.landing_mark().to_string())]));
        for f in &result.files {
            let bytes = f.bytes.to_string();
            println!("{}", match f.rows {
                Some(rows) => msg("results-file", &[("name", &f.name), ("bytes", &bytes), ("rows", &rows.to_string())]),
                None => msg("results-file-plain", &[("name", &f.name), ("bytes", &bytes)]),
            });
        }
        println!("{}", msg("results-manifest", &[("digest", &result.manifest_sha256)]));
        println!("{}", msg("results-unprotected", &[]));
    }
    if o.json {
        eprintln!("{}", msg("results-unprotected", &[]));
    }
    Ok(ExitCode::SUCCESS)
}

fn practice(o: &Opts) -> Result<ExitCode, String> {
    use fieldseal_adapters_memory::intake::practice::ExportSpec;
    let out = o.out.as_ref().ok_or("intake practice needs --out <file>")?;
    let authority = PracticeAuthority::new(o.seed);
    let label = o.devices.first().map_or("practice-device", String::as_str);
    let device = PracticeDevice::new(label);
    let build = sha256(b"practice build");
    let mut jb = device.journal(authority.record_recipient(), authority.record_key.id);
    jb.push(&jb.open_payload(tick(build, 1), build));
    jb.push(&Payload::Anchor { tick: tick(build, 2), kind: fieldseal_intake::wire::AnchorKind::TimeToken, address: sha256(b"anchor 1"), authority_time: at(5) });
    let journal = jb.journal();
    let mut manifest = manifest_for(&device, jb.records(), &journal, build);
    manifest.certificate = Some(authority.tenancy_certificate(
        &device,
        fieldseal_intake::wire::CertWindow { not_before: at(0), not_after: at(100), grace: 30 * AuthorityTime::DAY },
        &[],
    ));
    let spec = ExportSpec { device: &device, manifest, journal, seal_to: authority.record_recipient(), key_index: 0, parity: !o.no_parity };
    std::fs::write(out, spec.build().map_err(|e| e.to_string())?).map_err(|e| format!("{out}: {e}"))?;
    eprintln!("wrote {out}; run it with: fieldseal intake run {out} --device {label} --seed {}", o.seed);
    Ok(ExitCode::SUCCESS)
}
