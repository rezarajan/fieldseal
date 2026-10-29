//! `fieldseal bundle build | verify | inspect` (docs/reference/spec/cli.md §bundle,
//! DIS-001–DIS-062): build a sealed, signed bundle for a software device, and check one the
//! way a runtime does.
//!
//! The in-memory adapters keep nothing between runs, so `build` stands up the whole demo
//! factory (authority, transparency log, registry, one registered software device)
//! deterministically from `--seed`, publishes the instrument and layouts it is given, and
//! writes three files: the bundle, the trust bundle a device would be provisioned with, and
//! the device's key. `verify` and `inspect` need only those files. The software keys are
//! unattested and are never reported otherwise (TRU-061). A roster is released to them only
//! with `--allow-unattested`, the development factory's non-production allowance (REG-017):
//! policy then releases it with a flag. Production never grants the allowance.
//!
//! Roster contents never reach stdout or stderr (CLI-008): only counts do.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use fieldseal_adapters_memory::demo::{DEMO_SCHEMA, DemoWorld};
use fieldseal_adapters_memory::distribution::SoftwareAgreementKey;
use fieldseal_distribution::application::{BuildRequest, HeldState, ImportState, VerifyBundle};
use fieldseal_distribution::domain::{
    BundleFile, ConsentState, DistributionError, MAX_BUNDLE_FILE, Roster, RosterEntry, RuntimeProfile, file_name,
};
use fieldseal_instrument::application::validate_instrument;
use fieldseal_kernel::crypto::tags;
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::id::{CohortId, Generation, Salt, SubjectId, TenancyId};
use fieldseal_kernel::seal::{RecipientSecret, Suite};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, cbor};
use fieldseal_policy::domain::Controls;
use fieldseal_publishing::domain::ArtefactKind;
use fieldseal_trust::domain::{TrustBundle, TrustStore};

use crate::args::Args;
use crate::clients::{BundleReply, connect_factory, report};
use crate::custody::OsRandom;
use crate::device_dir::DeviceDir;
use crate::json;
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::support::{Res, fail, now, setting, usage};
use fieldseal_trust::ports::RandomSource;

const USAGE: &str = "usage: fieldseal bundle build --instrument <file> (--roster <file> | --practice) --out-dir <dir> [--layout <file>]... [--device <label> | --device-dir <dir>] [--seed <n>] [--time <ms>] [--generation <n>] [--salt <64 hex>] [--allow-unattested] [--json]\n\
     \x20      fieldseal bundle verify <file> --trust <file> --device-file <file> [--now <ms>] [--json]\n\
     \x20      fieldseal bundle inspect <file> [--trust <file>] [--now <ms>] [--json]\n\
     \x20      fieldseal bundle open <file> --key <handle> --trust <file> [--tenancy <hex>] [--now <ms>] [--reveal --out <file>] [--json]\n\
     \x20      fieldseal bundle fetch --device-dir <dir> [--factory-url <url>] [--trust-bundle <file>] [--held <seq>] [--at <time>] --out <path> [--json]";

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn int(n: impl Into<i128>) -> Value {
    Value::Int(n.into())
}

/// The system clock, which only the CLI (a composition root) may read.
fn system_millis() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

use crate::support::unhex;

fn number(args: &Args, flag: &str) -> Result<Option<u64>, String> {
    args.value(flag).map(|v| crate::support::parse_uint(v).ok_or_else(|| format!("{flag} needs a whole number, not `{v}`"))).transpose()
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

fn load_document(path: &str) -> Result<Value, String> {
    read(path)?;
    fieldseal_adapters_authoring::decode_path(std::path::Path::new(path)).map_err(|e| format!("{path}: {e}"))
}

fn metadata(doc: &Value, key: &str, path: &str) -> Result<String, String> {
    doc.as_map()
        .and_then(|m| m.get("metadata"))
        .and_then(Value::as_map)
        .and_then(|m| m.get(key))
        .and_then(Value::as_text)
        .map(str::to_owned)
        .ok_or_else(|| format!("{path}: no metadata.{key}"))
}

/// Runs `fieldseal bundle …`; `args` start at `bundle`.
pub fn run(args: &[String]) -> ExitCode {
    let Some(sub) = args.get(1) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    // `fetch` reports through an `Outcome` like the registration verbs, so it has its own exit codes.
    if sub == "fetch" {
        return ExitCode::from(crate::support::run_command("bundle fetch", &args[2..], &["--device-dir", "--factory-url", "--trust-bundle", "--held", "--out", "--at"], &[], fetch));
    }
    let (valued, switches): (&[&str], &[&str]) = match sub.as_str() {
        "build" => (&["--instrument", "--layout", "--roster", "--out-dir", "--seed", "--time", "--generation", "--salt", "--device", "--device-dir"], &["--practice", "--allow-unattested"]),
        "verify" => (&["--trust", "--device-file", "--now"], &["--stack"]),
        "inspect" => (&["--trust", "--now"], &[]),
        "open" => (&["--key", "--trust", "--tenancy", "--now", "--out"], &["--reveal"]),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let parsed = match Args::parse(&format!("bundle {sub}"), &args[2..], valued, switches) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("fieldseal: {}", e.0);
            return ExitCode::from(2);
        }
    };
    let result = match sub.as_str() {
        "build" => build(&parsed),
        "verify" => verify(&parsed),
        "open" => open(&parsed),
        _ => inspect(&parsed),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("fieldseal: {e}");
            ExitCode::from(2)
        }
    }
}

// ---- fetch ------------------------------------------------------------------------------------

/// `bundle fetch` (CLI-049): asks the factory for the device's latest bundle with a
/// proof-of-possession token made by the device's signing key, and stores it whole. With
/// `--held` equal to the latest the factory answers that it is current and nothing is written.
fn fetch(args: &Args, out: &mut Outcome) -> Res {
    let dir = DeviceDir::new(args.value("--device-dir").ok_or_else(|| usage("missing-flag", &[("command", "bundle fetch"), ("flag", "--device-dir")]))?);
    let target = args.value("--out").ok_or_else(|| usage("missing-flag", &[("command", "bundle fetch"), ("flag", "--out")]))?;
    let held = args.value("--held").map(|v| crate::support::parse_uint(v).ok_or_else(|| usage("bad-number", &[("flag", "--held"), ("value", v)]))).transpose()?;
    let at = now(args)?;
    let Some(device) = dir.software_device() else {
        fail(out, exit::NOT_FOUND, "device-not-registered", &[("dir", &dir.path().to_string_lossy())]);
        return Ok(());
    };
    let Some(url) = setting(args, "--factory-url", "FIELDSEAL_FACTORY_URL") else {
        fail(out, exit::CONFIG, "no-factory-url", &[]);
        return Ok(());
    };
    let client = match connect_factory(&url) {
        Ok(c) => c,
        Err(e) => {
            report(out, &url, &e);
            return Ok(());
        }
    };
    // The token names the request URL without its query: `held` is not signed (WIRE-171).
    let mut jti = [0u8; 16];
    OsRandom.fill(&mut jti);
    let endpoint = format!("{}/v1/bundle", url.trim_end_matches('/'));
    let header = device.pop_token(device.tenancy(), "GET", &endpoint, AuthorityTime(at.0), jti, None).to_header();
    let (bytes, sequence, file_name) = match client.bundle(&header, held) {
        Ok(BundleReply::Bundle { bytes, sequence, file_name }) => (bytes, sequence, file_name),
        Ok(BundleReply::Current) => {
            out.lines.push(msg("bundle-current", &[]));
            out.set("status", Value::Text("current".into()));
            if let Some(h) = held {
                out.set("sequence", int(h));
            }
            return Ok(());
        }
        Err(e) => {
            report(out, &url, &e);
            return Ok(());
        }
    };
    // With a trust bundle, check the factory's signature as far as a device can without opening
    // the roster (DIS-021); a bundle that fails is not stored.
    let verified = setting(args, "--trust-bundle", "FIELDSEAL_TRUST_BUNDLE").is_some();
    if verified {
        let Some(trust) = crate::trust_cmd::load_bundle(args, out) else { return Ok(()) };
        let checked = BundleFile::decode(&bytes, MAX_BUNDLE_FILE)
            .map_err(|e| e.to_string())
            .and_then(|f| TrustStore::new(&trust).verify_signature(&f.signer, &f.chain, &tags::BUNDLE, &f.structure(), &f.sig, at).map(drop).map_err(|e| e.to_string()));
        if let Err(e) = checked {
            out.raw_finding("DIS-021", "error", "(bundle)", "", &e);
            return Ok(());
        }
    }
    out.set("signatureVerified", Value::Bool(verified));
    let path = if target.ends_with('/') || Path::new(target).is_dir() {
        let Some(name) = file_name else {
            fail(out, exit::FAILED, "bundle-no-name", &[("url", &url)]);
            return Ok(());
        };
        Path::new(target).join(name)
    } else {
        Path::new(target).to_path_buf()
    };
    let shown = path.to_string_lossy().into_owned();
    let stored = path.parent().filter(|p| !p.as_os_str().is_empty()).map_or(Ok(()), std::fs::create_dir_all).and_then(|()| fieldseal_adapters_file::atomic::write_atomic(&path, &bytes));
    if let Err(e) = stored {
        fail(out, exit::CONFIG, "write-failed", &[("file", &shown), ("reason", &e.to_string())]);
        return Ok(());
    }
    out.lines.push(msg("bundle-fetched", &[("sequence", &sequence.to_string()), ("bytes", &bytes.len().to_string()), ("url", &url), ("file", &shown)]));
    if !verified {
        out.lines.push(msg("bundle-unchecked", &[]));
    }
    out.set("status", Value::Text("stored".into()));
    out.set("sequence", int(sequence));
    out.set("file", Value::Text(shown));
    out.set("bytes", int(bytes.len() as u64));
    Ok(())
}

// ---- the roster file --------------------------------------------------------------------------

/// Reads a roster file: `cohort`, `version`, optional `generation`, and `subjects`, each with
/// `subject`, `display`, optional `consent` (default `unknown`) and `prior_status`, and
/// `fields` (the roster-supplied values an instrument may reference).
pub(crate) fn parse_roster(value: Value, generation: u32) -> Result<Roster, String> {
    let Value::Map(mut m) = value else { return Err("the roster must be a map".into()) };
    let cohort = match m.remove("cohort") {
        Some(Value::Text(t)) => CohortId::new(t).map_err(|_| "cohort is empty".to_owned())?,
        _ => return Err("cohort must be text".into()),
    };
    let version = match m.remove("version") {
        Some(Value::Int(v)) if u64::try_from(v).is_ok() => v as u64,
        _ => return Err("version must be a whole number".into()),
    };
    let generation = match m.remove("generation") {
        None => generation,
        Some(Value::Int(g)) if (0..=i128::from(u32::MAX)).contains(&g) => g as u32,
        Some(_) => return Err("generation must be a whole number".into()),
    };
    let Some(Value::Array(subjects)) = m.remove("subjects") else { return Err("subjects must be a list".into()) };
    if let Some(extra) = m.keys().next() {
        return Err(format!("unknown field `{extra}`"));
    }
    let mut entries = Vec::new();
    for (i, s) in subjects.into_iter().enumerate() {
        let n = i + 1;
        let Value::Map(mut s) = s else { return Err(format!("subject {n} must be a map")) };
        let subject = match s.remove("subject") {
            Some(Value::Text(t)) => SubjectId::new(t).map_err(|_| format!("subject {n} has an empty ID"))?,
            _ => return Err(format!("subject {n} needs a `subject` ID")),
        };
        let display = match s.remove("display") {
            Some(Value::Text(t)) => t,
            _ => return Err(format!("subject {n} needs `display` text")),
        };
        let consent = match s.remove("consent") {
            Some(Value::Text(t)) => ConsentState::parse(&t).ok_or_else(|| format!("subject {n} has an unknown consent state"))?,
            None => ConsentState::Unknown,
            _ => return Err(format!("subject {n} has a bad `consent`")),
        };
        let prior_status = match s.remove("prior_status") {
            None => None,
            Some(Value::Text(t)) => Some(t),
            Some(_) => return Err(format!("subject {n} has a bad `prior_status`")),
        };
        let attributes = match s.remove("fields") {
            None => BTreeMap::new(),
            Some(Value::Map(f)) => f,
            Some(_) => return Err(format!("subject {n} has bad `fields`")),
        };
        if let Some(extra) = s.keys().next() {
            return Err(format!("subject {n} has an unknown field `{extra}`"));
        }
        if entries.iter().any(|e: &RosterEntry| e.subject == subject) {
            return Err(format!("subject {n} repeats an earlier subject ID"));
        }
        entries.push(RosterEntry { ordinal: i as u32 + 1, subject, display, attributes, consent, prior_status });
    }
    Ok(Roster { cohort, version, generation: Generation(generation), entries })
}

// ---- build ------------------------------------------------------------------------------------

fn build(args: &Args) -> Result<u8, String> {
    let instrument_path = args.value("--instrument").ok_or("bundle build needs --instrument <file>")?;
    let out_dir = args.value("--out-dir").ok_or("bundle build needs --out-dir <dir>")?;
    let practice = args.has("--practice");
    let roster_path = args.value("--roster");
    match (roster_path, practice) {
        (None, false) => return Err("bundle build needs --roster <file>, or --practice for a bundle without rosters".into()),
        (Some(_), true) => return Err("a practice bundle has no roster (DIS-004)".into()),
        _ => {}
    }
    let seed = number(args, "--seed")?.unwrap_or(1);
    let now = AuthorityTime(number(args, "--time")?.unwrap_or_else(system_millis));
    let generation = u32::try_from(number(args, "--generation")?.unwrap_or(1)).map_err(|_| "--generation is too large".to_owned())?;
    let label = args.value("--device").unwrap_or("demo-device");

    let instrument = load_document(instrument_path)?;
    if let Err(findings) = validate_instrument(&instrument) {
        eprintln!("{instrument_path}: the instrument is invalid ({} finding(s)); run `fieldseal instrument validate`", findings.iter().count());
        return Ok(1);
    }
    let roster = roster_path
        .map(|p| parse_roster(load_document(p)?, generation).map_err(|e| format!("{p}: {e}")))
        .transpose()?;

    let world = DemoWorld::new(seed, now)?;
    let salt = match args.value("--salt") {
        None => DemoWorld::salt_for(&metadata(&instrument, "name", instrument_path)?),
        Some(h) => Salt::from(<[u8; 32]>::try_from(unhex(h).ok_or("--salt is 64 hex digits")?).map_err(|_| "--salt is 64 hex digits".to_owned())?),
    };
    let bytes = cbor::encode(&instrument).map_err(|e| e.to_string())?;
    let published = world
        .publish(ArtefactKind::Instrument, &metadata(&instrument, "name", instrument_path)?, &metadata(&instrument, "version", instrument_path)?, bytes, Some(salt))
        .map_err(|e| format!("{instrument_path}: {e}"))?;
    let fingerprint = *published.address();
    let mut layouts = Vec::new();
    for path in args.values("--layout") {
        // A layout names its instrument by fingerprint once canonicalised (INS-200).
        let mut doc = load_document(path)?;
        if let Value::Map(root) = &mut doc
            && let Some(Value::Map(spec)) = root.get_mut("spec")
        {
            spec.insert("instrument".into(), Value::Bytes(fingerprint.as_bytes().to_vec()));
        }
        let bytes = cbor::encode(&doc).map_err(|e| e.to_string())?;
        let p = world
            .publish(ArtefactKind::Layout, &metadata(&doc, "name", path)?, &metadata(&doc, "version", path)?, bytes, None)
            .map_err(|e| format!("{path}: {e}"))?;
        layouts.push(*p.address());
    }

    let cohorts: Vec<(&str, u32)> = roster.iter().map(|r| (r.cohort.as_str(), r.generation.0)).collect();
    let profile = RuntimeProfile { instrument_schema: DEMO_SCHEMA, localisation_reference: None };
    // `--device-dir`: the bundle is for the device that registered with a factory (its tenancy
    // is the SHA-256 of its signing key and the bundle is sealed to its agreement key).
    let device = match args.value("--device-dir") {
        Some(d) => {
            let (sign, agree) = crate::device_dir::DeviceDir::new(d).keys().ok_or_else(|| format!("{d}: no device keys (run `registration request --device-dir`)"))?;
            let sign_pub = sign.signing().ok_or("sign.key is not a signing key")?.public_key();
            let secret: [u8; 32] = agree.secret_bytes().try_into().map_err(|_| "agree.key is not a 32-byte key".to_owned())?;
            let fieldseal_kernel::seal::RecipientKey::P256(agree_pub) = agree.agreement().ok_or("agree.key is not an agreement key")?.public().map_err(|e| e.to_string())? else {
                return Err("agree.key is not a P-256 key".into());
            };
            let name = crate::support::hex(&fieldseal_kernel::digest::sha256(sign_pub.as_bytes()).as_bytes()[..6]);
            world.register_keys(&name, &sign_pub, &agree_pub, Some(secret), &cohorts, false, profile)?
        }
        None => world.register(label, &cohorts, false, profile)?,
    };
    if let Some(r) = roster {
        world.assign_rosters(&device, vec![r]);
    }
    let mut request = BuildRequest::new(device.tenancy, vec![fingerprint]);
    request.layouts = layouts;
    request.practice = practice;

    // Software keys are never reported as attested (TRU-061). A development factory may release
    // rosters to them under the explicit non-production allowance (REG-017), with a flag.
    let allowance = if args.has("--allow-unattested") { UnattestedKeys::AllowNonProduction } else { UnattestedKeys::Refuse };
    let built = match world.build_with(&world.built_in_policy(), &request, allowance) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("fieldseal: the bundle was not released: {e}");
            if matches!(&e, DistributionError::Withheld(r) if r.iter().any(|x| x == "unattested-key-roster")) {
                eprintln!("hint: software keys are never attested; a development factory may release rosters to them with --allow-unattested (REG-017)");
            }
            return Ok(1);
        }
    };

    let dir = Path::new(out_dir);
    std::fs::create_dir_all(dir).map_err(|e| format!("{out_dir}: {e}"))?;
    let name = file_name(built.sealed.issued.0, built.sealed.seq.0);
    let trust = world.trust.encode().map_err(|e| e.to_string())?;
    let secret = device.agreement_secret().ok_or("the demo device has no key file")?;
    let device_file = format!(
        "# A simulated device (software keys; not for production).\ntenancy = {}\nagreement-key = {}\ninstrument-schema = {}\nissued-ms = {}\n",
        lower_hex(device.tenancy.as_bytes()),
        lower_hex(&secret),
        DEMO_SCHEMA,
        built.sealed.issued.0,
    );
    let write = |file: &str, bytes: &[u8]| std::fs::write(dir.join(file), bytes).map_err(|e| format!("{}: {e}", dir.join(file).display()));
    write(&name, &built.sealed.bytes)?;
    write("trust-bundle.cbor", &trust)?;
    write("device.txt", device_file.as_bytes())?;

    let m = &built.manifest;
    let subjects: usize = m.rosters.iter().map(|r| r.3).sum();
    if args.has("--json") {
        let doc = cbor::map([
            ("bundle", text(&dir.join(&name).display().to_string())),
            ("trust", text(&dir.join("trust-bundle.cbor").display().to_string())),
            ("device", text(&dir.join("device.txt").display().to_string())),
            ("address", text(&built.sealed.address.to_text())),
            ("tenancy", text(&lower_hex(device.tenancy.as_bytes()))),
            ("sequence", int(m.seq.0)),
            ("bytes", int(built.sealed.bytes.len() as u64)),
            ("rosters", int(m.rosters.len() as u64)),
            ("subjects", int(subjects as u64)),
            ("policy", Value::Array(m.policy.iter().map(|a| text(&a.to_text())).collect())),
        ]);
        println!("{}", json::pretty(&doc));
    } else {
        println!("built {} (sequence {}, {} bytes)", dir.join(&name).display(), m.seq.0, built.sealed.bytes.len());
        println!("{} instrument(s), {} layout(s), {} roster(s) with {} subject(s)", m.instruments.len(), m.layouts.len(), m.rosters.len(), subjects);
        println!("verify it with: fieldseal bundle verify {} --trust {} --device-file {}", dir.join(&name).display(), dir.join("trust-bundle.cbor").display(), dir.join("device.txt").display());
    }
    Ok(0)
}

// ---- verify -----------------------------------------------------------------------------------

struct DeviceFile {
    tenancy: TenancyId,
    key: SoftwareAgreementKey,
}

fn load_device(path: &str) -> Result<DeviceFile, String> {
    let content = String::from_utf8_lossy(&read(path)?).into_owned();
    let field = |name: &str| content.lines().find_map(|l| l.strip_prefix(&format!("{name} = "))).and_then(unhex);
    let parsed = (|| {
        let tenancy = TenancyId::from_bytes(&field("tenancy")?).ok()?;
        let secret = RecipientSecret::from_bytes(Suite::Fs1P, &field("agreement-key")?).ok()?;
        Some(DeviceFile { tenancy, key: SoftwareAgreementKey::new(secret).ok()? })
    })();
    parsed.ok_or_else(|| format!("{path}: not a device file written by `bundle build`"))
}

fn load_trust(path: &str) -> Result<TrustBundle, String> {
    TrustBundle::decode(&read(path)?).map_err(|e| format!("{path}: {e}"))
}

fn verify(args: &Args) -> Result<u8, String> {
    let path = args.file("bundle verify").map_err(|e| e.0)?;
    let trust = load_trust(args.value("--trust").ok_or("bundle verify needs --trust <file>")?)?;
    let device = load_device(args.value("--device-file").ok_or("bundle verify needs --device-file <file>")?)?;
    let now = AuthorityTime(number(args, "--now")?.unwrap_or_else(system_millis));
    let bytes = read(path)?;
    let mut publishing = Controls::defaults().publishing();
    // The demo factory's builder and source (the same constants `DemoWorld` publishes under).
    publishing.allowed_builders = vec!["https://ci.example.org/builders/fieldseal-demo".into()];
    publishing.allowed_sources = vec!["https://git.example.org/authority/artefacts".into()];
    if args.has("--stack") {
        publishing = crate::policy_support::publishing_policy();
    }
    let profile = RuntimeProfile { instrument_schema: DEMO_SCHEMA, localisation_reference: None };
    let state = ImportState { tenancy: device.tenancy, now, held: HeldState::default() };
    match VerifyBundle::new(&trust, &publishing, &device.key, profile).verify(&bytes, &state) {
        Ok(v) => {
            let m = &v.manifest;
            let subjects: usize = m.rosters.iter().map(|r| r.3).sum();
            if args.has("--json") {
                let instruments = m.instruments.iter().map(|(a, n, ver)| cbor::map([("address", text(&a.to_text())), ("name", text(n)), ("version", text(ver))])).collect();
                let doc = cbor::map([
                    ("verified", Value::Bool(true)),
                    ("address", text(&v.address.to_text())),
                    ("sequence", int(m.seq.0)),
                    ("issued", int(m.issued.0)),
                    ("instruments", Value::Array(instruments)),
                    ("layouts", int(m.layouts.len() as u64)),
                    ("rosters", int(m.rosters.len() as u64)),
                    ("subjects", int(subjects as u64)),
                    ("withdrawals", int(m.withdrawals as u64)),
                    ("trust_updates", int(m.trust_updates as u64)),
                ]);
                println!("{}", json::pretty(&doc));
            } else {
                println!("{path}: verified (sequence {}, issued {} ms)", m.seq.0, m.issued.0);
                println!("{} instrument(s), {} layout(s), {} roster(s) with {} subject(s), {} withdrawal(s)", m.instruments.len(), m.layouts.len(), m.rosters.len(), subjects, m.withdrawals);
            }
            Ok(0)
        }
        Err(r) => {
            if args.has("--json") {
                let doc = cbor::map([
                    ("verified", Value::Bool(false)),
                    ("step", text(&format!("{:?}", r.step()))),
                    ("code", r.code().map_or(Value::Bool(false), |c| text(c.as_str()))),
                    ("reason", text(r.collector_reason().message_id())),
                    ("detail", text(&r.to_string())),
                ]);
                println!("{}", json::pretty(&doc));
            } else {
                eprintln!("{path}: rejected at {:?}: {r}", r.step());
                eprintln!("{} ({})", r.collector_reason().text(), r.collector_reason().message_id());
            }
            Ok(1)
        }
    }
}

// ---- open -------------------------------------------------------------------------------------

/// The `--json` document of `bundle open` (CLI §6 shape).
fn open_doc(code: u8, mut fields: Vec<(&'static str, Value)>, findings: Vec<Value>) -> Value {
    fields.push(("command", text("bundle open")));
    fields.push(("ok", Value::Bool(code == 0)));
    fields.push(("exitCode", int(i128::from(code))));
    fields.push(("findings", Value::Array(findings)));
    cbor::map(fields)
}

fn roster_value(r: &Roster) -> Value {
    let subjects = r
        .entries
        .iter()
        .map(|e| {
            let mut f = vec![
                ("ordinal", int(e.ordinal)),
                ("subject", text(e.subject.as_str())),
                ("display", text(&e.display)),
                ("consent", text(e.consent.as_str())),
                ("fields", Value::Map(e.attributes.clone())),
            ];
            if let Some(p) = &e.prior_status {
                f.push(("prior_status", text(p)));
            }
            cbor::map(f)
        })
        .collect();
    cbor::map([("cohort", text(r.cohort.as_str())), ("version", int(r.version)), ("generation", int(r.generation.0)), ("subjects", Value::Array(subjects))])
}

/// Decrypts as the device would (CLI-014): the same verification order as `bundle verify`
/// runs before anything is opened. Roster contents are written only with `--reveal` and an
/// output file, with a warning on stderr; stdout carries counts only (CLI-008).
fn open(args: &Args) -> Result<u8, String> {
    let path = args.file("bundle open").map_err(|e| e.0)?;
    let reveal = args.has("--reveal");
    let out_file = args.value("--out");
    if reveal && out_file.is_none() {
        return Err("`--reveal` writes roster contents to a file, so it needs `--out <file>` (CLI-008)".into());
    }
    if !reveal && out_file.is_some() {
        return Err("`--out` is for `--reveal`; without it nothing but counts is shown (CLI-008)".into());
    }
    let key_path = args.value("--key").ok_or("bundle open needs --key <handle>")?;
    let key = crate::device_keys::DeviceKey::from_file(&String::from_utf8_lossy(&read(key_path)?)).map_err(|e| format!("{key_path}: {e}"))?;
    let secret = key.agreement().ok_or_else(|| format!("{key_path}: bundle open needs an agreement key (`keys generate --purpose agree`)"))?;
    let agreement = SoftwareAgreementKey::new(secret).map_err(|e| e.to_string())?;
    let tenancy = match args.value("--tenancy") {
        Some(h) => TenancyId::from_bytes(&unhex(h).ok_or("--tenancy is 64 hex digits")?).map_err(|_| "--tenancy is 64 hex digits".to_owned())?,
        None => {
            let content = String::from_utf8_lossy(&read(key_path)?).into_owned();
            content
                .lines()
                .find_map(|l| l.strip_prefix("tenancy = "))
                .and_then(unhex)
                .and_then(|b| TenancyId::from_bytes(&b).ok())
                .ok_or("bundle open needs --tenancy <hex> (a device file from `bundle build` names it)")?
        }
    };
    let trust = load_trust(args.value("--trust").ok_or("bundle open needs --trust <file>")?)?;
    let now = AuthorityTime(number(args, "--now")?.unwrap_or_else(system_millis));
    let bytes = read(path)?;
    let mut publishing = Controls::defaults().publishing();
    publishing.allowed_builders = vec!["https://ci.example.org/builders/fieldseal-demo".into()];
    publishing.allowed_sources = vec!["https://git.example.org/authority/artefacts".into()];
    let profile = RuntimeProfile { instrument_schema: DEMO_SCHEMA, localisation_reference: None };
    let state = ImportState { tenancy, now, held: HeldState::default() };
    match VerifyBundle::new(&trust, &publishing, &agreement, profile).verify(&bytes, &state) {
        Ok(v) => {
            let m = &v.manifest;
            let subjects: usize = m.rosters.iter().map(|r| r.3).sum();
            let mut fields = vec![
                ("address", text(&v.address.to_text())),
                ("sequence", int(m.seq.0)),
                ("instruments", int(m.instruments.len() as u64)),
                ("layouts", int(m.layouts.len() as u64)),
                ("rosters", int(m.rosters.len() as u64)),
                ("subjects", int(subjects as u64)),
                ("revealed", Value::Bool(reveal)),
                ("custody", text("software")),
                ("attested", Value::Bool(false)),
            ];
            if let Some(out_file) = out_file {
                eprintln!("warning: writing roster contents (subject data) to {out_file}; protect it and delete it when done (CLI-008)");
                let doc = cbor::map([
                    ("tenancy", text(&lower_hex(tenancy.as_bytes()))),
                    ("sequence", int(m.seq.0)),
                    ("instruments", Value::Array(m.instruments.iter().map(|(a, n, ver)| cbor::map([("address", text(&a.to_text())), ("name", text(n)), ("version", text(ver))])).collect())),
                    ("rosters", Value::Array(v.content.rosters.iter().map(roster_value).collect())),
                ]);
                std::fs::write(out_file, json::pretty(&doc)).map_err(|e| format!("{out_file}: {e}"))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    let _ = std::fs::set_permissions(out_file, std::fs::Permissions::from_mode(0o600));
                }
                fields.push(("revealedTo", text(out_file)));
            }
            if args.has("--json") {
                println!("{}", json::pretty(&open_doc(0, fields, Vec::new())));
            } else {
                println!("{path}: opened and verified (sequence {}, issued {} ms)", m.seq.0, m.issued.0);
                println!("{} instrument(s), {} layout(s), {} roster(s) with {} subject(s); roster contents {}", m.instruments.len(), m.layouts.len(), m.rosters.len(), subjects, if reveal { "written to the --out file" } else { "withheld (use --reveal --out <file>)" });
                println!("note: a software key, unattested (CLI-007).");
            }
            Ok(0)
        }
        Err(r) => {
            let finding = cbor::map([
                ("id", text(r.code().map_or("DIS-030", |c| c.as_str()))),
                ("severity", text("error")),
                ("message", text(&r.to_string())),
                ("where", cbor::map([("file", text(path)), ("step", text(&format!("{:?}", r.step())))])),
            ]);
            if args.has("--json") {
                println!("{}", json::pretty(&open_doc(1, Vec::new(), vec![finding])));
            } else {
                eprintln!("{path}: rejected at {:?}: {r}", r.step());
                eprintln!("{} ({})", r.collector_reason().text(), r.collector_reason().message_id());
            }
            Ok(1)
        }
    }
}

// ---- inspect ----------------------------------------------------------------------------------

fn inspect(args: &Args) -> Result<u8, String> {
    let path = args.file("bundle inspect").map_err(|e| e.0)?;
    let bytes = read(path)?;
    let file = match BundleFile::decode(&bytes, MAX_BUNDLE_FILE) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{path}: not a bundle file: {e}");
            return Ok(1);
        }
    };
    let mut signature = None;
    if let Some(trust_path) = args.value("--trust") {
        let trust = load_trust(trust_path)?;
        let now = AuthorityTime(number(args, "--now")?.unwrap_or_else(system_millis));
        signature = Some(
            TrustStore::new(&trust)
                .verify_signature(&file.signer, &file.chain, &tags::BUNDLE, &file.structure(), &file.sig, now)
                .map(|_| ())
                .map_err(|e| e.to_string()),
        );
    }
    if args.has("--json") {
        let mut fields = vec![
            ("bytes", int(bytes.len() as u64)),
            ("suite", text(file.sealed.suite.id())),
            ("recipient", text(&lower_hex(file.sealed.recipient.as_bytes()))),
            ("signer", text(&lower_hex(file.signer.as_bytes()))),
            ("chain", int(file.chain.len() as u64)),
        ];
        if let Some(s) = &signature {
            fields.push(("signature", Value::Bool(s.is_ok())));
        }
        println!("{}", json::pretty(&cbor::map(fields)));
    } else {
        println!("{path}: {} bytes, sealed with {}", bytes.len(), file.sealed.suite.id());
        println!("recipient key {}", lower_hex(file.sealed.recipient.as_bytes()));
        println!("signed by {} ({} certificate(s) in the chain)", lower_hex(file.signer.as_bytes()), file.chain.len());
        match &signature {
            Some(Ok(())) => println!("signature verifies against the trust bundle"),
            Some(Err(e)) => println!("signature does NOT verify: {e}"),
            None => println!("pass --trust <file> to check the signature"),
        }
    }
    Ok(u8::from(matches!(signature, Some(Err(_)))))
}
