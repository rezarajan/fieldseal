//! `fieldseal trust root-init|issue|bundle|verify|revoke` (CLI §5 `trust`, TRU): the
//! authority-side Trust use cases ([`Authority`]) and chain verification, driven from files.
//!
//! **Development custody.** The signer is the software key directory of [`crate::custody`]
//! (`--custody <dir>` or `FIELDSEAL_SIGNER=soft:<dir>`): the root key is a file, not a key in
//! an HSM, and a custodian threshold is recorded but not enforced by splitting the key. It is
//! for development, tests and practice ceremonies; a production authority uses an HSM
//! adapter for `KeyCustody` and the same commands. Every command that uses it says so.
//!
//! Files are canonical CBOR (WIRE §5.1): certificates `.crt`, requests `.csr`, revocations
//! `.revocation`, the ceremony record `.cbor` and the trust bundle (any name).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fieldseal_adapters_memory::publishing::MemoryTransparencyLog;
use fieldseal_kernel::Value;
use fieldseal_kernel::crypto::Purpose;
use fieldseal_kernel::id::{CollectionPeriodId, Digest, KeyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_publishing::domain::{ArtefactKind, CHECKPOINT_FORMAT};
use fieldseal_trust::application::{Authority, UseCaseError, verify_chain};
use fieldseal_trust::domain::{
    Ceremony, CollectionPeriod, IssueTerms, KeyCertificate, LogPin, RecordKeyTerms, Retention, Revocation, RevocationReason,
    RevocationTarget, RuntimeBuild, Threshold, TrustBundle, TrustBundleContents, BundleVersion, CertificateRequest, KeyRole,
};

use crate::args::Args;
use crate::custody::DirCustody;
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::support::{Res, fail, files_in, hex, load_doc, now, parse_duration, parse_time, read, run_command, setting, text, unhex, usage, write};
use crate::transport::NullTransport;

/// Runs `trust <verb>`; `None` if the verb is not one of these.
pub fn run(verb: &str, raw: &[String]) -> Option<u8> {
    let with = |extra: &[&'static str]| -> Vec<&'static str> { ["--custody", "--at", "--caller"].iter().chain(extra).copied().collect() };
    Some(match verb {
        "root-init" => run_command("trust root-init", raw, &with(&["--ceremony", "--out"]), &[], root_init),
        "issue" => run_command(
            "trust issue",
            raw,
            &with(&["--purpose", "--validity", "--period", "--period-start", "--period-end", "--retention", "--csr", "--out", "--root", "--serial"]),
            &[],
            issue,
        ),
        "bundle" => run_command(
            "trust bundle",
            raw,
            &with(&[
                "--roots", "--pins", "--attestation-roots", "--runtime-builds", "--out", "--name", "--version", "--publishers", "--log-origin", "--log",
                "--revocations", "--previous",
            ]),
            &[],
            bundle,
        ),
        "show" => run_command("trust show", raw, &["--trust-bundle", "--custody"], &[], show),
        "verify" => run_command("trust verify", raw, &["--trust-bundle", "--purpose", "--revocations", "--at"], &[], verify),
        "revoke" => run_command("trust revoke", raw, &with(&["--reason", "--effective", "--out", "--root", "--key-wide"]), &[], revoke),
        _ => return None,
    })
}

/// The key directory: `--custody`, else `FIELDSEAL_SIGNER` (`soft:<dir>`).
pub fn custody_dir(args: &Args, out: &mut Outcome) -> Option<DirCustody> {
    let spec = setting(args, "--custody", "FIELDSEAL_SIGNER");
    let Some(spec) = spec else {
        fail(out, exit::CONFIG, "no-signer", &[]);
        return None;
    };
    match spec.split_once(':') {
        Some(("soft", dir)) => Some(DirCustody::new(dir)),
        Some((kind, _)) => {
            fail(out, exit::CONFIG, "unknown-signer", &[("kind", kind)]);
            None
        }
        None => Some(DirCustody::new(spec)),
    }
}

/// Records a Trust or custody failure as a finding.
pub fn use_case_failed(out: &mut Outcome, file: &str, e: &UseCaseError) {
    let id = match e {
        UseCaseError::Trust(_) => "TRU",
        UseCaseError::Custody(_) => "TRU-001",
    };
    out.raw_finding(id, "error", file, "", &e.to_string());
}

fn dev_notice(out: &mut Outcome) {
    out.lines.push(msg("dev-custody", &[]));
    out.set("custody", Value::Text("development-software".into()));
    out.set("attested", Value::Bool(false));
}

fn read_cert(path: &str, out: &mut Outcome) -> Option<KeyCertificate> {
    let bytes = read(path, out)?;
    match KeyCertificate::decode(&bytes) {
        Ok(c) => Some(c),
        Err(e) => {
            out.raw_finding("WIRE", "error", path, "", &e.to_string());
            None
        }
    }
}

/// The root certificate: `--root`, else `root.crt` in the custody directory.
fn root_cert(args: &Args, custody: &DirCustody, out: &mut Outcome) -> Option<KeyCertificate> {
    let path = args.value("--root").map_or_else(|| custody.dir().join("root.crt").to_string_lossy().into_owned(), str::to_owned);
    read_cert(&path, out)
}

fn caller(args: &Args) -> String {
    args.value("--caller").unwrap_or("fieldseal-cli").to_owned()
}

// ---- root-init ------------------------------------------------------------------------------

/// Rejects the first key of `m` that is not in `allowed` (a closed schema, TRU-095).
fn unknown_key<'m>(m: &'m BTreeMap<String, Value>, allowed: &[&str]) -> Option<&'m str> {
    m.keys().map(String::as_str).find(|k| !allowed.contains(k))
}

/// `M-of-N` (decimal digits only) or `{m, n}` with exactly those two whole-number keys.
fn threshold(v: &Value) -> Option<Result<Threshold, fieldseal_trust::domain::TrustError>> {
    let digits = |t: &str| crate::support::parse_uint(t).and_then(|n| u32::try_from(n).ok());
    let (m, n) = match v {
        Value::Text(t) => {
            let (m, n) = t.split_once("-of-")?;
            (digits(m)?, digits(n)?)
        }
        Value::Map(m) if unknown_key(m, &["m", "n"]).is_none() => {
            (u32::try_from(m.get("m")?.as_int()?).ok()?, u32::try_from(m.get("n")?.as_int()?).ok()?)
        }
        _ => return None,
    };
    Some(Threshold::new(m, n))
}

/// A required list of text entries; anything else (a missing key, a scalar, a non-text entry) is `None`.
fn names(m: &BTreeMap<String, Value>, key: &str) -> Option<Vec<String>> {
    m.get(key)?.as_array()?.iter().map(|v| v.as_text().map(str::to_owned)).collect()
}

/// A time given as text; a present but mistyped or unparsable value is `Err`.
fn time_field(m: &BTreeMap<String, Value>, key: &str) -> Result<Option<AuthorityTime>, ()> {
    match m.get(key) {
        None => Ok(None),
        Some(v) => v.as_text().and_then(parse_time).map(Some).ok_or(()),
    }
}

/// Why a ceremony file is refused.
enum CeremonyError {
    /// The named field is unknown, missing or invalid.
    Field(String),
    /// The threshold is well formed but breaks TRU-002.
    Threshold(fieldseal_trust::domain::TrustError),
    /// The clock could not be read.
    Usage(crate::args::UsageError),
}

fn field_err(name: &str) -> CeremonyError {
    CeremonyError::Field(name.to_owned())
}

/// Reads the ceremony parameters file (`ceremony.yaml`): a closed map with exactly the fields
/// `authority`, `threshold`, `custodians`, `witnesses`, optional `held`, `notBefore`, and
/// exactly one of `validity` and `notAfter`.
fn read_ceremony(m: &BTreeMap<String, Value>, default_held: impl FnOnce() -> Res<AuthorityTime>) -> Result<Ceremony, CeremonyError> {
    const KEYS: &[&str] = &["authority", "threshold", "custodians", "witnesses", "held", "validity", "notBefore", "notAfter"];
    if let Some(k) = unknown_key(m, KEYS) {
        return Err(CeremonyError::Field(format!("unknown field {k}")));
    }
    let held = time_field(m, "held").map_err(|()| field_err("held"))?;
    let not_before = time_field(m, "notBefore").map_err(|()| field_err("notBefore"))?;
    let explicit_after = time_field(m, "notAfter").map_err(|()| field_err("notAfter"))?;
    let validity = match m.get("validity") {
        None => None,
        Some(v) => Some(v.as_text().and_then(parse_duration).ok_or_else(|| field_err("validity"))?),
    };
    let held = match held {
        Some(h) => h,
        None => default_held().map_err(CeremonyError::Usage)?,
    };
    let not_before = not_before.unwrap_or(held);
    let not_after = match (explicit_after, validity) {
        (Some(t), None) => t,
        (None, Some(ms)) => AuthorityTime(not_before.0.checked_add(ms).ok_or_else(|| field_err("validity"))?),
        _ => return Err(field_err("validity (give exactly one of validity and notAfter)")),
    };
    let authority = text(m, "authority").filter(|a| !a.is_empty()).ok_or_else(|| field_err("authority"))?.to_owned();
    let threshold = m.get("threshold").and_then(threshold).ok_or_else(|| field_err("threshold"))?.map_err(CeremonyError::Threshold)?;
    let custodians = names(m, "custodians").ok_or_else(|| field_err("custodians"))?;
    let witnesses = names(m, "witnesses").ok_or_else(|| field_err("witnesses"))?;
    Ok(Ceremony { authority, threshold, custodians, witnesses, held_at: held, not_before, not_after })
}

fn root_init(args: &Args, out: &mut Outcome) -> Res {
    let ceremony_path = args.required("trust root-init", "--ceremony")?;
    let dir = args.required("trust root-init", "--out")?;
    let Some(doc) = load_doc(ceremony_path, out)? else { return Ok(()) };
    let Some(m) = doc.as_map() else {
        return Err(usage("not-a-map", &[("file", ceremony_path), ("what", "ceremony parameters")]));
    };
    let bad = |what: &str| usage("bad-ceremony", &[("file", ceremony_path), ("field", what)]);
    let ceremony = match read_ceremony(m, || now(args)) {
        Ok(c) => c,
        Err(CeremonyError::Field(field)) => return Err(bad(&field)),
        Err(CeremonyError::Usage(e)) => return Err(e),
        Err(CeremonyError::Threshold(e)) => {
            out.raw_finding("TRU-002", "error", ceremony_path, "threshold", &e.to_string());
            return Ok(());
        }
    };
    if Path::new(dir).join("root.crt").exists() {
        fail(out, exit::FAILED, "root-exists", &[("dir", dir)]);
        return Ok(());
    }
    let custody = DirCustody::new(dir);
    let caller = caller(args);
    match Authority::new(&custody, &caller).init_root(ceremony) {
        Ok(record) => {
            let (Ok(root_bytes), Ok(record_bytes)) = (record.root.encode(), record.encode()) else {
                fail(out, exit::INTERNAL, "encode-failed", &[]);
                return Ok(());
            };
            let dirp = PathBuf::from(dir);
            if !write(&dirp.join("root.crt"), &root_bytes, false, out) || !write(&dirp.join("ceremony-record.cbor"), &record_bytes, false, out) {
                return Ok(());
            }
            let id = hex(record.root.key_id().as_bytes());
            out.lines.push(msg("root-created", &[("key", &id), ("dir", dir)]));
            out.set("rootKeyId", Value::Text(id));
            out.set("threshold", Value::Text(format!("{}-of-{}", record.ceremony.threshold.m(), record.ceremony.threshold.n())));
            dev_notice(out);
        }
        Err(e) => use_case_failed(out, ceremony_path, &e),
    }
    Ok(())
}

// ---- issue ----------------------------------------------------------------------------------

fn next_serial(custody: &DirCustody, args: &Args) -> Res<u64> {
    if let Some(s) = args.value("--serial") {
        return crate::support::parse_uint(s).ok_or_else(|| usage("bad-number", &[("flag", "--serial"), ("value", s)]));
    }
    let path = custody.dir().join("serial");
    // A missing counter starts at 1; a counter that is not a whole number is corrupt and
    // would reissue serials, so it is refused rather than reset.
    let last = match std::fs::read_to_string(&path) {
        Ok(t) => crate::support::parse_uint(t.trim()).ok_or_else(|| usage("bad-number", &[("flag", "serial file"), ("value", t.trim())]))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(usage("not-found", &[("file", &path.to_string_lossy()), ("reason", &e.to_string())])),
    };
    let n = last.checked_add(1).ok_or_else(|| usage("bad-number", &[("flag", "serial file"), ("value", "overflow")]))?;
    let _ = std::fs::write(path, n.to_string());
    Ok(n)
}

fn issue(args: &Args, out: &mut Outcome) -> Res {
    let purpose_name = args.required("trust issue", "--purpose")?;
    let purpose = Purpose::parse(purpose_name).ok_or_else(|| usage("unknown-purpose", &[("value", purpose_name)]))?;
    let csr_path = args.required("trust issue", "--csr")?;
    let out_dir = args.required("trust issue", "--out")?;
    let at = now(args)?;
    let Some(custody) = custody_dir(args, out) else { return Ok(()) };
    let Some(csr_bytes) = read(csr_path, out) else { return Ok(()) };
    let request = match CertificateRequest::decode(&csr_bytes) {
        Ok(r) => r,
        Err(e) => {
            out.raw_finding(if matches!(e, fieldseal_trust::domain::TrustError::IdentityAttributes(_)) { "TRU-091" } else { "WIRE" }, "error", csr_path, "", &e.to_string());
            return Ok(());
        }
    };
    let Some(root) = root_cert(args, &custody, out) else { return Ok(()) };
    let serial = next_serial(&custody, args)?;
    let caller = caller(args);
    let authority = Authority::new(&custody, &caller);
    let result = if purpose == Purpose::Record {
        let (Some(period), Some(start), Some(end), Some(retention)) = (
            args.value("--period"),
            args.value("--period-start").and_then(parse_time),
            args.value("--period-end").and_then(parse_time),
            args.value("--retention").and_then(parse_duration),
        ) else {
            return Err(usage("record-needs-period", &[]));
        };
        let id = CollectionPeriodId::new(period).map_err(|_| usage("bad-period", &[("value", period)]))?;
        let period = CollectionPeriod::new(id, start, end).map_err(|e| usage("bad-period", &[("value", &e.to_string())]))?;
        authority.open_collection_period(&root, &request, RecordKeyTerms { period, retention: Retention(retention) }, at.min(start), serial)
    } else {
        let validity = args.required("trust issue", "--validity")?;
        let ms = parse_duration(validity).ok_or_else(|| usage("bad-validity", &[("value", validity)]))?;
        authority.issue(&root, &request, IssueTerms { purpose, record: None, not_before: at, not_after: AuthorityTime(at.0 + ms), serial })
    };
    match result {
        Ok(cert) => {
            let Ok(bytes) = cert.encode() else {
                fail(out, exit::INTERNAL, "encode-failed", &[]);
                return Ok(());
            };
            let stem = Path::new(csr_path).file_stem().and_then(|s| s.to_str()).unwrap_or("certificate");
            let path = Path::new(out_dir).join(format!("{stem}.crt"));
            if !write(&path, &bytes, false, out) {
                return Ok(());
            }
            let id = hex(cert.key_id().as_bytes());
            out.lines.push(msg("issued", &[("purpose", purpose.as_str()), ("key", &id), ("file", &path.to_string_lossy())]));
            out.set("keyId", Value::Text(id));
            out.set("purpose", Value::Text(purpose.as_str().into()));
            out.set("serial", Value::Int(i128::from(serial)));
            out.set("file", Value::Text(path.to_string_lossy().into_owned()));
            dev_notice(out);
        }
        Err(e) => use_case_failed(out, csr_path, &e),
    }
    Ok(())
}

// ---- bundle ---------------------------------------------------------------------------------

fn read_certs(path: &str, out: &mut Outcome) -> Vec<KeyCertificate> {
    files_in(path).iter().filter(|f| f.ends_with(".crt")).filter_map(|f| read_cert(f, out)).collect()
}

/// A SHA-256 digest as 64 hexadecimal digits, optionally written `sha256:<hex>`.
fn digest_text(t: &str) -> Option<Digest> {
    let hex = t.strip_prefix("sha256:").unwrap_or(t);
    (hex.len() == 64).then(|| unhex(hex)).flatten().and_then(|b| Digest::from_bytes(&b).ok())
}

/// The runtime builds file: a list of builds, or a map with only `builds`. Each build is a
/// closed map of `platform`, `appId` and a non-empty list of `signingDigests`. Returns the
/// path of the first fault.
fn parse_builds(doc: &Value) -> Result<Vec<RuntimeBuild>, String> {
    let items = match doc {
        Value::Array(a) => a.as_slice(),
        Value::Map(m) => match (unknown_key(m, &["builds"]), m.get("builds").and_then(Value::as_array)) {
            (None, Some(a)) => a,
            (Some(k), _) => return Err(format!("unknown field {k}")),
            (None, None) => return Err("builds".into()),
        },
        _ => return Err("builds".into()),
    };
    let mut builds = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let at = |what: &str| format!("builds[{i}].{what}");
        let m = item.as_map().ok_or_else(|| format!("builds[{i}]"))?;
        if let Some(k) = unknown_key(m, &["platform", "appId", "signingDigests"]) {
            return Err(at(&format!("unknown field {k}")));
        }
        let platform = text(m, "platform").filter(|t| !t.is_empty()).ok_or_else(|| at("platform"))?;
        let app_id = text(m, "appId").filter(|t| !t.is_empty()).ok_or_else(|| at("appId"))?;
        let list = m.get("signingDigests").and_then(Value::as_array).filter(|a| !a.is_empty()).ok_or_else(|| at("signingDigests"))?;
        let signing_digests = list
            .iter()
            .map(|d| d.as_text().and_then(digest_text))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| at("signingDigests"))?;
        builds.push(RuntimeBuild { platform: platform.to_owned(), app_id: app_id.to_owned(), signing_digests });
    }
    Ok(builds)
}

/// The publishers file: a closed map from artefact kind to a non-empty list of 16-byte key IDs.
fn parse_publishers(doc: &Value) -> Result<BTreeMap<String, Vec<KeyId>>, String> {
    let m = doc.as_map().ok_or_else(|| "publishers".to_owned())?;
    let mut out = BTreeMap::new();
    for (kind, v) in m {
        if ArtefactKind::parse(kind).is_none() {
            return Err(format!("unknown artefact kind {kind}"));
        }
        let list = v.as_array().filter(|a| !a.is_empty()).ok_or_else(|| format!("publishers.{kind}"))?;
        let ids = list
            .iter()
            .map(|k| k.as_text().filter(|t| t.len() == 32).and_then(unhex).and_then(|b| KeyId::from_bytes(&b).ok()))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| format!("publishers.{kind}"))?;
        out.insert(kind.clone(), ids);
    }
    Ok(out)
}

fn read_builds(path: &str, out: &mut Outcome) -> Res<Option<Vec<RuntimeBuild>>> {
    let Some(doc) = load_doc(path, out)? else { return Ok(None) };
    parse_builds(&doc).map(Some).map_err(|field| usage("bad-ceremony", &[("file", path), ("field", &field)]))
}

fn bundle(args: &Args, out: &mut Outcome) -> Res {
    let out_file = args.required("trust bundle", "--out")?;
    let roots_path = args.required("trust bundle", "--roots")?;
    let at = now(args)?;
    let Some(custody) = custody_dir(args, out) else { return Ok(()) };
    let roots = read_certs(roots_path, out);
    let certificates = args.value("--pins").map(|p| read_certs(p, out)).unwrap_or_default();
    if out.exit != exit::OK {
        return Ok(());
    }
    let mut attestation_roots: BTreeMap<String, Vec<Vec<u8>>> = BTreeMap::new();
    if let Some(dir) = args.value("--attestation-roots") {
        for f in files_in(dir) {
            let format = Path::new(&f).file_stem().and_then(|s| s.to_str()).unwrap_or("").to_owned();
            if format.is_empty() {
                return Err(usage("bad-ceremony", &[("file", &f), ("field", "file name (the evidence format)")]));
            }
            let Some(bytes) = read(&f, out) else { return Ok(()) };
            attestation_roots.entry(format).or_default().push(bytes);
        }
    }
    let runtime_builds = match args.value("--runtime-builds") {
        Some(p) => match read_builds(p, out)? {
            Some(b) => b,
            None => return Ok(()),
        },
        None => Vec::new(),
    };
    let mut logs: Vec<LogPin> = args.values("--log-origin").iter().map(|o| MemoryTransparencyLog::new(o, NullTransport).pin()).collect();
    for spec in args.values("--log") {
        let pin = spec.split_once('=').and_then(|(origin, key)| {
            let key = unhex(key).filter(|k| fieldseal_kernel::crypto::P256PublicKey::from_bytes(k).is_ok())?;
            (!origin.is_empty() && !origin.contains(char::is_whitespace)).then(|| LogPin { origin: origin.to_owned(), public_key: key, format: CHECKPOINT_FORMAT.into() })
        });
        logs.push(pin.ok_or_else(|| usage("bad-log-pin", &[("value", spec)]))?);
    }
    let mut revocations = Vec::new();
    for p in args.values("--revocations") {
        for f in files_in(p) {
            let Some(bytes) = read(&f, out) else { return Ok(()) };
            match Revocation::decode(&bytes) {
                Ok(r) => revocations.push(r),
                Err(e) => {
                    out.raw_finding("WIRE", "error", &f, "", &e.to_string());
                    return Ok(());
                }
            }
        }
    }
    let publishers = match args.value("--publishers") {
        Some(p) => {
            let Some(doc) = load_doc(p, out)? else { return Ok(()) };
            parse_publishers(&doc).map_err(|field| usage("bad-ceremony", &[("file", p), ("field", &field)]))?
        }
        None => {
            let all: Vec<KeyId> = certificates.iter().filter(|c| c.purpose() == Some(Purpose::Publisher)).map(|c| *c.key_id()).collect();
            if all.is_empty() { BTreeMap::new() } else { ArtefactKind::ALL.iter().map(|k| (k.as_str().to_owned(), all.clone())).collect() }
        }
    };
    let previous = match args.value("--previous") {
        Some(p) => {
            let Some(bytes) = read(p, out) else { return Ok(()) };
            match TrustBundle::decode(&bytes) {
                Ok(b) => Some(b),
                Err(e) => {
                    out.raw_finding("WIRE", "error", p, "", &e.to_string());
                    return Ok(());
                }
            }
        }
        None => None,
    };
    let version = match args.value("--version") {
        Some(v) => BundleVersion::parse(v).map_err(|_| usage("bad-version", &[("value", v)]))?,
        None => previous.as_ref().map_or(BundleVersion { major: 1, minor: 0, patch: 0 }, |p| {
            let v = p.version();
            BundleVersion { patch: v.patch + 1, ..v }
        }),
    };
    let contents = TrustBundleContents {
        name: args.value("--name").unwrap_or("trust-bundle").to_owned(),
        version,
        issued: at,
        roots: roots.clone(),
        certificates,
        publishers,
        attestation_roots,
        runtime_builds,
        logs,
        revocations,
    };
    // Every root listed that this custody holds signs (TRU-031); a replacement root's bundle
    // is signed with both roots by pointing at both custodies in turn.
    let held: Vec<&KeyCertificate> = roots.iter().filter(|r| custody.holds(r.key_id())).collect();
    if held.is_empty() {
        fail(out, exit::CONFIG, "no-root-in-custody", &[]);
        return Ok(());
    }
    let caller = caller(args);
    match Authority::new(&custody, &caller).build_bundle(contents, &held, previous.as_ref()) {
        Ok(b) => {
            let Ok(bytes) = b.encode() else {
                fail(out, exit::INTERNAL, "encode-failed", &[]);
                return Ok(());
            };
            if !write(Path::new(out_file), &bytes, false, out) {
                return Ok(());
            }
            let address = b.content_address().map(|a| a.to_text()).unwrap_or_default();
            out.lines.push(msg("bundle-built", &[("file", out_file), ("version", &b.version().to_string()), ("address", &address)]));
            out.set("version", Value::Text(b.version().to_string()));
            out.set("address", Value::Text(address));
            out.set("signers", Value::Array(b.signatures().iter().map(|s| Value::Text(hex(s.signer.as_bytes()))).collect()));
            dev_notice(out);
        }
        Err(e) => use_case_failed(out, out_file, &e),
    }
    Ok(())
}

// ---- verify ---------------------------------------------------------------------------------

/// Loads the trust bundle: `--trust-bundle`, else `FIELDSEAL_TRUST_BUNDLE`.
pub fn load_bundle(args: &Args, out: &mut Outcome) -> Option<TrustBundle> {
    let Some(path) = setting(args, "--trust-bundle", "FIELDSEAL_TRUST_BUNDLE") else {
        fail(out, exit::CONFIG, "no-trust-bundle", &[]);
        return None;
    };
    let bytes = read(&path, out)?;
    match TrustBundle::decode(&bytes) {
        Ok(b) => Some(b),
        Err(e) => {
            out.raw_finding("WIRE", "error", &path, "", &e.to_string());
            None
        }
    }
}

fn verify(args: &Args, out: &mut Outcome) -> Res {
    if args.positionals.is_empty() {
        return Err(usage("missing-file", &[("command", "trust verify")]));
    }
    let at = now(args)?;
    let Some(bundle) = load_bundle(args, out) else { return Ok(()) };
    let mut revocations = Vec::new();
    for p in args.values("--revocations") {
        for f in files_in(p) {
            let Some(bytes) = read(&f, out) else { return Ok(()) };
            match Revocation::decode(&bytes) {
                Ok(r) => revocations.push(r),
                Err(e) => out.raw_finding("WIRE", "error", &f, "", &e.to_string()),
            }
        }
    }
    let mut verified = Vec::new();
    for file in &args.positionals {
        let Some(cert) = read_cert(file, out) else { continue };
        let result = match (cert.role(), args.value("--purpose")) {
            (KeyRole::Root, _) => verify_chain_root(&bundle, &cert, at),
            (role, requested) => {
                let purpose = match requested {
                    Some(p) => Purpose::parse(p).ok_or_else(|| usage("unknown-purpose", &[("value", p)]))?,
                    None => match role.purpose() {
                        Some(p) => p,
                        None => continue,
                    },
                };
                verify_chain(&bundle, revocations.clone(), cert.key_id(), std::slice::from_ref(&cert), purpose, at).map(|_| ())
            }
        };
        match result {
            Ok(()) => {
                out.lines.push(msg("chain-valid", &[("file", file), ("purpose", cert.role().as_str())]));
                verified.push(Value::Text(file.clone()));
            }
            Err(e) => out.raw_finding("TRU-011", "error", file, "", &e.to_string()),
        }
    }
    out.set("verified", Value::Array(verified));
    Ok(())
}

fn verify_chain_root(bundle: &TrustBundle, cert: &KeyCertificate, at: AuthorityTime) -> Result<(), fieldseal_trust::domain::TrustError> {
    let listed = bundle.root(cert.key_id()).ok_or(fieldseal_trust::domain::TrustError::UnknownRoot(*cert.key_id()))?;
    if listed != cert {
        return Err(fieldseal_trust::domain::TrustError::UnknownRoot(*cert.key_id()));
    }
    cert.check_valid_at(at)
}

// ---- revoke ---------------------------------------------------------------------------------

fn revoke(args: &Args, out: &mut Outcome) -> Res {
    let [cert_path] = args.positionals.as_slice() else {
        return Err(usage("missing-file", &[("command", "trust revoke")]));
    };
    let reason_name = args.required("trust revoke", "--reason")?;
    let reason = RevocationReason::parse(reason_name).ok_or_else(|| usage("unknown-reason", &[("value", reason_name)]))?;
    let at = now(args)?;
    let effective = match args.value("--effective") {
        Some(t) => parse_time(t).ok_or_else(|| usage("bad-time", &[("value", t)]))?,
        None => at,
    };
    let Some(custody) = custody_dir(args, out) else { return Ok(()) };
    let Some(cert) = read_cert(cert_path, out) else { return Ok(()) };
    let Some(root) = root_cert(args, &custody, out) else { return Ok(()) };
    let target = if args.has("--key-wide") { RevocationTarget::key(*cert.key_id()) } else { RevocationTarget::certificate(&cert) };
    let caller = caller(args);
    match Authority::new(&custody, &caller).revoke(&root, target, reason, effective, at) {
        Ok(r) => {
            let Ok(bytes) = r.encode() else {
                fail(out, exit::INTERNAL, "encode-failed", &[]);
                return Ok(());
            };
            let default = Path::new(cert_path).with_extension("revocation").to_string_lossy().into_owned();
            let path = args.value("--out").unwrap_or(&default).to_owned();
            if !write(Path::new(&path), &bytes, false, out) {
                return Ok(());
            }
            out.lines.push(msg("revoked", &[("key", &hex(cert.key_id().as_bytes())), ("file", &path)]));
            out.set("file", Value::Text(path));
            out.set("reason", Value::Text(reason.as_str().into()));
            dev_notice(out);
        }
        Err(e) => use_case_failed(out, cert_path, &e),
    }
    Ok(())
}

/// `trust show --trust-bundle <file> [--custody <dir>]` (CLI §5 `trust`): the authority behind a
/// trust bundle in readable form: its name, version and digest, the roots, every certified purpose
/// key with its validity, the pinned logs, and, given a key directory, which of those keys the
/// directory holds (development custody: software keys, unattested, CLI-019).
fn show(args: &Args, out: &mut Outcome) -> Res {
    let Some(bundle) = load_bundle(args, out) else { return Ok(()) };
    let c = bundle.contents();
    let encoded = match bundle.encode() {
        Ok(b) => b,
        Err(e) => {
            out.raw_finding("WIRE", "error", "(trust bundle)", "", &e.to_string());
            return Ok(());
        }
    };
    let digest = hex(fieldseal_kernel::digest::sha256(&encoded).as_bytes());
    let day = |t: AuthorityTime| {
        let secs = (t.0 / 1000) as i64;
        let (z, rem) = (secs.div_euclid(86_400) + 719_468, secs.rem_euclid(86_400));
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        format!("{:04}-{:02}-{:02}", yoe + era * 400 + i64::from(m <= 2), m, d) + &format!("T{:02}:{:02}Z", rem / 3600, rem % 3600 / 60)
    };
    let held: Vec<_> = custody_dir(args, out).map(|d| d.keys()).unwrap_or_default();
    // `custody_dir` records a configuration error when no custody was given; that is not one here.
    if args.value("--custody").is_none() && std::env::var("FIELDSEAL_SIGNER").is_err() {
        out.error = None;
        out.exit = exit::OK;
    }
    out.lines.push(format!("authority    {} version {}, issued {}", c.name, c.version, day(c.issued)));
    out.lines.push(format!("digest       sha256:{digest} ({} bytes)", encoded.len()));
    for r in &c.roots {
        out.lines.push(format!("root         key {} valid {} to {} (self-issued)", hex(r.key_id().as_bytes()), day(r.not_before()), day(r.not_after())));
    }
    let mut keys = Vec::new();
    for k in &c.certificates {
        let purpose = k.purpose().map_or("-", |p| p.as_str());
        let alg = format!("{:?}", k.public_key().algorithm()).to_lowercase();
        let custody = if held.iter().any(|h| h.id == *k.key_id()) { "held in custody" } else { "not in this custody" };
        out.lines.push(format!("purpose key  {purpose:<13} {alg:<7} key {} valid {} to {}; {custody}", hex(k.key_id().as_bytes()), day(k.not_before()), day(k.not_after())));
        keys.push(Value::Map(
            [
                ("purpose".to_owned(), Value::Text(purpose.into())),
                ("algorithm".to_owned(), Value::Text(alg)),
                ("keyId".to_owned(), Value::Text(hex(k.key_id().as_bytes()))),
                ("notBefore".to_owned(), Value::Int(i128::from(k.not_before().0))),
                ("notAfter".to_owned(), Value::Int(i128::from(k.not_after().0))),
            ]
            .into(),
        ));
    }
    for l in &c.logs {
        out.lines.push(format!("pinned log   {} public key {}", l.origin, hex(&l.public_key)));
    }
    for b in &c.runtime_builds {
        out.lines.push(format!("runtime      {} app {} (software builds are unattested)", b.platform, b.app_id));
    }
    out.lines.push("custody      development: software keys in a key directory, unattested; a production authority uses an HSM (CLI-019)".into());
    out.set("name", Value::Text(c.name.clone()));
    out.set("digest", Value::Text(format!("sha256:{digest}")));
    out.set("keys", Value::Array(keys));
    out.set("custody", Value::Text("development-software".into()));
    Ok(())
}
