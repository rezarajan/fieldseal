//! `fieldseal artefact provenance|sign|verify|publish|withdraw` and `fieldseal log prove`
//! (CLI §5 `artefact`, `log`; PUB): the Publishing use cases (`BuildProvenance`,
//! `SignPublication`, `VerifyPublication`, `Publish`, `SignWithdrawal`, `Withdraw`,
//! `ProveInclusion`) driven from files.
//!
//! State: `FIELDSEAL_ADAPTERS=files` keeps the transparency log and the artefact registry in
//! `--state <dir>` (`FIELDSEAL_STATE_DIR`, default `.fieldseal`) so separate invocations share
//! them; the default in-memory set lasts one invocation. The log is the local development log
//! ([`crate::stores::FileLog`]); the public log (Rekor) is used only when `FIELDSEAL_REKOR_URL`
//! is set. Keys are the development custody ([`crate::custody`]).
//!
//! Files: a draft or publication is canonical CBOR (`.publication`, `.published`), the
//! withdrawal draft likewise.

use std::path::{Path, PathBuf};

use fieldseal_adapters_authoring::Format;
use fieldseal_adapters_file::registry::FileRegistry;
use fieldseal_adapters_memory::publishing::{
    MemoryArtefactRegistry, MemoryReviewSystem, MemoryTransparencyLog,
};
use fieldseal_instrument::application::{ValidationOptions, validate_instrument_with};
use crate::artefact_kinds::{KindCx, LoadedInstrument, check_envelope, validate_kind, version_key};
use fieldseal_kernel::Value;
use fieldseal_kernel::cbor;
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{ContentAddress, KeyId, ReviewerId, Salt};
use fieldseal_policy::domain::PublishingPolicy;
use fieldseal_publishing::application::{
    BuildInput, BuildProvenance, Publish, ProveInclusion, SignPublication, SignWithdrawal, VerifyPublication, Withdraw,
};
use fieldseal_publishing::domain::{
    Artefact, ArtefactKind, BuilderId, Diagnostic, Publication, PublicationDraft, PublishingError, Review, ReviewDecision, ReviewerRole, RevisionId, SourceRef,
    Withdrawal, WithdrawalDraft, WithdrawalStatement,
};
use fieldseal_publishing::ports::{ArtefactRegistry, ArtefactValidator, ReviewSystem, TransparencyLog};
use fieldseal_trust::domain::{KeyRole, TrustStore};

use crate::args::Args;
use crate::composition::{AdapterSet, Config};
use crate::custody::DirCustody;
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::policy_cmd::{effective_of, load_layers};
use crate::stores::{FileLog, LOCAL_LOG_ORIGIN};
use crate::support::{
    Res, fail, hex, now, policy_paths, read, run_command, setting, unhex, usage, write,
};
use crate::transport::NullTransport;
use crate::trust_cmd::{custody_dir, load_bundle};

pub(crate) const COMMON: &[&str] = &["--custody", "--trust-bundle", "--policy", "--state", "--log-origin", "--at", "--key", "--out", "-o", "--caller"];

/// Runs `artefact <verb>`; `None` if the verb is not one of these.
pub fn run_artefact(verb: &str, raw: &[String]) -> Option<u8> {
    let with = |extra: &[&'static str]| -> Vec<&'static str> { COMMON.iter().chain(extra).copied().collect() };
    Some(match verb {
        "provenance" => run_command(
            "artefact provenance",
            raw,
            &with(&["--source", "--source-uri", "--reviewers", "--author", "--builder", "--definition", "--salt", "--instrument"]),
            &[],
            provenance,
        ),
        "sign" => run_command("artefact sign", raw, &with(&[]), &[], sign),
        "verify" => run_command("artefact verify", raw, &with(&["--revocations"]), &[], verify),
        "publish" => run_command("artefact publish", raw, &with(&["--revocations", "--time-token"]), &[], publish),
        "withdraw" => run_command("artefact withdraw", raw, &with(&["--reason", "--draft"]), &[], withdraw),
        _ => return None,
    })
}

/// Runs `log <verb>`; `None` if the verb is not one of these.
pub fn run_log(verb: &str, raw: &[String]) -> Option<u8> {
    match verb {
        "prove" => Some(run_command("log prove", raw, COMMON, &[], prove)),
        "append" => Some(run_command("log append", raw, COMMON, &[], crate::log_cmd::append)),
        "key" => Some(run_command("log key", raw, &["--key-file"], &["--generate"], crate::log_cmd::key)),
        "verify" => Some(run_command("log verify", raw, &["--trust-bundle", "--known-tree-head", "--state", "--log-origin", "--at"], &[], crate::log_cmd::verify)),
        _ => None,
    }
}

// ---- the adapters a command is given ----------------------------------------------------------

pub(crate) struct Stores {
    pub(crate) log: Box<dyn TransparencyLog>,
    pub(crate) registry: Box<dyn ArtefactRegistry>,
}

fn state_dir(args: &Args) -> PathBuf {
    PathBuf::from(setting(args, "--state", "FIELDSEAL_STATE_DIR").unwrap_or_else(|| ".fieldseal".into()))
}

pub(crate) fn stores(args: &Args, out: &mut Outcome) -> Option<Stores> {
    let config = match Config::from_lookup(|k| std::env::var(k).ok()) {
        Ok(c) => c,
        Err(e) => {
            out.error(exit::CONFIG, format!("fieldseal: {e}"));
            return None;
        }
    };
    let origin = setting(args, "--log-origin", "FIELDSEAL_LOG_ORIGIN").unwrap_or_else(|| LOCAL_LOG_ORIGIN.into());
    let state = state_dir(args);
    let local_log = || -> Result<Box<dyn TransparencyLog>, String> {
        if let Some(remote) = crate::stores::remote_translog() {
            return remote;
        }
        match config.adapters {
            AdapterSet::Memory => Ok(Box::new(MemoryTransparencyLog::new(&origin, NullTransport))),
            AdapterSet::Files => FileLog::open(&origin, &state.join("log")).map(|l| Box::new(l) as Box<dyn TransparencyLog>).map_err(|e| e.to_string()),
        }
    };
    let log: Box<dyn TransparencyLog> = match std::env::var(fieldseal_adapters_rekor::URL_VAR).ok().filter(|v| !v.is_empty()) {
        Some(url) => match fieldseal_adapters_rekor::RekorConfig::new(&url) {
            Ok(c) => Box::new(fieldseal_adapters_rekor::RekorLog::new(fieldseal_adapters_rekor::HttpTransport::new(c))),
            Err(e) => {
                out.error(exit::CONFIG, format!("fieldseal: {e}"));
                return None;
            }
        },
        None => match local_log() {
            Ok(l) => l,
            Err(e) => {
                out.error(exit::CONFIG, format!("fieldseal: {e}"));
                return None;
            }
        },
    };
    let registry: Box<dyn ArtefactRegistry> = match config.adapters {
        AdapterSet::Memory => Box::new(MemoryArtefactRegistry::new()),
        AdapterSet::Files => Box::new(FileRegistry::new(state.join("registry"))),
    };
    Some(Stores { log, registry })
}

/// Kind-specific validation of a publication's artefact (PUB-003): instruments and policies
/// are validated by their contexts.
pub(crate) struct KindValidator;

impl ArtefactValidator for KindValidator {
    fn validate(&self, artefact: &Artefact) -> Vec<Diagnostic> {
        let Ok(value) = cbor::decode(artefact.canonical_bytes()) else {
            return vec![Diagnostic { code: "WIRE".into(), blocking: true, message: "the artefact is not canonical CBOR".into() }];
        };
        // A layout is validated against its instrument, which a published artefact does not
        // carry: its check ran at `artefact provenance` (`--instrument`), where the publication
        // was built.
        if artefact.kind() == ArtefactKind::Layout {
            return Vec::new();
        }
        let cx = KindCx { instrument: None, salt: None, dir: Path::new("") };
        validate_kind(artefact.kind(), &cx, &value).err().unwrap_or_default()
    }
}

/// The publishing policy: the effective controls of `--policy` / `FIELDSEAL_POLICY` layers.
fn publishing_policy(args: &Args, out: &mut Outcome) -> Res<Option<PublishingPolicy>> {
    let paths = policy_paths(args)?;
    if paths.is_empty() {
        fail(out, exit::CONFIG, "no-policy", &[]);
        return Ok(None);
    }
    Ok(load_layers(&paths, out)?.map(|layers| effective_of(&layers).controls.publishing()))
}

fn decode_error(out: &mut Outcome, file: &str, e: &PublishingError) {
    out.raw_finding(e.code().map_or("PUB", |c| c.as_str()), "error", file, "", &e.to_string());
}

fn finding_for(out: &mut Outcome, file: &str, e: &PublishingError) {
    let id = match e {
        PublishingError::BelowThreshold { .. } => "PUB-040",
        PublishingError::Withdrawn => "PUB-080",
        PublishingError::Validation(_) => "PUB-003",
        PublishingError::Log(_) | PublishingError::Inclusion => "PUB-100",
        other => other.code().map_or("PUB", |c| c.as_str()),
    };
    out.raw_finding(id, "error", file, "", &e.to_string());
}

fn parse_address(text: &str) -> Option<ContentAddress> {
    ContentAddress::parse_text(text).ok().or_else(|| unhex(text).and_then(|b| ContentAddress::from_bytes(&b).ok()))
}

fn output_path(args: &Args, input: &str, extension: &str) -> PathBuf {
    args.value("--out").or_else(|| args.value("-o")).map_or_else(|| Path::new(input).with_extension(extension), PathBuf::from)
}

/// The key to sign with: `--key`, else the one key of `role` in the custody.
fn signing_key(args: &Args, custody: &DirCustody, role: KeyRole, out: &mut Outcome) -> Option<KeyId> {
    if let Some(k) = args.value("--key") {
        return match unhex(k).and_then(|b| KeyId::from_bytes(&b).ok()) {
            Some(id) => Some(id),
            None => {
                out.error(exit::USAGE, msg("bad-key-id", &[("value", k)]));
                None
            }
        };
    }
    let key = custody.sole_key(role);
    if key.is_none() {
        fail(out, exit::USAGE, "key-ambiguous", &[("role", role.as_str())]);
    }
    key
}

fn caller(args: &Args) -> String {
    args.value("--caller").unwrap_or("fieldseal-cli").to_owned()
}

// ---- artefact provenance ----------------------------------------------------------------------

fn provenance(args: &Args, out: &mut Outcome) -> Res {
    let file = args.file("artefact provenance")?;
    let revision = args.required("artefact provenance", "--source")?;
    let reviewers: Vec<&str> = args.values("--reviewers").iter().flat_map(|v| v.split(',')).filter(|s| !s.is_empty()).collect();
    if reviewers.is_empty() {
        return Err(usage("missing-flag", &[("command", "artefact provenance"), ("flag", "--reviewers")]));
    }
    let at = now(args)?;
    let Some(bytes) = read(file, out) else { return Ok(()) };
    let ext = Path::new(file).extension().and_then(|e| e.to_str()).unwrap_or("");
    let Some(format) = Format::from_extension(ext) else { return Err(usage("bad-extension", &[("file", file)])) };
    let _ = (&bytes, format);
    let doc = match fieldseal_adapters_authoring::decode_path(Path::new(file)) {
        Ok(d) => d,
        Err(e) => {
            out.raw_finding("INS-002", "error", file, &format!("{}:{}", e.line, e.column), &e.message);
            return Ok(());
        }
    };
    let Some(m) = doc.as_map() else { return Err(usage("not-a-map", &[("file", file), ("what", "an artefact")])) };
    if let Err(why) = check_envelope(m) {
        return Err(usage("bad-ceremony", &[("file", file), ("field", &why)]));
    }
    let kind = m.get("kind").and_then(Value::as_text).and_then(ArtefactKind::parse);
    let meta = m.get("metadata").and_then(Value::as_map);
    let (Some(kind), Some(name), Some(version)) = (
        kind,
        meta.and_then(|x| x.get("name")).and_then(Value::as_text),
        meta.and_then(|x| x.get(version_key(m.get("kind").and_then(Value::as_text).unwrap_or_default()))).and_then(Value::as_text),
    ) else {
        return Err(usage("unknown-kind", &[("file", file)]));
    };
    // `--instrument` is the instrument a layout is validated against, and only that.
    let instrument_flag = args.value("--instrument");
    if kind != ArtefactKind::Layout && instrument_flag.is_some() {
        return Err(usage("instrument-flag-layout-only", &[]));
    }
    // The artefact salt: an instrument's is its own (random unless `--salt`); for a layout,
    // `--salt` is the salt of the instrument it binds to (INS-200).
    let given_salt = match args.value("--salt") {
        Some(s) => Some(unhex(s).and_then(|b| Salt::from_bytes(&b).ok()).ok_or_else(|| usage("bad-salt", &[]))?),
        None => None,
    };
    let loaded = if kind == ArtefactKind::Layout {
        let path = instrument_flag.ok_or_else(|| usage("missing-flag", &[("command", "artefact provenance (Layout)"), ("flag", "--instrument")]))?;
        let Some(ins_doc) = crate::support::load_doc(path, out)? else { return Ok(()) };
        let digest = |b: &[u8]| *sha256(b).as_bytes();
        match validate_instrument_with(&ins_doc, ValidationOptions { media_digest: Some(&digest) }) {
            Ok(v) => match cbor::encode(&v.instrument.to_value()) {
                Ok(canonical) => Some(LoadedInstrument { instrument: v.instrument, canonical }),
                Err(_) => {
                    fail(out, exit::INTERNAL, "encode-failed", &[]);
                    return Ok(());
                }
            },
            Err(findings) => {
                for f in &findings {
                    out.finding(path, f);
                }
                return Ok(());
            }
        }
    } else {
        None
    };
    // Canonicalise as the kind's own hash command does, so addresses agree (`instrument hash`).
    // Each translation an instrument declares (every language but the default, which any
    // reviewer of the kind covers) needs a reviewer for that language (INS-083). Every kind is
    // validated by its context's validator (CLI-300); none is accepted on its envelope alone.
    let mut languages: Vec<String> = Vec::new();
    let dir = Path::new(file).parent().unwrap_or_else(|| Path::new(""));
    let cx = KindCx { instrument: loaded.as_ref(), salt: given_salt, dir };
    let canonical_value = match validate_kind(kind, &cx, &doc) {
        Ok(v) => v,
        Err(diagnostics) => {
            for d in diagnostics.iter().filter(|d| d.blocking) {
                out.raw_finding(&d.code, "error", file, "", &d.message);
            }
            return Ok(());
        }
    };
    if kind == ArtefactKind::Instrument {
        let digest = |b: &[u8]| *sha256(b).as_bytes();
        if let Ok(v) = validate_instrument_with(&doc, ValidationOptions { media_digest: Some(&digest) }) {
            languages = v.instrument.definition().languages.translations.keys().map(|l| l.as_str().to_owned()).collect();
        }
    }
    let Ok(canonical) = cbor::encode(&canonical_value) else {
        fail(out, exit::INTERNAL, "encode-failed", &[]);
        return Ok(());
    };
    let salt = if kind == ArtefactKind::Instrument {
        match given_salt {
            Some(s) => Some(s),
            None => {
                let mut b = [0u8; 32];
                if std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut b)).is_err() {
                    fail(out, exit::CONFIG, "no-randomness", &[]);
                    return Ok(());
                }
                Some(Salt::from(b))
            }
        }
    } else {
        None
    };
    let artefact = match Artefact::new(kind, name, version, canonical, salt) {
        Ok(a) => a,
        Err(e) => {
            finding_for(out, file, &e);
            return Ok(());
        }
    };
    let Some(policy) = publishing_policy(args, out)? else { return Ok(()) };
    let Some(custody) = custody_dir(args, out) else { return Ok(()) };
    let Some(key) = signing_key(args, &custody, KeyRole::Purpose(fieldseal_kernel::crypto::Purpose::Builder), out) else { return Ok(()) };
    let author = args.value("--author").unwrap_or("author");
    let reviews = MemoryReviewSystem::new();
    for r in &reviewers {
        // `--reviewers name` holds the reviewer role for the kind; `name:en+fr` also holds
        // the language roles (PUB-013, INS-083). The development review system takes its
        // roles from the flag.
        let (who, langs) = r.split_once(':').map_or((*r, ""), |(w, l)| (w, l));
        let Ok(reviewer) = ReviewerId::new(who) else { return Err(usage("bad-reviewer", &[("value", r)])) };
        reviews.grant_kind(&reviewer, kind);
        for l in langs.split('+').filter(|l| !l.is_empty()) {
            reviews.grant(&reviewer, ReviewerRole::for_language(kind, l));
        }
        let review = Review { address: *artefact.address(), revision: RevisionId(revision.into()), reviewer, decision: ReviewDecision::Approve };
        if let Err(e) = reviews.record(&review) {
            out.error(exit::INTERNAL, e.to_string());
            return Ok(());
        }
    }
    let first = |list: &[String], flag: &str, env: &str| setting(args, flag, env).or_else(|| list.first().cloned());
    let (Some(uri), Some(builder)) = (first(&policy.allowed_sources, "--source-uri", "FIELDSEAL_SOURCE_URI"), first(&policy.allowed_builders, "--builder", "FIELDSEAL_BUILDER"))
    else {
        fail(out, exit::CONFIG, "no-source-or-builder", &[]);
        return Ok(());
    };
    let definition = match args.value("--definition") {
        Some(h) => unhex(h).and_then(|b| fieldseal_kernel::id::Digest::from_bytes(&b).ok()).ok_or_else(|| usage("bad-digest", &[("value", h)]))?,
        None => sha256(b"fieldseal.dev/cli/local-build/v1"),
    };
    let Ok(author) = ReviewerId::new(author) else { return Err(usage("bad-reviewer", &[("value", author)])) };
    let input = BuildInput {
        artefact: artefact.clone(),
        source: SourceRef { uri, revision: RevisionId(revision.into()) },
        author,
        builder: BuilderId(builder),
        definition,
        finished: at,
        languages,
    };
    let caller = caller(args);
    match BuildProvenance::new(&custody, &reviews, &policy, key, &caller).build(input) {
        Ok(draft) => {
            let path = output_path(args, file, "publication");
            if write(&path, &draft.encode(), false, out) {
                let address = artefact.address().to_text();
                out.lines.push(msg("provenance-written", &[("file", &path.to_string_lossy()), ("address", &address)]));
                out.set("address", Value::Text(address));
                out.set("kind", Value::Text(kind.as_str().into()));
                out.set("file", Value::Text(path.to_string_lossy().into_owned()));
                out.set("reviewers", Value::Array(reviewers.iter().map(|r| Value::Text(r.split(':').next().unwrap_or(r).into())).collect()));
                out.set("custody", Value::Text("development-software".into()));
                out.set("attested", Value::Bool(false));
            }
        }
        Err(e) => finding_for(out, file, &e),
    }
    Ok(())
}

// ---- shared: reading a draft or publication ---------------------------------------------------

enum Loaded {
    Draft(PublicationDraft),
    Published(Publication),
}

fn load_publication(file: &str, out: &mut Outcome) -> Option<Loaded> {
    let bytes = read(file, out)?;
    let is_draft = cbor::decode(&bytes).ok().and_then(|v| v.as_map().map(|m| m.contains_key("approvals"))).unwrap_or(false);
    let result = if is_draft { PublicationDraft::decode(&bytes).map(Loaded::Draft) } else { Publication::decode(&bytes).map(Loaded::Published) };
    match result {
        Ok(l) => Some(l),
        Err(e) => {
            decode_error(out, file, &e);
            None
        }
    }
}

fn revocations(args: &Args, out: &mut Outcome) -> Option<Vec<fieldseal_trust::domain::Revocation>> {
    let mut v = Vec::new();
    for p in args.values("--revocations") {
        for f in crate::support::files_in(p) {
            let bytes = read(&f, out)?;
            match fieldseal_trust::domain::Revocation::decode(&bytes) {
                Ok(r) => v.push(r),
                Err(e) => {
                    out.raw_finding("WIRE", "error", &f, "", &e.to_string());
                    return None;
                }
            }
        }
    }
    Some(v)
}

/// The trust bundle, its revocations and the publishing policy every verifying command needs.
struct Verifying {
    bundle: fieldseal_trust::domain::TrustBundle,
    policy: PublishingPolicy,
    revocations: Vec<fieldseal_trust::domain::Revocation>,
}

fn verifying(args: &Args, out: &mut Outcome) -> Res<Option<Verifying>> {
    let Some(bundle) = load_bundle(args, out) else { return Ok(None) };
    let Some(policy) = publishing_policy(args, out)? else { return Ok(None) };
    let Some(revocations) = revocations(args, out) else { return Ok(None) };
    Ok(Some(Verifying { bundle, policy, revocations }))
}

impl Verifying {
    fn verifier(&self, out: &mut Outcome) -> Option<VerifyPublication<'_>> {
        match TrustStore::new(&self.bundle).with_revocations(self.revocations.clone()) {
            Ok(store) => Some(VerifyPublication::new(store, &self.policy).with_validator(&KindValidator)),
            Err(e) => {
                out.raw_finding("TRU-042", "error", "(revocations)", "", &e.to_string());
                None
            }
        }
    }
}

// ---- artefact sign ----------------------------------------------------------------------------

fn sign(args: &Args, out: &mut Outcome) -> Res {
    let file = args.file("artefact sign")?;
    let Some(Loaded::Draft(draft)) = load_publication(file, out) else {
        if out.exit == exit::OK {
            fail(out, exit::FAILED, "not-a-draft", &[("file", file)]);
        }
        return Ok(());
    };
    let Some(v) = verifying(args, out)? else { return Ok(()) };
    let Some(verifier) = v.verifier(out) else { return Ok(()) };
    let Some(custody) = custody_dir(args, out) else { return Ok(()) };
    let Some(key) = signing_key(args, &custody, KeyRole::Purpose(fieldseal_kernel::crypto::Purpose::Publisher), out) else { return Ok(()) };
    let caller = caller(args);
    match SignPublication::new(&custody, &verifier, &caller).sign(&draft, &key) {
        Ok(signed) => {
            let path = output_path(args, file, "publication");
            let path = if args.value("--out").is_none() && args.value("-o").is_none() { PathBuf::from(file) } else { path };
            if write(&path, &signed.encode(), false, out) {
                let status = verifier.verify_draft(&signed).ok();
                let (have, need) = status.map_or((signed.approvals.len() as u64, 0), |s| (s.signatures, s.threshold));
                out.lines.push(msg("signed", &[("key", &hex(key.as_bytes())), ("have", &have.to_string()), ("need", &need.to_string())]));
                out.set("signatures", Value::Int(i128::from(have)));
                out.set("threshold", Value::Int(i128::from(need)));
                out.set("signer", Value::Text(hex(key.as_bytes())));
                out.set("file", Value::Text(path.to_string_lossy().into_owned()));
                out.set("custody", Value::Text("development-software".into()));
                out.set("attested", Value::Bool(false));
            }
        }
        Err(e) => finding_for(out, file, &e),
    }
    Ok(())
}

// ---- artefact verify --------------------------------------------------------------------------

fn verify(args: &Args, out: &mut Outcome) -> Res {
    let file = args.file("artefact verify")?;
    let Some(loaded) = load_publication(file, out) else { return Ok(()) };
    let Some(v) = verifying(args, out)? else { return Ok(()) };
    let Some(verifier) = v.verifier(out) else { return Ok(()) };
    match loaded {
        Loaded::Draft(d) => match verifier.verify_draft(&d) {
            Ok(s) => {
                out.lines.push(msg("draft-verified", &[("file", file), ("have", &s.signatures.to_string()), ("need", &s.threshold.to_string())]));
                out.set("complete", Value::Bool(s.complete()));
                out.set("signatures", Value::Int(i128::from(s.signatures)));
                out.set("threshold", Value::Int(i128::from(s.threshold)));
                out.set("address", Value::Text(d.artefact.address().to_text()));
                for w in &s.warnings {
                    out.raw_finding(&w.code, "warning", file, "", &w.message);
                }
            }
            Err(e) => finding_for(out, file, &e),
        },
        Loaded::Published(p) => {
            let withdrawals = match Stores::registry_withdrawals(args, out) {
                Some(w) => w,
                None => return Ok(()),
            };
            match verifier.verify(&p, &withdrawals) {
                Ok(ok) => {
                    out.lines.push(msg("publication-verified", &[("file", file), ("signers", &ok.signers.len().to_string())]));
                    out.set("address", Value::Text(ok.address.to_text()));
                    out.set("signers", Value::Array(ok.signers.iter().map(|k| Value::Text(hex(k.as_bytes()))).collect()));
                }
                Err(e) => finding_for(out, file, &e),
            }
        }
    }
    Ok(())
}

impl Stores {
    /// The withdrawals the configured registry holds (none if it holds none yet).
    fn registry_withdrawals(args: &Args, out: &mut Outcome) -> Option<Vec<Withdrawal>> {
        let s = stores(args, out)?;
        match s.registry.withdrawals() {
            Ok(w) => Some(w),
            Err(e) => {
                out.error(exit::CONFIG, format!("fieldseal: {e}"));
                None
            }
        }
    }
}

// ---- artefact publish -------------------------------------------------------------------------

/// The encoded time token a publication carries (PUB-061, PUB-072), checked against the trust
/// bundle: from `--time-token`, else issued by the custody's `receipt` key. Refuses (usage,
/// exit 2) when neither is available.
fn time_token(args: &Args, v: &Verifying, out: &mut Outcome) -> Res<Option<Vec<u8>>> {
    use fieldseal_distribution::domain::TimeToken;
    use fieldseal_kernel::crypto::{Purpose, tags};
    let bytes = match args.value("--time-token") {
        Some(path) => match read(path, out) {
            Some(b) => b,
            None => return Ok(None),
        },
        None => {
            if setting(args, "--custody", "FIELDSEAL_SIGNER").is_none() {
                return Err(usage("publish-needs-time-token", &[]));
            }
            let Some(custody) = custody_dir(args, out) else { return Ok(None) };
            let role = KeyRole::Purpose(Purpose::Receipt);
            let Some(key) = custody.sole_key(role) else {
                return Err(usage("publish-needs-time-token", &[]));
            };
            let at = now(args)?;
            let mut token = TimeToken { authority_time: at, nonce: None, signer: key, signature: fieldseal_kernel::crypto::Signature(Vec::new()) };
            match fieldseal_trust::ports::KeyCustody::sign(&custody, &key, role, &tags::TIME_TOKEN, &token.signed_structure(), &caller(args)) {
                Ok(sig) => token.signature = sig,
                Err(e) => {
                    out.raw_finding("TRU-001", "error", "(time token)", "", &e.to_string());
                    return Ok(None);
                }
            }
            token.encode()
        }
    };
    let verified = TimeToken::decode(&bytes).map_err(|e| e.to_string()).and_then(|t| t.verify(&TrustStore::new(&v.bundle)).map_err(|e| e.to_string()));
    if let Err(e) = verified {
        out.raw_finding("PUB-072", "error", "(time token)", "", &format!("the time token is not valid against the trust bundle: {e}"));
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn publish(args: &Args, out: &mut Outcome) -> Res {
    let file = args.file("artefact publish")?;
    let Some(Loaded::Draft(draft)) = load_publication(file, out) else {
        if out.exit == exit::OK {
            fail(out, exit::FAILED, "not-a-draft", &[("file", file)]);
        }
        return Ok(());
    };
    let Some(v) = verifying(args, out)? else { return Ok(()) };
    // PUB-072: a tree head with no authority time token is too old for every runtime, so a
    // publication without one would be refused by devices. The token is `--time-token <file>`,
    // or one issued now by the `receipt` key of the configured custody (`--custody`,
    // `FIELDSEAL_SIGNER`). With neither, nothing is published.
    let Some(token) = time_token(args, &v, out)? else { return Ok(()) };
    let token = Some(token);
    let Some(verifier) = v.verifier(out) else { return Ok(()) };
    let Some(s) = stores(args, out) else { return Ok(()) };
    let address = draft.artefact.address().to_text();
    // Publishing is idempotent (CLI-006): the same content address is neither logged nor stored twice.
    let already = s.registry.get(draft.artefact.address()).unwrap_or(None);
    let withdrawals = s.registry.withdrawals().unwrap_or_default();
    let result = match &already {
        Some(p) => verifier.verify(p, &withdrawals).map(|_| p.clone()),
        None => {
            let publish = Publish::new(s.log.as_ref(), s.registry.as_ref(), &verifier);
            match token {
                Some(t) => publish.with_checkpoint_time(t),
                None => publish,
            }
            .publish(&draft, &withdrawals)
        }
    };
    match result {
        Ok(p) => {
            let path = output_path(args, file, "published");
            if write(&path, &p.encode(), false, out) {
                let key = if already.is_some() { "already-published" } else { "published" };
                out.lines.push(msg(key, &[("address", &address), ("file", &path.to_string_lossy())]));
                out.set("address", Value::Text(address));
                out.set("alreadyPublished", Value::Bool(already.is_some()));
                out.set("file", Value::Text(path.to_string_lossy().into_owned()));
                out.set("treeSize", Value::Int(i128::from(p.checkpoint.size())));
            }
        }
        Err(e) => finding_for(out, file, &e),
    }
    Ok(())
}

// ---- artefact withdraw ------------------------------------------------------------------------

fn withdraw(args: &Args, out: &mut Outcome) -> Res {
    let [addr_text] = args.positionals.as_slice() else { return Err(usage("missing-file", &[("command", "artefact withdraw")])) };
    let address = parse_address(addr_text).ok_or_else(|| usage("bad-address", &[("value", addr_text)]))?;
    let reason = args.required("artefact withdraw", "--reason")?;
    let at = now(args)?;
    let Some(v) = verifying(args, out)? else { return Ok(()) };
    let Some(verifier) = v.verifier(out) else { return Ok(()) };
    let Some(s) = stores(args, out) else { return Ok(()) };
    let publication = match s.registry.get(&address) {
        Ok(Some(p)) => p,
        Ok(None) => {
            fail(out, exit::NOT_FOUND, "no-such-publication", &[("address", addr_text)]);
            return Ok(());
        }
        Err(e) => {
            out.error(exit::CONFIG, format!("fieldseal: {e}"));
            return Ok(());
        }
    };
    let mut draft = match args.value("--draft") {
        Some(p) => {
            let Some(bytes) = read(p, out) else { return Ok(()) };
            match WithdrawalDraft::decode(&bytes) {
                Ok(d) => d,
                Err(e) => {
                    decode_error(out, p, &e);
                    return Ok(());
                }
            }
        }
        None => WithdrawalDraft { statement: WithdrawalStatement::of(&publication, reason, at), approvals: Vec::new() },
    };
    let Some(custody) = custody_dir(args, out) else { return Ok(()) };
    let keys: Vec<KeyId> = if args.flags.contains_key("--key") {
        let mut ks = Vec::new();
        for k in args.values("--key") {
            match unhex(k).and_then(|b| KeyId::from_bytes(&b).ok()) {
                Some(id) => ks.push(id),
                None => return Err(usage("bad-key-id", &[("value", k)])),
            }
        }
        ks
    } else {
        signing_key(args, &custody, KeyRole::Purpose(fieldseal_kernel::crypto::Purpose::Publisher), out).into_iter().collect()
    };
    let caller = caller(args);
    for key in &keys {
        match SignWithdrawal::new(&custody, &verifier, &caller).sign(&draft, &publication, key) {
            Ok(d) => draft = d,
            Err(e) => {
                finding_for(out, addr_text, &e);
                return Ok(());
            }
        }
    }
    let status = verifier.verify_withdrawal_draft(&draft, &publication);
    match status {
        Ok(st) if st.complete() => {}
        Ok(st) => {
            let path = args.value("--out").or_else(|| args.value("-o")).map_or_else(|| PathBuf::from(format!("{}.withdrawal", &hex(address.as_bytes())[..16])), PathBuf::from);
            if write(&path, &draft.encode(), false, out) {
                out.lines.push(msg("withdrawal-pending", &[("have", &st.signatures.to_string()), ("need", &st.threshold.to_string()), ("file", &path.to_string_lossy())]));
                out.set("file", Value::Text(path.to_string_lossy().into_owned()));
                out.fail(exit::FAILED);
            }
            return Ok(());
        }
        Err(e) => {
            finding_for(out, addr_text, &e);
            return Ok(());
        }
    }
    // Idempotent (CLI-006): an already-recorded withdrawal of the same statement is not logged again.
    match Withdraw::new(s.log.as_ref(), s.registry.as_ref(), &verifier).withdraw(&draft, &publication) {
        Ok(w) => {
            out.lines.push(msg("withdrawn", &[("address", &w.address().to_text())]));
            out.set("address", Value::Text(w.address().to_text()));
            out.set("treeSize", Value::Int(i128::from(w.checkpoint.size())));
        }
        Err(e) => finding_for(out, addr_text, &e),
    }
    Ok(())
}

// ---- log prove --------------------------------------------------------------------------------

fn prove(args: &Args, out: &mut Outcome) -> Res {
    let [addr_text] = args.positionals.as_slice() else { return Err(usage("missing-file", &[("command", "log prove")])) };
    let address = parse_address(addr_text).ok_or_else(|| usage("bad-address", &[("value", addr_text)]))?;
    let Some(v) = verifying(args, out)? else { return Ok(()) };
    let Some(verifier) = v.verifier(out) else { return Ok(()) };
    let Some(s) = stores(args, out) else { return Ok(()) };
    let publication = match s.registry.get(&address) {
        Ok(Some(p)) => p,
        Ok(None) => {
            fail(out, exit::NOT_FOUND, "no-such-publication", &[("address", addr_text)]);
            return Ok(());
        }
        Err(e) => {
            out.error(exit::CONFIG, format!("fieldseal: {e}"));
            return Ok(());
        }
    };
    match ProveInclusion::new(s.log.as_ref(), &verifier).prove(&publication) {
        Ok(p) => {
            let cp = &p.checkpoint;
            let indices: Vec<u64> = p.log.iter().map(|r| r.inclusion.leaf_index).collect();
            out.lines.push(msg("proved", &[("address", &address.to_text()), ("size", &cp.size().to_string()), ("root", &hex(cp.root().as_bytes()))]));
            out.set("address", Value::Text(address.to_text()));
            out.set("treeSize", Value::Int(i128::from(cp.size())));
            out.set("rootHash", Value::Text(hex(cp.root().as_bytes())));
            out.set("leafIndices", Value::Array(indices.iter().map(|i| Value::Int(i128::from(*i))).collect()));
            out.set("checkpoint", Value::Text(String::from_utf8_lossy(cp.note()).into_owned()));
            if let Some(path) = args.value("--out").or_else(|| args.value("-o"))
                && write(Path::new(path), &p.encode(), false, out)
            {
                out.set("file", Value::Text(path.into()));
            }
        }
        Err(e) => finding_for(out, addr_text, &e),
    }
    Ok(())
}
