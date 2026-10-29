//! `fieldseal registration token|request|inspect|approve` (CLI §5 `registration`, REG): the
//! factory's registration use cases and a software device, driven from files.
//!
//! The factory side (`token`, `inspect`, `approve`) runs against the authority's keys in the
//! development custody ([`crate::custody`]) and the trust bundle; the issued tokens persist in
//! `--state` so a token is single-use across invocations. Everything else the factory keeps
//! (tenancies, decisions) lives for one invocation, and the result is the file it writes.
//!
//! `request` builds the device side with software keys, so the request is **unattested**
//! (CLI-007, CLI-013). `approve` then denies it unless the policy in use accepts software
//! keys and `--allow-unattested` (a non-production switch) is given; production policy never
//! does.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fieldseal_adapters_memory::demo::DEMO_SCHEMA;
use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog};
use fieldseal_adapters_memory::registration::{
    MemoryReceivedProgress, MemoryRegistryStore, SoftwareDevice, reported_version,
};
use fieldseal_adapters_memory::trust::{FixedClock, SoftwareAttestationVerifier};
use fieldseal_kernel::Value;
use fieldseal_kernel::crypto::Purpose;
use fieldseal_kernel::id::{KeyId, Nonce};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::domain::{Controls, EffectivePolicy};
use fieldseal_registration::application::{Factory, FactoryConfig, FactoryPorts, Submission};
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::domain::wire::{RequestBody, decode_request, decode_request_file, encode_request_file};
use fieldseal_registration::domain::{
    AccountId, AuthRecord, AuthenticatedPerson, AuthenticationMethods, FingerprintWords,
    IssuedToken, MethodAssurance, RegistrationRoute, RegistrationToken, ReportedProfile, Role,
    TenancyState, TenancyTerms, TokenSecret, Window,
};
use fieldseal_registration::ports::{IssuedNonce, RegistryStore, RegistryStoreError, TokenError};
use fieldseal_trust::application::VerifyEvidence;
use fieldseal_trust::domain::{AuthorityPublicKey, KeyRole, TrustBundle};
use fieldseal_trust::ports::KeyCustody;

use crate::args::Args;
use crate::custody::{DirCustody, OsRandom};
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::policy_cmd::{effective_of, load_layers};
use crate::support::{Res, fail, hex, now, policy_paths, read, run_command, setting, unhex, usage, write};
use crate::trust_cmd::{custody_dir, load_bundle};

const COMMON: &[&str] = &["--custody", "--trust-bundle", "--policy", "--state", "--at", "--factory-url", "--record-key", "--out", "-o", "--caller"];

/// Runs `registration <verb>`; `None` if the verb is not one of these.
pub fn run(verb: &str, raw: &[String]) -> Option<u8> {
    let with = |extra: &[&'static str]| -> Vec<&'static str> { COMMON.iter().chain(extra).copied().collect() };
    Some(match verb {
        "token" => run_command("registration token", raw, &with(&["--account", "--batch", "--route", "--qr"]), &[], token),
        "request" => run_command("registration request", raw, &with(&["--token", "--label", "--device-dir"]), &[], request),
        "inspect" => run_command("registration inspect", raw, &with(&[]), &[], inspect),
        "approve" => run_command("registration approve", raw, &with(&["--words"]), &["--allow-unattested"], approve),
        // The device side over the network (REG-050): see `registration_remote`.
        _ => return crate::registration_remote::run(verb, raw),
    })
}

// ---- the token store: tokens persist, everything else is for one invocation ---------------------

pub(crate) struct TokenFiles {
    inner: MemoryRegistryStore,
    dir: PathBuf,
    /// Whether token use is written back (a dry run reads the tokens but leaves them as they were).
    persist: bool,
}

fn encode_issued(t: &IssuedToken, used: u32) -> String {
    format!(
        "token={}\naccount={}\nexpires={}\nmaxUses={}\nmethods={}\nphishingResistant={}\nasserted={}\nused={used}\n",
        t.token.to_text().unwrap_or_default(),
        t.account.0,
        t.expires_at.0,
        t.max_uses,
        t.authentication.methods.join(","),
        t.authentication.phishing_resistant,
        t.authentication.asserted
    )
}

/// Reads a persisted `key=value` record strictly: exactly the `keys`, each once, one per line,
/// no blank or malformed lines and no other key.
fn record<'t>(text: &'t str, keys: &[&str]) -> Option<BTreeMap<&'t str, &'t str>> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line.split_once('=')?;
        if !keys.contains(&k) || out.insert(k, v).is_some() {
            return None;
        }
    }
    (out.len() == keys.len()).then_some(out)
}

fn flag(v: &str) -> Option<bool> {
    match v {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// A whole number written in decimal digits only (no sign, no leading `+`, no spaces).
fn number<T: TryFrom<u64>>(v: &str) -> Option<T> {
    crate::support::parse_uint(v).and_then(|n| T::try_from(n).ok())
}

fn decode_issued(text: &str) -> Option<(IssuedToken, u32)> {
    let f = record(text, &["token", "account", "expires", "maxUses", "methods", "phishingResistant", "asserted", "used"])?;
    let token = RegistrationToken::from_text(f["token"]).ok()?;
    let issued = IssuedToken {
        token,
        account: AccountId(f["account"].to_owned()),
        expires_at: AuthorityTime(number(f["expires"])?),
        max_uses: number(f["maxUses"])?,
        authentication: AuthRecord {
            methods: f["methods"].split(',').filter(|s| !s.is_empty()).map(str::to_owned).collect(),
            phishing_resistant: flag(f["phishingResistant"])?,
            asserted: flag(f["asserted"])?,
        },
    };
    Some((issued, number(f["used"])?))
}

impl TokenFiles {
    pub(crate) fn open(dir: PathBuf, persist: bool) -> Self {
        let inner = MemoryRegistryStore::new();
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.filter_map(Result::ok) {
                let Some((issued, used)) = std::fs::read_to_string(e.path()).ok().and_then(|t| decode_issued(&t)) else { continue };
                if inner.put_token(&issued).is_ok() {
                    for _ in 0..used {
                        let _ = inner.consume_token(&issued.token.secret, AuthorityTime(issued.token.issued_at.0));
                    }
                }
            }
        }
        let this = Self { inner, dir, persist };
        // Accounts persist beside the tokens: the collector reference is issued once (REG §accounts).
        if let Ok(rd) = std::fs::read_dir(this.accounts_dir()) {
            for e in rd.filter_map(Result::ok) {
                if let Some(a) = std::fs::read_to_string(e.path()).ok().and_then(|t| decode_account(&t)) {
                    let _ = this.inner.put_account(&a);
                }
            }
        }
        this
    }

    fn accounts_dir(&self) -> PathBuf {
        self.dir.with_file_name("accounts")
    }

    fn file(&self, secret: &TokenSecret) -> PathBuf {
        self.dir.join(format!("{}.token", hex(secret.as_bytes())))
    }

    fn save(&self, secret: &TokenSecret) {
        if !self.persist {
            return;
        }
        if let Ok(Some((issued, remaining))) = self.inner.token(secret) {
            let _ = std::fs::create_dir_all(&self.dir);
            let _ = std::fs::write(self.file(secret), encode_issued(&issued, issued.max_uses.saturating_sub(remaining)));
        }
    }
}

fn encode_account(a: &fieldseal_registration::domain::Account) -> String {
    let roles: Vec<&str> = a.roles.iter().map(|r| r.as_str()).collect();
    format!("id={}\ncollector={}\nroles={}\n", a.id.0, hex(&a.collector), roles.join(","))
}

fn decode_account(text: &str) -> Option<fieldseal_registration::domain::Account> {
    let f = record(text, &["id", "collector", "roles"])?;
    let collector: [u8; 16] = unhex(f["collector"])?.try_into().ok()?;
    let roles = f["roles"].split(',').filter(|r| !r.is_empty()).map(Role::parse).collect::<Option<Vec<_>>>()?;
    Some(fieldseal_registration::domain::Account { id: AccountId(f["id"].to_owned()), collector, roles })
}

macro_rules! delegate {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => {
        $(fn $name(&self, $($arg: $ty),*) -> $ret { self.inner.$name($($arg),*) })*
    };
}

impl RegistryStore for TokenFiles {
    fn put_token(&self, token: &IssuedToken) -> Result<(), RegistryStoreError> {
        self.inner.put_token(token)?;
        self.save(&token.token.secret);
        Ok(())
    }

    fn consume_token(&self, secret: &TokenSecret, now: AuthorityTime) -> Result<IssuedToken, TokenError> {
        let t = self.inner.consume_token(secret, now)?;
        self.save(secret);
        Ok(t)
    }

    fn put_account(&self, account: &fieldseal_registration::domain::Account) -> Result<(), RegistryStoreError> {
        self.inner.put_account(account)?;
        if self.persist {
            let dir = self.accounts_dir();
            let _ = std::fs::create_dir_all(&dir);
            let _ = std::fs::write(dir.join(format!("{}.account", hex(fieldseal_kernel::digest::sha256(account.id.0.as_bytes()).as_bytes()))), encode_account(account));
        }
        Ok(())
    }

    delegate! {
        token(secret: &TokenSecret) -> Result<Option<(IssuedToken, u32)>, RegistryStoreError>;
        account(id: &AccountId) -> Result<Option<fieldseal_registration::domain::Account>, RegistryStoreError>;
        put_tenancy(tenancy: &fieldseal_registration::domain::TenancyRecord) -> Result<(), RegistryStoreError>;
        tenancy(id: &fieldseal_kernel::id::TenancyId) -> Result<Option<fieldseal_registration::domain::TenancyRecord>, RegistryStoreError>;
        tenancy_by_handle(handle: &fieldseal_kernel::id::TenancyHandle) -> Result<Option<fieldseal_registration::domain::TenancyRecord>, RegistryStoreError>;
        tenancies_of(account: &AccountId) -> Result<Vec<fieldseal_registration::domain::TenancyRecord>, RegistryStoreError>;
        put_device(device: &fieldseal_registration::domain::RegisteredDevice) -> Result<(), RegistryStoreError>;
        device(id: &fieldseal_registration::domain::DeviceId) -> Result<Option<fieldseal_registration::domain::RegisteredDevice>, RegistryStoreError>;
        devices_of(account: &AccountId) -> Result<Vec<fieldseal_registration::domain::RegisteredDevice>, RegistryStoreError>;
        put_nonce(nonce: &IssuedNonce) -> Result<(), RegistryStoreError>;
        take_nonce(nonce: &Nonce, tenancy: &fieldseal_kernel::id::TenancyId, now: AuthorityTime) -> Result<bool, RegistryStoreError>;
        record_jti(tenancy: &fieldseal_kernel::id::TenancyId, jti: &[u8; 16], until: AuthorityTime, now: AuthorityTime) -> Result<bool, RegistryStoreError>;
        put_access_token(token: &fieldseal_registration::domain::AccessToken) -> Result<(), RegistryStoreError>;
        access_token(value: &[u8; 32]) -> Result<Option<fieldseal_registration::domain::AccessToken>, RegistryStoreError>;
        put_assignment(assignment: &fieldseal_registration::domain::Assignment) -> Result<(), RegistryStoreError>;
        assignments() -> Result<Vec<fieldseal_registration::domain::Assignment>, RegistryStoreError>;
        put_roster_issue(issue: &fieldseal_registration::domain::RosterIssue) -> Result<(), RegistryStoreError>;
        roster_issues() -> Result<Vec<fieldseal_registration::domain::RosterIssue>, RegistryStoreError>;
    }
}

// ---- factory set-up ---------------------------------------------------------------------------

/// Everything a factory command needs, loaded once.
struct Setup {
    bundle: TrustBundle,
    custody: DirCustody,
    policy: EffectivePolicy,
    config: FactoryConfig,
    store: TokenFiles,
    at: AuthorityTime,
}

fn setup(args: &Args, out: &mut Outcome, persist: bool) -> Res<Option<Setup>> {
    let at = now(args)?;
    let Some(bundle) = load_bundle(args, out) else { return Ok(None) };
    let Some(custody) = custody_dir(args, out) else { return Ok(None) };
    let Some(url) = setting(args, "--factory-url", "FIELDSEAL_FACTORY_URL") else {
        fail(out, exit::CONFIG, "no-factory-url", &[]);
        return Ok(None);
    };
    let paths = policy_paths(args)?;
    let policy = if paths.is_empty() {
        EffectivePolicy { sources: vec![fieldseal_kernel::id::ContentAddress::of(b"schema-defaults")], controls: Controls::defaults() }
    } else {
        match load_layers(&paths, out)? {
            Some(layers) => effective_of(&layers),
            None => return Ok(None),
        }
    };
    let role = KeyRole::Purpose(Purpose::Registration);
    let held: Vec<_> = custody.keys().into_iter().filter(|k| k.role == role).collect();
    let signing = held.iter().find(|k| matches!(k.public_key, AuthorityPublicKey::P256(_)));
    let sealing = held.iter().find(|k| matches!(k.public_key, AuthorityPublicKey::X25519(_)));
    let (Some(signing), Some(sealing)) = (signing, sealing) else {
        fail(out, exit::CONFIG, "no-registration-keys", &[]);
        return Ok(None);
    };
    let record = match args.value("--record-key") {
        Some(k) => unhex(k).and_then(|b| KeyId::from_bytes(&b).ok()),
        None => {
            let mut certs = bundle.certificates().iter().filter(|c| c.purpose() == Some(Purpose::Record));
            certs.next().filter(|_| certs.next().is_none()).map(|c| *c.key_id())
        }
    };
    let Some(record) = record.and_then(|id| bundle.certificates_for(&id).next().cloned()) else {
        fail(out, exit::CONFIG, "no-record-key", &[]);
        return Ok(None);
    };
    let config = FactoryConfig {
        factory_url: url,
        signing_key: signing.id,
        sealing_key: sealing.id,
        terms: TenancyTerms {
            record_key: *record.key_id(),
            window: Window { not_before: record.not_before(), not_after: record.not_after(), grace_ms: 30 * AuthorityTime::DAY },
            cohorts: Vec::new(),
        },
        unattested: if args.has("--allow-unattested") { UnattestedKeys::AllowNonProduction } else { UnattestedKeys::Refuse },
        posture_nonce_ttl_ms: 10 * 60 * 1000,
        access_token_ttl_ms: 10 * 60 * 1000,
    };
    let store = TokenFiles::open(PathBuf::from(setting(args, "--state", "FIELDSEAL_STATE_DIR").unwrap_or_else(|| ".fieldseal".into())).join("registration").join("tokens"), persist);
    Ok(Some(Setup { bundle, custody, policy, config, store, at }))
}

/// Runs `body` with a factory built from `s`.
fn with_factory<T>(s: &Setup, out: &mut Outcome, body: impl FnOnce(&Factory<'_>, &mut Outcome) -> T) -> Option<T> {
    let (clock, random, progress, engine, log, verifier) =
        (FixedClock::new(s.at), OsRandom, MemoryReceivedProgress::new(), BuiltInPolicyEngine, MemoryDecisionLog::new(), SoftwareAttestationVerifier);
    let ports = FactoryPorts {
        store: &s.store,
        custody: &s.custody,
        verifiers: vec![&verifier],
        engine: &engine,
        log: &log,
        clock: &clock,
        random: &random,
        progress: &progress,
        fleet: None,
        notifier: None,
    };
    match Factory::new(ports, &s.bundle, &s.policy, &s.config) {
        Ok(f) => Some(body(&f, out)),
        Err(e) => {
            out.error(exit::CONFIG, format!("fieldseal: {e}"));
            None
        }
    }
}

fn dev_marks(out: &mut Outcome) {
    out.set("custody", Value::Text("development-software".into()));
}

// ---- token ------------------------------------------------------------------------------------

fn token(args: &Args, out: &mut Outcome) -> Res {
    let account = args.required("registration token", "--account")?;
    let uses: u32 = match args.value("--batch") {
        Some(n) => number::<u32>(n).filter(|n| *n >= 1).ok_or_else(|| usage("bad-number", &[("flag", "--batch"), ("value", n)]))?,
        None => 1,
    };
    let route = match args.value("--route") {
        None | Some("online") => RegistrationRoute::Online,
        Some("air-gapped") => RegistrationRoute::AirGapped,
        Some(other) => return Err(usage("bad-route", &[("value", other)])),
    };
    let Some(s) = setup(args, out, true)? else { return Ok(()) };
    // The CLI acts as an operator who signed in with a phishing-resistant method: it is the
    // admin tool (CLI-009), and the policy decision still applies.
    let person = AuthenticatedPerson {
        account: AccountId(account.to_owned()),
        roles: vec![Role::Collector, Role::Operator],
        role_names: vec!["operator".into()],
        authentication: AuthenticationMethods { methods: vec!["hwk".into()], phishing_resistant: true, assurance: MethodAssurance::FromProvider },
    };
    let issued = with_factory(&s, out, |f, _| f.issue_token(&person, route, uses));
    match issued {
        Some(Ok(t)) => {
            let Ok(text) = t.token.to_text() else {
                fail(out, exit::INTERNAL, "encode-failed", &[]);
                return Ok(());
            };
            let path = args.value("--out").or_else(|| args.value("-o")).map_or_else(|| PathBuf::from("registration-token.txt"), PathBuf::from);
            if !write(&path, text.as_bytes(), true, out) {
                return Ok(());
            }
            if let Some(qr) = args.value("--qr") {
                match qr_svg(&text) {
                    Some(svg) => {
                        if !write(Path::new(qr), svg.as_bytes(), false, out) {
                            return Ok(());
                        }
                        out.set("qr", Value::Text(qr.into()));
                    }
                    None => fail(out, exit::INTERNAL, "qr-failed", &[]),
                }
            }
            out.lines.push(msg("token-issued", &[("account", account), ("uses", &t.max_uses.to_string()), ("file", &path.to_string_lossy())]));
            out.set("account", Value::Text(account.into()));
            out.set("uses", Value::Int(i128::from(t.max_uses)));
            out.set("expiresAt", Value::Int(i128::from(t.expires_at.0)));
            out.set("file", Value::Text(path.to_string_lossy().into_owned()));
            dev_marks(out);
        }
        Some(Err(e)) => refusal(out, "token", &e),
        None => {}
    }
    Ok(())
}

pub(crate) fn qr_svg(text: &str) -> Option<String> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M).ok()?;
    Some(code.render::<qrcode::render::svg::Color>().min_dimensions(256, 256).quiet_zone(true).build())
}

/// A factory refusal: a policy denial is exit 5, anything else a validation failure (1).
fn refusal(out: &mut Outcome, file: &str, e: &fieldseal_registration::application::RegistrationError) {
    use fieldseal_registration::application::RegistrationError as E;
    let (id, code) = match e {
        E::PolicyDenied(_) | E::DeviceLimitReached => ("REG-PO", exit::DENIED),
        E::NotAuthorised(_) | E::Authentication(_) => ("REG-002", exit::DENIED),
        E::Port(_) => ("REG", exit::CONFIG),
        E::NotFound => ("REG", exit::NOT_FOUND),
        _ => ("REG", exit::FAILED),
    };
    out.raw_finding(id, "error", file, "", &e.to_string());
    out.fail(code);
}

// ---- request ----------------------------------------------------------------------------------

fn token_text(args: &Args, out: &mut Outcome) -> Option<String> {
    let t = args.value("--token")?;
    match t.strip_prefix('@') {
        Some(path) => read(path, out).map(|b| String::from_utf8_lossy(&b).trim().to_owned()),
        None if Path::new(t).is_file() => read(t, out).map(|b| String::from_utf8_lossy(&b).trim().to_owned()),
        None => Some(t.to_owned()),
    }
}

fn request(args: &Args, out: &mut Outcome) -> Res {
    if !args.flags.contains_key("--token") {
        return Err(usage("missing-flag", &[("command", "registration request"), ("flag", "--token")]));
    }
    let Some(bundle) = load_bundle(args, out) else { return Ok(()) };
    let Some(text) = token_text(args, out) else { return Ok(()) };
    let token = match RegistrationToken::from_text(&text) {
        Ok(t) => t,
        Err(e) => {
            out.raw_finding("WIRE-122", "error", "(token)", "", &e.to_string());
            return Ok(());
        }
    };
    if let Err(e) = token.verify(&bundle) {
        out.raw_finding("REG-010", "error", "(token)", "", &e.to_string());
        return Ok(());
    }
    let at = token.issued_at;
    // With `--device-dir` the keys are kept (and reused if the directory has them), so the
    // device can later prove possession of the tenancy it registers.
    let dir = args.value("--device-dir").map(crate::device_dir::DeviceDir::new);
    let device = match &dir {
        Some(d) => match d.keys_or_create(&OsRandom) {
            Ok((_, created)) => {
                if created {
                    out.lines.push(msg("device-dir-new", &[("dir", &d.path().to_string_lossy())]));
                }
                d.software_device().expect("the keys were just read")
            }
            Err(e) => {
                fail(out, exit::CONFIG, "write-failed", &[("file", &d.path().to_string_lossy()), ("reason", &e)]);
                return Ok(());
            }
        },
        None => SoftwareDevice::new(&OsRandom),
    };
    // The CLI device reports the schema version it builds bundles for (`bundle build`) and no catalogue.
    let profile = ReportedProfile {
        instrument_schema: reported_version(DEMO_SCHEMA),
        catalogue_reference: None,
    };
    let body: RequestBody = device.body_with_profile(&token, args.value("--label"), profile);
    let words = FingerprintWords::from_body_digest(&body.digest());
    let sealed = device.seal(&OsRandom, &bundle, at, &body, None);
    if let Some(d) = &dir
        && let Err(e) = d.save_tenancy(&hex(body.tenancy().as_bytes()))
    {
        fail(out, exit::CONFIG, "write-failed", &[("file", "tenancy"), ("reason", &e)]);
        return Ok(());
    }
    let path = args.value("--out").or_else(|| args.value("-o")).map_or_else(|| PathBuf::from("registration.request"), PathBuf::from);
    if write(&path, &encode_request_file(&sealed), false, out) {
        out.lines.push(msg("request-written", &[("file", &path.to_string_lossy()), ("words", &words.joined())]));
        out.lines.push(msg("unattested-keys", &[]));
        out.set("file", Value::Text(path.to_string_lossy().into_owned()));
        out.set("words", Value::Text(words.joined()));
        out.set("tenancy", Value::Text(hex(body.tenancy().as_bytes())));
        out.set("attested", Value::Bool(false));
        out.set("keys", Value::Text("software".into()));
    }
    Ok(())
}

// ---- inspect ----------------------------------------------------------------------------------

fn open_request(s: &Setup, file: &str, out: &mut Outcome) -> Option<fieldseal_registration::domain::RegistrationRequest> {
    let bytes = read(file, out)?;
    let sealed = match decode_request_file(&bytes) {
        Ok(x) => x,
        Err(e) => {
            out.raw_finding("WIRE-134", "error", file, "", &e.to_string());
            return None;
        }
    };
    match s.custody.open(&s.config.sealing_key, Purpose::Registration, &fieldseal_kernel::crypto::tags::REGISTRATION_SEAL, &sealed, "fieldseal-cli") {
        Ok(plain) => match decode_request(&plain) {
            Ok(r) => Some(r),
            Err(e) => {
                out.raw_finding("WIRE-134", "error", file, "", &e.to_string());
                None
            }
        },
        Err(e) => {
            out.raw_finding("REG-012", "error", file, "", &format!("the request can't be opened with the registration key: {e}"));
            None
        }
    }
}

fn inspect(args: &Args, out: &mut Outcome) -> Res {
    let file = args.file("registration inspect")?;
    let Some(s) = setup(args, out, false)? else { return Ok(()) };
    let Some(req) = open_request(&s, file, out) else { return Ok(()) };
    let verifier = SoftwareAttestationVerifier;
    let verify = VerifyEvidence::new(vec![&verifier]);
    let mut attested = false;
    for ev in &req.evidence {
        let key = match ev.kind {
            fieldseal_trust::domain::DeviceKeyKind::Signing => &req.sign_pub,
            _ => &req.agree_pub,
        };
        match verify.verify(&s.bundle, &ev.evidence, &req.nonce, key) {
            Ok(claims) => {
                attested |= claims.is_attested();
                if !claims.is_attested() {
                    out.raw_finding("TRU-061", "warning", file, &format!("{:?}", ev.kind), "the key is unattested (software evidence)");
                }
            }
            Err(e) => out.raw_finding("TRU-062", "error", file, &format!("{:?}", ev.kind), &e.to_string()),
        }
    }
    let words = req.fingerprint_words();
    out.lines.push(msg("request-inspected", &[("file", file), ("words", &words.joined())]));
    out.set("words", Value::Text(words.joined()));
    out.set("tenancy", Value::Text(hex(req.tenancy.as_bytes())));
    out.set("build", Value::Text(req.build.clone()));
    out.set("attested", Value::Bool(attested));
    Ok(())
}

// ---- approve ----------------------------------------------------------------------------------

fn approve(args: &Args, out: &mut Outcome) -> Res {
    let file = args.file("registration approve")?;
    // Until the confirmed words are read back, nothing is committed: the run only shows what
    // approval would do, and the token stays usable.
    let Some(mut s) = setup(args, out, false)? else { return Ok(()) };
    let Some(req) = open_request(&s, file, out) else { return Ok(()) };
    let Some(sealed) = read(file, out).and_then(|b| decode_request_file(&b).ok()) else { return Ok(()) };
    let words = req.fingerprint_words();
    let Ok(Some((issued, _))) = s.store.token(&req.token) else {
        fail(out, exit::NOT_FOUND, "no-such-token", &[]);
        return Ok(());
    };
    let via = if issued.token.route == RegistrationRoute::AirGapped { Submission::Upload(issued.account.clone()) } else { Submission::Online };
    // The collector confirms the fingerprint words (REG-021); an operator approving on their
    // behalf must read the same words back.
    let confirmed = args.value("--words").is_some_and(|w| w.split(|c: char| c == '·' || c.is_whitespace()).filter(|p| !p.is_empty()).eq(words.words().iter().copied()));
    s.store.persist = confirmed;
    let outcome = with_factory(&s, out, |f, _| {
        let submitted = f.submit(&sealed, via)?;
        let mut record = submitted.tenancy;
        if record.state == TenancyState::Pending && confirmed {
            record = f.confirm(&issued.account, &record.id)?;
        }
        let cert = if record.state == TenancyState::Registered { Some(f.certificate(&record.id)?) } else { None };
        Ok::<_, fieldseal_registration::application::RegistrationError>((record, cert))
    });
    match outcome {
        Some(Ok((record, Some(cert)))) => {
            let path = args.value("--out").or_else(|| args.value("-o")).map_or_else(|| Path::new(file).with_extension("tenancy-certificate"), PathBuf::from);
            if write(&path, &cert.encode(), false, out) {
                out.lines.push(msg("tenancy-approved", &[("tenancy", &hex(record.id.as_bytes())), ("file", &path.to_string_lossy())]));
                out.set("tenancy", Value::Text(hex(record.id.as_bytes())));
                out.set("state", Value::Text("registered".into()));
                out.set("file", Value::Text(path.to_string_lossy().into_owned()));
                out.set("attested", Value::Bool(false));
                dev_marks(out);
            }
        }
        Some(Ok((record, None))) => {
            let state = format!("{:?}", record.state).to_lowercase();
            out.set("state", Value::Text(state.clone()));
            out.set("reasons", Value::Array(record.reasons.iter().cloned().map(Value::Text).collect()));
            match record.state {
                TenancyState::Pending => {
                    out.lines.push(msg("words-not-confirmed", &[("words", &words.joined())]));
                    out.fail(exit::FAILED);
                }
                _ => {
                    for r in &record.reasons {
                        out.raw_finding("REG-017", "error", file, "", r);
                    }
                    out.lines.push(msg("tenancy-not-approved", &[("state", &state)]));
                    out.fail(if record.state == TenancyState::Held { exit::FAILED } else { exit::DENIED });
                }
            }
        }
        Some(Err(e)) => refusal(out, file, &e),
        None => {}
    }
    Ok(())
}
