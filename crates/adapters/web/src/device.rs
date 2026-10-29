//! The browser device: the Collection and Delivery contexts running on the `web` platform
//! profile (ADR 0036). Everything that matters (bundle verification in WIRE-093 order,
//! tenancy and PIN, the sealed dual write, field checks, the export, receipt verification) is
//! the same Rust the other platforms run; this module only wires the web adapters in and
//! reports what happened as JSON for the page.
//!
//! The device is **unattested software** (CLI-007, REG-017): its keys are not in hardware.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;

use fieldseal_adapters_memory::bundle_opener::FileBundleOpener;
use fieldseal_adapters_memory::delivery::{MemoryPrivateStorage, MemoryRegistrationRecords};
use fieldseal_adapters_memory::registration::reported_version;
use fieldseal_collection::application::{
    CaptureMode, CollectionError, ConsentInput, Platform, Provisioning, ReviewFilter, Runtime,
    StatusOutcome,
};
use fieldseal_collection::domain::bundle::OpenedBundle;
use fieldseal_collection::domain::{ReceiptCoverage, RuntimePin, TenancyState, WindowId};
use fieldseal_collection::ports::{BundleOpenError, BundleOpener};
use fieldseal_delivery::application::{DeliveryService, Ports};
use fieldseal_delivery::checks::{TrustReceiptCheck, TrustReceiverCheck, receipts_from_response};
use fieldseal_delivery::domain::{AddressHint, AuthorisedDestination, HintSource, POP_HEADER, ReceiverChallenge, ReceiverProof, UploadRequest, UploadRoute};
use fieldseal_delivery::ports::{UploadError, UploadTransport};
use fieldseal_distribution::domain::RuntimeProfile;
use fieldseal_instrument::domain::IMPLEMENTED_SCHEMA;
use fieldseal_instrument::domain::Instrument;
use fieldseal_instrument::domain::metadata::ConsentRequirement;
use fieldseal_kernel::Value;
use fieldseal_kernel::base64url::base64url_decode;
use fieldseal_kernel::digest::{lower_hex, sha256};
use fieldseal_kernel::id::{Digest, ItemPath, Seq, SubjectId, TenancyId};
use fieldseal_kernel::seal::SealedBox;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::domain::{Controls, PublishingPolicy, RuntimeEvaluator};
use fieldseal_publishing::application::VerifyPublication;
use fieldseal_registration::domain::wire::{RequestBody, encode_request_file, factory_sealing_key};
use fieldseal_registration::domain::{
    FingerprintWords, KeyEvidence, NonceSource, RegistrationToken, ReportedProfile,
};
use fieldseal_trust::domain::{DeviceKeyKind, TrustBundle, TrustStore};
use fieldseal_trust::ports::{SecureKeyStore, SourceRng};

use crate::json::{from_json, quote, to_json};
use crate::platform::{ArgonHash, Change, Namespace, NoShare, WebCamera, WebDevicePolicy, WebDisplay, WebDownloads, WebElapsed, WebKeyStore, WebRandom, WebStorage, WebWall};
use crate::workbench::{RenderOptions, Workbench};

/// One blocking POST: `(url, proof-of-possession header, body)` to `(status, body)`.
pub type PostFn = Rc<dyn Fn(&str, Option<&str>, &[u8]) -> Result<(u16, Vec<u8>), String>>;

/// What the page does for the device: the clock, the monotonic clock and one HTTP POST.
pub struct Host {
    /// Milliseconds since the Unix epoch.
    pub now_ms: Rc<dyn Fn() -> f64>,
    /// Milliseconds since this page load (`performance.now()`).
    pub elapsed_ms: Rc<dyn Fn() -> f64>,
    /// One blocking POST: `(url, proof-of-possession header, body)` to `(status, body)`. In
    /// the browser this is a synchronous request made from a worker.
    pub post: PostFn,
}

/// What the authority provisions the device with (DEP-024): trust and the build's identity.
pub struct Provisioned {
    /// The authority's name, for display.
    pub authority: String,
    /// The trust bundle.
    pub trust: TrustBundle,
    /// The publishing policy the publishers must meet.
    pub publishing: PublishingPolicy,
    /// The build's release anchor.
    pub build_anchor: Digest,
    /// The key records seal to before registration.
    pub provisional_record_key: [u8; 32],
    /// The factory's base URL, as the page reaches it.
    pub factory_url: String,
    /// The upload endpoint's base URL, as the page reaches it.
    pub upload_url: String,
}

impl Provisioned {
    /// Reads the provisioning JSON the authority serves (see the web-demo crate).
    pub fn from_json(text: &str) -> Result<Self, String> {
        let v = from_json(text).map_err(|e| format!("provisioning: {}:{}: {}", e.line, e.column, e.message))?;
        let m = v.as_map().ok_or("provisioning: expected an object")?;
        let text_of = |k: &str| m.get(k).and_then(Value::as_text).map(str::to_owned);
        let need = |k: &str| text_of(k).ok_or_else(|| format!("provisioning: missing `{k}`"));
        let list = |k: &str| m.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_text().map(str::to_owned)).collect::<Vec<_>>()).unwrap_or_default();
        let trust_bytes = base64url_decode(&need("trustBundle")?).map_err(|e| format!("provisioning: trustBundle: {e}"))?;
        let trust = TrustBundle::decode(&trust_bytes).map_err(|e| format!("provisioning: trust bundle: {e}"))?;
        let mut publishing = Controls::defaults().publishing();
        publishing.allowed_builders = list("allowedBuilders");
        publishing.allowed_sources = list("allowedSources");
        let hex32 = |k: &str| -> Result<[u8; 32], String> {
            let t = need(k)?;
            let b = unhex(&t).ok_or_else(|| format!("provisioning: `{k}` is not hex"))?;
            b.try_into().map_err(|_| format!("provisioning: `{k}` is not 32 bytes"))
        };
        Ok(Self {
            authority: text_of("authority").unwrap_or_default(),
            trust,
            publishing,
            build_anchor: Digest::from(hex32("buildAnchor")?),
            provisional_record_key: hex32("provisionalRecordKey")?,
            factory_url: text_of("factoryUrl").unwrap_or_default(),
            upload_url: text_of("uploadUrl").unwrap_or_default(),
        })
    }
}

/// Opens bundles for this device: the real `FSB1` verification (WIRE-090..095) against the
/// trust bundle, opened with the device's own agreement key.
pub struct WebBundleOpener {
    provisioned: &'static Provisioned,
    keys: &'static WebKeyStore,
    wall: &'static WebWall,
    tenancy: Cell<Option<TenancyId>>,
}

impl BundleOpener for WebBundleOpener {
    fn open(&self, file: &[u8]) -> Result<OpenedBundle, BundleOpenError> {
        let key = self.keys.agreement_key().ok_or_else(|| BundleOpenError::Rejected("no agreement key yet".into()))?;
        let tenancy = self.tenancy.get().ok_or_else(|| BundleOpenError::Rejected("no tenancy yet".into()))?;
        let wall = self.wall;
        let now = move || {
            AuthorityTime(fieldseal_collection::ports::WallClock::now_ms(wall).unwrap_or(0))
        };
        let profile = RuntimeProfile {
            instrument_schema: IMPLEMENTED_SCHEMA,
            localisation_reference: None,
        };
        FileBundleOpener::new(
            &self.provisioned.trust,
            &self.provisioned.publishing,
            &key,
            tenancy,
            profile,
            &now,
        )
        .open(file)
    }
}

/// The upload transport over the host's blocking POST: it asks an address to answer the
/// receiver challenge and sends uploads with a proof-of-possession token, exactly as the
/// native HTTP transport does. Addresses are untrusted hints (DEL-060).
struct BrowserTransport {
    post: PostFn,
}

impl UploadTransport for BrowserTransport {
    fn challenge(&self, address: &AddressHint, challenge: &ReceiverChallenge) -> Result<ReceiverProof, UploadError> {
        let (status, body) = (self.post)(&UploadRoute::Challenge.url(&address.address), None, &challenge.encode()).map_err(|_| UploadError::Unreachable)?;
        match status {
            200 => ReceiverProof::decode(&body).map_err(|e| UploadError::Malformed(e.to_string())),
            502..=504 => Err(UploadError::Unreachable),
            s => Err(UploadError::Rejected(format!("status {s}"))),
        }
    }

    fn upload(&self, destination: &AuthorisedDestination, request: &UploadRequest) -> Result<Vec<fieldseal_collection::domain::ReceiptClaim>, UploadError> {
        let url = request.route.url(&destination.address().address);
        let header = request.pop.as_ref().map(|p| p.to_header());
        let _ = POP_HEADER;
        let (status, body) = (self.post)(&url, header.as_deref(), &request.body).map_err(|_| UploadError::Unreachable)?;
        match status {
            200 => receipts_from_response(&body).map_err(|e| UploadError::Malformed(e.to_string())),
            401 => Err(UploadError::TokenRejected),
            502..=504 => Err(UploadError::Unreachable),
            s => Err(UploadError::Rejected(format!("status {s}: {}", String::from_utf8_lossy(&body)))),
        }
    }
}

fn unhex(t: &str) -> Option<Vec<u8>> {
    if !t.len().is_multiple_of(2) {
        return None;
    }
    (0..t.len()).step_by(2).map(|i| u8::from_str_radix(t.get(i..i + 2)?, 16).ok()).collect()
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn leak<T>(v: T) -> &'static T {
    Box::leak(Box::new(v))
}

fn state_name(s: TenancyState) -> &'static str {
    match s {
        TenancyState::Local => "local",
        TenancyState::Registered => "registered",
        TenancyState::Closing => "closing",
        TenancyState::Closed => "closed",
        TenancyState::Erased => "erased",
    }
}

fn list_json(items: &[String]) -> String {
    format!("[{}]", items.iter().map(|s| quote(s)).collect::<Vec<_>>().join(","))
}

/// A device on the `web` profile.
///
/// The adapters live for the page's lifetime (`Box::leak`): a tab holds one device, and a
/// reload builds a new one from the persisted objects.
pub struct WebDevice {
    rt: Runtime<'static>,
    provisioned: &'static Provisioned,
    storage: &'static WebStorage,
    keys: &'static WebKeyStore,
    random: &'static WebRandom,
    wall: &'static WebWall,
    downloads: &'static WebDownloads,
    opener: &'static WebBundleOpener,
    private: &'static MemoryPrivateStorage,
    records: &'static MemoryRegistrationRecords,
    policy: &'static RuntimeEvaluator,
    post: PostFn,
    now_ms: Rc<dyn Fn() -> f64>,
    coverage: Option<ReceiptCoverage>,
}

impl WebDevice {
    /// Builds the device from the authority's provisioning JSON and the objects the host
    /// persisted earlier. `boot_count` is the host's count of page loads, this one included.
    pub fn open(provisioning_json: &str, persisted: Vec<(Namespace, String, Vec<u8>)>, boot_count: u32, host: Host) -> Result<Self, String> {
        let provisioned: &'static Provisioned = leak(Provisioned::from_json(provisioning_json)?);
        let storage: &'static WebStorage = leak(WebStorage::new());
        for (ns, name, bytes) in persisted {
            storage.load(ns, &name, bytes);
        }
        let random: &'static WebRandom = leak(WebRandom);
        let keys: &'static WebKeyStore = leak(WebKeyStore::open(storage, random));
        let now = host.now_ms.clone();
        let wall: &'static WebWall = leak(WebWall::new(move || now()));
        let elapsed = host.elapsed_ms.clone();
        let clock: &'static WebElapsed = leak(WebElapsed::new(move || elapsed(), boot_count));
        let display: &'static WebDisplay = leak(WebDisplay::default());
        let device: &'static WebDevicePolicy = leak(WebDevicePolicy);
        let camera: &'static WebCamera = leak(WebCamera);
        let hash: &'static ArgonHash = leak(ArgonHash);
        let opener: &'static WebBundleOpener = leak(WebBundleOpener { provisioned, keys, wall, tenancy: Cell::new(None) });
        let windows: &'static [WindowId] = leak(vec![WindowId("capture".into()), WindowId("review".into()), WindowId("delivery".into())]).as_slice();
        let platform = Platform { keys, attestor: keys, clock, wall, storage, display, device, camera, hash, random, bundles: opener };
        let provisioning = Provisioning {
            trust: &provisioned.trust,
            publishing: &provisioned.publishing,
            build_anchor: provisioned.build_anchor,
            provisional_record_key: provisioned.provisional_record_key,
            windows,
        };
        let rt = Runtime::load(platform, provisioning).map_err(err)?;
        opener.tenancy.set(rt.tenancy());
        keys.set_locked(true);
        let policy: &'static RuntimeEvaluator = leak(RuntimeEvaluator::from_effective(&fieldseal_policy::fixtures::effective_default()).map_err(|f| format!("runtime policy: {f:?}"))?);
        Ok(Self {
            rt,
            provisioned,
            storage,
            keys,
            random,
            wall,
            downloads: leak(WebDownloads::default()),
            opener,
            private: leak(MemoryPrivateStorage::new()),
            records: leak(MemoryRegistrationRecords::new()),
            policy,
            post: host.post,
            now_ms: host.now_ms,
            coverage: None,
        })
    }

    /// The changes to persist since the last call.
    pub fn drain_changes(&self) -> Vec<Change> {
        self.storage.drain_changes()
    }

    /// Files written to the download destination since the last call.
    pub fn take_downloads(&self) -> Vec<(String, Vec<u8>)> {
        self.downloads.take()
    }

    /// The provisioning, for the page to show.
    pub fn provisioned(&self) -> &Provisioned {
        self.provisioned
    }

    /// The device's state as JSON.
    pub fn state_json(&mut self) -> String {
        let tenancy = self.rt.tenancy().map(|t| lower_hex(t.as_bytes()));
        let state = self.rt.state().map(state_name);
        let held = self.rt.held().map(|h| {
            let subjects: usize = h.rosters.iter().map(|r| r.subjects.len()).sum();
            format!("{{\"practice\":{},\"rosters\":{},\"subjects\":{},\"layouts\":{}}}", h.is_practice(), h.rosters.len(), subjects, h.layouts.len())
        });
        let posture = self.rt.posture_findings().into_iter().map(|(r, s)| format!("{{\"restriction\":{},\"state\":{}}}", quote(&r), quote(&s))).collect::<Vec<_>>().join(",");
        format!(
            "{{\"tenancy\":{},\"state\":{},\"unlocked\":{},\"bundle\":{},\"keys\":{},\"unattested\":true,\"authority\":{},\"posture\":[{posture}]}}",
            tenancy.map_or("null".into(), |t| quote(&t)),
            state.map_or("null".into(), quote),
            self.rt.is_unlocked(),
            held.unwrap_or_else(|| "null".into()),
            self.keys.key_count(),
            quote(&self.provisioned.authority),
        )
    }

    /// Creates the tenancy, protected by `pin` (COL-001, COL-020).
    pub fn create_tenancy(&mut self, pin: &str) -> Result<String, String> {
        let pin = RuntimePin::new(pin).map_err(err)?;
        self.keys.set_locked(false);
        if let Err(e) = self.rt.create_tenancy(&pin) {
            self.keys.set_locked(true);
            return Err(err(e));
        }
        self.opener.tenancy.set(self.rt.tenancy());
        Ok(self.state_json())
    }

    /// Opens a session with `pin` (COL-022, COL-023).
    pub fn unlock(&mut self, pin: &str) -> Result<String, String> {
        let pin = RuntimePin::new(pin).map_err(err)?;
        self.opener.tenancy.set(self.rt.tenancy());
        self.keys.set_locked(false);
        if let Err(e) = self.rt.open_session(&pin) {
            self.keys.set_locked(true);
            return Err(err(e));
        }
        Ok(self.state_json())
    }

    /// Locks the session.
    pub fn lock(&mut self) {
        self.rt.lock("collector");
        self.keys.set_locked(true);
    }

    /// Builds the sealed registration request for a token (WIRE-130..134): the request body
    /// from the runtime's own keys, the proof of possession signed in the key store, sealed to
    /// the factory's registration key. Returns the request file, the four words to compare with
    /// the portal, and the tenancy.
    pub fn registration_request(&mut self, token_text: &str, label: &str) -> Result<RegistrationRequest, String> {
        let token = RegistrationToken::from_text(token_text.trim()).map_err(|e| format!("the token is not readable: {e}"))?;
        token.verify(&self.provisioned.trust).map_err(|e| format!("the token does not verify against the trust bundle (REG-010): {e}"))?;
        let sign_pub = self.rt.key_history().into_iter().next().ok_or("create the tenancy before registering")?;
        let agree_pub = self.keys.agreement_public().ok_or("the device has no agreement key yet")?;
        let software = |kind, key: &fieldseal_kernel::crypto::P256PublicKey| crate::platform::software_evidence(kind, true, &token.nonce, key);
        let body = RequestBody {
            token: token.secret,
            nonce: token.nonce,
            nonce_source: NonceSource::Factory,
            sign_pub: sign_pub.clone(),
            agree_pub: agree_pub.clone(),
            evidence: vec![
                KeyEvidence { kind: DeviceKeyKind::Signing, evidence: software(DeviceKeyKind::Signing, &sign_pub) },
                KeyEvidence { kind: DeviceKeyKind::Agreement, evidence: software(DeviceKeyKind::Agreement, &agree_pub) },
            ],
            build: "fieldseal-web/0.1.0".into(),
            prev_closing: None,
            label: Some(label.to_owned()),
            // The schema version this device opens bundles with (`WebBundleOpener`, the same constant); no catalogue.
            profile: ReportedProfile {
                instrument_schema: reported_version(IMPLEMENTED_SCHEMA),
                catalogue_reference: None,
            },
        };
        let handle = self.keys.signing_handle(&sign_pub).ok_or("the signing key is not in the key store")?;
        let pop = self.keys.sign(&handle, &body.pop_message()).map_err(err)?;
        let factory = factory_sealing_key(&self.provisioned.trust, token.issued_at).ok_or("the trust bundle certifies no registration key")?;
        let sealed: SealedBox = body.seal(&mut SourceRng(self.random), &factory, &pop, None).map_err(err)?;
        let words = FingerprintWords::from_body_digest(&body.digest());
        Ok(RegistrationRequest { file: encode_request_file(&sealed), words: words.joined(), tenancy: lower_hex(TenancyId::from(*sha256(sign_pub.as_bytes()).as_bytes()).as_bytes()), sign_pub: lower_hex(sign_pub.as_bytes()), agree_pub: lower_hex(agree_pub.as_bytes()) })
    }

    /// Verifies a bundle step by step and imports it. The report lists each security step and
    /// what it found, in the order of WIRE-093 and DIS-030: the file and its signature and
    /// seal (the opener), then every publication it carries through the publishing context
    /// (signatures against the threshold, the reviewers, the log inclusion proofs).
    pub fn import_bundle(&mut self, file: &[u8]) -> Result<String, String> {
        self.opener.tenancy.set(self.rt.tenancy());
        let opened = self.opener.open(file).map_err(|e| format!("bundle rejected: {e}"))?;
        let mut steps: Vec<String> = Vec::new();
        let step = |name: &str, ok: bool, detail: String| format!("{{\"step\":{},\"ok\":{ok},\"detail\":{}}}", quote(name), quote(&detail));
        steps.push(step("envelope", true, format!("{} bytes; factory signature verified against the trust bundle; sealed to this device's agreement key and opened (WIRE-090..093)", file.len())));
        let verify = VerifyPublication::new(TrustStore::new(&self.provisioned.trust), &self.provisioned.publishing);
        let mut publications: Vec<String> = Vec::new();
        let all = std::iter::once(&opened.instrument).chain(opened.layouts.iter()).chain(opened.policy.iter());
        for p in all {
            let st = p.provenance.statement();
            match verify.verify(p, &opened.withdrawals) {
                Ok(v) => {
                    let threshold = self.provisioned.publishing.kinds.get(st.kind.as_str()).map_or(0, |k| k.publisher_threshold.m);
                    let line = format!(
                        "{} {} {}: {} publisher signatures verified (threshold {}), {} reviewer(s), {} log inclusion proof(s) against checkpoint of {} entries",
                        st.kind.as_str(),
                        st.name,
                        st.version,
                        v.signers.len(),
                        threshold,
                        st.reviewers.len(),
                        p.log.len(),
                        p.checkpoint.size()
                    );
                    steps.push(step("publication", true, line));
                    publications.push(format!(
                        "{{\"kind\":{},\"name\":{},\"version\":{},\"signatures\":{},\"threshold\":{threshold},\"reviewers\":{},\"logProofs\":{},\"checkpointSize\":{},\"address\":{}}}",
                        quote(st.kind.as_str()),
                        quote(&st.name),
                        quote(&st.version),
                        v.signers.len(),
                        st.reviewers.len(),
                        p.log.len(),
                        p.checkpoint.size(),
                        quote(&p.address().to_text())
                    ));
                }
                Err(e) => {
                    steps.push(step("publication", false, format!("{} {} {}: {e}", st.kind.as_str(), st.name, st.version)));
                    return Err(format!("publication did not verify: {e}"));
                }
            }
        }
        self.rt.import_bundle(file).map_err(err)?;
        steps.push(step("import", true, format!("the instrument, {} layout(s) and {} roster(s) validated and held; tenancy {}", opened.layouts.len(), opened.rosters.len(), self.rt.state().map_or("?", state_name))));
        Ok(format!("{{\"ok\":true,\"steps\":[{}],\"publications\":[{}],\"state\":{}}}", steps.join(","), publications.join(","), self.state_json()))
    }

    fn held_workbench(&self) -> Result<Workbench, String> {
        let h = self.rt.held().ok_or("no bundle is held")?;
        Ok(Workbench::from_parts(h.instrument.clone(), h.layouts.to_vec()))
    }

    /// Describes the held instrument for the page: its name, languages, subjects and consent
    /// bases.
    pub fn held_json(&self) -> Result<String, String> {
        let h = self.rt.held().ok_or("no bundle is held")?;
        let consent = match &h.instrument.definition().consent {
            ConsentRequirement::NotRequired => "{\"required\":false}".to_owned(),
            ConsentRequirement::Required { bases, statement, .. } => format!(
                "{{\"required\":true,\"statementVersion\":{},\"bases\":[{}]}}",
                statement.version,
                bases.iter().map(|b| quote(&b.code)).collect::<Vec<_>>().join(",")
            ),
        };
        let mut rosters = Vec::new();
        for r in &h.rosters {
            let subjects = r
                .subjects
                .iter()
                .map(|s| {
                    let display = s.display.iter().map(|(k, v)| format!("{}:{}", quote(k), quote(v))).collect::<Vec<_>>().join(",");
                    format!("{{\"subject\":{},\"consent\":{},\"display\":{{{display}}}}}", quote(s.subject.as_str()), quote(&format!("{:?}", s.consent).to_lowercase()))
                })
                .collect::<Vec<_>>()
                .join(",");
            rosters.push(format!("{{\"cohort\":{},\"version\":{},\"subjects\":[{subjects}]}}", quote(r.cohort.as_str()), r.version));
        }
        Ok(format!("{{\"fingerprint\":{},\"layouts\":{},\"consent\":{consent},\"rosters\":[{}]}}", quote(&lower_hex(h.fingerprint.as_bytes())), h.layouts.len(), rosters.join(",")))
    }

    /// Draws the held instrument for the collector (the same render as `instrument preview`),
    /// with the capture's current values when one is open.
    pub fn render(&mut self, options: &RenderOptions, values: Option<&BTreeMap<String, Value>>, roster: Option<&BTreeMap<String, Value>>) -> Result<String, String> {
        self.held_workbench()?.render(options, values, roster, true).map(|r| r.html)
    }

    /// Evaluates the held instrument's rules over `values` (live checks while typing).
    pub fn evaluate(&mut self, options: &RenderOptions, values: &BTreeMap<String, Value>, roster: &BTreeMap<String, Value>) -> Result<String, String> {
        self.held_workbench()?.evaluate_json(options, values, roster)
    }

    /// The roster fields of a subject, for rendering `$roster.<field>`.
    pub fn roster_fields(&self, subject: &str) -> Result<BTreeMap<String, Value>, String> {
        let s = SubjectId::new(subject).map_err(err)?;
        let h = self.rt.held().ok_or("no bundle is held")?;
        let (_, entry) = h.subject(&s).ok_or("the subject is not on a held roster")?;
        Ok(entry.fields())
    }

    /// Records consent for a subject (COL-040).
    pub fn record_consent(&mut self, subject: &str, basis: &str, statement_version: u32) -> Result<String, String> {
        let s = SubjectId::new(subject).map_err(err)?;
        let seq = self.rt.record_consent(&s, &ConsentInput { basis: basis.to_owned(), statement_version, capture_evidence: false }).map_err(err)?;
        Ok(format!("{{\"seq\":{}}}", seq.0))
    }

    /// Records that a subject was absent, declined or was not the expected person.
    pub fn record_status(&mut self, subject: &str, outcome: &str) -> Result<String, String> {
        let s = SubjectId::new(subject).map_err(err)?;
        let o = match outcome {
            "absent" => StatusOutcome::Absent,
            "declines" => StatusOutcome::Declines,
            "not-them" => StatusOutcome::NotThem,
            other => return Err(format!("unknown outcome {other}")),
        };
        let seq = self.rt.record_status(&s, o).map_err(err)?;
        Ok(format!("{{\"seq\":{}}}", seq.0))
    }

    fn capture_json(&self, v: &fieldseal_collection::application::CaptureView) -> String {
        let values: BTreeMap<String, Value> = v.values.clone();
        format!(
            "{{\"subject\":{},\"mode\":{},\"values\":{},\"hard\":{},\"soft\":{},\"unanswered\":{},\"step\":{}}}",
            quote(v.subject.as_str()),
            quote(v.mode.as_str()),
            to_json(&Value::Map(values)),
            list_json(&v.hard),
            list_json(&v.soft),
            list_json(&v.unanswered),
            v.step
        )
    }

    /// Starts a capture about `subject` (`first`, `resume`, `resurvey` or `correction`).
    pub fn start_capture(&mut self, subject: &str, mode: &str) -> Result<String, String> {
        let s = SubjectId::new(subject).map_err(err)?;
        let m = match mode {
            "first" => CaptureMode::First,
            "resume" => CaptureMode::Resume,
            "resurvey" => CaptureMode::Resurvey,
            "correction" => CaptureMode::Correction,
            other => return Err(format!("unknown mode {other}")),
        };
        let v = self.rt.start_capture(&s, m).map_err(|e| match e {
            CollectionError::ConsentNeeded => "consent_needed".to_owned(),
            other => other.to_string(),
        })?;
        Ok(self.capture_json(&v))
    }

    /// Sets answers from a JSON object of item path to value (a nonresponse is `{"nr":"refused"}`);
    /// `null`-free: a path mapped to `{"clear":true}` is cleared. Sets what can be set in
    /// rounds, because answering one question can make another editable. Returns the capture
    /// view with the core's verdicts.
    pub fn set_values(&mut self, values_json: &str) -> Result<String, String> {
        let map = match from_json(values_json) {
            Ok(Value::Map(m)) => m,
            Ok(_) => return Err("expected a JSON object".into()),
            Err(e) => return Err(format!("{}:{}: {}", e.line, e.column, e.message)),
        };
        let mut pending: Vec<(String, Value)> = map.into_iter().collect();
        let mut problems: Vec<String> = Vec::new();
        while !pending.is_empty() {
            let mut left = Vec::new();
            for (p, v) in pending.iter() {
                let path = ItemPath::new(p.as_str()).map_err(|e| format!("{p}: {e}"))?;
                let result = if v.as_map().and_then(|m| m.get("clear")) == Some(&Value::Bool(true)) { self.rt.clear_value(&path) } else { self.rt.set_value(&path, v.clone()) };
                match result {
                    Ok(()) => {}
                    Err(CollectionError::NotEditable(_)) => left.push((p.clone(), v.clone())),
                    Err(e) => problems.push(format!("{p}: {e}")),
                }
            }
            if left.len() == pending.len() {
                problems.extend(left.iter().map(|(p, _)| format!("{p}: not editable now")));
                break;
            }
            pending = left;
        }
        let v = self.rt.capture_view().map_err(err)?;
        Ok(format!("{{\"view\":{},\"problems\":{}}}", self.capture_json(&v), list_json(&problems)))
    }

    /// Keeps a soft verdict with a reason (COL-035).
    pub fn override_soft(&mut self, rule: &str, reason: &str) -> Result<(), String> {
        self.rt.override_soft(rule, reason).map_err(err)
    }

    /// Acknowledges the unanswered items (COL-036).
    pub fn acknowledge_incomplete(&mut self, count: usize) -> Result<(), String> {
        self.rt.acknowledge_incomplete(count).map_err(err)
    }

    /// Seals the open capture: the dual write of the journal and the local record (COL §4).
    pub fn seal(&mut self) -> Result<String, String> {
        let seq = self.rt.seal().map_err(err)?;
        Ok(format!("{{\"seq\":{}}}", seq.0))
    }

    /// Discards the open capture.
    pub fn discard_capture(&mut self) {
        self.rt.discard_capture();
    }

    /// The review (COL-060): every subject's current answers, unanswered counts, kept soft
    /// verdicts, records and delivery states, and the field checks raised.
    pub fn review(&mut self) -> Result<String, String> {
        let r = self.rt.review(&ReviewFilter::default()).map_err(err)?;
        let subjects = r
            .subjects
            .iter()
            .map(|s| {
                let records = s.records.iter().map(|x| format!("{{\"seq\":{},\"kind\":{},\"mode\":{},\"delivery\":{}}}", x.seq.0, quote(x.kind), x.mode.map_or("null".into(), quote), quote(&format!("{:?}", x.delivery)))).collect::<Vec<_>>().join(",");
                format!(
                    "{{\"cohort\":{},\"subject\":{},\"current\":{},\"unanswered\":{},\"keptSoft\":{},\"status\":{},\"records\":[{records}]}}",
                    s.cohort.as_ref().map_or("null".into(), |c| quote(c.as_str())),
                    quote(s.subject.as_str()),
                    to_json(&Value::Map(s.current.clone())),
                    s.unanswered,
                    to_json(&Value::Map(s.kept_soft.iter().map(|(k, v)| (k.clone(), Value::Text(v.clone()))).collect())),
                    s.status.map_or("null".into(), |x| quote(x.as_str())),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let checks = r.checks.iter().map(|c| format!("{{\"check\":{},\"subjects\":{}}}", quote(&c.check), list_json(&c.subjects.iter().map(|s| s.as_str().to_owned()).collect::<Vec<_>>()))).collect::<Vec<_>>().join(",");
        Ok(format!("{{\"subjects\":[{subjects}],\"checks\":[{checks}],\"cleared\":{{\"delivered\":{},\"awaiting\":{}}}}}", r.cleared.delivered, r.cleared.awaiting))
    }

    fn delivery(&self) -> (TrustReceiverCheck<'static>, TrustReceiptCheck<'static>) {
        let now = AuthorityTime(fieldseal_collection::ports::WallClock::now_ms(self.wall).unwrap_or(0));
        (TrustReceiverCheck::new(TrustStore::new(&self.provisioned.trust), now), TrustReceiptCheck::new(TrustStore::new(&self.provisioned.trust)))
    }

    /// Builds the export of everything sealed so far, verifies it (parity on unless `parity`
    /// is false) and offers it as a download. Returns what was built.
    pub fn export(&mut self, parity: bool) -> Result<String, String> {
        let (receiver, receipts) = self.delivery();
        let transport = BrowserTransport { post: self.post.clone() };
        let mut svc = DeliveryService::new(
            Ports { keys: self.keys, random: self.random, wall: self.wall, transport: &transport, receiver: &receiver, receipts: &receipts, files: self.downloads, share: &NoShare, storage: self.private, records: self.records },
            self.policy,
        );
        let export = svc.build_export(&mut self.rt, Some(parity)).map_err(|e| e.to_string())?;
        let handle = fieldseal_delivery::ports::FileAccess::pick_destination(self.downloads).map_err(err)?;
        let attempt = svc.deliver_file(&mut self.rt, &export, &handle).map_err(|e| e.to_string())?;
        Ok(format!(
            "{{\"name\":{},\"records\":{},\"from\":{},\"through\":{},\"parity\":{},\"size\":{},\"label\":{}}}",
            quote(&export.name),
            export.records,
            export.from.0,
            export.through.0,
            export.parity,
            export.size,
            quote(attempt.label.text())
        ))
    }

    /// Uploads to the endpoint: the receiver challenge (the endpoint proves its key against the
    /// trust bundle, DEL-062), the proof-of-possession token, the upload, and the receipt,
    /// which is verified against the trust bundle before it is applied (DEL-064).
    pub fn upload(&mut self, address: &str) -> Result<String, String> {
        let (receiver, receipts) = self.delivery();
        let transport = BrowserTransport { post: self.post.clone() };
        let mut svc = DeliveryService::new(
            Ports { keys: self.keys, random: self.random, wall: self.wall, transport: &transport, receiver: &receiver, receipts: &receipts, files: self.downloads, share: &NoShare, storage: self.private, records: self.records },
            self.policy,
        );
        let hints = [AddressHint { address: address.to_owned(), source: HintSource::DeviceConfiguration }];
        let r = svc.upload(&mut self.rt, &hints).map_err(|e| e.to_string())?;
        self.coverage = Some(r.coverage.clone());
        let _ = &self.now_ms;
        Ok(format!(
            "{{\"label\":{},\"coveredThrough\":{},\"journalDeleted\":{},\"offerClearThrough\":{},\"receiptVerified\":true,\"endpoint\":\"receiver challenge answered by a receiver key that chains to the trust root\"}}",
            quote(r.attempt.label.text()),
            r.covered_through.0,
            r.receipt.journal_deleted,
            r.receipt.offer_clear_through.map_or("null".into(), |s| s.0.to_string()),
        ))
    }

    /// Reads a receipt from a file and verifies it against the trust bundle (DEL-064), then
    /// applies it.
    pub fn import_receipt(&mut self, bytes: &[u8]) -> Result<String, String> {
        let (receiver, receipts) = self.delivery();
        let transport = BrowserTransport { post: self.post.clone() };
        let mut svc = DeliveryService::new(
            Ports { keys: self.keys, random: self.random, wall: self.wall, transport: &transport, receiver: &receiver, receipts: &receipts, files: self.downloads, share: &NoShare, storage: self.private, records: self.records },
            self.policy,
        );
        let o = svc.import_receipt(&mut self.rt, bytes).map_err(|e| e.to_string())?;
        Ok(format!("{{\"journalDeleted\":{},\"offerClearThrough\":{}}}", o.journal_deleted, o.offer_clear_through.map_or("null".into(), |s| s.0.to_string())))
    }

    /// What a clear through `through` would do, to show before the PIN is asked twice (COL-100).
    pub fn clear_preview(&mut self, through: u64) -> Result<String, String> {
        let p = self.rt.clear_preview(Seq(through)).map_err(err)?;
        Ok(format!("{{\"through\":{},\"records\":{},\"notReceived\":{},\"statement\":{}}}", p.through.0, p.records, p.not_received, quote(p.statement)))
    }

    /// Clears the local record through `through`, confirmed by the PIN entered twice
    /// (ADR 0029); journal frames are deleted only under a verified receipt.
    pub fn clear(&mut self, through: u64, first: &str, second: &str) -> Result<String, String> {
        let a = RuntimePin::new(first).map_err(err)?;
        let b = RuntimePin::new(second).map_err(err)?;
        let c = self.rt.clear(Seq(through), &a, &b, self.coverage.as_ref()).map_err(err)?;
        Ok(format!("{{\"checkpoint\":{},\"localDeleted\":{},\"journalDeleted\":{},\"journalKept\":{}}}", c.checkpoint.0, c.local_deleted, c.journal_deleted, c.journal_kept))
    }

    /// The highest `seq` sealed so far (what an export covers).
    pub fn last_seq(&self) -> Result<u64, String> {
        let report = fieldseal_kernel::record::read_journal(&self.rt.journal().map_err(err)?, &self.rt.key_history(), &self.rt.checkpoints());
        Ok(report.entries.iter().map(|e| e.record.header.seq).max().unwrap_or(0))
    }

    /// Public keys for the CLI's `bundle build` (`device.txt`): signing and agreement keys, hex.
    pub fn public_keys_json(&self) -> String {
        let sign = self.rt.key_history().into_iter().next().map_or("null".into(), |k| quote(&lower_hex(k.as_bytes())));
        let agree = self.keys.agreement_public().map_or("null".into(), |k| quote(&lower_hex(k.as_bytes())));
        format!("{{\"signing\":{sign},\"agreement\":{agree}}}")
    }

    /// Deletes everything this device holds from the host's store: tenancy, keys, journal.
    /// (A new device must be created afterwards.)
    pub fn erase_all(&self) -> Vec<Change> {
        let mut out = Vec::new();
        for (ns, name, _) in self.storage.sizes() {
            self.storage.remove(ns, &name);
            out.push(Change { namespace: ns, name, bytes: None });
        }
        out
    }
}

/// A registration request ready to send.
pub struct RegistrationRequest {
    /// The `FSRQ` request file (the online route accepts it as the POST body).
    pub file: Vec<u8>,
    /// The four words to compare with the portal (REG-020).
    pub words: String,
    /// The tenancy ID (lower-case hex), to poll the status.
    pub tenancy: String,
    /// The signing public key (hex).
    pub sign_pub: String,
    /// The agreement public key (hex).
    pub agree_pub: String,
}

/// An `Instrument` re-exported for hosts that render one directly.
pub type HeldInstrument = Instrument;
