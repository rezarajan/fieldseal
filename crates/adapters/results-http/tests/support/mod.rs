//! A reader over a real landing directory, a real signed publication and an export key.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use fieldseal_adapters_landing_files::FileDataPlatform;
use fieldseal_adapters_landing_files::export::ExportKey;
use fieldseal_adapters_memory::demo::DemoWorld;
use fieldseal_adapters_memory::registration::MemoryIdentityProvider;
use fieldseal_adapters_memory::trust::FixedClock;
use fieldseal_adapters_portal::{PortalSessions, Request, Response};
use fieldseal_adapters_results_http::{DEFAULT_CSP, ResultsConfig, ResultsHttp};
use fieldseal_intake::contract::sample_observation;
use fieldseal_intake::domain::{ObservedValue, Reading};
use fieldseal_intake::ports::{DataPlatform, LandingBatch};
use fieldseal_kernel::cbor;
use fieldseal_kernel::id::{Fingerprint, ItemPath, RecordId, SubjectId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_publishing::domain::ArtefactKind;
use fieldseal_registration::domain::MethodAssurance;

pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn scratch(name: &str) -> PathBuf {
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("fieldseal-results-{name}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

pub struct World {
    pub dir: PathBuf,
    pub landing: PathBuf,
    pub published: PathBuf,
    pub key_file: PathBuf,
    pub world: DemoWorld,
    pub fingerprint: Fingerprint,
    pub idp: MemoryIdentityProvider,
    pub clock: FixedClock,
}

/// The two logins: `reader` (role, passkey) and `collector` (no role, passkey), plus `weak`
/// (role, password only).
pub fn idp() -> MemoryIdentityProvider {
    let idp = MemoryIdentityProvider::new();
    idp.add("reader", "dev|reader", &["collector", "results-reader"], &["hwk"], MethodAssurance::FromProvider);
    idp.add("collector", "dev|collector", &["collector"], &["hwk"], MethodAssurance::FromProvider);
    idp.add("weak", "dev|weak", &["results-reader"], &["pwd"], MethodAssurance::FromProvider);
    idp
}

pub fn world(name: &str) -> World {
    let dir = scratch(name);
    let (landing, published) = (dir.join("landing"), dir.join("published"));
    std::fs::create_dir_all(&published).expect("published");
    let t0 = AuthorityTime(1_800_000_000_000);
    let demo = DemoWorld::new(7, t0).expect("a demo world");
    let doc = fieldseal_adapters_authoring::decode_path(&repo().join("examples/surveys/household-water-access")).expect("the survey decodes");
    let publication = demo.publish(ArtefactKind::Instrument, "household-water-access", "1.0.0", cbor::encode(&doc).expect("encodes"), Some(DemoWorld::salt_for("household-water-access"))).expect("published");
    std::fs::write(published.join("water.published"), publication.encode()).expect("write publication");
    let fingerprint = publication.artefact.fingerprint().expect("an instrument has a fingerprint");
    let key_file = dir.join("export.key");
    std::fs::write(&key_file, [9u8; 32]).expect("key");
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).expect("mode");
    land(&landing, fingerprint, 3);
    World { dir, landing, published, key_file, world: demo, fingerprint, idp: idp(), clock: FixedClock::new(t0) }
}

/// Lands `n` answered rows (record ids 1 to `n`) under the fingerprint.
pub fn land(dir: &Path, fingerprint: Fingerprint, n: u8) {
    let platform = FileDataPlatform::new(dir).expect("landing directory");
    let observations = (1..=n)
        .map(|r| {
            let mut o = sample_observation(1, r);
            o.instrument = fingerprint;
            o.subject = SubjectId::new("hh-0001").expect("subject");
            o.item = ItemPath::new("water.liters").expect("item");
            o.value_type = "integer";
            o.reading = Reading::Value(ObservedValue::Int(i64::from(r) * 10 - 20));
            o.unit = None;
            o
        })
        .collect();
    platform.land(&LandingBatch { observations, exclusions: vec![(RecordId::from([1; 16]), "consent refused".into())], ..LandingBatch::default() }).expect("land");
}

pub fn config(w: &World) -> ResultsConfig {
    ResultsConfig {
        landing_dir: w.landing.clone(),
        published_dir: w.published.clone(),
        trust: w.world.trust.clone(),
        policy: w.world.publishing.clone(),
        reader_role: "results-reader".into(),
        require_phishing_resistant: true,
        public_url: "http://localhost:8481".into(),
        csp: DEFAULT_CSP.into(),
        development_adapters: vec![],
        replay_gap: 0,
    }
}

pub fn reader<'a>(w: &'a World, cfg: ResultsConfig) -> ResultsHttp<'a> {
    ResultsHttp::new(PortalSessions::new("fs_intake_session", false, 3_600_000), &w.idp, ExportKey::load_file(&w.key_file).expect("key"), &w.clock, cfg)
}

pub fn get(path: &str, cookie: Option<&str>) -> Request {
    let mut headers = BTreeMap::from([("host".to_owned(), "localhost:8481".to_owned())]);
    if let Some(c) = cookie {
        headers.insert("cookie".to_owned(), c.to_owned());
    }
    Request::new("GET", path, headers, vec![])
}

pub fn post(path: &str, cookie: &str, form: &str) -> Request {
    let headers = BTreeMap::from([("cookie".to_owned(), cookie.to_owned()), ("host".to_owned(), "localhost:8481".to_owned())]);
    Request::new("POST", path, headers, form.as_bytes().to_vec())
}

pub fn header<'r>(r: &'r Response, name: &str) -> Option<&'r str> {
    r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// The `name=value` pair of the pre-auth cookie that `/sign-in` sets, as the browser sends it back.
pub fn pre_auth_pair(start: &Response) -> String {
    header(start, "Set-Cookie").expect("a pre-auth cookie").split(';').next().expect("name=value").to_owned()
}

/// Signs in as `login` and returns the `Cookie` header value of the new session.
pub fn sign_in(h: &ResultsHttp<'_>, w: &World, login: &str) -> String {
    w.idp.set_default(Some(login));
    let start = h.handle(&get("/sign-in", None));
    assert_eq!(start.status, 302);
    let location = header(&start, "Location").expect("a redirect").to_owned();
    let target = location.strip_prefix("http://localhost:8481").expect("back to the portal");
    let done = h.handle(&get(target, Some(&pre_auth_pair(&start))));
    assert_eq!(done.status, 302, "{}", String::from_utf8_lossy(&done.body));
    let set = header(&done, "Set-Cookie").expect("a cookie");
    set.split(';').next().expect("name=value").to_owned()
}

pub fn text(r: &Response) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}
