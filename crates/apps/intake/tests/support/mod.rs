//! A running intake app in process on ephemeral ports, with the memory-dev authority and a
//! tenancy that the factory's journal knows, plus a practice device export to upload.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use fieldseal_adapters_file::store::FileRegistryStore;
use fieldseal_adapters_memory::intake::practice::{ExportSpec, PracticeAuthority, PracticeDevice, at, manifest_for, tick};
use fieldseal_adapters_memory::trust::FixedClock;
use fieldseal_intake::wire::{AnchorKind, CertWindow, Payload};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_intake_app::config::Config;
use fieldseal_intake_app::front::BodyLimits;
use fieldseal_intake_app::{AppError, IntakeApp};
use fieldseal_registration::contract::sample_tenancy;
use fieldseal_registration::domain::TenancyState;
use fieldseal_registration::ports::RegistryStore;

static NEXT: AtomicU64 = AtomicU64::new(0);

pub fn scratch(name: &str) -> PathBuf {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("fieldseal-intake-app-{name}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// The directories one authority's intake app reads and writes.
pub struct Dirs {
    pub root: PathBuf,
}

impl Dirs {
    pub fn new(name: &str) -> Self {
        let root = scratch(name);
        for d in ["landing", "submissions", "published", "rosters", "tenancies", "export-key"] {
            std::fs::create_dir_all(root.join(d)).expect("dir");
        }
        let key = root.join("export-key/export.key");
        std::fs::write(&key, [5u8; 32]).expect("key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("mode");
        let device = PracticeDevice::new("practice-device");
        let mut t = sample_tenancy(1, "account-1");
        t.id = device.tenancy;
        t.handle = device.handle;
        t.state = TenancyState::Registered;
        t.keys[0].public_key = device.public_key();
        t.window.not_after = AuthorityTime(u64::MAX / 4);
        FileRegistryStore::open(root.join("tenancies")).expect("journal").put_tenancy(&t).expect("tenancy");
        Self { root }
    }

    pub fn p(&self, name: &str) -> String {
        self.root.join(name).display().to_string()
    }

    /// The configuration lookup for this authority; `extra` overrides or adds variables.
    pub fn env(&self, extra: &[(&str, &str)]) -> BTreeMap<String, String> {
        let mut m: BTreeMap<String, String> = [
            ("FIELDSEAL_ENVIRONMENT", "development".to_owned()),
            ("FIELDSEAL_INTAKE_BIND", "127.0.0.1:0".to_owned()),
            ("FIELDSEAL_INTAKE_PORTAL_BIND", "127.0.0.1:0".to_owned()),
            ("FIELDSEAL_INTAKE_PORTAL_URL", "http://localhost:8481".to_owned()),
            ("FIELDSEAL_IDENTITY", "dev".to_owned()),
            ("FIELDSEAL_CUSTODY", "memory-dev".to_owned()),
            ("FIELDSEAL_TENANCY_DIR", self.p("tenancies")),
            ("FIELDSEAL_LANDING_DIR", self.p("landing")),
            ("FIELDSEAL_INTAKE_SUBMISSIONS_DIR", self.p("submissions")),
            ("FIELDSEAL_INTAKE_PUBLISHED_DIR", self.p("published")),
            ("FIELDSEAL_INTAKE_ROSTERS_DIR", self.p("rosters")),
            ("FIELDSEAL_EXPORT_KEY_DIR", self.p("export-key")),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        for (k, v) in extra {
            m.insert((*k).to_owned(), (*v).to_owned());
        }
        m
    }

    pub fn config(&self, extra: &[(&str, &str)]) -> Config {
        let env = self.env(extra);
        Config::from_lookup(|k| env.get(k).cloned()).expect("a valid configuration")
    }
}

pub fn build(dirs: &Dirs) -> Result<IntakeApp, AppError> {
    IntakeApp::build_with_clock(dirs.config(&[]), Box::new(FixedClock::new(at(20))))
}

/// A practice device's export of its open and anchor records, sealed to the memory-dev
/// authority's record key (the authority `FIELDSEAL_CUSTODY=memory-dev` serves).
pub fn export() -> Vec<u8> {
    let authority = PracticeAuthority::new(7);
    let device = PracticeDevice::new("practice-device");
    let build = sha256(b"practice build");
    let mut jb = device.journal(authority.record_recipient(), authority.record_key.id);
    jb.push(&jb.open_payload(tick(build, 1), build));
    jb.push(&Payload::Anchor { tick: tick(build, 2), kind: AnchorKind::TimeToken, address: sha256(b"anchor 1"), authority_time: at(5) });
    let journal = jb.journal();
    let mut manifest = manifest_for(&device, jb.records(), &journal, build);
    manifest.certificate = Some(authority.tenancy_certificate(&device, CertWindow { not_before: at(0), not_after: at(100), grace: 30 * AuthorityTime::DAY }, &[]));
    ExportSpec { device: &device, manifest, journal, seal_to: authority.record_recipient(), key_index: 0, parity: false }.build().expect("an export")
}

/// A running app: its addresses, and a way to stop it.
pub struct Running {
    pub upload: String,
    pub portal: String,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Running {
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().expect("running").join().expect("the app thread ends");
    }
}

/// Builds the app in its own thread (its ports are not `Send`), listens and serves.
pub fn start(dirs: &Dirs) -> Result<Running, AppError> {
    start_with(dirs, &[], BodyLimits::default())
}

/// As [`start`], with extra configuration and the floors for how fast a request body must arrive.
pub fn start_with(dirs: &Dirs, extra: &[(&str, &str)], limits: BodyLimits) -> Result<Running, AppError> {
    let config = dirs.config(extra);
    let (tx, rx) = std::sync::mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let thread = std::thread::spawn(move || {
        match IntakeApp::build_with_clock(config, Box::new(FixedClock::new(at(20)))) {
            Err(e) => tx.send(Err(e)).expect("send"),
            Ok(app) => {
                let app = app.with_body_limits(limits);
                let live = app.listen().expect("listen");
                tx.send(Ok((format!("http://{}", live.upload_addr().expect("addr")), format!("http://{}", live.portal_addr().expect("addr"))))).expect("send");
                app.serve_until(&live, &flag);
            }
        }
    });
    match rx.recv().expect("the app thread reports") {
        Ok((upload, portal)) => Ok(Running { upload, portal, stop, thread: Some(thread) }),
        Err(e) => {
            thread.join().expect("ends");
            Err(e)
        }
    }
}

pub fn get(url: &str) -> (u16, String) {
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).max_redirects(0).build().into();
    let mut r = agent.get(url).call().expect("a response");
    (r.status().as_u16(), r.body_mut().read_to_string().unwrap_or_default())
}

pub fn upload(base: &str, export: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    use fieldseal_adapters_upload_http::{ClientConfig, HttpUploadTransport};
    HttpUploadTransport::new(ClientConfig { allow_http: true, ..ClientConfig::default() }).upload_outbox(base, export).map_err(|e| format!("{e:?}"))
}

pub fn exists(p: &Path) -> bool {
    p.exists()
}

/// Sends `request` (a whole HTTP/1.1 request) to `addr` and returns the status of the answer.
pub fn raw_status(addr: &str, request: &str) -> u16 {
    use std::io::{Read as _, Write as _};
    let mut stream = std::net::TcpStream::connect(addr.trim_start_matches("http://")).expect("connect");
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("timeout");
    stream.write_all(request.as_bytes()).expect("send");
    let mut answer = String::new();
    let mut buf = [0u8; 4096];
    // The head is enough: stop at the first blank line.
    while !answer.contains("\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => answer.push_str(&String::from_utf8_lossy(&buf[..n])),
        }
    }
    answer.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// A bodiless request to the portal, which only answers for the host of its public URL.
pub fn portal_request(addr: &str, method: &str, path: &str) -> u16 {
    raw_status(addr, &format!("{method} {path} HTTP/1.1\r\nHost: localhost:8481\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
}
