//! The app's shared, read-only state: where things are and which services are configured.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fieldseal_adapters_web_demo::Demo;

use crate::catalogue::Entry;

/// What the routes need to know, set once at start-up from the environment.
#[derive(Clone, Debug, Default)]
pub struct AppState {
    /// A directory with `surveys/` (one folder for each survey) and `rosters/` (one file for
    /// each cohort and version). Files are re-read on every request, so edits show up without a
    /// restart.
    pub examples_dir: PathBuf,
    /// The last version of each survey that loaded, by survey name. A load that fails leaves it
    /// alone; the pages show it beside the error. It lives in memory only.
    pub last_good: Arc<Mutex<BTreeMap<String, Entry>>>,
    /// Which cohort's roster each survey's pages use, by survey name
    /// (`FIELDSEAL_WEB_SURVEY_COHORTS`). A survey with no entry has no roster.
    pub survey_cohorts: BTreeMap<String, String>,
    /// The factory's roster store (`FIELDSEAL_WEB_ROSTER_DIR`), read only. When set, the roster
    /// page takes the survey's cohort from `survey_cohorts` and reads that cohort's latest stored
    /// version here; when unset it reads `rosters/` of `examples_dir`.
    pub roster_dir: Option<PathBuf>,
    /// The directory with `fieldseal_wasm.js` and `fieldseal_wasm_bg.wasm`, if configured.
    pub wasm_dir: Option<PathBuf>,
    /// The factory's base URL, for links and the registration proxy.
    pub factory_url: Option<String>,
    /// The intake upload endpoint's base URL.
    pub upload_url: Option<String>,
    /// The transparency log's base URL.
    pub log_url: Option<String>,
    /// This app's own public URL.
    pub public_url: Option<String>,
    /// The embedded demo authority (`FIELDSEAL_WEB_DEMO_AUTHORITY=true`): a practice factory,
    /// intake and transparency log over in-memory ports, so the app works standalone.
    pub demo: Option<DemoHandle>,
    /// A provisioning document (see the Device page) for use against another authority.
    pub provisioning_file: Option<PathBuf>,
    /// Stack mode (`FIELDSEAL_WEB_STACK=true`): a service of the compose stack, using its
    /// authority (`/authority`) and its published artefacts (`/published`). The device gets its
    /// bundle from the factory.
    pub stack: bool,
    /// Stack mode: the authority's directory (`FIELDSEAL_WEB_AUTHORITY_DIR`, default `/authority`).
    pub authority_dir: Option<PathBuf>,
    /// Stack mode: the directory of the `*.published` files (`FIELDSEAL_WEB_PUBLISHED_DIR`,
    /// default `/published`).
    pub published_dir: Option<PathBuf>,
    /// Stack mode: the CLI's artefact registry, the directory of `*.publication` files that the
    /// Publishing page lists (`FIELDSEAL_WEB_REGISTRY_DIR`, default none).
    pub registry_dir: Option<PathBuf>,
    /// The builders the device's publishing policy accepts (`FIELDSEAL_WEB_ALLOWED_BUILDERS`,
    /// comma separated), copied from the intake app's configuration.
    pub allowed_builders: Vec<String>,
    /// The sources the device's publishing policy accepts (`FIELDSEAL_WEB_ALLOWED_SOURCES`).
    pub allowed_sources: Vec<String>,
}

/// The demo authority, as a cheap copyable handle.
#[derive(Clone, Copy)]
pub struct DemoHandle(pub &'static Demo);

impl std::fmt::Debug for DemoHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DemoHandle")
    }
}

impl AppState {
    /// The authority's directory in stack mode.
    pub fn authority(&self) -> PathBuf {
        self.authority_dir.clone().unwrap_or_else(|| PathBuf::from("/authority"))
    }

    /// The directory of the published artefacts in stack mode.
    pub fn published(&self) -> PathBuf {
        self.published_dir.clone().unwrap_or_else(|| PathBuf::from("/published"))
    }

    /// The two files of the WASM bundle and whether both are present.
    pub fn wasm_available(&self) -> bool {
        self.wasm_dir.as_ref().is_some_and(|d| d.join("fieldseal_wasm.js").is_file() && d.join("fieldseal_wasm_bg.wasm").is_file())
    }
}
