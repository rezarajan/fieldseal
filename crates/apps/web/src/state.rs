//! The app's shared, read-only state: where things are and which services are configured.

use std::collections::BTreeMap;
use std::path::PathBuf;

use fieldseal_adapters_web_demo::Demo;

/// What the routes need to know, set once at start-up from the environment.
#[derive(Clone, Debug, Default)]
pub struct AppState {
    /// A directory with `surveys/` (one folder for each survey) and `rosters/` (one file for
    /// each cohort and version). Files are re-read on every request, so edits show up without a
    /// restart.
    pub examples_dir: PathBuf,
    /// Which cohort's roster each survey's pages use, by survey name
    /// (`FIELDSEAL_WEB_SURVEY_COHORTS`). A survey with no entry has no roster.
    pub survey_cohorts: BTreeMap<String, String>,
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
    /// authority (`/authority`), its published artefacts (`/published`), the factory's records
    /// (`/factory-state`) and the `fieldseal` CLI to build bundles (`FIELDSEAL_WEB_CLI`).
    pub stack: Option<String>,
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
    /// The two files of the WASM bundle and whether both are present.
    pub fn wasm_available(&self) -> bool {
        self.wasm_dir.as_ref().is_some_and(|d| d.join("fieldseal_wasm.js").is_file() && d.join("fieldseal_wasm_bg.wasm").is_file())
    }
}
