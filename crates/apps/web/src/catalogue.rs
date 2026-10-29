//! The surveys found in the examples directory and the layouts that belong to each.
//!
//! Surveys are read through the resolver (`<dir>/surveys/<name>/`). Everything is read from disk
//! on every call, so edits to the files show up. A survey that fails to resolve or validate is
//! still listed, with its findings.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fieldseal_adapters_authoring::survey::{RosterSet, SurveyTree};
use fieldseal_adapters_authoring::Format;
use fieldseal_adapters_web::workbench::{LoadError, Workbench};
use fieldseal_instrument::domain::WindowClass;

use crate::state::AppState;

/// A layout that belongs to an instrument and validated against it.
#[derive(Clone, Debug)]
pub struct LayoutFile {
    /// The window class, which is the file stem.
    pub name: String,
    /// The document.
    pub source: Vec<u8>,
    /// Its syntax.
    pub format: Format,
    /// The window class it declares.
    pub window: Option<WindowClass>,
    /// Its content address.
    pub address: String,
}

/// What a valid instrument looks like from outside.
#[derive(Clone, Debug)]
pub struct Summary {
    /// `metadata.name`.
    pub name: String,
    /// `metadata.version`.
    pub version: String,
    /// The declared languages.
    pub languages: Vec<String>,
    /// The default language.
    pub default_language: String,
    /// The number of elements of the compiled tree.
    pub elements: usize,
    /// Validation warnings, formatted.
    pub warnings: Vec<String>,
    /// Lints, formatted.
    pub lints: Vec<String>,
    /// The content address, `sha256:...`.
    pub address: String,
}

/// One survey.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The survey folder name; the id in URLs.
    pub id: String,
    /// The document.
    pub source: Vec<u8>,
    /// Its syntax.
    pub format: Format,
    /// The summary, or the error findings.
    pub status: Result<Summary, Vec<String>>,
    /// The survey's layouts that validate.
    pub layouts: Vec<LayoutFile>,
    /// The survey's layouts that do not validate: window class and findings.
    pub layout_errors: Vec<(String, Vec<String>)>,
    /// The latest roster of the survey's cohort, if the survey has a cohort and the cohort a roster.
    pub roster: Option<PathBuf>,
    /// Set when the survey on disk fails to load but an earlier version loaded: the other fields
    /// are that last good version, and this holds the findings of the file as it is now.
    pub current_errors: Option<Vec<String>>,
}

impl Entry {
    /// A workbench for this instrument with the layouts at `only` (indices into
    /// [`Entry::layouts`]) added, in that order.
    pub fn workbench(&self, only: &[usize]) -> Result<Workbench, LoadError> {
        let mut bench = Workbench::load(&self.source, self.format)?;
        let identity = bench.identity();
        for &i in only {
            let l = self.layouts.get(i).ok_or_else(|| LoadError { messages: vec![format!("no layout {i}")] })?;
            bench.add_layout(&l.source, l.format, &|_| Some(identity))?;
        }
        Ok(bench)
    }

    /// The indices of every layout.
    pub fn all_layouts(&self) -> Vec<usize> {
        (0..self.layouts.len()).collect()
    }
}

/// Like [`load_all`], keeping the last good version of each survey in `state` and showing it,
/// with the findings of the file as it is now, when the survey no longer loads.
pub fn load_all_cached(state: &AppState) -> Vec<Entry> {
    load_all(&state.examples_dir, &state.survey_cohorts).into_iter().map(|e| remember(state, e)).collect()
}

/// Like [`load`], with the last-good cache of [`load_all_cached`].
pub fn load_cached(state: &AppState, id: &str) -> Option<Entry> {
    load(&state.examples_dir, id, &state.survey_cohorts).map(|e| remember(state, e))
}

/// A good load replaces the cache; a failed one leaves it alone and is shown beside it.
fn remember(state: &AppState, entry: Entry) -> Entry {
    let Ok(mut cache) = state.last_good.lock() else { return entry };
    match &entry.status {
        Ok(_) => {
            cache.insert(entry.id.clone(), entry.clone());
            entry
        }
        Err(errors) => match cache.get(&entry.id) {
            Some(good) => Entry { current_errors: Some(errors.clone()), ..good.clone() },
            None => entry,
        },
    }
}

/// Loads every survey in `<dir>/surveys`. `cohorts` maps a survey name to the cohort whose roster
/// its pages use (`FIELDSEAL_WEB_SURVEY_COHORTS`); a survey with no entry has no roster.
pub fn load_all(dir: &Path, cohorts: &BTreeMap<String, String>) -> Vec<Entry> {
    let Ok(tree) = SurveyTree::open(&dir.join("surveys")) else { return Vec::new() };
    let rosters = RosterSet::open(&dir.join("rosters")).ok();
    tree.names().iter().map(|name| load_one(&tree, name, rosters.as_ref(), cohorts)).collect()
}

/// Loads the survey `id`.
pub fn load(dir: &Path, id: &str, cohorts: &BTreeMap<String, String>) -> Option<Entry> {
    let tree = SurveyTree::open(&dir.join("surveys")).ok()?;
    let rosters = RosterSet::open(&dir.join("rosters")).ok();
    tree.names().iter().any(|n| n == id).then(|| load_one(&tree, id, rosters.as_ref(), cohorts))
}

fn load_one(tree: &SurveyTree, id: &str, rosters: Option<&RosterSet>, cohorts: &BTreeMap<String, String>) -> Entry {
    let roster = cohorts.get(id).and_then(|cohort| rosters?.latest(cohort)).map(|f| f.path.clone());
    let mut entry = Entry { id: id.to_owned(), source: Vec::new(), format: Format::Json, status: Err(Vec::new()), layouts: Vec::new(), layout_errors: Vec::new(), roster, current_errors: None };
    let loaded = match tree.survey(id).map_err(|e| vec![e]).and_then(|survey| survey.load()) {
        Ok(loaded) => loaded,
        Err(errors) => {
            entry.status = Err(errors.iter().map(ToString::to_string).collect());
            return entry;
        }
    };
    // The workbench reads the canonical documents the survey expands to.
    entry.source = fieldseal_adapters_web::json::to_json(&loaded.instrument).into_bytes();
    let paired: Vec<(String, Vec<u8>, Format)> = loaded.layouts.iter().map(|(window, v)| (window.clone(), fieldseal_adapters_web::json::to_json(v).into_bytes(), Format::Json)).collect();

    match Workbench::load(&entry.source, entry.format) {
        Err(e) => {
            entry.status = Err(e.messages);
            // Without a valid instrument no layout can be checked; list them as unchecked.
            entry.layout_errors = paired.into_iter().map(|(n, _, _)| (n, vec!["not checked: the instrument is invalid".to_owned()])).collect();
        }
        Ok(mut bench) => {
            let identity = bench.identity();
            for (name, bytes, fmt) in paired {
                match bench.add_layout(&bytes, fmt, &|_| Some(identity)) {
                    Ok(i) => {
                        let (layout, address) = &bench.layouts()[i];
                        entry.layouts.push(LayoutFile { name, source: bytes, format: fmt, window: layout.window_class(), address: address.to_text() });
                    }
                    Err(e) => entry.layout_errors.push((name, e.messages)),
                }
            }
            let def = bench.instrument().definition();
            entry.status = Ok(Summary {
                name: def.name.clone(),
                version: def.version.to_string(),
                languages: def.languages.languages.iter().map(|l| l.as_str().to_owned()).collect(),
                default_language: def.languages.default.as_str().to_owned(),
                elements: bench.instrument().compiled().nodes().len(),
                warnings: bench.warnings().iter().map(|f| f.to_string()).collect(),
                lints: bench.lints().iter().map(|f| f.to_string()).collect(),
                address: bench.address().to_text(),
            });
        }
    }
    entry
}
