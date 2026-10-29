//! The surveys found in the examples directory and the layouts that belong to each.
//!
//! Surveys are read through the resolver (`<dir>/surveys/<name>/`). Everything is read from disk
//! on every call, so edits to the files show up. A survey that fails to resolve or validate is
//! still listed, with its findings.

use std::path::Path;

use fieldseal_adapters_authoring::survey::{RosterSet, SurveyTree};
use fieldseal_adapters_authoring::Format;
use fieldseal_adapters_file::roster_store::RosterStore;
use fieldseal_adapters_web::workbench::{LoadError, Workbench};
use fieldseal_distribution::domain::{ConsentState, Roster};
use fieldseal_instrument::domain::WindowClass;
use fieldseal_kernel::id::CohortId;

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
    load_all(&state.examples_dir).into_iter().map(|e| remember(state, e)).collect()
}

/// Like [`load`], with the last-good cache of [`load_all_cached`].
pub fn load_cached(state: &AppState, id: &str) -> Option<Entry> {
    load(&state.examples_dir, id).map(|e| remember(state, e))
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

/// The rosters the pages can use: the files of `<dir>/rosters`, or the factory's roster store.
struct Rosters {
    files: Option<RosterSet>,
    /// `Some` when `FIELDSEAL_WEB_ROSTER_DIR` is set: the store, `None` inside when the directory
    /// does not exist yet, or why it cannot be read.
    store: Option<Result<Option<RosterStore>, String>>,
}

impl Rosters {
    fn open(dir: &Path, roster_dir: Option<&Path>) -> Self {
        // The stand-in only reads: it opens a directory that exists (the store would create one,
        // owner-only) and never makes one. The factory creates it when it issues the first roster.
        let store = roster_dir.map(|d| if d.is_dir() { RosterStore::open(d).map(Some).map_err(|e| e.to_string()) } else { Ok(None) });
        Self { files: if store.is_some() { None } else { RosterSet::open(&dir.join("rosters")).ok() }, store }
    }

    fn for_cohort(&self, cohort: Option<&str>) -> Result<RosterPage, String> {
        match &self.store {
            None => match cohort.and_then(|c| self.files.as_ref()?.latest(c)) {
                Some(f) => file_counts(&f.path).map(RosterPage::Counts),
                None => Ok(RosterPage::Empty),
            },
            Some(Err(e)) => Err(e.clone()),
            Some(Ok(store)) => {
                let latest = cohort.zip(store.as_ref()).map(|(c, store)| CohortId::new(c).map_err(|e| e.to_string()).and_then(|c| store.latest(&c).map_err(|e| e.to_string())));
                Ok(latest.transpose()?.flatten().map_or(RosterPage::Empty, |r| RosterPage::Counts(counts(&r))))
            }
        }
    }
}

/// What the roster page answers for a cohort.
pub enum RosterPage {
    /// The cohort has no roster, or none was named: `{}`.
    Empty,
    /// The cohort, the version and counts, never a name, a subject or a field value.
    Counts(String),
}

/// The roster page's answer for `cohort`, the cohort the device's assignment names (the bundle
/// it holds links each survey to a cohort, WIRE-094). The latest roster in `<dir>/rosters`, or,
/// with `roster_dir` (`FIELDSEAL_WEB_ROSTER_DIR`), the latest in the factory's roster store there.
pub fn roster_page(state: &AppState, cohort: Option<&str>) -> Result<RosterPage, String> {
    Rosters::open(&state.examples_dir, state.roster_dir.as_deref()).for_cohort(cohort)
}

/// The roster page's answer for a stored roster: counts, not people.
fn counts(roster: &Roster) -> String {
    let n = |state: ConsentState| roster.entries.iter().filter(|e| e.consent == state).count();
    counts_json(roster.cohort.as_str(), roster.version, roster.entries.len(), [n(ConsentState::Granted), n(ConsentState::Refused), n(ConsentState::Unknown)])
}

fn counts_json(cohort: &str, version: u64, subjects: usize, [granted, refused, unknown]: [usize; 3]) -> String {
    format!("{{\"cohort\":{},\"version\":{version},\"subjects\":{subjects},\"granted\":{granted},\"refused\":{refused},\"unknown\":{unknown}}}", fieldseal_adapters_web::json::quote(cohort))
}

/// The same counts for an examples roster file, which is read as a document: its names and
/// fields are not passed on.
fn file_counts(path: &Path) -> Result<String, String> {
    let doc = fieldseal_adapters_authoring::decode_path(path).map_err(|e| e.message)?;
    let top = doc.as_map().ok_or("the roster is not a map")?;
    let head = top.get("roster").and_then(|v| v.as_map()).unwrap_or(top);
    let cohort = head.get("cohort").and_then(|v| v.as_text()).ok_or("the roster names no cohort")?;
    let version = head.get("version").and_then(|v| v.as_int()).and_then(|v| u64::try_from(v).ok()).ok_or("the roster names no version")?;
    let subjects = head.get("subjects").and_then(|v| v.as_array()).unwrap_or_default();
    let n = |state: &str| subjects.iter().filter(|s| s.as_map().and_then(|m| m.get("consent")).and_then(|c| c.as_text()).unwrap_or("unknown") == state).count();
    Ok(counts_json(cohort, version, subjects.len(), [n("granted"), n("refused"), n("unknown")]))
}

/// Loads every survey in `<dir>/surveys`.
pub fn load_all(dir: &Path) -> Vec<Entry> {
    let Ok(tree) = SurveyTree::open(&dir.join("surveys")) else { return Vec::new() };
    tree.names().iter().map(|name| load_one(&tree, name)).collect()
}

/// Loads the survey `id`.
pub fn load(dir: &Path, id: &str) -> Option<Entry> {
    let tree = SurveyTree::open(&dir.join("surveys")).ok()?;
    tree.names().iter().any(|n| n == id).then(|| load_one(&tree, id))
}

fn load_one(tree: &SurveyTree, id: &str) -> Entry {
    let mut entry = Entry { id: id.to_owned(), source: Vec::new(), format: Format::Json, status: Err(Vec::new()), layouts: Vec::new(), layout_errors: Vec::new(), current_errors: None };
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

#[cfg(test)]
mod tests {
    use super::counts_json;

    // covers: DIS-081
    #[test]
    fn a_cohort_name_is_escaped_in_the_counts() {
        let json = counts_json("a\"b\\c", 1, 2, [1, 0, 1]);
        assert!(json.starts_with(r#"{"cohort":"a\"b\\c","#), "{json}");
    }
}
