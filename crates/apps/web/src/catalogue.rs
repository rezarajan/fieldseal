//! The instruments found in the examples directory and the layouts that belong to each.
//!
//! Everything is read from disk on every call, so edits to the files show up. An instrument
//! that fails validation is still listed, with its findings.

use std::path::{Path, PathBuf};

use fieldseal_adapters_authoring::{Format, decode};
use fieldseal_adapters_web::workbench::{LoadError, Workbench};
use fieldseal_instrument::domain::WindowClass;
use fieldseal_kernel::Value;

/// A layout that belongs to an instrument and validated against it.
#[derive(Clone, Debug)]
pub struct LayoutFile {
    /// The file stem.
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

/// One instrument file.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The file stem; the id in URLs.
    pub id: String,
    /// The document.
    pub source: Vec<u8>,
    /// Its syntax.
    pub format: Format,
    /// The summary, or the error findings.
    pub status: Result<Summary, Vec<String>>,
    /// The layouts that bind to this instrument and validate.
    pub layouts: Vec<LayoutFile>,
    /// Layouts that bind to this instrument but do not validate: file name and findings.
    pub layout_errors: Vec<(String, Vec<String>)>,
    /// The roster file, if any.
    pub roster: Option<PathBuf>,
}

fn format_of(path: &Path) -> Option<Format> {
    Format::from_extension(path.extension()?.to_str()?)
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.is_file() && format_of(p).is_some()).collect();
    v.sort();
    v
}

/// The `spec.instrument` source path of a layout document.
fn instrument_ref(source: &[u8], format: Format) -> Option<String> {
    let doc = decode(source, format).ok()?;
    let spec = doc.as_map()?.get("spec")?;
    spec.as_map()?.get("instrument").and_then(Value::as_text).map(str::to_owned)
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

/// Loads every instrument in `<dir>/instruments`.
pub fn load_all(dir: &Path) -> Vec<Entry> {
    let layout_files = files(&dir.join("layouts"));
    files(&dir.join("instruments")).into_iter().filter_map(|path| load_one(dir, &path, &layout_files)).collect()
}

/// Loads the instrument `id`.
pub fn load(dir: &Path, id: &str) -> Option<Entry> {
    let layout_files = files(&dir.join("layouts"));
    files(&dir.join("instruments")).into_iter().find(|p| p.file_stem().and_then(|s| s.to_str()) == Some(id)).and_then(|p| load_one(dir, &p, &layout_files))
}

fn load_one(dir: &Path, path: &Path, layout_files: &[PathBuf]) -> Option<Entry> {
    let id = path.file_stem()?.to_str()?.to_owned();
    let mut format = format_of(path)?;
    let mut source = std::fs::read(path).ok()?;
    // A compact survey (ADR 0040) is expanded with its i18n/<lang>.po catalogues; the workbench
    // reads the canonical document it expands to.
    if fieldseal_adapters_authoring::decode_raw(&source, format).is_ok_and(|v| fieldseal_adapters_authoring::compact::is_compact(&v)) {
        let expanded = fieldseal_adapters_authoring::decode_path(path).ok()?;
        source = fieldseal_adapters_web::json::to_json(&expanded).into_bytes();
        format = Format::Json;
    }
    let canonical_path = path.canonicalize().ok();
    let mut entry = Entry { id: id.clone(), source, format, status: Err(Vec::new()), layouts: Vec::new(), layout_errors: Vec::new(), roster: None };
    entry.roster = ["yaml", "yml", "json"].iter().map(|e| dir.join("rosters").join(format!("{id}.{e}"))).find(|p| p.is_file());

    let mut paired: Vec<(String, Vec<u8>, Format)> = Vec::new();
    for lf in layout_files {
        let (Some(mut fmt), Ok(mut bytes)) = (format_of(lf), std::fs::read(lf)) else { continue };
        // A compact layout (ADR 0040) is expanded with its catalogues, like a compact survey.
        if fieldseal_adapters_authoring::decode_raw(&bytes, fmt).is_ok_and(|v| fieldseal_adapters_authoring::compact::is_compact(&v)) {
            let Ok(expanded) = fieldseal_adapters_authoring::decode_path(lf) else { continue };
            bytes = fieldseal_adapters_web::json::to_json(&expanded).into_bytes();
            fmt = Format::Json;
        }
        let Some(reference) = instrument_ref(&bytes, fmt) else { continue };
        let target = lf.parent().unwrap_or(Path::new("")).join(reference).canonicalize().ok();
        if target.is_some() && target == canonical_path {
            paired.push((lf.file_stem().and_then(|s| s.to_str()).unwrap_or("layout").to_owned(), bytes, fmt));
        }
    }

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
    Some(entry)
}
