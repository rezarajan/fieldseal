//! The survey folder and everything that knows its shape (ADR 0041).
//!
//! ```text
//! <root>/<name>/instrument.yaml
//!              /layouts/<window>.yaml
//!              /i18n/<lang>.po
//!              /README.md
//! ```
//!
//! This is the only code that knows that shape: callers name a survey and get its documents back.
//! The module reads files and returns values. It never prints, and it never skips content without
//! returning it: a file that is none of the above comes back as a warning, a catalogue that does
//! not match the source comes back as a [`Finding`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use fieldseal_kernel::schema::SchemaErrorKind;
use fieldseal_kernel::value::Value;

use crate::compact::{self, Seen, Texts};
use crate::po::{self, EntryCatalogues, PoEntry};
use crate::spans::Spans;
use crate::{AuthoringError, ErrorKind, Format, decode_with_spans};

/// What was wrong with a survey folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolveKind {
    /// A file cannot be read; the position is 0:0 and the message names the file.
    Io,
    /// The folder has no `instrument.yaml`.
    NoInstrument,
    /// The folder name differs from `survey.name`.
    NameMismatch,
    /// A layout's file stem differs from its declared `window`.
    WindowMismatch,
    /// A titled step or card has no `id:`.
    MissingLayoutId,
    /// Two steps or cards of one layout share an `id:`.
    DuplicateLayoutId,
    /// A file in the folder is none of the expected files (a warning).
    StrayFile,
    /// A malformed `.po` file.
    PoSyntax,
    /// A repeated `msgctxt`.
    PoDuplicateContext,
    /// A `msgctxt` outside the grammar.
    PoBadContext,
    /// One of the six schema kinds, passed through when a document fails validation.
    Schema(SchemaErrorKind),
    /// A document that is not well-formed or does not expand for a reason that is not one of the
    /// six schema kinds (a syntax error, a name that resolves to nothing).
    Decode(ErrorKind),
    /// A translation finding, as an error under `--strict` ([`LoadedSurvey::strict`]).
    Translation(FindingKind),
}

impl ResolveKind {
    /// The kebab-case name used in messages and in the design.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::NoInstrument => "no-instrument",
            Self::NameMismatch => "name-mismatch",
            Self::WindowMismatch => "window-mismatch",
            Self::MissingLayoutId => "missing-layout-id",
            Self::DuplicateLayoutId => "duplicate-layout-id",
            Self::StrayFile => "stray-file",
            Self::PoSyntax => "po-syntax",
            Self::PoDuplicateContext => "po-duplicate-context",
            Self::PoBadContext => "po-bad-context",
            Self::Schema(_) => "schema",
            Self::Decode(_) => "decode",
            Self::Translation(k) => k.name(),
        }
    }
}

/// A problem in a survey folder, with where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveError {
    /// The file, relative to the survey folder (the folder for an error about the folder).
    pub file: String,
    /// An RFC 6901 JSON Pointer into the document, or the `msgctxt` for a catalogue entry; empty
    /// when the position says where.
    pub pointer: String,
    /// The line, counting from 1; 0 with no position.
    pub line: usize,
    /// The column, counting from 1; 0 with no position.
    pub column: usize,
    /// Which problem.
    pub kind: ResolveKind,
    /// A message for the author.
    pub message: String,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}: {}: {}", self.file, self.line, self.column, self.kind.name(), self.message)?;
        if !self.pointer.is_empty() {
            write!(f, " ({})", self.pointer)?;
        }
        Ok(())
    }
}

impl std::error::Error for ResolveError {}

/// What a translation finding is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingKind {
    /// A source text has no entry, or its `msgstr` is empty.
    Missing,
    /// An entry's `msgctxt` matches no source text.
    Orphaned,
    /// The entry's `msgid` differs from the current English text.
    Stale,
    /// A language is declared under `translations:` and `i18n/<lang>.po` does not exist.
    NoCatalogue,
}

impl FindingKind {
    /// The name used in messages.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Orphaned => "orphaned",
            Self::Stale => "stale",
            Self::NoCatalogue => "no-catalogue",
        }
    }
}

/// One difference between a catalogue and the source texts. All four kinds are warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Which difference.
    pub kind: FindingKind,
    /// The language of the catalogue.
    pub language: String,
    /// The `.po` file, or for a missing entry the source file; relative to the survey folder.
    pub file: String,
    /// The line in `file`; 0 when there is none.
    pub line: usize,
    /// The entry's context, or the missing text's key.
    pub msgctxt: String,
    /// For a stale entry, the English text it was written against.
    pub old_msgid: Option<String>,
    /// The current English text; none for an orphaned entry.
    pub new_text: Option<String>,
}

/// A survey, loaded: the expanded documents and what the loader noticed.
#[derive(Debug, Clone)]
pub struct LoadedSurvey {
    /// The expanded instrument, with the catalogues applied.
    pub instrument: Value,
    /// The expanded layouts by window class.
    pub layouts: Vec<(String, Value)>,
    /// Missing, orphaned and stale translations and absent catalogues.
    pub translation_report: Vec<Finding>,
    /// Files that are none of the expected files (kind [`ResolveKind::StrayFile`]).
    pub warnings: Vec<ResolveError>,
}

impl LoadedSurvey {
    /// Turns every warning and every translation finding into an error (`survey check --strict`).
    ///
    /// # Errors
    ///
    /// Every warning and finding, as [`ResolveError`]s.
    pub fn strict(self) -> Result<Self, Vec<ResolveError>> {
        let mut errors = self.warnings.clone();
        for f in &self.translation_report {
            let message = match f.kind {
                FindingKind::Missing => format!("`{}` has no `{}` translation of \"{}\"", f.msgctxt, f.language, f.new_text.as_deref().unwrap_or_default()),
                FindingKind::Orphaned => format!("`{}` matches no source text", f.msgctxt),
                FindingKind::Stale => format!("`{}` was written against \"{}\" and the text is now \"{}\"", f.msgctxt, f.old_msgid.as_deref().unwrap_or_default(), f.new_text.as_deref().unwrap_or_default()),
                FindingKind::NoCatalogue => format!("`{}` is declared under `translations:` and has no catalogue", f.language),
            };
            errors.push(ResolveError { file: f.file.clone(), pointer: f.msgctxt.clone(), line: f.line, column: usize::from(f.line > 0), kind: ResolveKind::Translation(f.kind), message });
        }
        if errors.is_empty() { Ok(self) } else { Err(errors) }
    }
}

/// A layout file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutFile {
    /// The window class: the file stem.
    pub window: String,
    /// The file.
    pub path: PathBuf,
}

/// A translation catalogue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalogue {
    /// The language: the file stem.
    pub language: String,
    /// The file.
    pub path: PathBuf,
}

/// The files of one survey folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurveyRef {
    /// The folder name.
    pub name: String,
    /// The folder.
    pub dir: PathBuf,
    /// `instrument.yaml`.
    pub instrument: PathBuf,
    /// `layouts/*.yaml`, by window class.
    pub layouts: Vec<LayoutFile>,
    /// `i18n/*.po`, by language.
    pub catalogues: Vec<Catalogue>,
    /// Files that are none of the expected files, relative to the folder.
    pub stray: Vec<PathBuf>,
}

/// The folder that holds the surveys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurveyTree {
    root: PathBuf,
    names: Vec<String>,
}

fn io_error(file: &str, e: &std::io::Error) -> ResolveError {
    ResolveError { file: file.to_owned(), pointer: String::new(), line: 0, column: 0, kind: ResolveKind::Io, message: format!("{file}: {e}") }
}

/// The names in `dir` that are directories (`dirs`) or files, sorted.
fn list(dir: &Path, display: &str) -> Result<Vec<(String, bool)>, ResolveError> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| io_error(display, &e))? {
        let entry = entry.map_err(|e| io_error(display, &e))?;
        let is_dir = entry.file_type().map_err(|e| io_error(display, &e))?.is_dir();
        out.push((entry.file_name().to_string_lossy().into_owned(), is_dir));
    }
    out.sort();
    Ok(out)
}

impl SurveyTree {
    /// Lists the survey folders under `root`. A directory whose name begins with a dot is not a
    /// survey (`<root>/.fieldseal/` holds the schemas).
    ///
    /// # Errors
    ///
    /// [`ResolveKind::Io`] when `root` cannot be read.
    pub fn open(root: &Path) -> Result<Self, ResolveError> {
        let names = list(root, &root.display().to_string())?.into_iter().filter(|(n, dir)| *dir && !n.starts_with('.')).map(|(n, _)| n).collect();
        Ok(Self { root: root.to_owned(), names })
    }

    /// The survey root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The survey folder names, sorted.
    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// The files of the survey folder `name`.
    ///
    /// # Errors
    ///
    /// [`ResolveKind::NoInstrument`] when there is no such folder or it has no `instrument.yaml`;
    /// [`ResolveKind::Io`] when it cannot be read.
    pub fn survey(&self, name: &str) -> Result<SurveyRef, ResolveError> {
        let none = |message: String| ResolveError { file: name.to_owned(), pointer: String::new(), line: 0, column: 0, kind: ResolveKind::NoInstrument, message };
        if !self.names.iter().any(|n| n == name) {
            return Err(none(format!("no survey folder `{name}` under {}", self.root.display())));
        }
        let dir = self.root.join(name);
        let mut found = SurveyRef { name: name.to_owned(), dir: dir.clone(), instrument: dir.join("instrument.yaml"), layouts: Vec::new(), catalogues: Vec::new(), stray: Vec::new() };
        let mut has_instrument = false;
        for (entry, is_dir) in list(&dir, name)? {
            match (entry.as_str(), is_dir) {
                ("instrument.yaml", false) => has_instrument = true,
                ("README.md", false) => {}
                ("layouts", true) => {
                    for (file, is_dir) in list(&dir.join("layouts"), &format!("{name}/layouts"))? {
                        match file.strip_suffix(".yaml") {
                            Some(window) if !is_dir && !window.is_empty() => found.layouts.push(LayoutFile { window: window.to_owned(), path: dir.join("layouts").join(&file) }),
                            _ => found.stray.push(Path::new("layouts").join(file)),
                        }
                    }
                }
                ("i18n", true) => {
                    for (file, is_dir) in list(&dir.join("i18n"), &format!("{name}/i18n"))? {
                        match file.strip_suffix(".po") {
                            Some(language) if !is_dir && !language.is_empty() => found.catalogues.push(Catalogue { language: language.to_owned(), path: dir.join("i18n").join(&file) }),
                            _ => found.stray.push(Path::new("i18n").join(file)),
                        }
                    }
                }
                _ => found.stray.push(PathBuf::from(entry)),
            }
        }
        if !has_instrument {
            return Err(none(format!("{name} has no instrument.yaml")));
        }
        Ok(found)
    }
}

/// The catalogues of the survey folder that `path` is in: its `instrument.yaml` or a file of its
/// `layouts/`. A file anywhere else has none. Contexts are not checked here; [`SurveyRef::load`]
/// does that.
pub(crate) fn catalogues_of(path: &Path) -> Result<EntryCatalogues, AuthoringError> {
    let parent = path.parent().unwrap_or(Path::new(""));
    let dir = if path.file_name().is_some_and(|n| n == "instrument.yaml") {
        parent
    } else if parent.file_name().is_some_and(|n| n == "layouts") && parent.parent().is_some_and(|d| d.join("instrument.yaml").is_file()) {
        parent.parent().unwrap_or(parent)
    } else {
        return Ok(EntryCatalogues::new());
    };
    let i18n = dir.join("i18n");
    let mut catalogues = EntryCatalogues::new();
    let Ok(files) = list(&i18n, &i18n.display().to_string()) else { return Ok(catalogues) };
    for (file, is_dir) in files {
        let Some(language) = file.strip_suffix(".po").filter(|l| !is_dir && !l.is_empty()) else { continue };
        let po_path = i18n.join(&file);
        let at = |e: String| AuthoringError::new(ErrorKind::Encoding, 0, 0, format!("{}: {e}", po_path.display()));
        let text = std::fs::read_to_string(&po_path).map_err(|e| at(e.to_string()))?;
        let entries = po::parse_po(&text).map_err(|e| AuthoringError::new(e.kind, e.line, e.column, format!("{}: {}", po_path.display(), e.message)))?;
        catalogues.insert(language.to_owned(), entries.into_iter().map(|e| (e.msgctxt.clone(), e)).collect());
    }
    Ok(catalogues)
}

/// Where a source text is, for the report.
struct Source {
    key: String,
    text: String,
    file: String,
    line: usize,
}

/// One decoded document of a survey and what it asked the catalogues for.
struct Doc {
    file: String,
    raw: Value,
    spans: Spans,
}

fn rel(dir: &Path, path: &Path) -> String {
    path.strip_prefix(dir).unwrap_or(path).display().to_string()
}

fn escape(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

/// The first line in `doc` where a text equal to `text` is written; 0 when there is none.
fn first_line_of(doc: &Doc, text: &str) -> usize {
    fn walk(v: &Value, pointer: &str, spans: &Spans, text: &str, best: &mut Option<crate::Position>) {
        match v {
            Value::Text(s) if s == text => {
                if let Some(at) = spans.value(pointer) {
                    *best = Some(best.map_or(at, |b| b.min(at)));
                }
            }
            Value::Array(a) => a.iter().enumerate().for_each(|(i, x)| walk(x, &format!("{pointer}/{i}"), spans, text, best)),
            Value::Map(m) => m.iter().for_each(|(k, x)| walk(x, &format!("{pointer}/{}", escape(k)), spans, text, best)),
            _ => {}
        }
    }
    let mut best = None;
    walk(&doc.raw, "", &doc.spans, text, &mut best);
    best.map_or(0, |p| p.line)
}

fn sources(doc: &Doc, seen: Vec<Seen>) -> Vec<Source> {
    seen.into_iter()
        .map(|s| {
            let line = s.pointer.as_deref().and_then(|p| doc.spans.value(p)).map_or_else(|| first_line_of(doc, &s.text), |p| p.line);
            Source { key: s.key, text: s.text, file: doc.file.clone(), line }
        })
        .collect()
}

/// From a decoder or expander error to resolver errors: one for each finding of a schema failure.
fn from_authoring(file: &str, e: &AuthoringError) -> Vec<ResolveError> {
    if e.findings.is_empty() {
        return vec![ResolveError { file: file.to_owned(), pointer: String::new(), line: e.line, column: e.column, kind: ResolveKind::Decode(e.kind), message: e.message.clone() }];
    }
    e.findings.iter().map(|f| ResolveError { file: file.to_owned(), pointer: f.pointer.clone(), line: f.position.line, column: f.position.column, kind: ResolveKind::Schema(f.kind), message: f.message.clone() }).collect()
}

fn read(dir: &Path, path: &Path) -> Result<String, ResolveError> {
    let file = rel(dir, path);
    let bytes = std::fs::read(path).map_err(|e| io_error(&file, &e))?;
    let text = std::str::from_utf8(bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes)).map_err(|_| ResolveError { file: file.clone(), pointer: String::new(), line: 1, column: 1, kind: ResolveKind::Decode(ErrorKind::Encoding), message: "the file is not valid UTF-8".to_owned() })?;
    Ok(text.to_owned())
}

fn decode(dir: &Path, path: &Path) -> Result<Doc, Vec<ResolveError>> {
    let file = rel(dir, path);
    let text = read(dir, path).map_err(|e| vec![e])?;
    let (raw, spans) = decode_with_spans(&text, Format::Yaml).map_err(|e| from_authoring(&file, &e))?;
    Ok(Doc { file, raw, spans })
}

/// The window class and the ids of a layout, checked: a step and a card each need an `id:`, and
/// ids are unique in the layout (tabs may have one).
fn check_layout_ids(doc: &Doc) -> Vec<ResolveError> {
    fn walk(v: &Value, pointer: &str, needs_id: bool, doc: &Doc, ids: &mut BTreeMap<String, String>, errors: &mut Vec<ResolveError>) {
        let Some(m) = v.as_map() else { return };
        let at = |p: &str, kind, message: String| {
            let position = doc.spans.nearest(p);
            ResolveError { file: doc.file.clone(), pointer: p.to_owned(), line: position.line, column: position.column, kind, message }
        };
        match m.get("id") {
            Some(Value::Text(id)) => {
                if let Some(first) = ids.insert(id.clone(), pointer.to_owned()) {
                    errors.push(at(&format!("{pointer}/id"), ResolveKind::DuplicateLayoutId, format!("id `{id}` is already used at {first}")));
                }
            }
            Some(_) => {}
            None if needs_id && m.contains_key("title") => errors.push(at(pointer, ResolveKind::MissingLayoutId, "a titled step or card needs an `id:`, the key of its title in the catalogues".to_owned())),
            None => {}
        }
        let items = |key: &str| m.get(key).and_then(Value::as_array).unwrap_or_default();
        for (i, c) in items("contents").iter().enumerate() {
            let p = format!("{pointer}/contents/{i}");
            if let Some(card) = c.as_map().and_then(|c| c.get("card")) {
                walk(card, &format!("{p}/card"), true, doc, ids, errors);
            }
            for (j, tab) in c.as_map().and_then(|c| c.get("tabs")).and_then(Value::as_array).unwrap_or_default().iter().enumerate() {
                walk(tab, &format!("{p}/tabs/{j}"), false, doc, ids, errors);
            }
        }
    }
    let mut errors = Vec::new();
    let mut ids = BTreeMap::new();
    let Some(steps) = doc.raw.as_map().and_then(|m| m.get("steps")).and_then(Value::as_array) else { return errors };
    for (i, step) in steps.iter().enumerate() {
        walk(step, &format!("/steps/{i}"), true, doc, &mut ids, &mut errors);
    }
    errors
}

impl SurveyRef {
    /// Reads the survey: decodes `instrument.yaml` and each layout, parses the catalogues, checks
    /// the folder rules, expands every document with the catalogues and builds the translation
    /// report. The expansion is the one `decode_path` does, with the catalogue entries of the
    /// folder, so the bytes that are hashed are the bytes the decoder makes for the same documents.
    ///
    /// # Errors
    ///
    /// Every problem found, in file order; never empty.
    pub fn load(&self) -> Result<LoadedSurvey, Vec<ResolveError>> {
        let mut errors = Vec::new();
        let instrument = decode(&self.dir, &self.instrument).map_err(|e| errors.extend(e)).ok();
        if let Some(doc) = &instrument {
            let name = doc.raw.as_map().and_then(|m| m.get("survey")).and_then(Value::as_map).and_then(|s| s.get("name")).and_then(Value::as_text);
            if let Some(name) = name
                && name != self.name
            {
                let at = doc.spans.nearest("/survey/name");
                errors.push(ResolveError { file: doc.file.clone(), pointer: "/survey/name".to_owned(), line: at.line, column: at.column, kind: ResolveKind::NameMismatch, message: format!("the folder is `{}` and survey.name is `{name}`", self.name) });
            }
        }
        let mut layouts = Vec::new();
        for l in &self.layouts {
            let Some(doc) = decode(&self.dir, &l.path).map_err(|e| errors.extend(e)).ok() else { continue };
            let window = doc.raw.as_map().and_then(|m| m.get("layout")).and_then(Value::as_map).and_then(|s| s.get("window")).and_then(Value::as_text);
            if let Some(window) = window
                && window != l.window
            {
                let at = doc.spans.nearest("/layout/window");
                errors.push(ResolveError { file: doc.file.clone(), pointer: "/layout/window".to_owned(), line: at.line, column: at.column, kind: ResolveKind::WindowMismatch, message: format!("the file is `{}.yaml` and the layout declares window `{window}`", l.window) });
            }
            errors.extend(check_layout_ids(&doc));
            layouts.push((l.window.clone(), doc));
        }
        let mut entries = EntryCatalogues::new();
        for c in &self.catalogues {
            let file = rel(&self.dir, &c.path);
            let parsed = read(&self.dir, &c.path).map_err(|e| vec![e]).and_then(|text| {
                po::parse_po(&text).map_err(|e| {
                    let kind = if e.message.ends_with(po::REPEATED) { ResolveKind::PoDuplicateContext } else { ResolveKind::PoSyntax };
                    vec![ResolveError { file: file.clone(), pointer: String::new(), line: e.line, column: e.column, kind, message: e.message }]
                })
            });
            match parsed {
                Ok(list) => {
                    for e in &list {
                        if let Err(message) = po::check_context(&e.msgctxt) {
                            errors.push(ResolveError { file: file.clone(), pointer: e.msgctxt.clone(), line: e.line, column: 1, kind: ResolveKind::PoBadContext, message });
                        }
                    }
                    entries.insert(c.language.clone(), list.into_iter().map(|e| (e.msgctxt.clone(), e)).collect());
                }
                Err(e) => errors.extend(e),
            }
        }
        let (Some(instrument), true) = (instrument, errors.is_empty()) else { return Err(errors) };

        let texts = Texts::entries(&entries);
        let mut all_sources = Vec::new();
        let expanded = compact::expand_seen(instrument.raw.clone(), &texts, Some(&instrument.spans), Some(&instrument.file));
        let instrument_value = match expanded {
            Ok((v, seen)) => {
                all_sources.extend(sources(&instrument, seen));
                Some(v)
            }
            Err(e) => {
                errors.extend(from_authoring(&instrument.file, &e));
                None
            }
        };
        let mut layout_values = Vec::new();
        for (window, doc) in &layouts {
            match compact::expand_seen(doc.raw.clone(), &texts, Some(&doc.spans), Some(&doc.file)) {
                Ok((v, seen)) => {
                    all_sources.extend(sources(doc, seen));
                    layout_values.push((window.clone(), v));
                }
                Err(e) => errors.extend(from_authoring(&doc.file, &e)),
            }
        }
        let Some(instrument_value) = instrument_value.filter(|_| errors.is_empty()) else { return Err(errors) };

        let declared = declared_languages(&instrument.raw);
        let translation_report = report(&all_sources, &declared, &entries);
        let warnings = self
            .stray
            .iter()
            .map(|p| ResolveError { file: p.display().to_string(), pointer: String::new(), line: 0, column: 0, kind: ResolveKind::StrayFile, message: format!("{} is not an instrument, a layout, a catalogue or a README, and is not read", p.display()) })
            .collect();
        Ok(LoadedSurvey { instrument: instrument_value, layouts: layout_values, translation_report, warnings })
    }
}

fn declared_languages(instrument: &Value) -> BTreeSet<String> {
    instrument.as_map().and_then(|m| m.get("translations")).and_then(Value::as_map).map(|t| t.keys().cloned().collect()).unwrap_or_default()
}

/// The translation report over every source text of a survey (instrument and layouts together, so
/// a layout entry is not an orphan of the instrument pass).
fn report(sources: &[Source], declared: &BTreeSet<String>, entries: &EntryCatalogues) -> Vec<Finding> {
    let keys: BTreeSet<&str> = sources.iter().map(|s| s.key.as_str()).collect();
    let languages: BTreeSet<&String> = entries.keys().chain(declared).collect();
    let mut out = Vec::new();
    for lang in languages {
        let file = format!("i18n/{lang}.po");
        let finding = |kind, file: &str, line, msgctxt: &str, old_msgid, new_text| Finding { kind, language: lang.clone(), file: file.to_owned(), line, msgctxt: msgctxt.to_owned(), old_msgid, new_text };
        let Some(catalogue) = entries.get(lang) else {
            out.push(finding(FindingKind::NoCatalogue, &file, 0, "", None, None));
            continue;
        };
        for s in sources {
            match catalogue.get(&s.key) {
                None => out.push(finding(FindingKind::Missing, &s.file, s.line, &s.key, None, Some(s.text.clone()))),
                Some(e) if e.msgid != s.text => out.push(finding(FindingKind::Stale, &file, e.line, &s.key, Some(e.msgid.clone()), Some(s.text.clone()))),
                Some(e) if e.msgstr.is_empty() => out.push(finding(FindingKind::Missing, &file, e.line, &s.key, None, Some(s.text.clone()))),
                Some(_) => {}
            }
        }
        let mut orphans: Vec<&PoEntry> = catalogue.values().filter(|e| !keys.contains(e.msgctxt.as_str())).collect();
        orphans.sort_by_key(|e| e.line);
        out.extend(orphans.into_iter().map(|e| finding(FindingKind::Orphaned, &file, e.line, &e.msgctxt, None, None)));
    }
    out
}

/// One roster file, read for its cohort and version and never for its file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterFile {
    /// The file.
    pub path: PathBuf,
    /// The cohort the roster names.
    pub cohort: String,
    /// The roster's version.
    pub version: u64,
}

/// The roster files directly in one directory, by cohort and version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterSet {
    files: Vec<RosterFile>,
}

impl RosterSet {
    /// Reads every `*.yaml` and `*.yml` file directly in `dir`. It does not recurse, so a
    /// subdirectory such as `examples/rosters/next/` is not listed. A survey does not name its
    /// roster; callers find a roster by cohort.
    ///
    /// # Errors
    ///
    /// Every file that cannot be read or is not a roster, or two files with one cohort and version.
    pub fn open(dir: &Path) -> Result<Self, Vec<ResolveError>> {
        let shown = dir.display().to_string();
        let mut errors = Vec::new();
        let mut files: Vec<RosterFile> = Vec::new();
        for (name, is_dir) in list(dir, &shown).map_err(|e| vec![e])? {
            if is_dir || !(name.ends_with(".yaml") || name.ends_with(".yml")) {
                continue;
            }
            let path = dir.join(&name);
            let doc = match decode(dir, &path) {
                Ok(d) => d,
                Err(e) => {
                    errors.extend(e);
                    continue;
                }
            };
            let top = doc.raw.as_map();
            let head = top.and_then(|m| m.get("roster")).and_then(Value::as_map).or(top);
            let cohort = head.and_then(|m| m.get("cohort")).and_then(Value::as_text);
            let version = head.and_then(|m| m.get("version")).and_then(Value::as_int).and_then(|v| u64::try_from(v).ok());
            let (Some(cohort), Some(version)) = (cohort, version) else {
                errors.push(ResolveError { file: name, pointer: String::new(), line: 1, column: 1, kind: ResolveKind::Decode(ErrorKind::Compact), message: "a roster names its `cohort` and a whole `version`".to_owned() });
                continue;
            };
            if let Some(other) = files.iter().find(|f| f.cohort == cohort && f.version == version) {
                errors.push(ResolveError { file: name, pointer: String::new(), line: 1, column: 1, kind: ResolveKind::Decode(ErrorKind::Compact), message: format!("cohort `{cohort}` version {version} is also in {}", other.path.display()) });
                continue;
            }
            files.push(RosterFile { path, cohort: cohort.to_owned(), version });
        }
        if errors.is_empty() { Ok(Self { files }) } else { Err(errors) }
    }

    /// Every roster file, by cohort and then version.
    #[must_use]
    pub fn files(&self) -> Vec<&RosterFile> {
        let mut v: Vec<&RosterFile> = self.files.iter().collect();
        v.sort_by(|a, b| (&a.cohort, a.version).cmp(&(&b.cohort, b.version)));
        v
    }

    /// The cohorts, sorted.
    #[must_use]
    pub fn cohorts(&self) -> Vec<&str> {
        self.files.iter().map(|f| f.cohort.as_str()).collect::<BTreeSet<_>>().into_iter().collect()
    }

    /// The highest version of `cohort`.
    #[must_use]
    pub fn latest(&self, cohort: &str) -> Option<&RosterFile> {
        self.files.iter().filter(|f| f.cohort == cohort).max_by_key(|f| f.version)
    }
}
