//! The results export: the landed long format as an analysis-ready, versioned table, written
//! as JSON Lines and CSV with a data contract, a codebook and a manifest (INT-085 to INT-088,
//! Technical Plan §6).
//!
//! The CLI (`fieldseal intake results`) and the results reader call the same functions, so
//! their files are identical byte for byte.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fieldseal_adapters_file::atomic::write_atomic;
use fieldseal_intake::data_contract::DataContract;
use fieldseal_intake::domain::{LandedObservation, ObservedValue, Reading};
use fieldseal_intake::ports::DataPlatformError;
use fieldseal_kernel::digest::{lower_hex, sha256};
use fieldseal_kernel::id::{ContentAddress, Fingerprint};
use fieldseal_kernel::payload::Layout;

pub mod codebook;
pub mod manifest;
pub mod pseudonym;
pub mod reader;
pub mod writers;

pub use pseudonym::{ExportKey, ExportKeyError, IdentitySubject, KeyedSubject, SubjectMapper, key_id};

/// Why an export could not be built or written.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// The landing could not be read.
    #[error("{0}")]
    Platform(#[from] DataPlatformError),
    /// A file or directory could not be read or written.
    #[error("{0}")]
    Io(String),
    /// An instrument has landed rows but the published directory has no verified publication
    /// of it, so there is no contract to export it under.
    #[error("instrument {0} has landed data but no verified publication of it is in the published directory")]
    NoPublication(String),
    /// A landed row does not fit its instrument's data type.
    #[error("{0}")]
    Row(String),
}

fn io(path: &Path, e: std::io::Error) -> ExportError {
    ExportError::Io(format!("{}: {e}", path.display()))
}

/// A file format of the export.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Format {
    /// `results.jsonl` and `free_text.jsonl`.
    Jsonl,
    /// `results.csv` and `free_text.csv`.
    Csv,
}

/// What to write.
pub struct ExportOptions {
    /// The formats of the results and free-text files; the codebook, contracts and manifest
    /// are always written.
    pub formats: BTreeSet<Format>,
    /// The mapper whose key id the manifest records. It is the mapper the table was built with.
    pub subject: Box<dyn SubjectMapper>,
}

/// The one typed column an answered row fills (INT-085).
pub(crate) enum Typed {
    None,
    Number(String),
    Text(String),
    Date(String),
    Bool(bool),
    Codes(Vec<String>),
}

/// One row of `results.jsonl` and `results.csv`, with its subject already mapped.
pub(crate) struct Row {
    pub instrument: String,
    pub layout: String,
    pub lang: Vec<String>,
    pub subject: String,
    pub item_path: String,
    pub typed: Typed,
    pub value_type: &'static str,
    pub nonresponse: &'static str,
    pub retracted: bool,
    pub unit: Option<String>,
    pub record_id: String,
    pub tenancy: String,
    pub generation: u32,
    pub seq: u64,
    pub tick_lower_bound: Option<u64>,
    pub received_at: u64,
    pub consent_basis: String,
    pub flags: Vec<String>,
    /// The row as JSON Lines text; the last key of the row order.
    pub json: String,
}

/// One row of the free-text files.
pub(crate) struct FreeText {
    pub record_id: String,
    pub item_path: String,
    pub value_text: String,
}

/// The landed rows, ready to write: excluded rows left out and counted, typed columns filled,
/// subjects mapped, free text set apart, rows in their total order.
pub struct ExportTable {
    rows: Vec<Row>,
    free_text: Vec<FreeText>,
    omitted_excluded: u64,
    landing_mark: u64,
    contracts: BTreeMap<Fingerprint, DataContract>,
    instruments: BTreeMap<Fingerprint, ContentAddress>,
    layouts: BTreeSet<String>,
}

fn row_of(l: &LandedObservation, mapper: &dyn SubjectMapper) -> Result<(Row, Option<FreeText>), ExportError> {
    let o = &l.observation;
    let record_id = lower_hex(o.source.as_bytes());
    let mut free = None;
    let (typed, nonresponse) = match &o.reading {
        Reading::Value(v) => {
            let typed = match (o.value_type, v) {
                ("integer", ObservedValue::Int(i)) => Typed::Number(i.to_string()),
                ("decimal" | "money", ObservedValue::Decimal(t)) => Typed::Number(t.clone()),
                ("string", ObservedValue::Text(t)) => {
                    free = Some(FreeText { record_id: record_id.clone(), item_path: o.item.as_str().to_owned(), value_text: t.clone() });
                    Typed::None
                }
                ("code", ObservedValue::Code(t)) | ("evidence", ObservedValue::Text(t)) => Typed::Text(t.clone()),
                ("codes", ObservedValue::Codes(c)) => Typed::Codes(c.clone()),
                ("boolean", ObservedValue::Bool(b)) => Typed::Bool(*b),
                ("date", ObservedValue::Text(t)) => Typed::Date(t.clone()),
                _ => return Err(ExportError::Row(format!("record {record_id}, item {}: the value does not fit the type {}", o.item.as_str(), o.value_type))),
            };
            (typed, "")
        }
        Reading::Nonresponse(n) => (Typed::None, n.code()),
        Reading::Retracted => (Typed::None, ""),
    };
    let mut row = Row {
        instrument: lower_hex(o.instrument.as_bytes()),
        layout: match o.layout {
            Layout::Default => "default".to_owned(),
            Layout::Published(a) => lower_hex(a.as_bytes()),
        },
        lang: o.lang.clone(),
        subject: mapper.map(o.subject.as_str()),
        item_path: o.item.as_str().to_owned(),
        typed,
        value_type: o.value_type,
        nonresponse,
        retracted: matches!(o.reading, Reading::Retracted),
        unit: o.unit.clone(),
        record_id,
        tenancy: lower_hex(o.tenancy.as_bytes()),
        generation: o.generation.0,
        seq: o.seq.0,
        tick_lower_bound: o.not_before.map(|t| t.0),
        received_at: o.not_after.0,
        consent_basis: o.consent_basis.clone(),
        flags: o.flags.iter().cloned().collect(),
        json: String::new(),
    };
    row.json = writers::jsonl_row(&row);
    Ok((row, free))
}

impl ExportTable {
    /// Builds the table from every row of a landing snapshot and the data contract of each
    /// instrument in it. Rows with `excluded` set are left out of every file and counted; the
    /// landing mark is the number of rows given, excluded ones included (INT-085, INT-086).
    pub fn from_observations(
        rows: Vec<LandedObservation>,
        contracts: BTreeMap<Fingerprint, DataContract>,
        mapper: &dyn SubjectMapper,
    ) -> Result<Self, ExportError> {
        let landing_mark = rows.len() as u64;
        for fp in rows.iter().map(|r| r.observation.instrument).collect::<BTreeSet<_>>() {
            if !contracts.contains_key(&fp) {
                return Err(ExportError::NoPublication(lower_hex(fp.as_bytes())));
            }
        }
        let (mut out, mut free_text, mut omitted_excluded) = (Vec::new(), Vec::new(), 0);
        for l in &rows {
            if l.excluded.is_some() {
                omitted_excluded += 1;
                continue;
            }
            let (row, free) = row_of(l, mapper)?;
            out.push(row);
            free_text.extend(free);
        }
        let key = |r: &Row| (r.instrument.clone(), r.tenancy.clone(), r.seq, r.record_id.clone(), r.item_path.clone(), r.retracted, r.lang.clone());
        out.sort_by(|a, b| key(a).cmp(&key(b)).then_with(|| a.json.as_bytes().cmp(b.json.as_bytes())));
        free_text.sort_by(|a, b| {
            (&a.record_id, &a.item_path).cmp(&(&b.record_id, &b.item_path)).then_with(|| codebook::free_text_jsonl(a).as_bytes().cmp(codebook::free_text_jsonl(b).as_bytes()))
        });
        let present: BTreeSet<Fingerprint> = rows.iter().map(|r| r.observation.instrument).collect();
        let contracts = contracts.into_iter().filter(|(fp, _)| present.contains(fp)).collect();
        Ok(Self { rows: out, free_text, omitted_excluded, landing_mark, contracts, instruments: BTreeMap::new(), layouts: BTreeSet::new() })
    }

    /// Records the publications the manifest names: the address of each instrument's
    /// publication, and the addresses of the layouts bound to them.
    #[must_use]
    pub fn with_publications(mut self, instruments: BTreeMap<Fingerprint, ContentAddress>, layouts: impl IntoIterator<Item = ContentAddress>) -> Self {
        self.instruments = instruments;
        self.layouts = layouts.into_iter().map(|a| a.to_text()).collect();
        self
    }

    /// The number of rows in the landing snapshot this table was built from.
    pub fn landing_mark(&self) -> u64 {
        self.landing_mark
    }

    /// The number of rows written to the results files.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// The number of rows left out because they are excluded.
    pub fn omitted_excluded(&self) -> u64 {
        self.omitted_excluded
    }
}

/// One file of an export.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExportedFile {
    /// The path under the output directory.
    pub name: String,
    /// The SHA-256 of the file, in lower-case hex.
    pub sha256: String,
    /// The size in bytes.
    pub bytes: u64,
    /// The data rows of a JSON Lines or CSV file; `None` for a contract.
    pub rows: Option<u64>,
}

/// What an export wrote.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExportResult {
    /// The files, ascending by name; the manifest is not among them.
    pub files: Vec<ExportedFile>,
    /// The SHA-256 of `manifest.json`, in lower-case hex.
    pub manifest_sha256: String,
}

fn lines(rows: impl Iterator<Item = String>, header: Option<&str>) -> Vec<u8> {
    let mut out = String::new();
    if let Some(h) = header {
        out.push_str(h);
        out.push('\n');
    }
    for r in rows {
        out.push_str(&r);
        out.push('\n');
    }
    out.into_bytes()
}

/// An export built in memory: every file's bytes, as `write_export` would write them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RenderedExport {
    /// Each file by its path under the output directory, ascending by name, with
    /// `manifest.json` last.
    pub files: Vec<(String, Vec<u8>)>,
    /// What the export holds, as `write_export` returns it.
    pub result: ExportResult,
}

/// Builds the export in memory: `results.*` and `free_text.*` in the chosen formats,
/// `codebook.csv`, `contracts/<fingerprint hex>.json` and `manifest.json`. Nothing is written.
/// `write_export` writes exactly these bytes, so the CLI and the results reader agree.
pub fn render_export(table: &ExportTable, options: &ExportOptions) -> Result<RenderedExport, ExportError> {
    let mut files: Vec<(String, Vec<u8>, Option<u64>)> = Vec::new();
    let (n, f) = (table.rows.len() as u64, table.free_text.len() as u64);
    if options.formats.contains(&Format::Jsonl) {
        files.push(("results.jsonl".into(), lines(table.rows.iter().map(|r| r.json.clone()), None), Some(n)));
        files.push(("free_text.jsonl".into(), lines(table.free_text.iter().map(codebook::free_text_jsonl), None), Some(f)));
    }
    if options.formats.contains(&Format::Csv) {
        files.push(("results.csv".into(), lines(table.rows.iter().map(writers::csv_row), Some(&writers::long_header())), Some(n)));
        files.push(("free_text.csv".into(), lines(table.free_text.iter().map(codebook::free_text_csv), Some(codebook::FREE_TEXT_HEADER)), Some(f)));
    }
    let codebook_rows: Vec<String> = table.contracts.values().flat_map(codebook::codebook_rows).collect();
    let codebook_count = codebook_rows.len() as u64;
    files.push(("codebook.csv".into(), lines(codebook_rows.into_iter(), Some(codebook::CODEBOOK_HEADER)), Some(codebook_count)));
    for (fp, contract) in &table.contracts {
        files.push((format!("contracts/{}.json", lower_hex(fp.as_bytes())), writers::json(&contract.to_value()).into_bytes(), None));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let exported: Vec<ExportedFile> =
        files.iter().map(|(name, bytes, rows)| ExportedFile { name: name.clone(), sha256: lower_hex(sha256(bytes).as_bytes()), bytes: bytes.len() as u64, rows: *rows }).collect();
    let manifest = manifest::manifest(table, options.subject.key_id(), &exported)?;
    let result = ExportResult { files: exported, manifest_sha256: lower_hex(sha256(&manifest).as_bytes()) };
    let mut out: Vec<(String, Vec<u8>)> = files.into_iter().map(|(name, bytes, _)| (name, bytes)).collect();
    out.push(("manifest.json".into(), manifest));
    Ok(RenderedExport { files: out, result })
}

/// Writes the export into `out_dir` (created if absent): the files of [`render_export`].
/// Every file is written with the atomic-write helper, and the manifest last.
pub fn write_export(table: &ExportTable, options: &ExportOptions, out_dir: &Path) -> Result<ExportResult, ExportError> {
    let rendered = render_export(table, options)?;
    std::fs::create_dir_all(out_dir.join("contracts")).map_err(|e| io(out_dir, e))?;
    for (name, bytes) in &rendered.files {
        let path = out_dir.join(name);
        write_atomic(&path, bytes).map_err(|e| io(&path, e))?;
    }
    Ok(rendered.result)
}
