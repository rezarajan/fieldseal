//! A file-based [`DataPlatform`] for Intake: the generic long format as CSV, findings and
//! losses as CSV, and each instrument's data contract as JSON.
//!
//! CSV is chosen over Parquet for this first adapter because it needs no dependency beyond
//! the standard library, opens in every analysis tool, and is trivially diffable in review;
//! a lakehouse adapter (Parquet/Delta) is a drop-in replacement behind the same port. State
//! is held by an in-memory platform for the life of the process and the files are rewritten
//! from it after every write, so the files always show the full current state, with
//! exclusions as flags and nothing deleted. Values are landed locale-free (ADR 0034).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use fieldseal_adapters_memory::intake::MemoryDataPlatform;
use fieldseal_intake::data_contract::{DataContract, LONG_COLUMNS};
use fieldseal_intake::domain::{
    ConsentCase, Finding, LandedEnvelope, LandedObservation, LossLedgerEntry, Reading, SubmissionId,
};
use fieldseal_intake::ports::{DataPlatform, DataPlatformError, LandingBatch};
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::id::{Fingerprint, RecordId, SubjectId, TenancyId};
use fieldseal_kernel::payload::Layout;
use fieldseal_kernel::{Value, id::Digest};

use fieldseal_intake::domain::ObservedValue;

fn io(e: std::io::Error) -> DataPlatformError {
    DataPlatformError::Backend(e.to_string())
}

/// Quotes a CSV field when it needs it (RFC 4180).
pub fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

/// Renders a value tree as JSON, keys in order, text escaped (RFC 8259). Bytes render as
/// lowercase hex; the data contract holds none.
pub fn json(v: &Value) -> String {
    let mut out = String::new();
    write_json(v, &mut out);
    out
}

fn write_json(v: &Value, out: &mut String) {
    match v {
        Value::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Value::Decimal(d) => out.push_str(&fieldseal_intake::data_contract::decimal_text(*d)),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Bytes(b) => write_json(&Value::Text(lower_hex(b)), out),
        Value::Text(t) => {
            out.push('"');
            for c in t.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(x, out);
            }
            out.push(']');
        }
        Value::Map(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(&Value::Text(k.clone()), out);
                out.push(':');
                write_json(x, out);
            }
            out.push('}');
        }
    }
}

/// The CSV header of the long format (INT §6, INT-071, INS-072).
pub fn long_header() -> String {
    LONG_COLUMNS.iter().map(|c| c.name).collect::<Vec<_>>().join(",")
}

/// One landed observation as a CSV line in the order of [`LONG_COLUMNS`].
pub fn long_row(r: &LandedObservation) -> String {
    let o = &r.observation;
    let (value, nonresponse, retracted) = match &o.reading {
        Reading::Value(v) => (
            match v {
                ObservedValue::Bool(b) => b.to_string(),
                ObservedValue::Int(i) => i.to_string(),
                ObservedValue::Decimal(t) | ObservedValue::Text(t) | ObservedValue::Code(t) => t.clone(),
                ObservedValue::Codes(c) => c.join("|"),
            },
            "",
            false,
        ),
        Reading::Nonresponse(n) => (String::new(), n.code(), false),
        Reading::Retracted => (String::new(), "", true),
    };
    let layout = match o.layout {
        Layout::Default => "default".to_owned(),
        Layout::Published(a) => lower_hex(a.as_bytes()),
    };
    let fields = [
        lower_hex(o.instrument.as_bytes()),
        layout,
        o.lang.join("|"),
        o.subject.as_str().to_owned(),
        o.item.as_str().to_owned(),
        value,
        o.value_type.to_owned(),
        nonresponse.to_owned(),
        retracted.to_string(),
        o.unit.clone().unwrap_or_default(),
        lower_hex(o.source.as_bytes()),
        lower_hex(o.tenancy.as_bytes()),
        o.generation.0.to_string(),
        o.seq.0.to_string(),
        o.not_before.map(|t| t.0.to_string()).unwrap_or_default(),
        o.not_after.0.to_string(),
        o.consent_basis.clone(),
        o.flags.iter().cloned().collect::<Vec<_>>().join("|"),
        r.excluded.is_some().to_string(),
        r.excluded.clone().unwrap_or_default(),
    ];
    fields.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(",")
}

/// A [`DataPlatform`] that keeps the landed data in a directory: `observations.csv`,
/// `findings.csv`, `losses.csv`, and `contracts/<instrument>.json`.
pub struct FileDataPlatform {
    dir: PathBuf,
    inner: MemoryDataPlatform,
    instruments: std::sync::Mutex<std::collections::BTreeSet<Fingerprint>>,
}

impl FileDataPlatform {
    /// Writes into `dir`, which is created if absent.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, DataPlatformError> {
        let dir = dir.into();
        std::fs::create_dir_all(dir.join("contracts")).map_err(io)?;
        Ok(Self { dir, inner: MemoryDataPlatform::new(), instruments: Default::default() })
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Writes an instrument's data contract as JSON (INT-056) and returns its path.
    pub fn write_contract(&self, contract: &DataContract) -> Result<PathBuf, DataPlatformError> {
        let path = self.dir.join("contracts").join(format!("{}.json", lower_hex(contract.instrument.as_bytes())));
        std::fs::write(&path, json(&contract.to_value())).map_err(io)?;
        Ok(path)
    }

    fn rewrite(&self) -> Result<(), DataPlatformError> {
        let mut obs = long_header();
        obs.push('\n');
        let fps: Vec<Fingerprint> = self.instruments.lock().expect("lock").iter().copied().collect();
        for fp in fps {
            for r in self.inner.observations(&fp)? {
                obs.push_str(&long_row(&r));
                obs.push('\n');
            }
        }
        std::fs::write(self.dir.join("observations.csv"), obs).map_err(io)?;
        let mut f = String::from("submission,kind,rule,detail\n");
        for (id, x) in self.inner.findings()? {
            let _ = writeln!(f, "{},{:?},{},{}", lower_hex(id.0.as_bytes()), x.kind, csv_field(&x.rule), csv_field(&x.detail));
        }
        std::fs::write(self.dir.join("findings.csv"), f).map_err(io)?;
        let mut l = String::from("tenancy,from_seq,through_seq,reason\n");
        for x in self.inner.losses()? {
            let _ = writeln!(l, "{},{},{},{}", lower_hex(x.tenancy.as_bytes()), x.from.0, x.through.0, csv_field(&x.reason));
        }
        std::fs::write(self.dir.join("losses.csv"), l).map_err(io)
    }
}

impl DataPlatform for FileDataPlatform {
    fn land(&self, batch: &LandingBatch) -> Result<(), DataPlatformError> {
        self.inner.land(batch)?;
        self.instruments.lock().expect("lock").extend(batch.observations.iter().map(|o| o.instrument));
        self.rewrite()
    }

    fn exclude(&self, sources: &[RecordId], reason: &str) -> Result<(), DataPlatformError> {
        self.inner.exclude(sources, reason)?;
        self.rewrite()
    }

    fn reinstate(&self, sources: &[RecordId]) -> Result<(), DataPlatformError> {
        self.inner.reinstate(sources)?;
        self.rewrite()
    }

    fn observations(&self, instrument: &Fingerprint) -> Result<Vec<LandedObservation>, DataPlatformError> {
        self.inner.observations(instrument)
    }

    fn envelopes(&self, tenancy: &TenancyId) -> Result<Vec<LandedEnvelope>, DataPlatformError> {
        self.inner.envelopes(tenancy)
    }

    fn evidence(&self, blob_id: &[u8; 16]) -> Result<Option<Digest>, DataPlatformError> {
        self.inner.evidence(blob_id)
    }

    fn consent_case(&self, t: &TenancyId, s: &SubjectId, i: &Fingerprint) -> Result<Option<ConsentCase>, DataPlatformError> {
        self.inner.consent_case(t, s, i)
    }

    fn consent_cases(&self) -> Result<Vec<ConsentCase>, DataPlatformError> {
        self.inner.consent_cases()
    }

    fn losses(&self) -> Result<Vec<LossLedgerEntry>, DataPlatformError> {
        self.inner.losses()
    }

    fn findings(&self) -> Result<Vec<(SubmissionId, Finding)>, DataPlatformError> {
        self.inner.findings()
    }
}
