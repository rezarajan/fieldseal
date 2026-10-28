//! The demo's intake side: the real verification gate, upload service and a data platform,
//! over the world's keys and the live registry.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use fieldseal_adapters_memory::delivery::MemoryPopLedger;
use fieldseal_adapters_memory::demo::DemoWorld;
use fieldseal_adapters_memory::intake::{MemoryDataPlatform, MemoryInstrumentSource, MemoryRosterHistory, MemorySubmissionStore};
use fieldseal_adapters_memory::policy::BuiltInPolicyEngine;
use fieldseal_adapters_memory::trust::SeededRandom;
use fieldseal_intake::domain::{
    FindingKind, GateState, LandedObservation, ObservedValue, Reading, SubmissionId, SubmissionSource,
};
use fieldseal_intake::gate::{IngestReport as GateReport, IntakeService};
use fieldseal_intake::ports::{DataPlatform, SubmissionStore, SubmissionStoreError};
use fieldseal_intake::upload::UploadService;
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::id::Fingerprint;
use fieldseal_policy::domain::EffectivePolicy;
use fieldseal_trust::ports::AuthorityClock;

use crate::support::{LiveRegistry, RealClock};

/// A submission store that also remembers the order submissions arrived in.
pub struct RecordingStore {
    inner: MemorySubmissionStore,
    order: Mutex<Vec<SubmissionId>>,
}

impl RecordingStore {
    fn new() -> Self {
        Self { inner: MemorySubmissionStore::new(), order: Mutex::default() }
    }

    /// Every distinct submission, oldest first.
    pub fn ids(&self) -> Vec<SubmissionId> {
        self.order.lock().expect("lock").clone()
    }
}

impl SubmissionStore for RecordingStore {
    fn put(&self, bytes: &[u8]) -> Result<SubmissionId, SubmissionStoreError> {
        let id = self.inner.put(bytes)?;
        let mut order = self.order.lock().expect("lock");
        if !order.contains(&id) {
            order.push(id);
        }
        Ok(id)
    }

    fn get(&self, id: &SubmissionId) -> Result<Option<Vec<u8>>, SubmissionStoreError> {
        self.inner.get(id)
    }
}

/// What the gate decided about one submission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmissionReport {
    /// The submission's identifier (SHA-256 of its bytes), in hex.
    pub id: String,
    /// `file` for an export handed to `ingest_export`, `upload` for one that arrived over
    /// the upload endpoint.
    pub source: String,
    /// The gate state it ended in (`Landed`, `Rejected`, `Quarantined`, ...).
    pub state: String,
    /// The stage that rejected it, if it was rejected.
    pub rejection_stage: Option<String>,
    /// The rejection's error code, if it was rejected.
    pub rejection_code: Option<String>,
    /// What was found, without personal data, if it was rejected.
    pub rejection_detail: Option<String>,
    /// Findings other than the rejection itself, as `[kind] rule: detail`.
    pub findings: Vec<String>,
}

/// One loss-ledger entry: a range of records that never arrived (INT-020).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LossReport {
    /// The tenancy, in hex.
    pub tenancy: String,
    /// The first sequence number lost.
    pub from_seq: u64,
    /// The last sequence number lost.
    pub through_seq: u64,
    /// Why.
    pub reason: String,
}

/// One row of the generic long format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongRow {
    /// The instrument's fingerprint, in hex.
    pub instrument: String,
    /// The instrument's published name.
    pub instrument_name: String,
    /// The subject as intake names it (the hex of the roster identifier's bytes).
    pub subject: String,
    /// The subject's roster identifier, when the hex decodes to text.
    pub subject_id: String,
    /// The item path.
    pub item: String,
    /// `value`, `nonresponse` or `retracted`.
    pub outcome: String,
    /// The value, as text (empty for a nonresponse or a retraction); several codes are
    /// joined with `|`.
    pub value: String,
    /// The nonresponse code (`dont-know`, `refused`, `not-applicable`), or empty.
    pub nonresponse: String,
    /// The instrument's data type of the item.
    pub value_type: String,
    /// The unit, or empty.
    pub unit: String,
    /// The languages the record was administered in, joined with `,`.
    pub lang: String,
    /// The layout the record was collected with.
    pub layout: String,
    /// The tenancy, in hex.
    pub tenancy: String,
    /// The tenancy's generation for the subject's cohort.
    pub generation: u32,
    /// The record's sequence number.
    pub seq: u64,
    /// The record, in hex.
    pub record: String,
    /// Lower bound on when it was collected, in milliseconds, where anchors allow one.
    pub not_before_ms: Option<u64>,
    /// Upper bound (delivery time), in milliseconds.
    pub not_after_ms: u64,
    /// The consent basis.
    pub consent_basis: String,
    /// The record's flags, joined with `,`.
    pub flags: String,
    /// Why the row is excluded, if it is.
    pub excluded: Option<String>,
}

/// A snapshot of everything intake holds.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct IntakeReport {
    /// Every submission the gate has seen.
    pub submissions: Vec<SubmissionReport>,
    /// The loss ledger.
    pub losses: Vec<LossReport>,
    /// The landed long-format rows, ordered by instrument, then tenancy, then sequence.
    pub rows: Vec<LongRow>,
}

impl IntakeReport {
    /// The rows as CSV with a header line, for download.
    pub fn rows_csv(&self) -> String {
        let mut out = String::from(
            "instrument,instrument_name,subject_id,item,outcome,value,nonresponse,value_type,unit,lang,layout,tenancy,generation,seq,record,not_before_ms,not_after_ms,consent_basis,flags,excluded\n",
        );
        for r in &self.rows {
            let fields = [
                r.instrument.clone(),
                r.instrument_name.clone(),
                r.subject_id.clone(),
                r.item.clone(),
                r.outcome.clone(),
                r.value.clone(),
                r.nonresponse.clone(),
                r.value_type.clone(),
                r.unit.clone(),
                r.lang.clone(),
                r.layout.clone(),
                r.tenancy.clone(),
                r.generation.to_string(),
                r.seq.to_string(),
                r.record.clone(),
                r.not_before_ms.map(|v| v.to_string()).unwrap_or_default(),
                r.not_after_ms.to_string(),
                r.consent_basis.clone(),
                r.flags.clone(),
                r.excluded.clone().unwrap_or_default(),
            ];
            out.push_str(&fields.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
            out.push('\n');
        }
        out
    }
}

fn csv_field(f: &str) -> String {
    // A leading `=`, `+`, `-` or `@` would be read as a formula by a spreadsheet.
    let guarded = if f.starts_with(['=', '+', '-', '@']) { format!("'{f}") } else { f.to_owned() };
    if guarded.contains([',', '"', '\n', '\r']) { format!("\"{}\"", guarded.replace('"', "\"\"")) } else { guarded }
}

/// What `IntakeWorld::ingest_export` reports about one export file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngestReport {
    /// The submission's report as `IntakeWorld::report` lists it.
    pub submission: SubmissionReport,
    /// One entry per tenancy part acknowledged: the tenancy in hex, and the last sequence
    /// number the receipt covers.
    pub receipts: Vec<(String, u64)>,
    /// Records landed.
    pub landed: usize,
    /// Records already landed.
    pub duplicates: usize,
    /// Records verified but held for a custodian.
    pub held: usize,
    /// Records refused as conflicting with landed ones.
    pub conflicts: usize,
    /// Observation rows written.
    pub observations: usize,
    /// Loss-ledger entries written.
    pub losses: usize,
}

/// The gate, the upload endpoint's state and a data platform, over the demo world's keys.
///
/// Development only: the platform is in memory and starts empty on every run.
pub struct IntakeWorld {
    /// Raw submissions, write-once, in arrival order.
    pub store: RecordingStore,
    /// The data platform: landed envelopes, long-format observations, losses, findings.
    pub platform: MemoryDataPlatform,
    /// Rosters as issued, recorded when a bundle is built.
    pub rosters: MemoryRosterHistory,
    /// The published instruments.
    pub instruments: MemoryInstrumentSource,
    /// Registered tenancies, read live from the factory's registry.
    pub registry: LiveRegistry,
    /// Replay protection for upload tokens.
    pub ledger: MemoryPopLedger,
    world: &'static DemoWorld,
    engine: BuiltInPolicyEngine,
    effective: EffectivePolicy,
    random: SeededRandom,
    urls: Vec<String>,
    named: Vec<(Fingerprint, String)>,
    clock: RealClock,
    known: Mutex<BTreeMap<SubmissionId, SubmissionReport>>,
    files: Mutex<BTreeSet<SubmissionId>>,
}

impl IntakeWorld {
    pub(crate) fn new(world: &'static DemoWorld, urls: Vec<String>, now_ms: u64, named: Vec<(Fingerprint, String)>) -> Self {
        Self {
            store: RecordingStore::new(),
            platform: MemoryDataPlatform::new(),
            rosters: MemoryRosterHistory::new(),
            instruments: MemoryInstrumentSource::new(),
            registry: LiveRegistry::new(&world.registry),
            ledger: MemoryPopLedger::new(),
            world,
            engine: BuiltInPolicyEngine,
            effective: fieldseal_policy::fixtures::effective_default(),
            random: SeededRandom::new(99),
            urls,
            named,
            clock: RealClock::new(now_ms),
            known: Mutex::default(),
            files: Mutex::default(),
        }
    }

    /// The verification gate over this world's ports (INT-001).
    pub fn gate(&self) -> IntakeService<'_> {
        IntakeService {
            store: &self.store,
            registry: &self.registry,
            rosters: &self.rosters,
            instruments: &self.instruments,
            platform: &self.platform,
            custody: &self.world.custody,
            policy: &self.engine,
            effective: &self.effective,
            random: &self.random,
            trust: &self.world.trust,
            revocations: vec![],
            receipt_key: self.world.receipt,
            caller: "web-demo-intake",
        }
    }

    /// The upload endpoint's service over `gate`: receiver challenge, proof-of-possession
    /// tokens, then the gate (DEL-002, DEL-062). The public URLs are the upload URL the demo
    /// was started with.
    pub fn upload<'a>(&'a self, gate: &'a IntakeService<'a>, edge: &'a fieldseal_adapters_memory::demo::EdgeServices) -> UploadService<'a, 'a> {
        UploadService { intake: gate, ledger: &self.ledger, receiver_key: edge.receiver, receiver_certificate: &edge.receiver_certificate, public_urls: &self.urls }
    }

    /// The intake clock: the start time plus the time elapsed.
    pub fn now(&self) -> fieldseal_kernel::time::AuthorityTime {
        self.clock.now()
    }

    /// Runs an export file through the real gate, exactly as `IntakeService::ingest` does
    /// for `SubmissionSource::File`, landing what verifies.
    pub fn ingest_export(&self, bytes: &[u8]) -> Result<IngestReport, String> {
        let report = self.gate().ingest(bytes, SubmissionSource::File, self.now()).map_err(|e| e.to_string())?;
        let row = submission_row(&report, "file");
        self.files.lock().expect("lock").insert(*report.submission.id());
        self.known.lock().expect("lock").insert(*report.submission.id(), row.clone());
        Ok(IngestReport {
            submission: row,
            receipts: report.receipts.iter().map(|r| (lower_hex(r.receipt.tenancy.as_bytes()), r.receipt.last_seq)).collect(),
            landed: report.summary.landed,
            duplicates: report.summary.duplicates,
            held: report.summary.held,
            conflicts: report.summary.conflicts,
            observations: report.summary.observations,
            losses: report.losses.len(),
        })
    }

    /// A snapshot of submissions, losses, long-format rows (the tool makes no statistics: derivations are the data platform's job).
    ///
    /// Submissions that arrived over the upload endpoint are described by replaying them
    /// through the gate without landing anything (`dry_run`), once, when first listed.
    pub fn report(&self) -> IntakeReport {
        let mut submissions = Vec::new();
        for id in self.store.ids() {
            let cached = self.known.lock().expect("lock").get(&id).cloned();
            let row = match cached {
                Some(r) => r,
                None => {
                    let Ok(Some(bytes)) = self.store.get(&id) else { continue };
                    let source = if self.files.lock().expect("lock").contains(&id) { "file" } else { "upload" };
                    let Ok(report) = self.gate().dry_run(&bytes, SubmissionSource::Upload, self.now()) else { continue };
                    let row = submission_row(&report, source);
                    self.known.lock().expect("lock").insert(id, row.clone());
                    row
                }
            };
            submissions.push(row);
        }
        let losses = self
            .platform
            .losses()
            .unwrap_or_default()
            .iter()
            .map(|l| LossReport { tenancy: lower_hex(l.tenancy.as_bytes()), from_seq: l.from.0, through_seq: l.through.0, reason: l.reason.clone() })
            .collect();
        let mut rows = Vec::new();
        for (fp, name) in &self.named {
            let mut landed = self.platform.observations(fp).unwrap_or_default();
            landed.sort_by_key(|l| (l.observation.tenancy, l.observation.seq));
            rows.extend(landed.iter().map(|l| long_row(fp, name, l)));
        }
        IntakeReport { submissions, losses, rows }
    }
}

fn submission_row(report: &GateReport, source: &str) -> SubmissionReport {
    let sub = &report.submission;
    let rejection = sub.rejection();
    SubmissionReport {
        id: lower_hex(sub.id().0.as_bytes()),
        source: source.to_owned(),
        state: format!("{:?}", sub.state()),
        rejection_stage: rejection.map(|r| format!("{:?}", r.stage)),
        rejection_code: rejection.map(|r| r.code.to_string()),
        rejection_detail: rejection.map(|r| r.detail.clone()),
        findings: sub.findings().iter().filter(|f| f.kind != FindingKind::Rejection).map(|f| format!("[{:?}] {}: {}", f.kind, f.rule, f.detail)).collect(),
    }
}

fn value_text(v: &ObservedValue) -> String {
    match v {
        ObservedValue::Bool(b) => b.to_string(),
        ObservedValue::Int(i) => i.to_string(),
        ObservedValue::Decimal(s) | ObservedValue::Text(s) | ObservedValue::Code(s) => s.clone(),
        ObservedValue::Codes(c) => c.join("|"),
    }
}

fn unhex(s: &str) -> Option<String> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect();
    String::from_utf8(bytes?).ok()
}

fn long_row(fp: &Fingerprint, name: &str, l: &LandedObservation) -> LongRow {
    let o = &l.observation;
    let (outcome, value, nonresponse) = match &o.reading {
        Reading::Value(v) => ("value", value_text(v), String::new()),
        Reading::Nonresponse(n) => ("nonresponse", String::new(), n.code().to_owned()),
        Reading::Retracted => ("retracted", String::new(), String::new()),
    };
    LongRow {
        instrument: lower_hex(fp.as_bytes()),
        instrument_name: name.to_owned(),
        subject: o.subject.as_str().to_owned(),
        subject_id: unhex(o.subject.as_str()).unwrap_or_else(|| o.subject.as_str().to_owned()),
        item: o.item.as_str().to_owned(),
        outcome: outcome.to_owned(),
        value,
        nonresponse,
        value_type: o.value_type.to_owned(),
        unit: o.unit.clone().unwrap_or_default(),
        lang: o.lang.join(","),
        layout: format!("{:?}", o.layout),
        tenancy: lower_hex(o.tenancy.as_bytes()),
        generation: o.generation.0,
        seq: o.seq.0,
        record: lower_hex(o.source.as_bytes()),
        not_before_ms: o.not_before.map(|t| t.0),
        not_after_ms: o.not_after.0,
        consent_basis: o.consent_basis.clone(),
        flags: o.flags.iter().cloned().collect::<Vec<_>>().join(","),
        excluded: l.excluded.clone(),
    }
}

/// Whether a gate state means the submission's data landed.
pub fn is_landed(state: &str) -> bool {
    state == format!("{:?}", GateState::Landed) || state == format!("{:?}", GateState::Flagged)
}
