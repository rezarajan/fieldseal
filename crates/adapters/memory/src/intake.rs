//! In-memory adapters for the Intake context's driven ports.

use std::collections::BTreeMap;
use std::sync::Mutex;

use fieldseal_instrument::domain::Instrument;
use fieldseal_intake::domain::{
    ConsentCase, Finding, IssuedRoster, LandedEnvelope, LandedObservation, LossLedgerEntry, SubmissionId,
    TenancyView,
};
use fieldseal_intake::ports::{
    DataPlatform, DataPlatformError, InstrumentSource, InstrumentSourceError, LandingBatch, RosterHistory,
    RosterHistoryError, SubmissionStore, SubmissionStoreError, TenancyRegistry, TenancyRegistryError,
};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{Digest, Fingerprint, RecordId, SubjectId, TenancyHandle, TenancyId};

pub mod practice;

/// In-memory [`SubmissionStore`]: write-once, addressed by SHA-256.
#[derive(Default)]
pub struct MemorySubmissionStore {
    submissions: Mutex<BTreeMap<SubmissionId, Vec<u8>>>,
}

impl MemorySubmissionStore {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SubmissionStore for MemorySubmissionStore {
    fn put(&self, bytes: &[u8]) -> Result<SubmissionId, SubmissionStoreError> {
        let id = SubmissionId(sha256(bytes));
        self.submissions.lock().expect("lock").entry(id).or_insert_with(|| bytes.to_vec());
        Ok(id)
    }

    fn get(&self, id: &SubmissionId) -> Result<Option<Vec<u8>>, SubmissionStoreError> {
        Ok(self.submissions.lock().expect("lock").get(id).cloned())
    }
}

/// In-memory [`TenancyRegistry`] over fixed views.
#[derive(Default)]
pub struct MemoryTenancyRegistry {
    views: BTreeMap<TenancyId, TenancyView>,
}

impl MemoryTenancyRegistry {
    /// A registry holding `views`.
    pub fn new(views: Vec<TenancyView>) -> Self {
        Self { views: views.into_iter().map(|v| (v.tenancy, v)).collect() }
    }
}

impl TenancyRegistry for MemoryTenancyRegistry {
    fn by_handle(&self, handle: &TenancyHandle) -> Result<Option<TenancyView>, TenancyRegistryError> {
        Ok(self.views.values().find(|v| v.handle == *handle).cloned())
    }

    fn by_id(&self, id: &TenancyId) -> Result<Option<TenancyView>, TenancyRegistryError> {
        Ok(self.views.get(id).cloned())
    }
}

/// In-memory [`RosterHistory`].
#[derive(Default)]
pub struct MemoryRosterHistory {
    issued: Mutex<BTreeMap<TenancyId, Vec<IssuedRoster>>>,
}

impl MemoryRosterHistory {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a roster version issued to a tenancy.
    pub fn record(&self, tenancy: TenancyId, roster: IssuedRoster) {
        let mut issued = self.issued.lock().expect("lock");
        let list = issued.entry(tenancy).or_default();
        list.push(roster);
        list.sort_by(|a, b| (&a.cohort, a.version).cmp(&(&b.cohort, b.version)));
    }
}

impl RosterHistory for MemoryRosterHistory {
    fn issued(&self, tenancy: &TenancyId) -> Result<Vec<IssuedRoster>, RosterHistoryError> {
        Ok(self.issued.lock().expect("lock").get(tenancy).cloned().unwrap_or_default())
    }
}

/// In-memory [`InstrumentSource`] over fixed instruments.
#[derive(Default)]
pub struct MemoryInstrumentSource {
    instruments: Mutex<BTreeMap<Fingerprint, Instrument>>,
}

impl MemoryInstrumentSource {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Holds `instrument` under `fingerprint`.
    pub fn add(&self, fingerprint: Fingerprint, instrument: Instrument) {
        self.instruments.lock().expect("lock").insert(fingerprint, instrument);
    }
}

impl InstrumentSource for MemoryInstrumentSource {
    fn instrument(&self, fingerprint: &Fingerprint) -> Result<Option<Instrument>, InstrumentSourceError> {
        Ok(self.instruments.lock().expect("lock").get(fingerprint).cloned())
    }
}

#[derive(Default)]
struct PlatformState {
    observations: Vec<LandedObservation>,
    envelopes: Vec<LandedEnvelope>,
    findings: Vec<(SubmissionId, Finding)>,
    consent: Vec<ConsentCase>,
    losses: Vec<LossLedgerEntry>,
}

/// In-memory [`DataPlatform`]. A landing is applied under one lock, so it is atomic.
#[derive(Default)]
pub struct MemoryDataPlatform {
    state: Mutex<PlatformState>,
}

impl MemoryDataPlatform {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }
}

impl DataPlatform for MemoryDataPlatform {
    fn land(&self, batch: &LandingBatch) -> Result<(), DataPlatformError> {
        let mut s = self.state.lock().expect("lock");
        s.envelopes.extend(batch.envelopes.iter().cloned());
        s.observations.extend(batch.observations.iter().cloned().map(|o| {
            let excluded = batch.exclusions.iter().find(|(r, _)| *r == o.source).map(|(_, why)| why.clone());
            LandedObservation { observation: o, excluded }
        }));
        let submission = batch.submission.unwrap_or(SubmissionId(Digest::from([0; 32])));
        s.findings.extend(batch.findings.iter().cloned().map(|f| (submission, f)));
        for case in &batch.consent {
            let key = (case.tenancy, &case.subject, case.instrument);
            match s.consent.iter_mut().find(|c| (c.tenancy, &c.subject, c.instrument) == key) {
                Some(existing) => {
                    // Merge the records this submission added, keep history.
                    let mut next = case.clone();
                    for r in &existing.records {
                        if !next.records.contains(r) {
                            next.records.push(*r);
                        }
                    }
                    *existing = next;
                }
                None => s.consent.push(case.clone()),
            }
        }
        s.losses.extend(batch.losses.iter().cloned());
        Ok(())
    }

    fn exclude(&self, sources: &[RecordId], reason: &str) -> Result<(), DataPlatformError> {
        for o in self.state.lock().expect("lock").observations.iter_mut() {
            if sources.contains(&o.observation.source) {
                o.excluded = Some(reason.to_owned());
            }
        }
        Ok(())
    }

    fn reinstate(&self, sources: &[RecordId]) -> Result<(), DataPlatformError> {
        for o in self.state.lock().expect("lock").observations.iter_mut() {
            if sources.contains(&o.observation.source) {
                o.excluded = None;
            }
        }
        Ok(())
    }

    fn observations(&self, instrument: &Fingerprint) -> Result<Vec<LandedObservation>, DataPlatformError> {
        Ok(self.state.lock().expect("lock").observations.iter().filter(|o| o.observation.instrument == *instrument).cloned().collect())
    }

    fn envelopes(&self, tenancy: &TenancyId) -> Result<Vec<LandedEnvelope>, DataPlatformError> {
        let mut v: Vec<_> = self.state.lock().expect("lock").envelopes.iter().filter(|e| e.tenancy == *tenancy).cloned().collect();
        v.sort_by_key(|e| e.seq);
        Ok(v)
    }

    fn evidence(&self, blob_id: &[u8; 16]) -> Result<Option<Digest>, DataPlatformError> {
        Ok(self
            .state
            .lock()
            .expect("lock")
            .envelopes
            .iter()
            .find_map(|e| e.evidence.as_ref().filter(|(b, _)| b == blob_id).map(|(_, h)| *h)))
    }

    fn consent_case(&self, tenancy: &TenancyId, subject: &SubjectId, instrument: &Fingerprint) -> Result<Option<ConsentCase>, DataPlatformError> {
        Ok(self
            .state
            .lock()
            .expect("lock")
            .consent
            .iter()
            .find(|c| c.tenancy == *tenancy && &c.subject == subject && c.instrument == *instrument)
            .cloned())
    }

    fn consent_cases(&self) -> Result<Vec<ConsentCase>, DataPlatformError> {
        Ok(self.state.lock().expect("lock").consent.clone())
    }

    fn losses(&self) -> Result<Vec<LossLedgerEntry>, DataPlatformError> {
        Ok(self.state.lock().expect("lock").losses.clone())
    }

    fn findings(&self) -> Result<Vec<(SubmissionId, Finding)>, DataPlatformError> {
        Ok(self.state.lock().expect("lock").findings.clone())
    }
}
