//! Wrappers the app puts around its ports so that each accepted submission and each landing
//! leaves one event (no personal data, DEP-051). They are quiet while start-up replay runs.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use fieldseal_intake::domain::{ConsentCase, Finding, LandedEnvelope, LandedObservation, LossLedgerEntry, SubmissionId};
use fieldseal_intake::ports::{DataPlatform, DataPlatformError, LandingBatch, SubmissionStore, SubmissionStoreError};
use fieldseal_kernel::id::{Digest, Fingerprint, RecordId, SubjectId, TenancyId};
use fieldseal_trust::ports::RandomSource;

/// Randomness from the operating system.
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("the operating system's random source");
    }
}

/// Set while stored submissions are run through the gate again at start-up (no events then).
pub type Replaying = Arc<AtomicBool>;

/// Says in an event whether a stored submission was new or one the endpoint already held.
pub struct EventStore<S: SubmissionStore> {
    /// The store that keeps the submissions.
    pub inner: S,
    /// Whether start-up replay is running (no events then).
    pub replaying: Replaying,
}

impl<S: SubmissionStore> SubmissionStore for EventStore<S> {
    fn put(&self, bytes: &[u8]) -> Result<SubmissionId, SubmissionStoreError> {
        let id = SubmissionId(fieldseal_kernel::digest::sha256(bytes));
        let known = self.inner.get(&id)?.is_some();
        let id = self.inner.put(bytes)?;
        if !self.replaying.load(Ordering::SeqCst) {
            eprintln!("{{\"event\":\"submission\",\"id\":\"{}\",\"new\":{},\"bytes\":{}}}", &fieldseal_kernel::digest::lower_hex(id.0.as_bytes())[..16], !known, bytes.len());
        }
        Ok(id)
    }

    fn get(&self, id: &SubmissionId) -> Result<Option<Vec<u8>>, SubmissionStoreError> {
        self.inner.get(id)
    }
}

/// Says in an event what each submission landed: records that were already landed are
/// duplicates (INT-013) and add nothing, so a repeat shows `envelopes: 0`. Instruments and
/// reads print nothing.
pub struct EventPlatform {
    /// The landing that keeps the data.
    pub inner: Box<dyn DataPlatform>,
    /// Whether start-up replay is running (no events then).
    pub replaying: Replaying,
    /// Where the event lines go; standard error in the app.
    pub sink: Box<dyn Fn(&str)>,
}

impl EventPlatform {
    /// A wrapper whose events go to standard error.
    pub fn new(inner: Box<dyn DataPlatform>, replaying: Replaying) -> Self {
        Self { inner, replaying, sink: Box::new(|line| eprintln!("{line}")) }
    }
}

impl DataPlatform for EventPlatform {
    fn land(&self, batch: &LandingBatch) -> Result<(), DataPlatformError> {
        self.inner.land(batch)?;
        if !self.replaying.load(Ordering::SeqCst) {
            (self.sink)(&format!("{{\"event\":\"landed\",\"envelopes\":{},\"observations\":{},\"findings\":{}}}", batch.envelopes.len(), batch.observations.len(), batch.findings.len()));
        }
        Ok(())
    }

    fn exclude(&self, sources: &[RecordId], reason: &str) -> Result<(), DataPlatformError> {
        self.inner.exclude(sources, reason)
    }

    fn reinstate(&self, sources: &[RecordId]) -> Result<(), DataPlatformError> {
        self.inner.reinstate(sources)
    }

    fn instruments(&self) -> Result<Vec<Fingerprint>, DataPlatformError> {
        self.inner.instruments()
    }

    fn observations(&self, i: &Fingerprint) -> Result<Vec<LandedObservation>, DataPlatformError> {
        self.inner.observations(i)
    }

    fn envelopes(&self, t: &TenancyId) -> Result<Vec<LandedEnvelope>, DataPlatformError> {
        self.inner.envelopes(t)
    }

    fn evidence(&self, b: &[u8; 16]) -> Result<Option<Digest>, DataPlatformError> {
        self.inner.evidence(b)
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
