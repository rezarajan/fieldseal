//! Use cases: the driving ports the Intake context offers
//! (`docs/reference/spec/intake.md` §3).

use std::collections::BTreeSet;

use fieldseal_kernel::id::{Fingerprint, SubjectId, TenancyId};
use fieldseal_kernel::time::AuthorityTime;

use crate::data_contract::{DataContract, generate_data_contract};
use crate::domain::{
    ConsentCase, ConsentDecision, DecisionTrail, Finding, FindingKind, SubmissionId, SubmissionSource,
};
use crate::gate::{IngestReport, IntakeService};
use crate::landing::{SubjectState, fold_subject_state};
use crate::ports::{DataPlatform, LandingBatch};

/// Why an intake use case failed. A submission that fails verification is not an error: it
/// comes back as a report with state `Rejected` and the stage and code that refused it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntakeError {
    /// Over the size limit.
    #[error("too large")]
    TooLarge,
    /// Unreadable.
    #[error("unreadable")]
    Unreadable,
    /// The caller may not decide consent.
    #[error("not authorised")]
    NotAuthorised,
    /// The case isn't pending.
    #[error("not pending")]
    NotPending,
    /// A custodian may only accept or reject.
    #[error("a custodian decision is accepted or rejected")]
    InvalidDecision,
    /// No such submission.
    #[error("unknown submission")]
    UnknownSubmission,
    /// No such instrument.
    #[error("unknown instrument")]
    UnknownInstrument,
    /// A backing service failed; nothing was landed.
    #[error("backend: {0}")]
    Backend(String),
}

/// `IngestSubmission`: verify and land one export or upload.
pub trait IngestSubmission {
    /// Runs the gate and returns the submission in its final state, with its receipts.
    fn ingest(&self, bytes: &[u8], source: SubmissionSource, now: AuthorityTime) -> Result<IngestReport, IntakeError>;
}

impl IngestSubmission for IntakeService<'_> {
    fn ingest(&self, bytes: &[u8], source: SubmissionSource, now: AuthorityTime) -> Result<IngestReport, IntakeError> {
        IntakeService::ingest(self, bytes, source, now)
    }
}

/// `ReplaySubmission`.
pub trait ReplaySubmission {
    /// Replays a stored submission through the gate against the current instruments and
    /// policy, writing nothing, and returns its report (findings, receipts it would issue).
    fn replay(&self, id: &SubmissionId, now: AuthorityTime) -> Result<IngestReport, IntakeError>;
}

impl ReplaySubmission for IntakeService<'_> {
    fn replay(&self, id: &SubmissionId, now: AuthorityTime) -> Result<IngestReport, IntakeError> {
        let bytes = self
            .store
            .get(id)
            .map_err(|e| IntakeError::Backend(e.to_string()))?
            .ok_or(IntakeError::UnknownSubmission)?;
        self.dry_run(&bytes, SubmissionSource::File, now)
    }
}

/// `QuerySubjectState`.
pub trait QuerySubjectState {
    /// A subject's merged state for an instrument (INT-053–055).
    fn subject_state(&self, subject: &SubjectId, instrument: &Fingerprint) -> Result<SubjectState, IntakeError>;
}

impl QuerySubjectState for IntakeService<'_> {
    fn subject_state(&self, subject: &SubjectId, instrument: &Fingerprint) -> Result<SubjectState, IntakeError> {
        let rows = self.platform.observations(instrument).map_err(|e| IntakeError::Backend(e.to_string()))?;
        let rows: Vec<_> = rows.into_iter().filter(|r| &r.observation.subject == subject).collect();
        let lineage = |t: &TenancyId| {
            let mut cur = *t;
            let mut seen = BTreeSet::new();
            while seen.insert(cur) {
                match self.view_of(&cur).and_then(|v| v.predecessor) {
                    Some(p) => cur = p,
                    None => break,
                }
            }
            cur
        };
        Ok(fold_subject_state(&rows, &lineage))
    }
}

/// `GenerateDataContract` (INT-056): the contract of a published instrument.
pub fn data_contract(instruments: &dyn crate::ports::InstrumentSource, fingerprint: &Fingerprint) -> Result<DataContract, IntakeError> {
    let inst = instruments
        .instrument(fingerprint)
        .map_err(|e| IntakeError::Backend(e.to_string()))?
        .ok_or(IntakeError::UnknownInstrument)?;
    Ok(generate_data_contract(*fingerprint, &inst))
}

/// `DecideConsent` and `ReverseConsent`.
pub trait DecideConsent {
    /// Records a custodian's decision on a pending (or sampled) case (INT-039, INT-040).
    fn decide(&self, case: &ConsentCase, decision: ConsentDecision, custodian: &str, at: AuthorityTime) -> Result<ConsentCase, IntakeError>;
    /// Reverses consent: every dependent observation is excluded by flag, none is deleted.
    fn reverse(&self, case: &ConsentCase, reason: &str, custodian: &str, at: AuthorityTime) -> Result<ConsentCase, IntakeError>;
}

/// The custodian's consent desk: decisions go to the data platform and are logged with who
/// made them and when (INT-040, INT-061).
pub struct ConsentDesk<'a> {
    platform: &'a dyn DataPlatform,
    custodians: BTreeSet<String>,
}

impl<'a> ConsentDesk<'a> {
    /// A desk where only `custodians` may decide.
    pub fn new(platform: &'a dyn DataPlatform, custodians: impl IntoIterator<Item = String>) -> Self {
        Self { platform, custodians: custodians.into_iter().collect() }
    }

    fn write(&self, case: &ConsentCase, finding: Finding) -> Result<(), IntakeError> {
        let batch = LandingBatch { consent: vec![case.clone()], findings: vec![finding], ..LandingBatch::default() };
        self.platform.land(&batch).map_err(|e| IntakeError::Backend(e.to_string()))
    }
}

impl DecideConsent for ConsentDesk<'_> {
    fn decide(&self, case: &ConsentCase, decision: ConsentDecision, custodian: &str, at: AuthorityTime) -> Result<ConsentCase, IntakeError> {
        if !self.custodians.contains(custodian) {
            return Err(IntakeError::NotAuthorised);
        }
        if !matches!(decision, ConsentDecision::Accepted | ConsentDecision::Rejected) {
            return Err(IntakeError::InvalidDecision);
        }
        let reviewable = case.decision == ConsentDecision::Pending || (case.decision == ConsentDecision::AutoAccepted && case.sampled);
        if !reviewable {
            return Err(IntakeError::NotPending);
        }
        let mut next = case.clone();
        next.decision = decision;
        next.sampled = false;
        next.history.push(DecisionTrail { by: custodian.to_owned(), at, policy: vec![], decision });
        match decision {
            ConsentDecision::Rejected => self
                .platform
                .exclude(&case.records, &format!("consent-rejected by {custodian}"))
                .map_err(|e| IntakeError::Backend(e.to_string()))?,
            _ => self.platform.reinstate(&case.records).map_err(|e| IntakeError::Backend(e.to_string()))?,
        }
        self.write(&next, Finding::new(FindingKind::Flag, "INT-040", format!("consent decided: {decision:?} by {custodian}")))?;
        Ok(next)
    }

    fn reverse(&self, case: &ConsentCase, reason: &str, custodian: &str, at: AuthorityTime) -> Result<ConsentCase, IntakeError> {
        if !self.custodians.contains(custodian) {
            return Err(IntakeError::NotAuthorised);
        }
        let mut next = case.clone();
        next.decision = ConsentDecision::Rejected;
        next.sampled = false;
        next.history.push(DecisionTrail { by: custodian.to_owned(), at, policy: vec![], decision: ConsentDecision::Rejected });
        self.platform
            .exclude(&case.records, &format!("consent-reversed by {custodian}: {reason}"))
            .map_err(|e| IntakeError::Backend(e.to_string()))?;
        self.write(&next, Finding::new(FindingKind::Flag, "INT-039", format!("consent reversed by {custodian}")))?;
        Ok(next)
    }
}
