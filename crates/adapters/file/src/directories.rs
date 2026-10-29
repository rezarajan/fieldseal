//! The factory's answers to "is this survey published?" and "does this cohort have a roster?",
//! over the artefact registry directory and the roster store (REG-046).
//!
//! **Development adapters.**

use fieldseal_kernel::id::CohortId;
use fieldseal_publishing::domain::ArtefactKind;
use fieldseal_publishing::ports::ArtefactRegistry;
use fieldseal_registration::ports::{CohortDirectory, SurveyDirectory};

use crate::roster_store::RosterStore;

/// A survey exists when the registry holds an instrument of that name that no withdrawal
/// names. A registry that can't be read answers `false`, so an assignment is refused rather
/// than made for a survey that might not exist.
pub struct PublishedSurveys<R: ArtefactRegistry>(pub R);

impl<R: ArtefactRegistry> SurveyDirectory for PublishedSurveys<R> {
    fn exists(&self, name: &str) -> bool {
        let (Ok(versions), Ok(withdrawn)) = (self.0.list(ArtefactKind::Instrument, name), self.0.withdrawals()) else { return false };
        versions.iter().any(|(_, address)| !withdrawn.iter().any(|w| w.statement.address == *address))
    }
}

/// A cohort exists when the roster store holds a version of it.
pub struct StoredCohorts(pub RosterStore);

impl CohortDirectory for StoredCohorts {
    fn exists(&self, cohort: &CohortId) -> bool {
        self.0.versions(cohort).is_ok_and(|v| !v.is_empty())
    }
}
