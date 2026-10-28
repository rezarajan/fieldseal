//! The release policy (DIS-001–DIS-004): whether a bundle may go to a tenancy now.
//!
//! Three checks, in order. The tenancy's registration state decides first (the factory
//! never releases a roster to a tenancy that is not `registered`, and withholds from a
//! `flagged`, `lost`, `closing`, `closed` or `retired` one). Schema compatibility (DIS-012)
//! is checked as the bundle is assembled ([`crate::domain::check_composition`]). Then policy
//! decides at `bundle.release`, and its answer names the policy it came from (DIS-002).

use fieldseal_kernel::id::TenancyId;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::value::Value;
use fieldseal_policy::application::{Decide, DecideRequest};
use fieldseal_policy::domain::{DecisionPoint, Facts, LayerSelector, Subject, Verdict};
use fieldseal_registration::domain::{TenancyRecord, TenancyState};

use crate::domain::{DistributionError, ReleaseDecision};

/// What the state of a tenancy says about releasing to it (DIS-001, DIS-003, DIS-004).
///
/// `practice` is a bundle with no rosters. A tenancy that is not yet registered may receive
/// one if policy allows (DIS-004); the policy decision comes later. A registered tenancy
/// always passes this check.
pub fn check_state(state: TenancyState, practice: bool) -> Result<(), DistributionError> {
    match state {
        TenancyState::Registered => Ok(()),
        TenancyState::Flagged
        | TenancyState::Lost
        | TenancyState::Closing
        | TenancyState::Closed
        | TenancyState::Retired => Err(DistributionError::Withheld(vec![format!("tenancy-{}", state.as_str())])),
        TenancyState::Pending | TenancyState::Held if practice => Ok(()),
        TenancyState::Rejected if practice => Err(DistributionError::Withheld(vec!["tenancy-rejected".to_owned()])),
        TenancyState::Pending | TenancyState::Held | TenancyState::Rejected => Err(DistributionError::NotRegistered),
    }
}

/// The facts `bundle.release` reads (policy §6.2).
///
/// `unattested_allowed` is configuration, not a fact about the device: it is true only when the
/// factory runs with the non-production allowance for unattested keys (REG-017). The device's
/// own `keyAttested` is never altered.
pub fn release_facts(record: &TenancyRecord, contains_roster: bool, active_tenancies_in_cohort: u64, unattested_allowed: bool) -> Facts {
    Facts::from([
        ("tenancyRegistered".to_owned(), Value::Bool(record.state == TenancyState::Registered)),
        ("containsRoster".to_owned(), Value::Bool(contains_roster)),
        ("keyAttested".to_owned(), Value::Bool(record.keys_attested())),
        ("unattestedAllowed".to_owned(), Value::Bool(unattested_allowed)),
        ("activeTenanciesInCohort".to_owned(), Value::Int(i128::from(active_tenancies_in_cohort))),
        ("paused".to_owned(), Value::Bool(false)),
    ])
}

/// A release decision with its place in the decision log.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Released {
    /// The verdict.
    pub decision: ReleaseDecision,
    /// The index of the decision in the decision log.
    pub log_index: u64,
}

/// Asks policy whether to release (DIS-002). `allow` and `flag` release; `hold` and `deny`
/// withhold (DIS-003), and so does a policy failure: nothing is released on a guess (POL-034).
pub fn decide_release(
    policy: &dyn Decide,
    selector: &LayerSelector,
    tenancy: TenancyId,
    facts: Facts,
    at: AuthorityTime,
) -> Result<Released, DistributionError> {
    let request = DecideRequest {
        point: DecisionPoint::BundleRelease,
        selector: selector.clone(),
        facts,
        subject: Subject::Tenancy(tenancy),
        at,
    };
    let decided = policy
        .decide(&request)
        .map_err(|e| DistributionError::Withheld(vec![format!("policy-unavailable: {e}")]))?;
    match decided.decision.verdict {
        Verdict::Allow | Verdict::Flag => Ok(Released {
            decision: ReleaseDecision::Release { policy: decided.decision.policy },
            log_index: decided.log_index,
        }),
        Verdict::Deny | Verdict::Hold => Err(DistributionError::Withheld(decided.decision.reasons)),
    }
}
