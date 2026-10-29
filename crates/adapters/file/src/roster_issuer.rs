//! The factory's [`RosterIssuer`] over a [`RosterStore`]: it checks the bytes it is given with
//! the closed-schema check that `roster check` uses (DIS-063) and stores the roster.
//!
//! Nothing is written until the bytes pass every check: canonical CBOR first, then the schema check, then the
//! cohort the caller named, and only then a write. The store write is idempotent by content
//! digest; the journal record is the caller's second write (REG-047).
//!
//! **Development adapter.**

use fieldseal_distribution::domain::check_issue_form;
use fieldseal_kernel::cbor;
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{CohortId, Generation};
use fieldseal_registration::ports::{IssueOutcome, RosterIssuer};

use crate::roster_store::{IssueOutcome as Stored, RosterStore, RosterStoreError};

/// The largest roster body decoded.
const MAX_ROSTER_BODY: usize = 8 * 1024 * 1024;

/// The generation a stored roster carries. A generation belongs to one cohort on one tenancy
/// (DIS-014, WIRE-198), so the store holds a placeholder that the roster source replaces with
/// the tenancy's own.
const STORED_GENERATION: Generation = Generation(1);

/// Issues rosters into a [`RosterStore`].
pub struct FileRosterIssuer {
    store: RosterStore,
}

impl FileRosterIssuer {
    /// An issuer over `store`.
    pub fn new(store: RosterStore) -> Self {
        Self { store }
    }

    /// The store this issuer writes.
    pub fn store(&self) -> &RosterStore {
        &self.store
    }
}

impl RosterIssuer for FileRosterIssuer {
    fn issue(&self, cohort: &CohortId, canonical_bytes: &[u8]) -> IssueOutcome {
        let invalid = |reason: &str| IssueOutcome::Invalid(reason.to_owned());
        let Ok(value) = cbor::decode_limited(canonical_bytes, MAX_ROSTER_BODY) else {
            return invalid("the roster is not canonical CBOR");
        };
        if cbor::encode(&value).ok().as_deref() != Some(canonical_bytes) {
            return invalid("the roster is not in canonical form");
        }
        let form = match check_issue_form(value) {
            Ok(form) => form,
            Err(findings) => {
                let text: Vec<String> = findings.iter().map(|f| if f.path.is_empty() { f.message.clone() } else { format!("{}: {}", f.path, f.message) }).collect();
                return IssueOutcome::Invalid(text.join("; "));
            }
        };
        if form.cohort != *cohort {
            return invalid("the roster names another cohort than the request");
        }
        let version = form.version;
        let roster = form.into_roster(STORED_GENERATION);
        let digest = sha256(&roster.encode());
        match self.store.issue(&roster) {
            Ok(Stored::Stored) => IssueOutcome::Issued { version, digest },
            Ok(Stored::Unchanged) => IssueOutcome::AlreadyIssued { version, digest },
            Err(RosterStoreError::VersionTaken { .. }) => IssueOutcome::VersionTaken,
            Err(RosterStoreError::NotNewer { .. }) => IssueOutcome::NotNewer,
            Err(RosterStoreError::Cohort(_)) => invalid("the cohort name can't be stored"),
            Err(RosterStoreError::Backend(reason)) => IssueOutcome::Unavailable(reason),
        }
    }
}
