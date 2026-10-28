//! Collection periods and the lifetime of their record keys (TRU-020..023).

use fieldseal_kernel::id::CollectionPeriodId;
use fieldseal_kernel::time::AuthorityTime;

use super::error::TrustError;

/// A named time span with its own record key (TRU-020).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CollectionPeriod {
    id: CollectionPeriodId,
    start: AuthorityTime,
    end: AuthorityTime,
}

impl CollectionPeriod {
    /// A period from `start` to `end`; it must end after it starts.
    pub fn new(id: CollectionPeriodId, start: AuthorityTime, end: AuthorityTime) -> Result<Self, TrustError> {
        if end <= start {
            return Err(TrustError::EmptyValidity);
        }
        Ok(Self { id, start, end })
    }

    /// The period's identifier, as written in the record key's certificate.
    pub fn id(&self) -> &CollectionPeriodId {
        &self.id
    }

    /// When the period starts.
    pub fn start(&self) -> AuthorityTime {
        self.start
    }

    /// When the period ends.
    pub fn end(&self) -> AuthorityTime {
        self.end
    }
}

/// How long sealed data for a period may still arrive or be held after the period ends:
/// the deployment's retention period (TRU-023; its value is set in the deployment manifest,
/// TRU open question 3). In milliseconds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Retention(pub u64);

/// The terms that fix a record key's lifetime: its period and the retention after it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecordKeyTerms {
    /// The collection period the key is for.
    pub period: CollectionPeriod,
    /// The deployment's retention period.
    pub retention: Retention,
}

impl RecordKeyTerms {
    /// The latest `not_after` a record key certificate may have: the period's end plus the
    /// retention (TRU §6.1, "the period plus retention").
    pub fn latest_not_after(&self) -> Result<AuthorityTime, TrustError> {
        self.period.end.checked_add(self.retention.0).ok_or(TrustError::EmptyValidity)
    }

    /// Whether the record key's private part may be destroyed at `now` (TRU-023): only after
    /// the period's end plus the retention, and only once no sealed data for the period may
    /// still arrive or is still held (`sealed_data_outstanding`, which intake reports).
    pub fn may_destroy(&self, now: AuthorityTime, sealed_data_outstanding: bool) -> Result<(), TrustError> {
        let until = self.latest_not_after()?;
        if now < until || sealed_data_outstanding {
            return Err(TrustError::RecordKeyRetained { until });
        }
        Ok(())
    }
}
