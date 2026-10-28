//! Driven ports owned by the Policy context (`docs/reference/spec/policy.md` §4).

use crate::domain::{
    Decision, DecisionPoint, DecisionRecord, EffectivePolicy, Facts, LayerSelector, PublishedPolicy,
};

/// Errors from [`PolicyEngine`]. The caller turns every one into `hold` or `flag`, never
/// `allow` (POL-034).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyEngineError {
    /// Evaluation exceeded its time budget.
    #[error("evaluation timed out")]
    Timeout,
    /// The engine has no rules for this decision point.
    #[error("no rules for {0}")]
    UnknownDecisionPoint(&'static str),
    /// A fact the decision point needs was not supplied.
    #[error("missing fact `{0}`")]
    MissingFact(String),
    /// A fact had the wrong type or an impossible value.
    #[error("bad fact `{0}`")]
    BadFact(String),
    /// The engine failed.
    #[error("policy engine: {0}")]
    Backend(String),
}

/// Evaluates a decision point against an effective policy and input facts.
///
/// Contract: deterministic for the same inputs (POL-032); side-effect free; returns reasons
/// for every non-`Allow` outcome; the decision names the effective policy's sources; fails
/// with an error rather than guessing when facts are missing; times out rather than hangs.
/// The facts each point reads are listed in [`crate::domain::decision`].
pub trait PolicyEngine {
    /// Decides `point` under `policy` for `facts`.
    fn evaluate(
        &self,
        point: DecisionPoint,
        policy: &EffectivePolicy,
        facts: &Facts,
    ) -> Result<Decision, PolicyEngineError>;
}

/// Errors from [`PolicySource`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicySourceError {
    /// A policy failed publishing verification and was not returned.
    #[error("policy failed verification")]
    Unverified,
    /// The source is unavailable.
    #[error("policy source: {0}")]
    Unavailable(String),
}

/// Returns published policies for the layers in scope.
///
/// Contract: returns only policies that passed publishing verification; returns the
/// deployment layer first, then programme, then instrument.
pub trait PolicySource {
    /// The policies for `selector`, outermost layer first.
    fn policies(&self, selector: &LayerSelector) -> Result<Vec<PublishedPolicy>, PolicySourceError>;
}

/// Errors from [`DecisionLog`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecisionLogError {
    /// No entry at that index.
    #[error("no such entry")]
    NotFound,
    /// The log is unavailable.
    #[error("decision log: {0}")]
    Unavailable(String),
}

/// Append-only, tamper-evident store of decisions (POL-040).
///
/// Contract: indices increase by one per append; an entry, once written, always reads back
/// unchanged; there is no update or delete.
pub trait DecisionLog {
    /// Appends a record and returns its index.
    fn append(&self, record: &DecisionRecord) -> Result<u64, DecisionLogError>;

    /// Reads the entry at `index`.
    fn read(&self, index: u64) -> Result<DecisionRecord, DecisionLogError>;

    /// The number of entries.
    fn len(&self) -> u64;

    /// Whether the log is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
