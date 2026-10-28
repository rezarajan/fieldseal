//! Use cases offered by the Policy context (POL §3): `ValidatePolicy`,
//! `ComputeEffectivePolicy`, `Decide` and `DiffPolicies`.

use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::value::Value;

use crate::domain::{
    ControlChange, Decision, DecisionPoint, DecisionRecord, EffectivePolicy, Facts, Finding,
    LayerSelector, PolicyDocument, PolicyEvent, Subject, Verdict, decode_document, diff_documents,
    facts_digest, has_errors, merge_layers,
};
use crate::ports::{DecisionLog, DecisionLogError, PolicyEngine, PolicySource, PolicySourceError};

/// The outcome of validating one document.
#[derive(Clone, PartialEq, Debug)]
pub struct ValidationReport {
    /// The decoded document, when it has no errors.
    pub document: Option<PolicyDocument>,
    /// Every finding: unknown fields, wrong types, invariant breaches.
    pub findings: Vec<Finding>,
}

impl ValidationReport {
    /// Whether the document is usable.
    pub fn is_valid(&self) -> bool {
        self.document.is_some() && !has_errors(&self.findings)
    }

    /// The invariants breached, if any.
    pub fn invariant_breaches(&self) -> Vec<&'static str> {
        let mut ids: Vec<&'static str> = self
            .findings
            .iter()
            .filter(|f| f.is_invariant_breach())
            .map(|f| f.requirement)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// The `PolicyRejected` event, when an invariant is breached.
    pub fn rejection_event(&self) -> Option<PolicyEvent> {
        let invariants = self.invariant_breaches();
        (!invariants.is_empty()).then_some(PolicyEvent::PolicyRejected { invariants })
    }
}

/// `ValidatePolicy`: schema, invariant floors and loosening across layers.
pub trait ValidatePolicy {
    /// Validates one policy document (POL-001, POL-002, POL-010).
    fn validate(&self, document: &Value) -> ValidationReport;

    /// Validates documents as a stack, outermost layer first: each on its own, then merged, so
    /// loosening across layers is reported (POL-021). Returns every finding.
    fn validate_stack(&self, documents: &[Value]) -> Vec<Finding>;
}

/// `DiffPolicies`: control-by-control changes, marked tighter or looser.
pub trait DiffPolicies {
    /// The changes from `before` to `after`; the findings if either does not validate.
    fn diff(&self, before: &Value, after: &Value) -> Result<Vec<ControlChange>, Vec<Finding>>;
}

/// The pure use cases that need no port: validation and diffing.
#[derive(Clone, Copy, Default, Debug)]
pub struct PolicyValidator;

impl ValidatePolicy for PolicyValidator {
    fn validate(&self, document: &Value) -> ValidationReport {
        let decoded = decode_document(document);
        ValidationReport { document: decoded.document, findings: decoded.findings }
    }

    fn validate_stack(&self, documents: &[Value]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut decoded = Vec::new();
        for (i, value) in documents.iter().enumerate() {
            let report = self.validate(value);
            findings.extend(report.findings.into_iter().map(|mut f| {
                f.path = format!("documents[{i}].{}", f.path);
                f
            }));
            decoded.extend(report.document);
        }
        if decoded.len() == documents.len() {
            let refs: Vec<&PolicyDocument> = decoded.iter().collect();
            findings.extend(merge_layers(&refs).1);
        }
        findings
    }
}

impl DiffPolicies for PolicyValidator {
    fn diff(&self, before: &Value, after: &Value) -> Result<Vec<ControlChange>, Vec<Finding>> {
        let (b, a) = (self.validate(before), self.validate(after));
        match (b.document, a.document) {
            (Some(b), Some(a)) => Ok(diff_documents(&b, &a)),
            _ => Err(b.findings.into_iter().chain(a.findings).collect()),
        }
    }
}

/// Why an effective policy could not be computed.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ComputeError {
    /// The source failed.
    #[error("policy source: {0}")]
    Source(#[from] PolicySourceError),
    /// The source returned no deployment policy.
    #[error("no deployment policy is published")]
    NoPolicy,
    /// The layers do not merge: a loosening, an invariant breach or a bad order.
    #[error("the policy layers are invalid ({} findings)", .0.len())]
    Invalid(Vec<Finding>),
}

/// `ComputeEffectivePolicy`: merges the layers that apply, by each control's merge rule.
pub trait ComputeEffectivePolicy {
    /// The effective policy for `selector` (POL-020 to POL-023).
    fn compute(&self, selector: &LayerSelector) -> Result<EffectivePolicy, ComputeError>;
}

/// A request to `Decide`.
#[derive(Clone, PartialEq, Debug)]
pub struct DecideRequest {
    /// The decision point.
    pub point: DecisionPoint,
    /// Which layers apply.
    pub selector: LayerSelector,
    /// The input facts.
    pub facts: Facts,
    /// What the decision is about.
    pub subject: Subject,
    /// Authority time of the decision, supplied by the caller (policy reads no clock).
    pub at: AuthorityTime,
}

/// A decision that has been logged.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Decided {
    /// The decision.
    pub decision: Decision,
    /// Its index in the decision log.
    pub log_index: u64,
}

/// Why a decision could not be made.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum DecideError {
    /// No effective policy.
    #[error("no effective policy: {0}")]
    Policy(#[from] ComputeError),
    /// The decision could not be logged, so it was not made (POL-040).
    #[error("decision log: {0}")]
    Log(#[from] DecisionLogError),
}

/// `Decide`: evaluates a decision point and logs the decision.
pub trait Decide {
    /// Decides `request.point`, logs the decision and returns it (POL-030, POL-033, POL-034,
    /// POL-040).
    fn decide(&self, request: &DecideRequest) -> Result<Decided, DecideError>;
}

/// How a person resolves a held decision (POL-042).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Resolution {
    /// Proceed.
    Allow,
    /// Refuse.
    Deny,
}

/// Why a held decision could not be resolved.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ResolveError {
    /// The log entry is not a `hold`.
    #[error("entry {0} is not a held decision")]
    NotHeld(u64),
    /// The hold already has a resolution.
    #[error("entry {0} is already resolved")]
    AlreadyResolved(u64),
    /// The log failed.
    #[error("decision log: {0}")]
    Log(#[from] DecisionLogError),
}

/// The Policy use cases wired to their driven ports.
pub struct PolicyService<S, E, L> {
    source: S,
    engine: E,
    log: L,
}

impl<S: PolicySource, E: PolicyEngine, L: DecisionLog> PolicyService<S, E, L> {
    /// A service over the given source, engine and log.
    pub fn new(source: S, engine: E, log: L) -> Self {
        Self { source, engine, log }
    }

    /// The decision log, for reading back entries.
    pub fn log(&self) -> &L {
        &self.log
    }

    /// Resolves the held decision at `held_index`: writes a new decision referencing the first
    /// (POL-042). The caller MUST have established that the person holds the right role;
    /// authorisation is not a Policy concern.
    pub fn resolve_hold(
        &self,
        held_index: u64,
        resolution: Resolution,
        at: AuthorityTime,
    ) -> Result<u64, ResolveError> {
        let held = self.log.read(held_index)?;
        if held.decision.verdict != Verdict::Hold {
            return Err(ResolveError::NotHeld(held_index));
        }
        for i in 0..self.log.len() {
            if self.log.read(i)?.resolves == Some(held_index) {
                return Err(ResolveError::AlreadyResolved(held_index));
            }
        }
        let (verdict, reasons) = match resolution {
            Resolution::Allow => (Verdict::Allow, vec![]),
            Resolution::Deny => (Verdict::Deny, vec!["hold-resolved-deny".to_owned()]),
        };
        let record = DecisionRecord {
            decision: Decision {
                point: held.decision.point,
                verdict,
                reasons,
                obligations: vec![],
                policy: held.decision.policy.clone(),
            },
            input_digest: held.input_digest,
            subject: held.subject,
            at,
            resolves: Some(held_index),
        };
        Ok(self.log.append(&record)?)
    }
}

impl<S: PolicySource, E: PolicyEngine, L: DecisionLog> ComputeEffectivePolicy for PolicyService<S, E, L> {
    fn compute(&self, selector: &LayerSelector) -> Result<EffectivePolicy, ComputeError> {
        let published = self.source.policies(selector)?;
        if published.is_empty() {
            return Err(ComputeError::NoPolicy);
        }
        let docs: Vec<&PolicyDocument> = published.iter().map(|p| &p.document).collect();
        let (controls, findings) = merge_layers(&docs);
        if has_errors(&findings) {
            return Err(ComputeError::Invalid(findings));
        }
        Ok(EffectivePolicy {
            sources: published.iter().map(|p| p.address).collect(),
            controls,
        })
    }
}

impl<S: PolicySource, E: PolicyEngine, L: DecisionLog> Decide for PolicyService<S, E, L> {
    fn decide(&self, request: &DecideRequest) -> Result<Decided, DecideError> {
        let policy = self.compute(&request.selector)?;
        let mut decision = match self.engine.evaluate(request.point, &policy, &request.facts) {
            Ok(d) => d,
            // POL-034: an engine failure never allows.
            Err(error) => Decision {
                point: request.point,
                verdict: request.point.failure_verdict(),
                reasons: vec![format!("engine-failure: {error}")],
                obligations: vec![],
                policy: vec![],
            },
        };
        // Whatever the engine says, the decision is for this point and names this policy.
        decision.point = request.point;
        decision.policy = policy.sources.clone();
        if decision.verdict != Verdict::Allow && decision.reasons.is_empty() {
            decision.reasons.push("unexplained-by-engine".to_owned());
        }
        let record = DecisionRecord {
            decision: decision.clone(),
            input_digest: facts_digest(request.point, &request.facts),
            subject: request.subject.clone(),
            at: request.at,
            resolves: None,
        };
        let log_index = self.log.append(&record)?;
        Ok(Decided { decision, log_index })
    }
}
