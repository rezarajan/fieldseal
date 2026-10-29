//! Entities, value objects and invariants of the Policy context
//! (`docs/reference/spec/policy.md` §2). Pure: no I/O, clock, randomness or environment.
//!
//! - [`units`]: durations, sizes, dates and versions (POL-003).
//! - [`choice`]: the enumerated control values.
//! - [`control`]: typed control values, kinds, merge rules and the meaning of "tighter".
//! - [`schema`]: every control, its default and merge rule (POL §6.3).
//! - [`document`]: decoding a policy document from a value tree (POL-001, POL-002).
//! - [`invariant`]: the floors in code (POL §6.1).
//! - [`merge`]: layers, the effective policy, diffs (POL-020 to POL-023).
//! - [`sections`]: typed views of `factory`, `runtime`, `intake` and `publishing`.
//! - [`decision`]: decision points, decisions and log records.
//! - [`runtime`]: the typed runtime evaluator (POL-031).

pub mod choice;
pub mod control;
pub mod decision;
pub mod document;
pub mod finding;
pub mod invariant;
pub mod merge;
pub mod runtime;
pub mod schema;
pub mod sections;
pub mod units;

pub use choice::*;
pub use control::{Argon2Params, ControlValue, Direction, Kind, Merge, Threshold, Tightness};
pub use decision::{
    Decision, DecisionPoint, DecisionRecord, Facts, Obligation, Subject, Verdict, facts_digest,
};
pub use document::{Decoded, InstrumentRef, Layer, Metadata, PolicyDocument, decode_document};
pub use finding::{Finding, Severity, has_errors};
pub use invariant::{Invariant, check_floors};
pub use merge::{
    ChangeDirection, ControlChange, EffectivePolicy, PublishedPolicy, describe, diff_documents, merge_layers,
};
pub use runtime::{AppliedVersions, LockTrigger, RuntimeEvaluator};
pub use schema::CUSTODY_PURPOSES;
pub use sections::*;
pub use units::{ByteSize, Date, Duration, Version};

use fieldseal_kernel::id::ContentAddress;

/// Which layers to merge for one decision. The deployment layer always applies.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct LayerSelector {
    /// The programme, if any.
    pub programme: Option<String>,
    /// The instrument, if any.
    pub instrument: Option<InstrumentRef>,
}

/// Domain events of the Policy context (POL §2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PolicyEvent {
    /// A policy was published.
    PolicyPublished {
        /// Its content address.
        address: ContentAddress,
        /// Its name.
        name: String,
        /// Its version.
        version: Version,
    },
    /// A policy was rejected because it breaches an invariant.
    PolicyRejected {
        /// The invariants breached, for example `INV-4`.
        invariants: Vec<&'static str>,
    },
    /// A decision was made and logged.
    DecisionMade {
        /// The log index.
        index: u64,
        /// Where it was made.
        point: DecisionPoint,
        /// The outcome.
        verdict: Verdict,
    },
}
