//! Rules and field checks as authored (INS §5.5, §5.6).

use fieldseal_kernel::Decimal;

use super::element::Condition;
use super::rules::PathRef;
use super::text::LocalisedText;

/// A reason a collector may give to keep a soft verdict (stored as `override_reason`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Reason {
    /// The code recorded.
    pub code: String,
    /// Its label.
    pub label: LocalisedText,
}

/// What a rule does when its `when` is true.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RuleAction {
    /// Blocks sealing until resolved.
    Hard {
        /// The message shown.
        message: LocalisedText,
    },
    /// Asks again; the collector changes an answer or picks a reason.
    Soft {
        /// The message shown.
        message: LocalisedText,
        /// The reasons offered.
        reasons: Vec<Reason>,
    },
    /// Hides elements (INS-124).
    Skip {
        /// What it hides: element paths, or `@` siblings in a repeat.
        targets: Vec<PathRef>,
    },
    /// Computes a declared derived value (INS-045).
    Derive {
        /// The derived path, declared in `spec.derived`.
        target: PathRef,
        /// The value computed.
        value: Condition,
    },
}

/// The kind of a rule.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RuleKind {
    /// `hard`.
    Hard,
    /// `soft`.
    Soft,
    /// `skip`.
    Skip,
    /// `derive`.
    Derive,
}

impl RuleAction {
    /// The rule's kind.
    pub fn kind(&self) -> RuleKind {
        match self {
            RuleAction::Hard { .. } => RuleKind::Hard,
            RuleAction::Soft { .. } => RuleKind::Soft,
            RuleAction::Skip { .. } => RuleKind::Skip,
            RuleAction::Derive { .. } => RuleKind::Derive,
        }
    }
}

/// A rule as authored.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RuleDef {
    /// Its id, unique within its scope (INS-049).
    pub id: String,
    /// When it applies.
    pub when: Condition,
    /// What it does.
    pub action: RuleAction,
    /// Where it is in the document, for findings.
    pub doc_path: String,
}

/// The expected range of a `distribution` check.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Expected {
    /// A mean and standard deviation: raises when the cohort mean is further than
    /// `bound × sd / √n` from `mean`.
    MeanSd {
        /// The expected mean.
        mean: Decimal,
        /// The expected standard deviation.
        sd: Decimal,
    },
    /// A range: raises when the cohort mean is outside it.
    Range {
        /// The lowest expected mean.
        min: Decimal,
        /// The highest expected mean.
        max: Decimal,
    },
}

/// A field check's type and parameters (INS §5.6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CheckKind {
    /// The cohort's values deviate from the expected range.
    Distribution {
        /// The item.
        path: PathRef,
        /// The expected range.
        expected: Expected,
        /// The fewest values before it can raise.
        min_count: u32,
        /// The number of standard errors allowed (for `{mean, sd}`); 3 when not given.
        bound: Decimal,
    },
    /// Consecutive values move steadily in one direction.
    Drift {
        /// The item.
        path: PathRef,
        /// How many consecutive values to look at.
        window: u32,
        /// The total movement, in the item's unit, beyond which it raises.
        threshold: Decimal,
    },
    /// Two or more subjects' records match.
    Duplicates {
        /// The items compared.
        paths: Vec<PathRef>,
        /// How many must match.
        min_match: u32,
    },
    /// Elapsed capture time is out of bounds.
    Timing {
        /// The shortest plausible capture.
        min_seconds: Option<u64>,
        /// The longest plausible capture.
        max_seconds: Option<u64>,
    },
    /// Too many unanswered items.
    Completeness {
        /// A group path, or explicit item paths.
        scope: CheckScopeDef,
        /// The share of unanswered items above which it raises.
        threshold: Decimal,
    },
    /// One option chosen for too many of a group's items.
    Straightlining {
        /// The group.
        group: PathRef,
        /// The share above which it raises.
        threshold: Decimal,
    },
}

/// The items a completeness check covers.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CheckScopeDef {
    /// Every question in a group.
    Group(PathRef),
    /// These items.
    Paths(Vec<PathRef>),
}

/// A field check as authored (INS-050).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FieldCheckDef {
    /// Its id.
    pub id: String,
    /// Its type and parameters.
    pub kind: CheckKind,
    /// The message shown when it raises.
    pub message: LocalisedText,
    /// Where it is in the document, for findings.
    pub doc_path: String,
}
