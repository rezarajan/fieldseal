//! Findings: what validation and lint report about an instrument document.
//!
//! Every finding names the requirement it enforces (for example `INS-126`), a severity, and
//! a path into the authoring document (for example `spec.elements[1].elements[0].control.min`),
//! so an author can find and fix it.

use std::fmt;

/// How serious a finding is.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Severity {
    /// The document is invalid; validation fails.
    Error,
    /// Advisory: likely a mistake, or a SHOULD the document doesn't meet.
    Warning,
    /// Advisory: a suggestion.
    Advice,
}

/// The error classes of `ValidateInstrument` and `ValidateLayout` (INS §3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum FindingKind {
    /// The document doesn't have the required shape or values.
    SchemaViolation,
    /// A control type that isn't in the catalogue.
    UnknownControl,
    /// A reference to an item path, group, code list, table or media id that doesn't exist.
    UnknownItemPath,
    /// A rule over the evaluation bounds, or one that never settles (INS-044).
    UnboundedRule,
    /// A schema range this core can't implement (INS-092).
    IncompatibleSchemaRange,
    /// A layout names an instrument other than the one it is validated against (INS-200).
    FingerprintMismatch,
    /// A layout leaves a question out (INS-202).
    UnplacedQuestion,
    /// A layout places a question or display more than once (INS-202).
    DuplicatePlacement,
    /// A layout places elements out of the instrument's order (INS-214).
    OrderChanged,
    /// A layout carries text other than container titles, or overrides content (INS-203).
    ContentOverride,
    /// A layout chooses a presentation the control doesn't allow (INS-204).
    UnsupportedPresentation,
    /// An advisory lint finding.
    Lint,
}

/// One thing validation or lint found.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Finding {
    /// The requirement enforced, for example `INS-126`.
    pub requirement: &'static str,
    /// How serious it is.
    pub severity: Severity,
    /// The error class.
    pub kind: FindingKind,
    /// Where in the authoring document, for example `spec.elements[0].control.min`.
    pub path: String,
    /// What is wrong, for the author.
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let severity = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Advice => "advice",
        };
        write!(f, "{severity} {} at {}: {}", self.requirement, self.path, self.message)
    }
}

/// An ordered, de-duplicated collection of findings.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Findings {
    items: Vec<Finding>,
}

impl Findings {
    /// No findings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a finding unless an identical one is already present (expanded repeats would
    /// otherwise report a template's problem once per instance).
    pub fn push(&mut self, finding: Finding) {
        if !self.items.contains(&finding) {
            self.items.push(finding);
        }
    }

    /// Adds a [`Severity::Error`] schema violation.
    pub fn error(&mut self, requirement: &'static str, path: impl Into<String>, message: impl Into<String>) {
        self.add(requirement, Severity::Error, FindingKind::SchemaViolation, path, message);
    }

    /// Adds a [`Severity::Error`] of a given kind.
    pub fn error_of(&mut self, kind: FindingKind, requirement: &'static str, path: impl Into<String>, message: impl Into<String>) {
        self.add(requirement, Severity::Error, kind, path, message);
    }

    /// Adds an advisory lint finding.
    pub fn lint(&mut self, requirement: &'static str, severity: Severity, path: impl Into<String>, message: impl Into<String>) {
        self.add(requirement, severity, FindingKind::Lint, path, message);
    }

    /// Adds any finding.
    pub fn add(
        &mut self,
        requirement: &'static str,
        severity: Severity,
        kind: FindingKind,
        path: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.push(Finding { requirement, severity, kind, path: path.into(), message: message.into() });
    }

    /// Whether any finding is an error.
    pub fn has_errors(&self) -> bool {
        self.items.iter().any(|f| f.severity == Severity::Error)
    }

    /// Whether there are no findings at all.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The number of findings.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// The findings, in the order they were found.
    pub fn iter(&self) -> std::slice::Iter<'_, Finding> {
        self.items.iter()
    }

    /// Appends other findings.
    pub fn extend(&mut self, other: Findings) {
        for f in other.items {
            self.push(f);
        }
    }

    /// The findings as a vector.
    pub fn into_vec(self) -> Vec<Finding> {
        self.items
    }
}

impl IntoIterator for Findings {
    type Item = Finding;
    type IntoIter = std::vec::IntoIter<Finding>;
    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

impl<'a> IntoIterator for &'a Findings {
    type Item = &'a Finding;
    type IntoIter = std::slice::Iter<'a, Finding>;
    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

/// `parent.key`, or `key` at the root.
pub fn at(parent: &str, key: &str) -> String {
    if parent.is_empty() { key.to_owned() } else { format!("{parent}.{key}") }
}

/// `parent[index]`.
pub fn idx(parent: &str, index: usize) -> String {
    format!("{parent}[{index}]")
}
