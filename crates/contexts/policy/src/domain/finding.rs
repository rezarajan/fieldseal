//! Findings: what validation and merging report, with requirement ID, severity and path.

use std::fmt;

/// How serious a finding is.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    /// Worth knowing; the policy is still usable.
    Warning,
    /// The policy MUST NOT be used.
    Error,
}

/// One problem found in a policy document or a stack of layers.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Finding {
    /// The requirement or invariant it breaches, for example `POL-002` or `INV-4`.
    pub requirement: &'static str,
    /// How serious it is.
    pub severity: Severity,
    /// Where: a document path (`spec.runtime.pin.minLength`) or a control path
    /// (`runtime.pin.minLength`) when merging.
    pub path: String,
    /// What is wrong.
    pub message: String,
    /// The layer concerned, when the finding comes from merging layers.
    pub layer: Option<String>,
}

impl Finding {
    /// An error.
    pub fn error(requirement: &'static str, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            requirement,
            severity: Severity::Error,
            path: path.into(),
            message: message.into(),
            layer: None,
        }
    }

    /// A warning.
    pub fn warning(requirement: &'static str, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            ..Self::error(requirement, path, message)
        }
    }

    /// Names the layer the finding concerns.
    pub fn in_layer(mut self, layer: impl Into<String>) -> Self {
        self.layer = Some(layer.into());
        self
    }

    /// Whether this finding breaches an invariant floor (`INV-n`).
    pub fn is_invariant_breach(&self) -> bool {
        self.requirement.starts_with("INV-")
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sev = match self.severity {
            Severity::Warning => "warning",
            Severity::Error => "error",
        };
        write!(f, "{sev} [{}] {}", self.requirement, self.path)?;
        if let Some(layer) = &self.layer {
            write!(f, " (layer {layer})")?;
        }
        write!(f, ": {}", self.message)
    }
}

/// Whether any finding is an error.
pub fn has_errors(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity == Severity::Error)
}
