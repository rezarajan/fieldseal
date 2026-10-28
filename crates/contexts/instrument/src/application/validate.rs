//! `ValidateInstrument` (INS §3): from an authoring document, decoded by an adapter into a
//! [`Value`] tree, to a validated [`Instrument`], or every finding.

use fieldseal_kernel::Value;

use super::decode::decode;
use crate::domain::compile::compile;
use crate::domain::finding::{FindingKind, Findings, Severity, at};
use crate::domain::paths::is_segment;
use crate::domain::Instrument;

/// A SHA-256 function, supplied by the format core.
pub type Sha256<'a> = &'a dyn Fn(&[u8]) -> [u8; 32];

/// Optional collaborators for validation.
#[derive(Clone, Copy, Default)]
pub struct ValidationOptions<'a> {
    /// SHA-256, from the format core, to check each media item's declared `sha256` against
    /// its bytes (INS-180). Without it, only the digest's form is checked.
    pub media_digest: Option<Sha256<'a>>,
}

/// A validated instrument with any advisory findings validation noticed on the way.
#[derive(Clone, Debug)]
pub struct Validated {
    /// The instrument.
    pub instrument: Instrument,
    /// Warnings and advice (never errors).
    pub warnings: Findings,
}

/// Validates `document` with default options.
pub fn validate_instrument(document: &Value) -> Result<Validated, Findings> {
    validate_instrument_with(document, ValidationOptions::default())
}

/// Validates `document`: decodes it (rejecting unknown fields, INS-006), compiles it
/// (expanding repeats and `@` rules, INS-047, INS-126), checks every rule and reference, and
/// returns the instrument, or every finding when any is an error.
pub fn validate_instrument_with(document: &Value, options: ValidationOptions<'_>) -> Result<Validated, Findings> {
    let (definition, refs, mut findings) = decode(document);
    let Some(definition) = definition else {
        return Err(findings);
    };
    let (compiled, compile_findings) = compile(&definition);
    findings.extend(compile_findings);

    // Message variables name roster fields or items (INS-084).
    for (doc, vars) in &refs.variables {
        for var in vars {
            let ok = match var.strip_prefix("roster.") {
                Some(field) => is_segment(field),
                None => compiled.node(var).and_then(|n| n.question()).is_some() || compiled.derived_value(var).is_some(),
            };
            if !ok {
                findings.error_of(FindingKind::UnknownItemPath, "INS-084", doc.clone(), format!("`${var}` is neither `$roster.<field>` nor an item path"));
            }
        }
    }
    // Media references resolve (INS-180).
    for (doc, id) in &refs.media {
        if !definition.media.contains_key(id) {
            findings.error_of(FindingKind::UnknownItemPath, "INS-180", doc.clone(), format!("no media `{id}` in spec.media"));
        }
    }
    if let Some(digest) = options.media_digest {
        for (id, m) in &definition.media {
            let hex: String = digest(&m.bytes).iter().map(|b| format!("{b:02x}")).collect();
            if hex != m.sha256 {
                findings.error("INS-180", at(&at("spec.media", id), "sha256"), "the SHA-256 doesn't match the bytes");
            }
        }
    }
    // Atomic groups name questions (INS-031).
    for (doc, path) in &refs.atomic {
        if compiled.question(path).is_none() {
            findings.error_of(FindingKind::UnknownItemPath, "INS-031", doc.clone(), format!("no question at `{path}`"));
        }
    }

    if findings.has_errors() {
        return Err(findings);
    }
    let mut warnings = Findings::new();
    for f in findings {
        if f.severity != Severity::Error {
            warnings.push(f);
        }
    }
    Ok(Validated { instrument: Instrument::new(definition, compiled, document.clone()), warnings })
}
