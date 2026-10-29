//! Compares a roster with the instrument that reads it (DIS-013): shared by `survey check
//! --roster` and `roster check`.

use std::collections::BTreeSet;

use fieldseal_distribution::domain::{Roster, collect_roster_fields};
use fieldseal_instrument::domain::{Finding, FindingKind, Severity};
use fieldseal_kernel::Value;

/// What the roster lacks for the instrument and what it carries that the instrument never reads.
///
/// `instrument` is the expanded document. A field the instrument reads that a subject's
/// `attributes` lack is an error that names the field and the subject's ordinal, not its ID; a
/// field no instrument reads is a note, because the bundle builder drops it (DIS-013).
pub fn compare_roster(roster: &Roster, instrument: &Value) -> Vec<Finding> {
    let mut read = BTreeSet::new();
    collect_roster_fields(instrument, &mut read);
    let mut findings = Vec::new();
    for entry in &roster.entries {
        for field in read.iter().filter(|f| !entry.attributes.contains_key(*f)) {
            findings.push(Finding {
                requirement: "DIS-013",
                severity: Severity::Error,
                kind: FindingKind::SchemaViolation,
                path: format!("subjects[{}].fields", entry.ordinal),
                message: format!("the instrument reads `roster.{field}` and `{field}` is missing for subject {}", entry.ordinal),
            });
        }
    }
    for field in roster.field_names().into_iter().filter(|f| !read.contains(*f)) {
        findings.push(Finding {
            requirement: "DIS-013",
            severity: Severity::Advice,
            kind: FindingKind::Lint,
            path: "subjects[].fields".to_owned(),
            message: format!("the instrument never reads `roster.{field}`; the bundle builder drops it"),
        });
    }
    findings
}
