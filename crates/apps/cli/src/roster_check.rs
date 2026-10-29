//! Compares a roster with the instrument that reads it (DIS-013), and the surveys a roster's consent
//! covers with the instruments given: shared by `survey check --roster`, `roster check` and
//! `roster issue`.

use std::collections::BTreeSet;

use fieldseal_distribution::domain::{Roster, RosterFinding, collect_roster_fields};
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

/// The surveys a roster file names in `consent-covers` that none of `instruments` is: a typo
/// there would leave every `granted` consent uncovered. Nothing is checked when the file
/// declares none (the factory records the cohort's assigned surveys when it issues the roster).
pub fn coverage_findings(declared: Option<&[String]>, instruments: &[Value]) -> Vec<RosterFinding> {
    let names: Vec<&str> = instruments
        .iter()
        .filter_map(|i| i.as_map()?.get("metadata")?.as_map()?.get("name")?.as_text())
        .collect();
    declared
        .unwrap_or_default()
        .iter()
        .enumerate()
        .filter(|(_, name)| !names.contains(&name.as_str()))
        .map(|(i, name)| RosterFinding {
            path: format!("consent-covers[{}]", i + 1),
            message: format!("`{name}` is not one of the surveys given with --instrument"),
        })
        .collect()
}
