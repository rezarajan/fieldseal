//! The `strict-schema` suite (CLI-043, WIRE-213): the invalid-document corpus in
//! `tests/schema-corpus/`, run through every reader. Each document names, in a comment, the
//! finding it must produce (`# expect: <Kind> <JSON Pointer>`), and passes only when both readers
//! reject it with that finding:
//!
//! - the authoring decoder (`decode`), which checks a compact document against the schema as it
//!   expands it;
//! - the kernel's validator (`fieldseal_kernel::schema::check`) over the decoded document. A
//!   repeated key and a refused value never become a document, so for those two kinds the second
//!   reader is the decoder with no schema (`decode_raw`).
//!
//! The corpus is embedded, so the installed binary needs no files. The generated JSON Schema is
//! checked against the same corpus by the authoring crate's differential test, because the JSON
//! Schema validator is a dev-dependency there.

use fieldseal_adapters_authoring::{Format, LocatedFinding, decode, decode_raw};
use fieldseal_kernel::schema::{self, DocKind, SchemaErrorKind};

use super::harness::Collector;
use super::Unit;

const REQUIREMENTS: [&str; 3] = ["WIRE-210", "WIRE-211", "WIRE-213"];

/// Every document of the corpus: its kind, file name and text.
pub(super) static CORPUS: &[(DocKind, &str, &str)] = &[
    (DocKind::Survey, "coerced-boolean.yaml", include_str!("../../../../../tests/schema-corpus/survey/coerced-boolean.yaml")),
    (DocKind::Survey, "coerced-exponent.yaml", include_str!("../../../../../tests/schema-corpus/survey/coerced-exponent.yaml")),
    (DocKind::Survey, "coerced-leading-zero.yaml", include_str!("../../../../../tests/schema-corpus/survey/coerced-leading-zero.yaml")),
    (DocKind::Survey, "coerced-null.yaml", include_str!("../../../../../tests/schema-corpus/survey/coerced-null.yaml")),
    (DocKind::Survey, "coerced-plus-sign.yaml", include_str!("../../../../../tests/schema-corpus/survey/coerced-plus-sign.yaml")),
    (DocKind::Survey, "coerced-tilde.yaml", include_str!("../../../../../tests/schema-corpus/survey/coerced-tilde.yaml")),
    (DocKind::Survey, "duplicate-question-id.yaml", include_str!("../../../../../tests/schema-corpus/survey/duplicate-question-id.yaml")),
    (DocKind::Survey, "duplicate-question-key.yaml", include_str!("../../../../../tests/schema-corpus/survey/duplicate-question-key.yaml")),
    (DocKind::Survey, "duplicate-top-level.yaml", include_str!("../../../../../tests/schema-corpus/survey/duplicate-top-level.yaml")),
    (DocKind::Survey, "enum-question-type.yaml", include_str!("../../../../../tests/schema-corpus/survey/enum-question-type.yaml")),
    (DocKind::Survey, "enum-scale-per.yaml", include_str!("../../../../../tests/schema-corpus/survey/enum-scale-per.yaml")),
    (DocKind::Survey, "enum-scale-step.yaml", include_str!("../../../../../tests/schema-corpus/survey/enum-scale-step.yaml")),
    (DocKind::Survey, "missing-block-period.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-block-period.yaml")),
    (DocKind::Survey, "missing-categories-ask.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-categories-ask.yaml")),
    (DocKind::Survey, "missing-category-foods.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-category-foods.yaml")),
    (DocKind::Survey, "missing-check-id.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-check-id.yaml")),
    (DocKind::Survey, "missing-check-when.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-check-when.yaml")),
    (DocKind::Survey, "missing-choice-list.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-choice-list.yaml")),
    (DocKind::Survey, "missing-consent-statement-text.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-consent-statement-text.yaml")),
    (DocKind::Survey, "missing-display-text.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-display-text.yaml")),
    (DocKind::Survey, "missing-field-check-message.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-field-check-message.yaml")),
    (DocKind::Survey, "missing-list-item-label.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-list-item-label.yaml")),
    (DocKind::Survey, "missing-list-items.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-list-items.yaml")),
    (DocKind::Survey, "missing-list-other-label.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-list-other-label.yaml")),
    (DocKind::Survey, "missing-question-type.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-question-type.yaml")),
    (DocKind::Survey, "missing-scale-each-to.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-scale-each-to.yaml")),
    (DocKind::Survey, "missing-scale-per.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-scale-per.yaml")),
    (DocKind::Survey, "missing-sections.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-sections.yaml")),
    (DocKind::Survey, "missing-survey-name.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-survey-name.yaml")),
    (DocKind::Survey, "missing-survey-version.yaml", include_str!("../../../../../tests/schema-corpus/survey/missing-survey-version.yaml")),
    (DocKind::Survey, "type-boolean.yaml", include_str!("../../../../../tests/schema-corpus/survey/type-boolean.yaml")),
    (DocKind::Survey, "type-condition.yaml", include_str!("../../../../../tests/schema-corpus/survey/type-condition.yaml")),
    (DocKind::Survey, "type-consent-required.yaml", include_str!("../../../../../tests/schema-corpus/survey/type-consent-required.yaml")),
    (DocKind::Survey, "type-empty-text.yaml", include_str!("../../../../../tests/schema-corpus/survey/type-empty-text.yaml")),
    (DocKind::Survey, "type-entry-keys.yaml", include_str!("../../../../../tests/schema-corpus/survey/type-entry-keys.yaml")),
    (DocKind::Survey, "type-list-items.yaml", include_str!("../../../../../tests/schema-corpus/survey/type-list-items.yaml")),
    (DocKind::Survey, "type-list.yaml", include_str!("../../../../../tests/schema-corpus/survey/type-list.yaml")),
    (DocKind::Survey, "type-number.yaml", include_str!("../../../../../tests/schema-corpus/survey/type-number.yaml")),
    (DocKind::Survey, "type-operand.yaml", include_str!("../../../../../tests/schema-corpus/survey/type-operand.yaml")),
    (DocKind::Survey, "type-scale-step.yaml", include_str!("../../../../../tests/schema-corpus/survey/type-scale-step.yaml")),
    (DocKind::Survey, "type-sections.yaml", include_str!("../../../../../tests/schema-corpus/survey/type-sections.yaml")),
    (DocKind::Survey, "type-survey-id.yaml", include_str!("../../../../../tests/schema-corpus/survey/type-survey-id.yaml")),
    (DocKind::Survey, "type-title.yaml", include_str!("../../../../../tests/schema-corpus/survey/type-title.yaml")),
    (DocKind::Survey, "type-translation.yaml", include_str!("../../../../../tests/schema-corpus/survey/type-translation.yaml")),
    (DocKind::Survey, "unknown-block.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-block.yaml")),
    (DocKind::Survey, "unknown-categories.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-categories.yaml")),
    (DocKind::Survey, "unknown-category.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-category.yaml")),
    (DocKind::Survey, "unknown-check.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-check.yaml")),
    (DocKind::Survey, "unknown-condition-operator.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-condition-operator.yaml")),
    (DocKind::Survey, "unknown-consent-statement.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-consent-statement.yaml")),
    (DocKind::Survey, "unknown-consent.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-consent.yaml")),
    (DocKind::Survey, "unknown-defaults.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-defaults.yaml")),
    (DocKind::Survey, "unknown-display.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-display.yaml")),
    (DocKind::Survey, "unknown-field-check.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-field-check.yaml")),
    (DocKind::Survey, "unknown-food-override.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-food-override.yaml")),
    (DocKind::Survey, "unknown-food.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-food.yaml")),
    (DocKind::Survey, "unknown-group.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-group.yaml")),
    (DocKind::Survey, "unknown-list-item.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-list-item.yaml")),
    (DocKind::Survey, "unknown-list-other.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-list-other.yaml")),
    (DocKind::Survey, "unknown-list.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-list.yaml")),
    (DocKind::Survey, "unknown-nested-question.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-nested-question.yaml")),
    (DocKind::Survey, "unknown-operand-operator.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-operand-operator.yaml")),
    (DocKind::Survey, "unknown-other-text.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-other-text.yaml")),
    (DocKind::Survey, "unknown-question-for-its-type.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-question-for-its-type.yaml")),
    (DocKind::Survey, "unknown-question.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-question.yaml")),
    (DocKind::Survey, "unknown-scale-each.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-scale-each.yaml")),
    (DocKind::Survey, "unknown-scale-step.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-scale-step.yaml")),
    (DocKind::Survey, "unknown-survey-id.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-survey-id.yaml")),
    (DocKind::Survey, "unknown-top-level.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-top-level.yaml")),
    (DocKind::Survey, "unknown-translation.yaml", include_str!("../../../../../tests/schema-corpus/survey/unknown-translation.yaml")),
    (DocKind::Layout, "coerced-boolean.yaml", include_str!("../../../../../tests/schema-corpus/layout/coerced-boolean.yaml")),
    (DocKind::Layout, "coerced-float.yaml", include_str!("../../../../../tests/schema-corpus/layout/coerced-float.yaml")),
    (DocKind::Layout, "coerced-null.yaml", include_str!("../../../../../tests/schema-corpus/layout/coerced-null.yaml")),
    (DocKind::Layout, "coerced-number.yaml", include_str!("../../../../../tests/schema-corpus/layout/coerced-number.yaml")),
    (DocKind::Layout, "duplicate-layout-key.yaml", include_str!("../../../../../tests/schema-corpus/layout/duplicate-layout-key.yaml")),
    (DocKind::Layout, "duplicate-step-key.yaml", include_str!("../../../../../tests/schema-corpus/layout/duplicate-step-key.yaml")),
    (DocKind::Layout, "duplicate-top-level.yaml", include_str!("../../../../../tests/schema-corpus/layout/duplicate-top-level.yaml")),
    (DocKind::Layout, "enum-repeat-as-in-card.yaml", include_str!("../../../../../tests/schema-corpus/layout/enum-repeat-as-in-card.yaml")),
    (DocKind::Layout, "enum-repeat-as.yaml", include_str!("../../../../../tests/schema-corpus/layout/enum-repeat-as.yaml")),
    (DocKind::Layout, "missing-card-contents.yaml", include_str!("../../../../../tests/schema-corpus/layout/missing-card-contents.yaml")),
    (DocKind::Layout, "missing-card-title.yaml", include_str!("../../../../../tests/schema-corpus/layout/missing-card-title.yaml")),
    (DocKind::Layout, "missing-layout-instrument.yaml", include_str!("../../../../../tests/schema-corpus/layout/missing-layout-instrument.yaml")),
    (DocKind::Layout, "missing-layout-name.yaml", include_str!("../../../../../tests/schema-corpus/layout/missing-layout-name.yaml")),
    (DocKind::Layout, "missing-layout-window.yaml", include_str!("../../../../../tests/schema-corpus/layout/missing-layout-window.yaml")),
    (DocKind::Layout, "missing-step-contents.yaml", include_str!("../../../../../tests/schema-corpus/layout/missing-step-contents.yaml")),
    (DocKind::Layout, "missing-step-title.yaml", include_str!("../../../../../tests/schema-corpus/layout/missing-step-title.yaml")),
    (DocKind::Layout, "missing-steps.yaml", include_str!("../../../../../tests/schema-corpus/layout/missing-steps.yaml")),
    (DocKind::Layout, "missing-tab-contents.yaml", include_str!("../../../../../tests/schema-corpus/layout/missing-tab-contents.yaml")),
    (DocKind::Layout, "type-card.yaml", include_str!("../../../../../tests/schema-corpus/layout/type-card.yaml")),
    (DocKind::Layout, "type-content.yaml", include_str!("../../../../../tests/schema-corpus/layout/type-content.yaml")),
    (DocKind::Layout, "type-contents.yaml", include_str!("../../../../../tests/schema-corpus/layout/type-contents.yaml")),
    (DocKind::Layout, "type-element.yaml", include_str!("../../../../../tests/schema-corpus/layout/type-element.yaml")),
    (DocKind::Layout, "type-layout-id.yaml", include_str!("../../../../../tests/schema-corpus/layout/type-layout-id.yaml")),
    (DocKind::Layout, "type-show.yaml", include_str!("../../../../../tests/schema-corpus/layout/type-show.yaml")),
    (DocKind::Layout, "type-step-title.yaml", include_str!("../../../../../tests/schema-corpus/layout/type-step-title.yaml")),
    (DocKind::Layout, "type-steps.yaml", include_str!("../../../../../tests/schema-corpus/layout/type-steps.yaml")),
    (DocKind::Layout, "unknown-card.yaml", include_str!("../../../../../tests/schema-corpus/layout/unknown-card.yaml")),
    (DocKind::Layout, "unknown-element.yaml", include_str!("../../../../../tests/schema-corpus/layout/unknown-element.yaml")),
    (DocKind::Layout, "unknown-group.yaml", include_str!("../../../../../tests/schema-corpus/layout/unknown-group.yaml")),
    (DocKind::Layout, "unknown-layout-id.yaml", include_str!("../../../../../tests/schema-corpus/layout/unknown-layout-id.yaml")),
    (DocKind::Layout, "unknown-nested-card.yaml", include_str!("../../../../../tests/schema-corpus/layout/unknown-nested-card.yaml")),
    (DocKind::Layout, "unknown-repeat.yaml", include_str!("../../../../../tests/schema-corpus/layout/unknown-repeat.yaml")),
    (DocKind::Layout, "unknown-show.yaml", include_str!("../../../../../tests/schema-corpus/layout/unknown-show.yaml")),
    (DocKind::Layout, "unknown-step.yaml", include_str!("../../../../../tests/schema-corpus/layout/unknown-step.yaml")),
    (DocKind::Layout, "unknown-tab.yaml", include_str!("../../../../../tests/schema-corpus/layout/unknown-tab.yaml")),
    (DocKind::Layout, "unknown-top-level.yaml", include_str!("../../../../../tests/schema-corpus/layout/unknown-top-level.yaml")),
];

/// The `# expect: <Kind> <pointer>` comment of a corpus document.
fn expectation(text: &str) -> Result<(SchemaErrorKind, &str), String> {
    let line = text.lines().find_map(|l| l.strip_prefix("# expect:")).ok_or("no `# expect:` comment")?;
    let (kind, pointer) = line.trim().split_once(' ').ok_or("`# expect:` needs a kind and a pointer")?;
    Ok((SchemaErrorKind::parse(kind).ok_or_else(|| format!("`{kind}` is not one of the six kinds"))?, pointer))
}

fn names(findings: &[LocatedFinding], kind: SchemaErrorKind, pointer: &str) -> bool {
    findings.iter().any(|f| f.kind == kind && f.pointer == pointer)
}

fn reject(doc: DocKind, text: &str) -> Result<(), String> {
    let (kind, pointer) = expectation(text)?;
    let wanted = format!("{kind} at {pointer}");
    let e = decode(text.as_bytes(), Format::Yaml).err().ok_or_else(|| format!("the decoder accepts it; wanted {wanted}"))?;
    if !names(&e.findings, kind, pointer) {
        return Err(format!("the decoder reports {:?}; wanted {wanted}", e.findings.iter().map(|f| format!("{} at {}", f.kind, f.pointer)).collect::<Vec<_>>()));
    }
    if matches!(kind, SchemaErrorKind::DuplicateKey | SchemaErrorKind::CoercionRefused) {
        let e = decode_raw(text.as_bytes(), Format::Yaml).err().ok_or_else(|| format!("the decoder without a schema accepts it; wanted {wanted}"))?;
        return if names(&e.findings, kind, pointer) { Ok(()) } else { Err(format!("the decoder without a schema does not report {wanted}")) };
    }
    let value = decode_raw(text.as_bytes(), Format::Yaml).map_err(|e| format!("the document does not decode: {e}"))?;
    if schema::check(&value, doc).iter().any(|f| f.kind == kind && f.pointer == pointer) {
        Ok(())
    } else {
        Err(format!("the kernel validator does not report {wanted}"))
    }
}

fn run(c: &mut Collector, doc: DocKind) {
    for (kind, file, text) in CORPUS.iter().filter(|(k, ..)| *k == doc) {
        c.case(&REQUIREMENTS.map(String::from), format!("{}/{file}", kind.name()), || reject(*kind, text));
    }
}

pub fn units() -> Vec<Unit> {
    vec![
        Unit::new("schema:survey", &["strict-schema"], |c| run(c, DocKind::Survey)),
        Unit::new("schema:layout", &["strict-schema"], |c| run(c, DocKind::Layout)),
    ]
}
