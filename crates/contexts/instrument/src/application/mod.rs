//! Use cases offered by the Instrument context (INS §3).
//!
//! - [`validate_instrument`] (`ValidateInstrument`): from a decoded document to an
//!   [`Instrument`](crate::domain::Instrument), or findings.
//! - [`lint_instrument`] (`LintInstrument`): advisory findings.
//! - [`check_instrument`] (`CheckCompatibility`): against a runtime's control catalogue.
//! - [`evaluate_rules`] (`EvaluateRules`) and [`evaluate_field_checks`]
//!   (`EvaluateFieldChecks`).
//! - [`validate_layout`] (`ValidateLayout`): from a decoded layout document and its
//!   instrument to a [`Layout`](crate::domain::Layout), or findings; [`default_layout`]
//!   (INS-206) and [`select_layout`] (INS-207).
//! - [`lint_layout`] (`LintLayout`): choice-load findings (INS-210–INS-213).
//! - [`compile_render_plan`] (`CompileRenderPlan`) and [`resolve_visibility`]
//!   (`ResolveVisibility`): the render plan (INS-206–INS-208), documented in
//!   [`crate::domain::render_plan`].

pub mod compatibility;
mod decode;
pub mod layout;
pub mod layout_lint;
pub mod lint;
pub mod render;
pub mod validate;

pub use compatibility::{CompatibilityReport, check_against_catalogue, check_instrument};
pub use layout::{LayoutBinding, LayoutOptions, default_layout, select_layout, validate_layout, validate_layout_with};
pub use layout_lint::{LayoutLintThresholds, lint_layout};
pub use lint::lint_instrument;
pub use render::{PlanError, PlanLayout, PlanRequest, compile_render_plan, resolve_visibility};
pub use validate::{Validated, ValidationOptions, validate_instrument, validate_instrument_with};

use crate::domain::evaluation::{Evaluation, RecordInput};
use crate::domain::field_checks::{RaisedCheck, RecordView};
use crate::domain::{EvaluationLimitExceeded, Instrument};

/// `EvaluateRules`: verdicts, visibility, derived values and value problems for one record.
pub fn evaluate_rules(instrument: &Instrument, input: RecordInput<'_>) -> Result<Evaluation, EvaluationLimitExceeded> {
    crate::domain::evaluate_record(instrument, input)
}

/// `EvaluateFieldChecks`: the field checks raised over a set of records.
pub fn evaluate_field_checks(instrument: &Instrument, records: &[RecordView<'_>]) -> Result<Vec<RaisedCheck>, EvaluationLimitExceeded> {
    crate::domain::evaluate_field_checks(instrument, records)
}
