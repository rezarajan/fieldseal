# application

## Overview

The use cases (driving ports) of the Instrument context, as plain functions over domain types (spec section 3). Each takes already-decoded values (`fieldseal_kernel::Value` trees from an authoring adapter) and returns domain results or `Findings`. Pure: no I/O. The collaborators that need a hash or fingerprint (SHA-256, layout fingerprint resolution, content addresses) are passed in by the caller from the format core. `decode.rs` is private and turns a `Value` into an `InstrumentDefinition`.

Spec: [instrument.md](../../../../../docs/reference/spec/instrument.md).

## Interface

- `validate_instrument(&Value) -> Result<Validated, Findings>` and `validate_instrument_with(&Value, ValidationOptions)`; `Validated { instrument, warnings }`; `ValidationOptions { media_digest: Option<Sha256> }`.
- `lint_instrument(&Instrument) -> Findings`.
- `check_instrument(&dyn ControlCatalogue, &Instrument) -> CompatibilityReport` and `check_against_catalogue(catalogue, SchemaRange) -> Compatibility`; `CompatibilityReport::is_compatible`, `offered_languages`.
- `evaluate_rules(&Instrument, RecordInput) -> Result<Evaluation, EvaluationLimitExceeded>` and `evaluate_field_checks(&Instrument, &[RecordView]) -> Result<Vec<RaisedCheck>, EvaluationLimitExceeded>` (in `mod.rs`, delegating to the domain).
- `validate_layout(&Value, &Instrument) -> Result<Layout, Findings>`, `validate_layout_with(.., LayoutOptions)` (`LayoutBinding { expected, resolve }`), `default_layout(&Instrument)`, `select_layout(&[&Layout], WindowClass)`.
- `lint_layout(&Instrument, &Layout, LayoutLintThresholds) -> Findings` (defaults 7, 9, 7).
- `compile_render_plan(&Instrument, PlanLayout, PlanRequest) -> Result<RenderPlan, PlanError>` and `resolve_visibility(&Instrument, &RenderPlan, RecordInput) -> Result<PlanVisibility, EvaluationLimitExceeded>`.
- Port used: `ControlCatalogue` (`crate::ports`), by the compatibility check.

## Invariants

- Validation rejects unknown fields everywhere (INS-006), collects every finding rather than stopping at the first, and returns `Ok` only when no finding is an error; warnings and advice travel in `Validated.warnings`.
- Without `media_digest`, only the form of each media `sha256` is checked; with it, the digest is checked against the bytes (INS-180).
- Linting is advisory: it never makes an instrument or layout invalid (layout lint thresholds come from publishing policy).
- `check_instrument` counts `ConsentAttestation` as a used control whenever consent is required, and `is_compatible` needs a matching schema, no unsupported controls or presentations, and at least one renderable language (INS-025, INS-089, INS-092).
- `compile_render_plan` is deterministic: the same instrument, layout and request give the same plan on every platform; it fails with `PlanError::LayoutMismatch` for a layout validated against another instrument (INS-208).
- Layout validation rejects content overrides, unplaced or duplicated questions and reordering (INS-202, INS-203, INS-214).

## Side Effects

None. All use cases are synchronous and pure; the only injected behaviour is the caller's closures (`Sha256`, `LayoutBinding::resolve`) and the `ControlCatalogue` implementation.

## Verification

`cargo test -p fieldseal-instrument` (repo-wide: `just test`).
