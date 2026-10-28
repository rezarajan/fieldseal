# domain

## Overview

Entities, value objects and invariants of the Instrument context (spec section 2): the authored `InstrumentDefinition`, the validated `Instrument` aggregate with its `CompiledInstrument`, controls, codes, layouts, the render plan, findings, versions, units, locales and the rule evaluator. Pure: no I/O, clock or randomness. Depends only on `fieldseal-kernel` (for `Value`, `Decimal`, ids), `thiserror` and the ICU4X crates (compiled CLDR data, used in `locale.rs`).

Spec: [instrument.md](../../../../../docs/reference/spec/instrument.md). ADRs: [0028](../../../../../docs/explanation/adr/0028-clean-architecture.md), [0033](../../../../../docs/explanation/adr/0033-presentation-layouts.md), [0034](../../../../../docs/explanation/adr/0034-internationalisation-and-localisation.md), [0027](../../../../../docs/explanation/adr/0027-salted-instrument-fingerprints.md).

## Interface

Submodules (re-exported from `mod.rs`): `codes`, `compile`, `compiled`, `control`, `definitions`, `element`, `evaluation`, `field_checks`, `finding`, `instrument`, `language`, `layout`, `locale`, `media`, `message`, `metadata`, `num`, `paths`, `published`, `render_plan`, `rules`, `text`, `units`, `version`.

- Aggregate: `Instrument` (read-only `definition()`, `compiled()`, `to_value()`, `code_list()`; `new` is `pub(crate)`), `InstrumentDefinition`.
- Compilation: `compile::compile(&InstrumentDefinition) -> (CompiledInstrument, Findings)`; `CompiledInstrument`, `Node`, `NodeKind`, `QuestionNode`.
- Evaluation: `evaluate_record`, `RecordInput`, `Evaluation`, `Verdict`, `Visibility`; `evaluate_field_checks`, `RecordView`, `RaisedCheck`.
- Findings: `Finding`, `Findings`, `FindingKind`, `Severity`.
- Controls: `ControlType` (`V1` catalogue), `Control`, `ControlPresentation`, `Options`.
- Layout and plan: `Layout`, `LayoutStep`, `Container`, `Content`, `WindowClass`, `RenderPlan`, `PlanNode`, `PlanKind`, `PlanQuestion`, `PlanControl`, `PlanVisibility`.
- Versions: `SchemaVersion`, `SchemaRange`, `SemVer`, `IMPLEMENTED_SCHEMA` (1.0.0), `Compatibility`, `check_compatibility`.
- Published: `PublishedInstrument`, `InstrumentLabel`, `FingerprintMismatch`.
- Text and language: `LocalisedText`, `LanguageTag`, `Direction`, `locale::LocaleFormatter`, `message::parse_message`.
- Rule language: see [./rules/README.md](./rules/README.md); `EvaluationLimitExceeded` and `Num` are re-exported.

## Invariants

- An `Instrument` is immutable and obtainable only through `application::validate_instrument` (`Instrument::new` is crate-private); a `Layout` only through `validate_layout`.
- Every `Finding` names the requirement it enforces (for example `INS-126`), a severity and a document path.
- The compiled instrument keeps elements in one pre-order arena with repeats expanded and sibling references rewritten to item paths; layouts must preserve that order (INS-047, INS-214).
- Compilation bounds: `MAX_GROUP_DEPTH` 4, `MAX_NODES` 100,000, `MAX_COMPILED_RULES` 100,000, `MAX_TABLE_ROWS` 10,000; evaluation order must be cycle free (INS-044).
- Media: at most 1 MiB per image and 8 MiB in total; types `image/png`, `image/webp`, `image/svg+xml` (INS-180-183).
- `PublishedInstrument::new` refuses a fingerprint that does not match salt and canonical bytes (INS-103); this crate does not hash, the caller supplies the verify function.
- Rule evaluation uses exact rationals (`Num`), never floating point (INS-046).

## Side Effects

None. No I/O, clock, randomness or global state; ICU4X formatting uses data compiled into the binary.

## Verification

`cargo test -p fieldseal-instrument` (repo-wide: `just test`).
