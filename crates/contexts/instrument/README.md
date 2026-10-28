# fieldseal-instrument

## Overview

The Instrument bounded context: how an instrument (a declarative survey or assessment definition) is validated, linted, checked against a runtime, evaluated against records, and compiled to a render plan. Layering (ADR 0028): `kernel <- contexts <- adapters <- bindings, apps`. This crate depends only on `fieldseal-kernel`, `thiserror` and ICU4X, and performs no I/O, so it is pure; the code lives in `src/`.

Spec: [instrument.md](../../../docs/reference/spec/instrument.md). ADRs: [0028](../../../docs/explanation/adr/0028-clean-architecture.md), [0033](../../../docs/explanation/adr/0033-presentation-layouts.md).

## Interface

`lib.rs` exposes four public modules: `application`, `contract`, `domain`, `ports`.

- Use cases (`application`): see [./src/application/README.md](./src/application/README.md). `validate_instrument`, `lint_instrument`, `check_instrument`, `evaluate_rules`, `evaluate_field_checks`, `validate_layout`, `default_layout`, `select_layout`, `lint_layout`, `compile_render_plan`, `resolve_visibility`.
- Domain model (`domain`): see [./src/domain/README.md](./src/domain/README.md). Key types `Instrument`, `InstrumentDefinition`, `CompiledInstrument`, `Layout`, `RenderPlan`, `Evaluation`, `Findings`, `SchemaVersion`, `PublishedInstrument`.
- Rule language: see [./src/domain/rules/README.md](./src/domain/rules/README.md).
- Port (`ports`): trait `ControlCatalogue`, implemented by adapters and runtimes. Required methods `schema_version()` and `controls()`; provided `supports`, `presentations`, `supports_presentation`, and `renders_language` (the default claims every language, suited to headless catalogues only).
- Contract (`contract`): `control_catalogue_contract(make)` runs the conformance checks every `ControlCatalogue` adapter must pass (schema major >= 1; `supports` agrees with `controls`).
- Errors: validation returns `Findings` (`Finding` with requirement id, `Severity`, `FindingKind`, path); `PlanError::LayoutMismatch`; `EvaluationLimitExceeded`; `FingerprintMismatch`; parse errors `ParseError`.

## Invariants

- Layout validation and rule evaluation are deterministic across platforms (exact arithmetic, no floating point).
- An `Instrument` or `Layout` exists only after successful validation; both are immutable.
- This context does not canonicalise or hash: canonical encoding and fingerprints are format-core functions, supplied by callers (`ValidationOptions::media_digest`, `LayoutBinding`, `PublishedInstrument::new`'s verify closure).
- A `ControlCatalogue` never advertises a control or language it cannot render; `supports` agrees with `controls`.

## Side Effects

None. No file, network, clock or randomness access; adapters implement `ControlCatalogue` and decode authoring documents (YAML, JSON and the like) into `fieldseal_kernel::Value` before calling in.

## Verification

`cargo test -p fieldseal-instrument` (repo-wide: `just test`).
