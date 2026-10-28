# Policy domain

## Overview

The pure core of the Policy bounded context. It models signed policy documents, the schema of every control, layered merging into an effective policy, the invariant floors, decision points and log records, and a typed runtime evaluator. It performs no I/O and reads no clock, randomness or environment (see the module docs in [mod.rs](./mod.rs)). Normative behaviour is in [the Policy spec](../../../../../docs/reference/spec/policy.md); layering follows [ADR 0028](../../../../../docs/explanation/adr/0028-clean-architecture.md). It depends only on `fieldseal-kernel` (ids, `Value`, `AuthorityTime`) and `sha2`.

## Interface

All items are re-exported from `domain` (`mod.rs`); submodules are public.

- Documents: `decode_document(&Value) -> Decoded { document, findings }`, `PolicyDocument`, `Metadata`, `Layer` (`Deployment`, `Programme`, `Instrument`; `rank`, `label`), `InstrumentRef`, `API_VERSION`, `KIND`.
- Schema and controls: `schema::schema()`, `control_spec(path)`, `SCHEMA_VERSION_MAJOR`, `SECTIONS`, `CUSTODY_PURPOSES`; `ControlValue`, `Kind`, `Merge` (`Tighten(Direction)`, `Override`, `Intersect`, `Union`), `Direction`, `Tightness`, `Threshold`, `Argon2Params`; enumerated choices in `choice` (re-exported by glob, plus `ARTEFACT_KINDS`).
- Units: `Duration`, `ByteSize`, `Date`, `Version`, each with `parse` and `Display`.
- Merging: `merge_layers(&[&PolicyDocument]) -> (Controls, Vec<Finding>)`, `EffectivePolicy { sources, controls }` with `factory()`, `runtime()`, `intake()`, `publishing()`; `PublishedPolicy { address, document }`; `diff_documents` returning `ControlChange` with `ChangeDirection` (`Tighter`, `Looser`, `Changed`).
- Typed sections (glob from `sections`): `Controls` (`defaults`, `from_map`, `get`, `iter`, `as_map`), `FactoryPolicy`, `RuntimePolicy`, `IntakePolicy`, `PublishingPolicy` and their sub-policies.
- Invariants: `Invariant` (`INV-1` to `INV-15`, `ALL`, `id`, `has_control`), `check_floors(controls, at)`, and floor constants in `invariant` (for example `MIN_PIN_LENGTH`).
- Findings: `Finding` (`error`, `warning`, `in_layer`, `is_invariant_breach`, `Display`), `Severity`, `has_errors`.
- Decisions: `DecisionPoint` (11 points, `ALL`, `name`, `parse`, `failure_verdict`), `Verdict` (`Allow`, `Deny`, `Hold`, `Flag`), `Obligation`, `Facts` (`BTreeMap<String, Value>`), `Decision`, `Subject`, `DecisionRecord`, `facts_digest`. The facts each point reads are tabulated in the module docs of `decision.rs`.
- Runtime: `RuntimeEvaluator` (`from_effective`, `from_bundle`, `policy`, and question methods such as `pin_length_acceptable`, `lockout_delay`, `session_expired`, `locks_on(LockTrigger)`, `export_allowed`, `retry_delay`, `missing_restrictions`), `AppliedVersions` (`new`, `entries`, `restore`, `check`, `admit`).
- `LayerSelector { programme, instrument }` and the `PolicyEvent` enum (`PolicyPublished`, `PolicyRejected`, `DecisionMade`) are defined in `mod.rs`.

## Invariants

- Decoding collects every finding rather than stopping at the first, and returns a document only when no error was found (`Decoded`). Unknown controls are errors (POL-002).
- Floors live in code: no control can disable one (POL-011). They are checked on each layer's own controls and again on the merged set; a runtime evaluator re-checks them when built.
- Layers must be applied deployment, then programme, then instrument, once each, starting with the deployment layer (POL-020). A later layer that loosens a `Tighten` control is an error naming the control and layer (POL-021). Intersect and union sets combine as the schema declares; unset controls take schema defaults (POL-022).
- Values that cannot be ordered compare as `Looser`.
- `DecisionPoint::failure_verdict` is `Flag` for `intake.accept`, `consent.decide` and `tenancy.late`, and `Hold` for every other point; never `Allow` (POL-034).
- `facts_digest` is deterministic: key-sorted, length-prefixed, domain-separated by a fixed prefix and the point name, SHA-256.
- `AppliedVersions::admit` refuses a version lower than the highest already applied for the same layer and name; re-applying the same version is allowed (POL-052).
- `DecisionRecord` holds only a facts hash, an opaque `Subject` and policy addresses, no personal data (POL-041).

## Side Effects

None. The module is pure: no I/O, clock, randomness, environment or network. Callers supply authority time (`AuthorityTime`) and random draws (`sampleDraw` fact). `AppliedVersions` mutates only its own in-memory map; persisting it is the caller's job. The only static state is the lazily built schema table.

## Verification

`cargo test -p fieldseal-policy` (repo-wide runner: `just test`).
