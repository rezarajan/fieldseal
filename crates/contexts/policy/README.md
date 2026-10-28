# fieldseal-policy

## Overview

The Fieldseal Policy bounded context: signed policy documents, layered merging, invariant floors, decisions and the decision log, per [the Policy spec](../../../docs/reference/spec/policy.md) and [ADR 0028](../../../docs/explanation/adr/0028-clean-architecture.md). It sits in the contexts layer and depends only on `fieldseal-kernel`, `sha2` and `thiserror`. The domain (`src/domain`) and use-case logic are pure; all I/O is behind three driven ports that adapters implement. This README treats `src/` as the crate's code.

## Interface

`lib.rs` exposes five public modules: `domain`, `application`, `ports`, `contract` and `fixtures`. There are no re-exports at the crate root.

- `domain`: entities, value objects, schema, merge, floors, decisions and the runtime evaluator. See [./src/domain/README.md](./src/domain/README.md).
- `application` (driving ports and service):
  - Traits `ValidatePolicy` (`validate`, `validate_stack`), `DiffPolicies` (`diff`), `ComputeEffectivePolicy` (`compute`), `Decide` (`decide`).
  - `PolicyValidator`: pure implementation of validation and diffing.
  - `PolicyService<S, E, L>::new(source, engine, log)`: implements `ComputeEffectivePolicy` and `Decide`; also `log()` and `resolve_hold(held_index, Resolution, at)`.
  - Types `ValidationReport` (`is_valid`, `invariant_breaches`, `rejection_event`), `DecideRequest`, `Decided`, `Resolution`.
  - Errors `ComputeError` (`Source`, `NoPolicy`, `Invalid`), `DecideError` (`Policy`, `Log`), `ResolveError` (`NotHeld`, `AlreadyResolved`, `Log`).
- `ports` (driven ports adapters implement):
  - `PolicyEngine::evaluate(point, &EffectivePolicy, &Facts) -> Result<Decision, PolicyEngineError>`; errors `Timeout`, `UnknownDecisionPoint`, `MissingFact`, `BadFact`, `Backend`.
  - `PolicySource::policies(&LayerSelector) -> Result<Vec<PublishedPolicy>, PolicySourceError>`; errors `Unverified`, `Unavailable`.
  - `DecisionLog`: `append(&DecisionRecord) -> u64`, `read(index)`, `len()`, default `is_empty()`; errors `NotFound`, `Unavailable`. Methods take `&self`, so implementations manage their own interior mutability.
- `contract` (for adapter test modules): `policy_engine_contract`, `policy_source_contract`, `decision_log_contract`, `diff_marks_tighter_and_looser`, plus `EngineCase` and `engine_cases()` covering every decision point.
- `fixtures` (test support, not gated behind a feature): `DocBuilder` (`deployment`, `programme`, `instrument`, `set`, `root_field`, `layer`, `build`), value helpers `text`, `int`, `dec`, `words`, `map`, `facts`, and `default_deployment_policy`, `programme_a_policy`, `empty_deployment_policy`, `effective`, `effective_default`.

## Invariants

- `Decide::decide` always logs: if the log append fails, no decision is returned (`DecideError::Log`, POL-040).
- Engine failure never allows: any `PolicyEngineError` becomes the point's `failure_verdict` (`Hold` or `Flag`) with reason `engine-failure: ...` (POL-034).
- The returned decision's `point` and `policy` are overwritten with the request's point and the effective policy's source addresses; a non-`Allow` decision with no reasons gets `unexplained-by-engine`.
- `compute` fails with `NoPolicy` when the source returns nothing and `Invalid` when merging yields any error finding (loosening, floor breach, bad layer order).
- `resolve_hold` accepts only a log entry whose verdict is `Hold` and which no later entry resolves; it appends a new `Allow` or `Deny` (reason `hold-resolved-deny`) entry with `resolves` set (POL-042). It does not check the caller's role; authorisation is the caller's concern.
- Port contracts (documented on each trait and enforced by `contract`): engines are deterministic and side-effect free; sources return only verified policies, deployment layer first; the decision log is append-only, indices increase by one, entries read back unchanged.
- `validate_stack` merges only when every document decoded.

## Side Effects

None in this crate's own code: it performs no I/O, reads no clock and draws no randomness. Effects occur only through the injected ports: `PolicySource::policies` (reads published policies), `DecisionLog::append` and `read` (the only durable write: appending decision records), and `PolicyEngine::evaluate` (expected to be side-effect free). `resolve_hold` scans the whole log with `read`. Callers supply authority time in `DecideRequest::at`. The `contract` and `fixtures` modules are compiled into the library and panic via asserts on contract failure, so they are intended for tests only.

## Verification

`cargo test -p fieldseal-policy` (repo-wide runner: `just test`). Adapters verify themselves by calling the functions in `contract`.
