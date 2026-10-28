# fieldseal-adapters-opa

## Overview

Open Policy Agent adapter for the Policy context's `PolicyEngine` port ([policy spec](../../../docs/reference/spec/policy.md) section 4; [ADR 0011](../../../docs/explanation/adr/0011-policy-as-signed-files.md)). The decision logic is Rego, bundled in this crate and written to mirror the reference engine (`BuiltInPolicyEngine` in `fieldseal-adapters-memory`) rule for rule. The Rust code type-checks the facts, serialises the effective policy, runs OPA and reads the answer back as a `Decision`.

## Interface

Implements `fieldseal_policy::ports::PolicyEngine` for `OpaEngine` (`evaluate(point, policy, facts) -> Result<Decision, PolicyEngineError>`).

| Symbol | Role |
|---|---|
| `OpaEngine` | `OpaEngine::new(OpaConfig)`. |
| `OpaConfig` | `Binary { program, policy, timeout }` (runs `opa eval`) or `Rest { url, timeout }` (OPA server). Constructors: `binary()` (`opa` on `PATH`, bundled Rego, 10 s), `rest(url)` (10 s), `from_setting(setting)` (`http://` or `https://` selects REST, anything else is the `opa` executable path), `with_timeout(limit)`. |
| `REGO` | The bundled Rego source, embedded with `include_str!`. |
| `bundled_policy_dir()` | Path to this crate's `policy/` directory (via `CARGO_MANIFEST_DIR`). |

The Rego lives in `policy/policy.rego` (package `fieldseal.policy`, queried as `data.fieldseal.policy.decision`). It is a data directory, not a code package. It has one section per decision point (`registration.token.issue`, `registration.approve`, `device.add`, `key.roll`, `key.issue`, `bundle.release`, `posture.recheck`, `artefact.publish`, `intake.accept`, `consent.decide`, `tenancy.late`) and a final section that combines them. Verdict precedence is deny, then hold, then flag, then allow; reasons and obligations are sorted so output is deterministic (POL-032). `fieldseal_policy::contract::engine_cases()` is the table both engines must match.

## Invariants

- Fail closed (POL-034): OPA that cannot start, times out, exits non-zero, prints unreadable output, returns an undefined answer or an unknown verdict yields a `PolicyEngineError`; the adapter never returns `allow` from a failure.
- Missing or mistyped facts are errors (`MissingFact`, `BadFact`), never decisions; facts are checked per decision point before OPA sees them. Durations go to Rego in seconds, sizes in bytes, the sample draw and sample rate as decimal strings, dates as `YYYY-MM-DD`.
- A timeout kills the `opa` child process, so evaluation cannot hang.
- The Rego and the reference engine must stay in agreement (shared contract cases).

## Side Effects

- Binary mode: spawns `opa eval --format json --stdin-input --data <policy> data.fieldseal.policy.decision` per decision, writes the input to its stdin, polls for exit, kills on timeout. Reads the policy files from disk through OPA.
- REST mode: blocking HTTP POST (`ureq`, no redirects) to `{url}/v1/data/fieldseal/policy/decision`; responses over 1 MiB are refused.
- Reads the system clock for timeouts (`Instant`). No other filesystem, crypto or state.

## Verification

- Run: `cargo test -p fieldseal-adapters-opa`. Repo-wide: `just test`.
