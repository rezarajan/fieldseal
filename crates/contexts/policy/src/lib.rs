//! The Policy bounded context.
//!
//! Normative behaviour: `docs/reference/spec/policy.md`. Layering (ADR 0028):
//! - [`domain`]: entities, value objects, the schema, merging, invariants and the typed runtime evaluator; pure.
//! - [`application`]: use cases (driving ports).
//! - [`ports`]: driven-port interfaces this context owns; adapters implement them.
//! - [`contract`]: contract tests every adapter of these ports must pass.

pub mod application;
pub mod contract;
pub mod domain;
pub mod fixtures;
pub mod ports;

