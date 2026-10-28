//! The Publishing bounded context.
//!
//! Normative behaviour: `docs/reference/spec/publishing.md`. Layering (ADR 0028):
//! - [`domain`]: entities and value objects; pure.
//! - [`application`]: use cases (driving ports).
//! - [`ports`]: driven-port interfaces this context owns; adapters implement them.
//! - [`contract`]: contract tests every adapter of these ports must pass.

pub mod application;
pub mod contract;
pub mod domain;
pub mod ports;
