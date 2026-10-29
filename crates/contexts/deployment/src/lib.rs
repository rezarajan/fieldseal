//! The Deployment bounded context.
//!
//! Normative behaviour: `docs/reference/spec/deployment.md`. Layering (ADR 0028):
//! - [`domain`]: entities and value objects; pure.
//! - [`application`]: use cases (driving ports).
//! - [`ports`]: driven-port interfaces this context owns; adapters implement them.
//! - [`contract`]: contract tests every adapter of these ports must pass.

pub mod application;
pub mod contract;
pub mod custody;
pub mod docs;
pub mod domain;
pub mod events;
pub mod manifest;
pub mod release;
pub mod render;
pub mod validate;
pub mod ports;
