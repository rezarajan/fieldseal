//! The Registration bounded context.
//!
//! Normative behaviour: `docs/reference/spec/registration.md`. Layering (ADR 0028):
//! - [`domain`]: entities, value objects, wire forms and pure checks;
//! - [`application`]: the use cases (driving ports), as methods of
//!   [`application::Factory`];
//! - [`ports`]: driven-port interfaces this context owns; adapters implement them;
//! - [`contract`]: contract tests every adapter of these ports must pass.

pub mod application;
pub mod contract;
pub mod domain;
pub mod ports;
