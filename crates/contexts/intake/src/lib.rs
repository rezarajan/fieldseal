//! The Intake bounded context.
//!
//! Normative behaviour: `docs/reference/spec/intake.md`. Layering (ADR 0028):
//! - [`domain`]: entities and value objects; pure.
//! - [`wire`]: the export manifest, certificates, receipts and payload types intake reads.
//! - [`gate`]: the verification pipeline and landing, in the fixed order of INT-001.
//! - [`landing`], [`data_contract`]: the generic long format, subject state and data contracts.
//! - [`application`]: use cases (driving ports).
//! - [`ports`]: driven-port interfaces this context owns; adapters implement them.
//! - [`contract`]: contract tests every adapter of these ports must pass.

pub mod application;
pub mod contract;
pub mod data_contract;
pub mod domain;
pub mod gate;
pub mod landing;
pub mod ports;
pub mod upload;
pub mod wire;
