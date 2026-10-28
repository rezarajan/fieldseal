//! The Distribution bounded context.
//!
//! Normative behaviour: `docs/reference/spec/distribution.md`. Layering (ADR 0028):
//! - [`domain`]: entities and value objects, the `FSB1` bundle file and `BundleContent`; pure.
//! - [`application`]: use cases (driving ports): `BuildBundle`, `VerifyBundle` and
//!   `ImportBundle`, `FetchBundle`, `DownloadBundle`, and the release policy.
//! - [`ports`]: driven-port interfaces this context owns; adapters implement them.
//! - [`contract`]: contract tests every adapter of these ports must pass.

pub mod application;
pub mod contract;
pub mod domain;
pub mod ports;
