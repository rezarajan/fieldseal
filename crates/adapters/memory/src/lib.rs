//! In-memory adapters for every driven port (ADR 0003, ADR 0028).
//!
//! These adapters keep all state in memory and are deterministic. They are used by
//! tests, by `fieldseal device simulate`, and as the reference for contract tests.
//! Anything they produce that a real adapter would attest is marked unattested.

pub mod trust;
pub mod instrument;
pub mod policy;
pub mod publishing;
pub mod registration;
pub mod distribution;
pub mod collection;
pub mod delivery;
pub mod delivery_world;
pub mod intake;
pub mod deployment;
pub mod demo;
pub mod bundle_opener;
pub mod conformance;
