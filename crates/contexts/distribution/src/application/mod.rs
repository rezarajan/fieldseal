//! Use cases: the driving ports the Distribution context offers
//! (`docs/reference/spec/distribution.md` §3).
//!
//! - [`build`]: `BuildBundle` (factory side).
//! - [`release`]: the release policy `BuildBundle` applies (DIS-001–DIS-004).
//! - [`fetch`]: `FetchBundle` and `DownloadBundle`.
//! - [`verify`]: `VerifyBundle` and `ImportBundle` (runtime side), the hook the Collection
//!   core imports bundles through.

pub mod build;
pub mod fetch;
pub mod release;
pub mod verify;

pub use build::{BuildBundle, BuildRequest, BuiltBundle, BundleBuilder, FactoryIdentity, FactoryPorts};
pub use fetch::{BundleDelivery, BundleFetchResponse, DownloadBundle, FetchBundle};
pub use release::{Released, check_state, decide_release, release_facts};
pub use verify::{BundleImporter, HeldRoster, HeldState, ImportBundle, ImportRecord, ImportState, VerifiedBundle, VerifyBundle};
