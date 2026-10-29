//! File-backed adapters for development and for running the local stack.
//!
//! **Not for production.** Keys are files in a directory ([`custody::DirCustody`]); the
//! factory's state is a journal on disk ([`store::FileRegistryStore`]); and
//! [`tenancy::FileTenancyRegistry`] lets another process (the upload endpoint) read the
//! factory's registered tenancies from that journal, read-only. Production uses an HSM or
//! KMS custody and a database; the ports are the same (ADR 0028).
//!
//! Every adapter here is a development adapter: [`custody::DirCustody`],
//! [`store::FileRegistryStore`], [`tenancy::FileTenancyRegistry`], [`registry::FileRegistry`],
//! [`roster_store::RosterStore`] with [`roster_store::FileRosterSource`] and
//! [`roster_issuer::FileRosterIssuer`],
//! [`directories::PublishedSurveys`], [`directories::StoredCohorts`], [`bundles::FileBundleStore`], [`profiles::FileRuntimeProfiles`] and the intake stores
//! ([`rosters`], [`submissions`], [`instruments`]).

pub mod atomic;
pub mod bundles;
pub mod codec;
pub mod custody;
pub mod directories;
pub mod instruments;
pub mod profiles;
pub mod registry;
pub mod roster_issuer;
pub mod roster_store;
pub mod rosters;
pub mod store;
pub mod submissions;
pub mod tenancy;
