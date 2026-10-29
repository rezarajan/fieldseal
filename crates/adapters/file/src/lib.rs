//! File-backed adapters for development and for running the local stack.
//!
//! **Not for production.** Keys are files in a directory ([`custody::DirCustody`]); the
//! factory's state is a journal on disk ([`store::FileRegistryStore`]); and
//! [`tenancy::FileTenancyRegistry`] lets another process (the upload endpoint) read the
//! factory's registered tenancies from that journal, read-only. Production uses an HSM or
//! KMS custody and a database; the ports are the same (ADR 0028).

pub mod atomic;
pub mod codec;
pub mod rosters;
pub mod submissions;
pub mod custody;
pub mod instruments;
pub mod store;
pub mod tenancy;
