//! The factory service's configuration, build inputs and reconciler. The binary
//! `fieldseal-factory` (`src/main.rs`) is the composition root; these modules are a library so
//! that integration tests start the reconciler in process.
//!
//! - [`config`]: the environment variables.
//! - [`inputs`]: what a tenancy's bundle is built from and the digest that says when to rebuild.
//! - [`reconciler`]: builds and stores bundles when the inputs change or the anchor is too old.

pub mod config;
pub mod inputs;
pub mod reconciler;
