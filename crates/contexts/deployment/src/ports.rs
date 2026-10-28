//! Driven ports owned by the Deployment context (`docs/reference/spec/deployment.md` §4).
//! Deployment also uses Publishing's `ArtefactRegistry`.

use fieldseal_kernel::crypto::Signature;
use fieldseal_kernel::id::{ContentAddress, Digest};

use crate::domain::{Component, DocumentationBundle, SecretRef, SecretValue, StoredBuild};

/// Errors from [`BuildRegistry`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildRegistryError {
    /// The registry failed.
    #[error("build registry: {0}")]
    Backend(String),
}

/// Stores and serves signed builds.
///
/// Contract: returns the build's digest; a digest always returns the same build.
pub trait BuildRegistry {
    /// Stores a signed build and returns its digest.
    fn store(
        &self,
        component: Component,
        bytes: &[u8],
        signature: Signature,
    ) -> Result<Digest, BuildRegistryError>;

    /// The build with `digest`.
    fn fetch(&self, digest: &Digest) -> Result<Option<StoredBuild>, BuildRegistryError>;
}

/// Errors from [`SecretStore`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretStoreError {
    /// No secret with that reference.
    #[error("secret not found")]
    NotFound,
    /// The caller may not read it.
    #[error("access denied")]
    Denied,
}

/// Resolves secret references at run time inside a component.
///
/// Contract: resolves references only; offers no listing; deployment tooling never
/// calls it (DEP §4).
pub trait SecretStore {
    /// Resolves `reference`.
    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretStoreError>;
}

/// Errors from [`DocumentationSink`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DocumentationSinkError {
    /// Different documentation is already stored for the release.
    #[error("release already has different documentation")]
    Conflict,
    /// The sink failed.
    #[error("documentation sink: {0}")]
    Backend(String),
}

/// Stores a release's documentation next to it.
///
/// Contract: addressed by the release; immutable once stored.
pub trait DocumentationSink {
    /// Stores `bundle`.
    fn store(&self, bundle: &DocumentationBundle) -> Result<(), DocumentationSinkError>;

    /// The documentation for `release`.
    fn fetch(
        &self,
        release: &ContentAddress,
    ) -> Result<Option<DocumentationBundle>, DocumentationSinkError>;
}
