//! In-memory adapters for the Deployment context's driven ports.

use std::collections::BTreeMap;
use std::sync::Mutex;

use fieldseal_deployment::domain::{
    Component, DocumentationBundle, SecretRef, SecretValue, StoredBuild,
};
use fieldseal_deployment::ports::{
    BuildRegistry, BuildRegistryError, DocumentationSink, DocumentationSinkError, SecretStore,
    SecretStoreError,
};
use fieldseal_kernel::crypto::Signature;
use fieldseal_kernel::id::{ContentAddress, Digest};

use crate::trust::toy_digest;

/// An in-memory [`BuildRegistry`], addressing builds by a non-cryptographic digest.
#[derive(Default)]
pub struct MemoryBuildRegistry {
    builds: Mutex<BTreeMap<Digest, StoredBuild>>,
}

impl MemoryBuildRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }
}

impl BuildRegistry for MemoryBuildRegistry {
    fn store(
        &self,
        component: Component,
        bytes: &[u8],
        signature: Signature,
    ) -> Result<Digest, BuildRegistryError> {
        let digest = Digest::from(toy_digest(&[bytes]));
        self.builds
            .lock()
            .expect("lock")
            .entry(digest)
            .or_insert(StoredBuild {
                component,
                digest,
                signature,
                bytes: bytes.to_vec(),
            });
        Ok(digest)
    }

    fn fetch(&self, digest: &Digest) -> Result<Option<StoredBuild>, BuildRegistryError> {
        Ok(self.builds.lock().expect("lock").get(digest).cloned())
    }
}

/// An in-memory [`SecretStore`] seeded with fixed secrets.
pub struct MemorySecretStore {
    secrets: BTreeMap<SecretRef, Vec<u8>>,
}

impl MemorySecretStore {
    /// A store holding `secrets`.
    pub fn new(secrets: BTreeMap<SecretRef, Vec<u8>>) -> Self {
        Self { secrets }
    }
}

impl SecretStore for MemorySecretStore {
    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretStoreError> {
        self.secrets
            .get(reference)
            .cloned()
            .map(SecretValue::new)
            .ok_or(SecretStoreError::NotFound)
    }
}

/// An in-memory, immutable [`DocumentationSink`].
#[derive(Default)]
pub struct MemoryDocumentationSink {
    bundles: Mutex<BTreeMap<ContentAddress, DocumentationBundle>>,
}

impl MemoryDocumentationSink {
    /// An empty sink.
    pub fn new() -> Self {
        Self::default()
    }
}

impl DocumentationSink for MemoryDocumentationSink {
    fn store(&self, bundle: &DocumentationBundle) -> Result<(), DocumentationSinkError> {
        let mut bundles = self.bundles.lock().expect("lock");
        match bundles.get(&bundle.release) {
            Some(existing) if existing == bundle => Ok(()),
            Some(_) => Err(DocumentationSinkError::Conflict),
            None => {
                bundles.insert(bundle.release, bundle.clone());
                Ok(())
            }
        }
    }

    fn fetch(
        &self,
        release: &ContentAddress,
    ) -> Result<Option<DocumentationBundle>, DocumentationSinkError> {
        Ok(self.bundles.lock().expect("lock").get(release).cloned())
    }
}
