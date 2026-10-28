//! Contract tests for adapters of the Deployment context's driven ports.

use std::collections::BTreeMap;

use fieldseal_kernel::crypto::Signature;
use fieldseal_kernel::id::ContentAddress;

use crate::domain::{Component, DocumentationBundle, SecretRef};
use crate::ports::{
    BuildRegistry, DocumentationSink, DocumentationSinkError, SecretStore, SecretStoreError,
};

/// [`BuildRegistry`]: a digest always returns the build stored under it.
pub fn build_registry_contract<B: BuildRegistry>(make: impl Fn() -> B) {
    let registry = make();
    let a = registry
        .store(Component::Cli, b"build-a", Signature(vec![1]))
        .expect("store");
    let b = registry
        .store(Component::Cli, b"build-b", Signature(vec![2]))
        .expect("store");
    assert_ne!(a, b, "different builds must have different digests");
    let stored = registry.fetch(&a).expect("fetch").expect("present");
    assert_eq!(
        stored.bytes,
        b"build-a".to_vec(),
        "a digest returns its build"
    );
    assert_eq!(stored.digest, a, "the stored build names its digest");
}

/// [`SecretStore`]: resolves known references; never prints secret values. `known` must resolve.
pub fn secret_store_contract<S: SecretStore>(make: impl Fn() -> S, known: SecretRef) {
    let store = make();
    let value = store.resolve(&known).expect("resolve a known reference");
    assert!(
        !format!("{value:?}").contains(&String::from_utf8_lossy(value.expose()).to_string())
            || value.expose().is_empty(),
        "secret values must not appear in debug output"
    );
    assert_eq!(
        store.resolve(&SecretRef("no-such-secret".into())),
        Err(SecretStoreError::NotFound),
        "unknown references fail"
    );
}

/// [`DocumentationSink`]: addressed by release, immutable.
pub fn documentation_sink_contract<D: DocumentationSink>(make: impl Fn() -> D) {
    let sink = make();
    let release = ContentAddress::from([3; 32]);
    let mut files = BTreeMap::new();
    files.insert("index.md".to_owned(), b"# Release".to_vec());
    let bundle = DocumentationBundle { release, files };
    sink.store(&bundle).expect("store");
    sink.store(&bundle)
        .expect("storing the same bundle again is a no-op");
    assert_eq!(
        sink.fetch(&release),
        Ok(Some(bundle.clone())),
        "fetch returns what was stored"
    );
    let mut changed = bundle;
    changed.files.insert("extra.md".into(), vec![]);
    assert_eq!(
        sink.store(&changed),
        Err(DocumentationSinkError::Conflict),
        "documentation is immutable once stored"
    );
}
