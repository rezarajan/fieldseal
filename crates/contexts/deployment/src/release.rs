//! Releases: an immutable tuple of signed component builds and a published manifest,
//! content-addressed (DEP-010, DEP-011, DEP-013).

use std::collections::BTreeMap;

use fieldseal_kernel::Value;
use fieldseal_kernel::cbor;
use fieldseal_kernel::id::ContentAddress;

use crate::domain::{Component, StoredBuild};

/// Why a release can't be created (DEP §3 `CreateRelease`).
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ReleaseError {
    /// The manifest has not been published through PUB (DEP-005).
    #[error("the manifest is not published")]
    UnpublishedManifest,
    /// A build has no valid signature (DEP-010).
    #[error("the {0:?} build is unsigned or its signature does not verify")]
    UnsignedBuild(Component),
    /// A required component has no build.
    #[error("no build for {0:?}")]
    MissingBuild(Component),
    /// Two builds given for one component.
    #[error("two builds for {0:?}")]
    DuplicateBuild(Component),
}

/// An immutable release (DEP-011).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Release {
    /// The release's content address; documentation is stored under it (DEP-032).
    pub address: ContentAddress,
    /// The published manifest's content address.
    pub manifest: ContentAddress,
    /// One build digest per component.
    pub builds: BTreeMap<Component, ContentAddress>,
}

/// The release's canonical value: what its address is computed over.
pub fn release_value(manifest: &ContentAddress, builds: &BTreeMap<Component, ContentAddress>) -> Value {
    Value::Map(BTreeMap::from([
        ("kind".to_owned(), Value::Text("Release".into())),
        ("manifest".to_owned(), Value::Text(manifest.to_text())),
        ("builds".to_owned(), Value::Map(builds.iter().map(|(c, d)| (c.name().to_owned(), Value::Text(d.to_text()))).collect())),
    ]))
}

impl Release {
    /// The canonical value of the release.
    pub fn to_value(&self) -> Value {
        release_value(&self.manifest, &self.builds)
    }

    /// Whether `address` is this release's address.
    pub fn is_address(&self, address: &ContentAddress) -> bool {
        &self.address == address
    }
}

/// The message a build signature covers: a domain prefix, the component and the digest.
pub fn build_signing_message(component: Component, digest: &ContentAddress) -> Vec<u8> {
    let mut m = b"fieldseal.dev/build/v1\0".to_vec();
    m.extend_from_slice(component.name().as_bytes());
    m.push(0);
    m.extend_from_slice(digest.as_bytes());
    m
}

/// `CreateRelease`: one build per `required` component plus a published manifest. `verify`
/// checks a build's signature against the builder keys the deployment trusts (DEP-010).
pub fn create_release(
    manifest: ContentAddress,
    manifest_published: bool,
    builds: &[StoredBuild],
    required: &[Component],
    verify: &dyn Fn(&StoredBuild) -> bool,
) -> Result<Release, ReleaseError> {
    if !manifest_published {
        return Err(ReleaseError::UnpublishedManifest);
    }
    let mut by = BTreeMap::new();
    for b in builds {
        if b.signature.0.is_empty() || !verify(b) {
            return Err(ReleaseError::UnsignedBuild(b.component));
        }
        if by.insert(b.component, ContentAddress::from(*b.digest.as_bytes())).is_some() {
            return Err(ReleaseError::DuplicateBuild(b.component));
        }
    }
    if let Some(c) = required.iter().find(|c| !by.contains_key(c)) {
        return Err(ReleaseError::MissingBuild(*c));
    }
    let bytes = cbor::encode(&release_value(&manifest, &by)).expect("release values encode");
    Ok(Release { address: ContentAddress::of(&bytes), manifest, builds: by })
}
