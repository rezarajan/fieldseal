//! Entities, value objects and invariants of the Deployment context
//! (`docs/reference/spec/deployment.md` §2).

use std::collections::BTreeMap;

use fieldseal_kernel::crypto::Signature;
use fieldseal_kernel::id::{ContentAddress, Digest};

/// A reference to a secret, resolved only inside the component that uses it. A manifest
/// holds references, never values.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct SecretRef(pub String);

/// A resolved secret. Its `Debug` output never shows the value.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    /// Wraps a secret.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The secret bytes, for the component that needs them.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

/// The deployable components.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Component {
    /// The factory and portal.
    Factory,
    /// Intake and the upload endpoint.
    Intake,
    /// The publishing pipeline.
    Publishing,
    /// A runtime for one platform.
    Runtime,
    /// The CLI.
    Cli,
}

impl Component {
    /// The component's name in manifests and environment variables.
    pub fn name(self) -> &'static str {
        match self {
            Component::Factory => "factory",
            Component::Intake => "intake",
            Component::Publishing => "publishing",
            Component::Runtime => "runtime",
            Component::Cli => "cli",
        }
    }

    /// Parses a component name.
    pub fn parse(name: &str) -> Option<Self> {
        [Component::Factory, Component::Intake, Component::Publishing, Component::Runtime, Component::Cli]
            .into_iter()
            .find(|c| c.name() == name)
    }

    /// The services a manifest configures through adapters (DEP-040).
    pub const SERVICES: [Component; 3] = [Component::Factory, Component::Intake, Component::Publishing];
}

/// A signed build stored in a build registry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StoredBuild {
    /// The component it builds.
    pub component: Component,
    /// The build's digest.
    pub digest: Digest,
    /// The build signature.
    pub signature: Signature,
    /// The build's bytes.
    pub bytes: Vec<u8>,
}

/// The generated documentation of one release.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DocumentationBundle {
    /// The release it documents.
    pub release: ContentAddress,
    /// Files by relative path.
    pub files: BTreeMap<String, Vec<u8>>,
}

/// A named environment of a deployment.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct EnvironmentName(pub String);
