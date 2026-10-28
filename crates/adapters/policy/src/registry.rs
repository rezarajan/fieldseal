//! Published policies read from the artefact registry (POL-004).

use fieldseal_kernel::cbor;
use fieldseal_policy::domain::{LayerSelector, PublishedPolicy, decode_document};
use fieldseal_policy::ports::{PolicySource, PolicySourceError};
use fieldseal_publishing::application::{ProvenanceCheck, VerifyPublication};
use fieldseal_publishing::domain::ArtefactKind;
use fieldseal_publishing::ports::ArtefactRegistry;
use fieldseal_trust::domain::{TrustBundle, TrustStore};

use crate::in_scope;

/// A [`PolicySource`] over an [`ArtefactRegistry`].
///
/// It is configured with the names of the policies in use (the deployment manifest names its
/// policy layers, not the process environment: POL §7). For each name it takes the highest
/// version that verifies: signatures, provenance, transparency-log inclusion and no valid
/// withdrawal (PUB-060). A version that fails is skipped, so a forged or withdrawn newer one
/// cannot hide an older good one but also cannot be used. If a name has publications and none
/// verifies, the source fails with [`PolicySourceError::Unverified`] rather than silently
/// serving less policy.
pub struct RegistryPolicySource<'a> {
    registry: &'a dyn ArtefactRegistry,
    trust: &'a TrustBundle,
    publishing: &'a fieldseal_policy::domain::PublishingPolicy,
    names: Vec<String>,
    provenance: ProvenanceCheck,
}

impl<'a> RegistryPolicySource<'a> {
    /// A source reading `names` from `registry`, verifying against `trust` and `publishing`
    /// with the full provenance check.
    pub fn new(
        registry: &'a dyn ArtefactRegistry,
        trust: &'a TrustBundle,
        publishing: &'a fieldseal_policy::domain::PublishingPolicy,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self { registry, trust, publishing, names: names.into_iter().map(Into::into).collect(), provenance: ProvenanceCheck::Full }
    }

    /// Sets how much provenance to check (a runtime checks only that it describes the artefact).
    #[must_use]
    pub fn with_provenance_check(mut self, check: ProvenanceCheck) -> Self {
        self.provenance = check;
        self
    }

    fn unavailable(e: impl std::fmt::Display) -> PolicySourceError {
        PolicySourceError::Unavailable(e.to_string())
    }
}

impl PolicySource for RegistryPolicySource<'_> {
    fn policies(&self, selector: &LayerSelector) -> Result<Vec<PublishedPolicy>, PolicySourceError> {
        let verifier = VerifyPublication::new(TrustStore::new(self.trust), self.publishing).with_provenance_check(self.provenance);
        let withdrawals = self.registry.withdrawals().map_err(Self::unavailable)?;
        let mut found = Vec::new();
        for name in &self.names {
            let versions = self.registry.list(ArtefactKind::Policy, name).map_err(Self::unavailable)?;
            if versions.is_empty() {
                continue;
            }
            let mut best: Option<PublishedPolicy> = None;
            for (_, address) in versions {
                let Some(publication) = self.registry.get(&address).map_err(Self::unavailable)? else {
                    continue;
                };
                if publication.artefact.kind() != ArtefactKind::Policy || verifier.verify(&publication, &withdrawals).is_err() {
                    continue;
                }
                let Some(document) = cbor::decode(publication.artefact.canonical_bytes())
                    .ok()
                    .and_then(|value| decode_document(&value).document)
                    .filter(|d| &d.metadata.name == name)
                else {
                    continue;
                };
                if best.as_ref().is_none_or(|b| document.metadata.version > b.document.metadata.version) {
                    best = Some(PublishedPolicy { address: *publication.address(), document });
                }
            }
            found.push(best.ok_or(PolicySourceError::Unverified)?);
        }
        Ok(in_scope(found, selector))
    }
}
