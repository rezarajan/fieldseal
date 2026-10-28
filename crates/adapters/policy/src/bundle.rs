//! The policy layers a bundle carries (POL-050).

use fieldseal_distribution::application::VerifiedBundle;
use fieldseal_policy::domain::{LayerSelector, PublishedPolicy};
use fieldseal_policy::ports::{PolicySource, PolicySourceError};

use crate::in_scope;

/// A [`PolicySource`] over the policy layers of one bundle that passed Distribution's
/// verification: every publication verified, the invariant floors checked (POL-051).
///
/// There is no way to build one from unverified layers except [`BundlePolicySource::new`],
/// which takes layers the caller already holds as [`PublishedPolicy`] values.
#[derive(Clone, Debug)]
pub struct BundlePolicySource {
    layers: Vec<PublishedPolicy>,
}

impl BundlePolicySource {
    /// A source over `layers`, which the caller has verified.
    pub fn new(layers: Vec<PublishedPolicy>) -> Self {
        Self { layers }
    }

    /// The layers of a bundle that passed verification, each under the content address of the
    /// publication that carried it.
    pub fn from_verified(bundle: &VerifiedBundle) -> Result<Self, PolicySourceError> {
        let publications = &bundle.content.policy;
        if publications.len() != bundle.policy.len() {
            // Verification yields one document per publication; anything else is not the
            // output of a verifier.
            return Err(PolicySourceError::Unverified);
        }
        let layers = publications
            .iter()
            .zip(&bundle.policy)
            .map(|(publication, document)| PublishedPolicy { address: *publication.address(), document: document.clone() })
            .collect();
        Ok(Self { layers })
    }
}

impl PolicySource for BundlePolicySource {
    fn policies(&self, selector: &LayerSelector) -> Result<Vec<PublishedPolicy>, PolicySourceError> {
        Ok(in_scope(self.layers.clone(), selector))
    }
}
