//! Adapters for the Policy context's driven ports (`docs/reference/spec/policy.md` §4):
//!
//! - [`RegistryPolicySource`]: published policies read from the artefact registry, each one
//!   verified with Publishing's `VerifyPublication` before it is returned (POL-004);
//! - [`BundlePolicySource`]: the policy layers a verified bundle carries (POL-050, POL-051);
//! - [`FileDecisionLog`]: an append-only, hash-chained decision log in a file, with an
//!   integrity check (POL-040).

mod bundle;
mod file_log;
mod registry;

pub use bundle::BundlePolicySource;
pub use file_log::{FileDecisionLog, Head, IntegrityError};
pub use registry::RegistryPolicySource;

use fieldseal_policy::domain::{Layer, LayerSelector, PublishedPolicy};

/// Keeps the policies in scope for `selector`: the deployment layer, the selected programme and
/// the selected instrument; outermost layer first (the `PolicySource` contract).
fn in_scope(mut policies: Vec<PublishedPolicy>, selector: &LayerSelector) -> Vec<PublishedPolicy> {
    policies.retain(|p| match &p.document.layer {
        Layer::Deployment => true,
        Layer::Programme(name) => selector.programme.as_deref() == Some(name.as_str()),
        Layer::Instrument(r) => selector.instrument.as_ref() == Some(r),
    });
    policies.sort_by_key(|p| p.document.layer.rank());
    policies
}
