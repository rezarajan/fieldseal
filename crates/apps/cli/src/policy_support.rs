//! The publishing policy of the local stack: the defaults with the builder and source the
//! stack publishes under (`tools/stack-demo.sh`). Development only; the commands that check
//! published artefacts against the stack (`bundle verify --stack`, `registry`, `intake`,
//! `device capture`) share it.

use fieldseal_policy::domain::Controls;

/// The builder and source the stack's publishing policy allows (`tools/stack-demo.sh`).
pub const BUILDER: &str = "https://ci.example.org/builders/fieldseal-publish";
/// See [`BUILDER`].
pub const SOURCE: &str = "https://git.example.org/authority/artefacts";

/// The publishing policy thresholds of the stack: the defaults with the stack's builder and source.
pub fn publishing_policy() -> fieldseal_policy::domain::PublishingPolicy {
    let mut p = Controls::defaults().publishing();
    p.allowed_builders = vec![BUILDER.into()];
    p.allowed_sources = vec![SOURCE.into()];
    p
}
