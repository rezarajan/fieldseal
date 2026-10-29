//! Plain-data reports of what the Publishing page verified, for the page to render. None of
//! these types serialise themselves: they are `pub` fields all the way down. The report is
//! built in [`crate::publishing`] from a publication, the trust bundle and the publishing
//! policy, never from the log's own claims.

/// One publisher signature on an artefact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureReport {
    /// The signing key's identifier, in hex.
    pub key_id: String,
    /// What the trust bundle certifies the key for (for example `publisher`) and the
    /// certificate's serial, if the bundle holds a certificate for it.
    pub signer_certificate: Option<String>,
    /// Whether the signature verifies against the certified key at the build time.
    pub valid: bool,
}

/// How many publisher signatures an artefact kind needs, and how many publishers exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdReport {
    /// Signatures required by the publishing policy for this kind.
    pub required: u64,
    /// Publishers the trust bundle lists for this kind.
    pub available: u64,
    /// Distinct valid signatures the publication carries.
    pub valid_signatures: u64,
}

/// One reviewer named in the build provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewerReport {
    /// The reviewer's pseudonymous identifier.
    pub id: String,
    /// The decision. Provenance lists approving reviewers only, so this is `approve`.
    pub decision: String,
}

/// One transparency-log entry of a publication and its inclusion proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionReport {
    /// The log origin of the checkpoint the proof is against.
    pub log_origin: String,
    /// The signing key that made the entry, in hex.
    pub signer_key_id: String,
    /// The leaf's position in the log.
    pub leaf_index: u64,
    /// The leaf hash, in hex.
    pub leaf_hash: String,
    /// The size of the tree the proof is against.
    pub tree_size: u64,
    /// The root hash of that tree, in hex.
    pub root_hash: String,
    /// Whether the inclusion proof the publication carries reaches its checkpoint's root.
    pub verified: bool,
    /// Whether the log answers, now, with an inclusion proof for this leaf that reaches the
    /// root of its latest checkpoint. `None` when the log or its checkpoint could not be read.
    pub held_by_log: Option<bool>,
}

/// Where and by what an artefact was built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildReport {
    /// The builder's identity.
    pub builder: String,
    /// The source repository.
    pub source: String,
    /// The source revision.
    pub revision: String,
    /// When the build finished, in milliseconds since the epoch.
    pub finished_ms: u64,
}

/// The log's signed tree head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointReport {
    /// The log's origin line.
    pub origin: String,
    /// The tree size.
    pub size: u64,
    /// The root hash, in hex.
    pub root_hash: String,
    /// Whether the checkpoint is signed by the log key pinned in the trust bundle.
    pub signature_verified: bool,
}

/// One published artefact, verified in the app through the publishing context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationReport {
    /// The artefact kind (`Instrument`, `Layout`, `Policy`).
    pub kind: String,
    /// Its name.
    pub name: String,
    /// Its version.
    pub version: String,
    /// The content address, in hex (the fingerprint for an instrument).
    pub address: String,
    /// The verdict of the publishing context's `VerifyPublication` over the whole
    /// publication (provenance, threshold signatures, log inclusion, checkpoint).
    pub verified: Result<(), String>,
    /// The publisher signatures.
    pub signatures: Vec<SignatureReport>,
    /// The signature threshold.
    pub threshold: ThresholdReport,
    /// The reviewers the provenance names.
    pub reviewers: Vec<ReviewerReport>,
    /// The log entries, one per signature.
    pub log_entries: Vec<InclusionReport>,
    /// The build provenance.
    pub build: BuildReport,
    /// The checkpoint the publication's proofs are against.
    pub checkpoint: CheckpointReport,
}
