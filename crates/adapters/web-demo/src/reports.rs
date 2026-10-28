//! Plain-data reports of what the demo authority holds, for the web app to render. None of
//! these types serialise themselves: they are `pub` fields all the way down.

use fieldseal_adapters_memory::demo::DemoWorld;
use fieldseal_kernel::crypto::tags;
use fieldseal_kernel::digest::lower_hex;
use fieldseal_publishing::application::VerifyPublication;
use fieldseal_publishing::domain::merkle::{leaf_hash, verify_inclusion};
use fieldseal_publishing::domain::{Publication, SignedCheckpoint};
use fieldseal_trust::domain::TrustStore;

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
    /// Whether the inclusion proof reaches the checkpoint's root.
    pub verified: bool,
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

/// One published artefact, verified offline through the publishing context.
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

/// One leaf of the transparency log and the artefact it logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntryReport {
    /// The leaf index.
    pub index: u64,
    /// The leaf hash, in hex.
    pub leaf_hash: String,
    /// The kind of artefact the entry logs.
    pub kind: String,
    /// The artefact's name.
    pub name: String,
    /// The artefact's version.
    pub version: String,
    /// The artefact's content address, in hex.
    pub address: String,
    /// The signing key that made the entry, in hex.
    pub signer_key_id: String,
}

/// One tenancy in the demo registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationReport {
    /// The tenancy identifier, in hex.
    pub tenancy: String,
    /// The state (`pending`, `registered`, ...).
    pub state: String,
    /// Whether every active key carries hardware-attestation claims. The browser device's
    /// keys never do: the demo never writes claims (TRU-061, TRU-063).
    pub keys_attested: bool,
    /// The four fingerprint words, while the request is pending confirmation.
    pub words: Option<String>,
    /// The label the device gave itself, if any.
    pub label: Option<String>,
    /// The account the tenancy belongs to.
    pub account: String,
    /// The cohorts certified for the tenancy.
    pub cohorts: Vec<String>,
    /// Policy reasons for the current state.
    pub reasons: Vec<String>,
    /// Whether the registry holds a tenancy certificate for it.
    pub certificate: bool,
}

/// Verdict on a checkpoint against the pinned log keys.
pub(crate) fn checkpoint_report(world: &DemoWorld, c: &SignedCheckpoint) -> CheckpointReport {
    CheckpointReport {
        origin: c.origin().to_owned(),
        size: c.size(),
        root_hash: lower_hex(c.root().as_bytes()),
        signature_verified: c.verify(&world.trust.contents().logs, 0).is_ok(),
    }
}

/// Verifies `p` offline and describes it.
pub(crate) fn publication_report(world: &DemoWorld, p: &Publication) -> PublicationReport {
    let verifier = VerifyPublication::new(TrustStore::new(&world.trust), &world.publishing);
    let verified = verifier.verify(p, &[]).map(|_| ()).map_err(|e| e.to_string());
    let statement = p.provenance.statement();
    let store = TrustStore::new(&world.trust);
    let kind = p.artefact.kind();
    let signatures: Vec<SignatureReport> = p
        .signatures
        .iter()
        .map(|s| {
            let certificate = world.trust.certificates_for(&s.signer).next().map(|c| format!("{:?} certificate, serial {}", c.role(), c.serial()));
            let valid = store.verify_signature(&s.signer, &[], &tags::ARTEFACT, &p.signed_structure(), &s.sig, statement.finished).is_ok();
            SignatureReport { key_id: lower_hex(s.signer.as_bytes()), signer_certificate: certificate, valid }
        })
        .collect();
    let required = world.publishing.kinds.get(kind.as_str()).map_or(1, |k| k.publisher_threshold.m.max(1));
    let threshold = ThresholdReport {
        required,
        available: world.trust.publishers_for(kind.as_str()).len() as u64,
        valid_signatures: signatures.iter().filter(|s| s.valid).count() as u64,
    };
    let reviewers = statement.reviewers.iter().map(|r| ReviewerReport { id: r.as_str().to_owned(), decision: "approve".into() }).collect();
    let log_entries = p
        .log
        .iter()
        .map(|r| {
            let leaf = leaf_hash(&r.leaf.leaf(&r.entry));
            InclusionReport {
                log_origin: p.checkpoint.origin().to_owned(),
                signer_key_id: lower_hex(r.entry.key_id().as_bytes()),
                leaf_index: r.inclusion.leaf_index,
                leaf_hash: lower_hex(leaf.as_bytes()),
                tree_size: r.inclusion.tree_size,
                root_hash: lower_hex(p.checkpoint.root().as_bytes()),
                verified: r.inclusion.tree_size == p.checkpoint.size() && verify_inclusion(&leaf, &r.inclusion, p.checkpoint.root()),
            }
        })
        .collect();
    PublicationReport {
        kind: kind.as_str().to_owned(),
        name: p.artefact.name().to_owned(),
        version: p.artefact.version().to_owned(),
        address: lower_hex(p.address().as_bytes()),
        verified,
        signatures,
        threshold,
        reviewers,
        log_entries,
        build: BuildReport {
            builder: statement.builder.0.clone(),
            source: statement.source.uri.clone(),
            revision: statement.source.revision.0.clone(),
            finished_ms: statement.finished.0,
        },
        checkpoint: checkpoint_report(world, &p.checkpoint),
    }
}
