//! Entities, value objects and invariants of the Distribution context
//! (`docs/reference/spec/distribution.md` §2). Pure: no I/O, clock, randomness or environment.
//!
//! - [`roster`]: rosters and their consent states (DIS-013, DIS-014).
//! - [`time_token`]: the authority time statement a bundle carries as its anchor.
//! - [`content`]: `BundleContent`, the plaintext inside the seal, and its manifest.
//! - [`file`]: the `FSB1` bundle file and its name (DIS-020–DIS-023).
//! - [`facts`]: what composing a bundle reads from artefacts (DIS-012, DIS-013, DIS-016, DIS-017).
//! - [`error`]: build errors and verification rejections.

pub mod content;
pub mod error;
pub mod facts;
pub mod file;
pub mod roster;
pub mod time_token;

pub use content::{BundleContent, BundleManifest, BundleSeq};
pub use error::{BundleRejection, CollectorReason, CompositionError, DistributionError, VerifyStep};
pub use facts::{InstrumentFacts, LayoutFacts, RuntimeProfile, artefacts_of, check_composition, instrument_facts, layout_facts, localisation_reference};
pub use file::{BundleFile, MAGIC, MAX_BUNDLE_FILE, file_name};
pub use roster::{ConsentState, Roster, RosterEntry, RosterError};
pub use time_token::{AnchorKind, TimeToken, check_publication_tree_head_age};

use fieldseal_kernel::id::{ContentAddress, TenancyId};
use fieldseal_kernel::time::AuthorityTime;

/// A sealed, signed bundle as stored and transferred: the file bytes exactly as built or
/// received (DIS-033), with the identity the stores order and address it by.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SealedBundle {
    /// The bundle's content address: SHA-256 of the file bytes.
    pub address: ContentAddress,
    /// The tenancy it is for.
    pub tenancy: TenancyId,
    /// Its sequence number, kept beside the file so stores can order bundles without opening
    /// them. The factory knows it from building; a runtime knows it after verifying.
    pub seq: BundleSeq,
    /// When the factory issued it (for the file name, DIS-023).
    pub issued: AuthorityTime,
    /// The `FSB1` file.
    pub bytes: Vec<u8>,
}

impl SealedBundle {
    /// Wraps file bytes, computing their address.
    pub fn new(tenancy: TenancyId, seq: BundleSeq, issued: AuthorityTime, bytes: Vec<u8>) -> Self {
        Self { address: ContentAddress::of(&bytes), tenancy, seq, issued, bytes }
    }
}

/// The release decision for one bundle (distribution §2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ReleaseDecision {
    /// Release it; names the policy layers that allowed it (DIS-002).
    Release {
        /// The effective policy's sources.
        policy: Vec<ContentAddress>,
    },
    /// Withhold it, with reasons (DIS-003).
    Withhold {
        /// Why.
        reasons: Vec<String>,
    },
}

/// Domain events of the Distribution context (distribution §2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DistributionEvent {
    /// A bundle was built and released.
    BundleReleased {
        /// The tenancy.
        tenancy: TenancyId,
        /// The bundle.
        bundle: ContentAddress,
        /// The policy layers behind the decision.
        policy: Vec<ContentAddress>,
    },
    /// A bundle was withheld.
    BundleWithheld {
        /// The tenancy.
        tenancy: TenancyId,
        /// Why.
        reasons: Vec<String>,
    },
    /// A bundle was imported on a runtime.
    BundleImported {
        /// The bundle.
        bundle: ContentAddress,
    },
    /// A bundle was rejected on a runtime.
    BundleRejected {
        /// The check that failed.
        step: VerifyStep,
    },
}
