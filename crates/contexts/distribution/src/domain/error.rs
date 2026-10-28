//! Errors of the Distribution context: why a bundle can't be built (§3 `BuildBundle`), why
//! its pieces don't fit together, and why a runtime rejects one (§5.4).

use fieldseal_kernel::error::{ErrorCode, WireError};
use fieldseal_kernel::id::{CohortId, ContentAddress};
use fieldseal_publishing::domain::{ArtefactKind, PublishingError};
use fieldseal_trust::domain::TrustError;

use super::file::MAX_BUNDLE_FILE;
use super::roster::RosterError;

/// The pieces of a bundle don't fit each other or the runtime (DIS-012, DIS-016, DIS-017).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompositionError {
    /// An artefact is not of the kind its place in the bundle needs.
    #[error("artefact {address:?} is a {found}, not a {expected}")]
    WrongKind {
        /// The artefact.
        address: ContentAddress,
        /// What the bundle needs there.
        expected: ArtefactKind,
        /// What it is.
        found: ArtefactKind,
    },
    /// An artefact's canonical bytes lack what the bundle reads from them.
    #[error("artefact {address:?} can't be read")]
    Unreadable {
        /// The artefact.
        address: ContentAddress,
    },
    /// The runtime can't open the instrument (DIS-012, INS-092).
    #[error("instrument {address:?} is incompatible with the runtime: {reason}")]
    IncompatibleSchema {
        /// The instrument.
        address: ContentAddress,
        /// Why.
        reason: String,
    },
    /// A layout is bound to an instrument that is not in the bundle (DIS-016, INS-200).
    #[error("layout {layout:?} is bound to an instrument the bundle doesn't carry")]
    LayoutNotBound {
        /// The layout.
        layout: ContentAddress,
    },
    /// A second layout for the same instrument and window class (DIS-016, INS-207).
    #[error("layout {layout:?} repeats a window class for its instrument")]
    DuplicateLayoutClass {
        /// The layout.
        layout: ContentAddress,
    },
    /// A localisation's reference version isn't the runtime build's (DIS-017).
    #[error("localisation {address:?} doesn't match the runtime's reference catalogue")]
    LocalisationReference {
        /// The localisation.
        address: ContentAddress,
    },
}

/// Why a use case of the factory side failed (distribution §3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DistributionError {
    /// The tenancy isn't registered (DIS-001).
    #[error("tenancy not registered")]
    NotRegistered,
    /// Policy or the tenancy's state withheld the bundle (DIS-002, DIS-003).
    #[error("withheld: {0:?}")]
    Withheld(Vec<String>),
    /// An artefact isn't published, is withdrawn, or doesn't verify (DIS-011).
    #[error("artefact {address:?} is not published: {reason}")]
    ArtefactNotPublished {
        /// The artefact.
        address: ContentAddress,
        /// Why.
        reason: String,
    },
    /// The instrument needs a schema the runtime doesn't support (DIS-012).
    #[error("incompatible schema: {0}")]
    IncompatibleSchema(String),
    /// The pieces don't fit together (DIS-016, DIS-017).
    #[error("composition: {0}")]
    Composition(CompositionError),
    /// A roster doesn't match the tenancy's cohorts and generations (DIS-014).
    #[error("roster for cohort {cohort:?}: {reason}")]
    Roster {
        /// The cohort.
        cohort: CohortId,
        /// Why.
        reason: String,
    },
    /// The built file would exceed the size limit.
    #[error("bundle of {size} bytes exceeds the limit of {limit}")]
    TooLarge {
        /// The size.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// A driven port failed.
    #[error("{port}: {reason}")]
    Port {
        /// Which port.
        port: &'static str,
        /// What it said.
        reason: String,
    },
    /// The bundle could not be assembled, sealed or signed.
    #[error("wire: {0}")]
    Wire(WireError),
    /// The bundle failed verification on import.
    #[error("bundle rejected: {0}")]
    Rejected(BundleRejection),
}

impl From<CompositionError> for DistributionError {
    fn from(e: CompositionError) -> Self {
        match e {
            CompositionError::IncompatibleSchema { address, reason } => {
                Self::IncompatibleSchema(format!("{address:?}: {reason}"))
            }
            other => Self::Composition(other),
        }
    }
}

impl From<BundleRejection> for DistributionError {
    fn from(e: BundleRejection) -> Self {
        Self::Rejected(e)
    }
}

/// The checks of DIS-030, in order. A rejection says which one failed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum VerifyStep {
    /// Size and a well-formed envelope (WIRE-093).
    Envelope,
    /// The factory signature, chained to the trust bundle.
    Signature,
    /// Opening the seal with the agreement key.
    Open,
    /// Strict decoding and the bundle's own consistency: tenancy, certificate, time token.
    Content,
    /// The bundle sequence number.
    Sequence,
    /// Each artefact's signatures, provenance, log inclusion and withdrawal status.
    Artefacts,
    /// Instrument schema, layouts and localisations against the runtime.
    Compatibility,
    /// Roster contents, versions and generations.
    Rosters,
}

/// The one-line reason shown to the collector (DIS-031).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CollectorReason {
    /// The bundle is for another device.
    WrongDevice,
    /// The bundle is older than the one held.
    OlderVersion,
    /// The bundle is damaged or can't be trusted.
    Damaged,
    /// The bundle needs something this app doesn't support.
    Unsupported,
}

impl CollectorReason {
    /// The message ID, for a runtime's message catalogue (ADR 0034).
    pub fn message_id(self) -> &'static str {
        match self {
            Self::WrongDevice => "bundle-rejected-wrong-device",
            Self::OlderVersion => "bundle-rejected-older-version",
            Self::Damaged => "bundle-rejected-damaged",
            Self::Unsupported => "bundle-rejected-unsupported",
        }
    }

    /// The default English line.
    pub fn text(self) -> &'static str {
        match self {
            Self::WrongDevice => "This bundle is for a different device.",
            Self::OlderVersion => "This bundle is older than the one already on this device.",
            Self::Damaged => "This bundle is damaged or can't be trusted.",
            Self::Unsupported => "This bundle needs a newer version of the app.",
        }
    }
}

/// Why a runtime rejected a bundle (DIS-030). Nothing from a rejected bundle is used, and the
/// previously held bundle is kept (DIS-031).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleRejection {
    /// The file is over the size limit.
    #[error("bundle of {size} bytes exceeds the limit of {limit}")]
    TooLarge {
        /// The size.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// The envelope isn't a well-formed bundle file.
    #[error("malformed bundle file: {0}")]
    Malformed(WireError),
    /// The factory signature, signer or chain didn't verify against the trust bundle.
    #[error("signature: {0}")]
    Signature(TrustError),
    /// The seal is addressed to another key.
    #[error("sealed to another device")]
    WrongRecipient,
    /// The seal couldn't be opened.
    #[error("can't open the seal: {0}")]
    Open(WireError),
    /// The contents aren't a well-formed `BundleContent`.
    #[error("malformed contents: {0}")]
    Content(WireError),
    /// The bundle is for another tenancy.
    #[error("bundle is for another tenancy")]
    WrongTenancy,
    /// The tenancy certificate or time token doesn't hold up.
    #[error("{0}")]
    Certificate(String),
    /// The sequence number isn't greater than the last one held.
    #[error("bundle sequence {offered} is not newer than {held}")]
    NotNewer {
        /// The sequence held.
        held: u64,
        /// The sequence offered.
        offered: u64,
    },
    /// An artefact failed publication verification.
    #[error("artefact {address:?}: {error}")]
    Artefact {
        /// The artefact.
        address: ContentAddress,
        /// Why.
        error: PublishingError,
    },
    /// An artefact is on the withdrawal list.
    #[error("artefact {0:?} has been withdrawn")]
    Withdrawn(ContentAddress),
    /// An instrument's fingerprint doesn't match its salt and bytes (INS-103).
    #[error("instrument {0:?} doesn't match its fingerprint")]
    Fingerprint(ContentAddress),
    /// The pieces don't fit each other or this runtime.
    #[error("{0}")]
    Composition(CompositionError),
    /// The runtime policy is invalid (POL-051).
    #[error("runtime policy: {0}")]
    Policy(String),
    /// A roster carries a field no instrument references (DIS-013).
    #[error("roster for {cohort:?} carries the unreferenced field `{field}`")]
    UnreferencedRosterField {
        /// The cohort.
        cohort: CohortId,
        /// The field.
        field: String,
    },
    /// A roster's generation or version isn't what the certificate or the held roster allows
    /// (DIS-014, DIS-030 step 9).
    #[error("roster for {cohort:?}: {error}")]
    Roster {
        /// The cohort.
        cohort: CohortId,
        /// Why.
        error: RosterError,
    },
    /// A roster's generation isn't the certificate's for the cohort.
    #[error("roster for {cohort:?} has generation {offered}, the certificate says {certified}")]
    StaleGeneration {
        /// The cohort.
        cohort: CohortId,
        /// The roster's generation.
        offered: u32,
        /// The certificate's generation, or `u32::MAX` when the cohort isn't certified.
        certified: u32,
    },
}

impl BundleRejection {
    /// Which check failed.
    pub fn step(&self) -> VerifyStep {
        match self {
            Self::TooLarge { .. } | Self::Malformed(_) => VerifyStep::Envelope,
            Self::Signature(_) => VerifyStep::Signature,
            Self::WrongRecipient | Self::Open(_) => VerifyStep::Open,
            Self::Content(_) | Self::WrongTenancy | Self::Certificate(_) => VerifyStep::Content,
            Self::NotNewer { .. } => VerifyStep::Sequence,
            Self::Artefact { .. } | Self::Withdrawn(_) | Self::Fingerprint(_) | Self::Policy(_) => VerifyStep::Artefacts,
            Self::Composition(_) => VerifyStep::Compatibility,
            Self::UnreferencedRosterField { .. } | Self::Roster { .. } | Self::StaleGeneration { .. } => VerifyStep::Rosters,
        }
    }

    /// The WIRE error code, where the failure has one (WIRE §6.8).
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::TooLarge { .. } => Some(ErrorCode::Size),
            Self::Malformed(e) | Self::Open(e) | Self::Content(e) => Some(e.code),
            Self::Signature(e) => e.code().or(Some(ErrorCode::Sig)),
            Self::WrongRecipient => Some(ErrorCode::Recipient),
            Self::Fingerprint(_) => Some(ErrorCode::Hash),
            Self::NotNewer { .. } => Some(ErrorCode::Seq),
            _ => None,
        }
    }

    /// The one-line reason for the collector (DIS-031).
    pub fn collector_reason(&self) -> CollectorReason {
        match self {
            Self::WrongRecipient | Self::WrongTenancy => CollectorReason::WrongDevice,
            Self::NotNewer { .. } | Self::Roster { .. } | Self::StaleGeneration { .. } => CollectorReason::OlderVersion,
            Self::Composition(CompositionError::IncompatibleSchema { .. } | CompositionError::LocalisationReference { .. }) => {
                CollectorReason::Unsupported
            }
            Self::TooLarge { .. } | Self::Policy(_) => CollectorReason::Unsupported,
            _ => CollectorReason::Damaged,
        }
    }
}

/// The size limit as a `usize`, for callers that start from the wire default.
pub const DEFAULT_MAX_SIZE: usize = MAX_BUNDLE_FILE;
