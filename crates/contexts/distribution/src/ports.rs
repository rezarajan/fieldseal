//! Driven ports owned by the Distribution context (`docs/reference/spec/distribution.md` §4).
//!
//! Distribution also uses ports owned by other contexts: Publishing's `ArtefactRegistry`,
//! Registration's `RegistryStore`, Policy's `Decide` over its `PolicyEngine`, and Trust's
//! `KeyCustody` (the factory's `Signer`) and `RandomSource`. HPKE sealing and signature
//! verification are format-core functions, not ports.

use fieldseal_kernel::crypto::DomainTag;
use fieldseal_kernel::id::{CohortId, KeyId, TenancyId};
use fieldseal_kernel::seal::SealedBox;
use fieldseal_trust::domain::TrustBundle;
use zeroize::Zeroizing;

use crate::domain::{BundleSeq, Roster, RuntimeProfile, SealedBundle, TimeToken};

/// Errors from [`RosterSource`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RosterSourceError {
    /// The tenancy has no assignments.
    #[error("unknown tenancy")]
    UnknownTenancy,
    /// The source is unavailable.
    #[error("roster source: {0}")]
    Unavailable(String),
}

/// The current roster versions for a tenancy's cohorts.
///
/// Contract ([`crate::contract::roster_source_contract`]): for a cohort, the version returned
/// never decreases between calls; an unknown tenancy is an error, not an empty list.
pub trait RosterSource {
    /// Current rosters for every cohort assigned to `tenancy`. They may carry every column the
    /// source has; the builder restricts them to the fields instruments reference (DIS-013).
    fn current_rosters(&self, tenancy: &TenancyId) -> Result<Vec<Roster>, RosterSourceError>;

    /// How many tenancies other than `except` are active for `cohort`, for the
    /// `bundle.release` decision (`activeTenanciesInCohort`).
    fn active_tenancies(&self, cohort: &CohortId, except: &TenancyId) -> Result<u64, RosterSourceError>;
}

/// Errors from [`AnchorSource`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnchorSourceError {
    /// No anchor could be produced.
    #[error("anchor source: {0}")]
    Unavailable(String),
}

/// Authority time statements, signed by the receipt-and-time key (WIRE §6.6).
///
/// Contract ([`crate::contract::anchor_source_contract`]): successive tokens never go back in
/// authority time, and each verifies against the trust bundle.
pub trait AnchorSource {
    /// A fresh time token.
    fn time_token(&self) -> Result<TimeToken, AnchorSourceError>;
}

/// Errors from [`RuntimeProfiles`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// The source is unavailable.
    #[error("runtime profiles: {0}")]
    Unavailable(String),
}

/// What each tenancy's runtime reported at registration: the schema version it implements and
/// its UI reference-catalogue version (DIS-012, DIS-017).
///
/// Contract: returns what was recorded for the tenancy, and `None` for a tenancy it has no
/// record of; never a default.
pub trait RuntimeProfiles {
    /// The profile of `tenancy`'s runtime.
    fn profile(&self, tenancy: &TenancyId) -> Result<Option<RuntimeProfile>, ProfileError>;
}

/// Errors from [`TrustStore`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustStoreError {
    /// The offered trust bundle can't replace the one held (TRU-033).
    #[error("trust bundle can't replace the one held: {0}")]
    NotAcceptable(String),
    /// No trust bundle has been provisioned.
    #[error("no trust bundle provisioned")]
    NotProvisioned,
}

/// The runtime's current trust bundle.
///
/// Contract ([`crate::contract::trust_store_contract`]): replaces the held bundle only with
/// one that passes `TrustBundle::check_update` (newer, same authority, signed by a held root);
/// never returns a bundle it wasn't given.
pub trait TrustStore {
    /// The trust bundle held.
    fn current(&self) -> Result<TrustBundle, TrustStoreError>;

    /// Replaces it with a newer one.
    fn replace(&self, next: TrustBundle) -> Result<(), TrustStoreError>;
}

/// Errors from [`BundleStore`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleStoreError {
    /// A bundle with the same or a higher sequence number is already stored.
    #[error("bundle {offered:?} is not newer than {held:?}")]
    NotNewer {
        /// The latest sequence number held.
        held: BundleSeq,
        /// The sequence number offered.
        offered: BundleSeq,
    },
    /// The store failed.
    #[error("bundle store: {0}")]
    Backend(String),
}

/// Stores sealed bundles exactly as received, at the factory or on the runtime (DIS-033).
///
/// Contract ([`crate::contract::bundle_store_contract`]): stores bytes unchanged; accepts only
/// bundles newer than the latest held for the tenancy; returns the latest by sequence number.
pub trait BundleStore {
    /// Stores a bundle.
    fn put(&self, bundle: &SealedBundle) -> Result<(), BundleStoreError>;

    /// The latest bundle for a tenancy.
    fn latest(&self, tenancy: &TenancyId) -> Result<Option<SealedBundle>, BundleStoreError>;
}

/// Errors from [`AgreementKey`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AgreementError {
    /// The seal is addressed to another key.
    #[error("sealed to another key")]
    WrongRecipient,
    /// The seal couldn't be opened (wrong suite, wrong context, damaged).
    #[error("can't open: {0}")]
    Open(fieldseal_kernel::WireError),
    /// The platform key store failed.
    #[error("key store: {0}")]
    Backend(String),
}

/// The tenancy's agreement key on the runtime. It performs the HPKE key-agreement step inside
/// the platform key store; the private key never leaves it (platform profiles).
///
/// Contract ([`crate::contract::agreement_key_contract`]): opens only seals addressed to
/// [`AgreementKey::key_id`] under the same tag and context; says `WrongRecipient` for a seal
/// to another key before attempting to open it.
pub trait AgreementKey {
    /// The identifier of the public key bundles are sealed to (WIRE-010).
    fn key_id(&self) -> KeyId;

    /// Opens `sealed`, which was sealed under `tag` with `context` bound in (DIS-020). The
    /// plaintext is zeroised when dropped.
    fn open(&self, tag: &DomainTag, context: &[u8], sealed: &SealedBox) -> Result<Zeroizing<Vec<u8>>, AgreementError>;
}
