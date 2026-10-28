//! Entities, value objects and invariants of the Trust context (`docs/reference/spec/trust.md` §2).
//!
//! Authority trust material is split by concept: [`purpose`] (key roles, the tags each may
//! sign, validity limits), [`certificate`] (requests and key certificates), [`revocation`],
//! [`bundle`] (trust bundles), [`chain`] (verification against a bundle), [`root`] (the
//! ceremony and its threshold) and [`period`] (collection periods and record-key lifetime).
//! Device keys and attestation follow.

use fieldseal_kernel::id::{KeyId, Nonce};
use fieldseal_kernel::time::AuthorityTime;

pub mod bundle;
pub mod certificate;
pub mod chain;
pub mod custody;
pub mod error;
pub mod period;
pub mod purpose;
pub mod revocation;
pub mod root;
mod wire;

pub use bundle::{BundleSignature, BundleVersion, LogPin, RuntimeBuild, TrustBundle, TrustBundleContents, UnsignedTrustBundle};
pub use certificate::{AuthorityPublicKey, CertificateRequest, IssueTerms, KeyCertificate, UnsignedCertificate};
pub use chain::TrustStore;
pub use custody::{
    Assurance, AuditFinding, AuditIssue, Custody, CustodyMinimum, IssuanceRecord, Means, Mode, RootTier, admit, audit, check_hot_key_terms,
    check_rotation, establish,
};
pub use error::TrustError;
pub use period::{CollectionPeriod, RecordKeyTerms, Retention};
pub use purpose::{KeyAlgorithm, KeyRole, ValidityLimit, may_open, may_sign, signer_role, validity_limit};
pub use revocation::{Revocation, RevocationReason, RevocationTarget, UnsignedRevocation};
pub use root::{Ceremony, CeremonyRecord, Threshold};

/// Where a key is stored, as attested (TRU §6.3). `Software` means unattested.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum SecurityLevel {
    /// A software key: never attested, never accepted in production (TRU-061).
    Software,
    /// A trusted execution environment.
    Tee,
    /// A TPM.
    Tpm,
    /// A secure element.
    SecureElement,
    /// Android StrongBox.
    StrongBox,
}

/// The kinds of key a device generates per tenancy.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DeviceKeyKind {
    /// P-256 signing key.
    Signing,
    /// P-256 key-agreement key.
    Agreement,
    /// AES-256 key that wraps the session secret.
    Wrapping,
}

/// How a device key is protected.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyProtection {
    /// The key is usable only while the device is unlocked.
    pub unlocked_required: bool,
}

/// An opaque handle to a key inside a device's key store.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct KeyHandle(pub String);

/// Verified-boot state, as attested.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BootState {
    /// Verified boot with the vendor's keys.
    Verified,
    /// Verified boot with a self-signed image.
    SelfSigned,
    /// No verified boot.
    Unverified,
}

/// Platform-specific bytes proving where and how a device key was created.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AttestationEvidence {
    /// The evidence format, for example `android-key-attestation` (TRU §6.2).
    pub format: String,
    /// The format-specific evidence bytes.
    pub data: Vec<u8>,
}

/// Platform-neutral facts verified from evidence (TRU §6.3). The device-only claims
/// (`unlocked_required`, `app_id`, `app_version`, `boot_state`, `bootloader_locked`) are
/// present only when the evidence format establishes them, and absent otherwise (TRU-063,
/// TRU-118). Only an
/// [`crate::ports::AttestationVerifier`] produces these.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AttestationClaims {
    /// Where the key lives.
    pub security_level: SecurityLevel,
    /// The key was generated inside the store.
    pub origin_generated: bool,
    /// Operations the key permits.
    pub kind: DeviceKeyKind,
    /// The key works only while the device is unlocked.
    pub unlocked_required: Option<bool>,
    /// The challenge bound into the evidence.
    pub challenge: Nonce,
    /// Runtime identity.
    pub app_id: Option<String>,
    /// Runtime build version.
    pub app_version: Option<String>,
    /// Platform security patch level, as `YYYY-MM-DD`.
    pub os_patch_level: Option<String>,
    /// Verified-boot state.
    pub boot_state: Option<BootState>,
    /// Bootloader lock state.
    pub bootloader_locked: Option<bool>,
    /// Device serial, only when the platform attests it.
    pub device_serial: Option<String>,
}

impl AttestationClaims {
    /// Whether these claims come from hardware-backed attestation.
    pub fn is_attested(&self) -> bool {
        self.security_level != SecurityLevel::Software
    }
}

/// A pseudonymous reference to the person who holds a key or reviews artefacts.
/// Meaningful only inside the private [`crate::ports::KeyHolderRegistry`] (TRU-092).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct PersonRef(pub String);

/// The span during which a person holds a key; either end may be open.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct HoldingBounds {
    /// The holding starts at this time; `None` means from the beginning.
    pub not_before: Option<fieldseal_kernel::time::AuthorityTime>,
    /// The holding ends at this time (exclusive); `None` means it has not ended.
    pub not_after: Option<fieldseal_kernel::time::AuthorityTime>,
}

impl HoldingBounds {
    /// Whether the holding is in force at `at`.
    pub fn covers(&self, at: fieldseal_kernel::time::AuthorityTime) -> bool {
        self.not_before.is_none_or(|start| start <= at) && self.not_after.is_none_or(|end| at < end)
    }
}

/// One recorded holding: a person holds a key for a span. Private to the authority; never
/// placed in a certificate, bundle, log entry or export (TRU-094).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyHolding {
    /// The key.
    pub key: KeyId,
    /// The opaque reference to its holder.
    pub holder: PersonRef,
    /// When the holder holds it.
    pub bounds: HoldingBounds,
}

/// Who is asking the key-holder registry, and with what authority.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccessContext {
    /// The authenticated caller.
    pub caller: String,
    /// Whether the caller holds the custodian or auditor role required to resolve holders.
    pub may_resolve_holders: bool,
}

/// One recorded use of an authority key (KeyCustody's use log): key ID, role and caller,
/// never key material or plaintext (TRU §7, logs).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyUse {
    /// The key used.
    pub key: KeyId,
    /// The key's role.
    pub role: KeyRole,
    /// What it was used for.
    pub operation: KeyOperation,
    /// The identity of the caller.
    pub caller: String,
}

/// Operations on an authority key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum KeyOperation {
    /// A signature.
    Sign,
    /// An HPKE open (decapsulation and decryption).
    Open,
}

/// A newly generated authority key, as reported by key custody.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CustodyKey {
    /// Its identifier.
    pub id: KeyId,
    /// Its public key.
    pub public_key: AuthorityPublicKey,
    /// The one role it may be used for.
    pub role: KeyRole,
}

/// A vendor's revocation status for an attestation certificate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RevocationStatus {
    /// Whether the certificate is revoked.
    pub revoked: bool,
    /// When the status list was retrieved.
    pub retrieved_at: AuthorityTime,
}
