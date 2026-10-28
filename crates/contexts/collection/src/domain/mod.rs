//! Entities, value objects and invariants of the Collection context
//! (`docs/reference/spec/collection.md` §2, `platform-profiles.md`).

pub mod bundle;
pub mod capture;
pub mod local;
pub mod meta;
pub mod payload;
pub mod pin;
pub mod ticks;

use std::collections::BTreeMap;

use fieldseal_kernel::KernelError;
use fieldseal_kernel::crypto::Signature;
use fieldseal_kernel::id::{Digest, KeyId, Seq, TenancyId};
use fieldseal_kernel::time::AuthorityTime;

use crate::ports::{ReceiptCheck, ReceiptCheckError};

/// The device-side tenancy's lifecycle.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TenancyState {
    /// Created on the device; not yet registered.
    Local,
    /// Registered with the factory.
    Registered,
    /// Closing (by the collector, or forced by a close certificate).
    Closing,
    /// Closed: closing record sealed.
    Closed,
    /// Keys and local data deleted.
    Erased,
}

/// The collector's runtime PIN. Never stored; its `Debug` output is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct RuntimePin(String);

impl RuntimePin {
    /// The invariant floor on PIN length (POL invariants; ADR 0017).
    pub const MIN_LENGTH: usize = 6;

    /// Accepts at least [`Self::MIN_LENGTH`] decimal digits.
    pub fn new(digits: impl Into<String>) -> Result<Self, KernelError> {
        let digits = digits.into();
        if digits.len() < Self::MIN_LENGTH || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(KernelError::Malformed {
                kind: "RuntimePin",
                reason: "at least 6 decimal digits",
            });
        }
        Ok(Self(digits))
    }

    /// The digits, for passing to the memory-hard hash only.
    pub fn digits(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for RuntimePin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RuntimePin(<redacted>)")
    }
}

/// Why a clear couldn't be confirmed (COL-101).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClearConfirmationError {
    /// The two entries differed.
    #[error("the two PIN entries differ")]
    Mismatch,
    /// The PIN was wrong; counts toward lockout.
    #[error("wrong PIN")]
    WrongPin,
}

/// Proof that the collector confirmed a clear by entering the runtime PIN twice
/// (ADR 0029, COL-101). It can only be created by [`ClearConfirmation::confirm`], is
/// neither `Clone` nor `Copy`, and is consumed by [`plan_clear`], so every clear needs
/// a fresh confirmation.
#[derive(Debug)]
pub struct ClearConfirmation {
    _private: (),
}

impl ClearConfirmation {
    /// Confirms a clear from two separate PIN entries. `verify` checks a PIN against
    /// the session (the use case passes the session's check, which counts failures).
    pub fn confirm(
        first: &RuntimePin,
        second: &RuntimePin,
        verify: impl FnOnce(&RuntimePin) -> bool,
    ) -> Result<Self, ClearConfirmationError> {
        if first != second {
            return Err(ClearConfirmationError::Mismatch);
        }
        if !verify(first) {
            return Err(ClearConfirmationError::WrongPin);
        }
        Ok(Self { _private: () })
    }
}

/// A record's delivery state (see the Delivery context); moves only forward.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum DeliveryState {
    /// Not delivered.
    None,
    /// Handed to an opaque destination; never counts as delivered.
    HandedOver,
    /// Saved to local or removable storage and read back.
    SavedAndChecked,
    /// Covered by a verified authority receipt.
    Received,
}

/// An authority receipt as received, before verification (WIRE §receipt).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReceiptClaim {
    /// The tenancy it acknowledges.
    pub tenancy: TenancyId,
    /// The highest `seq` received.
    pub last_seq: Seq,
    /// The journal hash through `last_seq`.
    pub journal_hash: Digest,
    /// The authority's receive time.
    pub time: AuthorityTime,
    /// The receipt key that signed it.
    pub signer: KeyId,
    /// The canonical signed statement.
    pub statement: Vec<u8>,
    /// The signature over `statement`.
    pub signature: Signature,
}

/// The records a verified receipt covers. It can only be created by
/// [`ReceiptCoverage::verify`], so journal records are deleted only under a receipt
/// that passed [`ReceiptCheck`] (COL-105, COL-106).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReceiptCoverage {
    tenancy: TenancyId,
    through: Seq,
    journal_hash: Digest,
    address: Digest,
    time: AuthorityTime,
}

impl ReceiptCoverage {
    /// Verifies a receipt and, if it checks out, returns what it covers.
    pub fn verify(
        claim: &ReceiptClaim,
        check: &impl ReceiptCheck,
    ) -> Result<Self, ReceiptCheckError> {
        check.verify(claim)?;
        Ok(Self {
            tenancy: claim.tenancy,
            through: claim.last_seq,
            journal_hash: claim.journal_hash,
            address: fieldseal_kernel::digest::sha256(&claim.statement),
            time: claim.time,
        })
    }

    /// The receipt's content address: SHA-256 of its signed statement. A checkpoint names it
    /// as the delivery evidence (WIRE-060), and the receipt anchor uses it (COL-082).
    pub fn address(&self) -> &Digest {
        &self.address
    }

    /// The authority receive time it states.
    pub fn time(&self) -> AuthorityTime {
        self.time
    }

    /// The tenancy covered.
    pub fn tenancy(&self) -> &TenancyId {
        &self.tenancy
    }

    /// The highest `seq` covered.
    pub fn through(&self) -> Seq {
        self.through
    }

    /// The journal hash at `through`.
    pub fn journal_hash(&self) -> &Digest {
        &self.journal_hash
    }
}

/// A checkpoint record's content: what was cleared, and the hash that keeps the
/// journal verifiable (COL-105, COL-107).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Checkpoint {
    /// Records with `seq` at or below this were cleared from the local record.
    pub cleared_through: Seq,
    /// The journal hash at `cleared_through`.
    pub journal_hash: Digest,
}

/// What a clear will do, decided from a confirmation and any verified coverage.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClearPlan {
    /// The checkpoint to seal first.
    pub checkpoint: Checkpoint,
    /// Delete local-record data through this `seq`.
    pub delete_local_through: Seq,
    /// Delete sealed journal records through this `seq`, if any are covered by a receipt.
    pub delete_journal_through: Option<Seq>,
}

/// Plans a clear through `through` (ADR 0029). Always allowed once confirmed; sealed
/// journal records are deleted only as far as a verified receipt for this tenancy
/// covers them, and the rest wait for delivery.
pub fn plan_clear(
    tenancy: &TenancyId,
    through: Seq,
    journal_hash_at_through: Digest,
    confirmation: ClearConfirmation,
    coverage: Option<&ReceiptCoverage>,
) -> ClearPlan {
    let ClearConfirmation { _private: () } = confirmation;
    let delete_journal_through = coverage
        .filter(|c| c.tenancy() == tenancy)
        .map(|c| c.through().min(through));
    ClearPlan {
        checkpoint: Checkpoint {
            cleared_through: through,
            journal_hash: journal_hash_at_through,
        },
        delete_local_through: through,
        delete_journal_through,
    }
}

/// Which multi-step operation a marker belongs to (COL-092).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum OperationKind {
    /// Sealing a record.
    Seal,
    /// Clearing.
    Clear,
    /// Ending the tenancy.
    EndTenancy,
    /// Applying a close certificate.
    ApplyCloseCertificate,
    /// Building an export.
    Export,
}

/// Persisted progress of a multi-step operation, for resumption after a crash.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OperationMarker {
    /// The operation.
    pub kind: OperationKind,
    /// The last step completed.
    pub step: u32,
}

/// Where data is stored on the device (PLAT §Storage).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum StorageClass {
    /// Device-encrypted: available without the runtime PIN (the sealed journal, outbox, markers).
    DeviceEncrypted,
    /// Session-encrypted: readable only inside an unlocked session (local record, rosters).
    SessionEncrypted,
}

/// A stored object's name within its class.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct StorageName(pub String);

/// A UI surface the runtime asks the platform to protect.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct WindowId(pub String);

/// The device restrictions runtime policy can require (`runtime.device.requiredRestrictions`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Restriction {
    /// The runtime can't be uninstalled.
    UninstallBlocked,
    /// The runtime's data can't be cleared, and it can't be force-stopped.
    ClearDataBlocked,
    /// Developer options and debugging are off.
    DebuggingDisabled,
    /// Safe boot is unavailable.
    SafeBootDisabled,
    /// Factory reset from settings is unavailable.
    FactoryResetDisabled,
    /// Backup of the runtime's data is off.
    BackupDisabled,
    /// Content capture and suggestions are off.
    ContentCaptureDisabled,
    /// Only allow-listed input methods may run.
    InputMethodsAllowListed,
    /// Only allow-listed accessibility services may run.
    AccessibilityAllowListed,
}

impl Restriction {
    /// Every restriction.
    pub const ALL: [Restriction; 9] = [
        Self::UninstallBlocked,
        Self::ClearDataBlocked,
        Self::DebuggingDisabled,
        Self::SafeBootDisabled,
        Self::FactoryResetDisabled,
        Self::BackupDisabled,
        Self::ContentCaptureDisabled,
        Self::InputMethodsAllowListed,
        Self::AccessibilityAllowListed,
    ];

    /// The name used in policy files and posture reports (AND-063).
    pub fn name(self) -> &'static str {
        match self {
            Self::UninstallBlocked => "uninstall-blocked",
            Self::ClearDataBlocked => "clear-data-blocked",
            Self::DebuggingDisabled => "debugging-disabled",
            Self::SafeBootDisabled => "safe-boot-disabled",
            Self::FactoryResetDisabled => "factory-reset-disabled",
            Self::BackupDisabled => "backup-disabled",
            Self::ContentCaptureDisabled => "content-capture-disabled",
            Self::InputMethodsAllowListed => "input-methods-allow-listed",
            Self::AccessibilityAllowListed => "accessibility-allow-listed",
        }
    }
}

/// A restriction's state, read from live platform state (PLAT-042).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RestrictionState {
    /// In force.
    InForce,
    /// Not in force.
    Missing,
    /// Couldn't be read.
    Unknown,
}

/// How the device's lock-down is managed (ADR 0031).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ManagementMode {
    /// The runtime is device owner and applies the restrictions.
    SelfManaged,
    /// An EMM is device owner; the runtime only reads state.
    EmmManaged,
}

/// One gap between required and effective restrictions (PLAT-043).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PostureFinding {
    /// The restriction.
    pub restriction: Restriction,
    /// Its effective state: `Missing` or `Unknown`.
    pub state: RestrictionState,
}

/// Compares required restrictions with effective ones. A required restriction the
/// platform didn't report is `Unknown`.
pub fn posture_findings(
    required: &[Restriction],
    effective: &BTreeMap<Restriction, RestrictionState>,
) -> Vec<PostureFinding> {
    required
        .iter()
        .filter_map(|r| {
            let state = effective.get(r).copied().unwrap_or(RestrictionState::Unknown);
            (state != RestrictionState::InForce).then_some(PostureFinding {
                restriction: *r,
                state,
            })
        })
        .collect()
}

/// Constraints for an evidence capture.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CaptureConstraints {
    /// Longest image edge in pixels.
    pub max_edge: u32,
}

/// An image captured straight into memory. Its `Debug` output is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct CapturedImage(pub Vec<u8>);

impl core::fmt::Debug for CapturedImage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CapturedImage({} bytes)", self.0.len())
    }
}

/// Parameters for the PIN's memory-hard hash (`runtime.pin.argon2`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HashParams {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Iterations.
    pub iterations: u32,
    /// Parallelism.
    pub parallelism: u32,
}

impl HashParams {
    /// The floor: 64 MiB, 3 iterations, parallelism 1.
    pub const FLOOR: HashParams = HashParams {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Whether these parameters are at or above the floor.
    pub fn meets_floor(&self) -> bool {
        self.memory_kib >= Self::FLOOR.memory_kib && self.iterations >= Self::FLOOR.iterations
    }
}
