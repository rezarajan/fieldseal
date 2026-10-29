//! What a bundle gives the runtime once Distribution has opened it (WIRE-094, WIRE-095),
//! and what a close certificate states (WIRE-141).
//!
//! These are the minimal types through which Distribution (issue #49) and Registration plug
//! into Collection: [`crate::ports::BundleOpener`] returns an [`OpenedBundle`], and
//! [`crate::ports::CloseCertificateCheck`] returns a [`CloseCertificate`]. Collection still
//! verifies every [`Publication`] itself before relying on it (PUB-073).

use std::collections::BTreeMap;

use fieldseal_distribution::domain::{AnchorKind, BundleAssignment, ConsentState};
use fieldseal_kernel::Value;
use fieldseal_kernel::id::{CohortId, Digest, KeyId, Seq, SubjectId, TenancyHandle, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_publishing::domain::{Publication, Withdrawal};

/// What a verified tenancy certificate grants the device (WIRE-140, COL-005).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegistrationGrant {
    /// The certificate's content address.
    pub certificate: Digest,
    /// The authority record key for the collection period (`fs1-x`, X25519).
    pub record_key: [u8; 32],
    /// Its key ID (the record header's `period`).
    pub period: KeyId,
    /// The opaque export handle (WIRE-102).
    pub handle: TenancyHandle,
    /// The collection window: not before, in authority milliseconds.
    pub not_before: AuthorityTime,
    /// The collection window: not after, in authority milliseconds.
    pub not_after: AuthorityTime,
    /// The verified tenancy certificate itself, as a value, if the bundle's opener keeps it.
    /// Exports and the closing manifest carry it (WIRE-104); the runtime holds it in
    /// device-encrypted storage because it is not secret.
    pub document: Option<fieldseal_kernel::Value>,
}

/// An authority time statement a bundle, receipt or time token carries (WIRE-057).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TimeAnchor {
    /// Its kind.
    pub kind: AnchorKind,
    /// The content address of the signed statement.
    pub address: Digest,
    /// The authority time it states.
    pub authority_time: AuthorityTime,
}

/// One subject on a held roster (WIRE-095). Display fields are names: they exist only in
/// memory during a session (COL-090), so `Debug` never prints them.
#[derive(Clone, PartialEq, Eq)]
pub struct RosterSubject {
    /// The roster ordinal.
    pub ordinal: u64,
    /// The pseudonymous subject ID.
    pub subject: SubjectId,
    /// Display fields shown to the collector (for example a name), by field name.
    pub display: BTreeMap<String, String>,
    /// Values the instrument declares as roster-supplied.
    pub attributes: BTreeMap<String, Value>,
    /// The consent state.
    pub consent: ConsentState,
    /// Status carried over from a predecessor tenancy.
    pub prior_status: Option<String>,
}

impl core::fmt::Debug for RosterSubject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RosterSubject")
            .field("ordinal", &self.ordinal)
            .field("subject", &self.subject)
            .field("display", &"<redacted>")
            .field("consent", &self.consent)
            .finish_non_exhaustive()
    }
}

impl RosterSubject {
    /// The fields rules and read-only items see (`roster.<field>`): attributes, then display
    /// fields as text. Held only in memory.
    pub fn fields(&self) -> BTreeMap<String, Value> {
        let mut fields = self.attributes.clone();
        for (k, v) in &self.display {
            fields.entry(k.clone()).or_insert_with(|| Value::Text(v.clone()));
        }
        fields
    }
}

/// A cohort's roster as held by the runtime (WIRE-095).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HeldRoster {
    /// The cohort.
    pub cohort: CohortId,
    /// The roster version.
    pub version: u64,
    /// This tenancy's generation for the cohort.
    pub generation: u64,
    /// The roster's content address, for `consent_ref` and `import` records.
    pub address: Digest,
    /// The subjects.
    pub subjects: Vec<RosterSubject>,
    /// The surveys, by name, that a `granted` consent on this roster covers (WIRE-095).
    pub consent_covers: Vec<String>,
}

impl HeldRoster {
    /// Whether a `granted` consent on this roster covers the survey named `survey`.
    pub fn covers(&self, survey: &str) -> bool {
        self.consent_covers.iter().any(|c| c == survey)
    }
}

/// A bundle's contents after Distribution verified its envelope and opened its seal
/// (WIRE-094). Nothing in it is trusted until Collection verifies the publications.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OpenedBundle {
    /// The content address of the bundle content.
    pub address: Digest,
    /// The tenancy it is for.
    pub tenancy: TenancyId,
    /// The bundle sequence number: a bundle must be newer than the one held (DIS-030).
    pub seq: u64,
    /// The factory's issue time (anchored as a `bundle` anchor, COL-082).
    pub issued: AuthorityTime,
    /// The verified tenancy certificate's grant, if the bundle carries one.
    pub registration: Option<RegistrationGrant>,
    /// Time tokens carried (anchored when first seen, COL-082).
    pub time_tokens: Vec<TimeAnchor>,
    /// The instruments, one for each survey the bundle carries.
    pub instruments: Vec<Publication>,
    /// Layouts for the instruments, each bound to one of them (DIS-016).
    pub layouts: Vec<Publication>,
    /// The runtime policy, one publication per contributing layer, outermost first
    /// (POL-050); empty means the policy defaults apply.
    pub policy: Vec<Publication>,
    /// Rosters; a bundle without rosters is a practice bundle (COL-003).
    pub rosters: Vec<HeldRoster>,
    /// The surveys the factory assigned to this account, each linking the instrument to a
    /// cohort (WIRE-094); empty when the bundle carries none.
    pub assignments: Vec<BundleAssignment>,
    /// Withdrawals to check the publications against.
    pub withdrawals: Vec<Withdrawal>,
}

/// What a verified close or reset certificate states (WIRE-141).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CloseCertificate {
    /// The tenancy it closes.
    pub tenancy: TenancyId,
    /// The last `seq` the authority accepts.
    pub cutoff_seq: Seq,
    /// Whether it is a reset certificate rather than a close certificate.
    pub reset: bool,
    /// The stated reason (for example `forgotten-pin`).
    pub reason: String,
    /// The certificate's bytes, attached to the outbox in place of a closing record.
    pub bytes: Vec<u8>,
}
