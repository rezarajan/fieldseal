//! Collection's [`BundleOpener`] over Distribution's [`VerifyBundle`]: the runtime imports
//! real `FSB1` bundles (WIRE-090..095, DIS-030).
//!
//! The opener runs the whole verification of DIS-030 except the checks against what the
//! runtime already holds (the sequence number and the roster versions): Collection makes
//! those, because it owns the held bundle and re-opens the same file at every unlock. It then
//! maps the verified content onto the types Collection works with. Trust updates the bundle
//! carries are applied to the runtime's [`TrustStore`] once they have verified.

use fieldseal_collection::domain::bundle::{HeldRoster, OpenedBundle, RegistrationGrant, RosterSubject, TimeAnchor};
use fieldseal_collection::ports::{BundleOpenError, BundleOpener};
use fieldseal_distribution::application::{HeldState, ImportState, VerifyBundle};
use fieldseal_distribution::domain::{AnchorKind, BundleRejection, CollectorReason, Roster, RuntimeProfile, VerifyStep};
use fieldseal_distribution::ports::{AgreementKey, TrustStore};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{Digest, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::domain::PublishingPolicy;
use fieldseal_trust::domain::{AuthorityPublicKey, TrustBundle};

/// The runtime's bundle opener: verifies a bundle file against the runtime's trust bundle and
/// agreement key and opens it.
pub struct FileBundleOpener<'a> {
    trust: &'a TrustBundle,
    publishing: &'a PublishingPolicy,
    agreement: &'a dyn AgreementKey,
    tenancy: TenancyId,
    profile: RuntimeProfile,
    now: &'a dyn Fn() -> AuthorityTime,
    max_size: usize,
    trust_store: Option<&'a dyn TrustStore>,
}

impl<'a> FileBundleOpener<'a> {
    /// An opener for the runtime of `tenancy`, which implements `profile`. `now` is the
    /// runtime's latest authority time, at which the factory signature must be valid.
    pub fn new(
        trust: &'a TrustBundle,
        publishing: &'a PublishingPolicy,
        agreement: &'a dyn AgreementKey,
        tenancy: TenancyId,
        profile: RuntimeProfile,
        now: &'a dyn Fn() -> AuthorityTime,
    ) -> Self {
        Self { trust, publishing, agreement, tenancy, profile, now, max_size: fieldseal_distribution::domain::MAX_BUNDLE_FILE, trust_store: None }
    }

    /// Lowers the size limit (the runtime policy's limit, WIRE-093).
    pub fn with_max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size;
        self
    }

    /// Applies verified trust updates to `store` (TRU-033).
    pub fn with_trust_store(mut self, store: &'a dyn TrustStore) -> Self {
        self.trust_store = Some(store);
        self
    }
}

fn rejected(r: &BundleRejection) -> BundleOpenError {
    if r.collector_reason() == CollectorReason::WrongDevice && r.step() == VerifyStep::Open {
        BundleOpenError::WrongDevice
    } else {
        BundleOpenError::Rejected(format!("{r}"))
    }
}

fn roster(r: &Roster) -> HeldRoster {
    HeldRoster {
        cohort: r.cohort.clone(),
        version: r.version,
        generation: u64::from(r.generation.0),
        address: Digest::from(*fieldseal_kernel::id::ContentAddress::of(&r.encode()).as_bytes()),
        subjects: r
            .entries
            .iter()
            .map(|e| RosterSubject {
                ordinal: u64::from(e.ordinal),
                subject: e.subject.clone(),
                display: std::collections::BTreeMap::from([("display".to_owned(), e.display.clone())]),
                attributes: e.attributes.clone(),
                consent: e.consent,
                prior_status: e.prior_status.clone(),
            })
            .collect(),
    }
}

impl BundleOpener for FileBundleOpener<'_> {
    fn open(&self, file: &[u8]) -> Result<OpenedBundle, BundleOpenError> {
        let verified = VerifyBundle::new(self.trust, self.publishing, self.agreement, self.profile.clone())
            .with_max_size(self.max_size)
            .verify(file, &ImportState { tenancy: self.tenancy, now: (self.now)(), held: HeldState::default() })
            .map_err(|r| rejected(&r))?;
        let content = verified.content;
        let mut instruments = content.instruments.into_iter();
        let (Some(instrument), None) = (instruments.next(), instruments.next()) else {
            return Err(BundleOpenError::Rejected("this runtime holds exactly one instrument per bundle".into()));
        };
        let registration = match &content.certificate {
            None => None,
            Some(cert) => {
                // The record key itself is certified in the trust bundle; the tenancy
                // certificate names it by key ID.
                let record_key = self
                    .trust
                    .contents()
                    .certificates
                    .iter()
                    .find(|c| c.key_id() == &cert.record_key)
                    .and_then(|c| match c.public_key() {
                        AuthorityPublicKey::X25519(k) => Some(*k),
                        AuthorityPublicKey::P256(_) => None,
                    })
                    .ok_or_else(|| BundleOpenError::Rejected("the trust bundle doesn't certify the tenancy's record key".into()))?;
                Some(RegistrationGrant {
                    certificate: sha256(&cert.encode()),
                    record_key,
                    period: cert.record_key,
                    handle: cert.handle,
                    not_before: cert.window.not_before,
                    not_after: cert.window.not_after,
                    // Kept on the device so exports and closing manifests carry it (INT-006).
                    document: Some(cert.to_value()),
                })
            }
        };
        if let Some(store) = self.trust_store {
            for update in &verified.trust_updates {
                // A second open of the same bundle finds the update already applied.
                let _ = store.replace(update.clone());
            }
        }
        Ok(OpenedBundle {
            address: Digest::from(*verified.address.as_bytes()),
            tenancy: content.tenancy,
            seq: content.seq.0,
            issued: content.issued,
            registration,
            time_tokens: vec![TimeAnchor {
                kind: AnchorKind::TimeToken,
                address: sha256(&content.time_token.encode()),
                authority_time: content.time_token.authority_time,
            }],
            instrument,
            layouts: content.layouts,
            policy: content.policy,
            rosters: content.rosters.iter().map(roster).collect(),
            withdrawals: content.withdrawals,
        })
    }
}
