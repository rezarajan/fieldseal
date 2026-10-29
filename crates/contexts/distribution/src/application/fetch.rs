//! `FetchBundle` and `DownloadBundle` (distribution §3, DIS-040, DIS-041): handing a built
//! bundle to a runtime or to the portal. Neither builds anything: the bundle was built when
//! something changed (registration, assignment, artefact, policy, key roll), and these
//! deliver the latest, unless the tenancy is no longer eligible.

use fieldseal_kernel::id::TenancyId;
use fieldseal_registration::domain::{DeviceId, TenancyRecord};
use fieldseal_registration::ports::RegistryStore;

use super::release::check_state;
use crate::domain::file::file_name;
use crate::domain::{BundleSeq, DistributionError, SealedBundle};
use crate::ports::BundleStore;

/// What a fetch found. The three outcomes are different answers for a runtime: it keeps
/// asking, it keeps what it holds, or it imports.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BundleFetchResponse {
    /// The tenancy is eligible but nothing is stored yet (the first build is still to come).
    NoBundle,
    /// The bundle the runtime holds (`held`) is the latest.
    Current,
    /// The latest bundle, newer than `held`.
    Bundle(SealedBundle),
}

/// `FetchBundle`: a runtime asks for its latest bundle, after authenticating with a
/// proof-of-possession token (Registration's `authenticate_api`).
pub trait FetchBundle {
    /// What is stored for `tenancy`, compared with the sequence number `held`. It reads the
    /// store and never builds.
    fn fetch(&self, tenancy: &TenancyId, held: Option<BundleSeq>) -> Result<BundleFetchResponse, DistributionError>;
}

/// `DownloadBundle`: the portal gives a signed-in collector the latest bundle for a device
/// as a file (DIS-041).
pub trait DownloadBundle {
    /// The file name (DIS-023) and bytes of the latest bundle for `device`.
    fn download(&self, device: &DeviceId) -> Result<(String, SealedBundle), DistributionError>;
}

/// Both, over the registry and the bundle store.
pub struct BundleDelivery<'a> {
    registry: &'a dyn RegistryStore,
    bundles: &'a dyn BundleStore,
}

impl<'a> BundleDelivery<'a> {
    /// Delivery over `registry` (for eligibility) and `bundles` (for the bundles).
    pub fn new(registry: &'a dyn RegistryStore, bundles: &'a dyn BundleStore) -> Self {
        Self { registry, bundles }
    }

    fn eligible(&self, tenancy: &TenancyId) -> Result<TenancyRecord, DistributionError> {
        let record = self
            .registry
            .tenancy(tenancy)
            .map_err(|e| DistributionError::Port { port: "RegistryStore", reason: e.to_string() })?
            .ok_or(DistributionError::NotRegistered)?;
        // A bundle already built is withheld the same way a new one would be (DIS-003).
        check_state(record.state, false)?;
        // A policy hold on the stored bundle stops delivery too; a marker that can't be read
        // fails closed.
        let held = self
            .bundles
            .withheld(tenancy)
            .map_err(|e| DistributionError::Port { port: "BundleStore", reason: e.to_string() })?;
        if let Some(reasons) = held {
            return Err(DistributionError::Withheld(reasons));
        }
        Ok(record)
    }

    fn latest(&self, tenancy: &TenancyId) -> Result<Option<SealedBundle>, DistributionError> {
        self.bundles
            .latest(tenancy)
            .map_err(|e| DistributionError::Port { port: "BundleStore", reason: e.to_string() })
    }
}

impl FetchBundle for BundleDelivery<'_> {
    fn fetch(&self, tenancy: &TenancyId, held: Option<BundleSeq>) -> Result<BundleFetchResponse, DistributionError> {
        self.eligible(tenancy)?;
        Ok(match self.latest(tenancy)? {
            None => BundleFetchResponse::NoBundle,
            Some(latest) if held.is_some_and(|h| latest.seq <= h) => BundleFetchResponse::Current,
            Some(latest) => BundleFetchResponse::Bundle(latest),
        })
    }
}

impl DownloadBundle for BundleDelivery<'_> {
    fn download(&self, device: &DeviceId) -> Result<(String, SealedBundle), DistributionError> {
        let record = self
            .registry
            .device(device)
            .map_err(|e| DistributionError::Port { port: "RegistryStore", reason: e.to_string() })?
            .ok_or(DistributionError::NotRegistered)?;
        let tenancy = record.tenancies.last().ok_or(DistributionError::NotRegistered)?;
        self.eligible(tenancy)?;
        let bundle = self
            .latest(tenancy)?
            .ok_or_else(|| DistributionError::Withheld(vec!["no-bundle-built".into()]))?;
        Ok((file_name(bundle.issued.0, bundle.seq.0), bundle))
    }
}
