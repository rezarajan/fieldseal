//! The [`RuntimeProfiles`] the factory serves from what each runtime reported at registration
//! (REG-091), read from the tenancy registry journal.
//!
//! **Development adapter**: the tenancy registry journal is a file store.

use std::path::PathBuf;

use fieldseal_distribution::domain::RuntimeProfile;
use fieldseal_distribution::ports::{ProfileError, RuntimeProfiles};
use fieldseal_instrument::domain::SchemaVersion;
use fieldseal_kernel::id::TenancyId;
use fieldseal_registration::ports::RegistryStore;

use crate::store::FileRegistryStore;

/// Runtime profiles read from the tenancy registry journal in a directory.
pub struct FileRuntimeProfiles {
    tenancy_registry_dir: PathBuf,
}

impl FileRuntimeProfiles {
    /// Profiles of the tenancies in the journal in `tenancy_registry_dir`.
    pub fn new(tenancy_registry_dir: impl Into<PathBuf>) -> Self {
        Self {
            tenancy_registry_dir: tenancy_registry_dir.into(),
        }
    }
}

fn unavailable(e: impl std::fmt::Display) -> ProfileError {
    ProfileError::Unavailable(e.to_string())
}

impl RuntimeProfiles for FileRuntimeProfiles {
    fn profile(&self, tenancy: &TenancyId) -> Result<Option<RuntimeProfile>, ProfileError> {
        let registry =
            FileRegistryStore::snapshot(&self.tenancy_registry_dir).map_err(unavailable)?;
        // Distribution depends on Registration and not the reverse, so the reported version is
        // converted to the instrument context's type here.
        Ok(registry.tenancy(tenancy).map_err(unavailable)?.map(|t| {
            let v = t.profile.instrument_schema;
            RuntimeProfile {
                instrument_schema: SchemaVersion {
                    major: v.major,
                    minor: v.minor,
                    patch: v.patch,
                },
                localisation_reference: t.profile.catalogue_reference,
            }
        }))
    }
}
