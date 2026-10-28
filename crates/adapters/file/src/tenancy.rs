//! Intake's read-only [`TenancyRegistry`] over the factory's file-backed state: the upload
//! endpoint resolves the devices the factory registered by reading the factory's journal
//! (mounted read-only), so no network call and no extra surface on the factory. The journal
//! is replayed on each lookup, so a device registered a moment ago is known at once.

use std::path::PathBuf;

use fieldseal_intake::domain::TenancyView;
use fieldseal_intake::ports::{TenancyRegistry, TenancyRegistryError};
use fieldseal_kernel::id::{TenancyHandle, TenancyId};
use fieldseal_registration::domain::{TenancyRecord, TenancyState};
use fieldseal_registration::ports::RegistryStore;
use fieldseal_trust::domain::DeviceKeyKind;

use crate::store::FileRegistryStore;

/// The view of the tenancies in a factory state directory.
pub struct FileTenancyRegistry {
    dir: PathBuf,
}

impl FileTenancyRegistry {
    /// The registry over the factory state directory `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

/// What Intake sees of a tenancy: its signing keys by index, its cutoff and whether it is
/// deny-listed. Only tenancies that were registered at some point are visible.
pub fn view_of(t: &TenancyRecord) -> Option<TenancyView> {
    if matches!(t.state, TenancyState::Pending | TenancyState::Held | TenancyState::Rejected) {
        return None;
    }
    let mut keys: Vec<_> = t.keys.iter().filter(|k| k.kind == DeviceKeyKind::Signing).collect();
    keys.sort_by_key(|k| k.index);
    let mut view = TenancyView::new(t.id, t.handle, keys.iter().map(|k| k.public_key.clone()).collect());
    view.cutoff = t.cutoff;
    view.deny_listed = t.state == TenancyState::Lost;
    Some(view)
}

fn unavailable(e: impl std::fmt::Display) -> TenancyRegistryError {
    TenancyRegistryError::Unavailable(e.to_string())
}

impl TenancyRegistry for FileTenancyRegistry {
    fn by_handle(&self, handle: &TenancyHandle) -> Result<Option<TenancyView>, TenancyRegistryError> {
        let s = FileRegistryStore::snapshot(&self.dir).map_err(unavailable)?;
        Ok(s.tenancy_by_handle(handle).map_err(unavailable)?.as_ref().and_then(view_of))
    }

    fn by_id(&self, id: &TenancyId) -> Result<Option<TenancyView>, TenancyRegistryError> {
        let s = FileRegistryStore::snapshot(&self.dir).map_err(unavailable)?;
        Ok(s.tenancy(id).map_err(unavailable)?.as_ref().and_then(view_of))
    }
}
