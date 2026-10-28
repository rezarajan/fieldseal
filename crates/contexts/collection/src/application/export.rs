//! What Delivery needs from the runtime to build an export or sign an upload (DEL-010,
//! DEL-011, DEL-029): the tenancy's identity, key history, sealed journal and the key
//! handle to sign with. Nothing here is secret: the journal is sealed to the authority's
//! record key and the handle is only a reference into the key store.

use fieldseal_kernel::id::{Digest, Fingerprint, KeyId, TenancyHandle, TenancyId};
use fieldseal_kernel::crypto::P256PublicKey;
use fieldseal_trust::domain::KeyHandle;

use super::{CollectionError, Runtime};

/// The facts about the open tenancy an export is built from (WIRE-104).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExportSource {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The opaque export handle (WIRE-102).
    pub handle: TenancyHandle,
    /// The authority record key the manifest is sealed to (`fs1-x`).
    pub record_key: [u8; 32],
    /// Its key ID.
    pub period: KeyId,
    /// The signing key, by reference into the key store.
    pub sign: KeyHandle,
    /// The key history: `(index, public key, evidence address)`.
    pub keys: Vec<(u64, P256PublicKey, Digest)>,
    /// The runtime build's release anchor.
    pub build_anchor: Digest,
    /// The instruments records were made with.
    pub instruments: Vec<Fingerprint>,
    /// The runtime policy in use, if a bundle carried one.
    pub policy: Option<Digest>,
    /// The tenancy certificate's content address, once registered.
    pub certificate: Option<Digest>,
    /// The verified tenancy certificate as a value, if the bundle carried it.
    pub certificate_document: Option<fieldseal_kernel::Value>,
    /// The journal's frames as held: sealed, readable without a session (COL-008).
    pub journal: Vec<u8>,
    /// Checkpoints sealed, `(cleared_through, hash_at)`, for verifying across cleared frames.
    pub checkpoints: Vec<(u64, Digest)>,
}

impl Runtime<'_> {
    /// The tenancy certificate a bundle carried, if the runtime holds it (WIRE-104).
    pub(crate) fn registration_document(&self) -> Result<Option<fieldseal_kernel::Value>, CollectionError> {
        self.p
            .storage
            .read(super::names::DEVICE, &super::names::registration())?
            .map(|b| fieldseal_kernel::cbor::decode(&b).map_err(CollectionError::from))
            .transpose()
    }

    /// The open tenancy's export source (`BuildExport`, `StartBackgroundUpload`). With
    /// `require_session`, the session must be open and unexpired: exporting the active
    /// tenancy to a file needs an unlocked session (DEL-029). Background upload reads the
    /// same sealed data without one (DEL-001).
    pub fn export_source(&mut self, require_session: bool) -> Result<ExportSource, CollectionError> {
        if require_session {
            self.active()?;
        }
        let m = self.meta()?.clone();
        Ok(ExportSource {
            tenancy: m.tenancy,
            handle: m.handle,
            record_key: m.record_key,
            period: m.period,
            sign: m.sign,
            keys: vec![(0, m.sign_pub, m.evidence.first().copied().unwrap_or(Digest::from([0; 32])))],
            build_anchor: m.build_anchor,
            instruments: m.instruments,
            policy: m.policy,
            certificate: m.certificate,
            certificate_document: self.registration_document()?,
            journal: self.journal()?,
            checkpoints: m.cleared,
        })
    }
}
