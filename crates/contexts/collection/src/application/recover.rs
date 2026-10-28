//! Crash safety (COL-051, COL-092, COL-093): what the runtime does when it loads after a
//! crash or power loss.
//!
//! - A torn frame at the end of the journal is truncated; earlier records are kept. Damage
//!   anywhere else is reported and the journal left as it is (COL-051).
//! - The chain head is taken from the journal, which is the source of truth.
//! - An interrupted seal is completed when the journal holds its record (the pending local
//!   entry is moved into place) and discarded when it doesn't: the record was never sealed.
//! - An interrupted clear whose checkpoint is in the journal is completed; one whose
//!   checkpoint isn't is abandoned (nothing irreversible had happened).
//! - An interrupted close or forced close whose outbox entry exists is completed without
//!   the PIN; one that still needs the signing key completes at the next unlock.

use fieldseal_kernel::cbor;
use fieldseal_kernel::frame::{FRAME_HEADER_LEN, read_frames};
use fieldseal_kernel::id::Digest;
use fieldseal_kernel::record::{Record, record_hash};

use super::{CollectionError, Runtime, names};
use crate::domain::meta::{Marker, TenancyMeta};
use crate::domain::ticks::TickState;
use crate::domain::{OperationKind, TenancyState};

/// What recovery found and did.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RecoveryReport {
    /// Bytes of a torn final frame truncated from the journal (COL-093).
    pub truncated_bytes: u64,
    /// Damaged regions left in place, by offset (they need the authority, not the device).
    pub damage: Vec<usize>,
    /// Seals completed: the local record entry moved into place.
    pub seals_completed: Vec<u64>,
    /// Seals discarded: the journal never received the record.
    pub seals_discarded: Vec<u64>,
    /// Multi-step operations completed or abandoned, by name.
    pub operations: Vec<String>,
    /// Whether the chain head was repaired from the journal.
    pub head_repaired: bool,
}

impl RecoveryReport {
    /// Whether recovery had anything to do.
    pub fn is_clean(&self) -> bool {
        *self == Self::default()
    }
}

impl Runtime<'_> {
    pub(crate) fn recover(&mut self) -> Result<(), CollectionError> {
        let storage = self.p.storage;
        let mut report = RecoveryReport::default();
        self.meta = match storage.read(names::DEVICE, &names::tenancy())? {
            Some(b) => Some(TenancyMeta::decode(&b)?),
            None => None,
        };
        let op = storage.read(names::DEVICE, &names::op_marker())?.map(|b| Marker::decode(&b)).transpose()?;
        if self.meta.is_none() {
            if op.is_some() {
                storage.delete(names::DEVICE, &names::op_marker())?;
                report.operations.push("close completed".into());
            }
            self.recovery = report;
            return Ok(());
        }
        self.ticks = storage.read(names::DEVICE, &names::ticks())?.map(|b| cbor::decode(&b).and_then(TickState::from_value)).transpose()?;

        // The journal: truncate a torn tail, take the head from it.
        let journal = storage.read(names::DEVICE, &names::journal())?.unwrap_or_default();
        let scan = read_frames(&journal);
        let end = scan.frames.last().map_or(0, |f| f.offset + FRAME_HEADER_LEN + f.body.len());
        let tail_damage: Vec<usize> = scan.damage.iter().map(|d| d.offset).filter(|o| *o >= end).collect();
        report.damage = scan.damage.iter().map(|d| d.offset).filter(|o| *o < end).collect();
        let last = match scan.frames.last() {
            Some(f) => Some((Record::decode(f.body)?.header.seq, record_hash(f.body))),
            None => None,
        };
        if !tail_damage.is_empty() && end < journal.len() {
            report.truncated_bytes = (journal.len() - end) as u64;
            storage.write(names::DEVICE, &names::journal(), &journal[..end])?;
        }
        let head = self.meta.as_ref().and_then(|m| m.head);
        if last.is_some_and(|l| head.is_none_or(|h| l.0 > h.0)) {
            if let Some(m) = self.meta.as_mut() {
                m.head = last;
            }
            report.head_repaired = true;
            self.save_meta()?;
        }
        let has_seq = |seq: u64| last.is_some_and(|(l, _)| seq <= l);

        // An interrupted seal.
        if let Some(b) = storage.read(names::DEVICE, &names::seal_marker())? {
            let m = Marker::decode(&b)?;
            if has_seq(m.seq) {
                for (pending, final_name) in [(names::pending_local(m.seq), names::local(m.seq)), (names::pending_note(m.seq), names::note(m.seq))] {
                    if let Some(bytes) = storage.read(names::SESSION, &pending)? {
                        storage.write(names::SESSION, &final_name, &bytes)?;
                        storage.delete(names::SESSION, &pending)?;
                    }
                }
                report.seals_completed.push(m.seq);
            } else {
                storage.delete(names::SESSION, &names::pending_local(m.seq))?;
                storage.delete(names::SESSION, &names::pending_note(m.seq))?;
                report.seals_discarded.push(m.seq);
            }
            storage.delete(names::DEVICE, &names::seal_marker())?;
        }
        // Orphaned pending entries (a seal that failed before its marker could be read).
        for name in storage.names(names::SESSION)? {
            if name.0.starts_with("pending/") {
                storage.delete(names::SESSION, &name)?;
            }
        }

        // An interrupted multi-step operation.
        if let Some(m) = op {
            match m.kind {
                OperationKind::Clear if has_seq(m.seq) => {
                    let frames = read_frames(&storage.read(names::DEVICE, &names::journal())?.unwrap_or_default())
                        .frames
                        .iter()
                        .map(|f| Record::decode(f.body).map(|r| (r.header.seq, record_hash(f.body))))
                        .collect::<Result<Vec<_>, _>>()?;
                    let hash_at = frames.iter().find(|(s, _)| *s == m.through).map(|(_, h)| *h).unwrap_or(Digest::from([0; 32]));
                    let limit = m.extra.as_deref().and_then(|b| <[u8; 8]>::try_from(b).ok()).map(u64::from_be_bytes);
                    self.finish_clear(m.through, limit, hash_at)?;
                    storage.delete(names::DEVICE, &names::op_marker())?;
                    report.operations.push(format!("clear through {} completed", m.through));
                }
                OperationKind::Clear => {
                    storage.delete(names::DEVICE, &names::op_marker())?;
                    report.operations.push(format!("clear through {} abandoned before its checkpoint", m.through));
                }
                OperationKind::EndTenancy | OperationKind::ApplyCloseCertificate => {
                    let tenancy = self.meta.as_ref().map(|t| t.tenancy).expect("checked above");
                    let outbox = storage.read(names::DEVICE, &names::outbox(&fieldseal_kernel::digest::lower_hex(&tenancy.as_bytes()[..8])))?;
                    if outbox.is_some() {
                        self.erase()?;
                        storage.delete(names::DEVICE, &names::op_marker())?;
                        report.operations.push("close completed".into());
                    } else {
                        report.operations.push("close waits for the next unlock".into());
                    }
                }
                OperationKind::Seal | OperationKind::Export => {
                    storage.delete(names::DEVICE, &names::op_marker())?;
                }
            }
        }
        self.recovery = report;
        Ok(())
    }

    /// Work that needs a session after unlock: anchors seen while locked, and a close that
    /// was interrupted before its outbox entry was signed.
    pub(crate) fn resume_after_unlock(&mut self) -> Result<(), CollectionError> {
        if let Some(b) = self.p.storage.read(names::DEVICE, &names::op_marker())? {
            let m = Marker::decode(&b)?;
            if m.kind == OperationKind::EndTenancy {
                if self.meta()?.head.is_none_or(|(h, _)| h < m.seq) {
                    let meta = self.meta()?;
                    let last_seq = meta.next_seq();
                    let prev_hash = meta.head.map_or(Digest::from([0; 32]), |(_, h)| h);
                    self.seal_record(
                        |tick| crate::domain::payload::Payload::Closing { tick, last_seq, prev_hash, reason: crate::domain::payload::ClosingReason::Collector },
                        None,
                    )?;
                }
                self.write_closed_outbox()?;
                self.erase()?;
                self.p.storage.delete(names::DEVICE, &names::op_marker())?;
                self.recovery.operations.push("close completed at unlock".into());
                return Ok(());
            }
        }
        if self.meta()?.state != TenancyState::Closing {
            self.chain_pending_anchors()?;
        }
        Ok(())
    }
}
