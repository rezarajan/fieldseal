//! `Clear` (ADR 0029, COL-100–COL-107, COL-073) and receipts (COL-103, COL-106).
//!
//! A clear through `N` is always available once confirmed by the runtime PIN entered twice
//! ([`ClearConfirmation`]): it seals a `checkpoint` record (`cleared_through = N`, the record
//! hash at `N`), deletes the local record through `N`, and deletes journal frames through
//! `N` only where a verified receipt covers them. Frames cleared but not yet received are
//! kept and deleted without prompting once a receipt covers them.

use fieldseal_distribution::domain::AnchorKind;
use fieldseal_kernel::frame::read_frames;
use fieldseal_kernel::id::{Digest, Seq};
use fieldseal_kernel::record::{Record, record_hash};

use super::{CollectionError, CollectionEvent, Runtime, names};
use crate::domain::bundle::TimeAnchor;
use crate::domain::meta::Marker;
use crate::domain::payload::Payload;
use crate::domain::{ClearConfirmation, ClearConfirmationError, DeliveryState, OperationKind, ReceiptCoverage, RuntimePin, plan_clear};

/// What the collector is shown before confirming a clear (COL-102).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClearPreview {
    /// The `seq` cleared through.
    pub through: Seq,
    /// Records in the local record being cleared.
    pub records: u64,
    /// How many of them the authority hasn't received.
    pub not_received: u64,
    /// The statement shown with the counts.
    pub statement: &'static str,
}

/// What a clear did.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClearOutcome {
    /// The checkpoint record's `seq`.
    pub checkpoint: Seq,
    /// Local record entries deleted.
    pub local_deleted: u64,
    /// Journal frames deleted under a receipt.
    pub journal_deleted: u64,
    /// Journal frames kept until a receipt covers them (COL-106).
    pub journal_kept: u64,
}

/// What applying a receipt did.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReceiptOutcome {
    /// Cleared journal frames now deleted without prompting (COL-106).
    pub journal_deleted: u64,
    /// The clear the runtime offers, if the receipt covers records still in the local record
    /// (COL-103).
    pub offer_clear_through: Option<Seq>,
}

const STATEMENT: &str = "Sealed copies of records not yet delivered stay on this device, unreadable, until the authority receives them.";

impl Runtime<'_> {
    fn frames(&self) -> Result<Vec<(u64, Digest, std::ops::Range<usize>)>, CollectionError> {
        let journal = self.journal()?;
        let scan = read_frames(&journal);
        let mut out = Vec::new();
        for f in scan.frames {
            let record = Record::decode(f.body)?;
            let start = f.offset;
            out.push((record.header.seq, record_hash(f.body), start..start + fieldseal_kernel::frame::FRAME_HEADER_LEN + f.body.len()));
        }
        Ok(out)
    }

    /// The counts shown before a clear through `through` (COL-102).
    pub fn clear_preview(&mut self, through: Seq) -> Result<ClearPreview, CollectionError> {
        self.active()?;
        let local: Vec<Seq> = self.local_entries()?.into_iter().map(|e| e.seq).filter(|s| *s <= through).collect();
        let not_received = local.iter().filter(|s| self.delivery_state(**s) != DeliveryState::Received).count() as u64;
        Ok(ClearPreview { through, records: local.len() as u64, not_received, statement: STATEMENT })
    }

    /// `Clear` (COL-100–COL-107): clears the local record through `through` after the
    /// runtime PIN is entered twice. A mismatch or a wrong PIN cancels the clear and counts
    /// toward lockout (COL-101). `coverage` is a verified receipt, if one is held.
    pub fn clear(&mut self, through: Seq, first: &RuntimePin, second: &RuntimePin, coverage: Option<&ReceiptCoverage>) -> Result<ClearOutcome, CollectionError> {
        self.active()?;
        if self.capture.as_ref().is_some_and(|c| c.has_unsealed_changes()) {
            return Err(CollectionError::CaptureOpen);
        }
        let mut wrong = None;
        let confirmed = ClearConfirmation::confirm(first, second, |pin| match self.check_pin(pin) {
            Ok(_) => true,
            Err(e) => {
                wrong = Some(e);
                false
            }
        });
        let confirmation = match confirmed {
            Ok(c) => c,
            Err(ClearConfirmationError::Mismatch) => {
                self.count_failure()?;
                return Err(CollectionError::ClearCancelled("the two PIN entries differ".into()));
            }
            Err(ClearConfirmationError::WrongPin) => {
                return Err(match wrong {
                    Some(CollectionError::LockedOut(s)) => CollectionError::LockedOut(s),
                    Some(CollectionError::WrongPin(_)) | None => CollectionError::ClearCancelled("wrong PIN".into()),
                    Some(e) => e,
                });
            }
        };
        let meta = self.meta()?.clone();
        let head = meta.head.map_or(0, |(s, _)| s);
        if through.0 > head {
            return Err(CollectionError::NotAllowed(format!("seq {} is past the journal's last record {head}", through.0)));
        }
        if meta.cleared_through().is_some_and(|c| through.0 <= c) {
            return Err(CollectionError::NotAllowed(format!("already cleared through {}", through.0)));
        }
        let frames = self.frames()?;
        let hash_at = frames.iter().find(|(s, _, _)| *s == through.0).map(|(_, h, _)| *h).ok_or_else(|| CollectionError::Failed(format!("no frame for seq {}", through.0)))?;
        let coverage = coverage.filter(|c| c.tenancy() == &meta.tenancy);
        let plan = plan_clear(&meta.tenancy, through, hash_at, confirmation, coverage);
        let delivery = coverage.map_or(Digest::from([0; 32]), |c| *c.address());

        let mut marker = Marker {
            kind: OperationKind::Clear,
            step: 0,
            seq: meta.next_seq(),
            through: through.0,
            extra: plan.delete_journal_through.map(|s| s.0.to_be_bytes().to_vec()),
        };
        self.p.storage.write(names::DEVICE, &names::op_marker(), &marker.encode())?;
        let cp = plan.checkpoint;
        let sealed = self.seal_record(
            |tick| Payload::Checkpoint { tick, cleared_through: cp.cleared_through.0, hash_at: cp.journal_hash, delivery },
            None,
        )?;
        marker.step = 1;
        self.p.storage.write(names::DEVICE, &names::op_marker(), &marker.encode())?;
        if let Some((r, addr)) = coverage.map(|c| (c.through().0, *c.address()))
            && let Some(m) = self.meta.as_mut()
            && m.received.is_none_or(|(x, _)| r > x)
        {
            m.received = Some((r, addr));
        }
        let outcome = self.finish_clear(through.0, plan.delete_journal_through.map(|s| s.0), hash_at)?;
        self.p.storage.delete(names::DEVICE, &names::op_marker())?;
        self.events.push(CollectionEvent::LocalRecordCleared(through));
        Ok(ClearOutcome { checkpoint: sealed.seq, ..outcome })
    }

    /// Steps 2 and 3 of a clear, idempotent so recovery can repeat them.
    pub(crate) fn finish_clear(&mut self, through: u64, delete_journal_through: Option<u64>, hash_at: Digest) -> Result<ClearOutcome, CollectionError> {
        let storage = self.p.storage;
        let mut local_deleted = 0;
        for name in storage.names(names::SESSION)? {
            let seq = names::seq_of(&name, "local/").or_else(|| names::seq_of(&name, "note/"));
            if seq.is_some_and(|s| s <= through) {
                if name.0.starts_with("local/") {
                    local_deleted += 1;
                }
                storage.delete(names::SESSION, &name)?;
            }
        }
        if let Some(m) = self.meta.as_mut()
            && !m.cleared.iter().any(|(s, _)| *s == through)
        {
            m.cleared.push((through, hash_at));
        }
        self.save_meta()?;
        let journal_deleted = if delete_journal_through.is_some() { self.delete_journal_through(through)? } else { 0 };
        let journal_kept = self.frames()?.iter().filter(|(s, _, _)| *s <= through).count() as u64;
        Ok(ClearOutcome { checkpoint: Seq(0), local_deleted, journal_deleted, journal_kept })
    }

    /// Deletes journal frames through the highest checkpoint a verified receipt covers
    /// entirely (COL-105, COL-106). Frames are deleted only up to a checkpoint's
    /// `cleared_through`, so the journal stays verifiable from the checkpoint on: the gap
    /// always ends where a checkpoint states the hash (COL-107, WIRE-041). `through` caps it.
    fn delete_journal_through(&mut self, through: u64) -> Result<u64, CollectionError> {
        let meta = self.meta()?;
        let Some((received, _)) = meta.received else { return Ok(0) };
        let Some(allowed) = meta.cleared.iter().map(|(s, _)| *s).filter(|s| *s <= received && *s <= through).max() else {
            return Ok(0);
        };
        let journal = self.journal()?;
        let frames = self.frames()?;
        let mut kept = Vec::with_capacity(journal.len());
        let mut deleted = 0;
        for (seq, _, range) in &frames {
            if *seq <= allowed {
                deleted += 1;
            } else {
                kept.extend_from_slice(&journal[range.clone()]);
            }
        }
        if deleted > 0 {
            self.p.storage.write(names::DEVICE, &names::journal(), &kept)?;
            if let Some(m) = self.meta.as_mut() {
                m.journal_deleted_through = Some(m.journal_deleted_through.map_or(allowed, |d| d.max(allowed)));
            }
            self.save_meta()?;
        }
        Ok(deleted)
    }

    /// Applies a verified receipt (COL-103, COL-106, COL-082): marks the records received,
    /// deletes cleared frames it covers without prompting, chains the receipt as an anchor
    /// (at the next unlock if locked), and offers a clear of what it covers.
    pub fn apply_receipt(&mut self, coverage: &ReceiptCoverage) -> Result<ReceiptOutcome, CollectionError> {
        let meta = self.meta()?;
        if coverage.tenancy() != &meta.tenancy {
            return Err(CollectionError::NotAllowed("the receipt is for another tenancy".into()));
        }
        if let Some(m) = self.meta.as_mut()
            && m.received.is_none_or(|(r, _)| coverage.through().0 > r)
        {
            m.received = Some((coverage.through().0, *coverage.address()));
        }
        self.save_meta()?;
        let journal_deleted = self.delete_journal_through(coverage.through().0)?;
        self.chain_anchor(TimeAnchor { kind: AnchorKind::Receipt, address: *coverage.address(), authority_time: coverage.time() })?;
        let offer = self.session.as_ref().is_none_or(|s| s.policy.offer_clear_on_receipt());
        Ok(ReceiptOutcome { journal_deleted, offer_clear_through: if offer { self.clear_offer() } else { None } })
    }

    /// The clear on offer: everything a verified receipt covers that is still in the local
    /// record. It stays available until taken (COL-103).
    pub fn clear_offer(&self) -> Option<Seq> {
        let m = self.meta.as_ref()?;
        let (received, _) = m.received?;
        (m.cleared_through().is_none_or(|c| received > c)).then_some(Seq(received))
    }

    /// Records a delivery outcome other than a receipt (Delivery: saved and read back, or
    /// handed over). States only move forward.
    pub fn mark_delivered(&mut self, through: Seq, state: DeliveryState) -> Result<(), CollectionError> {
        if let Some(m) = self.meta.as_mut() {
            match state {
                DeliveryState::SavedAndChecked => m.saved = Some(m.saved.map_or(through.0, |s| s.max(through.0))),
                DeliveryState::HandedOver => m.handed_over = Some(m.handed_over.map_or(through.0, |s| s.max(through.0))),
                DeliveryState::Received => return Err(CollectionError::NotAllowed("only a verified receipt marks records received".into())),
                DeliveryState::None => {}
            }
        }
        self.save_meta()
    }
}
