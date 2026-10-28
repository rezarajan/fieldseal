//! Dual write (ADR 0018, COL-050–COL-053, COL-092): every record goes to the journal,
//! sealed to the authority's record key and signed by the tenancy key, and to the local
//! record under the session key, as one recoverable operation.
//!
//! The steps, each persisted before the next:
//!
//! 1. the seal marker (`marker/seal`) names the `seq`;
//! 2. the local entry and its note are written under `pending/…` (session class);
//! 3. the tick state is written, so the high-water mark survives a crash (COL-080);
//! 4. the frame is appended to the journal: **the commit point**;
//! 5. the pending entry is moved to `local/…`;
//! 6. the chain head is saved and the marker deleted.
//!
//! Recovery ([`super::recover`]) completes step 5 when the journal holds the `seq`, and
//! discards the pending entry when it doesn't.

use fieldseal_distribution::domain::AnchorKind;
use fieldseal_kernel::crypto::tags;
use fieldseal_kernel::frame::frame;
use fieldseal_kernel::id::{Digest, RecordId, Seq};
use fieldseal_kernel::local_record::{LocalEntry, MAX_ENCRYPTIONS};
use fieldseal_kernel::payload::Tick;
use fieldseal_kernel::record::{Record, RecordHeader, record_hash, record_id_from_random, record_signed_structure};
use fieldseal_kernel::seal::{RecipientKey, seal};
use fieldseal_kernel::sign::signed_message;
use fieldseal_trust::ports::SourceRng;

use super::{CollectionError, CollectionEvent, Runtime, names};
use crate::domain::OperationKind;
use crate::domain::bundle::TimeAnchor;
use crate::domain::local::LocalNote;
use crate::domain::meta::Marker;
use crate::domain::payload::Payload;
use crate::domain::ticks::TickState;

/// A sealed record's identity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Sealed {
    pub seq: Seq,
    pub record_id: RecordId,
    pub hash: Digest,
}

/// The local record's copy of a payload: evidence bytes are not kept (COL-043).
fn local_copy(payload: &Payload) -> Payload {
    match payload {
        Payload::Evidence { tick, blob_id, media_type, .. } => {
            Payload::Evidence { tick: *tick, blob_id: *blob_id, media_type: media_type.clone(), bytes: Vec::new() }
        }
        p => p.clone(),
    }
}

impl Runtime<'_> {
    fn next_tick(&mut self) -> Result<Tick, CollectionError> {
        let now = self.now();
        let wall = self.p.wall.now_ms();
        let build = self.build_anchor()?;
        let ticks = self.ticks.get_or_insert_with(|| TickState::new(build, now));
        Ok(ticks.next(now, wall))
    }

    /// Seals one record built from its tick: the dual write of ADR 0018. Requires the
    /// session key (for the local record) and uses the tenancy signing key (COL-026).
    pub(crate) fn seal_record(&mut self, build: impl FnOnce(Tick) -> Payload, capture_ms: Option<u64>) -> Result<Sealed, CollectionError> {
        if self.session.is_none() {
            return Err(CollectionError::Locked);
        }
        let meta = self.meta()?.clone();
        if meta.encryptions + 2 >= MAX_ENCRYPTIONS {
            return Err(CollectionError::Failed("session storage key needs rotation (WIRE-082)".into()));
        }
        let seq = meta.next_seq();
        let prev = meta.head.map_or(Digest::from([0; 32]), |(_, h)| h);
        let tick = self.next_tick()?;
        let payload = build(tick);
        let plaintext = zeroize::Zeroizing::new(payload.encode()?);
        let sealed_payload = seal(&mut SourceRng(self.p.random), &RecipientKey::X25519(meta.record_key), &tags::RECORD_SEAL, &plaintext)?;
        let record_id = record_id_from_random(self.random::<16>());
        let header = RecordHeader { record_id, seq, prev, key: 0, period: meta.period };
        let message = signed_message(&tags::RECORD, &record_signed_structure(&header, &sealed_payload))?;
        let sig = self.p.keys.sign(&meta.sign, &message)?;
        let record = Record { header, payload: sealed_payload, sig };
        let body = record.encode()?;
        let hash = record_hash(&body);
        let framed = frame(&body)?;

        let session = self.session.as_ref().ok_or(CollectionError::Locked)?;
        let local_plain = zeroize::Zeroizing::new(local_copy(&payload).encode()?);
        let mut nonce = [0u8; 12];
        self.p.random.fill(&mut nonce);
        let entry = LocalEntry::seal(&session.key, &meta.tenancy, seq, nonce, &local_plain).encode();
        self.p.random.fill(&mut nonce);
        let note = LocalEntry::seal(&session.key, &meta.tenancy, seq, nonce, &LocalNote { record_id, capture_ms }.encode()).encode();

        let storage = self.p.storage;
        let marker = Marker { kind: OperationKind::Seal, step: 1, seq, through: 0, extra: None };
        storage.write(names::DEVICE, &names::seal_marker(), &marker.encode())?;
        storage.write(names::SESSION, &names::pending_local(seq), &entry)?;
        storage.write(names::SESSION, &names::pending_note(seq), &note)?;
        let ticks = self.ticks.as_ref().expect("set by next_tick").to_value();
        storage.write(names::DEVICE, &names::ticks(), &fieldseal_kernel::cbor::encode(&ticks)?)?;
        storage.append(names::DEVICE, &names::journal(), &framed)?;
        // Committed: the journal holds the record.
        storage.write(names::SESSION, &names::local(seq), &entry)?;
        storage.write(names::SESSION, &names::note(seq), &note)?;
        storage.delete(names::SESSION, &names::pending_local(seq))?;
        storage.delete(names::SESSION, &names::pending_note(seq))?;
        if let Some(m) = self.meta.as_mut() {
            m.head = Some((seq, hash));
            m.encryptions += 2;
        }
        self.save_meta()?;
        storage.delete(names::DEVICE, &names::seal_marker())?;
        self.events.push(CollectionEvent::RecordSealed { seq: Seq(seq), kind: payload.kind() });
        Ok(Sealed { seq: Seq(seq), record_id, hash })
    }

    /// Seals the journal's first record (WIRE-039, WIRE-062).
    pub(crate) fn seal_open(&mut self) -> Result<Sealed, CollectionError> {
        let meta = self.meta()?.clone();
        self.seal_record(
            |tick| Payload::Open {
                tick,
                tenancy: Digest::from(*meta.tenancy.as_bytes()),
                sign_pub: meta.sign_pub.clone(),
                agree_pub: meta.agree_pub.clone(),
                evidence: meta.evidence.clone(),
                build_anchor: meta.build_anchor,
            },
            None,
        )
    }

    /// Chains an anchor into the journal when first seen (COL-082). Later ticks count from
    /// it. Without a session the anchor waits and is chained at the next unlock.
    pub(crate) fn chain_anchor(&mut self, anchor: TimeAnchor) -> Result<bool, CollectionError> {
        let meta = self.meta()?;
        if meta.anchors.contains(&anchor.address) {
            return Ok(false);
        }
        if self.session.is_none() {
            let kind = anchor_code(anchor.kind);
            if let Some(m) = self.meta.as_mut()
                && !m.pending_anchors.iter().any(|(_, d, _)| *d == anchor.address)
            {
                m.pending_anchors.push((kind, anchor.address, anchor.authority_time.0));
            }
            self.save_meta()?;
            return Ok(false);
        }
        self.seal_record(
            |tick| Payload::Anchor { tick, kind: anchor.kind, address: anchor.address, authority_time: anchor.authority_time.0 },
            None,
        )?;
        let now = self.now();
        if let Some(t) = self.ticks.as_mut() {
            t.rebase(anchor.address, now);
        }
        let ticks = self.ticks.as_ref().expect("ticks exist once a record is sealed").to_value();
        self.p.storage.write(names::DEVICE, &names::ticks(), &fieldseal_kernel::cbor::encode(&ticks)?)?;
        if let Some(m) = self.meta.as_mut() {
            m.anchors.push(anchor.address);
            m.pending_anchors.retain(|(_, d, _)| *d != anchor.address);
        }
        self.save_meta()?;
        Ok(true)
    }

    /// Chains anchors that arrived while locked.
    pub(crate) fn chain_pending_anchors(&mut self) -> Result<(), CollectionError> {
        let pending = self.meta()?.pending_anchors.clone();
        for (kind, address, time) in pending {
            self.chain_anchor(TimeAnchor { kind: anchor_kind(kind), address, authority_time: fieldseal_kernel::time::AuthorityTime(time) })?;
        }
        Ok(())
    }
}

fn anchor_code(kind: AnchorKind) -> u8 {
    match kind {
        AnchorKind::Build => 0,
        AnchorKind::Bundle => 1,
        AnchorKind::Receipt => 2,
        AnchorKind::TimeToken => 3,
    }
}

fn anchor_kind(code: u8) -> AnchorKind {
    match code {
        0 => AnchorKind::Build,
        1 => AnchorKind::Bundle,
        2 => AnchorKind::Receipt,
        _ => AnchorKind::TimeToken,
    }
}
