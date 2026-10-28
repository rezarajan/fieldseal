//! Stages 4–9: the tenancy certificate, the key history, the journal chain, record
//! decryption, payload decoding, and ticks (INT-006–011, INT-020, INT-009).

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::{Purpose, tags};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{Digest, Seq};
use fieldseal_kernel::record::{ChainLink, read_journal, verify_chain};
use fieldseal_kernel::seal::SealedBox;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{ErrorCode, Value};
use fieldseal_policy::domain::{DecisionPoint, IntakePolicy, Verdict};
use fieldseal_trust::domain::TrustStore;

use super::{Fail, Gap, IntakeService, Part, backend};
use crate::domain::{Code, Finding, FindingKind, GateState, LossLedgerEntry, Rejection, Stage, Submission};
use crate::wire::{ExportManifest, ManifestEnd, Payload};

fn reject(stage: Stage, code: Code, detail: impl Into<String>) -> Fail {
    Fail::Reject(Rejection::new(stage, code, detail))
}

fn wire(stage: Stage, code: ErrorCode, detail: impl Into<String>) -> Fail {
    reject(stage, Code::Wire(code), detail)
}

/// The inclusive ranges of `from..=through` not in `held`.
fn missing_ranges(from: u64, through: u64, held: &BTreeSet<u64>) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut start = None;
    let mut s = from;
    while s <= through {
        match (held.contains(&s), start) {
            (false, None) => start = Some(s),
            (true, Some(a)) => {
                out.push((a, s - 1));
                start = None;
            }
            _ => {}
        }
        if s == u64::MAX {
            break;
        }
        s += 1;
    }
    if let Some(a) = start {
        out.push((a, through));
    }
    out
}

impl IntakeService<'_> {
    /// Stage 4: opens the manifest (only now that the export signature is valid, INT-001) and
    /// checks the tenancy certificate against the trust bundle (INT-006).
    pub(super) fn stage_certificate(&self, parts: &mut [Part], sub: &mut Submission) -> Result<(), Fail> {
        sub.advance(GateState::Opened).map_err(backend)?;
        let stage = Stage::Certificate;
        let store = TrustStore::new(self.trust)
            .with_revocations(self.revocations.clone())
            .map_err(|e| reject(stage, Code::Wire(e.code().unwrap_or(ErrorCode::Sig)), format!("revocation: {e}")))?;
        for (i, part) in parts.iter_mut().enumerate() {
            let sealed = SealedBox::decode(&part.sealed_manifest).map_err(|e| wire(stage, e.code, format!("part {i}: manifest: {}", e.detail)))?;
            if part.manifest.is_none() {
                let plain = self
                    .custody
                    .open(&sealed.recipient, Purpose::Record, &tags::EXPORT_MANIFEST_SEAL, &sealed, self.caller)
                    .map_err(|e| self.custody_fail(stage, e))?;
                let manifest = cbor::decode(&plain)
                    .and_then(ExportManifest::from_value)
                    .map_err(|e| wire(stage, e.code, format!("part {i}: manifest: {}", e.detail)))?;
                part.manifest = Some(manifest);
                part.record_key = Some(sealed.recipient);
            }
            let m = part.manifest.as_ref().ok_or_else(|| wire(stage, ErrorCode::ExportSection, "no manifest"))?;
            if m.tenancy != part.view.tenancy {
                return Err(wire(stage, ErrorCode::Hash, format!("part {i}: the manifest names a different tenancy than the export handle")));
            }
            if part.registered {
                let Some(c) = &m.certificate else {
                    return Err(reject(stage, Code::Int("INT-006"), format!("part {i}: no tenancy certificate")));
                };
                store
                    .verify_signature(&c.signer, &[], &tags::TENANCY_CERTIFICATE, &c.signed_structure(), &c.sig, c.issued)
                    .map_err(|e| {
                        reject(stage, Code::Wire(e.code().unwrap_or(ErrorCode::Sig)), format!("part {i}: tenancy certificate does not chain to the authority root: {e}"))
                    })?;
                if c.tenancy != m.tenancy || c.handle != part.view.handle {
                    return Err(wire(stage, ErrorCode::Hash, format!("part {i}: the certificate is for another tenancy or handle")));
                }
                if Some(c.period) != part.record_key {
                    return Err(wire(stage, ErrorCode::Recipient, format!("part {i}: the manifest is not sealed to the certificate's record key")));
                }
                part.window = Some(c.window);
                part.cohorts = c.cohorts.clone();
            }
            if let Some(ManifestEnd::Certificate(cc)) = &m.end {
                if cc.tenancy != m.tenancy {
                    return Err(wire(stage, ErrorCode::Hash, format!("part {i}: the close certificate is for another tenancy")));
                }
                let verify = |tag| store.verify_signature(&cc.signer, &[], tag, &cc.signed_structure(), &cc.sig, cc.issued).is_ok();
                if !verify(&tags::CLOSE_CERTIFICATE) && !verify(&tags::RESET_CERTIFICATE) {
                    return Err(wire(stage, ErrorCode::Sig, format!("part {i}: the close or reset certificate does not chain to the authority root")));
                }
            }
        }
        sub.advance(GateState::Certified).map_err(backend)?;
        Ok(())
    }

    /// Stage 5: the key history in the manifest is the registered one (INT-006).
    pub(super) fn stage_key_history(&self, parts: &mut [Part]) -> Result<(), Fail> {
        let stage = Stage::KeyHistory;
        for (i, part) in parts.iter_mut().enumerate() {
            let m = part.manifest.as_ref().ok_or_else(|| wire(stage, ErrorCode::ExportSection, "no manifest"))?;
            if m.keys.is_empty() {
                return Err(reject(stage, Code::Int("INT-006"), format!("part {i}: empty key history")));
            }
            for (n, k) in m.keys.iter().enumerate() {
                if k.index != n as u64 {
                    return Err(reject(stage, Code::Int("INT-006"), format!("part {i}: key history indexes are not 0, 1, 2, …")));
                }
                if part.view.signing_keys.get(n) != Some(&k.public_key) {
                    return Err(reject(stage, Code::Int("INT-006"), format!("part {i}: key {n} is not registered for this tenancy")));
                }
            }
            if sha256(m.keys[0].public_key.as_bytes()).as_bytes() != m.tenancy.as_bytes() {
                return Err(wire(stage, ErrorCode::Hash, format!("part {i}: the tenancy is not the SHA-256 of its first signing key")));
            }
            if let Some(c) = &m.certificate {
                for (idx, pk) in &c.keys {
                    if m.keys.get(*idx as usize).map(|k| &k.public_key) != Some(pk) {
                        return Err(reject(stage, Code::Int("INT-006"), format!("part {i}: the certificate's key {idx} differs from the manifest's")));
                    }
                }
            }
            if let Some(sig) = &part.signature
                && sig.key as usize >= m.keys.len()
            {
                return Err(reject(stage, Code::Int("INT-006"), format!("part {i}: the export is signed with a key outside the history")));
            }
            part.keys = m.keys.iter().map(|k| k.public_key.clone()).collect();
        }
        Ok(())
    }

    /// Stage 6: record signatures, the hash chain, checkpoints and cutoffs (INT-006,
    /// INT-008–009). A partial part (damaged beyond repair, INT-020) keeps every intact record
    /// and writes a loss-ledger entry for each gap.
    pub(super) fn stage_chain(&self, parts: &mut [Part], sub: &mut Submission) -> Result<(), Fail> {
        let stage = Stage::Chain;
        if !parts.iter().all(|p| p.partial) {
            sub.advance(GateState::RecordsOk).map_err(backend)?;
        }
        for (i, part) in parts.iter_mut().enumerate() {
            if let Some(m) = &part.manifest
                && sha256(&part.journal) != m.journal_sha256
            {
                return Err(wire(stage, ErrorCode::Hash, format!("part {i}: the journal does not match the manifest's hash")));
            }
            let report = read_journal(&part.journal, &part.keys, &[]);
            let mut problems: Vec<_> = report
                .errors
                .iter()
                .filter(|e| !matches!(e.code, ErrorCode::Chain | ErrorCode::Seq))
                .filter(|e| !part.partial || !matches!(e.code, ErrorCode::Crc | ErrorCode::FrameLength | ErrorCode::FrameMagic))
                .collect();
            problems.sort_by_key(|e| e.offset);
            if let Some(e) = problems.first() {
                return Err(Fail::Reject(Rejection::new(stage, Code::Wire(e.code), format!("part {i}: {}", e.detail)).at(e.offset)));
            }
            if part.partial {
                for e in report.errors.iter().filter(|e| matches!(e.code, ErrorCode::Crc | ErrorCode::FrameLength | ErrorCode::FrameMagic)) {
                    sub.record(Finding::new(FindingKind::Loss, "INT-020", format!("{}: {} (offset {})", e.code, e.detail, e.offset)));
                }
            }
            let mut entries = report.entries;
            if part.partial {
                entries.sort_by_key(|e| e.record.header.seq);
                entries.dedup_by(|b, a| a.record.header.seq == b.record.header.seq && a.hash == b.hash);
            }
            if entries.is_empty() {
                return Err(wire(stage, ErrorCode::Seq, format!("part {i}: no intact records")));
            }
            for e in &entries {
                if let Some(from) = part.view.key_revoked_from.get(&e.record.header.key)
                    && e.record.header.seq >= from.0
                {
                    return Err(Fail::Reject(
                        Rejection::new(stage, Code::Wire(ErrorCode::Sig), format!("part {i}: key {} is revoked from seq {} (INT-006)", e.record.header.key, from.0)).at(e.offset),
                    ));
                }
            }
            let held: BTreeMap<u64, Digest> = self
                .platform
                .envelopes(&part.view.tenancy)
                .map_err(backend)?
                .into_iter()
                .map(|e| (e.seq.0, e.hash))
                .collect();
            let links: Vec<ChainLink> = entries
                .iter()
                .map(|e| ChainLink { offset: e.offset, seq: e.record.header.seq, prev: e.record.header.prev, hash: e.hash })
                .collect();
            let mut gaps = Vec::new();
            let mut synthetic = Vec::new();
            for (n, link) in links.iter().enumerate() {
                let after = n.checked_sub(1).map(|p| links[p].seq);
                let starts_gap = match after {
                    None => link.seq > 0,
                    Some(a) => link.seq > a + 1,
                };
                if starts_gap {
                    // Continuing what the authority already holds needs no checkpoint; any
                    // other gap waits for one (INT-009).
                    synthetic.push((link.seq - 1, link.prev));
                    if held.get(&(link.seq - 1)) != Some(&link.prev) {
                        gaps.push(Gap { seq: link.seq, prev: link.prev, offset: link.offset, after });
                    }
                }
            }
            let mut errs = verify_chain(&links, &synthetic);
            errs.sort_by_key(|e| e.offset);
            if let Some(e) = errs.first() {
                return Err(Fail::Reject(Rejection::new(stage, Code::Wire(e.code), format!("part {i}: {}", e.detail)).at(e.offset)));
            }
            let held_seqs: BTreeSet<u64> = held.keys().copied().collect();
            if part.partial {
                // Every gap is a loss; the manifest is not available to explain it (INT-020).
                for g in std::mem::take(&mut gaps) {
                    let from = g.after.map_or(0, |a| a + 1);
                    for (a, b) in missing_ranges(from, g.seq - 1, &held_seqs) {
                        part.losses.push(LossLedgerEntry {
                            tenancy: part.view.tenancy,
                            from: Seq(a),
                            through: Seq(b),
                            reason: "damaged beyond repair (INT-020)".to_owned(),
                        });
                    }
                }
            }
            part.gaps = gaps;

            if let Some(m) = &part.manifest {
                let first = &entries[0];
                let last = &entries[entries.len() - 1];
                if m.records != entries.len() as u64
                    || m.first_seq != first.record.header.seq
                    || m.last_seq != last.record.header.seq
                    || m.first_hash != first.hash
                    || m.last_hash != last.hash
                {
                    return Err(wire(stage, ErrorCode::Hash, format!("part {i}: the records do not match the manifest's count, bounds or hashes")));
                }
            }
            // Flags: after a closing record, above a cutoff (INT-008).
            let mut cutoff = part.view.cutoff.map(|c| c.0);
            let mut closing_seq = None;
            if let Some(m) = &part.manifest {
                match &m.end {
                    Some(ManifestEnd::Closing(h)) => {
                        closing_seq = Some(
                            entries
                                .iter()
                                .find(|e| &e.hash == h)
                                .map(|e| e.record.header.seq)
                                .ok_or_else(|| wire(stage, ErrorCode::Hash, format!("part {i}: the manifest's closing hash names no record")))?,
                        );
                    }
                    Some(ManifestEnd::Certificate(cc)) => cutoff = Some(cutoff.map_or(cc.cutoff_seq, |c| c.min(cc.cutoff_seq))),
                    None => {}
                }
            }
            let mut flagged_after_closing = 0;
            let mut flagged_above = 0;
            for e in &entries {
                let seq = e.record.header.seq;
                if closing_seq.is_some_and(|c| seq > c) {
                    part.flag(seq, "after-closing");
                    flagged_after_closing += 1;
                }
                if cutoff.is_some_and(|c| seq > c) {
                    part.flag(seq, "above-cutoff");
                    flagged_above += 1;
                }
            }
            if flagged_after_closing > 0 {
                sub.record(Finding::new(FindingKind::Flag, "INT-008", format!("{flagged_after_closing} record(s) after the closing record (E_CHAIN evidence)")));
            }
            if flagged_above > 0 {
                sub.record(Finding::new(FindingKind::Flag, "INT-008", format!("{flagged_above} record(s) above the cutoff")));
            }
            part.entries = entries;
        }
        if sub.state() == GateState::Certified {
            sub.advance(GateState::RecordsOk).map_err(backend)?;
        }
        if sub.state() == GateState::RecordsOk {
            sub.advance(GateState::Chained).map_err(backend)?;
        }
        Ok(())
    }

    /// Stage 7: decrypts each record with the period's record key in custody (INT-001: only
    /// now that its signature and chain position are valid).
    pub(super) fn stage_decrypt(&self, parts: &mut [Part], sub: &mut Submission) -> Result<(), Fail> {
        let stage = Stage::Decrypt;
        for (i, part) in parts.iter_mut().enumerate() {
            let mut out = Vec::with_capacity(part.entries.len());
            for e in &part.entries {
                let sealed = &e.record.payload;
                if sealed.recipient != e.record.header.period || part.record_key.is_some_and(|k| k != e.record.header.period) {
                    return Err(Fail::Reject(
                        Rejection::new(stage, Code::Wire(ErrorCode::Recipient), format!("part {i}: seq {}: sealed to a key other than the tenancy's period key", e.record.header.seq))
                            .at(e.offset),
                    ));
                }
                let plain = self
                    .custody
                    .open(&sealed.recipient, Purpose::Record, &tags::RECORD_SEAL, sealed, self.caller)
                    .map_err(|err| match self.custody_fail(stage, err) {
                        Fail::Reject(r) => Fail::Reject(r.at(e.offset)),
                        other => other,
                    })?;
                out.push(plain);
            }
            part.plaintexts = out;
        }
        sub.advance(GateState::Decrypted).map_err(backend)?;
        Ok(())
    }

    /// Stage 8: decodes the payloads and checks what only the payloads can show: the `open`
    /// record, the `closing` record, and that every gap is covered by a checkpoint whose hash
    /// agrees with what the authority received (INT-009).
    pub(super) fn stage_payload(&self, parts: &mut [Part]) -> Result<(), Fail> {
        let stage = Stage::Payload;
        for (i, part) in parts.iter_mut().enumerate() {
            let mut payloads = Vec::with_capacity(part.entries.len());
            for (e, plain) in part.entries.iter().zip(&part.plaintexts) {
                let p = Payload::decode(plain).map_err(|err| {
                    Fail::Reject(Rejection::new(stage, Code::Wire(err.code), format!("part {i}: seq {}: {}", e.record.header.seq, err.detail)).at(e.offset))
                })?;
                let seq = e.record.header.seq;
                if seq == 0 && !matches!(p, Payload::Open { .. }) {
                    return Err(Fail::Reject(Rejection::new(stage, Code::Wire(ErrorCode::Chain), format!("part {i}: the record at seq 0 is not an open record (WIRE-039)")).at(e.offset)));
                }
                match &p {
                    Payload::Open { tenancy, build_anchor, .. } => {
                        if tenancy.as_bytes() != part.view.tenancy.as_bytes() {
                            return Err(wire(stage, ErrorCode::Hash, format!("part {i}: the open record names another tenancy")));
                        }
                        if let Some(m) = &part.manifest
                            && &m.build_anchor != build_anchor
                        {
                            return Err(wire(stage, ErrorCode::Hash, format!("part {i}: the open record's build anchor differs from the manifest's")));
                        }
                    }
                    Payload::Closing { last_seq, .. } if *last_seq != seq => {
                        return Err(Fail::Reject(Rejection::new(stage, Code::Wire(ErrorCode::Chain), format!("part {i}: a closing record names a last_seq other than its own")).at(e.offset)));
                    }
                    Payload::Evidence { bytes, .. } if bytes.len() > 3 * 1024 * 1024 => {
                        return Err(Fail::Reject(Rejection::new(stage, Code::Wire(ErrorCode::Size), format!("part {i}: evidence exceeds 3 MiB (WIRE-042)")).at(e.offset)));
                    }
                    _ => {}
                }
                payloads.push(p);
            }
            // A closing record is the last of its journal: later ones are flagged (INT-008).
            if let Some(c) = payloads.iter().position(|p| matches!(p, Payload::Closing { .. })) {
                let closing_seq = part.entries[c].record.header.seq;
                let later: Vec<u64> = part.entries[c + 1..].iter().map(|e| e.record.header.seq).collect();
                for s in later {
                    part.flag(s, "after-closing");
                }
                let _ = closing_seq;
            }
            part.payloads = payloads;
            self.resolve_gaps(part, i)?;
        }
        Ok(())
    }

    fn resolve_gaps(&self, part: &mut Part, i: usize) -> Result<(), Fail> {
        let stage = Stage::Payload;
        if part.gaps.is_empty() {
            return Ok(());
        }
        let held: BTreeMap<u64, Digest> = self
            .platform
            .envelopes(&part.view.tenancy)
            .map_err(backend)?
            .into_iter()
            .map(|e| (e.seq.0, e.hash))
            .collect();
        let held_seqs: BTreeSet<u64> = held.keys().copied().collect();
        let gaps = std::mem::take(&mut part.gaps);
        for g in &gaps {
            let covered = part.payloads.iter().any(|p| {
                matches!(p, Payload::Checkpoint { cleared_through, hash_at, .. } if *cleared_through == g.seq - 1 && *hash_at == g.prev)
            });
            if !covered {
                return Err(Fail::Reject(
                    Rejection::new(stage, Code::Wire(ErrorCode::Seq), format!("part {i}: the gap before seq {} is not covered by a checkpoint (INT-009)", g.seq)).at(g.offset),
                ));
            }
            if let Some(h) = held.get(&(g.seq - 1))
                && h != &g.prev
            {
                return Err(Fail::Reject(
                    Rejection::new(stage, Code::Wire(ErrorCode::Chain), format!("part {i}: the checkpoint's hash differs from the record the authority received at seq {} (INT-009)", g.seq - 1))
                        .at(g.offset),
                ));
            }
            let from = g.after.map_or(0, |a| a + 1);
            for (a, b) in missing_ranges(from, g.seq - 1, &held_seqs) {
                part.losses.push(LossLedgerEntry {
                    tenancy: part.view.tenancy,
                    from: Seq(a),
                    through: Seq(b),
                    reason: "cleared on the device before the authority received it (INT-009)".to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Stage 9: ticks and anchors (INT-010, INT-011, WIRE-071).
    pub(super) fn stage_ticks(&self, parts: &mut [Part], now: AuthorityTime, sub: &mut Submission, _intake: &IntakePolicy) -> Result<(), Fail> {
        let stage = Stage::Ticks;
        for (i, part) in parts.iter_mut().enumerate() {
            let strict = part.entries.first().is_some_and(|e| e.record.header.seq == 0);
            let build = part.manifest.as_ref().map(|m| m.build_anchor).or_else(|| match part.payloads.first() {
                Some(Payload::Open { build_anchor, .. }) => Some(*build_anchor),
                _ => None,
            });
            let mut position: BTreeMap<Digest, usize> = BTreeMap::new();
            let mut times: Vec<Option<AuthorityTime>> = Vec::new();
            if let Some(b) = build {
                position.insert(b, 0);
                times.push(None);
            }
            let mut prev: Option<(usize, u64)> = None;
            let mut fast = false;
            let mut bounds = Vec::with_capacity(part.payloads.len());
            for (e, p) in part.entries.iter().zip(&part.payloads) {
                let t = p.tick();
                let pos = match position.get(&t.anchor) {
                    Some(pos) => *pos,
                    None if !strict => {
                        let pos = times.len();
                        position.insert(t.anchor, pos);
                        times.push(None);
                        pos
                    }
                    None => {
                        return Err(Fail::Reject(
                            Rejection::new(stage, Code::Wire(ErrorCode::Tick), format!("part {i}: seq {}: the tick names an anchor not chained into the journal", e.record.header.seq))
                                .at(e.offset),
                        ));
                    }
                };
                if let Some((pp, ps)) = prev
                    && (pos < pp || (pos == pp && t.slot <= ps))
                {
                    return Err(Fail::Reject(
                        Rejection::new(stage, Code::Wire(ErrorCode::Tick), format!("part {i}: seq {}: ticks must strictly increase (WIRE-071)", e.record.header.seq)).at(e.offset),
                    ));
                }
                prev = Some((pos, t.slot));
                bounds.push(times.get(pos).copied().flatten().and_then(|a| a.checked_add(t.slot)));
                if let Payload::Anchor { address, authority_time, .. } = p {
                    // The anchor record's own slot counts time under the previous anchor; it
                    // must fit in the authority time between the two anchors (INT-010).
                    if let Some(Some(t_prev)) = times.get(pos)
                        && t.slot > authority_time.0.saturating_sub(t_prev.0)
                    {
                        fast = true;
                    }
                    match position.get(address) {
                        Some(known) => times[*known] = Some(*authority_time),
                        None => {
                            position.insert(*address, times.len());
                            times.push(Some(*authority_time));
                        }
                    }
                }
            }
            part.bounds = bounds;

            let provably_late: Vec<u64> = match part.window {
                Some(w) => part
                    .entries
                    .iter()
                    .zip(&part.bounds)
                    .filter(|(_, b)| b.is_some_and(|b| b > w.not_after))
                    .map(|(e, _)| e.record.header.seq)
                    .collect(),
                None => vec![],
            };
            for s in &provably_late {
                part.flag(*s, "provably-late");
            }
            let late_ms = part.window.map_or(0, |w| now.0.saturating_sub(w.not_after.0.saturating_add(w.grace)));
            if part.window.is_some() || fast {
                let facts = BTreeMap::from([
                    ("lateSeconds".to_owned(), Value::Int(i128::from(late_ms / 1000))),
                    ("provablyLate".to_owned(), Value::Bool(!provably_late.is_empty())),
                    ("fastRunning".to_owned(), Value::Bool(fast)),
                ]);
                let (verdict, reasons) = match self.policy.evaluate(DecisionPoint::TenancyLate, self.effective, &facts) {
                    Ok(d) => (d.verdict, d.reasons),
                    Err(e) => {
                        sub.record(Finding::new(FindingKind::Flag, "POL-034", format!("tenancy.late failed: {e}; flagged")));
                        (Verdict::Flag, vec!["policy-unavailable".to_owned()])
                    }
                };
                if verdict == Verdict::Deny {
                    let code = if fast { Code::Wire(ErrorCode::Tick) } else { Code::Int("INT-011") };
                    return Err(reject(stage, code, format!("part {i}: refused by policy: {}", reasons.join(", "))));
                }
                if verdict != Verdict::Allow {
                    let late = reasons.iter().any(|r| r == "late-beyond-grace" || r == "provably-late");
                    for e in &part.entries {
                        let seq = e.record.header.seq;
                        if late {
                            part.flags.entry(seq).or_default().insert("late".to_owned());
                        }
                        if fast {
                            part.flags.entry(seq).or_default().insert("clock-running-fast".to_owned());
                        }
                        if !late && !fast {
                            part.flags.entry(seq).or_default().insert("tenancy-review".to_owned());
                        }
                    }
                    sub.record(Finding::new(FindingKind::Flag, if fast { "INT-010" } else { "INT-011" }, format!("tenancy flagged: {}", reasons.join(", "))));
                }
            }
            if !provably_late.is_empty() {
                sub.record(Finding::new(FindingKind::Flag, "INT-011", format!("{} record(s) provably late", provably_late.len())));
            }
        }
        sub.advance(GateState::Timed).map_err(backend)?;
        Ok(())
    }
}
