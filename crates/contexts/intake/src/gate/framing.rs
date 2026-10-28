//! Stages 1–3: size and framing, parity repair, and the export signature (INT-001–005,
//! INT-020, INT-003, INT-004).

use std::collections::BTreeMap;

use fieldseal_kernel::crc::crc32c;
use fieldseal_kernel::crypto::{Purpose, Signature, tags};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::export::{EXPORT_MAGIC, ExportFile, ExportHeader, ExportPart, SECTION_HEADER_LEN, repair};
use fieldseal_kernel::seal::SealedBox;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{ErrorCode, Value, cbor};
use fieldseal_policy::domain::{DecisionPoint, IntakePolicy, Verdict};
use fieldseal_trust::ports::CustodyError;

use super::{Fail, IntakeService, Part, Step, backend};
use crate::domain::{Code, Finding, FindingKind, GateState, Rejection, Stage, Submission, TenancyView};
use crate::wire::{ExportManifest, RegistrationBody};

/// The largest export file (WIRE §6.7).
const MAX_EXPORT: u64 = 4 * 1024 * 1024 * 1024;

fn reject(stage: Stage, code: Code, detail: impl Into<String>) -> Fail {
    Fail::Reject(Rejection::new(stage, code, detail))
}

/// The header of an export, read from its first section without trusting anything else.
fn read_header(bytes: &[u8]) -> Result<ExportHeader, Fail> {
    let unreadable = |code, offset, detail: &'static str| {
        Fail::Reject(Rejection::new(Stage::Framing, Code::Wire(code), detail).at(offset))
    };
    if !bytes.starts_with(&EXPORT_MAGIC) {
        return Err(unreadable(ErrorCode::FrameMagic, 0, "not an export file"));
    }
    let at = EXPORT_MAGIC.len();
    let head = bytes
        .get(at..at + SECTION_HEADER_LEN)
        .ok_or_else(|| unreadable(ErrorCode::FrameLength, at, "header section truncated"))?;
    if head[0] != 0x01 {
        return Err(unreadable(ErrorCode::ExportSection, at, "the first section is not the header"));
    }
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    let crc = u32::from_be_bytes([head[5], head[6], head[7], head[8]]);
    let start = at + SECTION_HEADER_LEN;
    let body = bytes
        .get(start..start + len)
        .ok_or_else(|| unreadable(ErrorCode::FrameLength, at, "header section runs past the end"))?;
    if crc32c(body) != crc {
        return Err(unreadable(ErrorCode::Crc, at, "header section CRC-32C mismatch"));
    }
    let value = cbor::decode(body).map_err(|e| Fail::Reject(Rejection::new(Stage::Framing, Code::Wire(e.code), e.detail).at(start + e.offset)))?;
    ExportHeader::from_value(value).map_err(|e| Fail::Reject(Rejection::new(Stage::Framing, Code::Wire(e.code), e.detail).at(at)))
}

fn blank_part(view: TenancyView, registered: bool) -> Part {
    Part {
        sealed_manifest: vec![],
        journal: vec![],
        signature: None,
        has_parity: false,
        keys: view.signing_keys.clone(),
        view,
        registered,
        manifest: None,
        entries: vec![],
        gaps: vec![],
        flags: BTreeMap::new(),
        plaintexts: vec![],
        payloads: vec![],
        bounds: vec![],
        losses: vec![],
        partial: false,
        window: None,
        cohorts: vec![],
        record_key: None,
    }
}

impl IntakeService<'_> {
    pub(super) fn custody_fail(&self, stage: Stage, e: CustodyError) -> Fail {
        match e {
            CustodyError::Open(w) => Fail::Reject(Rejection::new(stage, Code::Wire(w.code), w.detail).at(w.offset)),
            CustodyError::UnknownKey => Fail::Reject(Rejection::new(
                stage,
                Code::Wire(ErrorCode::Recipient),
                "the authority holds no key for the recipient the seal names",
            )),
            CustodyError::WrongPurpose { .. } | CustodyError::TagNotAllowed { .. } | CustodyError::Unsupported => {
                Fail::Reject(Rejection::new(stage, Code::Int("TRU-011"), "the key in custody may not open this seal"))
            }
            CustodyError::Backend(b) => backend(b),
        }
    }

    /// Stages 1–3. Returns the parts with their tenancy resolved and their signatures
    /// verified, or the salvaged partial part (INT-020).
    pub(super) fn stage_framing_to_signature(
        &self,
        bytes: &[u8],
        _now: AuthorityTime,
        sub: &mut Submission,
        intake: &IntakePolicy,
    ) -> Step<Vec<Part>> {
        // Stage 1: size, then framing.
        let size = bytes.len() as u64;
        if size > MAX_EXPORT {
            return Err(reject(Stage::Framing, Code::Wire(ErrorCode::Size), "an export file is at most 4 GiB"));
        }
        let facts = BTreeMap::from([
            ("sizeBytes".to_owned(), Value::Int(i128::from(size))),
            ("qualityFailures".to_owned(), Value::Int(0)),
        ]);
        let too_large = match self.policy.evaluate(DecisionPoint::IntakeAccept, self.effective, &facts) {
            Ok(d) => d.verdict == Verdict::Deny,
            Err(e) => {
                sub.record(Finding::new(FindingKind::Flag, "POL-034", format!("intake.accept failed: {e}; size checked against policy")));
                size > intake.max_submission_size.as_bytes()
            }
        };
        if too_large {
            return Err(reject(Stage::Framing, Code::Int("INT-003"), format!("{size} bytes exceeds the intake size limit")));
        }
        let mut current = bytes.to_vec();
        let mut repaired = false;
        let mut damaged = false;
        let file = match ExportFile::decode(&current) {
            Ok(f) => Some(f),
            Err(e) if matches!(e.code, ErrorCode::Crc | ErrorCode::FrameLength) => {
                damaged = true;
                // Stage 2: parity repair (INT-005).
                if intake.parity_repair {
                    match repair(&current) {
                        Ok((fixed, n)) => match ExportFile::decode(&fixed) {
                            Ok(f) => {
                                sub.record(Finding::new(FindingKind::Repair, "INT-005", format!("{n} shard(s) rebuilt from parity")));
                                current = fixed;
                                repaired = true;
                                Some(f)
                            }
                            Err(_) => None,
                        },
                        Err(r) => {
                            sub.record(Finding::new(FindingKind::Loss, "INT-005", format!("{}: {} (offset {})", r.code, r.detail, r.offset)));
                            None
                        }
                    }
                } else {
                    sub.record(Finding::new(FindingKind::Flag, "INT-005", "parity repair is disabled by intake policy"));
                    None
                }
            }
            Err(e) => {
                return Err(Fail::Reject(Rejection::new(Stage::Framing, Code::Wire(e.code), e.detail).at(e.offset)));
            }
        };

        let header = read_header(&current)?;
        let view = self.registry.by_handle(&header.handle).map_err(backend)?;

        let Some(mut file) = file else {
            // Beyond repair: salvage what is intact (INT-020). Only a known tenancy can have
            // its records checked, because the manifest is not available.
            let Some(view) = view else {
                return Err(reject(Stage::Parity, Code::Int("INT-004"), "unknown tenancy handle in a damaged export"));
            };
            sub.advance(GateState::Resolved).map_err(backend)?;
            sub.advance(GateState::Repair).map_err(backend)?;
            sub.advance(GateState::PartialLoss).map_err(backend)?;
            sub.record(Finding::new(
                FindingKind::Flag,
                "INT-020",
                "damaged beyond repair: the export signature and certificate were not checked; intact records are verified one by one",
            ));
            let mut part = blank_part(view, true);
            part.partial = true;
            part.journal = current;
            return Ok(vec![part]);
        };

        // Stage 3: the export signature, by the tenancy key.
        match &view {
            Some(_) => sub.advance(GateState::Resolved).map_err(backend)?,
            None => sub.advance(GateState::Unregistered).map_err(backend)?,
        }
        if damaged {
            sub.advance(GateState::Repair).map_err(backend)?;
        }
        let mut may_repair = !repaired && intake.parity_repair;
        let parts = loop {
            match self.verify_signatures(&header, &file, view.as_ref(), sub) {
                Ok(parts) => break parts,
                Err(Fail::Reject(r)) if r.code == Code::Wire(ErrorCode::Sig) && may_repair && file.parts.iter().any(|p| p.parity.is_some()) => {
                    may_repair = false;
                    match repair(&current) {
                        Ok((fixed, n)) => {
                            let decoded = ExportFile::decode(&fixed);
                            match decoded {
                                Ok(f) => {
                                    sub.record(Finding::new(FindingKind::Repair, "INT-005", format!("signature failed; {n} shard(s) rebuilt from parity")));
                                    current = fixed;
                                    file = f;
                                }
                                Err(_) => return Err(Fail::Reject(r)),
                            }
                        }
                        Err(_) => return Err(Fail::Reject(r)),
                    }
                }
                Err(e) => return Err(e),
            }
        };
        if sub.state() == GateState::Unregistered {
            sub.advance(GateState::Resolved).map_err(backend)?;
        }
        sub.advance(GateState::Signed).map_err(backend)?;
        Ok(parts)
    }

    fn verify_signatures(&self, header: &ExportHeader, file: &ExportFile, view: Option<&TenancyView>, sub: &mut Submission) -> Step<Vec<Part>> {
        let mut parts = Vec::new();
        for (i, p) in file.parts.iter().enumerate() {
            let (view, registered, manifest) = match view {
                Some(v) => (v.clone(), true, None),
                None => {
                    let (v, m) = self.register_from_manifest(header, p, sub)?;
                    (v, false, Some(m))
                }
            };
            let sig = &p.signature;
            let key = usize::try_from(sig.key).ok().and_then(|k| view.signing_keys.get(k)).ok_or_else(|| {
                reject(Stage::ExportSignature, Code::Wire(ErrorCode::Sig), format!("part {i}: the signature names key {} which the tenancy does not have", sig.key))
            })?;
            p.verify(header, key).map_err(|e| {
                Fail::Reject(Rejection::new(Stage::ExportSignature, Code::Wire(e.code), format!("part {i}: {}", e.detail)))
            })?;
            let mut part = blank_part(view, registered);
            part.sealed_manifest = p.manifest.clone();
            part.journal = p.journal.clone();
            part.signature = Some(p.signature.clone());
            part.has_parity = p.parity.is_some();
            part.manifest = manifest;
            parts.push(part);
        }
        Ok(parts)
    }

    /// An unknown handle takes the `Unregistered` path (INT-004): the registration request in
    /// the manifest is opened with the registration key and checked (proof of possession,
    /// WIRE-131, WIRE-132). The manifest of an unregistered tenancy is sealed to the
    /// registration key (WIRE-103), so it is opened before the export signature can be
    /// checked: the signing key is only known from the request inside it.
    fn register_from_manifest(&self, header: &ExportHeader, part: &ExportPart, sub: &mut Submission) -> Step<(TenancyView, ExportManifest)> {
        let no = |detail: &str| reject(Stage::ExportSignature, Code::Int("INT-004"), detail.to_owned());
        let sealed = SealedBox::decode(&part.manifest).map_err(|e| no(&format!("unknown tenancy handle and unreadable manifest ({})", e.code)))?;
        let plaintext = self
            .custody
            .open(&sealed.recipient, Purpose::Registration, &tags::EXPORT_MANIFEST_SEAL, &sealed, self.caller)
            .map_err(|e| match e {
                CustodyError::Backend(b) => backend(b),
                _ => no("unknown tenancy handle and the manifest is not sealed to the registration key"),
            })?;
        let manifest = cbor::decode(&plaintext)
            .and_then(ExportManifest::from_value)
            .map_err(|e| no(&format!("unknown tenancy handle and undecodable manifest ({})", e.code)))?;
        let request = manifest.registration.clone().ok_or_else(|| no("unknown tenancy handle and the manifest carries no registration request"))?;
        let body_plain = self
            .custody
            .open(&request.recipient, Purpose::Registration, &tags::REGISTRATION_SEAL, &request, self.caller)
            .map_err(|e| match e {
                CustodyError::Backend(b) => backend(b),
                _ => no("the registration request cannot be opened"),
            })?;
        let value = cbor::decode(&body_plain).map_err(|e| no(&format!("registration request: {}", e.code)))?;
        let Value::Map(mut m) = value else { return Err(no("registration request is not a map")) };
        let (Some(body_v), Some(Value::Bytes(pop))) = (m.remove("body"), m.remove("pop")) else {
            return Err(no("registration request lacks body or pop"));
        };
        if !m.is_empty() {
            return Err(no("registration request carries fields other than body and pop"));
        }
        let body = RegistrationBody::from_value(body_v.clone()).map_err(|e| no(&format!("registration body: {}", e.code)))?;
        if sha256(body.sign_pub.as_bytes()).as_bytes() != body.tenancy.as_bytes() {
            return Err(no("registration request: tenancy is not the SHA-256 of sign_pub (WIRE-131)"));
        }
        let body_sha = sha256(&cbor::encode(&body_v).map_err(|e| no(&format!("registration body: {}", e.code)))?);
        let pop_structure = cbor::map([
            ("nonce", Value::Bytes(body.nonce.to_vec())),
            ("body_sha256", Value::Bytes(body_sha.as_bytes().to_vec())),
        ]);
        fieldseal_kernel::sign::verify(&body.sign_pub, &tags::REGISTRATION_POP, &pop_structure, &Signature(pop))
            .map_err(|_| no("registration request: proof of possession does not verify (WIRE-132)"))?;
        if manifest.tenancy != body.tenancy {
            return Err(no("the manifest and the registration request name different tenancies"));
        }
        sub.record(Finding::new(
            FindingKind::Flag,
            "INT-004",
            "tenancy registered from the registration request in its manifest; Registration's approval is still required",
        ));
        let view = TenancyView::new(body.tenancy, header.handle, vec![body.sign_pub]);
        Ok((view, manifest))
    }
}
