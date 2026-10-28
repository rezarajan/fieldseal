//! `EndTenancy` and `ApplyCloseCertificate` (COL-006–COL-010, ADR 0016): the closing
//! record, the outbox, and crypto-erase through the key store.
//!
//! Closing seals a `closing` record, then signs a closing manifest: a complete one-part
//! export file (WIRE-100–WIRE-106) whose manifest is sealed to the authority record key and
//! whose signature is made now, before the keys are deleted, so the outbox part can be
//! delivered later without any live key (DEL-050). Then the tenancy's keys are deleted in
//! the key store (which makes everything under the session key unreadable), and the local
//! record, held bundle, progress data and PIN material are deleted.

use fieldseal_kernel::Value;
use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::tags;
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::export::{ExportFile, ExportHeader, ExportPart, ExportSignature, export_signed_structure};
use fieldseal_kernel::frame::read_frames;
use fieldseal_kernel::id::{Digest, TenancyId};
use fieldseal_kernel::record::{Record, record_hash};
use fieldseal_kernel::seal::{RecipientKey, seal_value};
use fieldseal_kernel::sign::signed_message;
use fieldseal_kernel::structure::Fields;
use fieldseal_trust::ports::SourceRng;

use super::{CollectionError, CollectionEvent, Runtime, names};
use crate::domain::meta::Marker;
use crate::domain::payload::{ClosingReason, Payload};
use crate::domain::{OperationKind, ReceiptCoverage, TenancyState};
use crate::ports::CloseCertificateCheck;

/// One outbox entry (COL §2 `Outbox`): a closed tenancy's journal, waiting for delivery.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum OutboxEntry {
    /// Closed by the collector: a signed one-part export file (the closing manifest).
    Closed {
        /// The tenancy.
        tenancy: TenancyId,
        /// The export file's bytes.
        export: Vec<u8>,
    },
    /// Force-closed by a certificate: the journal with the certificate attached in place of
    /// a closing record (COL-007). No tenancy key signed it.
    Certified {
        /// The tenancy.
        tenancy: TenancyId,
        /// The journal's frames.
        journal: Vec<u8>,
        /// The close or reset certificate's bytes.
        certificate: Vec<u8>,
    },
}

impl OutboxEntry {
    /// The tenancy.
    pub fn tenancy(&self) -> &TenancyId {
        match self {
            Self::Closed { tenancy, .. } | Self::Certified { tenancy, .. } => tenancy,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let v = match self {
            Self::Closed { tenancy, export } => cbor::map([
                ("kind", Value::Text("closed".into())),
                ("tenancy", Value::Bytes(tenancy.as_bytes().to_vec())),
                ("export", Value::Bytes(export.clone())),
            ]),
            Self::Certified { tenancy, journal, certificate } => cbor::map([
                ("kind", Value::Text("certified".into())),
                ("tenancy", Value::Bytes(tenancy.as_bytes().to_vec())),
                ("journal", Value::Bytes(journal.clone())),
                ("certificate", Value::Bytes(certificate.clone())),
            ]),
        };
        cbor::encode(&v).expect("encodable")
    }

    fn decode(bytes: &[u8]) -> Result<Self, CollectionError> {
        let mut f = Fields::new(cbor::decode(bytes)?)?;
        let kind = f.text("kind")?;
        let tenancy = TenancyId::from(f.bytes_n::<32>("tenancy")?);
        let e = match kind.as_str() {
            "closed" => Self::Closed { tenancy, export: f.bytes("export")? },
            "certified" => Self::Certified { tenancy, journal: f.bytes("journal")?, certificate: f.bytes("certificate")? },
            _ => return Err(CollectionError::Failed("unknown outbox entry".into())),
        };
        f.finish()?;
        Ok(e)
    }
}

/// The outbox as anyone using the device may see it: counts only (COL-010).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct OutboxSummary {
    /// Closed tenancies waiting for delivery.
    pub parts: u64,
    /// Their total size in bytes.
    pub bytes: u64,
}

fn outbox_id(tenancy: &TenancyId) -> String {
    fieldseal_kernel::digest::lower_hex(&tenancy.as_bytes()[..8])
}

impl Runtime<'_> {
    /// `EndTenancy` (COL-006): seals the closing record, signs the closing manifest, moves
    /// the journal and manifest to the outbox, and erases the tenancy (keys, local record,
    /// held bundle, progress data, PIN material). Hold-to-confirm is the shell's.
    pub fn end_tenancy(&mut self) -> Result<OutboxSummary, CollectionError> {
        self.active()?;
        if self.capture.as_ref().is_some_and(|c| c.has_unsealed_changes()) {
            return Err(CollectionError::CaptureOpen);
        }
        let state = self.meta()?.state;
        if !matches!(state, TenancyState::Local | TenancyState::Registered | TenancyState::Closing) {
            return Err(CollectionError::WrongState(state));
        }
        if let Some(m) = self.meta.as_mut() {
            m.state = TenancyState::Closing;
        }
        self.save_meta()?;
        let mut marker = Marker { kind: OperationKind::EndTenancy, step: 0, seq: self.meta()?.next_seq(), through: 0, extra: None };
        self.p.storage.write(names::DEVICE, &names::op_marker(), &marker.encode())?;
        self.seal_closing()?;
        marker.step = 1;
        self.p.storage.write(names::DEVICE, &names::op_marker(), &marker.encode())?;
        self.write_closed_outbox()?;
        marker.step = 2;
        self.p.storage.write(names::DEVICE, &names::op_marker(), &marker.encode())?;
        self.erase()?;
        self.p.storage.delete(names::DEVICE, &names::op_marker())?;
        self.outbox_summary()
    }

    fn seal_closing(&mut self) -> Result<(), CollectionError> {
        let meta = self.meta()?;
        let last_seq = meta.next_seq();
        let prev_hash = meta.head.map_or(Digest::from([0; 32]), |(_, h)| h);
        self.seal_record(|tick| Payload::Closing { tick, last_seq, prev_hash, reason: ClosingReason::Collector }, None)?;
        Ok(())
    }

    /// Builds and signs the closing manifest: a one-part export (WIRE-104, WIRE-106).
    pub(crate) fn write_closed_outbox(&mut self) -> Result<(), CollectionError> {
        let meta = self.meta()?.clone();
        let journal = self.journal()?;
        let scan = read_frames(&journal);
        let mut seqs = Vec::new();
        for f in &scan.frames {
            seqs.push((Record::decode(f.body)?.header.seq, record_hash(f.body)));
        }
        let (first, last) = match (seqs.first(), seqs.last()) {
            (Some(a), Some(b)) => (*a, *b),
            _ => return Err(CollectionError::Failed("empty journal".into())),
        };
        let b = |d: &[u8]| Value::Bytes(d.to_vec());
        let u = |n: u64| Value::Int(i128::from(n));
        let certificate = self.registration_document()?;
        let mut manifest = cbor::map([
            ("tenancy", b(meta.tenancy.as_bytes())),
            ("keys", Value::Array(vec![cbor::map([("index", u(0)), ("public_key", b(meta.sign_pub.as_bytes())), ("evidence", b(meta.evidence.first().map_or(&[0u8; 32][..], |d| d.as_bytes())))])])),
            ("records", u(seqs.len() as u64)),
            ("first_seq", u(first.0)),
            ("last_seq", u(last.0)),
            ("first_hash", b(first.1.as_bytes())),
            ("last_hash", b(last.1.as_bytes())),
            ("journal_sha256", b(sha256(&journal).as_bytes())),
            ("end", b(last.1.as_bytes())),
            ("build_anchor", b(meta.build_anchor.as_bytes())),
            ("instruments", Value::Array(meta.instruments.iter().map(|f| b(f.as_bytes())).collect())),
            ("policy", b(meta.policy.map_or([0u8; 32], |p| *p.as_bytes()).as_slice())),
        ]);
        if let (Some(c), Value::Map(m)) = (certificate, &mut manifest) {
            m.insert("certificate".to_owned(), c);
        }
        let sealed = seal_value(&mut SourceRng(self.p.random), &RecipientKey::X25519(meta.record_key), &tags::EXPORT_MANIFEST_SEAL, &manifest)?;
        let manifest_bytes = sealed.encode();
        let header = ExportHeader { handle: meta.handle, parts: 1 };
        let message = signed_message(&tags::EXPORT, &export_signed_structure(&header, &manifest_bytes, &journal))?;
        let sig = self.p.keys.sign(&meta.sign, &message)?;
        let file = ExportFile {
            header,
            parts: vec![ExportPart { manifest: manifest_bytes, journal, signature: ExportSignature { key: 0, sig }, parity: None }],
        };
        let entry = OutboxEntry::Closed { tenancy: meta.tenancy, export: file.encode(false)? };
        self.p.storage.write(names::DEVICE, &names::outbox(&outbox_id(&meta.tenancy)), &entry.encode())?;
        self.events.push(CollectionEvent::TenancyClosed(meta.tenancy));
        Ok(())
    }

    /// Steps 3 and 5 of COL-006: deletes the keys (crypto-erase), the local record, held
    /// bundle, progress data and PIN material, and the journal (already in the outbox).
    /// Idempotent, so recovery can repeat it.
    pub(crate) fn erase(&mut self) -> Result<(), CollectionError> {
        let Some(meta) = self.meta.clone() else { return Ok(()) };
        self.session = None;
        self.capture = None;
        for k in [&meta.sign, &meta.agree, &meta.wrap] {
            if self.p.keys.exists(k) {
                self.p.keys.delete(k)?;
            }
        }
        let storage = self.p.storage;
        for name in storage.names(names::SESSION)? {
            storage.delete(names::SESSION, &name)?;
        }
        for name in [names::bundle(), names::registration(), names::pin_attempts(), names::ticks(), names::seal_marker(), names::journal()] {
            storage.delete(names::DEVICE, &name)?;
        }
        storage.delete(names::DEVICE, &names::tenancy())?;
        self.meta = None;
        self.ticks = None;
        self.events.push(CollectionEvent::TenancyErased(meta.tenancy));
        Ok(())
    }

    /// `ApplyCloseCertificate` (COL-007): verifies the certificate's chain and tenancy, then
    /// moves the journal to the outbox with the certificate attached in place of a closing
    /// record, and erases the tenancy. Needs neither the PIN nor any tenancy key (COL-008).
    pub fn apply_close_certificate(&mut self, bytes: &[u8], check: &dyn CloseCertificateCheck) -> Result<OutboxSummary, CollectionError> {
        let cert = check.verify(bytes).map_err(|e| CollectionError::InvalidCertificate(e.to_string()))?;
        let meta = self.meta()?.clone();
        if cert.tenancy != meta.tenancy {
            return Err(CollectionError::InvalidCertificate("for another tenancy".into()));
        }
        self.session = None;
        self.capture = None;
        if let Some(m) = self.meta.as_mut() {
            m.state = TenancyState::Closing;
        }
        self.save_meta()?;
        let marker = Marker { kind: OperationKind::ApplyCloseCertificate, step: 1, seq: 0, through: 0, extra: None };
        self.p.storage.write(names::DEVICE, &names::op_marker(), &marker.encode())?;
        let entry = OutboxEntry::Certified { tenancy: meta.tenancy, journal: self.journal()?, certificate: cert.bytes };
        self.p.storage.write(names::DEVICE, &names::outbox(&outbox_id(&meta.tenancy)), &entry.encode())?;
        self.events.push(CollectionEvent::TenancyClosed(meta.tenancy));
        self.erase()?;
        self.p.storage.delete(names::DEVICE, &names::op_marker())?;
        self.outbox_summary()
    }

    /// The outbox, as counts only (COL-010). Needs no session.
    pub fn outbox_summary(&self) -> Result<OutboxSummary, CollectionError> {
        let mut s = OutboxSummary::default();
        for name in self.p.storage.names(names::DEVICE)? {
            if name.0.starts_with("outbox/")
                && let Some(b) = self.p.storage.read(names::DEVICE, &name)?
            {
                s.parts += 1;
                s.bytes += b.len() as u64;
            }
        }
        Ok(s)
    }

    /// The outbox entries, for Delivery to export or upload without a session (COL-010,
    /// DEL-050). They hold only data sealed to the authority.
    pub fn outbox(&self) -> Result<Vec<OutboxEntry>, CollectionError> {
        let mut out = Vec::new();
        for name in self.p.storage.names(names::DEVICE)? {
            if name.0.starts_with("outbox/")
                && let Some(b) = self.p.storage.read(names::DEVICE, &name)?
            {
                out.push(OutboxEntry::decode(&b)?);
            }
        }
        Ok(out)
    }

    /// Removes an outbox entry once a verified receipt covers its whole journal (COL-009).
    pub fn remove_outbox(&mut self, coverage: &ReceiptCoverage) -> Result<bool, CollectionError> {
        for entry in self.outbox()? {
            if entry.tenancy() != coverage.tenancy() {
                continue;
            }
            let journal = match &entry {
                OutboxEntry::Closed { export, .. } => ExportFile::decode(export)?.parts.first().map(|p| p.journal.clone()).unwrap_or_default(),
                OutboxEntry::Certified { journal, .. } => journal.clone(),
            };
            let last = read_frames(&journal).frames.last().map(|f| Record::decode(f.body).map(|r| r.header.seq)).transpose()?;
            if last.is_some_and(|l| coverage.through().0 >= l) {
                self.p.storage.delete(names::DEVICE, &names::outbox(&outbox_id(entry.tenancy())))?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}
