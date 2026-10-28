//! Use cases: the driving ports the Delivery context offers
//! (`docs/reference/spec/delivery.md` §3), implemented by [`DeliveryService`] over the
//! collection [`Runtime`].
//!
//! | Spec port | Methods |
//! |---|---|
//! | `StartBackgroundUpload` | [`DeliveryService::upload`], [`DeliveryService::background_tick`] |
//! | `BuildExport` | [`DeliveryService::build_export`], [`DeliveryService::build_outbox_export`] |
//! | `DeliverExport` | [`DeliveryService::deliver_file`], [`DeliveryService::deliver_share`] |
//! | `ImportReceipt` | [`DeliveryService::import_receipt`] |
//! | `QueryDeliveryState` | [`DeliveryService::delivery_states`], [`DeliveryService::outstanding`] |
//!
//! The service is pure in the ADR 0028 sense: keys, time, randomness, storage, files and
//! the network all arrive through [`Ports`].

use std::collections::BTreeSet;

use fieldseal_collection::application::{CollectionError, OutboxEntry, ReceiptOutcome, Runtime};
use fieldseal_collection::domain::{DeliveryState, ReceiptClaim, ReceiptCoverage};
use fieldseal_collection::ports::{ReceiptCheck, WallClock};
use fieldseal_kernel::digest::{lower_hex, sha256};
use fieldseal_kernel::export::ExportFile;
use fieldseal_kernel::frame::read_frames;
use fieldseal_kernel::id::{Digest, Seq, TenancyId};
use fieldseal_kernel::record::{Record, read_journal, record_hash};
use fieldseal_kernel::{Value, cbor};
use fieldseal_policy::domain::RuntimeEvaluator;
use fieldseal_trust::ports::{RandomSource, SecureKeyStore};

use crate::checks::receipt_claim;
use crate::domain::{
    AddressHint, AttemptOutcome, AuthorisedDestination, DestinationAttempt, DestinationClass, Export, ExportId, HintSource,
    PopToken, ReceiverChallenge, UploadRequest, UploadRoute, export_file_name,
};
use crate::export::{self, Finding, PartContext, manifest_keys};
use crate::ports::{
    DestinationHandle, FileAccess, FileAccessError, PrivateStorage, PrivateStorageError, QrScanner, ReceiverCheck, RegistrationRecords,
    ShareOutcome, ShareTarget, UploadError, UploadTransport,
};

/// Why a receipt was refused (DEL §3 `ImportReceipt`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptRejection {
    /// The bytes aren't a receipt, or the signature or signer doesn't check out (DEL-007,
    /// DEL-064).
    BadSignature,
    /// The receipt is for a tenancy this device doesn't hold.
    UnknownTenancy,
    /// The receipt's journal hash isn't the hash of this device's record at that `seq`.
    HashMismatch,
}

/// Why a delivery use case failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeliveryError {
    /// No network: nothing answered.
    #[error("no network")]
    NoNetwork,
    /// The tenancy isn't registered, so it can't upload.
    #[error("not registered")]
    NotRegistered,
    /// The endpoint refused the proof-of-possession token.
    #[error("token rejected")]
    TokenRejected,
    /// No address passed the receiver challenge (DEL-062).
    #[error("no authorised destination")]
    NoAuthorisedDestination,
    /// Nothing to upload: a receipt covers every record the last upload sent.
    #[error("nothing to upload")]
    NothingToUpload,
    /// Background upload is off in runtime policy.
    #[error("background upload is off")]
    BackgroundOff,
    /// The export failed self-verification and was not offered (DEL-013).
    #[error("export failed verification")]
    VerificationFailed(Vec<Finding>),
    /// The export couldn't be assembled.
    #[error("export could not be built: {0}")]
    BuildFailed(String),
    /// Private storage is full.
    #[error("storage full")]
    StorageFull,
    /// Parity may not be turned off by runtime policy.
    #[error("parity cannot be turned off")]
    ParityRequired,
    /// The destination isn't allowed by runtime policy, or is not a file destination.
    #[error("destination not allowed")]
    DestinationNotAllowed,
    /// Writing to the destination failed.
    #[error("write failed: {0}")]
    WriteFailed(String),
    /// The destination returned other bytes than were written (DEL-023).
    #[error("read-back mismatch")]
    ReadBackMismatch,
    /// The collector cancelled.
    #[error("cancelled")]
    Cancelled,
    /// The export isn't in private storage.
    #[error("unknown export")]
    UnknownExport,
    /// A receipt didn't verify.
    #[error("receipt rejected")]
    ReceiptRejected(ReceiptRejection),
    /// The session is locked; exporting the active tenancy needs it (DEL-029).
    #[error("session locked")]
    Locked,
    /// Collection refused.
    #[error("collection: {0}")]
    Collection(String),
}

impl From<CollectionError> for DeliveryError {
    fn from(e: CollectionError) -> Self {
        match e {
            CollectionError::Locked => Self::Locked,
            e => Self::Collection(e.to_string()),
        }
    }
}

impl From<PrivateStorageError> for DeliveryError {
    fn from(e: PrivateStorageError) -> Self {
        match e {
            PrivateStorageError::Full => Self::StorageFull,
            PrivateStorageError::Backend(b) => Self::BuildFailed(b),
        }
    }
}

/// A domain event (DEL §2). None carries a destination name, path, account or any personal
/// data (DEL §7 factor XI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryEvent {
    /// An export was built.
    ExportBuilt {
        /// Records in it.
        records: u64,
        /// Whether it carries parity.
        parity: bool,
    },
    /// It passed self-verification.
    ExportVerified,
    /// Self-verification refused it (DEL-013).
    ExportRefused,
    /// A copy was written, synced and read back identical.
    CopySavedAndChecked(DestinationClass),
    /// A copy was handed over, unconfirmed.
    CopyHandedOver(DestinationClass),
    /// A copy failed.
    CopyFailed(DestinationClass),
    /// An upload was accepted and returned receipts.
    UploadAccepted,
    /// A destination failed the receiver challenge (DEL-063); logged without the address.
    ChallengeFailed(&'static str),
    /// A receipt verified.
    ReceiptVerified,
    /// Every record through a `seq` is covered by a receipt.
    DeliveryConditionMet(Seq),
}

/// The platform and server-side ports the service runs on.
#[derive(Clone, Copy)]
pub struct Ports<'a> {
    /// The key store, for proof-of-possession tokens and export signatures (the spec's
    /// `ProofSigner`).
    pub keys: &'a dyn SecureKeyStore,
    /// Randomness: nonces, token identifiers, manifest seals, retry jitter.
    pub random: &'a dyn RandomSource,
    /// The untrusted wall clock: file names and token times.
    pub wall: &'a dyn WallClock,
    /// How to reach an upload endpoint.
    pub transport: &'a dyn UploadTransport,
    /// Judges a destination's answer to the receiver challenge.
    pub receiver: &'a dyn ReceiverCheck,
    /// Judges receipts (Collection's port, the spec's `ReceiptVerifier`).
    pub receipts: &'a dyn ReceiptCheck,
    /// Destinations chosen through the platform's file picker.
    pub files: &'a dyn FileAccess,
    /// The share sheet.
    pub share: &'a dyn ShareTarget,
    /// Device-encrypted storage for exports being built.
    pub storage: &'a dyn PrivateStorage,
    /// The registration documents a manifest carries.
    pub records: &'a dyn RegistrationRecords,
}

/// What a successful upload achieved.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UploadResult {
    /// The attempt: class `upload`, label **Received**.
    pub attempt: DestinationAttempt,
    /// What applying the receipt did, including the clear on offer (COL-103).
    pub receipt: ReceiptOutcome,
    /// The highest `seq` the receipt covers.
    pub covered_through: Seq,
    /// What the verified receipt covers, for a `Clear` that deletes journal frames under it
    /// (COL-105, COL-106).
    pub coverage: ReceiptCoverage,
    /// The address that worked, to try first next time (DEL-065).
    pub next_hint: AddressHint,
}

/// What one background tick did.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Tick {
    /// Everything uploaded is covered; nothing to do.
    Idle,
    /// A failure's backoff has not elapsed yet.
    Waiting {
        /// When to try again, in the caller's clock.
        until_ms: u64,
    },
    /// Uploaded and receipted.
    Uploaded(UploadResult),
    /// The attempt failed; it will be retried after the backoff (DEL-005).
    Failed {
        /// Why.
        error: DeliveryError,
        /// When to try again.
        retry_at_ms: u64,
    },
}

/// Where an export copy is going, besides an upload.
pub enum Target<'a> {
    /// A file destination chosen through the picker.
    File(&'a DestinationHandle),
    /// Another app, from this allow-list of targets.
    Share(&'a [String]),
}

/// The Delivery use cases.
pub struct DeliveryService<'a> {
    ports: Ports<'a>,
    policy: &'a RuntimeEvaluator,
    events: Vec<DeliveryEvent>,
    attempts: Vec<DestinationAttempt>,
    failed_addresses: BTreeSet<String>,
}

struct Dyn<'x>(&'x dyn ReceiptCheck);

impl ReceiptCheck for Dyn<'_> {
    fn verify(&self, claim: &ReceiptClaim) -> Result<(), fieldseal_collection::ports::ReceiptCheckError> {
        self.0.verify(claim)
    }
}

fn hex(t: &TenancyId) -> String {
    lower_hex(&t.as_bytes()[..8])
}

fn hint_rank(source: HintSource) -> u8 {
    match source {
        HintSource::PreviousSuccess => 0,
        HintSource::DeviceConfiguration => 1,
        HintSource::ScannedQr | HintSource::CollectorEntry => 2,
        HintSource::BundleHint => 3,
    }
}

/// The record hash at `seq` in a journal's frames, if the frame is present.
fn hash_at(journal: &[u8], seq: u64) -> Option<Digest> {
    read_frames(journal)
        .frames
        .iter()
        .find_map(|f| Record::decode(f.body).ok().filter(|r| r.header.seq == seq).map(|_| record_hash(f.body)))
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
struct RetryState {
    attempts: u64,
    next_at_ms: u64,
    settled_head: u64,
    has_settled: bool,
}

impl RetryState {
    fn encode(&self) -> Vec<u8> {
        let u = |n: u64| Value::Int(i128::from(n));
        let mut entries = vec![("attempts", u(self.attempts)), ("next_at", u(self.next_at_ms))];
        if self.has_settled {
            entries.push(("settled", u(self.settled_head)));
        }
        cbor::encode(&cbor::map(entries)).expect("encodes")
    }

    /// Strict decode: unknown fields, wrong types and missing required fields are errors.
    fn decode(bytes: &[u8]) -> Result<Self, fieldseal_kernel::error::WireError> {
        let mut f = fieldseal_kernel::structure::Fields::new(cbor::decode(bytes)?)?;
        let attempts = f.uint("attempts")?;
        let next_at_ms = f.uint("next_at")?;
        let settled = f.take_opt("settled").map(fieldseal_kernel::structure::expect_uint).transpose()?;
        f.finish()?;
        Ok(Self { attempts, next_at_ms, settled_head: settled.unwrap_or(0), has_settled: settled.is_some() })
    }
}

impl<'a> DeliveryService<'a> {
    /// A service over `ports`, with decisions from the runtime policy.
    pub fn new(ports: Ports<'a>, policy: &'a RuntimeEvaluator) -> Self {
        Self { ports, policy, events: Vec::new(), attempts: Vec::new(), failed_addresses: BTreeSet::new() }
    }

    /// Takes the events raised since the last call.
    pub fn take_events(&mut self) -> Vec<DeliveryEvent> {
        std::mem::take(&mut self.events)
    }

    /// Every copy attempt this session and what it earned. Destinations are not recorded
    /// (DEL-028).
    pub fn attempts(&self) -> &[DestinationAttempt] {
        &self.attempts
    }

    // ---------------------------------------------------------------------------------
    // BuildExport

    fn next_name(&self, tenancy: &TenancyId) -> Result<String, DeliveryError> {
        let marker = format!("export-counter/{}", hex(tenancy));
        let n = self
            .ports
            .storage
            .get_marker(&marker)?
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map_or(0, u64::from_be_bytes)
            + 1;
        self.ports.storage.put_marker(&marker, &n.to_be_bytes())?;
        let p = self.policy.policy();
        Ok(export_file_name(&p.export.file_prefix, &p.export.file_extension, self.ports.wall.now_ms(), n))
    }

    fn resolve_parity(&self, choice: Option<bool>) -> Result<bool, DeliveryError> {
        match choice {
            None => Ok(self.policy.parity_default_on()),
            Some(false) if !self.policy.may_turn_parity_off() => Err(DeliveryError::ParityRequired),
            Some(p) => Ok(p),
        }
    }

    /// `BuildExport` for the open tenancy (DEL-010–DEL-018): assembles the export in
    /// private storage, verifies it in full, and only then returns it. `parity` is the
    /// collector's choice for this export alone (DEL-015): `None` takes the policy default
    /// (DEL-014). Needs an unlocked session (DEL-029).
    pub fn build_export(&mut self, rt: &mut Runtime<'_>, parity: Option<bool>) -> Result<Export, DeliveryError> {
        let with_parity = self.resolve_parity(parity)?;
        let source = rt.export_source(true)?;
        let attachments = self.ports.records.attachments(&source.tenancy);
        let built = export::assemble(&source, &attachments, self.ports.keys, self.ports.random, with_parity)
            .map_err(|e| DeliveryError::BuildFailed(e.to_string()))?;
        self.events.push(DeliveryEvent::ExportBuilt { records: built.records, parity: with_parity });
        // DEL-012: the same checks intake makes, minus decryption.
        let ctx = PartContext {
            keys: source.keys.iter().map(|(_, k, _)| k.clone()).collect(),
            checkpoints: source.checkpoints.clone(),
            recipient: Some(source.period),
            manifest: Some(built.manifest.clone()),
        };
        let report = export::verify(&built.bytes, &[Some(ctx)]);
        if !report.ok() || !report.signature_checked || report.parity_parts != usize::from(with_parity) {
            self.events.push(DeliveryEvent::ExportRefused);
            return Err(DeliveryError::VerificationFailed(report.findings));
        }
        self.events.push(DeliveryEvent::ExportVerified);
        self.store(Some(source.tenancy), built.bytes, built.first_seq, built.last_seq, built.records, with_parity)
    }

    /// `BuildExport` for the outbox (DEL-050, DEL-051): one part per closed tenancy, each
    /// signed at close, buildable with no live key and no session. The result is verified
    /// structurally: the parts' keys are gone with their tenancies, so signatures were
    /// checked when they were made.
    pub fn build_outbox_export(&mut self, rt: &Runtime<'_>, parity: Option<bool>) -> Result<Export, DeliveryError> {
        let with_parity = self.resolve_parity(parity)?;
        let mut files = Vec::new();
        for entry in rt.outbox()? {
            if let OutboxEntry::Closed { export, .. } = entry {
                files.push(export);
            }
        }
        if files.is_empty() {
            return Err(DeliveryError::NothingToUpload);
        }
        let bytes = export::merge_parts(&files, with_parity).map_err(|e| DeliveryError::BuildFailed(e.to_string()))?;
        self.events.push(DeliveryEvent::ExportBuilt { records: 0, parity: with_parity });
        let report = export::verify(&bytes, &[]);
        if !report.ok() || report.parity_parts != if with_parity { report.parts } else { 0 } {
            self.events.push(DeliveryEvent::ExportRefused);
            return Err(DeliveryError::VerificationFailed(report.findings));
        }
        self.events.push(DeliveryEvent::ExportVerified);
        let info = export::inspect(&bytes).map_err(|e| DeliveryError::BuildFailed(e.to_string()))?;
        let from = info.parts.iter().filter_map(|p| p.seq_range.map(|r| r.0)).min().unwrap_or(0);
        let through = info.parts.iter().filter_map(|p| p.seq_range.map(|r| r.1)).max().unwrap_or(0);
        let records = info.parts.iter().map(|p| p.records).sum();
        self.store(None, bytes, from, through, records, with_parity)
    }

    fn store(&mut self, tenancy: Option<TenancyId>, bytes: Vec<u8>, from: u64, through: u64, records: u64, parity: bool) -> Result<Export, DeliveryError> {
        let id = ExportId(sha256(&bytes));
        self.ports.storage.put(&id, &bytes)?;
        // The outbox has its own counter: its exports belong to no open tenancy.
        let name = self.next_name(&tenancy.unwrap_or(TenancyId::from([0; 32])))?;
        Ok(Export { id, tenancy, from: Seq(from), through: Seq(through), records, parity, size: bytes.len() as u64, name })
    }

    // ---------------------------------------------------------------------------------
    // DeliverExport

    /// `DeliverExport` to a file destination (DEL-020–DEL-023, DEL-028). The class comes
    /// from the platform's report of the destination, never from the collector. For
    /// `local` and `removable` the file is written, synced and read back through the same
    /// handle, and the SHA-256 compared: a match is **Saved and checked**, a mismatch
    /// **Failed** and the copy doesn't count. `cloud` is only ever **Handed over - not
    /// confirmed** (DEL-024).
    pub fn deliver_file(&mut self, rt: &mut Runtime<'_>, export: &Export, handle: &DestinationHandle) -> Result<DestinationAttempt, DeliveryError> {
        let report = self.ports.files.report(handle);
        let class = report.class;
        if class == DestinationClass::Upload || class == DestinationClass::Share || !self.policy.export_allowed(class.destination()) {
            return Err(DeliveryError::DestinationNotAllowed);
        }
        let bytes = self.ports.storage.get(&export.id)?.ok_or(DeliveryError::UnknownExport)?;
        let fail = |this: &mut Self, e: DeliveryError| {
            this.attempts.push(DestinationAttempt::new(class, AttemptOutcome::Failed));
            this.events.push(DeliveryEvent::CopyFailed(class));
            Err(e)
        };
        let written = self.ports.files.write(handle, &bytes).and_then(|()| self.ports.files.sync(handle));
        if let Err(e) = written {
            return match e {
                FileAccessError::Cancelled => Err(DeliveryError::Cancelled),
                e => fail(self, DeliveryError::WriteFailed(e.to_string())),
            };
        }
        let outcome = match class {
            DestinationClass::Local | DestinationClass::Removable => match self.ports.files.read_back(handle) {
                Ok(back) if sha256(&back) == export.id.0 => AttemptOutcome::ReadBackMatched,
                Ok(_) => return fail(self, DeliveryError::ReadBackMismatch),
                Err(e) => return fail(self, DeliveryError::WriteFailed(e.to_string())),
            },
            _ => AttemptOutcome::HandedOver,
        };
        self.record_copy(rt, export, class, outcome)
    }

    /// `DeliverExport` through the share sheet (DEL-025): only ever **Handed over - not
    /// confirmed**, since only success or failure is known.
    pub fn deliver_share(&mut self, rt: &mut Runtime<'_>, export: &Export, allowed: &[String]) -> Result<DestinationAttempt, DeliveryError> {
        if !self.policy.export_allowed(DestinationClass::Share.destination()) {
            return Err(DeliveryError::DestinationNotAllowed);
        }
        let bytes = self.ports.storage.get(&export.id)?.ok_or(DeliveryError::UnknownExport)?;
        match self.ports.share.share(&bytes, allowed) {
            ShareOutcome::Shared => self.record_copy(rt, export, DestinationClass::Share, AttemptOutcome::HandedOver),
            ShareOutcome::Cancelled => Err(DeliveryError::Cancelled),
            ShareOutcome::Failed => {
                self.attempts.push(DestinationAttempt::new(DestinationClass::Share, AttemptOutcome::Failed));
                self.events.push(DeliveryEvent::CopyFailed(DestinationClass::Share));
                Err(DeliveryError::WriteFailed("share failed".into()))
            }
        }
    }

    fn record_copy(&mut self, rt: &mut Runtime<'_>, export: &Export, class: DestinationClass, outcome: AttemptOutcome) -> Result<DestinationAttempt, DeliveryError> {
        let attempt = DestinationAttempt::new(class, outcome);
        // An outbox export holds other tenancies' records: no open tenancy's state moves.
        if export.tenancy.is_none() || export.tenancy != rt.tenancy() {
            self.attempts.push(attempt);
            return Ok(attempt);
        }
        match outcome {
            AttemptOutcome::ReadBackMatched => {
                rt.mark_delivered(export.through, DeliveryState::SavedAndChecked)?;
                self.events.push(DeliveryEvent::CopySavedAndChecked(class));
            }
            _ => {
                rt.mark_delivered(export.through, DeliveryState::HandedOver)?;
                self.events.push(DeliveryEvent::CopyHandedOver(class));
            }
        }
        self.attempts.push(attempt);
        Ok(attempt)
    }

    // ---------------------------------------------------------------------------------
    // Receipts

    /// `ImportReceipt` (DEL-007, DEL-040–DEL-042): verifies a receipt's signature and
    /// signer (Collection's `ReceiptCheck`), its tenancy and its journal hash, and only
    /// then changes delivery state. The same checks apply whether the bytes came from an
    /// upload response, a file or a scanned code.
    pub fn import_receipt(&mut self, rt: &mut Runtime<'_>, bytes: &[u8]) -> Result<ReceiptOutcome, DeliveryError> {
        let claim = receipt_claim(bytes).map_err(|_| DeliveryError::ReceiptRejected(ReceiptRejection::BadSignature))?;
        self.apply_claim(rt, &claim).map(|(outcome, _)| outcome)
    }

    /// `ImportReceipt` from the text form a QR code carries (`FS1R:…`, WIRE-144, DEL-042).
    pub fn import_receipt_text(&mut self, rt: &mut Runtime<'_>, text: &str) -> Result<ReceiptOutcome, DeliveryError> {
        let bytes = fieldseal_kernel::text::decode(fieldseal_kernel::text::RECEIPT_PREFIX, text)
            .map_err(|_| DeliveryError::ReceiptRejected(ReceiptRejection::BadSignature))?;
        self.import_receipt(rt, &bytes)
    }

    /// `ImportReceipt` from a code scanned off another screen (DEL-042): the camera reads it
    /// straight into memory and it gets the same checks as a receipt from an upload.
    pub fn import_receipt_scan(&mut self, rt: &mut Runtime<'_>, scanner: &dyn QrScanner) -> Result<ReceiptOutcome, DeliveryError> {
        let scanned = scanner.scan().map_err(|_| DeliveryError::Cancelled)?;
        let text = String::from_utf8(scanned).map_err(|_| DeliveryError::ReceiptRejected(ReceiptRejection::BadSignature))?;
        self.import_receipt_text(rt, &text)
    }

    fn verified(&self, claim: &ReceiptClaim) -> Result<ReceiptCoverage, DeliveryError> {
        ReceiptCoverage::verify(claim, &Dyn(self.ports.receipts)).map_err(|_| DeliveryError::ReceiptRejected(ReceiptRejection::BadSignature))
    }

    fn apply_claim(&mut self, rt: &mut Runtime<'_>, claim: &ReceiptClaim) -> Result<(ReceiptOutcome, ReceiptCoverage), DeliveryError> {
        let coverage = self.verified(claim)?;
        let reject = |r| Err(DeliveryError::ReceiptRejected(r));
        if rt.tenancy() != Some(claim.tenancy) {
            // A receipt for a closed tenancy marks its outbox part delivered (DEL-041).
            let part = rt.outbox()?.into_iter().find_map(|e| match e {
                OutboxEntry::Closed { tenancy, export } if tenancy == claim.tenancy => {
                    ExportFile::decode(&export).ok().and_then(|f| f.parts.first().map(|p| p.journal.clone()))
                }
                OutboxEntry::Certified { tenancy, journal, .. } if tenancy == claim.tenancy => Some(journal),
                _ => None,
            });
            let Some(journal) = part else { return reject(ReceiptRejection::UnknownTenancy) };
            if hash_at(&journal, claim.last_seq.0) != Some(claim.journal_hash) {
                return reject(ReceiptRejection::HashMismatch);
            }
            self.events.push(DeliveryEvent::ReceiptVerified);
            rt.remove_outbox(&coverage)?;
            self.events.push(DeliveryEvent::DeliveryConditionMet(claim.last_seq));
            return Ok((ReceiptOutcome { journal_deleted: 0, offer_clear_through: None }, coverage));
        }
        // DEL-007: the journal hash must be this device's hash at that seq.
        let report = read_journal(&rt.journal()?, &rt.key_history(), &rt.checkpoints());
        let ours = report
            .entries
            .iter()
            .find(|e| e.record.header.seq == claim.last_seq.0)
            .map(|e| e.hash)
            .or_else(|| rt.checkpoints().iter().find(|(s, _)| *s == claim.last_seq.0).map(|(_, h)| *h));
        if ours != Some(claim.journal_hash) {
            return reject(ReceiptRejection::HashMismatch);
        }
        self.events.push(DeliveryEvent::ReceiptVerified);
        let outcome = rt.apply_receipt(&coverage)?;
        self.events.push(DeliveryEvent::DeliveryConditionMet(claim.last_seq));
        Ok((outcome, coverage))
    }

    /// `QueryDeliveryState`: each record's delivery state (DEL-030).
    pub fn delivery_states(&self, rt: &Runtime<'_>) -> Result<Vec<(Seq, DeliveryState)>, DeliveryError> {
        let mut out = Vec::new();
        for f in read_frames(&rt.journal()?).frames {
            if let Ok(r) = Record::decode(f.body) {
                out.push((Seq(r.header.seq), rt.delivery_state(Seq(r.header.seq))));
            }
        }
        Ok(out)
    }

    /// The records no receipt covers yet.
    pub fn outstanding(&self, rt: &Runtime<'_>) -> Result<Vec<Seq>, DeliveryError> {
        Ok(self.delivery_states(rt)?.into_iter().filter(|(_, s)| *s != DeliveryState::Received).map(|(s, _)| s).collect())
    }

    /// Whether the delivery condition holds for every record in `from..=through`: each is
    /// covered by a verified receipt. A handed-over copy never counts (DEL-032, DEL-033,
    /// DEL-070).
    pub fn condition_met(&self, rt: &Runtime<'_>, from: Seq, through: Seq) -> Result<bool, DeliveryError> {
        Ok(self.delivery_states(rt)?.into_iter().filter(|(s, _)| *s >= from && *s <= through).all(|(_, st)| st == DeliveryState::Received))
    }

    // ---------------------------------------------------------------------------------
    // Upload

    fn candidates(&self, hints: &[AddressHint]) -> Vec<AddressHint> {
        let mut v: Vec<AddressHint> = hints.iter().filter(|h| !self.failed_addresses.contains(&h.address)).cloned().collect();
        v.sort_by_key(|h| hint_rank(h.source));
        v.dedup_by(|a, b| a.address == b.address);
        v
    }

    /// Runs the receiver challenge against each candidate in order (last successful,
    /// configured, hinted; DEL-065) and returns the first that passes. A failed challenge
    /// is logged without personal data and not retried at that address in this session
    /// (DEL-063). Nothing is sent to an address that fails (DEL-062).
    fn authorise_first(&mut self, hints: &[AddressHint], tenancy_handle: fieldseal_kernel::id::TenancyHandle) -> Result<AuthorisedDestination, DeliveryError> {
        let mut unreachable = 0;
        let candidates = self.candidates(hints);
        let total = candidates.len();
        for hint in candidates {
            let challenge = ReceiverChallenge::new(self.ports.random.nonce(), tenancy_handle);
            match self.ports.transport.challenge(&hint, &challenge) {
                Err(UploadError::Unreachable) => unreachable += 1,
                Err(_) => {
                    self.failed_addresses.insert(hint.address.clone());
                    self.events.push(DeliveryEvent::ChallengeFailed("malformed"));
                }
                Ok(proof) => match AuthorisedDestination::authorise(hint.clone(), &challenge, &proof, self.ports.receiver) {
                    Ok(d) => return Ok(d),
                    Err(e) => {
                        self.failed_addresses.insert(hint.address.clone());
                        self.events.push(DeliveryEvent::ChallengeFailed(match e {
                            crate::ports::ReceiverCheckError::NotAuthorised => "not-authorised",
                            crate::ports::ReceiverCheckError::BadSignature => "bad-signature",
                        }));
                    }
                },
            }
        }
        if total > 0 && unreachable == total { Err(DeliveryError::NoNetwork) } else { Err(DeliveryError::NoAuthorisedDestination) }
    }

    fn pop_token(&self, source: &fieldseal_collection::application::ExportSource, url: String) -> Result<PopToken, DeliveryError> {
        let mut pop = PopToken {
            tenancy: source.tenancy,
            method: "POST".into(),
            url,
            iat: fieldseal_kernel::time::AuthorityTime(self.ports.wall.now_ms().unwrap_or(0)),
            jti: self.ports.random.nonce().as_bytes()[..16].try_into().expect("16 bytes"),
            ath: None,
            signature: fieldseal_kernel::crypto::Signature(vec![0; 64]),
        };
        pop.signature = self.ports.keys.sign(&source.sign, &pop.message()).map_err(|_| DeliveryError::TokenRejected)?;
        Ok(pop)
    }

    fn map_upload(e: UploadError) -> DeliveryError {
        match e {
            UploadError::Unreachable => DeliveryError::NoNetwork,
            UploadError::TokenRejected => DeliveryError::TokenRejected,
            UploadError::Rejected(r) => DeliveryError::BuildFailed(format!("rejected: {r}")),
            UploadError::Malformed(m) => DeliveryError::BuildFailed(format!("malformed answer: {m}")),
        }
    }

    /// `StartBackgroundUpload` (DEL-001–DEL-008, DEL-060–DEL-066): builds the upload body
    /// (an export without parity, DEL-016), completes the receiver challenge with each
    /// candidate address in turn, sends the body with a proof-of-possession token bound to
    /// the request, verifies the receipt, and applies it to the runtime. Needs no session
    /// and never blocks collection (DEL-005): a failure is an `Err` and changes nothing.
    pub fn upload(&mut self, rt: &mut Runtime<'_>, hints: &[AddressHint]) -> Result<UploadResult, DeliveryError> {
        if !self.policy.policy().upload.background {
            return Err(DeliveryError::BackgroundOff);
        }
        let source = rt.export_source(false)?;
        if source.certificate.is_none() {
            return Err(DeliveryError::NotRegistered);
        }
        let attachments = self.ports.records.attachments(&source.tenancy);
        let built = export::assemble(&source, &attachments, self.ports.keys, self.ports.random, false).map_err(|e| DeliveryError::BuildFailed(e.to_string()))?;
        let destination = self.authorise_first(hints, source.handle)?;
        let url = UploadRoute::Tenancy.url(&destination.address().address);
        let pop = self.pop_token(&source, url)?;
        let request = UploadRequest { route: UploadRoute::Tenancy, body: built.bytes, pop: Some(pop) };
        let claims = self.ports.transport.upload(&destination, &request).map_err(Self::map_upload)?;
        self.events.push(DeliveryEvent::UploadAccepted);
        let claim = claims.into_iter().find(|c| c.tenancy == source.tenancy).ok_or(DeliveryError::ReceiptRejected(ReceiptRejection::UnknownTenancy))?;
        let (receipt, coverage) = self.apply_claim(rt, &claim)?;
        Ok(UploadResult {
            attempt: DestinationAttempt::new(DestinationClass::Upload, AttemptOutcome::ReceiptVerified),
            receipt,
            covered_through: claim.last_seq,
            coverage,
            next_hint: AddressHint { address: destination.address().address.clone(), source: HintSource::PreviousSuccess },
        })
    }

    /// Uploads the outbox (DEL-052): each closed tenancy's signed part, with a token from
    /// the active tenancy if there is one, otherwise on the outbox route, which accepts
    /// only parts whose closing manifests verify. A receipt that verifies and matches the
    /// part's journal removes the part (DEL-041, COL-009).
    pub fn upload_outbox(&mut self, rt: &mut Runtime<'_>, hints: &[AddressHint]) -> Result<Vec<UploadResult>, DeliveryError> {
        if !self.policy.policy().upload.background {
            return Err(DeliveryError::BackgroundOff);
        }
        let entries = rt.outbox()?;
        let closed: Vec<(TenancyId, Vec<u8>)> = entries
            .into_iter()
            .filter_map(|e| match e {
                OutboxEntry::Closed { tenancy, export } => Some((tenancy, export)),
                OutboxEntry::Certified { .. } => None,
            })
            .collect();
        if closed.is_empty() {
            return Err(DeliveryError::NothingToUpload);
        }
        let active = if rt.tenancy().is_some() { Some(rt.export_source(false)?) } else { None };
        let handle = match &active {
            Some(s) => s.handle,
            None => ExportFile::decode(&closed[0].1).map_err(|e| DeliveryError::BuildFailed(e.to_string()))?.header.handle,
        };
        let destination = self.authorise_first(hints, handle)?;
        let mut results = Vec::new();
        for (tenancy, file) in closed {
            let body = export::reencode(&file, false).map_err(|e| DeliveryError::BuildFailed(e.to_string()))?;
            let (route, pop) = match &active {
                Some(s) => (UploadRoute::Tenancy, Some(self.pop_token(s, UploadRoute::Tenancy.url(&destination.address().address))?)),
                None => (UploadRoute::Outbox, None),
            };
            let request = UploadRequest { route, body: body.clone(), pop };
            let claims = self.ports.transport.upload(&destination, &request).map_err(Self::map_upload)?;
            self.events.push(DeliveryEvent::UploadAccepted);
            let claim = claims.into_iter().find(|c| c.tenancy == tenancy).ok_or(DeliveryError::ReceiptRejected(ReceiptRejection::UnknownTenancy))?;
            let coverage = self.verified(&claim)?;
            let journal = ExportFile::decode(&file).ok().and_then(|f| f.parts.first().map(|p| p.journal.clone())).unwrap_or_default();
            if hash_at(&journal, claim.last_seq.0) != Some(claim.journal_hash) {
                return Err(DeliveryError::ReceiptRejected(ReceiptRejection::HashMismatch));
            }
            self.events.push(DeliveryEvent::ReceiptVerified);
            rt.remove_outbox(&coverage)?;
            results.push(UploadResult {
                attempt: DestinationAttempt::new(DestinationClass::Upload, AttemptOutcome::ReceiptVerified),
                receipt: ReceiptOutcome { journal_deleted: 0, offer_clear_through: None },
                covered_through: claim.last_seq,
                coverage,
                next_hint: AddressHint { address: destination.address().address.clone(), source: HintSource::PreviousSuccess },
            });
        }
        Ok(results)
    }

    /// One tick of background upload (DEL-001, DEL-005). If records beyond the last
    /// receipted upload exist and no backoff is running, it tries the upload; a failure
    /// schedules the next try after the policy's backoff step plus jitter and is returned
    /// as data, never as a reason to stop anything else. `now_ms` is the caller's
    /// monotonic or wall time in milliseconds.
    pub fn background_tick(&mut self, rt: &mut Runtime<'_>, hints: &[AddressHint], now_ms: u64) -> Result<Tick, DeliveryError> {
        if !self.policy.policy().upload.background {
            return Ok(Tick::Idle);
        }
        let Some(tenancy) = rt.tenancy() else { return Ok(Tick::Idle) };
        let marker = format!("upload-retry/{}", hex(&tenancy));
        let mut state = self.ports.storage.get_marker(&marker)?.map_or_else(RetryState::default, |b| RetryState::decode(&b).unwrap_or_default());
        let source = rt.export_source(false)?;
        let head = read_frames(&source.journal).frames.iter().filter_map(|f| Record::decode(f.body).ok().map(|r| r.header.seq)).max();
        let Some(head) = head else { return Ok(Tick::Idle) };
        let settled = if state.has_settled { state.settled_head } else { 0 };
        if (rt.delivery_state(Seq(head)) == DeliveryState::Received) || (state.has_settled && head <= settled) {
            return Ok(Tick::Idle);
        }
        if now_ms < state.next_at_ms {
            return Ok(Tick::Waiting { until_ms: state.next_at_ms });
        }
        match self.upload(rt, hints) {
            Ok(result) => {
                // The receipt anchor the runtime chains is its own record; don't upload
                // again just for that.
                let new_head = read_frames(&rt.journal()?).frames.iter().filter_map(|f| Record::decode(f.body).ok().map(|r| r.header.seq)).max().unwrap_or(head);
                state = RetryState { attempts: 0, next_at_ms: 0, settled_head: new_head, has_settled: true };
                self.ports.storage.put_marker(&marker, &state.encode())?;
                Ok(Tick::Uploaded(result))
            }
            Err(DeliveryError::NothingToUpload) => Ok(Tick::Idle),
            Err(error) => {
                let base = self.policy.retry_delay(usize::try_from(state.attempts).unwrap_or(usize::MAX)).as_secs().saturating_mul(1000);
                let jitter = base / 100 * u64::from(self.ports.random.nonce().as_bytes()[0] % 21);
                state.attempts += 1;
                state.next_at_ms = now_ms.saturating_add(base).saturating_add(jitter);
                self.ports.storage.put_marker(&marker, &state.encode())?;
                Ok(Tick::Failed { error, retry_at_ms: state.next_at_ms })
            }
        }
    }
}

/// The key history of an opened manifest, for building a [`PartContext`] outside a
/// runtime (CLI `export verify`).
pub fn part_context(manifest: Value, checkpoints: Vec<(u64, Digest)>) -> PartContext {
    PartContext { keys: manifest_keys(&manifest), checkpoints, recipient: None, manifest: Some(manifest) }
}
