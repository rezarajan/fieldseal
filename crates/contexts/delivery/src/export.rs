//! Export files: assembling from the journal, verifying as intake does minus decryption,
//! inspecting and repairing (DEL-010–DEL-016, DEL-050, WIRE-100–WIRE-111).
//!
//! The byte formats are the format core's ([`fieldseal_kernel::export`]); this module
//! decides what goes in and checks what comes out. Nothing here does I/O: keys sign
//! through the key store port, randomness comes from its port.

use std::collections::BTreeSet;

use fieldseal_collection::application::ExportSource;
use fieldseal_kernel::crypto::{P256PublicKey, Signature, tags};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::export::{
    ExportFile, ExportHeader, ExportPart, ExportSignature, SECTION_HEADER_LEN, export_signed_structure, parity_from_value,
};
use fieldseal_kernel::frame::read_frames;
use fieldseal_kernel::id::{Digest, KeyId};
use fieldseal_kernel::record::{Record, read_journal, record_hash};
use fieldseal_kernel::seal::{RecipientKey, SealedBox, seal_value};
use fieldseal_kernel::sign::signed_message;
use fieldseal_kernel::{ErrorCode, Value, WireError, cbor, parity};
use fieldseal_trust::ports::{RandomSource, SecureKeyStore, SourceRng};

use crate::ports::ManifestAttachments;

/// Why an export couldn't be assembled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AssembleError {
    /// The journal holds no records.
    #[error("the journal is empty")]
    EmptyJournal,
    /// The journal couldn't be read.
    #[error("the journal is unreadable: {0}")]
    Journal(String),
    /// Sealing, signing or encoding failed.
    #[error("assembling failed: {0}")]
    Failed(String),
}

impl From<WireError> for AssembleError {
    fn from(e: WireError) -> Self {
        Self::Failed(format!("{}: {}", e.code, e.detail))
    }
}

/// What an assembled export contains.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Assembled {
    /// The file.
    pub bytes: Vec<u8>,
    /// The manifest as sealed, for the self-verification.
    pub manifest: Value,
    /// First `seq`.
    pub first_seq: u64,
    /// Last `seq`.
    pub last_seq: u64,
    /// Number of records.
    pub records: u64,
}

fn b(d: &[u8]) -> Value {
    Value::Bytes(d.to_vec())
}

fn u(n: u64) -> Value {
    Value::Int(i128::from(n))
}

/// Assembles the open tenancy's export (DEL-010, WIRE-100–WIRE-106): the sealed manifest
/// (sealed to the authority record key), the journal as held, optional parity (WIRE-107)
/// and the signature by the tenancy's signing key made through the key store.
///
/// The export is cumulative (DEL-018): it holds the whole journal, whatever has arrived.
pub fn assemble(
    source: &ExportSource,
    attachments: &ManifestAttachments,
    keys: &dyn SecureKeyStore,
    random: &dyn RandomSource,
    with_parity: bool,
) -> Result<Assembled, AssembleError> {
    let scan = read_frames(&source.journal);
    let mut seqs = Vec::new();
    for f in &scan.frames {
        let r = Record::decode(f.body).map_err(|e| AssembleError::Journal(format!("{}: {}", e.code, e.detail)))?;
        seqs.push((r.header.seq, record_hash(f.body)));
    }
    let (Some(first), Some(last)) = (seqs.first().copied(), seqs.last().copied()) else {
        return Err(AssembleError::EmptyJournal);
    };
    let mut entries = vec![
        ("tenancy", b(source.tenancy.as_bytes())),
        (
            "keys",
            Value::Array(
                source
                    .keys
                    .iter()
                    .map(|(index, public_key, evidence)| {
                        cbor::map([("index", u(*index)), ("public_key", b(public_key.as_bytes())), ("evidence", b(evidence.as_bytes()))])
                    })
                    .collect(),
            ),
        ),
        ("records", u(seqs.len() as u64)),
        ("first_seq", u(first.0)),
        ("last_seq", u(last.0)),
        ("first_hash", b(first.1.as_bytes())),
        ("last_hash", b(last.1.as_bytes())),
        ("journal_sha256", b(sha256(&source.journal).as_bytes())),
        ("build_anchor", b(source.build_anchor.as_bytes())),
        ("instruments", Value::Array(source.instruments.iter().map(|f| b(f.as_bytes())).collect())),
        ("policy", b(source.policy.map_or([0u8; 32], |p| *p.as_bytes()).as_slice())),
    ];
    if let Some(c) = source.certificate_document.as_ref().or(attachments.certificate.as_ref()) {
        entries.push(("certificate", c.clone()));
    }
    if let Some(r) = &attachments.registration {
        entries.push(("registration", r.clone()));
    }
    let manifest = cbor::map(entries);
    let sealed = seal_value(&mut SourceRng(random), &RecipientKey::X25519(source.record_key), &tags::EXPORT_MANIFEST_SEAL, &manifest)?;
    let manifest_bytes = sealed.encode();
    let header = ExportHeader { handle: source.handle, parts: 1 };
    let message = signed_message(&tags::EXPORT, &export_signed_structure(&header, &manifest_bytes, &source.journal))?;
    let sig = keys.sign(&source.sign, &message).map_err(|e| AssembleError::Failed(format!("signing: {e}")))?;
    let file = ExportFile {
        header,
        parts: vec![ExportPart { manifest: manifest_bytes, journal: source.journal.clone(), signature: ExportSignature { key: 0, sig }, parity: None }],
    };
    Ok(Assembled { bytes: file.encode(with_parity)?, manifest, first_seq: first.0, last_seq: last.0, records: seqs.len() as u64 })
}

/// Re-encodes an export with or without parity, leaving every signed byte alone
/// (WIRE-108): used to add parity to an outbox part or to strip it for upload (DEL-016).
pub fn reencode(bytes: &[u8], with_parity: bool) -> Result<Vec<u8>, WireError> {
    ExportFile::decode(bytes)?.encode(with_parity)
}

/// Joins single-part exports into one outbox export with a part per closed tenancy
/// (DEL-050, WIRE-110). The header names the first part's handle.
pub fn merge_parts(files: &[Vec<u8>], with_parity: bool) -> Result<Vec<u8>, WireError> {
    let mut header = None;
    let mut parts = Vec::new();
    for f in files {
        let file = ExportFile::decode(f)?;
        header.get_or_insert(file.header);
        parts.extend(file.parts);
    }
    let Some(mut header) = header else {
        return Err(WireError::new(ErrorCode::ExportSection, 0, "no parts to merge"));
    };
    header.parts = parts.len() as u64;
    ExportFile { header, parts }.encode(with_parity)
}

/// What the verifier knows about one part from outside the file (the manifest is sealed).
#[derive(Clone, Debug)]
pub struct PartContext {
    /// The tenancy's signing keys, by index.
    pub keys: Vec<P256PublicKey>,
    /// Checkpoints that bridge cleared frames, `(cleared_through, hash_at)`.
    pub checkpoints: Vec<(u64, Digest)>,
    /// The record key the manifest must be sealed to, if known.
    pub recipient: Option<KeyId>,
    /// The manifest's plaintext, if the verifier can open it.
    pub manifest: Option<Value>,
}

/// One verification finding (CLI §6 `findings`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Finding {
    /// The requirement or error code.
    pub code: String,
    /// What is wrong.
    pub message: String,
    /// The `seq` it concerns, if any.
    pub seq: Option<u64>,
    /// The byte offset in the file, if known.
    pub offset: Option<usize>,
    /// Whether it makes the export unfit to offer.
    pub error: bool,
}

/// The result of verifying an export (DEL-012).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct VerifyReport {
    /// Every finding, errors first found first.
    pub findings: Vec<Finding>,
    /// Parts in the file.
    pub parts: usize,
    /// Records seen across the parts.
    pub records: u64,
    /// Parts that carry parity.
    pub parity_parts: usize,
    /// Whether the file signature was checked (it needs the signing keys).
    pub signature_checked: bool,
}

impl VerifyReport {
    /// Whether the export passed: no error findings.
    pub fn ok(&self) -> bool {
        !self.findings.iter().any(|f| f.error)
    }

    fn error(&mut self, code: impl Into<String>, message: impl Into<String>, offset: Option<usize>, seq: Option<u64>) {
        self.findings.push(Finding { code: code.into(), message: message.into(), seq, offset, error: true });
    }

    fn note(&mut self, code: impl Into<String>, message: impl Into<String>) {
        self.findings.push(Finding { code: code.into(), message: message.into(), seq: None, offset: None, error: false });
    }

    fn wire(&mut self, e: &WireError, prefix: &str) {
        self.error(e.code.to_string(), format!("{prefix}{}", e.detail), Some(e.offset), None);
    }
}

fn parity_input(header: &ExportHeader, part: &ExportPart) -> Result<Vec<u8>, WireError> {
    Ok([cbor::encode(&header.to_value())?.as_slice(), &part.manifest, &part.journal].concat())
}

/// Verifies an export as intake does, minus decryption (DEL-012): envelope and section
/// CRCs, section order, the sealed manifest's envelope, parity against the bodies, and,
/// where the signing keys are known, the file signature, every record's signature, the
/// hash chain and the manifest's statements about the journal. `contexts` holds what is
/// known about each part, in order; a part with `None` is checked structurally only and
/// the report says so.
pub fn verify(bytes: &[u8], contexts: &[Option<PartContext>]) -> VerifyReport {
    let mut report = VerifyReport::default();
    let file = match ExportFile::decode(bytes) {
        Ok(f) => f,
        Err(e) => {
            report.wire(&e, "");
            return report;
        }
    };
    report.parts = file.parts.len();
    for (i, part) in file.parts.iter().enumerate() {
        let ctx = contexts.get(i).and_then(Option::as_ref);
        let at = format!("part {i}: ");
        match SealedBox::decode(&part.manifest) {
            Ok(sealed) => {
                if let Some(want) = ctx.and_then(|c| c.recipient.as_ref())
                    && &sealed.recipient != want
                {
                    report.error(ErrorCode::Recipient.to_string(), format!("{at}the manifest is not sealed to the expected record key"), None, None);
                }
            }
            Err(e) => report.wire(&e, &at),
        }
        if let Some(p) = &part.parity {
            report.parity_parts += 1;
            match parity_input(&file.header, part) {
                Ok(data) if parity::compute(&data) == *p => {}
                Ok(_) => report.error(ErrorCode::Parity.to_string(), format!("{at}parity does not match the header, manifest and journal"), None, None),
                Err(e) => report.wire(&e, &at),
            }
        }
        let Some(ctx) = ctx else {
            let scan = read_frames(&part.journal);
            for d in &scan.damage {
                report.error(d.code.to_string(), format!("{at}{}", d.detail), Some(d.offset), None);
            }
            report.records += scan.frames.len() as u64;
            report.note("DEL-012", format!("{at}the signing keys are not known, so the signature and record signatures were not checked"));
            continue;
        };
        report.signature_checked = true;
        match usize::try_from(part.signature.key).ok().and_then(|k| ctx.keys.get(k)) {
            Some(key) => {
                if let Err(e) = part.verify(&file.header, key) {
                    report.wire(&e, &format!("{at}file signature: "));
                }
            }
            None => report.error(ErrorCode::Sig.to_string(), format!("{at}the signature names key {} outside the key history", part.signature.key), None, None),
        }
        let journal = read_journal(&part.journal, &ctx.keys, &ctx.checkpoints);
        for e in &journal.errors {
            report.error(e.code.to_string(), format!("{at}{}", e.detail), Some(e.offset), None);
        }
        report.records += journal.entries.len() as u64;
        if let Some(manifest) = &ctx.manifest
            && let Err(detail) = check_manifest_shape(manifest)
        {
            report.error(ErrorCode::UnknownField.to_string(), format!("{at}manifest: {detail}"), None, None);
        }
        if let Some(Value::Map(m)) = &ctx.manifest {
            if m.get("journal_sha256") != Some(&b(sha256(&part.journal).as_bytes())) {
                report.error(ErrorCode::Hash.to_string(), format!("{at}the journal does not match the manifest's hash"), None, None);
            }
            let held: BTreeSet<u64> = journal.entries.iter().map(|e| e.record.header.seq).collect();
            if let (Some(Value::Int(first)), Some(Value::Int(last))) = (m.get("first_seq"), m.get("last_seq"))
                && (held.first().map(|s| i128::from(*s)) != Some(*first) || held.last().map(|s| i128::from(*s)) != Some(*last))
            {
                report.error(ErrorCode::Seq.to_string(), format!("{at}the manifest's seq range differs from the journal's"), None, None);
            }
        }
    }
    report
}

/// A part's summary for `export inspect`; sealed parts stay sealed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PartInfo {
    /// Sealed manifest size.
    pub manifest_bytes: usize,
    /// Journal size.
    pub journal_bytes: usize,
    /// Records whose frames read.
    pub records: u64,
    /// The `seq` range of the readable frames.
    pub seq_range: Option<(u64, u64)>,
    /// Whether the part carries parity.
    pub parity: bool,
    /// The signing key index named by the signature.
    pub signature_key: u64,
}

/// A summary of an export file.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Inspection {
    /// The file's size.
    pub size: usize,
    /// The opaque handle in the header.
    pub handle: [u8; 16],
    /// The parts.
    pub parts: Vec<PartInfo>,
}

/// Summarises an export without opening anything sealed (CLI `export inspect`).
pub fn inspect(bytes: &[u8]) -> Result<Inspection, WireError> {
    let file = ExportFile::decode(bytes)?;
    let parts = file
        .parts
        .iter()
        .map(|p| {
            let scan = read_frames(&p.journal);
            let seqs: Vec<u64> = scan.frames.iter().filter_map(|f| Record::decode(f.body).ok().map(|r| r.header.seq)).collect();
            PartInfo {
                manifest_bytes: p.manifest.len(),
                journal_bytes: p.journal.len(),
                records: seqs.len() as u64,
                seq_range: seqs.iter().min().zip(seqs.iter().max()).map(|(a, z)| (*a, *z)),
                parity: p.parity.is_some(),
                signature_key: p.signature.key,
            }
        })
        .collect();
    Ok(Inspection { size: bytes.len(), handle: *file.header.handle.as_bytes(), parts })
}

/// The result of repairing an export from its parity.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Repair {
    /// The corrected file.
    pub bytes: Vec<u8>,
    /// How many shards were rebuilt.
    pub shards_rebuilt: usize,
    /// The data shards found damaged, as `(part, shard index)` (CLI-016).
    pub damaged: Vec<(usize, usize)>,
}

/// The data shards whose hashes differ from the parity section's, per part.
fn damaged_shards(file: &[u8]) -> Vec<(usize, usize)> {
    // Walk the sections by their (intact) framing; bodies may fail their CRCs.
    let mut sections: Vec<(u8, &[u8])> = Vec::new();
    let mut pos = 4;
    while pos + SECTION_HEADER_LEN <= file.len() {
        let len = u32::from_be_bytes([file[pos + 1], file[pos + 2], file[pos + 3], file[pos + 4]]) as usize;
        let Some(body) = file.get(pos + SECTION_HEADER_LEN..pos + SECTION_HEADER_LEN + len) else { break };
        sections.push((file[pos], body));
        pos += SECTION_HEADER_LEN + len;
    }
    let mut out = Vec::new();
    let Some((0x01, header)) = sections.first().copied() else { return out };
    let mut part = 0;
    let mut i = 1;
    while i < sections.len() {
        if sections[i..].len() >= 4 && sections[i + 2].0 == 0x04 {
            if let Some(p) = cbor::decode(sections[i + 2].1).ok().and_then(|v| parity_from_value(v).ok()) {
                let data = [header, sections[i].1, sections[i + 1].1].concat();
                let size = p.shard_size;
                for (n, want) in p.data_hashes.iter().enumerate() {
                    let mut shard = vec![0u8; size];
                    let start = (n * size).min(data.len());
                    let end = ((n + 1) * size).min(data.len());
                    shard[..end - start].copy_from_slice(&data[start..end]);
                    if sha256(&shard) != *want {
                        out.push((part, n));
                    }
                }
            }
            i += 4;
        } else {
            i += 3;
        }
        part += 1;
    }
    out
}

/// Repairs up to four damaged shards per part from the parity section (WIRE-109). It
/// changes only bytes the parity recovers, and reports which (CLI-016). The caller MUST
/// verify the repaired file's signatures: parity is not signed (WIRE-108).
pub fn repair(bytes: &[u8]) -> Result<Repair, WireError> {
    let damaged = damaged_shards(bytes);
    let (fixed, shards_rebuilt) = fieldseal_kernel::export::repair(bytes)?;
    Ok(Repair { bytes: fixed, shards_rebuilt, damaged })
}

/// The signature section of the first part, for tests and inspection.
pub fn first_signature(bytes: &[u8]) -> Result<Signature, WireError> {
    ExportFile::decode(bytes)?
        .parts
        .first()
        .map(|p| p.signature.sig.clone())
        .ok_or_else(|| WireError::new(ErrorCode::ExportSection, 0, "no parts"))
}

/// The key history in an opened manifest: the signing keys by index (WIRE-104).
pub fn manifest_keys(manifest: &Value) -> Vec<P256PublicKey> {
    let Value::Map(m) = manifest else { return Vec::new() };
    let Some(Value::Array(keys)) = m.get("keys") else { return Vec::new() };
    let mut out: Vec<(u64, P256PublicKey)> = Vec::new();
    for k in keys {
        if let Value::Map(k) = k
            && let (Some(Value::Int(i)), Some(Value::Bytes(p))) = (k.get("index"), k.get("public_key"))
            && let (Ok(i), Ok(p)) = (u64::try_from(*i), P256PublicKey::from_bytes(p))
        {
            out.push((i, p));
        }
    }
    out.sort_by_key(|(i, _)| *i);
    out.into_iter().map(|(_, p)| p).collect()
}

/// Checks an opened manifest against the closed WIRE §6.5 field set: no unknown fields, every
/// required field present with its exact type and length, key entries closed too. The
/// `certificate`, `registration` and `end` documents are checked by their own readers.
pub fn check_manifest_shape(manifest: &Value) -> Result<(), String> {
    let Value::Map(m) = manifest else { return Err("the manifest is not a map".into()) };
    const KNOWN: [&str; 14] = [
        "tenancy", "certificate", "registration", "keys", "records", "first_seq", "last_seq", "first_hash", "last_hash", "journal_sha256", "end",
        "build_anchor", "instruments", "policy",
    ];
    if let Some(k) = m.keys().find(|k| !KNOWN.contains(&k.as_str())) {
        return Err(format!("unknown field `{k}`"));
    }
    let bytes_n = |k: &str, n: usize| match m.get(k) {
        Some(Value::Bytes(b)) if b.len() == n => Ok(()),
        Some(_) => Err(format!("field `{k}` must be a byte string of {n} bytes")),
        None => Err(format!("required field `{k}` missing")),
    };
    let uint = |k: &str| match m.get(k) {
        Some(Value::Int(i)) if u64::try_from(*i).is_ok() => Ok(()),
        Some(_) => Err(format!("field `{k}` must be an unsigned integer")),
        None => Err(format!("required field `{k}` missing")),
    };
    bytes_n("tenancy", 32)?;
    for k in ["records", "first_seq", "last_seq"] {
        uint(k)?;
    }
    for k in ["first_hash", "last_hash", "journal_sha256", "build_anchor", "policy"] {
        bytes_n(k, 32)?;
    }
    match m.get("keys") {
        Some(Value::Array(keys)) => {
            for e in keys {
                let Value::Map(e) = e else { return Err("a key entry must be a map".into()) };
                if let Some(k) = e.keys().find(|k| !["index", "public_key", "evidence"].contains(&k.as_str())) {
                    return Err(format!("unknown key-entry field `{k}`"));
                }
                match (e.get("index"), e.get("public_key"), e.get("evidence")) {
                    (Some(Value::Int(i)), Some(Value::Bytes(p)), Some(Value::Bytes(ev))) if u64::try_from(*i).is_ok() && P256PublicKey::from_bytes(p).is_ok() && ev.len() == 32 => {}
                    _ => return Err("a key entry needs an unsigned `index`, a valid `public_key` and a 32-byte `evidence`".into()),
                }
            }
        }
        _ => return Err("field `keys` must be an array".into()),
    }
    match m.get("instruments") {
        Some(Value::Array(a)) if a.iter().all(|v| matches!(v, Value::Bytes(b) if b.len() == 32)) => {}
        _ => return Err("field `instruments` must be an array of 32-byte strings".into()),
    }
    match m.get("end") {
        None | Some(Value::Bytes(_) | Value::Map(_)) => {}
        Some(_) => return Err("field `end` must be a hash or a certificate".into()),
    }
    Ok(())
}
