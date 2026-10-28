//! Export files (WIRE-100..110): `"FSX1"` then sections `type (1) ‖ length (u32 BE) ‖
//! CRC-32C (u32 BE) ‖ body`, in the order header, then per part: sealed manifest, journal,
//! optional parity, signature.
//!
//! The kernel frames, signs, verifies and repairs exports; it treats the sealed manifest and
//! the journal as opaque bytes (they are produced by [`crate::seal`] and [`crate::frame`]).

use crate::cbor;
use crate::crc::crc32c;
use crate::crypto::{P256PublicKey, Signature, tags};
use crate::digest::sha256;
use crate::error::{ErrorCode, WireError};
use crate::frame::read_frames;
use crate::id::{Digest, TenancyHandle};
use crate::parity::{self, Parity};
use crate::sign::{SigningKey, verify};
use crate::structure::{Fields, expect_bytes, expect_bytes_n};
use crate::value::Value;

/// The export magic, "FSX1".
pub const EXPORT_MAGIC: [u8; 4] = *b"FSX1";
/// The header's `format` value.
pub const EXPORT_FORMAT: &str = "fieldseal.dev/export/v1";
/// Bytes before a section body.
pub const SECTION_HEADER_LEN: usize = 9;

/// Section types (WIRE-101).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum SectionType {
    /// The plaintext header.
    Header = 0x01,
    /// The sealed manifest.
    Manifest = 0x02,
    /// The journal's frames.
    Journal = 0x03,
    /// Reed–Solomon parity (optional).
    Parity = 0x04,
    /// The export signature.
    Signature = 0x05,
}

/// The export header (WIRE-102): `{"format", "handle", "parts"}`.
///
/// The spec's header also has `"parity": bool`, but the header is signed (WIRE-106) while
/// parity must be addable and removable without re-signing (WIRE-108); the two can't both
/// hold, so the field is left out and the presence of section `0x04` says whether a part has
/// parity (issue #42 spec notes).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExportHeader {
    /// The opaque tenancy handle.
    pub handle: TenancyHandle,
    /// The number of parts (WIRE-110).
    pub parts: u64,
}

impl ExportHeader {
    /// The header as a value.
    pub fn to_value(&self) -> Value {
        cbor::map([
            ("format", Value::Text(EXPORT_FORMAT.to_owned())),
            ("handle", Value::Bytes(self.handle.as_bytes().to_vec())),
            ("parts", Value::Int(i128::from(self.parts))),
        ])
    }

    /// Reads a header value; an unknown `format` is `E_VERSION` (WIRE-150).
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        f.version("format", &Value::Text(EXPORT_FORMAT.to_owned()))?;
        let header = Self {
            handle: TenancyHandle::from(f.bytes_n::<16>("handle")?),
            parts: f.uint("parts")?,
        };
        f.finish()?;
        if header.parts == 0 {
            return Err(WireError::new(ErrorCode::UnknownField, 0, "an export has at least one part (WIRE-110)"));
        }
        Ok(header)
    }
}

/// The export signature section (WIRE-106): `{"key": index, "sig": Signature}`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExportSignature {
    /// Index of the signing key in the tenancy's key history.
    pub key: u64,
    /// The signature.
    pub sig: Signature,
}

impl ExportSignature {
    /// The section as a value.
    pub fn to_value(&self) -> Value {
        cbor::map([("key", Value::Int(i128::from(self.key))), ("sig", Value::Bytes(self.sig.0.clone()))])
    }

    /// Reads the section value.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        let s = Self { key: f.uint("key")?, sig: Signature(f.bytes_n::<64>("sig")?.to_vec()) };
        f.finish()?;
        Ok(s)
    }
}

/// The parity section as a value (WIRE-107).
pub fn parity_to_value(p: &Parity) -> Value {
    cbor::map([
        ("k", Value::Int(parity::K as i128)),
        ("m", Value::Int(parity::M as i128)),
        ("shard_size", Value::Int(p.shard_size as i128)),
        ("data_hashes", Value::Array(p.data_hashes.iter().map(|h| Value::Bytes(h.as_bytes().to_vec())).collect())),
        ("parity_shards", Value::Array(p.parity_shards.iter().map(|s| Value::Bytes(s.clone())).collect())),
    ])
}

/// Reads a parity section value. `k` and `m` other than 10 and 4 are `E_VERSION`.
pub fn parity_from_value(value: Value) -> Result<Parity, WireError> {
    let mut f = Fields::new(value)?;
    f.version("k", &Value::Int(parity::K as i128))?;
    f.version("m", &Value::Int(parity::M as i128))?;
    let shard_size = usize::try_from(f.uint("shard_size")?)
        .map_err(|_| WireError::new(ErrorCode::Size, 0, "shard size does not fit memory"))?;
    let hashes = f.array("data_hashes")?;
    let shards = f.array("parity_shards")?;
    f.finish()?;
    let wrong = || WireError::new(ErrorCode::UnknownField, 0, "parity needs 10 hashes and 4 shards");
    if shard_size == 0 {
        return Err(WireError::new(ErrorCode::UnknownField, 0, "parity shard_size is at least 1"));
    }
    let hashes: Vec<Digest> = hashes.into_iter().map(|h| expect_bytes_n::<32>(h).map(Digest::from)).collect::<Result<_, _>>()?;
    let shards: Vec<Vec<u8>> = shards.into_iter().map(expect_bytes).collect::<Result<_, _>>()?;
    if shards.iter().any(|s| s.len() != shard_size) {
        return Err(WireError::new(ErrorCode::UnknownField, 0, "every parity shard is shard_size bytes"));
    }
    Ok(Parity {
        shard_size,
        data_hashes: hashes.try_into().map_err(|_| wrong())?,
        parity_shards: shards.try_into().map_err(|_| wrong())?,
    })
}

/// The structure an export signature covers: `{header, manifest_sha256, journal_sha256}`
/// (WIRE-106), where the hashes are over the manifest and journal section bodies.
pub fn export_signed_structure(header: &ExportHeader, manifest: &[u8], journal: &[u8]) -> Value {
    cbor::map([
        ("header", header.to_value()),
        ("manifest_sha256", Value::Bytes(sha256(manifest).as_bytes().to_vec())),
        ("journal_sha256", Value::Bytes(sha256(journal).as_bytes().to_vec())),
    ])
}

/// One part of an export: the sealed manifest's canonical bytes, the journal and the
/// signature over them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExportPart {
    /// The sealed manifest section body.
    pub manifest: Vec<u8>,
    /// The journal section body (frames, unmodified, WIRE-105).
    pub journal: Vec<u8>,
    /// The signature section.
    pub signature: ExportSignature,
    /// The parity section, if present.
    pub parity: Option<Parity>,
}

impl ExportPart {
    /// Signs a part with the tenancy's signing key at `key_index` (WIRE-106).
    pub fn sign(header: &ExportHeader, manifest: Vec<u8>, journal: Vec<u8>, key: &SigningKey, key_index: u64) -> Result<Self, WireError> {
        let sig = key.sign(&tags::EXPORT, &export_signed_structure(header, &manifest, &journal))?;
        Ok(Self { manifest, journal, signature: ExportSignature { key: key_index, sig }, parity: None })
    }

    /// Verifies the part's signature with the key its signature section names.
    pub fn verify(&self, header: &ExportHeader, key: &P256PublicKey) -> Result<(), WireError> {
        verify(key, &tags::EXPORT, &export_signed_structure(header, &self.manifest, &self.journal), &self.signature.sig)
    }
}

/// An export file's contents.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExportFile {
    /// The header.
    pub header: ExportHeader,
    /// The parts, `header.parts` of them.
    pub parts: Vec<ExportPart>,
}

fn push_section(out: &mut Vec<u8>, kind: SectionType, body: &[u8]) -> Result<(), WireError> {
    let len = u32::try_from(body.len()).map_err(|_| WireError::new(ErrorCode::Size, 0, "section exceeds 4 GiB"))?;
    out.push(kind as u8);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&crc32c(body).to_be_bytes());
    out.extend_from_slice(body);
    Ok(())
}

fn parity_data(header_body: &[u8], part: &ExportPart) -> Vec<u8> {
    [header_body, &part.manifest, &part.journal].concat()
}

impl ExportFile {
    /// Encodes the file (WIRE-100, WIRE-101). With `with_parity`, each part's parity is
    /// computed afresh over its header, manifest and journal bodies (WIRE-107); without, no
    /// parity is written. Either way the signatures are unchanged (WIRE-108).
    /// `header.parts` must equal the number of parts (WIRE-110).
    pub fn encode(&self, with_parity: bool) -> Result<Vec<u8>, WireError> {
        if self.header.parts != self.parts.len() as u64 || self.parts.is_empty() {
            return Err(WireError::new(ErrorCode::ExportSection, 0, "parts does not match the parts given"));
        }
        let header_body = cbor::encode(&self.header.to_value())?;
        let mut out = EXPORT_MAGIC.to_vec();
        push_section(&mut out, SectionType::Header, &header_body)?;
        for part in &self.parts {
            push_section(&mut out, SectionType::Manifest, &part.manifest)?;
            push_section(&mut out, SectionType::Journal, &part.journal)?;
            if with_parity {
                let p = parity::compute(&parity_data(&header_body, part));
                push_section(&mut out, SectionType::Parity, &cbor::encode(&parity_to_value(&p))?)?;
            }
            push_section(&mut out, SectionType::Signature, &cbor::encode(&part.signature.to_value())?)?;
        }
        Ok(out)
    }

    /// Decodes and checks the file's structure: magic, every section's length and CRC, the
    /// section order and the header. Signatures are checked separately with
    /// [`ExportPart::verify`].
    pub fn decode(file: &[u8]) -> Result<Self, WireError> {
        let sections = scan_sections(file)?;
        if let Some(bad) = sections.iter().find(|s| !s.crc_ok) {
            return Err(WireError::new(ErrorCode::Crc, bad.offset, "section CRC-32C mismatch"));
        }
        assemble(&sections)
    }
}

/// A section located in a file.
struct RawSection<'a> {
    kind: u8,
    offset: usize,
    body: &'a [u8],
    crc_ok: bool,
}

fn scan_sections(file: &[u8]) -> Result<Vec<RawSection<'_>>, WireError> {
    if !file.starts_with(&EXPORT_MAGIC) {
        return Err(WireError::new(ErrorCode::FrameMagic, 0, "not an export file"));
    }
    let mut pos = EXPORT_MAGIC.len();
    let mut sections = Vec::new();
    while pos < file.len() {
        let head = file
            .get(pos..pos + SECTION_HEADER_LEN)
            .ok_or(WireError::new(ErrorCode::FrameLength, pos, "section header truncated"))?;
        let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        let crc = u32::from_be_bytes([head[5], head[6], head[7], head[8]]);
        let start = pos + SECTION_HEADER_LEN;
        let body = file
            .get(start..start + len)
            .ok_or(WireError::new(ErrorCode::FrameLength, pos, "section runs past the end"))?;
        sections.push(RawSection { kind: head[0], offset: pos, body, crc_ok: crc32c(body) == crc });
        pos = start + len;
    }
    Ok(sections)
}

/// Checks section order (WIRE-101, WIRE-110) and decodes the structured sections.
fn assemble(sections: &[RawSection<'_>]) -> Result<ExportFile, WireError> {
    let order = |offset| WireError::new(ErrorCode::ExportSection, offset, "sections missing or out of order");
    let first = sections.first().ok_or(order(EXPORT_MAGIC.len()))?;
    if first.kind != SectionType::Header as u8 {
        return Err(order(first.offset));
    }
    let header = ExportHeader::from_value(cbor::decode(first.body).map_err(|e| e.shifted(first.offset + SECTION_HEADER_LEN))?)
        .map_err(|e| e.shifted(first.offset))?;
    let mut parts = Vec::new();
    let mut rest = &sections[1..];
    while !rest.is_empty() {
        let kinds: Vec<u8> = rest.iter().take(4).map(|s| s.kind).collect();
        let with_parity = kinds.starts_with(&[0x02, 0x03, 0x04, 0x05]);
        if !with_parity && !kinds.starts_with(&[0x02, 0x03, 0x05]) {
            return Err(order(rest[0].offset));
        }
        let n = if with_parity { 4 } else { 3 };
        let decode_at = |s: &RawSection<'_>| cbor::decode(s.body).map_err(|e| e.shifted(s.offset + SECTION_HEADER_LEN));
        let parity = if with_parity { Some(parity_from_value(decode_at(&rest[2])?).map_err(|e| e.shifted(rest[2].offset))?) } else { None };
        let sig_section = &rest[n - 1];
        let signature = ExportSignature::from_value(decode_at(sig_section)?).map_err(|e| e.shifted(sig_section.offset))?;
        parts.push(ExportPart { manifest: rest[0].body.to_vec(), journal: rest[1].body.to_vec(), signature, parity });
        rest = &rest[n..];
    }
    if parts.len() as u64 != header.parts {
        return Err(order(sections.last().map_or(0, |s| s.offset)));
    }
    Ok(ExportFile { header, parts })
}

/// Repairs damaged header, manifest and journal bodies from each part's parity (WIRE-109)
/// and returns the file rewritten with fresh section CRCs, plus the number of shards rebuilt.
///
/// Section framing (type and length) must be intact; the parity and signature sections must
/// pass their CRCs. A part without parity whose bodies are damaged, or with more than 4
/// damaged shards, fails with `E_PARITY`; use [`salvage_frames`] to recover intact frames.
/// Parity is not signed (WIRE-108): the caller MUST verify the repaired file's signatures.
pub fn repair(file: &[u8]) -> Result<(Vec<u8>, usize), WireError> {
    let sections = scan_sections(file)?;
    for s in &sections {
        if !s.crc_ok && (s.kind == SectionType::Parity as u8 || s.kind == SectionType::Signature as u8) {
            return Err(WireError::new(ErrorCode::Parity, s.offset, "parity or signature section damaged"));
        }
    }
    // The header may itself be damaged: take the kinds from the framing, and decode only
    // what the parity has repaired.
    let mut bodies: Vec<Vec<u8>> = sections.iter().map(|s| s.body.to_vec()).collect();
    let kinds: Vec<u8> = sections.iter().map(|s| s.kind).collect();
    if kinds.first() != Some(&(SectionType::Header as u8)) {
        return Err(WireError::new(ErrorCode::ExportSection, EXPORT_MAGIC.len(), "header section missing"));
    }
    let mut repaired_total = 0;
    let mut i = 1;
    let mut header_fixed = sections[0].crc_ok;
    while i < sections.len() {
        let with_parity = kinds[i..].starts_with(&[0x02, 0x03, 0x04, 0x05]);
        if !with_parity && !kinds[i..].starts_with(&[0x02, 0x03, 0x05]) {
            return Err(WireError::new(ErrorCode::ExportSection, sections[i].offset, "sections missing or out of order"));
        }
        let damaged = !sections[i].crc_ok || !sections[i + 1].crc_ok || !header_fixed;
        if with_parity {
            let p = parity_from_value(cbor::decode(&bodies[i + 2])?)?;
            let (h, m, j) = (bodies[0].len(), bodies[i].len(), bodies[i + 1].len());
            let mut data = [bodies[0].as_slice(), &bodies[i], &bodies[i + 1]].concat();
            // Report a failure at the file offset of the first damaged shard.
            let to_file = |d: usize| {
                let body = |s: &RawSection<'_>| s.offset + SECTION_HEADER_LEN;
                if d < h {
                    body(&sections[0]) + d
                } else if d < h + m {
                    body(&sections[i]) + (d - h)
                } else {
                    body(&sections[i + 1]) + (d - h - m)
                }
            };
            repaired_total += parity::repair(&mut data, &p).map_err(|e| WireError { offset: to_file(e.offset), ..e })?;
            bodies[0] = data[..h].to_vec();
            bodies[i] = data[h..h + m].to_vec();
            bodies[i + 1] = data[h + m..h + m + j].to_vec();
            header_fixed = true;
            i += 4;
        } else {
            if damaged {
                return Err(WireError::new(ErrorCode::Parity, sections[i].offset, "damaged part has no parity"));
            }
            i += 3;
        }
    }
    let mut out = EXPORT_MAGIC.to_vec();
    for (s, body) in sections.iter().zip(&bodies) {
        let kind = match s.kind {
            0x01 => SectionType::Header,
            0x02 => SectionType::Manifest,
            0x03 => SectionType::Journal,
            0x04 => SectionType::Parity,
            _ => SectionType::Signature,
        };
        push_section(&mut out, kind, body)?;
    }
    // The rewritten file must now parse; its signatures are the caller's to check.
    ExportFile::decode(&out)?;
    Ok((out, repaired_total))
}

/// Salvages every intact journal frame from a possibly damaged export file (WIRE-109):
/// returns the frame bodies of each journal section whose framing can be found.
pub fn salvage_frames(file: &[u8]) -> Vec<Vec<u8>> {
    let Ok(sections) = scan_sections(file) else { return Vec::new() };
    sections
        .iter()
        .filter(|s| s.kind == SectionType::Journal as u8)
        .flat_map(|s| read_frames(s.body).frames.into_iter().map(|f| f.body.to_vec()).collect::<Vec<_>>())
        .collect()
}
