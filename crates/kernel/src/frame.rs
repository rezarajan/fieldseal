//! Journal frames (WIRE-030..032): `"FSR1"`, version `0x01`, flags `0x00`, body length
//! (u32 BE), CRC-32C of the body (u32 BE), body.

use crate::crc::crc32c;
use crate::error::{ErrorCode, WireError};

/// The frame magic, "FSR1".
pub const FRAME_MAGIC: [u8; 4] = *b"FSR1";
/// The frame format version.
pub const FRAME_VERSION: u8 = 0x01;
/// The only defined flags value; others are reserved.
pub const FRAME_FLAGS: u8 = 0x00;
/// Bytes before the body.
pub const FRAME_HEADER_LEN: usize = 14;
/// The largest record (WIRE-042, §6.7).
pub const MAX_RECORD: usize = 4 * 1024 * 1024;

/// Frames one record body (WIRE-031). A body over 4 MiB is refused with `E_SIZE`.
pub fn frame(body: &[u8]) -> Result<Vec<u8>, WireError> {
    if body.len() > MAX_RECORD {
        return Err(WireError::new(ErrorCode::Size, 0, "record exceeds 4 MiB"));
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
    out.extend_from_slice(&FRAME_MAGIC);
    out.push(FRAME_VERSION);
    out.push(FRAME_FLAGS);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&crc32c(body).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// A frame whose length and CRC checked out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FoundFrame<'a> {
    /// Offset of the frame's magic in the journal.
    pub offset: usize,
    /// The body.
    pub body: &'a [u8],
}

/// The result of scanning a journal: every intact frame, and every damaged region.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct FrameScan<'a> {
    /// Intact frames, in journal order.
    pub frames: Vec<FoundFrame<'a>>,
    /// One error per damaged frame or run of unframed bytes, by offset (WIRE-032).
    pub damage: Vec<WireError>,
}

/// Scans a journal for frames (WIRE-032). The scan never stops at damage: a frame whose
/// fixed fields, length or CRC fail is reported at its offset and the scan resumes at the
/// next occurrence of the magic; bytes that are not a frame are reported once per run.
pub fn read_frames(journal: &[u8]) -> FrameScan<'_> {
    let mut scan = FrameScan::default();
    let mut pos = 0;
    while pos < journal.len() {
        if !journal[pos..].starts_with(&FRAME_MAGIC) {
            scan.damage.push(WireError::new(ErrorCode::FrameMagic, pos, "bytes outside any frame"));
            pos = next_magic(journal, pos + 1);
            continue;
        }
        match check_frame(journal, pos) {
            Ok(body) => {
                scan.frames.push(FoundFrame { offset: pos, body });
                pos += FRAME_HEADER_LEN + body.len();
            }
            Err(e) => {
                scan.damage.push(e);
                pos = next_magic(journal, pos + 1);
            }
        }
    }
    scan
}

fn check_frame(journal: &[u8], pos: usize) -> Result<&[u8], WireError> {
    let header = journal
        .get(pos..pos + FRAME_HEADER_LEN)
        .ok_or(WireError::new(ErrorCode::FrameLength, pos, "frame header truncated"))?;
    if header[4] != FRAME_VERSION {
        return Err(WireError::new(ErrorCode::FrameMagic, pos, "unknown frame version"));
    }
    if header[5] != FRAME_FLAGS {
        return Err(WireError::new(ErrorCode::FrameMagic, pos, "reserved frame flags set"));
    }
    let len = u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;
    let crc = u32::from_be_bytes([header[10], header[11], header[12], header[13]]);
    let start = pos + FRAME_HEADER_LEN;
    if len > MAX_RECORD || start + len > journal.len() {
        return Err(WireError::new(ErrorCode::FrameLength, pos, "frame length impossible or past the end"));
    }
    let body = &journal[start..start + len];
    if crc32c(body) != crc {
        return Err(WireError::new(ErrorCode::Crc, pos, "frame CRC-32C mismatch"));
    }
    Ok(body)
}

fn next_magic(bytes: &[u8], from: usize) -> usize {
    (from..bytes.len()).find(|&i| bytes[i..].starts_with(&FRAME_MAGIC)).unwrap_or(bytes.len())
}
