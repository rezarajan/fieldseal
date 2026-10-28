//! Animated QR sequences (WIRE-175..177): an object too large for one QR code, shown as a
//! loop of frames the receiver reassembles. This module makes and reads the frames' text;
//! drawing them as images is the platform's job.
//!
//! A frame is `FS1A:<seq>/<total>:<message-id>:<payload>`. `seq` and `total` are decimal
//! with no sign or leading zeros, `seq` counting from 1; `message-id` is the first 8 bytes
//! of the object's SHA-256 in Crockford base32 (13 characters); `payload` is Crockford
//! base32 of one chunk of the object. Every chunk but the last is exactly [`CHUNK_BYTES`]
//! long, so one object has one sequence. A frame never exceeds [`MAX_FRAME_CHARS`].
//!
//! The receiver may see frames in any order, any number of times, and from interleaved
//! messages; it reassembles by message ID, checks the object's SHA-256 against the ID, and
//! only then hands the object over (WIRE-177). The kernel reads no clock and no randomness:
//! a sequence is a pure function of the object.

use std::collections::BTreeMap;

use crate::digest::{crockford_base32, sha256};
use crate::error::{ErrorCode, WireError};
use crate::text::crockford_base32_decode;

/// The text prefix of a frame.
pub const FRAME_PREFIX: &str = "FS1A:";

/// The longest frame text (WIRE-176).
pub const MAX_FRAME_CHARS: usize = 600;

/// The object bytes in every frame but the last. With the longest header (`FS1A:` + a
/// four-digit `seq/total` + the 13-character ID + two colons = 29 characters), a chunk this
/// size keeps the frame at 599 characters.
pub const CHUNK_BYTES: usize = 356;

/// The most frames one object may take.
pub const MAX_FRAMES: usize = 1000;

/// The largest object a sequence can carry.
pub const MAX_OBJECT: usize = MAX_FRAMES * CHUNK_BYTES;

/// The most distinct messages a receiver follows at once, so scanning stray codes can't
/// grow its memory without bound.
pub const MAX_OPEN_MESSAGES: usize = 8;

/// The length in bytes of a message ID.
pub const MESSAGE_ID_LEN: usize = 8;

/// The message ID of an object: the first 8 bytes of its SHA-256 (WIRE-175).
pub fn message_id(object: &[u8]) -> [u8; MESSAGE_ID_LEN] {
    sha256(object).as_bytes()[..MESSAGE_ID_LEN].try_into().expect("a digest is 32 bytes")
}

/// Cuts `object` into frames, in order (WIRE-175). An empty object, or one over
/// [`MAX_OBJECT`], is `E_SIZE`.
pub fn encode_sequence(object: &[u8]) -> Result<Vec<String>, WireError> {
    if object.is_empty() || object.len() > MAX_OBJECT {
        return Err(WireError::new(ErrorCode::Size, 0, "an animated sequence carries 1..=MAX_OBJECT bytes"));
    }
    let id = crockford_base32(&message_id(object));
    let total = object.len().div_ceil(CHUNK_BYTES);
    Ok(object
        .chunks(CHUNK_BYTES)
        .enumerate()
        .map(|(i, chunk)| format!("{FRAME_PREFIX}{}/{total}:{id}:{}", i + 1, crockford_base32(chunk)))
        .collect())
}

/// One frame, read and checked on its own.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Frame {
    /// This frame's position, from 1.
    pub seq: usize,
    /// How many frames the message has.
    pub total: usize,
    /// The first 8 bytes of the object's SHA-256.
    pub message_id: [u8; MESSAGE_ID_LEN],
    /// The chunk of the object.
    pub payload: Vec<u8>,
}

fn decimal(s: &str, at: usize) -> Result<usize, WireError> {
    if s.is_empty() || s.len() > 4 || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return Err(WireError::new(ErrorCode::FrameMagic, at, "not a plain decimal number"));
    }
    Ok(s.parse().expect("at most four digits"))
}

impl Frame {
    /// Reads one frame's text (leading and trailing whitespace ignored; the prefix and
    /// base32 are case-insensitive, as a scanner may change case). A frame over 600
    /// characters is `E_SIZE`; a bad prefix, field or character `E_FRAME_MAGIC`; a `seq`
    /// outside `1..=total` `E_SEQ`; more than [`MAX_FRAMES`] frames `E_SIZE`; a payload that
    /// is empty, over a chunk or not a whole base32 string `E_FRAME_LENGTH`.
    pub fn parse(input: &str) -> Result<Self, WireError> {
        let text = input.trim();
        if text.len() > MAX_FRAME_CHARS {
            return Err(WireError::new(ErrorCode::Size, MAX_FRAME_CHARS, "a frame is at most 600 characters"));
        }
        if !text.is_ascii() {
            let at = text.bytes().position(|b| !b.is_ascii()).unwrap_or(0);
            return Err(WireError::new(ErrorCode::FrameMagic, at, "a frame is ASCII"));
        }
        let bad = |at, detail| WireError::new(ErrorCode::FrameMagic, at, detail);
        if text.len() < FRAME_PREFIX.len() || !text.as_bytes()[..FRAME_PREFIX.len()].eq_ignore_ascii_case(FRAME_PREFIX.as_bytes()) {
            return Err(bad(0, "wrong frame prefix"));
        }
        let rest = &text[FRAME_PREFIX.len()..];
        let parts: Vec<&str> = rest.split(':').collect();
        let [position, id, payload] = parts[..] else { return Err(bad(FRAME_PREFIX.len(), "a frame has position, message ID and payload")) };
        let (seq, total) = position.split_once('/').ok_or_else(|| bad(FRAME_PREFIX.len(), "position is seq/total"))?;
        let seq = decimal(seq, FRAME_PREFIX.len())?;
        let total = decimal(total, FRAME_PREFIX.len() + position.len() - 1)?;
        if total > MAX_FRAMES {
            return Err(WireError::new(ErrorCode::Size, FRAME_PREFIX.len(), "more frames than a sequence may have"));
        }
        if seq == 0 || seq > total {
            return Err(WireError::new(ErrorCode::Seq, FRAME_PREFIX.len(), "seq is outside 1..=total"));
        }
        let id_at = FRAME_PREFIX.len() + position.len() + 1;
        if id.len() != 13 {
            return Err(bad(id_at, "a message ID is 13 characters"));
        }
        let message_id: [u8; MESSAGE_ID_LEN] =
            crockford_base32_decode(id).map_err(|e| e.shifted(id_at))?.try_into().map_err(|_| bad(id_at, "a message ID is 8 bytes"))?;
        let payload_at = id_at + id.len() + 1;
        if payload.is_empty() {
            return Err(WireError::new(ErrorCode::FrameLength, payload_at, "a frame carries a payload"));
        }
        let payload = crockford_base32_decode(payload).map_err(|e| e.shifted(payload_at))?;
        if payload.is_empty() || payload.len() > CHUNK_BYTES || (seq < total && payload.len() != CHUNK_BYTES) {
            return Err(WireError::new(ErrorCode::FrameLength, payload_at, "a chunk is CHUNK_BYTES long, except the last"));
        }
        Ok(Self { seq, total, message_id, payload })
    }
}

/// What a receiver knows about one message so far.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Partial {
    total: usize,
    chunks: BTreeMap<usize, Vec<u8>>,
}

/// A receiver's reassembly state (WIRE-177). Feed it every frame the camera reads.
#[derive(Clone, Default, Debug)]
pub struct Reassembler {
    open: BTreeMap<[u8; MESSAGE_ID_LEN], Partial>,
}

impl Reassembler {
    /// An empty receiver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes one frame's text. Returns the object once every frame of a message has arrived
    /// and its SHA-256 matches the message ID; `None` while frames are missing. Frames may
    /// come in any order and repeat; a repeat is ignored.
    ///
    /// Errors: whatever [`Frame::parse`] reports; `E_SEQ` for a frame that disagrees with
    /// the message's `total` or repeats a `seq` with a different payload; `E_SIZE` for a
    /// message beyond [`MAX_OPEN_MESSAGES`]; `E_HASH` when the reassembled object's SHA-256
    /// does not match the message ID (the message is then dropped, so the loop can restart
    /// it).
    pub fn push(&mut self, input: &str) -> Result<Option<Vec<u8>>, WireError> {
        let frame = Frame::parse(input)?;
        if !self.open.contains_key(&frame.message_id) && self.open.len() >= MAX_OPEN_MESSAGES {
            return Err(WireError::new(ErrorCode::Size, 0, "too many messages are open at once"));
        }
        let partial = self.open.entry(frame.message_id).or_insert_with(|| Partial { total: frame.total, chunks: BTreeMap::new() });
        if partial.total != frame.total {
            return Err(WireError::new(ErrorCode::Seq, 0, "a frame disagrees with its message about the total"));
        }
        match partial.chunks.get(&frame.seq) {
            Some(seen) if *seen != frame.payload => {
                return Err(WireError::new(ErrorCode::Seq, 0, "a repeated seq carries a different payload"));
            }
            Some(_) => return Ok(None),
            None => {
                partial.chunks.insert(frame.seq, frame.payload);
            }
        }
        if partial.chunks.len() < partial.total {
            return Ok(None);
        }
        let done = self.open.remove(&frame.message_id).expect("just inserted");
        let object: Vec<u8> = done.chunks.into_values().flatten().collect();
        if message_id(&object) != frame.message_id {
            return Err(WireError::new(ErrorCode::Hash, 0, "the object's SHA-256 does not match the message ID"));
        }
        Ok(Some(object))
    }

    /// How many frames of each open message have arrived, as `(message ID, have, total)`.
    pub fn progress(&self) -> Vec<([u8; MESSAGE_ID_LEN], usize, usize)> {
        self.open.iter().map(|(id, p)| (*id, p.chunks.len(), p.total)).collect()
    }
}
