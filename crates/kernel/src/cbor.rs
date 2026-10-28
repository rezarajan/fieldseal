//! Deterministic CBOR (WIRE §5.1): the one encoding of every [`Value`].
//!
//! This is RFC 8949 §4.2.1 core deterministic encoding restricted to the canonical data
//! model: integers, tag-4 decimal fractions, byte strings, NFC text, booleans, arrays and
//! text-keyed maps. The codec is written by hand so that every acceptance rule is visible
//! here; a decoder accepts exactly the bytes the encoder produces, so
//! `encode(decode(b)?)? == b` for every accepted `b` and `decode(encode(v)?)? == v` for
//! every encodable `v`.

use std::collections::BTreeMap;

use unicode_normalization::is_nfc;

use crate::error::{ErrorCode, WireError};
use crate::value::{Decimal, Value};

/// The deepest nesting of arrays and maps a structure may have (WIRE §6.7).
pub const MAX_DEPTH: usize = 16;
/// The longest text string, in bytes (WIRE §6.7).
pub const MAX_TEXT: usize = 64 * 1024;
/// The most elements an array (or entries a map) may have (WIRE §6.7).
pub const MAX_ELEMENTS: usize = 1_048_576;
/// The smallest integer CBOR can carry without a bignum: −2⁶⁴.
pub const INT_MIN: i128 = -(1i128 << 64);
/// The largest integer CBOR can carry without a bignum: 2⁶⁴ − 1.
pub const INT_MAX: i128 = (1i128 << 64) - 1;

const MAJOR_UINT: u8 = 0;
const MAJOR_NINT: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;
const TAG_DECIMAL: u64 = 4;
const FALSE: u8 = 0xf4;
const TRUE: u8 = 0xf5;

/// Encodes a value as deterministic CBOR (WIRE-001).
///
/// Fails (offset 0) if the value is outside the data model: an integer or mantissa beyond
/// [`INT_MIN`]..=[`INT_MAX`] or text not in NFC (`E_CBOR_NONCANONICAL`), or a text string,
/// array or nesting depth beyond WIRE §6.7 (`E_SIZE`). Encoders never normalise silently.
pub fn encode(value: &Value) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::new();
    encode_into(value, &mut out)?;
    Ok(out)
}

/// Encodes a value, appending to `out`.
pub fn encode_into(value: &Value, out: &mut Vec<u8>) -> Result<(), WireError> {
    encode_at(value, out, 0)
}

fn encode_at(value: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), WireError> {
    match value {
        Value::Int(i) => encode_int(*i, out),
        Value::Decimal(d) => {
            head(out, MAJOR_TAG, TAG_DECIMAL);
            head(out, MAJOR_ARRAY, 2);
            encode_int(i128::from(d.exponent), out)?;
            encode_int(d.mantissa, out)
        }
        Value::Bytes(b) => {
            head(out, MAJOR_BYTES, b.len() as u64);
            out.extend_from_slice(b);
            Ok(())
        }
        Value::Text(t) => encode_text(t, out),
        Value::Bool(b) => {
            out.push(if *b { TRUE } else { FALSE });
            Ok(())
        }
        Value::Array(items) => {
            enter(depth, items.len())?;
            head(out, MAJOR_ARRAY, items.len() as u64);
            items.iter().try_for_each(|v| encode_at(v, out, depth + 1))
        }
        Value::Map(entries) => {
            enter(depth, entries.len())?;
            let mut encoded = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let mut key = Vec::with_capacity(k.len() + 9);
                encode_text(k, &mut key)?;
                encoded.push((key, v));
            }
            // Core deterministic order: bytewise order of the encoded keys (RFC 8949 §4.2.1).
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            head(out, MAJOR_MAP, encoded.len() as u64);
            for (key, v) in encoded {
                out.extend_from_slice(&key);
                encode_at(v, out, depth + 1)?;
            }
            Ok(())
        }
    }
}

fn enter(depth: usize, len: usize) -> Result<(), WireError> {
    if depth >= MAX_DEPTH {
        return Err(WireError::new(ErrorCode::Size, 0, "nesting deeper than 16"));
    }
    if len > MAX_ELEMENTS {
        return Err(WireError::new(ErrorCode::Size, 0, "more than 1 048 576 elements"));
    }
    Ok(())
}

fn encode_int(i: i128, out: &mut Vec<u8>) -> Result<(), WireError> {
    if !(INT_MIN..=INT_MAX).contains(&i) {
        return Err(WireError::new(ErrorCode::CborNoncanonical, 0, "integer outside -2^64..2^64-1"));
    }
    if i >= 0 {
        head(out, MAJOR_UINT, i as u64);
    } else {
        head(out, MAJOR_NINT, (-1 - i) as u64);
    }
    Ok(())
}

fn encode_text(t: &str, out: &mut Vec<u8>) -> Result<(), WireError> {
    if t.len() > MAX_TEXT {
        return Err(WireError::new(ErrorCode::Size, 0, "text longer than 64 KiB"));
    }
    if !is_nfc(t) {
        return Err(WireError::new(ErrorCode::CborNoncanonical, 0, "text not in NFC"));
    }
    head(out, MAJOR_TEXT, t.len() as u64);
    out.extend_from_slice(t.as_bytes());
    Ok(())
}

/// Writes a shortest-form head (RFC 8949 §4.2.1).
fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xff {
        out.extend_from_slice(&[m | 24, arg as u8]);
    } else if arg <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Decodes one deterministic CBOR value that spans the whole input (WIRE-002..007).
///
/// Every rejection carries the offset of the offending byte. Trailing bytes are rejected.
pub fn decode(bytes: &[u8]) -> Result<Value, WireError> {
    let mut d = Decoder { buf: bytes, pos: 0 };
    let value = d.value(0)?;
    if d.pos != bytes.len() {
        return Err(WireError::new(ErrorCode::CborNoncanonical, d.pos, "trailing bytes"));
    }
    Ok(value)
}

/// Decodes like [`decode`], first refusing input longer than `max_len` bytes with `E_SIZE`
/// (WIRE-160): the object's own limit is checked before anything is allocated.
pub fn decode_limited(bytes: &[u8], max_len: usize) -> Result<Value, WireError> {
    if bytes.len() > max_len {
        return Err(WireError::new(ErrorCode::Size, max_len, "object exceeds its size limit"));
    }
    decode(bytes)
}

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Decoder<'_> {
    fn err(&self, code: ErrorCode, offset: usize, detail: &'static str) -> WireError {
        WireError::new(code, offset, detail)
    }

    fn truncated(&self) -> WireError {
        self.err(ErrorCode::CborNoncanonical, self.buf.len(), "truncated input")
    }

    fn take(&mut self, n: usize) -> Result<&[u8], WireError> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.buf.len()).ok_or_else(|| self.truncated())?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Reads an initial byte and its argument, rejecting non-shortest and indefinite forms.
    /// Returns (major, additional info, argument).
    fn head(&mut self) -> Result<(u8, u8, u64), WireError> {
        let start = self.pos;
        let ib = self.take(1)?[0];
        let (major, ai) = (ib >> 5, ib & 0x1f);
        if major == MAJOR_SIMPLE {
            return match ib {
                FALSE | TRUE => Ok((major, ai, 0)),
                0xf9..=0xfb => Err(self.err(ErrorCode::CborNoncanonical, start, "floating point is not allowed")),
                0xf6 | 0xf7 => Err(self.err(ErrorCode::CborNoncanonical, start, "null and undefined are not allowed")),
                0xff => Err(self.err(ErrorCode::CborNoncanonical, start, "unexpected break")),
                _ => Err(self.err(ErrorCode::CborNoncanonical, start, "simple values are not allowed")),
            };
        }
        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(self.array()?)),
            26 => u64::from(u32::from_be_bytes(self.array()?)),
            27 => u64::from_be_bytes(self.array()?),
            31 => return Err(self.err(ErrorCode::CborNoncanonical, start, "indefinite length")),
            _ => return Err(self.err(ErrorCode::CborNoncanonical, start, "reserved additional information")),
        };
        let shortest = match ai {
            24 => arg >= 24,
            25 => arg > 0xff,
            26 => arg > 0xffff,
            27 => arg > 0xffff_ffff,
            _ => true,
        };
        if !shortest {
            return Err(self.err(ErrorCode::CborNoncanonical, start, "argument not in shortest form"));
        }
        Ok((major, ai, arg))
    }

    fn length(&self, arg: u64, start: usize) -> Result<usize, WireError> {
        usize::try_from(arg).map_err(|_| self.err(ErrorCode::Size, start, "length does not fit memory"))
    }

    fn value(&mut self, depth: usize) -> Result<Value, WireError> {
        let start = self.pos;
        let (major, ai, arg) = self.head()?;
        match major {
            MAJOR_UINT => Ok(Value::Int(i128::from(arg))),
            MAJOR_NINT => Ok(Value::Int(-1 - i128::from(arg))),
            MAJOR_BYTES => {
                let len = self.length(arg, start)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            MAJOR_TEXT => Ok(Value::Text(self.text_body(arg, start)?)),
            MAJOR_ARRAY => {
                let len = self.container(arg, start, depth)?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            MAJOR_MAP => {
                let len = self.container(arg, start, depth)?;
                let mut map = BTreeMap::new();
                let mut previous: Option<&[u8]> = None;
                for _ in 0..len {
                    let key_start = self.pos;
                    let (kmajor, _, karg) = self.head()?;
                    if kmajor != MAJOR_TEXT {
                        return Err(self.err(ErrorCode::CborNoncanonical, key_start, "map key is not text"));
                    }
                    let key = self.text_body(karg, key_start)?;
                    let raw = &self.buf[key_start..self.pos];
                    if map.contains_key(&key) {
                        return Err(self.err(ErrorCode::CborDuplicate, key_start, "duplicate map key"));
                    }
                    if previous.is_some_and(|p| raw <= p) {
                        return Err(self.err(ErrorCode::CborNoncanonical, key_start, "map keys out of order"));
                    }
                    previous = Some(raw);
                    let value = self.value(depth + 1)?;
                    map.insert(key, value);
                }
                Ok(Value::Map(map))
            }
            MAJOR_TAG => {
                if arg != TAG_DECIMAL {
                    return Err(self.err(ErrorCode::CborTag, start, "only tag 4 is permitted"));
                }
                self.decimal_body(start).map(Value::Decimal)
            }
            _ => Ok(Value::Bool(ai == (TRUE & 0x1f))),
        }
    }

    fn container(&self, arg: u64, start: usize, depth: usize) -> Result<usize, WireError> {
        if depth >= MAX_DEPTH {
            return Err(self.err(ErrorCode::Size, start, "nesting deeper than 16"));
        }
        let len = self.length(arg, start)?;
        if len > MAX_ELEMENTS {
            return Err(self.err(ErrorCode::Size, start, "more than 1 048 576 elements"));
        }
        // Every element takes at least one byte: refuse impossible lengths before allocating.
        if len > self.remaining() {
            return Err(self.truncated());
        }
        Ok(len)
    }

    fn text_body(&mut self, arg: u64, start: usize) -> Result<String, WireError> {
        let len = self.length(arg, start)?;
        if len > MAX_TEXT {
            return Err(self.err(ErrorCode::Size, start, "text longer than 64 KiB"));
        }
        let bytes = self.take(len)?;
        let text = core::str::from_utf8(bytes)
            .map_err(|_| WireError::new(ErrorCode::CborNoncanonical, start, "text is not UTF-8"))?;
        if !is_nfc(text) {
            return Err(self.err(ErrorCode::CborNoncanonical, start, "text not in NFC"));
        }
        Ok(text.to_owned())
    }

    fn decimal_body(&mut self, start: usize) -> Result<Decimal, WireError> {
        let array_start = self.pos;
        let (major, _, arg) = self.head()?;
        if major != MAJOR_ARRAY || arg != 2 {
            return Err(self.err(ErrorCode::CborNoncanonical, array_start, "decimal is not [exponent, mantissa]"));
        }
        let exponent = self.int()?;
        let exponent = i32::try_from(exponent)
            .map_err(|_| self.err(ErrorCode::CborNoncanonical, start, "decimal exponent out of range"))?;
        let mantissa = self.int()?;
        Ok(Decimal { mantissa, exponent })
    }

    fn int(&mut self) -> Result<i128, WireError> {
        let at = self.pos;
        match self.head()? {
            (MAJOR_UINT, _, arg) => Ok(i128::from(arg)),
            (MAJOR_NINT, _, arg) => Ok(-1 - i128::from(arg)),
            (MAJOR_TAG, _, _) => Err(self.err(ErrorCode::CborTag, at, "only tag 4 is permitted")),
            _ => Err(self.err(ErrorCode::CborNoncanonical, at, "decimal part is not an integer")),
        }
    }
}

/// Builds a map value from `(key, value)` pairs.
pub fn map<'a>(entries: impl IntoIterator<Item = (&'a str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}
