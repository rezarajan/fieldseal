//! The strict JSON decoder.
//!
//! A small RFC 8259 parser written for this adapter rather than a general-purpose library,
//! because the rules that matter here are the ones libraries leave off by default: duplicate
//! keys are an error (most parsers keep the last silently), numbers keep their written digits
//! (no float is ever built), and null, exponents and non-NFC text are refused.

use std::collections::BTreeMap;

use fieldseal_kernel::value::Value;

use crate::error::{AuthoringError, ErrorKind};
use crate::scalar::{MAX_DEPTH, ScalarError, canonical_number, check_nfc};

struct Parser<'a> {
    text: &'a str,
    pos: usize,
}

type Res<T> = Result<T, AuthoringError>;

impl<'a> Parser<'a> {
    /// Line and column (both from 1, the column in characters) of a byte offset.
    fn position(&self, offset: usize) -> (usize, usize) {
        let before = &self.text[..offset.min(self.text.len())];
        let line = before.bytes().filter(|b| *b == b'\n').count() + 1;
        let line_start = before.rfind('\n').map_or(0, |i| i + 1);
        (line, before[line_start..].chars().count() + 1)
    }

    fn error_at(&self, offset: usize, kind: ErrorKind, message: impl Into<String>) -> AuthoringError {
        let (line, column) = self.position(offset);
        AuthoringError::new(kind, line, column, message)
    }

    fn syntax(&self, message: impl Into<String>) -> AuthoringError {
        self.error_at(self.pos, ErrorKind::Syntax, message)
    }

    fn scalar_error(&self, offset: usize) -> impl Fn(ScalarError) -> AuthoringError + '_ {
        move |(kind, message)| self.error_at(offset, kind, message)
    }

    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn describe_next(&self) -> String {
        self.text[self.pos..].chars().next().map_or_else(|| "end of input".to_owned(), |c| format!("{c:?}"))
    }

    fn expect(&mut self, byte: u8) -> Res<()> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.syntax(format!("expected {:?}, found {}", byte as char, self.describe_next())))
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Res<Value> {
        if self.text[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(self.syntax(format!("unexpected {}", self.describe_next())))
        }
    }

    fn value(&mut self, depth: usize) -> Res<Value> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::Text),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') if self.text[self.pos..].starts_with("null") => Err(self.error_at(
                self.pos,
                ErrorKind::Null,
                "null is not allowed; omit the field instead",
            )),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.syntax(format!("unexpected {}", self.describe_next()))),
        }
    }

    fn number(&mut self) -> Res<Value> {
        let start = self.pos;
        let bytes = self.text.as_bytes();
        let digits = |p: &mut usize| {
            let from = *p;
            while bytes.get(*p).is_some_and(u8::is_ascii_digit) {
                *p += 1;
            }
            *p - from
        };
        let mut p = start;
        if bytes.get(p) == Some(&b'-') {
            p += 1;
        }
        match bytes.get(p) {
            Some(b'0') => {
                p += 1;
                if bytes.get(p).is_some_and(u8::is_ascii_digit) {
                    return Err(self.error_at(start, ErrorKind::Number, "a leading zero is not allowed in JSON numbers"));
                }
            }
            Some(b'1'..=b'9') => {
                digits(&mut p);
            }
            _ => return Err(self.error_at(start, ErrorKind::Syntax, "a number needs digits")),
        }
        if bytes.get(p) == Some(&b'.') {
            p += 1;
            if digits(&mut p) == 0 {
                return Err(self.error_at(start, ErrorKind::Syntax, "a fraction needs digits after the point"));
            }
        }
        if matches!(bytes.get(p), Some(b'e' | b'E')) {
            return Err(self.error_at(
                start,
                ErrorKind::Float,
                "exponent notation is not allowed; write a plain decimal such as 1000 or 0.001",
            ));
        }
        self.pos = p;
        canonical_number(&self.text[start..p]).map_err(self.scalar_error(start))
    }

    fn hex4(&mut self) -> Res<u32> {
        let slice = self.text.get(self.pos..self.pos + 4).filter(|s| s.bytes().all(|b| b.is_ascii_hexdigit()));
        let Some(slice) = slice else {
            return Err(self.syntax("\\u needs four hexadecimal digits"));
        };
        self.pos += 4;
        Ok(u32::from_str_radix(slice, 16).unwrap_or(0))
    }

    fn string(&mut self) -> Res<String> {
        let start = self.pos;
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let Some(c) = self.text[self.pos..].chars().next() else {
                return Err(self.error_at(start, ErrorKind::Syntax, "unterminated string"));
            };
            match c {
                '"' => {
                    self.pos += 1;
                    break;
                }
                '\\' => {
                    self.pos += 1;
                    let escape = self.peek().ok_or_else(|| self.syntax("unterminated escape"))?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let first = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&first) {
                                if !self.text[self.pos..].starts_with("\\u") {
                                    return Err(self.syntax("a high surrogate must be followed by a low surrogate"));
                                }
                                self.pos += 2;
                                let second = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&second) {
                                    return Err(self.syntax("a high surrogate must be followed by a low surrogate"));
                                }
                                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&first) {
                                return Err(self.syntax("a lone low surrogate is not valid text"));
                            } else {
                                first
                            };
                            out.push(char::from_u32(code).ok_or_else(|| self.syntax("invalid code point"))?);
                        }
                        other => {
                            self.pos -= 1;
                            return Err(self.syntax(format!("invalid escape \\{}", other as char)));
                        }
                    }
                }
                c if (c as u32) < 0x20 => {
                    return Err(self.syntax("a control character must be escaped inside a string"));
                }
                c => {
                    out.push(c);
                    self.pos += c.len_utf8();
                }
            }
        }
        check_nfc(&out).map_err(self.scalar_error(start))?;
        Ok(out)
    }

    fn array(&mut self, depth: usize) -> Res<Value> {
        self.nest(depth)?;
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.syntax(format!("expected ',' or ']', found {}", self.describe_next()))),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Res<Value> {
        self.nest(depth)?;
        self.expect(b'{')?;
        let mut entries = BTreeMap::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Map(entries));
        }
        loop {
            self.skip_whitespace();
            let key_at = self.pos;
            if self.peek() != Some(b'"') {
                return Err(self.syntax(format!("expected a string key, found {}", self.describe_next())));
            }
            let key = self.string()?;
            if entries.contains_key(&key) {
                return Err(self.error_at(key_at, ErrorKind::DuplicateKey, format!("duplicate key {key:?}")));
            }
            self.skip_whitespace();
            self.expect(b':')?;
            let value = self.value(depth + 1)?;
            entries.insert(key, value);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Map(entries));
                }
                _ => return Err(self.syntax(format!("expected ',' or '}}', found {}", self.describe_next()))),
            }
        }
    }

    fn nest(&self, depth: usize) -> Res<()> {
        if depth >= MAX_DEPTH {
            Err(self.syntax(format!("nesting is deeper than {MAX_DEPTH} levels"))).map_err(|mut e| {
                e.kind = ErrorKind::TooDeep;
                e
            })
        } else {
            Ok(())
        }
    }
}

/// Decodes one JSON document.
pub(crate) fn decode(text: &str) -> Result<Value, AuthoringError> {
    let mut parser = Parser { text, pos: 0 };
    parser.skip_whitespace();
    if parser.pos >= text.len() {
        return Err(AuthoringError::new(ErrorKind::EmptyDocument, 1, 1, "the file holds no document"));
    }
    let value = parser.value(0)?;
    parser.skip_whitespace();
    if parser.pos < text.len() {
        return Err(parser.syntax(format!("unexpected {} after the document", parser.describe_next())));
    }
    Ok(value)
}
