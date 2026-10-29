//! The strict YAML decoder.
//!
//! YAML is read as an event stream (`saphyr-parser`, YAML 1.2) and turned into [`Value`]s here, so
//! that every decision about what a scalar means is ours, in `scalar.rs`, and not a library
//! default. Anything that could hide content from a reviewer is refused: anchors, aliases, merge
//! keys, tags, duplicate keys, further documents.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use fieldseal_kernel::value::Value;
use saphyr_parser::{Event, Marker, Parser, ScalarStyle, Span, Tag};

use fieldseal_kernel::schema::{SchemaErrorKind, child_pointer};

use crate::error::{AuthoringError, ErrorKind, Position};
use crate::scalar::{MAX_DEPTH, ScalarError, check_nfc, resolve_plain};
use crate::spans::Spans;

/// The tag handle YAML assigns to `!!`.
const CORE_TAG_PREFIX: &str = "tag:yaml.org,2002:";

enum Frame {
    Seq(Vec<Value>),
    Map { entries: BTreeMap<String, Value>, key: Option<String> },
}

struct Builder {
    stack: Vec<Frame>,
    root: Option<Value>,
    spans: Spans,
}

fn position(mark: Marker) -> Position {
    Position { line: mark.line(), column: mark.col() + 1 }
}

fn at(kind: ErrorKind, mark: Marker, message: impl Into<String>) -> AuthoringError {
    AuthoringError::new(kind, mark.line(), mark.col() + 1, message)
}

/// An error at `mark`; a refused value carries the JSON Pointer of the node it is in.
fn scalar_err<'a>(mark: Marker, pointer: &'a str) -> impl Fn(ScalarError) -> AuthoringError + 'a {
    move |(kind, message)| match AuthoringError::schema_kind(kind) {
        Some(finding) => AuthoringError::finding(kind, finding, pointer, mark.line(), mark.col() + 1, message),
        None => at(kind, mark, message),
    }
}

fn is_binary_tag(tag: &Tag) -> bool {
    (tag.handle == CORE_TAG_PREFIX || tag.handle == "!!") && tag.suffix == "binary"
}

fn reject_tag_and_anchor(tag: Option<&Tag>, anchor: usize, span: Span, collection: bool) -> Result<(), AuthoringError> {
    if anchor != 0 {
        return Err(at(
            ErrorKind::Anchor,
            span.start,
            "anchors are not allowed: they hide content from reviewers; write the content out",
        ));
    }
    if let Some(tag) = tag {
        if collection && is_binary_tag(tag) {
            return Err(at(ErrorKind::Binary, span.start, "!!binary can tag only a scalar"));
        }
        if !is_binary_tag(tag) {
            return Err(at(
                ErrorKind::Tag,
                span.start,
                format!("tag {}{} is not allowed; only !!binary is", tag.handle, tag.suffix),
            ));
        }
    }
    Ok(())
}

impl Builder {
    /// Whether the next node is a map key.
    fn expecting_key(&self) -> bool {
        matches!(self.stack.last(), Some(Frame::Map { key: None, .. }))
    }

    /// The JSON Pointer of the node being read: the path through the open collections.
    fn pointer(&self) -> String {
        self.stack.iter().fold(String::new(), |p, frame| match frame {
            Frame::Seq(items) => child_pointer(&p, &items.len().to_string()),
            Frame::Map { key: Some(k), .. } => child_pointer(&p, k),
            Frame::Map { key: None, .. } => p,
        })
    }

    fn check_depth(&self, mark: Marker) -> Result<(), AuthoringError> {
        if self.stack.len() >= MAX_DEPTH {
            Err(at(ErrorKind::TooDeep, mark, format!("nesting is deeper than {MAX_DEPTH} levels")))
        } else {
            Ok(())
        }
    }

    fn start_collection(&mut self, frame: Frame, mark: Marker) -> Result<(), AuthoringError> {
        if self.expecting_key() {
            return Err(at(ErrorKind::NonStringKey, mark, "map keys must be strings, not collections"));
        }
        self.check_depth(mark)?;
        self.spans.note_value(self.pointer(), position(mark));
        self.stack.push(frame);
        Ok(())
    }

    /// Places a finished value (never a key) into its parent.
    fn place(&mut self, value: Value) {
        match self.stack.last_mut() {
            None => self.root = Some(value),
            Some(Frame::Seq(items)) => items.push(value),
            Some(Frame::Map { entries, key }) => {
                if let Some(k) = key.take() {
                    entries.insert(k, value);
                }
            }
        }
    }

    fn scalar(
        &mut self,
        text: &str,
        style: ScalarStyle,
        tag: Option<&Tag>,
        mark: Marker,
    ) -> Result<(), AuthoringError> {
        let plain = matches!(style, ScalarStyle::Plain);
        let here = self.pointer();
        let named = if self.expecting_key() { child_pointer(&here, text) } else { here.clone() };
        let value = if tag.is_some() {
            let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            Value::Bytes(STANDARD.decode(compact.as_bytes()).map_err(|e| {
                at(ErrorKind::Binary, mark, format!("!!binary content is not valid base64: {e}"))
            })?)
        } else if plain {
            resolve_plain(text).map_err(scalar_err(mark, &named))?
        } else {
            Value::Text(text.to_owned())
        };
        if self.expecting_key() {
            let Value::Text(key) = value else {
                return Err(at(
                    ErrorKind::NonStringKey,
                    mark,
                    format!("map keys must be strings, found {}; quote the key", value.kind()),
                ));
            };
            if plain && key == "<<" {
                return Err(at(ErrorKind::MergeKey, mark, "merge keys (<<) are not allowed: they hide content from reviewers"));
            }
            check_nfc(&key).map_err(scalar_err(mark, &named))?;
            if let Some(Frame::Map { entries, key: pending }) = self.stack.last_mut() {
                if entries.contains_key(&key) {
                    return Err(AuthoringError::finding(
                        ErrorKind::DuplicateKey,
                        SchemaErrorKind::DuplicateKey,
                        &child_pointer(&here, &key),
                        mark.line(),
                        mark.col() + 1,
                        format!("duplicate key {key:?}"),
                    ));
                }
                self.spans.note_key(child_pointer(&here, &key), position(mark));
                *pending = Some(key);
            }
            return Ok(());
        }
        if let Value::Text(t) = &value {
            check_nfc(t).map_err(scalar_err(mark, &named))?;
        }
        self.spans.note_value(here, position(mark));
        self.place(value);
        Ok(())
    }

    fn end_collection(&mut self) {
        let value = match self.stack.pop() {
            Some(Frame::Seq(items)) => Value::Array(items),
            Some(Frame::Map { entries, .. }) => Value::Map(entries),
            None => return,
        };
        self.place(value);
    }
}

/// Decodes one YAML document.
pub(crate) fn decode(text: &str) -> Result<Value, AuthoringError> {
    decode_with_spans(text).map(|(value, _)| value)
}

/// Decodes one YAML document and notes where each key and value is, by JSON Pointer.
pub(crate) fn decode_with_spans(text: &str) -> Result<(Value, Spans), AuthoringError> {
    let mut parser = Parser::new_from_str(text);
    let mut b = Builder { stack: Vec::new(), root: None, spans: Spans::default() };
    let mut documents = 0usize;
    for item in &mut parser {
        let (event, span) = item.map_err(|e| {
            let m = e.marker();
            AuthoringError::new(ErrorKind::Syntax, m.line(), m.col() + 1, e.info().to_owned())
        })?;
        match event {
            Event::Nothing | Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => {}
            Event::DocumentStart(_) => {
                documents += 1;
                if documents > 1 {
                    return Err(at(
                        ErrorKind::MultipleDocuments,
                        span.start,
                        "a file holds exactly one document; remove the extra `---`",
                    ));
                }
            }
            Event::Alias(_) => {
                return Err(at(
                    ErrorKind::Alias,
                    span.start,
                    "aliases are not allowed: they hide content from reviewers; write the content out",
                ));
            }
            Event::Scalar(text, style, anchor, tag) => {
                reject_tag_and_anchor(tag.as_deref(), anchor, span, false)?;
                b.scalar(&text, style, tag.as_deref(), span.start)?;
            }
            Event::SequenceStart(anchor, tag) => {
                reject_tag_and_anchor(tag.as_deref(), anchor, span, true)?;
                b.start_collection(Frame::Seq(Vec::new()), span.start)?;
            }
            Event::MappingStart(anchor, tag) => {
                reject_tag_and_anchor(tag.as_deref(), anchor, span, true)?;
                b.start_collection(Frame::Map { entries: BTreeMap::new(), key: None }, span.start)?;
            }
            Event::SequenceEnd | Event::MappingEnd => b.end_collection(),
        }
    }
    let spans = b.spans;
    b.root.map(|root| (root, spans)).ok_or_else(|| AuthoringError::new(ErrorKind::EmptyDocument, 1, 1, "the file holds no document"))
}
