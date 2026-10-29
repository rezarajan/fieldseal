//! Where each part of a decoded document is in its text.

use std::collections::BTreeMap;

use crate::error::Position;

/// Where one value is: its own start, and for a map entry the key that names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Where the key is; none for the root and for an item of a list.
    pub key: Option<Position>,
    /// Where the value starts.
    pub value: Position,
}

/// The positions of a decoded document, by RFC 6901 JSON Pointer (for example
/// `/lists/water-sources/items/2/label`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Spans {
    spans: BTreeMap<String, Span>,
}

impl Spans {
    /// The span of the value at `pointer`.
    #[must_use]
    pub fn get(&self, pointer: &str) -> Option<&Span> {
        self.spans.get(pointer)
    }

    /// Where the key of the entry at `pointer` is, or its value when it is not an entry.
    #[must_use]
    pub fn key(&self, pointer: &str) -> Option<Position> {
        self.get(pointer).map(|s| s.key.unwrap_or(s.value))
    }

    /// Where the value at `pointer` starts.
    #[must_use]
    pub fn value(&self, pointer: &str) -> Option<Position> {
        self.get(pointer).map(|s| s.value)
    }

    /// Where to point for something at `pointer`: its value, or when nothing is there (a missing
    /// key) the nearest enclosing entry's key. The start of the file when nothing encloses it.
    #[must_use]
    pub fn nearest(&self, pointer: &str) -> Position {
        let mut p = pointer;
        loop {
            if let Some(s) = self.get(p) {
                return if p == pointer { s.value } else { s.key.unwrap_or(s.value) };
            }
            match p.rfind('/') {
                Some(i) => p = &p[..i],
                None => return Position { line: 1, column: 1 },
            }
        }
    }

    /// Notes where the key of the entry at `pointer` is.
    pub(crate) fn note_key(&mut self, pointer: String, at: Position) {
        let entry = self.spans.entry(pointer).or_insert(Span { key: None, value: at });
        entry.key = Some(at);
    }

    /// Notes where the value at `pointer` starts.
    pub(crate) fn note_value(&mut self, pointer: String, at: Position) {
        self.spans.entry(pointer).and_modify(|s| s.value = at).or_insert(Span { key: None, value: at });
    }
}
