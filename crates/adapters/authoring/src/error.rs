//! The error every decoder reports.

use std::fmt;

use fieldseal_kernel::schema::SchemaErrorKind;

/// What was wrong with a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The bytes are not valid UTF-8.
    Encoding,
    /// The document is not well-formed YAML or JSON.
    Syntax,
    /// The input holds no document.
    EmptyDocument,
    /// A YAML stream holds more than one document.
    MultipleDocuments,
    /// A map has the same key twice.
    DuplicateKey,
    /// A map key is not a string (a number, a boolean, a collection).
    NonStringKey,
    /// A null (`null`, `~` or an empty value). The canonical data model has no null.
    Null,
    /// A floating-point form (`1e3`, `.inf`, `.nan`). Write a plain decimal such as `0.5`.
    Float,
    /// A number written in a form that is ambiguous between YAML versions or readers
    /// (leading zero, octal, hexadecimal, a plus sign, digit separators, `.5`, `5.`), or out of range.
    Number,
    /// `True`, `FALSE` and the like. Only `true` and `false` are booleans.
    AmbiguousBoolean,
    /// A YAML alias (`*name`).
    Alias,
    /// A YAML anchor (`&name`).
    Anchor,
    /// A YAML merge key (`<<`).
    MergeKey,
    /// A YAML tag other than `!!binary`.
    Tag,
    /// `!!binary` content that is not valid base64, or `!!binary` on a non-scalar.
    Binary,
    /// Text that is not in Unicode Normalization Form C (WIRE-004).
    NotNfc,
    /// Nesting deeper than the limit.
    TooDeep,
    /// A compact document (ADR 0040) that does not expand: an unknown key, a wrong type, or a
    /// name that resolves to nothing. The message names the path.
    Compact,
}

/// A place in a document: line and column, both counting from 1 (the column in characters).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Position {
    /// The line.
    pub line: usize,
    /// The column.
    pub column: usize,
}

/// One problem found in a document, with where it is (WIRE-211).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedFinding {
    /// The file, when the document was read from one.
    pub file: Option<String>,
    /// An RFC 6901 JSON Pointer to the offending location.
    pub pointer: String,
    /// Where that location is in the file.
    pub position: Position,
    /// Which of the six WIRE-211 kinds.
    pub kind: SchemaErrorKind,
    /// A message for the author.
    pub message: String,
}

impl fmt::Display for LocatedFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(file) = &self.file {
            write!(f, "{file}:")?;
        }
        write!(f, "{}:{}: {}: {}: {}", self.position.line, self.position.column, self.kind, self.pointer, self.message)
    }
}

/// A document the adapter refused, with where and why.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct AuthoringError {
    /// What kind of problem it is.
    pub kind: ErrorKind,
    /// The line, counting from 1.
    pub line: usize,
    /// The column in characters, counting from 1.
    pub column: usize,
    /// A message for the author.
    pub message: String,
    /// The same place as `line` and `column`; none for an error with no position in the text
    /// (an unreadable file keeps line 0, column 0 and names the file in the message).
    pub position: Option<Position>,
    /// Every finding of a schema failure, in the order they appear in the file; `line`, `column`
    /// and `message` are the first one's. Empty for any other error, except that a repeated key
    /// and a refused value carry their one finding.
    pub findings: Vec<LocatedFinding>,
}

impl fmt::Display for AuthoringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}, column {}: {}", self.line, self.column, self.message)
    }
}

impl AuthoringError {
    pub(crate) fn new(kind: ErrorKind, line: usize, column: usize, message: impl Into<String>) -> Self {
        let position = (line > 0).then_some(Position { line, column });
        Self { kind, line, column, message: message.into(), position, findings: Vec::new() }
    }

    /// An error that is also a WIRE-211 finding at `pointer`: a repeated key or a refused value.
    pub(crate) fn finding(kind: ErrorKind, finding: SchemaErrorKind, pointer: &str, line: usize, column: usize, message: impl Into<String>) -> Self {
        let message = message.into();
        let mut e = Self::new(kind, line, column, message.clone());
        e.findings.push(LocatedFinding { file: None, pointer: pointer.to_owned(), position: Position { line, column }, kind: finding, message });
        e
    }

    /// The schema kind a decoder error stands for, if it is one of the six.
    pub(crate) fn schema_kind(kind: ErrorKind) -> Option<SchemaErrorKind> {
        match kind {
            ErrorKind::DuplicateKey => Some(SchemaErrorKind::DuplicateKey),
            ErrorKind::Null | ErrorKind::Float | ErrorKind::Number | ErrorKind::AmbiguousBoolean => Some(SchemaErrorKind::CoercionRefused),
            _ => None,
        }
    }
}
