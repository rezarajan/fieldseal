//! The error every decoder reports.

use std::fmt;

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
}

impl fmt::Display for AuthoringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}, column {}: {}", self.line, self.column, self.message)
    }
}

impl AuthoringError {
    pub(crate) fn new(kind: ErrorKind, line: usize, column: usize, message: impl Into<String>) -> Self {
        Self { kind, line, column, message: message.into() }
    }
}
