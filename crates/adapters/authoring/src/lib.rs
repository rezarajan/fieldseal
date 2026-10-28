//! Strict decoding of YAML and JSON authoring documents into the canonical data model.
//!
//! Instruments, layouts and policies are written by people in YAML or JSON and converted by
//! `fieldseal` before they are validated, signed or hashed (spec README, "Resources"). This
//! adapter does the first step: bytes to [`Value`] (WIRE §5.1). It is deliberately stricter than
//! general-purpose YAML and JSON libraries, because what a reviewer reads must be exactly what is
//! signed.
//!
//! # Rules, both formats
//!
//! - **No duplicate keys**, and **map keys are strings.**
//! - **No null**: `null`, `~`, an empty YAML value and JSON `null` are errors. The canonical data
//!   model has none; omit the field instead.
//! - **No floats.** A number with a fraction is a [`fieldseal_kernel::Decimal`] that keeps every
//!   written digit (`1.10` stays `1.10`); `1e3`, `.inf` and `.nan` are errors. Integers are
//!   limited to −2⁶⁴ ..= 2⁶⁴−1.
//! - **Text must already be in Unicode Normalization Form C** (WIRE-004). Non-NFC text is
//!   *rejected*, not normalised: normalising would silently change what the author typed.
//! - Nesting is limited to 128 levels.
//!
//! # Rules, YAML only
//!
//! YAML 1.2 syntax, read as events (`saphyr-parser`) with our own scalar rules:
//!
//! - Plain scalars are `true`/`false`, canonical numbers (`-?(0|[1-9][0-9]*)` and the same with a
//!   `.digits` fraction), or text. `yes`, `no`, `on`, `off`, `y` and `n` are **text**, never
//!   booleans. Dates and versions (`2026-01-05`, `1.0.0`) and times (`1:30`) are text.
//! - `True`, `TRUE`, `False` and `FALSE` are errors (ambiguous between YAML versions).
//! - Number-like scalars that are not canonical are **errors**, not text: a leading zero or
//!   octal form (`007`, `0o17`), hexadecimal and binary (`0x1F`), a plus sign (`+1`), digit
//!   separators (`1_000`), and `.5` or `5.`. Quote them to keep them as text.
//! - Quoted and block scalars are always text.
//! - **No anchors, aliases, merge keys (`<<`) or tags**, because they hide content from
//!   reviewers. The single exception is `!!binary`, which decodes base64 to
//!   [`fieldseal_kernel::Value::Bytes`].
//! - **One document per file.**
//!
//! # Rules, JSON only
//!
//! RFC 8259 with nothing extra: no comments, no trailing commas, no leading zeros. The decoder is
//! a small parser written here, because duplicate-key detection and digit-preserving numbers are
//! what most libraries lack.
//!
//! Every error carries the line and column (from 1) where it was found.

mod error;
mod json;
mod scalar;
mod yaml;

pub use error::{AuthoringError, ErrorKind};
pub use fieldseal_kernel::value::Value;

/// The syntax of an authoring document. The caller chooses it, usually from the file extension
/// (see [`Format::from_extension`]); the decoder never sniffs content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    /// YAML 1.2, restricted as described in the crate documentation.
    Yaml,
    /// JSON (RFC 8259), restricted as described in the crate documentation.
    Json,
}

impl Format {
    /// The format for a file extension without its dot (`yaml`, `yml`, `json`), case-insensitively.
    #[must_use]
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.to_ascii_lowercase().as_str() {
            "yaml" | "yml" => Some(Self::Yaml),
            "json" => Some(Self::Json),
            _ => None,
        }
    }
}

/// Decodes an authoring document into the canonical data model, strictly.
///
/// A leading UTF-8 byte-order mark is ignored.
///
/// # Errors
///
/// An [`AuthoringError`] with the position of the first problem found.
pub fn decode(bytes: &[u8], format: Format) -> Result<Value, AuthoringError> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let text = std::str::from_utf8(bytes).map_err(|e| {
        let valid = &bytes[..e.valid_up_to()];
        let line = valid.iter().filter(|b| **b == b'\n').count() + 1;
        let line_start = valid.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        let column = String::from_utf8_lossy(&valid[line_start..]).chars().count() + 1;
        AuthoringError {
            kind: ErrorKind::Encoding,
            line,
            column,
            message: "the file is not valid UTF-8".to_owned(),
        }
    })?;
    let doc = match format {
        Format::Yaml => yaml::decode(text),
        Format::Json => json::decode(text),
    }?;
    compact::expand(doc)
}

/// Decodes an authoring document without expanding a compact one (ADR 0040): what the file says.
///
/// # Errors
///
/// An [`AuthoringError`] with the position of the first problem found.
pub fn decode_raw(bytes: &[u8], format: Format) -> Result<Value, AuthoringError> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let text = std::str::from_utf8(bytes).map_err(|_| AuthoringError::new(ErrorKind::Encoding, 1, 1, "the file is not valid UTF-8"))?;
    match format {
        Format::Yaml => yaml::decode(text),
        Format::Json => json::decode(text),
    }
}

/// Decodes the authoring document at `path` (format from its extension), expanding a compact
/// document (ADR 0040) with the translations in the `i18n/<lang>.po` catalogues beside it.
///
/// # Errors
///
/// An [`AuthoringError`]; an unreadable file or catalogue is reported as [`ErrorKind::Encoding`].
pub fn decode_path(path: &std::path::Path) -> Result<Value, AuthoringError> {
    let io = |p: &std::path::Path, e: std::io::Error| AuthoringError::new(ErrorKind::Encoding, 0, 0, format!("{}: {e}", p.display()));
    let format = path.extension().and_then(|e| e.to_str()).and_then(Format::from_extension).ok_or_else(|| AuthoringError::new(ErrorKind::Encoding, 0, 0, format!("{}: use a .yaml, .yml or .json file", path.display())))?;
    let bytes = std::fs::read(path).map_err(|e| io(path, e))?;
    let text = std::str::from_utf8(bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes)).map_err(|_| AuthoringError::new(ErrorKind::Encoding, 1, 1, "the file is not valid UTF-8"))?;
    let doc = match format {
        Format::Yaml => yaml::decode(text),
        Format::Json => json::decode(text),
    }?;
    if !compact::is_compact(&doc) {
        return Ok(doc);
    }
    let mut catalogues = compact::Catalogues::new();
    let dir = path.parent().unwrap_or(std::path::Path::new(".")).join("i18n").join(path.file_stem().and_then(|s| s.to_str()).unwrap_or(""));
    if let Ok(entries) = std::fs::read_dir(&dir) {
        let mut files: Vec<_> = entries.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "po")).collect();
        files.sort();
        for po in files {
            let lang = po.file_stem().and_then(|s| s.to_str()).unwrap_or_default().to_owned();
            let text = std::fs::read_to_string(&po).map_err(|e| io(&po, e))?;
            let cat = compact::parse_po(&text).map_err(|e| AuthoringError::new(e.kind, e.line, e.column, format!("{}: {}", po.display(), e.message)))?;
            catalogues.insert(lang, cat);
        }
    }
    compact::expand_with(doc, &catalogues)
}

pub mod compact;

