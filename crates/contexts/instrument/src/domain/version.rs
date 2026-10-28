//! Schema versions, schema ranges and the compatibility rule (INS §5.10), and the semantic
//! versions instruments label themselves with (INS-001).

use std::fmt;

/// A semantic version `major.minor.patch`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct SchemaVersion {
    /// Breaking changes.
    pub major: u32,
    /// Additions.
    pub minor: u32,
    /// Fixes.
    pub patch: u32,
}

/// The instrument-schema version this format core implements (INS-090).
pub const IMPLEMENTED_SCHEMA: SchemaVersion = SchemaVersion { major: 1, minor: 0, patch: 0 };

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The instrument-schema versions an instrument needs: a major version and the lowest minor
/// version within it, written `^<major>.<minor>` (INS-091).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SchemaRange {
    /// The major version required.
    pub major: u32,
    /// The lowest minor version required.
    pub min_minor: u32,
}

/// Why a schema range couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("schema range must be written ^<major>.<minor>")]
pub struct SchemaRangeError;

impl SchemaRange {
    /// Parses `^<major>.<minor>`.
    pub fn parse(text: &str) -> Result<Self, SchemaRangeError> {
        let rest = text.strip_prefix('^').ok_or(SchemaRangeError)?;
        let (major, minor) = rest.split_once('.').ok_or(SchemaRangeError)?;
        Ok(Self { major: number(major).ok_or(SchemaRangeError)?, min_minor: number(minor).ok_or(SchemaRangeError)? })
    }
}

impl fmt::Display for SchemaRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "^{}.{}", self.major, self.min_minor)
    }
}

/// A decimal number without sign or leading zeros (semver §2).
fn number(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    text.parse().ok()
}

/// Whether a runtime can open an instrument.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Compatibility {
    /// It can.
    Compatible,
    /// It can't, and why.
    Incompatible(String),
}

/// The runtime accepts an instrument only if the major versions match and the runtime's
/// minor version is at least the one required (ADR 0010, INS-092).
pub fn check_compatibility(required: SchemaRange, supported: SchemaVersion) -> Compatibility {
    if required.major != supported.major {
        Compatibility::Incompatible(format!(
            "needs schema major {}, runtime implements {}",
            required.major, supported.major
        ))
    } else if supported.minor < required.min_minor {
        Compatibility::Incompatible(format!(
            "needs schema {}.{} or later, runtime implements {}.{}",
            required.major, required.min_minor, supported.major, supported.minor
        ))
    } else {
        Compatibility::Compatible
    }
}

/// A semantic version 2.0.0 label, kept as written (INS-001). Labels only (INS-101).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct SemVer {
    /// The core `major.minor.patch`.
    pub core: SchemaVersion,
    /// The pre-release part after `-`, if any.
    pub pre: Option<String>,
    /// The build metadata after `+`, if any.
    pub build: Option<String>,
}

/// Why a semantic version couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a semantic version: {0:?}")]
pub struct SemVerError(pub String);

impl SemVer {
    /// Parses `major.minor.patch[-pre][+build]` (semver 2.0.0).
    pub fn parse(text: &str) -> Result<Self, SemVerError> {
        let err = || SemVerError(text.to_owned());
        let (rest, build) = match text.split_once('+') {
            Some((r, b)) => (r, Some(b)),
            None => (text, None),
        };
        let (core, pre) = match rest.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (rest, None),
        };
        let parts: Vec<&str> = core.split('.').collect();
        let [major, minor, patch] = parts.as_slice() else { return Err(err()) };
        let ident_ok = |s: &str, numeric_rule: bool| {
            s.split('.').all(|id| {
                !id.is_empty()
                    && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    && !(numeric_rule && id.len() > 1 && id.starts_with('0') && id.bytes().all(|b| b.is_ascii_digit()))
            })
        };
        if pre.is_some_and(|p| !ident_ok(p, true)) || build.is_some_and(|b| !ident_ok(b, false)) {
            return Err(err());
        }
        Ok(Self {
            core: SchemaVersion { major: number(major).ok_or_else(err)?, minor: number(minor).ok_or_else(err)?, patch: number(patch).ok_or_else(err)? },
            pre: pre.map(str::to_owned),
            build: build.map(str::to_owned),
        })
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.core)?;
        if let Some(p) = &self.pre {
            write!(f, "-{p}")?;
        }
        if let Some(b) = &self.build {
            write!(f, "+{b}")?;
        }
        Ok(())
    }
}
