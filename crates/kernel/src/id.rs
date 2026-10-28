//! Identifiers. Every identifier is a distinct type, so one can't be passed where
//! another is expected.

use crate::KernelError;

/// Defines a fixed-length byte identifier with a checked constructor.
macro_rules! fixed_id {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Length in bytes.
            pub const LEN: usize = $len;

            /// Wraps exactly `LEN` bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, KernelError> {
                let array: [u8; $len] = bytes.try_into().map_err(|_| KernelError::Length {
                    kind: stringify!($name),
                    expected: $len,
                    actual: bytes.len(),
                })?;
                Ok(Self(array))
            }

            /// The raw bytes.
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($name), "("))?;
                for b in &self.0[..4.min($len)] {
                    write!(f, "{b:02x}")?;
                }
                write!(f, "…)")
            }
        }
    };
}

fixed_id!(
    /// A SHA-256 digest.
    Digest,
    32
);
fixed_id!(
    /// A key's identifier (`key-id`, WIRE-010, TRU-090): the first 16 bytes of SHA-256 over
    /// the encoded public key. See [`crate::digest::key_id`].
    KeyId,
    16
);
fixed_id!(
    /// An instrument version's salted fingerprint (ADR 0027).
    Fingerprint,
    32
);
fixed_id!(
    /// The content address of a published artefact.
    ContentAddress,
    32
);
fixed_id!(
    /// A tenancy's identifier: the SHA-256 of its signing public key.
    TenancyId,
    32
);
fixed_id!(
    /// The opaque handle that identifies a tenancy outside the sealed parts of an export.
    TenancyHandle,
    16
);
fixed_id!(
    /// A record's random identifier, used only for identity and deduplication.
    RecordId,
    16
);
fixed_id!(
    /// A fresh challenge value.
    Nonce,
    32
);
fixed_id!(
    /// A salt for an instrument fingerprint (ADR 0027).
    Salt,
    32
);

/// Defines a textual identifier that must be non-empty.
macro_rules! text_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
        pub struct $name(String);

        impl $name {
            /// Wraps a non-empty identifier.
            pub fn new(value: impl Into<String>) -> Result<Self, KernelError> {
                let value = value.into();
                if value.is_empty() {
                    return Err(KernelError::Malformed { kind: stringify!($name), reason: "empty" });
                }
                Ok(Self(value))
            }

            /// The identifier as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

text_id!(
    /// A subject's pseudonymous identifier, issued by the authority.
    SubjectId
);
text_id!(
    /// A cohort's identifier.
    CohortId
);
text_id!(
    /// A collection period's identifier.
    CollectionPeriodId
);
text_id!(
    /// A pseudonymous reviewer identifier (PUB-107).
    ReviewerId
);
text_id!(
    /// An opaque collector reference; the mapping to a person stays at the authority.
    CollectorRef
);

/// A path to an item inside an instrument, for example `body.weight`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ItemPath(String);

impl ItemPath {
    /// Accepts dot-separated segments of ASCII letters, digits, `-` and `_`.
    pub fn new(value: impl Into<String>) -> Result<Self, KernelError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.split('.').all(|seg| {
                !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            });
        if !valid {
            return Err(KernelError::Malformed { kind: "ItemPath", reason: "segments must be [A-Za-z0-9_-]+ separated by dots" });
        }
        Ok(Self(value))
    }

    /// The path as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A record's position in its tenancy's journal.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Seq(pub u64);

/// A tenancy's generation for a cohort, assigned by the authority.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Generation(pub u32);
