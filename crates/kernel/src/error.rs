//! Errors raised by the kernel: invariant failures when constructing value types
//! ([`KernelError`]) and wire-format failures carrying a WIRE §6.8 code ([`WireError`]).

/// A value failed a kernel-level invariant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KernelError {
    /// A byte string had the wrong length for its type.
    #[error("{kind}: expected {expected} bytes, got {actual}")]
    Length {
        /// The type being constructed.
        kind: &'static str,
        /// The required length.
        expected: usize,
        /// The length supplied.
        actual: usize,
    },
    /// A textual value was empty or malformed.
    #[error("{kind}: {reason}")]
    Malformed {
        /// The type being constructed.
        kind: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },
}

/// The error codes of WIRE §6.8. Every wire-level failure carries exactly one (WIRE-161).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// A frame or section does not start with the expected magic, or its fixed fields are invalid.
    FrameMagic,
    /// A frame or section length is impossible or runs past the input.
    FrameLength,
    /// A frame or section body does not match its CRC-32C.
    Crc,
    /// The input is not RFC 8949 core deterministic CBOR, is not well formed, or uses a
    /// construct the data model excludes (floats, null, simple values, non-text keys,
    /// invalid UTF-8, non-NFC text, out-of-range integers).
    CborNoncanonical,
    /// A map contains the same key twice.
    CborDuplicate,
    /// A CBOR tag other than 4 (decimal fraction).
    CborTag,
    /// A map key not defined for the structure's version, or a required key missing or of
    /// the wrong type.
    UnknownField,
    /// A limit of WIRE §6.7 is exceeded.
    Size,
    /// An unknown structure version.
    Version,
    /// A wrong or unknown domain tag.
    Tag,
    /// A signature is invalid, high-`s`, or its signer is not trusted.
    Sig,
    /// A sealing suite the recipient does not expect.
    Suite,
    /// A seal addressed to another recipient.
    Recipient,
    /// HPKE decapsulation or AEAD decryption failed.
    Decrypt,
    /// The hash chain is broken, or a record follows a closing record.
    Chain,
    /// A sequence number is missing, repeated or out of order.
    Seq,
    /// A tick is not monotonic.
    Tick,
    /// Export sections are missing or out of order.
    ExportSection,
    /// Damage exceeds what the parity can repair.
    Parity,
    /// A stated hash does not match the content.
    Hash,
}

impl ErrorCode {
    /// Every code, in the order of WIRE §6.8.
    pub const ALL: [ErrorCode; 20] = [
        ErrorCode::FrameMagic,
        ErrorCode::FrameLength,
        ErrorCode::Crc,
        ErrorCode::CborNoncanonical,
        ErrorCode::CborDuplicate,
        ErrorCode::CborTag,
        ErrorCode::UnknownField,
        ErrorCode::Size,
        ErrorCode::Version,
        ErrorCode::Tag,
        ErrorCode::Sig,
        ErrorCode::Suite,
        ErrorCode::Recipient,
        ErrorCode::Decrypt,
        ErrorCode::Chain,
        ErrorCode::Seq,
        ErrorCode::Tick,
        ErrorCode::ExportSection,
        ErrorCode::Parity,
        ErrorCode::Hash,
    ];

    /// The code as written in the spec, for example `E_CBOR_NONCANONICAL`.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::FrameMagic => "E_FRAME_MAGIC",
            ErrorCode::FrameLength => "E_FRAME_LENGTH",
            ErrorCode::Crc => "E_CRC",
            ErrorCode::CborNoncanonical => "E_CBOR_NONCANONICAL",
            ErrorCode::CborDuplicate => "E_CBOR_DUPLICATE",
            ErrorCode::CborTag => "E_CBOR_TAG",
            ErrorCode::UnknownField => "E_UNKNOWN_FIELD",
            ErrorCode::Size => "E_SIZE",
            ErrorCode::Version => "E_VERSION",
            ErrorCode::Tag => "E_TAG",
            ErrorCode::Sig => "E_SIG",
            ErrorCode::Suite => "E_SUITE",
            ErrorCode::Recipient => "E_RECIPIENT",
            ErrorCode::Decrypt => "E_DECRYPT",
            ErrorCode::Chain => "E_CHAIN",
            ErrorCode::Seq => "E_SEQ",
            ErrorCode::Tick => "E_TICK",
            ErrorCode::ExportSection => "E_EXPORT_SECTION",
            ErrorCode::Parity => "E_PARITY",
            ErrorCode::Hash => "E_HASH",
        }
    }

    /// Parses a code written as in the spec.
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == text)
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A wire-format failure: one code and the byte offset where it was found (WIRE-161).
///
/// For checks above the byte level (a signature, a chain link, a missing field) the offset is
/// that of the object being checked within the input the caller passed, usually 0.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code} at byte {offset}: {detail}")]
pub struct WireError {
    /// The spec's error code.
    pub code: ErrorCode,
    /// Byte offset into the input.
    pub offset: usize,
    /// A short human-readable explanation; not part of the contract.
    pub detail: &'static str,
}

impl WireError {
    /// A failure with the given code, offset and explanation.
    pub const fn new(code: ErrorCode, offset: usize, detail: &'static str) -> Self {
        Self { code, offset, detail }
    }

    /// The same failure, with its offset moved forward by `base` (for errors found inside a
    /// nested object).
    pub const fn shifted(mut self, base: usize) -> Self {
        self.offset += base;
        self
    }
}
