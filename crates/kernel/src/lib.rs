//! Fieldseal's shared kernel (ADR 0004, ADR 0005).
//!
//! The value types every bounded context agrees on, and the format core that gives them
//! their bytes (`docs/reference/spec/wire-formats.md`): deterministic CBOR ([`cbor`]),
//! hashes and identifiers ([`digest`]), domain-tagged signatures ([`sign`]), HPKE seals
//! ([`seal`]), journal frames and the hash chain ([`frame`], [`record`]) and export files
//! with Reed–Solomon parity ([`export`], [`parity`]).
//!
//! This crate is the innermost ring of the clean architecture (ADR 0028): it depends on
//! nothing but pure libraries, performs no I/O, and reads no clock, randomness or
//! environment. Randomness is passed in by the caller.

pub mod base64url;
pub mod cbor;
pub mod crc;
pub mod crypto;
pub mod digest;
pub mod error;
pub mod export;
pub mod frame;
pub mod id;
pub mod local_record;
pub mod parity;
pub mod pop;
pub mod qr_sequence;
pub mod payload;
pub mod record;
pub mod seal;
pub mod sign;
pub mod structure;
pub mod text;
pub mod time;
pub mod value;
pub mod words;

pub use error::{ErrorCode, KernelError, WireError};
pub use value::{Decimal, Value};

/// The random-source trait the kernel's key generation and sealing take from their caller
/// (re-exported so callers need not depend on `rand_core` themselves).
pub use rand_core::CryptoRng;
