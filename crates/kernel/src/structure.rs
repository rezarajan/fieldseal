//! Reading typed structures out of decoded [`Value`]s (WIRE-005).
//!
//! A structure decoder takes each field it defines and then calls [`Fields::finish`], which
//! rejects any key left over with `E_UNKNOWN_FIELD`. A required field that is missing or has
//! the wrong type is also `E_UNKNOWN_FIELD`: the map is not the structure the version defines.

use std::collections::BTreeMap;

use crate::error::{ErrorCode, WireError};
use crate::value::Value;

/// The fields of a map being read as a structure.
#[derive(Debug)]
pub struct Fields(BTreeMap<String, Value>);

fn field_error(detail: &'static str) -> WireError {
    WireError::new(ErrorCode::UnknownField, 0, detail)
}

impl Fields {
    /// Starts reading a map.
    pub fn new(value: Value) -> Result<Self, WireError> {
        match value {
            Value::Map(m) => Ok(Self(m)),
            _ => Err(field_error("structure is not a map")),
        }
    }

    /// Removes an optional field.
    pub fn take_opt(&mut self, key: &str) -> Option<Value> {
        self.0.remove(key)
    }

    /// Removes a required field.
    pub fn take(&mut self, key: &str) -> Result<Value, WireError> {
        self.0.remove(key).ok_or(field_error("required field missing"))
    }

    /// A required text field.
    pub fn text(&mut self, key: &str) -> Result<String, WireError> {
        match self.take(key)? {
            Value::Text(t) => Ok(t),
            _ => Err(field_error("field is not text")),
        }
    }

    /// A required byte-string field.
    pub fn bytes(&mut self, key: &str) -> Result<Vec<u8>, WireError> {
        expect_bytes(self.take(key)?)
    }

    /// A required byte-string field of exactly `N` bytes.
    pub fn bytes_n<const N: usize>(&mut self, key: &str) -> Result<[u8; N], WireError> {
        expect_bytes_n(self.take(key)?)
    }

    /// A required unsigned integer field.
    pub fn uint(&mut self, key: &str) -> Result<u64, WireError> {
        expect_uint(self.take(key)?)
    }

    /// A required boolean field.
    pub fn bool(&mut self, key: &str) -> Result<bool, WireError> {
        match self.take(key)? {
            Value::Bool(b) => Ok(b),
            _ => Err(field_error("field is not a boolean")),
        }
    }

    /// A required array field.
    pub fn array(&mut self, key: &str) -> Result<Vec<Value>, WireError> {
        match self.take(key)? {
            Value::Array(a) => Ok(a),
            _ => Err(field_error("field is not an array")),
        }
    }

    /// Requires the field to be the exact value `expected` (a fixed version or constant);
    /// any other value is `E_VERSION`.
    pub fn version(&mut self, key: &str, expected: &Value) -> Result<(), WireError> {
        if &self.take(key)? == expected {
            Ok(())
        } else {
            Err(WireError::new(ErrorCode::Version, 0, "unknown structure version"))
        }
    }

    /// Finishes reading: any field not taken is unknown (WIRE-005).
    pub fn finish(self) -> Result<(), WireError> {
        if self.0.is_empty() { Ok(()) } else { Err(field_error("field not defined for this version")) }
    }
}

/// A byte string.
pub fn expect_bytes(value: Value) -> Result<Vec<u8>, WireError> {
    match value {
        Value::Bytes(b) => Ok(b),
        _ => Err(field_error("field is not a byte string")),
    }
}

/// A byte string of exactly `N` bytes.
pub fn expect_bytes_n<const N: usize>(value: Value) -> Result<[u8; N], WireError> {
    expect_bytes(value)?.try_into().map_err(|_| field_error("byte string has the wrong length"))
}

/// An unsigned integer that fits 64 bits.
pub fn expect_uint(value: Value) -> Result<u64, WireError> {
    match value {
        Value::Int(i) => u64::try_from(i).map_err(|_| field_error("field is not an unsigned integer")),
        _ => Err(field_error("field is not an unsigned integer")),
    }
}
