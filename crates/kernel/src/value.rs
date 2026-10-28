//! The canonical data model (WIRE §5.1): the values every Fieldseal structure is made of
//! before it is encoded as deterministic CBOR.
//!
//! Authoring adapters decode YAML or JSON into [`Value`]; contexts read their resources
//! from it; the format core encodes it (issue #42). There is no null and no floating
//! point (WIRE-006): non-integer numbers are [`Decimal`]s.

use std::collections::BTreeMap;
use std::fmt;

/// One canonical value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Value {
    /// A CBOR integer (major types 0 and 1): −2⁶⁴ ..= 2⁶⁴ − 1.
    Int(i128),
    /// A decimal fraction (CBOR tag 4).
    Decimal(Decimal),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A text string, NFC-normalised UTF-8 (WIRE-004).
    Text(String),
    /// A boolean.
    Bool(bool),
    /// An ordered array.
    Array(Vec<Value>),
    /// A map with text keys (WIRE-004). Key order here is irrelevant; the encoder sorts keys
    /// by the bytewise order of their encodings (WIRE-001).
    Map(BTreeMap<String, Value>),
}

impl Value {
    /// The text, if this is text.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The integer, if this is an integer.
    pub fn as_int(&self) -> Option<i128> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// The boolean, if this is a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The entries, if this is a map.
    pub fn as_map(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    /// A number as a decimal: integers are widened with exponent 0.
    pub fn as_decimal(&self) -> Option<Decimal> {
        match self {
            Value::Decimal(d) => Some(*d),
            Value::Int(i) => Some(Decimal { mantissa: *i, exponent: 0 }),
            _ => None,
        }
    }

    /// A short name of the value's kind, for error messages.
    pub fn kind(&self) -> &'static str {
        match self {
            Value::Int(_) => "integer",
            Value::Decimal(_) => "decimal",
            Value::Bytes(_) => "bytes",
            Value::Text(_) => "text",
            Value::Bool(_) => "boolean",
            Value::Array(_) => "array",
            Value::Map(_) => "map",
        }
    }
}

/// A decimal fraction `mantissa × 10^exponent` (RFC 8949 §3.4.4). Never a float.
///
/// Two decimals with different exponents are different encodings; each wire structure fixes
/// the exponent (scale) of its values (WIRE-006). [`Decimal::numeric_cmp`] compares values.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Decimal {
    /// The digits.
    pub mantissa: i128,
    /// The power of ten.
    pub exponent: i32,
}

/// Why a decimal couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a decimal number: {0:?}")]
pub struct DecimalError(pub String);

impl Decimal {
    /// Parses plain decimal notation (`-12`, `0.214`, `98.40`), keeping every written digit:
    /// `98.40` has exponent −2. Exponent notation, `NaN`, infinities and floats are refused.
    pub fn parse(text: &str) -> Result<Self, DecimalError> {
        let err = || DecimalError(text.to_owned());
        let (negative, digits) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let (whole, fraction) = digits.split_once('.').unwrap_or((digits, ""));
        if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
            return Err(err());
        }
        if digits.contains('.') && (fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit())) {
            return Err(err());
        }
        let mut mantissa: i128 = 0;
        for b in whole.bytes().chain(fraction.bytes()) {
            mantissa = mantissa
                .checked_mul(10)
                .and_then(|m| m.checked_add(i128::from(b - b'0')))
                .ok_or_else(err)?;
        }
        let exponent = -i32::try_from(fraction.len()).map_err(|_| err())?;
        Ok(Self { mantissa: if negative { -mantissa } else { mantissa }, exponent })
    }

    /// The same value at another exponent, if that loses no digits and doesn't overflow.
    pub fn rescale(self, exponent: i32) -> Option<Self> {
        let shift = self.exponent - exponent;
        let factor = 10i128.checked_pow(shift.unsigned_abs())?;
        let mantissa = if shift >= 0 {
            self.mantissa.checked_mul(factor)?
        } else if self.mantissa % factor == 0 {
            self.mantissa / factor
        } else {
            return None;
        };
        Some(Self { mantissa, exponent })
    }

    /// Compares the numeric values, whatever their exponents. `None` only on overflow.
    pub fn numeric_cmp(self, other: Self) -> Option<std::cmp::Ordering> {
        let exponent = self.exponent.min(other.exponent);
        Some(self.rescale(exponent)?.mantissa.cmp(&other.rescale(exponent)?.mantissa))
    }
}

impl fmt::Display for Decimal {
    /// Plain notation with exactly `-exponent` fraction digits (for negative exponents).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.exponent >= 0 {
            let factor = 10i128.checked_pow(self.exponent.unsigned_abs()).ok_or(fmt::Error)?;
            return write!(f, "{}", self.mantissa.checked_mul(factor).ok_or(fmt::Error)?);
        }
        let digits = self.mantissa.unsigned_abs().to_string();
        let scale = self.exponent.unsigned_abs() as usize;
        let padded = format!("{digits:0>width$}", width = scale + 1);
        let (whole, fraction) = padded.split_at(padded.len() - scale);
        let sign = if self.mantissa < 0 { "-" } else { "" };
        write!(f, "{sign}{whole}.{fraction}")
    }
}
