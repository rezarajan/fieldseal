//! Rules shared by the YAML and JSON decoders: number forms, text normalisation and limits.

use fieldseal_kernel::value::{Decimal, Value};
use unicode_normalization::is_nfc;

use crate::error::ErrorKind;

/// The deepest nesting of arrays and maps accepted.
pub(crate) const MAX_DEPTH: usize = 128;

/// A problem with a scalar, before it has a position.
pub(crate) type ScalarError = (ErrorKind, String);

/// Checks that text is in NFC (WIRE-004). Normalising silently would change what a reviewer sees,
/// so non-NFC text is refused.
pub(crate) fn check_nfc(text: &str) -> Result<(), ScalarError> {
    if is_nfc(text) {
        Ok(())
    } else {
        Err((
            ErrorKind::NotNfc,
            format!("text is not in Unicode Normalization Form C: {text:?}; re-enter it precomposed"),
        ))
    }
}

fn int_in_range(negative: bool, digits: &str) -> Result<Value, ScalarError> {
    let out_of_range = || (ErrorKind::Number, format!("integer {digits} is outside -2^64 ..= 2^64-1"));
    let magnitude: u128 = digits.parse().map_err(|_| out_of_range())?;
    if negative {
        if magnitude > 1u128 << 64 {
            return Err(out_of_range());
        }
        Ok(Value::Int(-i128::try_from(magnitude).map_err(|_| out_of_range())?))
    } else {
        if magnitude > u128::from(u64::MAX) {
            return Err(out_of_range());
        }
        Ok(Value::Int(i128::try_from(magnitude).map_err(|_| out_of_range())?))
    }
}

/// Reads a canonical number: `-?(0|[1-9][0-9]*)` as an integer, or the same followed by
/// `.[0-9]+` as a decimal that keeps every written digit.
pub(crate) fn canonical_number(text: &str) -> Result<Value, ScalarError> {
    let (negative, rest) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    if rest.contains('.') {
        Decimal::parse(text)
            .map(Value::Decimal)
            .map_err(|_| (ErrorKind::Number, format!("decimal {text} is too large")))
    } else {
        int_in_range(negative, rest)
    }
}

fn number_error(text: &str, why: &str) -> ScalarError {
    (ErrorKind::Number, format!("{text:?} is ambiguous: {why}; quote it to keep it as text"))
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Resolves a plain (unquoted) YAML scalar.
///
/// Only `true` and `false`, canonical integers (`-?(0|[1-9][0-9]*)`) and canonical decimals
/// (the same, then `.` and at least one digit) are not text. YAML 1.1 words (`yes`, `no`, `on`,
/// `off`, `y`, `n`) are text. Everything that looks like a number but is not canonical, and
/// everything that is null or a float, is an error instead of a guess.
pub(crate) fn resolve_plain(text: &str) -> Result<Value, ScalarError> {
    match text {
        "" | "~" | "null" | "Null" | "NULL" => {
            return Err((ErrorKind::Null, "null is not allowed; omit the field instead".into()));
        }
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        "True" | "TRUE" | "False" | "FALSE" => {
            return Err((
                ErrorKind::AmbiguousBoolean,
                format!("{text:?} is ambiguous; write true or false, or quote it"),
            ));
        }
        _ => {}
    }
    let (sign, rest) = match text.as_bytes().first() {
        Some(b'-' | b'+') => (text.as_bytes()[0] as char, &text[1..]),
        _ => ('\0', text),
    };
    let lower = rest.to_ascii_lowercase();
    if lower == ".inf" || lower == ".nan" {
        return Err((ErrorKind::Float, format!("{text:?} is a floating-point special value; floats are not allowed")));
    }
    let starts_numeric = rest.as_bytes().first().is_some_and(u8::is_ascii_digit)
        || (rest.starts_with('.') && rest.as_bytes().get(1).is_some_and(u8::is_ascii_digit));
    if !starts_numeric {
        return Ok(Value::Text(text.to_owned()));
    }

    // Radix prefixes: 0x1F, 0o17, 0b101.
    let rb = rest.as_bytes();
    if rb.len() > 2
        && rb[0] == b'0'
        && matches!(rb[1], b'x' | b'X' | b'o' | b'O' | b'b' | b'B')
        && rb[2..].iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        return Err(number_error(text, "hexadecimal, octal and binary integers are not allowed"));
    }

    // Plain digits.
    if is_digits(rest) {
        if sign == '+' {
            return Err(number_error(text, "a leading plus sign is not allowed"));
        }
        if rest.len() > 1 && rest.starts_with('0') {
            return Err(number_error(text, "a leading zero reads as octal in YAML 1.1"));
        }
        return canonical_number(text);
    }
    // Digits with separators: 1_000.
    if rest.bytes().all(|b| b.is_ascii_digit() || b == b'_' || b == b'.') && rest.contains('_') {
        return Err(number_error(text, "digit separators are not allowed"));
    }
    // Fractions: digits '.' digits.
    if let Some((whole, fraction)) = rest.split_once('.') {
        let whole_ok = whole.is_empty() || is_digits(whole);
        let fraction_ok = fraction.is_empty() || is_digits(fraction);
        if whole_ok && fraction_ok {
            if whole.is_empty() || fraction.is_empty() {
                return Err(number_error(text, "write digits on both sides of the point, as 0.5"));
            }
            if sign == '+' {
                return Err(number_error(text, "a leading plus sign is not allowed"));
            }
            if whole.len() > 1 && whole.starts_with('0') {
                return Err(number_error(text, "a leading zero is not allowed"));
            }
            return canonical_number(text);
        }
    }
    // Exponents: 1e3, 1.5E-2, 1.e3, .5e2.
    if let Some(pos) = rest.find(['e', 'E']) {
        let (mantissa, exponent) = (&rest[..pos], &rest[pos + 1..]);
        let exponent = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        let mantissa_ok = mantissa.split_once('.').map_or_else(
            || is_digits(mantissa),
            |(w, f)| (w.is_empty() || is_digits(w)) && (f.is_empty() || is_digits(f)) && !(w.is_empty() && f.is_empty()),
        );
        if mantissa_ok && is_digits(exponent) {
            return Err((
                ErrorKind::Float,
                format!("{text:?} uses exponent notation; write a plain decimal such as 1000 or 0.001"),
            ));
        }
    }
    // Dates, versions, times (2024-01-05, 1.0.0, 1:30) and the like are text.
    Ok(Value::Text(text.to_owned()))
}
