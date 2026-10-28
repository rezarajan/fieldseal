//! JSON text of canonical values (the mapping of CLI-011b), and JSON text back into values.

use fieldseal_adapters_authoring::{AuthoringError, Format, decode};
use fieldseal_kernel::Value;

/// `v` as compact JSON: maps with sorted keys, decimals with every written digit, byte
/// strings as lowercase hexadecimal text.
pub fn to_json(v: &Value) -> String {
    let mut out = String::new();
    write(v, &mut out);
    out
}

/// Parses JSON text with the strict authoring decoder (no null, no floats, NFC text).
pub fn from_json(text: &str) -> Result<Value, AuthoringError> {
    decode(text.as_bytes(), Format::Json)
}

fn write(v: &Value, out: &mut String) {
    match v {
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::Decimal(d) => out.push_str(&d.to_string()),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Text(t) => string(t, out),
        Value::Bytes(b) => string(&fieldseal_kernel::digest::lower_hex(b), out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(x, out);
            }
            out.push(']');
        }
        Value::Map(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(k, out);
                out.push(':');
                write(x, out);
            }
            out.push('}');
        }
    }
}

/// A JSON string literal.
pub fn string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A JSON string literal as an owned string.
pub fn quote(s: &str) -> String {
    let mut out = String::new();
    string(s, &mut out);
    out
}
