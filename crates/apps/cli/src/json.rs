//! JSON output (RFC 8259) of canonical values.
//!
//! The mapping is fixed and locale-independent (CLI-011b): maps are objects with keys in
//! sorted order, decimals are JSON numbers with every written digit (`1.10`), byte strings
//! are lowercase hexadecimal text, and text is escaped minimally (`"`, `\` and control
//! characters).

use fieldseal_kernel::Value;

/// `v` as compact JSON.
pub fn compact(v: &Value) -> String {
    let mut out = String::new();
    write(v, None, 0, &mut out);
    out
}

/// `v` as JSON indented by two spaces.
pub fn pretty(v: &Value) -> String {
    let mut out = String::new();
    write(v, Some(2), 0, &mut out);
    out
}

fn newline(indent: Option<usize>, depth: usize, out: &mut String) {
    if let Some(n) = indent {
        out.push('\n');
        out.push_str(&" ".repeat(n * depth));
    }
}

fn write(v: &Value, indent: Option<usize>, depth: usize, out: &mut String) {
    match v {
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::Decimal(d) => out.push_str(&d.to_string()),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Text(t) => string(t, out),
        Value::Bytes(b) => string(&fieldseal_kernel::digest::lower_hex(b), out),
        Value::Array(a) if a.is_empty() => out.push_str("[]"),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(indent, depth + 1, out);
                write(x, indent, depth + 1, out);
            }
            newline(indent, depth, out);
            out.push(']');
        }
        Value::Map(m) if m.is_empty() => out.push_str("{}"),
        Value::Map(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(indent, depth + 1, out);
                string(k, out);
                out.push(':');
                if indent.is_some() {
                    out.push(' ');
                }
                write(x, indent, depth + 1, out);
            }
            newline(indent, depth, out);
            out.push('}');
        }
    }
}

fn string(s: &str, out: &mut String) {
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
