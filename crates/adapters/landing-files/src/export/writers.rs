//! The CSV and JSON writers: the long format of `observations.csv` and the results export.

use std::fmt::Write as _;

use fieldseal_intake::data_contract::{LONG_COLUMNS, TYPED_VALUE_COLUMNS};
use fieldseal_intake::domain::{LandedObservation, ObservedValue, Reading};
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::payload::Layout;
use fieldseal_kernel::Value;

use super::{Row, Typed};

/// Quotes a CSV field when it needs it (RFC 4180).
pub fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

/// Renders a value tree as JSON, keys in order, text escaped (RFC 8259). Bytes render as
/// lowercase hex; the data contract holds none.
pub fn json(v: &Value) -> String {
    let mut out = String::new();
    write_json(v, &mut out);
    out
}

fn write_json(v: &Value, out: &mut String) {
    match v {
        Value::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Value::Decimal(d) => out.push_str(&fieldseal_intake::data_contract::decimal_text(*d)),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Bytes(b) => write_json(&Value::Text(lower_hex(b)), out),
        Value::Text(t) => {
            out.push('"');
            for c in t.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(x, out);
            }
            out.push(']');
        }
        Value::Map(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(&Value::Text(k.clone()), out);
                out.push(':');
                write_json(x, out);
            }
            out.push('}');
        }
    }
}

/// The CSV header of the long format (INT §6, INT-071, INS-072).
pub fn long_header() -> String {
    LONG_COLUMNS.iter().map(|c| c.name).collect::<Vec<_>>().join(",")
}

/// One landed observation as a CSV line in the order of [`LONG_COLUMNS`].
pub fn long_row(r: &LandedObservation) -> String {
    let o = &r.observation;
    let (value, nonresponse, retracted) = match &o.reading {
        Reading::Value(v) => (
            match v {
                ObservedValue::Bool(b) => b.to_string(),
                ObservedValue::Int(i) => i.to_string(),
                ObservedValue::Decimal(t) | ObservedValue::Text(t) | ObservedValue::Code(t) => t.clone(),
                ObservedValue::Codes(c) => c.join("|"),
            },
            "",
            false,
        ),
        Reading::Nonresponse(n) => (String::new(), n.code(), false),
        Reading::Retracted => (String::new(), "", true),
    };
    let layout = match o.layout {
        Layout::Default => "default".to_owned(),
        Layout::Published(a) => lower_hex(a.as_bytes()),
    };
    let fields = [
        lower_hex(o.instrument.as_bytes()),
        layout,
        o.lang.join("|"),
        o.subject.as_str().to_owned(),
        o.item.as_str().to_owned(),
        value,
        o.value_type.to_owned(),
        nonresponse.to_owned(),
        retracted.to_string(),
        o.unit.clone().unwrap_or_default(),
        lower_hex(o.source.as_bytes()),
        lower_hex(o.tenancy.as_bytes()),
        o.generation.0.to_string(),
        o.seq.0.to_string(),
        o.not_before.map(|t| t.0.to_string()).unwrap_or_default(),
        o.not_after.0.to_string(),
        o.consent_basis.clone(),
        o.flags.iter().cloned().collect::<Vec<_>>().join("|"),
        r.excluded.is_some().to_string(),
        r.excluded.clone().unwrap_or_default(),
    ];
    fields.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(",")
}

/// The CSV formula guard (INT-085): text that a spreadsheet would run as a formula gets a `'`
/// in front.
pub fn guard(text: &str) -> String {
    if text.starts_with(['=', '+', '-', '@']) { format!("'{text}") } else { text.to_owned() }
}

/// One cell of a results row, before it is written as JSON or CSV.
enum Cell {
    Null,
    Text(String),
    Int(u64),
    Bool(bool),
    Array(Vec<String>),
}

fn some_text(t: &str) -> Cell {
    if t.is_empty() { Cell::Null } else { Cell::Text(t.to_owned()) }
}

fn cell(row: &Row, column: &str) -> Cell {
    let typed = |pick: fn(&Typed) -> Option<Cell>| pick(&row.typed).unwrap_or(Cell::Null);
    match column {
        "instrument" => Cell::Text(row.instrument.clone()),
        "layout" => Cell::Text(row.layout.clone()),
        "lang" => Cell::Array(row.lang.clone()),
        "subject" => Cell::Text(row.subject.clone()),
        "item_path" => Cell::Text(row.item_path.clone()),
        "value" => match &row.typed {
            Typed::None => Cell::Null,
            Typed::Number(t) | Typed::Text(t) | Typed::Date(t) => Cell::Text(t.clone()),
            Typed::Bool(b) => Cell::Text(b.to_string()),
            Typed::Codes(c) => Cell::Text(c.join("|")),
        },
        "value_number" => typed(|t| if let Typed::Number(n) = t { Some(Cell::Text(n.clone())) } else { None }),
        "value_text" => typed(|t| if let Typed::Text(n) = t { Some(Cell::Text(n.clone())) } else { None }),
        "value_date" => typed(|t| if let Typed::Date(n) = t { Some(Cell::Text(n.clone())) } else { None }),
        "value_bool" => typed(|t| if let Typed::Bool(b) = t { Some(Cell::Bool(*b)) } else { None }),
        "value_codes" => typed(|t| if let Typed::Codes(c) = t { Some(Cell::Array(c.clone())) } else { None }),
        "value_type" => Cell::Text(row.value_type.to_owned()),
        "nonresponse" => some_text(row.nonresponse),
        "retracted" => Cell::Bool(row.retracted),
        "unit" => row.unit.as_deref().map_or(Cell::Null, some_text),
        "record_id" => Cell::Text(row.record_id.clone()),
        "tenancy" => Cell::Text(row.tenancy.clone()),
        "generation" => Cell::Int(u64::from(row.generation)),
        "seq" => Cell::Int(row.seq),
        "tick_lower_bound" => row.tick_lower_bound.map_or(Cell::Null, Cell::Int),
        "received_at" => Cell::Int(row.received_at),
        "consent_basis" => Cell::Text(row.consent_basis.clone()),
        "flags" => Cell::Array(row.flags.clone()),
        // Excluded rows are left out of the results export (INT-086).
        "excluded" => Cell::Bool(false),
        "exclusion_reason" => Cell::Null,
        other => unreachable!("unknown long column {other}"),
    }
}

fn json_cell(c: &Cell) -> String {
    match c {
        Cell::Null => "null".to_owned(),
        Cell::Text(t) => json(&Value::Text(t.clone())),
        Cell::Int(i) => i.to_string(),
        Cell::Bool(b) => b.to_string(),
        Cell::Array(a) => format!("[{}]", a.iter().map(|t| json(&Value::Text(t.clone()))).collect::<Vec<_>>().join(",")),
    }
}

/// The columns of the JSON Lines results: [`LONG_COLUMNS`] with `value` replaced by the typed
/// value columns.
pub fn jsonl_columns() -> Vec<&'static str> {
    LONG_COLUMNS.iter().flat_map(|c| if c.name == "value" { TYPED_VALUE_COLUMNS.to_vec() } else { vec![c.name] }).collect()
}

/// A results row as one JSON object, keys in column order, without the line end.
pub(crate) fn jsonl_row(row: &Row) -> String {
    let fields: Vec<String> = jsonl_columns().iter().map(|c| format!("{}:{}", json(&Value::Text((*c).to_owned())), json_cell(&cell(row, c)))).collect();
    format!("{{{}}}", fields.join(","))
}

/// A results row as a CSV line over [`LONG_COLUMNS`]: arrays joined with `|`, null as an empty
/// cell, and `value` guarded unless the item is numeric (INT-085).
pub(crate) fn csv_row(row: &Row) -> String {
    let guarded = !matches!(row.value_type, "integer" | "decimal" | "money");
    LONG_COLUMNS
        .iter()
        .map(|c| {
            let text = match cell(row, c.name) {
                Cell::Null => String::new(),
                Cell::Text(t) if c.name == "value" && guarded => guard(&t),
                Cell::Text(t) => t,
                Cell::Int(i) => i.to_string(),
                Cell::Bool(b) => b.to_string(),
                Cell::Array(a) => a.join("|"),
            };
            csv_field(&text)
        })
        .collect::<Vec<_>>()
        .join(",")
}
