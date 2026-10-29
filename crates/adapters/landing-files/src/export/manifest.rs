//! `manifest.json` of the results export (INT-085).

use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::{Value, cbor};

use super::writers::json;
use super::{ExportError, ExportTable, ExportedFile};

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// The manifest bytes: keys sorted, compact, one `\n` at the end. It lists the files but not
/// itself, and the instruments and layouts the published directory supplied, ascending.
pub(crate) fn manifest(table: &ExportTable, key_id: Option<String>, files: &[ExportedFile]) -> Result<Vec<u8>, ExportError> {
    let mut instruments = Vec::new();
    for fp in table.contracts.keys() {
        let address = table.instruments.get(fp).ok_or_else(|| ExportError::NoPublication(lower_hex(fp.as_bytes())))?;
        instruments.push((lower_hex(fp.as_bytes()), address.to_text()));
    }
    instruments.sort();
    let files = files
        .iter()
        .map(|f| {
            let mut e = vec![("name", text(&f.name)), ("sha256", text(&f.sha256)), ("bytes", Value::Int(i128::from(f.bytes)))];
            if let Some(rows) = f.rows {
                e.push(("rows", Value::Int(i128::from(rows))));
            }
            cbor::map(e)
        })
        .collect();
    let mut top = vec![
        ("export_schema_version", text(fieldseal_intake::data_contract::EXPORT_SCHEMA_VERSION)),
        ("landing_mark", Value::Int(i128::from(table.landing_mark))),
        ("instruments", Value::Array(instruments.iter().map(|(fp, a)| cbor::map([("fingerprint", text(fp)), ("address", text(a))])).collect())),
        ("layouts", Value::Array(table.layouts.iter().map(|a| text(a)).collect())),
        ("files", Value::Array(files)),
        ("rows_omitted_excluded", Value::Int(i128::from(table.omitted_excluded))),
    ];
    if let Some(id) = &key_id {
        top.push(("pseudonymisation_key_id", text(id)));
    }
    let mut out = json(&cbor::map(top));
    out.push('\n');
    Ok(out.into_bytes())
}
