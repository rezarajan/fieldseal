//! `codebook.csv` and the free-text files of the results export.

use fieldseal_intake::data_contract::DataContract;
use fieldseal_kernel::Value;
use fieldseal_kernel::digest::lower_hex;

use super::FreeText;
use super::writers::{csv_field, guard, json};

/// A free-text answer as one JSON object.
pub(crate) fn free_text_jsonl(t: &FreeText) -> String {
    let text = |s: &str| json(&Value::Text(s.to_owned()));
    format!("{{\"record_id\":{},\"item_path\":{},\"value_text\":{}}}", text(&t.record_id), text(&t.item_path), text(&t.value_text))
}

/// The header of `free_text.csv`.
pub const FREE_TEXT_HEADER: &str = "record_id,item_path,value_text";

/// A free-text answer as a CSV line; the text is guarded (INT-085).
pub(crate) fn free_text_csv(t: &FreeText) -> String {
    [csv_field(&t.record_id), csv_field(&t.item_path), csv_field(&guard(&t.value_text))].join(",")
}

/// The header of `codebook.csv`. The first column names the instrument, because one export can
/// hold several and their item paths would otherwise be ambiguous.
pub const CODEBOOK_HEADER: &str = "instrument,item_path,lang,item_label,code,code_label,value_type,unit,sensitivity,free_text";

/// The rows of one contract's codebook: one per item and language, and one per code and
/// language of the item's code list. Every text cell is guarded.
pub(crate) fn codebook_rows(contract: &DataContract) -> Vec<String> {
    let instrument = lower_hex(contract.instrument.as_bytes());
    let line = |cells: [&str; 10]| cells.iter().map(|c| csv_field(&guard(c))).collect::<Vec<_>>().join(",");
    let mut rows = Vec::new();
    for item in &contract.items {
        let unit = item.unit.as_deref().unwrap_or("");
        let free = item.free_text.to_string();
        for lang in &contract.languages {
            let label = item.labels.get(lang).map_or("", String::as_str);
            rows.push(line([&instrument, &item.path, lang, label, "", "", item.value_type, unit, item.sensitivity, &free]));
            let list = item.code_list.as_ref().and_then(|id| contract.code_lists.iter().find(|l| &l.id == id));
            let codes = list.into_iter().flat_map(|l| l.codes.iter().map(|c| (c.code.as_str(), &c.labels)).chain(l.other.iter().map(|(code, labels)| (code.as_str(), labels))));
            for (code, labels) in codes {
                let code_label = labels.get(lang).map_or("", String::as_str);
                rows.push(line([&instrument, &item.path, lang, label, code, code_label, item.value_type, unit, item.sensitivity, &free]));
            }
        }
    }
    rows
}

/// `codebook.csv` for one data contract, rendered from the contract alone (INT-088).
pub fn codebook(contract: &DataContract) -> String {
    let mut out = String::from(CODEBOOK_HEADER);
    out.push('\n');
    for r in codebook_rows(contract) {
        out.push_str(&r);
        out.push('\n');
    }
    out
}
