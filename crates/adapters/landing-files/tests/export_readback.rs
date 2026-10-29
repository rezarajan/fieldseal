//! The results export reads back to the same rows (INT-085, INT-088).

mod support;

use std::collections::BTreeMap;

use fieldseal_adapters_landing_files::export::codebook::codebook;
use fieldseal_adapters_landing_files::export::writers::jsonl_columns;
use fieldseal_adapters_landing_files::export::{ExportTable, IdentitySubject};
use fieldseal_intake::data_contract::{EXPORT_SCHEMA_VERSION, LONG_COLUMNS, TYPED_VALUE_COLUMNS};
use fieldseal_intake::domain::{ObservedValue, Reading};
use support::*;

type Rowmap = BTreeMap<String, String>;

/// A JSON Lines row as the cells a CSV would hold.
fn json_cells(j: &J) -> Rowmap {
    j.keys().into_iter().map(|k| (k.to_owned(), j.get(k).cell())).collect()
}

/// The typed column of a CSV row, as the CSV holds it in `value`.
fn typed_of(r: &Rowmap) -> (&'static str, String) {
    let column = match r["value_type"].as_str() {
        "integer" | "decimal" | "money" => "value_number",
        "code" | "evidence" => "value_text",
        "codes" => "value_codes",
        "boolean" => "value_bool",
        "date" => "value_date",
        _ => "",
    };
    (column, r["value"].clone())
}

fn by_key(mut rows: Vec<Rowmap>) -> Vec<Rowmap> {
    rows.sort_by(|a, b| (&a["record_id"], &a["item_path"]).cmp(&(&b["record_id"], &b["item_path"])));
    rows
}

fn read_both(dir: &std::path::Path) -> (Vec<Rowmap>, Vec<Rowmap>) {
    let json = by_key(jsonl_rows(&read(dir, "results.jsonl")).iter().map(json_cells).collect());
    let csv = by_key(csv_rows(&read(dir, "results.csv"), &["value"]));
    (json, csv)
}

// covers: INT-085
#[test]
fn int_085_jsonl_and_csv_read_back_to_the_same_rows() {
    let dir = export("readback", table_rows("s-1"));
    let (json, csv) = read_both(&dir);
    assert_eq!(json.len(), 14, "the excluded row is left out of the 15");
    assert_eq!(json.len(), csv.len());
    for (j, c) in json.iter().zip(&csv) {
        for col in LONG_COLUMNS.iter().map(|c| c.name).filter(|n| *n != "value") {
            assert_eq!(j[col], c[col], "{col} of {} {}", c["record_id"], c["item_path"]);
        }
        let (column, text) = typed_of(c);
        for typed in TYPED_VALUE_COLUMNS {
            let expected = if typed == column { text.clone() } else { String::new() };
            assert_eq!(j[typed], expected, "{typed} of {}", c["item_path"]);
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-085
#[test]
fn int_085_decimal_text_is_exact_and_money_keeps_currency_scale() {
    let dir = export("decimal", table_rows("s-1"));
    let (json, csv) = read_both(&dir);
    let get = |rows: &[Rowmap], item: &str| rows.iter().find(|r| r["item_path"] == item).expect("row").clone();
    assert_eq!(get(&json, "a.decimal")["value_number"], "0.1000000001", "no float rounds the decimal");
    assert_eq!(get(&csv, "a.decimal")["value"], "0.1000000001");
    assert_eq!(get(&json, "a.money")["value_number"], "12.50");
    assert_eq!(get(&json, "a.money")["unit"], "EUR");
    let raw = read(&dir, "results.jsonl");
    assert!(raw.contains("\"value_number\":\"12.50\""), "a number is text, never a JSON number\n{raw}");
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-085
#[test]
fn int_085_nonresponse_and_retraction_rows_have_null_typed_columns() {
    let dir = export("states", table_rows("s-1"));
    let rows = jsonl_rows(&read(&dir, "results.jsonl"));
    for item in ["b.dont_know", "b.refused", "b.not_applicable", "b.retracted"] {
        let r = rows.iter().find(|r| r.get("item_path") == &J::Str(item.into())).expect("row");
        for typed in TYPED_VALUE_COLUMNS {
            assert_eq!(r.get(typed), &J::Null, "{typed} of {item}");
        }
    }
    let nr = |item: &str| rows.iter().find(|r| r.get("item_path") == &J::Str(item.into())).expect("row");
    assert_eq!(nr("b.dont_know").get("nonresponse"), &J::Str("dont-know".into()));
    assert_eq!(nr("b.retracted").get("retracted"), &J::Bool(true));
    assert_eq!(nr("b.retracted").get("nonresponse"), &J::Null);
    assert_eq!(nr("a.integer").get("retracted"), &J::Bool(false));
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-085
#[test]
fn int_085_an_empty_csv_cell_equals_a_json_null() {
    let dir = export("null", table_rows("s-1"));
    let (json, csv) = read_both(&dir);
    let item = |rows: &[Rowmap]| rows.iter().find(|r| r["item_path"] == "b.refused").expect("row").clone();
    let (j, c) = (item(&json), item(&csv));
    assert_eq!(j["value_text"], "");
    assert_eq!(c["value"], "");
    assert_eq!(c["unit"], "");
    assert_eq!(j["unit"], "");
    let raw = read(&dir, "results.jsonl");
    assert!(raw.contains("\"unit\":null"), "a JSON null for a missing unit");
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-088
#[test]
fn int_088_free_text_is_joined_back_by_record_and_item() {
    let dir = export("free", table_rows("s-1"));
    let free_json = jsonl_rows(&read(&dir, "free_text.jsonl"));
    let free_csv = csv_rows(&read(&dir, "free_text.csv"), &["value_text"]);
    assert_eq!(free_json.len(), 1, "one free-text answer; the refused string has no text");
    assert_eq!(free_csv.len(), 1);
    assert_eq!(free_json[0].keys(), ["record_id", "item_path", "value_text"]);
    assert_eq!(free_json[0].get("value_text").cell(), "walks to the well, twice a day");
    assert_eq!(free_csv[0]["value_text"], "walks to the well, twice a day");
    let main = jsonl_rows(&read(&dir, "results.jsonl"));
    let joined = main.iter().find(|r| r.get("record_id") == free_json[0].get("record_id") && r.get("item_path") == free_json[0].get("item_path"));
    assert!(joined.is_some(), "the main table keeps the row that the text joins to");
    assert!(!read(&dir, "results.jsonl").contains("well, twice"), "no free text reaches the results file");
    assert!(!read(&dir, "results.csv").contains("well, twice"));
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-085
#[test]
fn int_085_numbers_are_never_prefixed_and_text_starting_with_a_formula_character_is() {
    let mut rows = table_rows("s-1");
    rows.push(value(5, "e.decimal", "decimal", ObservedValue::Decimal("-0.5".into())));
    rows.push(value(5, "e.code", "code", ObservedValue::Code("=SUM(A1)".into())));
    rows.push(value(5, "e.codes", "codes", ObservedValue::Codes(vec!["+a".into(), "b".into()])));
    rows.push(value(5, "e.evidence", "evidence", ObservedValue::Text("@evidence".into())));
    rows.push(value(5, "e.fine", "code", ObservedValue::Code("'quoted".into())));
    rows.push(value(5, "e.tab", "code", ObservedValue::Code("\t=1+1".into())));
    rows.push(value(5, "e.cr", "code", ObservedValue::Code("\r=1+1".into())));
    let dir = export("guard", rows);
    let csv = csv_rows(&read(&dir, "results.csv"), &[]);
    let cell = |item: &str| csv.iter().find(|r| r["item_path"] == item).expect("row")["value"].clone();
    assert_eq!(cell("a.integer"), "-5", "an integer is never prefixed");
    assert_eq!(cell("e.decimal"), "-0.5", "a decimal is never prefixed");
    assert_eq!(cell("e.code"), "'=SUM(A1)");
    assert_eq!(cell("e.codes"), "'+a|b");
    assert_eq!(cell("e.evidence"), "'@evidence");
    assert_eq!(cell("e.fine"), "'quoted", "text that starts with a quote is not changed");
    assert_eq!(cell("e.tab"), "'\t=1+1", "a leading tab is guarded");
    assert_eq!(cell("e.cr"), "'\r=1+1", "a leading carriage return is guarded");
    let json = jsonl_rows(&read(&dir, "results.jsonl"));
    let text = |item: &str| json.iter().find(|r| r.get("item_path") == &J::Str(item.into())).expect("row").get("value_text").cell();
    assert_eq!(text("e.code"), "=SUM(A1)", "JSON Lines is never guarded");
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-085
#[test]
fn int_085_the_guard_covers_free_text_csv_and_the_codebook() {
    let mut rows = table_rows("s-1");
    rows.push(value(5, "f.free", "string", ObservedValue::Text("=HYPERLINK(\"x\")".into())));
    let mut contract = contract();
    contract.items[0].labels.insert("en".into(), "-first label".into());
    contract.items[0].unit = Some("=unit".into());
    let table = ExportTable::from_observations(rows, BTreeMap::from([(fingerprint(), contract.clone())]), &IdentitySubject)
        .expect("table")
        .with_publications(BTreeMap::from([(fingerprint(), fieldseal_kernel::id::ContentAddress::from([1; 32]))]), []);
    let dir = scratch("guard-free");
    fieldseal_adapters_landing_files::export::write_export(&table, &both(), &dir).expect("export");
    let free = read(&dir, "free_text.csv");
    assert!(free.contains("\"'=HYPERLINK(\"\"x\"\")\""), "the guarded text is quoted as CSV needs\n{free}");
    let book = csv_rows(&read(&dir, "codebook.csv"), &[]);
    let first = book.iter().find(|r| r["item_path"] == contract.items[0].path && r["lang"] == "en" && r["code"].is_empty()).expect("the item row");
    assert_eq!(first["item_label"], "'-first label");
    assert_eq!(first["unit"], "'=unit");
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-085
#[test]
fn int_085_rows_have_a_total_order_even_when_the_listed_keys_are_equal() {
    let rows = |flip: bool| {
        let mut a = value(1, "a.code", "code", ObservedValue::Code("x".into()));
        let mut b = value(1, "a.code", "code", ObservedValue::Code("y".into()));
        a.observation.generation = fieldseal_kernel::id::Generation(1);
        b.observation.generation = fieldseal_kernel::id::Generation(2);
        if flip { vec![b, a] } else { vec![a, b] }
    };
    let (one, two) = (export("order-a", rows(false)), export("order-b", rows(true)));
    for name in ["results.jsonl", "results.csv", "manifest.json"] {
        assert_eq!(read(&one, name), read(&two, name), "{name} does not depend on the order rows arrived in");
    }
    let _ = (std::fs::remove_dir_all(one), std::fs::remove_dir_all(two));
}

// covers: INT-085
#[test]
fn int_085_the_manifest_records_the_landing_mark() {
    let dir = export("mark", table_rows("s-1"));
    let manifest = parse_json(&read(&dir, "manifest.json"));
    assert_eq!(manifest.get("landing_mark"), &J::Num("15".into()), "the mark counts excluded rows");
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-085
#[test]
fn int_085_codebook_is_rendered_from_the_contract() {
    let dir = export("codebook", table_rows("s-1"));
    let book = read(&dir, "codebook.csv");
    assert_eq!(book, codebook(&contract()), "the file is the function's output for the contract");
    assert!(book.starts_with("instrument,item_path,lang,item_label,code,code_label,value_type,unit,sensitivity,free_text\n"));
    let c = contract();
    let rows = csv_rows(&book, &[]);
    for item in &c.items {
        for lang in &c.languages {
            assert!(rows.iter().any(|r| r["item_path"] == item.path && &r["lang"] == lang && r["code"].is_empty()), "{} {lang}", item.path);
        }
    }
    let coded = c.items.iter().find(|i| i.code_list.is_some()).expect("the survey has a coded item");
    let list = c.code_lists.iter().find(|l| Some(&l.id) == coded.code_list.as_ref()).expect("its list");
    assert!(rows.iter().any(|r| r["item_path"] == coded.path && r["code"] == list.codes[0].code), "a row per code");
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-085
#[test]
fn int_085_manifest_digests_match_the_files() {
    let out = scratch("digests");
    let result = fieldseal_adapters_landing_files::export::write_export(&table(table_rows("s-1"), &IdentitySubject), &both(), &out).expect("export");
    let manifest = parse_json(&read(&out, "manifest.json"));
    let J::Arr(files) = manifest.get("files") else { panic!("files is a list") };
    let names: Vec<String> = files.iter().map(|f| f.get("name").cell()).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "files are ascending by name");
    assert!(!names.iter().any(|n| n == "manifest.json"), "the manifest does not list itself");
    assert!(names.contains(&"results.jsonl".to_owned()) && names.contains(&"codebook.csv".to_owned()));
    for f in files {
        let bytes = std::fs::read(out.join(f.get("name").cell())).expect("file");
        assert_eq!(f.get("sha256").cell(), fieldseal_kernel::digest::lower_hex(fieldseal_kernel::digest::sha256(&bytes).as_bytes()));
        assert_eq!(f.get("bytes").cell(), bytes.len().to_string());
    }
    let results = files.iter().find(|f| f.get("name") == &J::Str("results.jsonl".into())).expect("results.jsonl");
    assert_eq!(results.get("rows"), &J::Num("14".into()));
    let manifest_bytes = std::fs::read(out.join("manifest.json")).expect("manifest");
    assert_eq!(result.manifest_sha256, fieldseal_kernel::digest::lower_hex(fieldseal_kernel::digest::sha256(&manifest_bytes).as_bytes()), "the printed digest is the manifest's");
    let _ = std::fs::remove_dir_all(out);
}

// covers: INT-085
#[test]
fn int_085_export_schema_version_is_in_manifest_and_contract() {
    let dir = export("version", table_rows("s-1"));
    let manifest = parse_json(&read(&dir, "manifest.json"));
    assert_eq!(manifest.get("export_schema_version"), &J::Str(EXPORT_SCHEMA_VERSION.into()));
    let name = format!("contracts/{}.json", "ab".repeat(32));
    let contract = parse_json(&read(&dir, &name));
    assert_eq!(contract.get("exportSchemaVersion"), &J::Str(EXPORT_SCHEMA_VERSION.into()));
    let J::Arr(items) = contract.get("items") else { panic!("items") };
    assert!(items.iter().all(|i| matches!(i.get("free_text"), J::Bool(_))), "every item says whether it is free text");
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-085
#[test]
fn int_085_rows_are_sorted_by_instrument_tenancy_seq_record_and_item() {
    let mut rows = Vec::new();
    for (record, seq, tenancy, item) in [(3u8, 10u64, 7u8, "z.b"), (2, 2, 7, "z.b"), (9, 2, 7, "a.a"), (1, 2, 8, "a.a"), (1, 2, 7, "z.b"), (1, 2, 7, "a.a")] {
        let mut r = value(record, item, "integer", ObservedValue::Int(1));
        r.observation.seq = fieldseal_kernel::id::Seq(seq);
        r.observation.tenancy = fieldseal_kernel::id::TenancyId::from([tenancy; 32]);
        rows.push(r);
    }
    let dir = export("sorted", rows);
    let got: Vec<(String, u64, String, String)> = jsonl_rows(&read(&dir, "results.jsonl"))
        .iter()
        .map(|r| (r.get("tenancy").cell()[..2].to_owned(), r.get("seq").cell().parse().expect("seq"), r.get("record_id").cell()[..2].to_owned(), r.get("item_path").cell()))
        .collect();
    let want: Vec<(String, u64, String, String)> = [(7u8, 2u64, 1u8, "a.a"), (7, 2, 1, "z.b"), (7, 2, 2, "z.b"), (7, 2, 9, "a.a"), (7, 10, 3, "z.b"), (8, 2, 1, "a.a")]
        .iter()
        .map(|(t, s, r, i)| (format!("{t:02x}"), *s, format!("{r:02x}"), (*i).to_owned()))
        .collect();
    assert_eq!(got, want, "seq 10 sorts after seq 2: it is an integer, not text");
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-085
#[test]
fn int_085_json_lines_are_compact_with_column_order_keys() {
    let dir = export("compact", table_rows("s-1"));
    let raw = read(&dir, "results.jsonl");
    assert!(raw.ends_with('\n') && !raw.contains("\n\n"));
    for line in raw.lines() {
        assert!(!line.contains(": ") && !line.contains(", "), "no spaces outside strings: {line}");
        assert_eq!(parse_json(line).keys(), jsonl_columns());
    }
    let wanted: Vec<&str> = LONG_COLUMNS.iter().flat_map(|c| if c.name == "value" { TYPED_VALUE_COLUMNS.to_vec() } else { vec![c.name] }).collect();
    assert_eq!(jsonl_columns(), wanted, "the LONG_COLUMNS order with `value` replaced by the typed columns");
    let csv = read(&dir, "results.csv");
    assert_eq!(csv.lines().next().expect("header"), LONG_COLUMNS.iter().map(|c| c.name).collect::<Vec<_>>().join(","), "the CSV header is LONG_COLUMNS");
    assert!(!csv.contains('\r') && !csv.starts_with('\u{feff}'));
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-085
#[test]
fn int_085_manifest_and_contract_keys_are_sorted() {
    fn sorted(j: &J) {
        match j {
            J::Obj(o) => {
                let keys: Vec<&String> = o.iter().map(|(k, _)| k).collect();
                let mut want = keys.clone();
                want.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
                assert_eq!(keys, want);
                o.iter().for_each(|(_, v)| sorted(v));
            }
            J::Arr(a) => a.iter().for_each(sorted),
            _ => {}
        }
    }
    let dir = export("keys", table_rows("s-1"));
    let manifest = read(&dir, "manifest.json");
    assert!(manifest.ends_with("}\n") && !manifest.ends_with("\n\n"), "one line end");
    sorted(&parse_json(&manifest));
    sorted(&parse_json(&read(&dir, &format!("contracts/{}.json", "ab".repeat(32)))));
    let parsed = parse_json(&manifest);
    let J::Arr(layouts) = parsed.get("layouts") else { panic!("layouts") };
    assert_eq!(layouts.len(), 2, "layouts are listed once each, ascending");
    assert!(layouts[0].cell() < layouts[1].cell());
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-088
#[test]
fn int_088_a_free_text_item_has_a_null_value_and_null_typed_columns_in_both_formats() {
    let dir = export("free-null", table_rows("s-1"));
    let json = jsonl_rows(&read(&dir, "results.jsonl"));
    let r = json.iter().find(|r| r.get("item_path") == &J::Str("a.string".into())).expect("the free-text row stays in the main table");
    for typed in TYPED_VALUE_COLUMNS {
        assert_eq!(r.get(typed), &J::Null, "{typed}");
    }
    assert_eq!(r.get("value_type"), &J::Str("string".into()));
    assert_eq!(r.get("nonresponse"), &J::Null);
    assert_eq!(r.get("retracted"), &J::Bool(false));
    let csv = csv_rows(&read(&dir, "results.csv"), &[]);
    let c = csv.iter().find(|r| r["item_path"] == "a.string").expect("row");
    assert_eq!(c["value"], "");
    let _ = (std::fs::remove_dir_all(dir), Reading::Retracted);
}
