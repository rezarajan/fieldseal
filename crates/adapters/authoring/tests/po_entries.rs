//! Catalogue entries keep their `msgid` and their line (INS-259, INS-260).

use fieldseal_adapters_authoring::compact;
use fieldseal_adapters_authoring::po::{ContextKind, check_context, parse_po};

const CATALOGUE: &str = r#"# Spanish.
msgid ""
msgstr "Language: es\n"

msgctxt "instrument/title"
msgid "Water at home"
msgstr "Agua en casa"

msgctxt "instrument/water"
msgid "Water"
msgstr ""

msgctxt "layout/compact/household"
msgid "The "
"household"
msgstr "El hogar\n"
"con \"comillas\" y \\"
"#;

#[test]
fn ins_259_parse_po_keeps_msgid_msgstr_and_line() {
    let entries = parse_po(CATALOGUE).expect("parses");
    assert_eq!(entries.len(), 3, "the header has no msgctxt and is left out");
    let first = &entries[0];
    assert_eq!((first.msgctxt.as_str(), first.msgid.as_str(), first.msgstr.as_str(), first.line), ("instrument/title", "Water at home", "Agua en casa", 5));
}

#[test]
fn ins_260_an_empty_msgstr_is_kept_and_counts_as_missing() {
    let entries = parse_po(CATALOGUE).expect("parses");
    let water = entries.iter().find(|e| e.msgctxt == "instrument/water").expect("kept");
    assert_eq!((water.msgid.as_str(), water.msgstr.as_str(), water.line), ("Water", "", 9));
}

#[test]
fn ins_259_a_repeated_msgctxt_is_rejected_with_the_second_line() {
    let text = "msgctxt \"instrument/title\"\nmsgid \"A\"\nmsgstr \"B\"\n\nmsgctxt \"instrument/title\"\nmsgid \"A\"\nmsgstr \"\"\n";
    let e = parse_po(text).expect_err("a repeat");
    assert_eq!(e.line, 5, "{e}");
}

#[test]
fn ins_259_multi_line_strings_and_escapes_round_trip() {
    let entries = parse_po(CATALOGUE).expect("parses");
    let household = entries.iter().find(|e| e.msgctxt == "layout/compact/household").expect("entry");
    assert_eq!(household.msgid, "The household");
    assert_eq!(household.msgstr, "El hogar\ncon \"comillas\" y \\");
}

#[test]
fn ins_259_parse_po_accepts_a_legacy_context() {
    let entries = parse_po("msgctxt \"lists.water-sources.borehole\"\nmsgid \"Borehole\"\nmsgstr \"Pozo\"\n").expect("parses");
    assert_eq!(entries[0].msgctxt, "lists.water-sources.borehole");
    assert!(check_context(&entries[0].msgctxt).is_err());
}

#[test]
fn ins_259_check_context_accepts_instrument_and_layout_contexts() {
    assert_eq!(check_context("instrument/title"), Ok(ContextKind::Instrument));
    assert_eq!(check_context("instrument/lists.water-sources.borehole"), Ok(ContextKind::Instrument));
    assert_eq!(check_context("layout/compact/who-lives-here"), Ok(ContextKind::Layout));
}

#[test]
fn ins_259_check_context_rejects_other_prefixes() {
    for bad in ["title", "steps.0.contents.1.card", "instrument/", "instrument/a..b", "instrument/a b", "layout/compact", "layout//id", "layout/compact/", "layout/compact/a/b", "layouts/compact/id"] {
        assert!(check_context(bad).is_err(), "{bad}");
    }
}

#[test]
fn ins_259_the_compact_adapter_keeps_the_old_map_and_drops_empty_msgstr() {
    let map = compact::parse_po(CATALOGUE).expect("parses");
    assert_eq!(map.len(), 2);
    assert_eq!(map.get("instrument/title").map(String::as_str), Some("Agua en casa"));
    assert!(!map.contains_key("instrument/water"));
}
