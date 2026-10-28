//! The instrument suites the spec's section 8 names: `ins-checks`, `ins-locale`,
//! `ins-codes`, `ins-nonresponse` and `ins-units`. Most checks are the instrument context's
//! own integration tests (kept as cargo tests in `crates/contexts/instrument/tests/`), copied
//! into the `ins_*` modules next to this file; the locale checks run the CLDR-backed
//! formatter directly. Each names the INS requirements it exercises.

use std::collections::BTreeMap;

use fieldseal_instrument::application::evaluate_rules;
use fieldseal_instrument::domain::evaluation::RecordInput;
use fieldseal_instrument::domain::locale::{LocaleFormatter, TESTED_LOCALES};
use fieldseal_instrument::domain::rules::Val;
use fieldseal_kernel::Decimal;

use super::harness::Check;
use super::ins_support::fixtures::clinic_visit;
use super::ins_support::{valid, values};
use super::Unit;
use super::{ins_clinic as clinic, ins_invalid as invalid, ins_render as render, ins_spec as spec};

fn d(s: &str) -> Decimal {
    Decimal::parse(s).expect("decimal")
}

/// INS-088: numbers use each locale's separators and native digits.
fn ins_088_numbers_use_each_locales_separators_and_digits() {
    let x = d("1234567.5");
    assert_eq!(LocaleFormatter::new("en").number(x), "1,234,567.5");
    assert_eq!(LocaleFormatter::new("es").number(x), "1.234.567,5");
    assert_eq!(LocaleFormatter::new("fr").number(x), "1\u{202f}234\u{202f}567,5");
    assert_eq!(LocaleFormatter::new("hi").number(x), "12,34,567.5");
    assert_eq!(LocaleFormatter::new("ar").number(x), "١٬٢٣٤٬٥٦٧٫٥");
    assert_eq!(LocaleFormatter::new("ar").input_number(d("1234.5")), "١٢٣٤٫٥");
    assert_eq!(LocaleFormatter::new("en").input_number(d("1234.5")), "1234.5");
}

/// INS-088: input accepts the locale's separators and native digits, and normalises them.
fn ins_088_input_accepts_separators_and_native_digits() {
    for (tag, text, want) in [
        ("en", "1,234.5", "1234.5"),
        ("es", "1.234,5", "1234.5"),
        ("fr", "1\u{202f}234,5", "1234.5"),
        ("hi", "12,34,567.5", "1234567.5"),
        ("ar", "١٢٣٤٫٥", "1234.5"),
        ("ar", "١٬٢٣٤٫٥", "1234.5"),
        ("ar", "\u{200f}-٣٫٥", "-3.5"),
        ("ar", "٠٫٠٥", "0.05"),
    ] {
        let got = LocaleFormatter::new(tag).parse_number(text);
        let want = d(want);
        assert_eq!(got.map(|g| (g.mantissa, g.exponent)), Ok((want.mantissa, want.exponent)), "{tag} {text}");
    }
    let en = LocaleFormatter::new("en");
    for bad in ["", "-", "1,5", "12,34", "1..2", "1.", ".5", "abc", "1e3", "1,2,3"] {
        assert!(en.parse_number(bad).is_err(), "{bad}");
    }
    assert!(LocaleFormatter::new("es").parse_number("1,234.5").is_err());
}

/// INS-088: what is displayed parses back to the same locale-independent value.
fn ins_088_display_then_parse_round_trips() {
    for tag in TESTED_LOCALES {
        let f = LocaleFormatter::new(tag);
        for v in ["0", "7", "-7.25", "1234567.891", "1000", "0.001"] {
            let x = d(v);
            for text in [f.number(x), f.input_number(x)] {
                let back = f.parse_number(&text).unwrap_or_else(|e| panic!("{tag} {text}: {e}"));
                assert_eq!(back.numeric_cmp(x), Some(std::cmp::Ordering::Equal), "{tag} {text}");
            }
        }
    }
}

/// INS-088: currencies round to the currency's minor digits; dates follow the locale; plural
/// categories come from CLDR.
fn ins_088_currencies_dates_and_plurals_follow_the_locale() {
    assert_eq!(LocaleFormatter::new("en").money(d("1234.5"), "EUR", 2), "EUR\u{a0}1,234.50");
    assert_eq!(LocaleFormatter::new("es").money(d("12345.5"), "EUR", 2), "12.345,50\u{a0}EUR");
    assert_eq!(LocaleFormatter::new("en").money(d("1500"), "JPY", 0), "JPY\u{a0}1,500");
    assert!(LocaleFormatter::new("ar").money(d("12.5"), "USD", 2).contains("١٢٫٥٠"));
    assert_eq!(LocaleFormatter::new("en").date("2026-10-27").as_deref(), Some("Oct 27, 2026"));
    assert_eq!(LocaleFormatter::new("es").date("2026-10-27").as_deref(), Some("27 oct 2026"));
    assert_eq!(LocaleFormatter::new("en").date("2026-02-30"), None);
    let cat = |tag: &str, n: &str| LocaleFormatter::new(tag).plural(d(n)).name();
    assert_eq!((cat("en", "1"), cat("en", "2"), cat("en", "0")), ("one", "other", "other"));
    assert_eq!((cat("fr", "0"), cat("fr", "1"), cat("fr", "2")), ("one", "one", "other"));
    assert_eq!((cat("es", "1"), cat("es", "1000000"), cat("es", "2")), ("one", "many", "other"));
}

/// INS-143 and INS-141: a nonresponse is not encoded as a number, sentinel or empty value:
/// the evaluation holds no value for the item, and holds the nonresponse code beside it.
fn ins_143_a_nonresponse_leaves_no_value_behind() {
    let v = valid(&clinic_visit());
    let vals = values(r#"{ visit.fee: { nr: refused } }"#);
    let roster = BTreeMap::new();
    let e = evaluate_rules(&v.instrument, RecordInput { values: &vals, roster: &roster }).unwrap();
    assert!(e.problems.is_empty(), "{:?}", e.problems);
    assert!(!e.values.contains_key("visit.fee") || matches!(e.values["visit.fee"], Val::Unset), "no number or sentinel stands in for the answer");
    assert!(e.nonresponse.contains_key("visit.fee"), "the nonresponse is held as such");
    assert!(!e.unanswered.contains(&"visit.fee".to_owned()), "and it counts as answered (INS-141)");
}

// covers: INS-048, INS-050, INS-052, INS-087, INS-088, INS-089, INS-131, INS-132, INS-133, INS-134, INS-135, INS-136, INS-137, INS-140, INS-141, INS-142, INS-143, INS-160, INS-161, INS-162, INS-163

const fn c(reqs: &'static [&'static str], name: &'static str, run: fn()) -> Check {
    Check { reqs, name, run }
}

const CHECKS: &[Check] = &[
    c(&["INS-050", "INS-052"], "field checks raise on golden record sets and name their records", clinic::ins_050_field_checks_raise_with_their_records),
    c(&["INS-050"], "the drift check raises on a steady rise and waits for a full window", clinic::ins_050_drift_raises_on_a_steady_rise_in_the_items_unit),
    c(&["INS-050"], "a field check names a known type, parameters and a message", invalid::ins_050_field_checks_name_a_known_type_parameters_and_message),
];

const LOCALE: &[Check] = &[
    c(&["INS-087"], "language lookup falls back to the default and gives the direction", clinic::ins_087_language_lookup_falls_back_to_the_default),
    c(&["INS-087"], "the render plan carries the selected language and its direction", render::ins_087_the_plan_carries_the_selected_language_and_its_direction),
    c(&["INS-088"], "numbers use each locale's separators and native digits", ins_088_numbers_use_each_locales_separators_and_digits),
    c(&["INS-088"], "input accepts the locale's separators and native digits", ins_088_input_accepts_separators_and_native_digits),
    c(&["INS-088"], "display then parse round-trips in every tested locale", ins_088_display_then_parse_round_trips),
    c(&["INS-088"], "currencies, dates and plural forms follow the locale", ins_088_currencies_dates_and_plurals_follow_the_locale),
    c(&["INS-089"], "compatibility reports controls and languages", clinic::ins_089_compatibility_reports_controls_and_languages),
];

const CODES: &[Check] = &[
    c(&["INS-131"], "coded controls need exactly one source", invalid::ins_131_coded_controls_need_exactly_one_source),
    c(&["INS-132"], "code values are decimals", invalid::ins_132_code_values_are_decimals),
    c(&["INS-133"], "an exclusive code cannot be combined", clinic::ins_133_exclusive_code_cannot_be_combined),
    c(&["INS-134"], "a coded list with other reserves the other code", invalid::ins_134_coded_list_with_other_reserves_the_other_code),
    c(&["INS-134", "INS-137"], "a multi-choice other text is synthesised, shown and required", clinic::ins_137_multi_choice_other_text_is_synthesised_and_shown_with_its_code),
    c(&["INS-137"], "an other instance gets a naming question", spec::ins_137_other_instance_gets_a_naming_question),
    c(&["INS-137"], "the other code appears in the codes", invalid::ins_137_the_other_code_appears_in_the_codes),
    c(&["INS-135"], "scales need an ordered list", invalid::ins_135_scales_need_an_ordered_list),
    c(&["INS-136"], "codes are valid and unique", invalid::ins_136_codes_are_valid_and_unique),
    c(&["INS-048", "INS-132"], "value() reads the code's numeric value; the record keeps the code", spec::ins_048_value_reads_the_code_value),
];

const NONRESPONSE: &[Check] = &[
    c(&["INS-140", "INS-142"], "only declared nonresponse codes are valid; not-applicable is never entered", invalid::ins_140_142_nonresponse_codes),
    c(&["INS-140", "INS-141"], "a nonresponse counts as answered and only declared codes are offered", spec::ins_141_nonresponse_counts_as_answered_and_offers_only_declared_codes),
    c(&["INS-140", "INS-141", "INS-142"], "refused is recorded and counts as answered; undeclared codes are problems", clinic::ins_141_refused_is_recorded_and_counts_as_answered),
    c(&["INS-141", "INS-143"], "a nonresponse leaves no value behind", ins_143_a_nonresponse_leaves_no_value_behind),
];

const UNITS: &[Check] = &[
    c(&["INS-160"], "unit codes are UCUM and labels are localised", invalid::ins_160_unit_codes_and_labels),
    c(&["INS-161"], "entry units must convert exactly", invalid::ins_161_entry_units_must_convert_exactly),
    c(&["INS-161"], "entry units convert exactly before bounds are checked", spec::ins_161_entry_units_convert_exactly_before_bounds),
    c(&["INS-161"], "inches convert to centimetres exactly", clinic::ins_161_inches_convert_to_centimetres_exactly),
    c(&["INS-162"], "money needs an ISO currency and its minor digits", invalid::ins_162_money_needs_an_iso_currency_and_minor_digits),
    c(&["INS-162"], "money has at most the currency's minor digits", spec::ins_162_money_has_at_most_the_currencys_minor_digits),
    c(&["INS-162"], "a zero-decimal currency takes whole amounts only", clinic::ins_162_zero_decimal_currency),
    c(&["INS-163"], "a stepper declares a grid", invalid::ins_163_stepper_grid),
    c(&["INS-163"], "stepper values lie on the grid", spec::ins_163_stepper_values_lie_on_the_grid),
];

/// The units of the instrument suites defined here.
pub fn units() -> Vec<Unit> {
    vec![
        Unit::table("ins:checks", &["ins-checks"], CHECKS),
        Unit::table("ins:locale", &["ins-locale"], LOCALE),
        Unit::table("ins:codes", &["ins-codes"], CODES),
        Unit::table("ins:nonresponse", &["ins-nonresponse"], NONRESPONSE),
        Unit::table("ins:units", &["ins-units"], UNITS),
    ]
}
