//! Invalid-instrument fixtures (copied from `crates/contexts/instrument/tests/invalid.rs`).

#![allow(dead_code, unused_imports, missing_docs, clippy::all)]


use super::ins_support as support;

use fieldseal_instrument::domain::FindingKind;
use fieldseal_kernel::Value;
use support::fixtures::minimal;
use support::{doc, en, invalid, push, rejects, remove, set, t, valid};

const G: &str = "spec.elements[0]";
const Q: &str = "spec.elements[0].elements[0]";
const C: &str = "spec.elements[0].elements[1]";

fn with(path: &str, value: Value) -> Value {
    let mut d = minimal();
    set(&mut d, path, value);
    d
}

fn without(path: &str) -> Value {
    let mut d = minimal();
    remove(&mut d, path);
    d
}

fn rule(text: &str) -> Value {
    with("spec.rules", doc(&format!("[{text}]")))
}

fn bilingual() -> Value {
    let mut d = minimal();
    set(&mut d, "spec.languages", doc("[en, fr]"));
    set(&mut d, "spec.translations", doc("{ fr: { method: human, reviewedBy: 2 } }"));
    for p in ["spec.title", &format!("{G}.label"), &format!("{Q}.label"), &format!("{C}.label"), "spec.codeLists.ab.codes[0].label", "spec.codeLists.ab.codes[1].label"] {
        set(&mut d, p, doc("{ en: Text, fr: Texte }"));
    }
    d
}

pub fn ins_131_coded_controls_need_exactly_one_source() {
    rejects(&with(&format!("{C}.control.options"), doc("[{ code: x, label: { en: X } }]")), "INS-131", &format!("{C}.control"));
    rejects(&with(&format!("{C}.control.codes"), t("nope")), "INS-131", &format!("{C}.control.codes"));
    rejects(&with(&format!("{C}.control"), doc("{ type: choice }")), "INS-131", &format!("{C}.control"));
}

pub fn ins_135_scales_need_an_ordered_list() {
    let mut d = with(&format!("{C}.control"), doc("{ type: scale, codes: ab }"));
    rejects(&d, "INS-135", &format!("{C}.control.codes"));
    set(&mut d, "spec.codeLists.ab.ordered", Value::Bool(true));
    valid(&d);
}

pub fn ins_160_unit_codes_and_labels() {
    rejects(&with(&format!("{Q}.control.unit"), t("k g")), "INS-160", &format!("{Q}.control.unit"));
    let mut d = with(&format!("{Q}.control.unit"), t("[lb_av]"));
    set(&mut d, &format!("{Q}.data.unit"), t("[lb_av]"));
    rejects(&d, "INS-160", &format!("{Q}.control.unitLabel"));
    rejects(&with(&format!("{Q}.control.unitLabel"), en("lbs")), "INS-160", &format!("{Q}.control.unitLabel"));
}

pub fn ins_161_entry_units_must_convert_exactly() {
    let mut d = with(&format!("{Q}.control.unit"), t("kg"));
    set(&mut d, &format!("{Q}.data.unit"), t("kg"));
    set(&mut d, &format!("{Q}.data.type"), t("decimal"));
    set(&mut d, &format!("{Q}.control.entryUnits"), doc(r#"["[lb_av]"]"#));
    valid(&d);
    for bad in [r#"["cm"]"#, r#"["{each}"]"#, r#"["kg"]"#] {
        let mut d2 = d.clone();
        set(&mut d2, &format!("{Q}.control.entryUnits"), doc(bad));
        rejects(&d2, "INS-161", &format!("{Q}.control.entryUnits[0]"));
    }
    rejects(&with(&format!("{Q}.control.entryUnits"), doc("[kg]")), "INS-161", &format!("{Q}.control.entryUnits"));
}

pub fn ins_162_money_needs_an_iso_currency_and_minor_digits() {
    let money = |c: &str| with(&format!("{Q}.control"), doc(c));
    let mut ok = money("{ type: money, currency: TTD, min: 0, max: 200, step: 0.25 }");
    set(&mut ok, &format!("{Q}.data.type"), t("money"));
    valid(&ok);
    let mut d = ok.clone();
    set(&mut d, &format!("{Q}.control.currency"), t("XYZ"));
    rejects(&d, "INS-162", &format!("{Q}.control.currency"));
    let mut d = ok.clone();
    set(&mut d, &format!("{Q}.control.step"), doc("0.125"));
    rejects(&d, "INS-162", &format!("{Q}.control.step"));
    let mut d = ok.clone();
    remove(&mut d, &format!("{Q}.control.currency"));
    rejects(&d, "INS-162", &format!("{Q}.control"));
}

pub fn ins_163_stepper_grid() {
    let stepper = |c: &str| {
        let mut d = with(&format!("{Q}.control"), doc(c));
        set(&mut d, &format!("{Q}.data.type"), t("decimal"));
        d
    };
    valid(&stepper("{ type: stepper, min: 0.5, max: 20, start: 1, step: 0.5 }"));
    rejects(&stepper("{ type: stepper, min: 0, max: 20, step: 0 }"), "INS-163", &format!("{Q}.control.step"));
    rejects(&stepper("{ type: stepper, min: 1, max: 20, start: 30 }"), "INS-163", &format!("{Q}.control.start"));
    rejects(&stepper("{ type: stepper, max: 20 }"), "INS-163", &format!("{Q}.control"));
    let mut d = stepper("{ type: stepper, min: 0, max: 20, step: 0.5 }");
    set(&mut d, &format!("{Q}.data.type"), t("integer"));
    rejects(&d, "INS-070", &format!("{Q}.data.type"));
}

fn repeated(rules: &str) -> Value {
    doc(&format!(
        r#"{{ kind: group, id: rep, label: {{ en: R }}, repeat: {{ over: ab }},
             elements: [
               {{ kind: question, path: x, label: {{ en: X }}, control: {{ type: number, min: 0, max: 9 }}, data: {{ type: integer }} }},
               {{ kind: question, path: y, label: {{ en: Y }}, when: '@x > 1', control: {{ type: stepper, min: 1, max: 5 }}, data: {{ type: integer }} }},
             ],
             rules: [{rules}] }}"#
    ))
}

// ---- field checks ---------------------------------------------------------------------------

pub fn ins_050_field_checks_name_a_known_type_parameters_and_message() {
    let check = |c: &str| with("spec.fieldChecks", doc(&format!("[{c}]")));
    valid(&check("{ id: c, type: drift, path: g.q, window: 5, threshold: 1, message: { en: M } }"));
    rejects(&check("{ id: c, type: wobble, message: { en: M } }"), "INS-050", "spec.fieldChecks[0].type");
    rejects(&check("{ id: c, type: drift, path: g.q, window: 5, threshold: 1 }"), "INS-050", "spec.fieldChecks[0]");
    rejects(&check("{ id: c, type: drift, path: g.c, window: 5, threshold: 1, message: { en: M } }"), "INS-050", "spec.fieldChecks[0].path");
    rejects(&check("{ id: c, type: straightlining, group: g.q, threshold: 0.8, message: { en: M } }"), "INS-050", "spec.fieldChecks[0].group");
    rejects(&check("{ id: c, type: completeness, group: g, threshold: 1.5, message: { en: M } }"), "INS-050", "spec.fieldChecks[0].threshold");
    rejects(&check("{ id: c, type: timing, message: { en: M } }"), "INS-050", "spec.fieldChecks[0]");
    rejects(&check("{ id: c, type: duplicates, paths: [g.q], minMatch: 2, message: { en: M } }"), "INS-050", "spec.fieldChecks[0].minMatch");
    rejects(&check("{ id: c, type: drift, path: g.q, window: 5, threshold: 1, message: { en: M }, colour: red }"), "INS-006", "spec.fieldChecks[0].colour");
}

// ---- code lists ---------------------------------------------------------------------------

pub fn ins_136_codes_are_valid_and_unique() {
    rejects(&with("spec.codeLists.ab.codes[1].code", t("a")), "INS-136", "spec.codeLists.ab.codes[1].code");
    rejects(&with("spec.codeLists.ab.codes[1].code", t("b c")), "INS-136", "spec.codeLists.ab.codes[1].code");
    rejects(&with("spec.codeLists.ab.codes", doc("[]")), "INS-131", "spec.codeLists.ab.codes");
    rejects(&without("spec.codeLists.ab.ordered"), "INS-131", "spec.codeLists.ab");
}

pub fn ins_132_code_values_are_decimals() {
    rejects(&with("spec.codeLists.ab.codes[0].value", t("high")), "INS-132", "spec.codeLists.ab.codes[0].value");
}

pub fn ins_137_the_other_code_appears_in_the_codes() {
    rejects(&with("spec.codeLists.ab.other", doc("{ code: z, label: { en: Other }, maxLength: 20 }")), "INS-137", "spec.codeLists.ab.other.code");
    let d = with("spec.codeLists.ab.other", doc("{ code: b, label: { en: Other }, maxLength: 20 }"));
    let v = valid(&d);
    assert!(v.instrument.compiled().question("g.c.other").is_some());
    let mut clash = d.clone();
    push(&mut clash, &format!("{G}.elements"), doc("{ kind: question, path: c.other, label: { en: X }, control: { type: text }, data: { type: string } }"));
    rejects(&clash, "INS-011", &format!("{G}.elements[2]"));
}

pub fn ins_134_coded_list_with_other_reserves_the_other_code() {
    let mut d = with(&format!("{C}.control"), doc("{ type: coded-list-with-other, options: [ { code: other, label: { en: O } } ], otherLabel: { en: Other }, maxLength: 20 }"));
    remove(&mut d, &format!("{C}.data.codeList"));
    rejects(&d, "INS-134", &format!("{C}.control.options"));
}

// ---- nonresponse --------------------------------------------------------------------------

pub fn ins_140_142_nonresponse_codes() {
    rejects(&with("spec.nonresponse", doc("[dont-know, maybe]")), "INS-140", "spec.nonresponse[1]");
    rejects(&with(&format!("{Q}.nonresponse"), doc("[not-applicable]")), "INS-142", &format!("{Q}.nonresponse[0]"));
    rejects(&with(&format!("{Q}.nonresponse"), doc("[refused, refused]")), "INS-140", &format!("{Q}.nonresponse[1]"));
}

fn with_media(media: &str) -> Value {
    with("spec.media", doc(&format!("{{ pic: {media} }}")))
}

const PNG: &str = r#"{ mediaType: image/png, sha256: "0000000000000000000000000000000000000000000000000000000000000000", bytes: x"89504e470d0a1a0a", alt: { en: A picture } }"#;
