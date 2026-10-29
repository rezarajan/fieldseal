//! Layout fixtures in the test notation, and the instruments they are bound to.

#![allow(dead_code)]

use fieldseal_instrument::application::{validate_layout, PlanLayout, PlanRequest, compile_render_plan};
use fieldseal_instrument::domain::{Findings, Instrument, Layout, RenderPlan, WindowClass};
use fieldseal_kernel::id::ContentAddress;
use fieldseal_kernel::Value;

use super::{doc, render, valid};

/// The layout of `docs/reference/spec/instrument.md` §6.2, over the §6.1 instrument.
pub fn spec_layout() -> Value {
    doc(r#"
{
  apiVersion: fieldseal.dev/v1alpha1,
  kind: Layout,
  metadata: { name: school-meals-baseline-wide, version: 1.0.0 },
  spec: {
    schema: "^1.0",
    instrument: "./school-meals-baseline.yaml",
    windowClass: expanded,
    steps: [
      {
        title: { en: About you }, navigation: linear,
        contents: [
          { card: { title: { en: Basic details }, icon: "🧒", contents: [ { element: about.sex } ] } },
          { card: { title: { en: Measurements }, icon: "📏", contents: [ { element: about.weight } ] } },
          { card: { title: { en: Spending money }, icon: "💵", contents: [ { element: about.money_gets }, { element: about.money_per_day } ] } },
        ],
      },
      {
        title: { en: Foods and drinks }, navigation: linear,
        contents: [
          { element: diet_intro },
          { tabs: [ { tab: { title: { en: Staples }, icon: "🍞", contents: [ { repeat: staples, as: list } ] } } ] },
        ],
      },
    ],
  },
}
"#)
}

/// A reduced school-meals instrument with the structure of `examples/surveys/school-meals-baseline/instrument.yaml`:
/// a demographics group, a diet group of two displays and repeat categories, and a top-level
/// end display.
pub fn school_meals() -> Value {
    doc(r#"
{
  apiVersion: fieldseal.dev/v1alpha1,
  kind: Instrument,
  metadata: { name: school-meals-mini, version: 1.0.0 },
  spec: {
    schema: "^1.0",
    title: { en: School meals survey },
    administration: interviewer,
    languages: [en],
    defaultLanguage: en,
    nonresponse: [dont-know],
    consent: { required: false },
    codeLists: {
      freq: {
        ordered: true,
        codes: [
          { code: never, label: { en: Never } }, { code: monthly, label: { en: Monthly } }, { code: weekly, label: { en: Weekly } },
          { code: daily, label: { en: Daily } },
        ],
      },
      staples: {
        ordered: false,
        other: { code: other, label: { en: Other staple }, maxLength: 40 },
        codes: [ { code: bread, label: { en: Bread }, icon: "🍞" }, { code: rice, label: { en: Rice } }, { code: other, label: { en: Other staple } } ],
      },
      legumes: { ordered: false, codes: [ { code: beans, label: { en: Beans } }, { code: peas, label: { en: Peas } } ] },
      sex: { ordered: false, codes: [ { code: male, label: { en: Male } }, { code: female, label: { en: Female } } ] },
    },
    elements: [
      {
        kind: group, id: about, label: { en: General information },
        elements: [
          { kind: question, path: name, label: { en: Name }, control: { type: text, maxLength: 60 }, data: { type: string } },
          { kind: question, path: sex, label: { en: Sex }, control: { type: choice, codes: sex }, data: { type: code } },
          { kind: question, path: weight, label: { en: Weight }, control: { type: number, min: 10, max: 200, decimals: 1, unit: kg }, data: { type: decimal, unit: kg } },
          { kind: question, path: money_gets, label: { en: Do you get spending money? }, control: { type: yes-no }, data: { type: boolean } },
          {
            kind: question, path: money_per_day, label: { en: How much each day? }, when: '$about.money_gets == true', disabledDisplay: protected,
            control: { type: money, currency: USD, min: 0, max: 200, step: 5 }, data: { type: money },
          },
        ],
      },
      {
        kind: group, id: diet, label: { en: Foods and drinks },
        elements: [
          { kind: display, id: diet_intro, role: introduction, text: { en: These questions are about foods. } },
          { kind: display, id: diet_instructions, role: instruction, text: { en: Ask about each food in turn. } },
          {
            kind: group, id: staples, label: { en: Staples }, repeat: { over: staples },
            elements: [
              { kind: question, path: freq, label: { en: How often? }, control: { type: scale, codes: freq }, data: { type: code, codeList: freq } },
              { kind: question, path: yesterday, label: { en: Yesterday? }, when: '@freq != "never"', control: { type: yes-no }, data: { type: boolean } },
            ],
          },
          {
            kind: group, id: legumes, label: { en: Legumes }, repeat: { over: legumes },
            elements: [
              { kind: question, path: freq, label: { en: How often? }, control: { type: scale, codes: freq }, data: { type: code, codeList: freq } },
            ],
          },
        ],
      },
      { kind: display, id: survey_end, role: end, text: { en: Thank you. } },
    ],
  },
}
"#)
}

/// The equivalent of `examples/surveys/school-meals-baseline/layouts/expanded.yaml` for [`school_meals`].
pub fn school_meals_expanded() -> Value {
    doc(r#"
{
  apiVersion: fieldseal.dev/v1alpha1,
  kind: Layout,
  metadata: { name: school-meals-mini-expanded, version: 1.0.0 },
  spec: {
    schema: "^1.0",
    instrument: "../instruments/school-meals-mini.yaml",
    windowClass: expanded,
    steps: [
      {
        title: { en: General information }, navigation: linear,
        contents: [
          { card: { title: { en: Basic details }, icon: "🧒", contents: [ { element: about.name }, { element: about.sex } ] } },
          { card: { title: { en: Measurements }, icon: "📏", contents: [ { element: about.weight } ] } },
          { card: { title: { en: Spending money }, icon: "💵", contents: [ { element: about.money_gets }, { element: about.money_per_day } ] } },
        ],
      },
      {
        title: { en: Foods and drinks }, navigation: linear,
        contents: [
          { element: diet.diet_intro },
          { element: diet.diet_instructions },
          {
            tabs: [
              { tab: { title: { en: Staples }, icon: "🍞", contents: [ { repeat: diet.staples, as: list } ] } },
              { tab: { title: { en: Legumes }, icon: "🫘", contents: [ { repeat: diet.legumes, as: list } ] } },
            ],
          },
          { element: survey_end },
        ],
      },
    ],
  },
}
"#)
}

/// A layout for the clinic-visit instrument (two languages, nested groups, a repeat as a table,
/// rows and presentations).
pub fn clinic_layout() -> Value {
    doc(r#"
{
  apiVersion: fieldseal.dev/v1alpha1,
  kind: Layout,
  metadata: { name: clinic-visit-medium, version: 0.1.0 },
  spec: {
    schema: "^1.0",
    instrument: "clinic-visit.yaml",
    windowClass: medium,
    steps: [
      {
        title: { en: Visit, fr: Consultation }, navigation: linear,
        contents: [
          { element: welcome },
          { card: { title: { en: The visit, fr: La consultation }, contents: [ { row: { contents: [ { element: visit.date }, { element: visit.type } ] } }, { element: visit.age_band }, { element: visit.fee, presentation: stepper } ] } },
        ],
      },
      {
        title: { en: Examination, fr: Examen }, navigation: free, emphasis: compact,
        contents: [
          { group: vitals },
          { card: { title: { en: Complaint, fr: Plainte }, icon: "🩺", contents: [ { element: complaint.symptoms }, { element: complaint.pain, presentation: slider }, { element: complaint.days }, { element: complaint.days_note }, { element: complaint.notes } ] } },
        ],
      },
      {
        title: { en: Treatment, fr: Traitement }, navigation: linear,
        contents: [ { repeat: treatment.given, as: table }, { element: done } ],
      },
    ],
  },
}
"#)
}

/// Validates a layout, panicking with every finding if invalid.
#[track_caller]
pub fn valid_layout(layout: &Value, instrument: &Instrument) -> Layout {
    match validate_layout(layout, instrument) {
        Ok(l) => l,
        Err(f) => panic!("expected a valid layout:\n{}", render(&f)),
    }
}

/// Validates a layout, expecting failure.
#[track_caller]
pub fn invalid_layout(layout: &Value, instrument: &Instrument) -> Findings {
    match validate_layout(layout, instrument) {
        Ok(_) => panic!("expected the layout to be invalid"),
        Err(f) => f,
    }
}

/// The instrument of a fixture.
pub fn instrument(v: &Value) -> Instrument {
    valid(v).instrument
}

/// A content address for tests.
pub fn address() -> ContentAddress {
    ContentAddress::from([7; 32])
}

/// Compiles a plan for `layout` (or the default) in `lang` and `class`.
pub fn plan(instrument: &Instrument, layout: Option<&Layout>, lang: &str, class: WindowClass) -> RenderPlan {
    let languages = [lang];
    let request = PlanRequest { languages: &languages, window_class: class };
    let layout = match layout {
        Some(layout) => PlanLayout::Layout { layout, address: address() },
        None => PlanLayout::Default,
    };
    compile_render_plan(instrument, layout, request).expect("the layout is for this instrument")
}

/// A stable, indented text rendering of a value for golden files: maps in key order, one
/// entry per line; text quoted as JSON strings; decimals as `mantissa e exponent`.
pub fn pretty(v: &Value) -> String {
    fn go(v: &Value, indent: usize, out: &mut String) {
        let pad = "  ".repeat(indent + 1);
        match v {
            Value::Map(m) if m.is_empty() => out.push_str("{}"),
            Value::Map(m) => {
                out.push_str("{\n");
                for (k, x) in m {
                    out.push_str(&format!("{pad}{k}: "));
                    go(x, indent + 1, out);
                    out.push('\n');
                }
                out.push_str(&"  ".repeat(indent));
                out.push('}');
            }
            Value::Array(a) if a.is_empty() => out.push_str("[]"),
            Value::Array(a) => {
                out.push_str("[\n");
                for x in a {
                    out.push_str(&pad);
                    go(x, indent + 1, out);
                    out.push('\n');
                }
                out.push_str(&"  ".repeat(indent));
                out.push(']');
            }
            Value::Text(t) => out.push_str(&format!("{t:?}")),
            Value::Int(i) => out.push_str(&i.to_string()),
            Value::Decimal(d) => out.push_str(&format!("{}e{}", d.mantissa, d.exponent)),
            Value::Bool(b) => out.push_str(&b.to_string()),
            Value::Bytes(b) => out.push_str(&format!("bytes({})", b.iter().map(|x| format!("{x:02x}")).collect::<String>())),
        }
    }
    let mut out = String::new();
    go(v, 0, &mut out);
    out.push('\n');
    out
}

/// Compares `actual` with the golden file `tests/golden/<name>`; with `FIELDSEAL_BLESS=1`
/// set, writes it instead.
#[track_caller]
pub fn golden(name: &str, actual: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(name);
    if std::env::var_os("FIELDSEAL_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}; run with FIELDSEAL_BLESS=1", path.display()));
    assert!(expected == actual, "{name} differs from the golden plan; run with FIELDSEAL_BLESS=1 and review the diff");
}

/// A small two-language instrument, one right-to-left, for golden plans.
pub fn golden_instrument() -> Value {
    doc(r#"
{
  apiVersion: fieldseal.dev/v1alpha1,
  kind: Instrument,
  metadata: { name: golden, version: 1.0.0 },
  spec: {
    schema: "^1.0",
    title: { en: Golden, ar: "ذهبي" },
    administration: self,
    languages: [en, ar],
    defaultLanguage: en,
    translations: { ar: { method: human, reviewedBy: 1 } },
    nonresponse: [refused],
    consent: { required: false },
    codeLists: {
      pick: {
        ordered: false,
        other: { code: other, label: { en: Something else, ar: "شيء آخر" }, maxLength: 20 },
        codes: [ { code: a, label: { en: A, ar: "أ" }, icon: "🍞" }, { code: other, label: { en: Other, ar: "آخر" } } ],
      },
      size: { ordered: true, codes: [ { code: s, label: { en: Small, ar: "صغير" } }, { code: l, label: { en: Large, ar: "كبير" } } ] },
      things: { ordered: false, codes: [ { code: x, label: { en: X, ar: "س" } }, { code: y, label: { en: Y, ar: "ص" } } ] },
    },
    elements: [
      { kind: display, id: hello, role: introduction, text: { en: "Hello {$roster.name}.", ar: "مرحبا {$roster.name}." } },
      {
        kind: group, id: g, label: { en: First, ar: "الأول" },
        elements: [
          { kind: question, path: pick, prefix: "1", label: { en: Pick one, ar: "اختر" }, guidance: { en: Hidden when self-administered, ar: "مخفي" }, control: { type: choice, codes: pick }, data: { type: code, codeList: pick } },
          {
            kind: question, path: n, label: { en: How much?, ar: "كم؟" }, when: '$g.pick == "a"', disabledDisplay: protected,
            control: { type: number, min: 0, max: 9.5, decimals: 1, unit: kg, entryUnits: ["[lb_av]"] }, data: { type: decimal, unit: kg },
          },
          {
            kind: group, id: inner, label: { en: Inner, ar: "داخلي" },
            elements: [ { kind: question, path: ok, label: { en: OK?, ar: "حسنا؟" }, control: { type: yes-no, presentation: buttons }, data: { type: boolean } } ],
          },
        ],
      },
      {
        kind: group, id: r, label: { en: Things, ar: "أشياء" }, repeat: { over: things },
        elements: [
          { kind: question, path: size, label: { en: Size, ar: "الحجم" }, control: { type: scale, codes: size }, data: { type: code, codeList: size } },
          { kind: question, path: cost, label: { en: Cost, ar: "التكلفة" }, nonresponse: [], control: { type: money, currency: JOD, min: 0, max: 100 }, data: { type: money } },
        ],
      },
    ],
  },
}
"#)
}

/// A layout for [`golden_instrument`] using tabs, a card, a row and a table.
pub fn golden_layout() -> Value {
    doc(r#"
{
  apiVersion: fieldseal.dev/v1alpha1,
  kind: Layout,
  metadata: { name: golden-medium, version: 1.0.0 },
  spec: {
    schema: "^1.0",
    instrument: "golden.yaml",
    windowClass: medium,
    steps: [
      {
        title: { en: Start, ar: "البداية" }, navigation: free, emphasis: compact,
        contents: [
          { element: hello },
          { card: { title: { en: Choose, ar: "اختر" }, icon: "🧭", contents: [ { row: { contents: [ { element: g.pick }, { element: g.n } ] } } ] } },
          { tabs: [ { tab: { title: { en: Inner, ar: "داخلي" }, contents: [ { group: g.inner } ] } } ] },
        ],
      },
      {
        title: { en: Things, ar: "أشياء" }, navigation: linear,
        contents: [ { repeat: r, as: table } ],
      },
    ],
  },
}
"#)
}
