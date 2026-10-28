//! Render-plan language and direction (copied from `crates/contexts/instrument/tests/render_plan.rs`).

#![allow(dead_code, unused_imports, missing_docs, clippy::all)]


use super::ins_support as support;

use std::collections::BTreeMap;

use fieldseal_instrument::application::{PlanError, PlanLayout, PlanRequest, compile_render_plan, resolve_visibility};
use fieldseal_instrument::domain::evaluation::RecordInput;
use fieldseal_instrument::domain::render_plan::{PlanOrigin, PlanVisibility};
use fieldseal_instrument::domain::{Direction, Instrument, LayoutIdentity, PlanControl, PlanKind, Presentation, RenderPlan, Visibility, WindowClass};
use support::fixtures::{clinic_visit, minimal, spec_example};
use support::layouts::*;
use support::values;

fn kinds(plan: &RenderPlan) -> Vec<String> {
    plan.nodes().iter().map(|n| format!("{} {}", n.kind.name(), n.bind.as_deref().unwrap_or("-"))).collect()
}

fn visibility(ins: &Instrument, plan: &RenderPlan, vals: &str) -> PlanVisibility {
    let values = values(vals);
    let roster = BTreeMap::new();
    resolve_visibility(ins, plan, RecordInput { values: &values, roster: &roster }).unwrap()
}

fn vis_of(plan: &RenderPlan, v: &PlanVisibility, bind: &str) -> Visibility {
    v.of(plan.node_bound_to(bind).unwrap_or_else(|| panic!("no node bound to {bind}")).id)
}

// ---- metadata --------------------------------------------------------------------------------

pub fn ins_087_the_plan_carries_the_selected_language_and_its_direction() {
    let ins = instrument(&golden_instrument());
    let p = plan(&ins, None, "ar-JO", WindowClass::Compact);
    assert_eq!((p.language.as_str(), p.direction), ("ar", Direction::Rtl));
    assert_eq!(p.instrument.title.text, "ذهبي");
    let p = plan(&ins, None, "fr-CA", WindowClass::Compact);
    assert_eq!((p.language.as_str(), p.direction), ("en", Direction::Ltr), "no French: the default language");
    let languages = ["de", "ar"];
    let p = compile_render_plan(&ins, PlanLayout::Default, PlanRequest { languages: &languages, window_class: WindowClass::Compact }).unwrap();
    assert_eq!(p.language.as_str(), "ar");
}
