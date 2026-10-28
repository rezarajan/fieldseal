//! `LintInstrument` (INS §3): advisory findings about a valid instrument. Nothing here
//! makes an instrument invalid; publishing policy may promote any of them.

use std::collections::BTreeSet;

use crate::domain::codes::CodeList;
use crate::domain::compiled::{CompiledAction, NodeKind, QuestionOrigin};
use crate::domain::control::{Control, Options};
use crate::domain::element::{DataType, DisabledDisplay, DisplayRole};
use crate::domain::finding::{Findings, Severity, at};
use crate::domain::metadata::Administration;
use crate::domain::num::Num;
use crate::domain::rules::{Expr, Function, PathRef};
use crate::domain::text::LocalisedText;
use crate::domain::Instrument;

/// Codes that look like nonresponse sentinels (INS-143).
const SENTINELS: [&str; 10] = ["dont-know", "dont_know", "dk", "refused", "not-applicable", "na", "n-a", "98", "99", "999"];

/// Advisory findings for `instrument`.
pub fn lint_instrument(instrument: &Instrument) -> Findings {
    let mut f = Findings::new();
    let def = instrument.definition();
    let compiled = instrument.compiled();

    // Descriptive metadata SHOULDs (INS-111, INS-112).
    if def.metadata.description.is_none() {
        f.lint("INS-111", Severity::Warning, "spec", "declare a `description`");
    }
    if def.metadata.purpose.is_none() {
        f.lint("INS-111", Severity::Warning, "spec", "declare a `purpose`");
    }
    if def.metadata.publisher.is_none() {
        f.lint("INS-111", Severity::Warning, "spec", "declare a `publisher`");
    }
    if !def.metadata.derived_from.is_empty() && def.metadata.copyright.is_none() {
        f.lint("INS-112", Severity::Warning, "spec.derivedFrom", "a derived instrument usually needs `copyright` for its source");
    }
    for (tag, t) in &def.languages.translations {
        if t.reviewed_by == 0 {
            f.lint("INS-083", Severity::Warning, at(&at("spec.translations", tag.as_str()), "reviewedBy"), "nobody has reviewed this translation");
        }
    }

    // Unused code lists, tables and media (INS-131, INS-043, INS-180).
    let mut used_lists = BTreeSet::new();
    let mut used_tables = BTreeSet::new();
    let mut used_media = BTreeSet::new();
    let mut lists_with_media: Vec<&CodeList> = Vec::new();
    for n in compiled.nodes() {
        match &n.kind {
            NodeKind::Group(g) => {
                if let Some(over) = &g.repeat_over {
                    used_lists.insert(over.clone());
                }
                if let Some(m) = &g.media {
                    used_media.extend(m.ids().into_iter().map(str::to_owned));
                }
            }
            NodeKind::Question(q) => {
                if let Some(Options::Named(id)) = q.control.as_ref().and_then(Control::options) {
                    used_lists.insert(id.clone());
                }
                if let Some(Control::CodedListWithOther { options, .. }) = &q.control {
                    lists_with_media.push(options);
                }
                if let Some(Options::Inline(l)) = q.control.as_ref().and_then(Control::options) {
                    lists_with_media.push(l);
                }
                if let Some(id) = &q.data.code_list {
                    used_lists.insert(id.clone());
                }
                if let Some(m) = &q.media {
                    used_media.extend(m.ids().into_iter().map(str::to_owned));
                }
            }
            NodeKind::Display(d) => {
                if let Some(m) = &d.media {
                    used_media.extend(m.ids().into_iter().map(str::to_owned));
                }
            }
        }
    }
    for (id, list) in &def.code_lists {
        if used_lists.contains(id) {
            lists_with_media.push(list);
        } else {
            f.lint("INS-131", Severity::Warning, at("spec.codeLists", id), format!("code list `{id}` is never used"));
        }
    }
    for list in lists_with_media {
        for c in &list.codes {
            if let Some(m) = &c.media {
                used_media.extend(m.ids().into_iter().map(str::to_owned));
            }
        }
    }
    let mut exprs: Vec<(&Expr, String, bool)> = Vec::new();
    for n in compiled.nodes() {
        if let Some(w) = &n.when {
            exprs.push((w, at(&n.doc_path, "when"), false));
        }
    }
    for r in compiled.rules() {
        let validation = matches!(r.action, CompiledAction::Hard { .. } | CompiledAction::Soft { .. });
        exprs.push((&r.when, at(&r.doc_path, "when"), validation));
        if let CompiledAction::Derive { value, .. } = &r.action {
            exprs.push((value, at(&r.doc_path, "value"), false));
        }
    }
    for (e, doc, validation) in &exprs {
        e.visit(&mut |x| {
            if let Expr::Call(func, args) = x {
                match func {
                    Function::Lookup => {
                        if let Some(Expr::Text(t)) = args.first() {
                            used_tables.insert(t.clone());
                        }
                    }
                    Function::IsSet | Function::CountSet if *validation => {
                        f.lint("INS-042", Severity::Warning, doc.clone(), format!("{}() in a hard or soft rule: such rules run only when every item they reference is set", func.name()));
                    }
                    Function::IsNr => {
                        if let Some(Expr::Path(PathRef::Item(p))) = args.first()
                            && compiled.question(p).is_some_and(|q| q.nonresponse.is_empty()) {
                                f.lint("INS-140", Severity::Warning, doc.clone(), format!("`${p}` offers no nonresponse, so is_nr() is always false"));
                            }
                    }
                    _ => {}
                }
            }
        });
    }
    for id in def.tables.keys() {
        if !used_tables.contains(id) {
            f.lint("INS-043", Severity::Warning, at("spec.tables", id), format!("table `{id}` is never used"));
        }
    }
    for id in def.media.keys() {
        if !used_media.contains(id) {
            f.lint("INS-180", Severity::Warning, at("spec.media", id), format!("media `{id}` is never used"));
        }
    }

    // Sentinel codes (INS-143).
    for (id, list) in &def.code_lists {
        for c in &list.codes {
            if SENTINELS.contains(&c.code.to_ascii_lowercase().as_str()) {
                f.lint("INS-143", Severity::Warning, at("spec.codeLists", id), format!("code `{}` looks like a nonresponse; use `nonresponse` instead", c.code));
            }
        }
    }

    // Questions.
    let mut has_concepts = !def.code_lists.values().all(|l| l.codes.iter().all(|c| c.concept.is_empty()));
    let mut seen_doc = BTreeSet::new();
    for n in compiled.nodes() {
        let tag = match n.kind { NodeKind::Group(_) => 0u8, NodeKind::Question(_) => 1, NodeKind::Display(_) => 2 };
        if !seen_doc.insert((n.doc_path.clone(), tag)) {
            continue; // report a repeat template once, not once per instance
        }
        match &n.kind {
            NodeKind::Question(q) => {
                if q.origin != QuestionOrigin::Authored {
                    continue;
                }
                has_concepts |= !q.concept.is_empty() || !q.data.concept.is_empty();
                if def.metadata.administration == Administration::SelfAdministered && q.guidance.is_some() {
                    f.lint("INS-151", Severity::Warning, at(&n.doc_path, "guidance"), "guidance is never shown in a self-administered instrument");
                }
                let numeric = matches!(q.control, Some(Control::Number(_) | Control::Stepper(_) | Control::MeasurementPair(_)));
                if numeric && q.data.data_type == DataType::Decimal && q.data.unit.is_none() {
                    f.lint("INS-160", Severity::Advice, at(&n.doc_path, "data"), "a measured quantity usually has a unit");
                }
                if let Some(Control::Stepper(s)) = &q.control {
                    let (min, start, step) = (Num::from_decimal(s.min), Num::from_decimal(s.start), Num::from_decimal(s.step));
                    if let (Some(min), Some(start), Some(step)) = (min, start, step)
                        && step > Num::ZERO && start.sub(min).and_then(|d| d.div(step)).is_ok_and(|k| !k.is_integer()) {
                            f.lint("INS-163", Severity::Advice, at(&n.doc_path, "control.min"), "`min` is not on the stepper's grid, so it can't be reached");
                        }
                }
                if n.disabled_display == DisabledDisplay::Protected && n.when.is_none() && n.skipped_by.is_empty() {
                    f.lint("INS-125", Severity::Advice, at(&n.doc_path, "disabledDisplay"), "`protected` has no effect without a `when` or skip rule");
                }
                for (key, text) in [("label", Some(&q.label)), ("help", q.help.as_ref()), ("guidance", q.guidance.as_ref())] {
                    if let Some(t) = text {
                        untranslated(&mut f, t, &at(&n.doc_path, key));
                    }
                }
            }
            NodeKind::Group(g) => {
                has_concepts |= !g.concept.is_empty();
                if g.instance_code.is_none() {
                    untranslated(&mut f, &g.label, &at(&n.doc_path, "label"));
                }
            }
            NodeKind::Display(d) => {
                if let Some(t) = &d.text {
                    untranslated(&mut f, t, &at(&n.doc_path, "text"));
                }
            }
        }
    }
    if !has_concepts {
        f.lint("INS-170", Severity::Advice, "spec.elements", "no question, group or code declares a concept; consider mapping key items to a terminology");
    }

    // An end display should come last (INS-123).
    let roots = compiled.roots();
    for (i, r) in roots.iter().enumerate() {
        let n = &compiled.nodes()[*r];
        if let NodeKind::Display(d) = &n.kind
            && d.role == DisplayRole::End && i + 1 != roots.len() {
                f.lint("INS-123", Severity::Warning, n.doc_path.clone(), "an `end` display is not the last element");
            }
    }
    f
}

/// Warns when a text is the same in several languages: probably untranslated (INS-082).
fn untranslated(f: &mut Findings, text: &LocalisedText, doc: &str) {
    let texts: Vec<&str> = text.iter().map(|(_, t)| t).collect();
    if texts.len() > 1 && texts.iter().all(|t| *t == texts[0]) && texts[0].chars().any(char::is_alphabetic) {
        f.lint("INS-082", Severity::Advice, doc, "the text is identical in every language; is it translated?");
    }
}
