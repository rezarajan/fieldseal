//! `LintLayout` (INS §3, INS-210–INS-213): choice-load findings about a validated layout. They
//! are warnings, except that too many questions on a screen of a compact layout is an error
//! (INS-210). Nothing here makes a layout invalid; publishing policy
//! (`publishing.layoutLint.*`) sets the thresholds and may make any of them blocking.

use std::collections::BTreeMap;

use fieldseal_kernel::id::ContentAddress;

use super::render::{PlanLayout, PlanRequest, compile_render_plan};
use crate::domain::compiled::{CompiledAction, NodeKind};
use crate::domain::finding::{Findings, Severity};
use crate::domain::layout::{Layout, WindowClass};
use crate::domain::render_plan::{PlanControl, PlanKind, PlanNode, PlanOrigin};
use crate::domain::rules::PathRef;
use crate::domain::Instrument;

/// The thresholds of the choice-load lints (publishing policy `publishing.layoutLint`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LayoutLintThresholds {
    /// INS-210: the most questions a screen may show at once.
    pub max_decisions_per_screen: u32,
    /// INS-211: the most options a visible choice may show.
    pub max_visible_options: u32,
    /// INS-212: the fewest scale steps that warn in a `table` on a compact (or unclassed)
    /// layout.
    pub max_scale_steps_compact: u32,
}

impl Default for LayoutLintThresholds {
    /// 7, 9 and 7 (INS-210–INS-212).
    fn default() -> Self {
        Self { max_decisions_per_screen: 7, max_visible_options: 9, max_scale_steps_compact: 7 }
    }
}

/// `LintLayout`: findings for `layout` (validated against `instrument`), at the layout document
/// path of the screen or leaf concerned. They are warnings, except INS-210 on a compact layout.
pub fn lint_layout(instrument: &Instrument, layout: &Layout, thresholds: LayoutLintThresholds) -> Findings {
    let mut f = Findings::new();
    let request = PlanRequest { languages: &[], window_class: layout.window_class().unwrap_or(WindowClass::Compact) };
    let plan = if layout.is_default() {
        compile_render_plan(instrument, PlanLayout::Default, request)
    } else {
        compile_render_plan(instrument, PlanLayout::Layout { layout, address: ContentAddress::from([0; 32]) }, request)
    };
    let Ok(plan) = plan else {
        f.lint("INS-200", Severity::Warning, "spec.instrument", "the layout was validated against a different instrument");
        return f;
    };

    // INS-210: questions on one screen. A step is one screen, except that each tab is its own.
    fn screen<'p>(n: &'p PlanNode, count: &mut u32, screens: &mut Vec<&'p PlanNode>) {
        for c in &n.children {
            match &c.kind {
                PlanKind::Tab { .. } => screens.push(c),
                PlanKind::Question(q) if q.control.is_some() && q.origin == PlanOrigin::Authored => *count += 1,
                _ => screen(c, count, screens),
            }
        }
    }
    let mut screens: Vec<&PlanNode> = plan.steps.iter().collect();
    let mut i = 0;
    while i < screens.len() {
        let s = screens[i];
        let mut count = 0;
        let mut more = Vec::new();
        screen(s, &mut count, &mut more);
        if count > thresholds.max_decisions_per_screen {
            let what = if matches!(s.kind, PlanKind::Tab { .. }) { "tab" } else { "step" };
            // A compact window is a phone: a screen that long cannot be answered without scrolling.
            let severity = if layout.window_class() == Some(WindowClass::Compact) { Severity::Error } else { Severity::Warning };
            f.lint(
                "INS-210",
                severity,
                s.source.clone(),
                format!("this {what} shows {count} questions at once; more than {} slows every decision (Hick's law)", thresholds.max_decisions_per_screen),
            );
        }
        screens.extend(more);
        i += 1;
    }

    let nodes = plan.nodes();
    let unclassed_or_compact = matches!(layout.window_class(), None | Some(WindowClass::Compact));
    for n in &nodes {
        // INS-211: long option lists.
        if let Some(q) = n.question()
            && let Some(c @ (PlanControl::Choice { .. } | PlanControl::MultiChoice { .. } | PlanControl::CodedListWithOther { .. })) = &q.control
        {
            let options = c.options().len() + usize::from(matches!(c, PlanControl::CodedListWithOther { .. }));
            if options > thresholds.max_visible_options as usize {
                f.lint(
                    "INS-211",
                    Severity::Warning,
                    n.source.clone(),
                    format!("`{}` shows {options} options; more than {} without grouping is hard to scan", n.bind.as_deref().unwrap_or(""), thresholds.max_visible_options),
                );
            }
        }
        // INS-212: long scales in a grid on narrow screens.
        if matches!(n.kind, PlanKind::Table { .. }) && unclassed_or_compact {
            let longest = n.walk().iter().filter_map(|m| match m.question().and_then(|q| q.control.as_ref()) {
                Some(PlanControl::Scale { steps }) => Some(steps.len()),
                _ => None,
            }).max();
            if let Some(steps) = longest.filter(|s| *s >= thresholds.max_scale_steps_compact as usize) {
                let class = if layout.window_class().is_some() { "a compact layout" } else { "a layout without a window class" };
                f.lint(
                    "INS-212",
                    Severity::Warning,
                    n.source.clone(),
                    format!("a table with a {steps}-step scale on {class}; grids of long scales raise straightlining on small screens, so use `as: list`"),
                );
            }
        }
    }

    // INS-213: a dependent element placed before what it depends on.
    let compiled = instrument.compiled();
    let mut position: BTreeMap<&str, usize> = BTreeMap::new();
    for n in &nodes {
        if let Some(b) = &n.bind {
            position.entry(b.as_str()).or_insert(n.id);
        }
    }
    for (i, node) in compiled.nodes().iter().enumerate() {
        let mut deps: Vec<String> = Vec::new();
        if let Some(w) = &node.when {
            deps.extend(w.paths().into_iter().filter_map(|p| match p {
                PathRef::Item(p) => Some(p),
                _ => None,
            }));
        }
        for &k in &node.skipped_by {
            let r = &compiled.rules()[k];
            if matches!(r.action, CompiledAction::Skip { .. }) {
                deps.extend(r.refs.iter().cloned());
            }
        }
        if deps.is_empty() {
            continue;
        }
        // Where the dependent element first appears: its own node, or its first placed question.
        let first = position.get(node.path.as_str()).copied().or_else(|| {
            compiled.questions_under(i).iter().filter_map(|q| position.get(compiled.nodes()[*q].path.as_str()).copied()).min()
        });
        let Some(first) = first else { continue };
        let is_other_text = matches!(&node.kind, NodeKind::Question(q) if !matches!(q.origin, crate::domain::compiled::QuestionOrigin::Authored));
        if is_other_text {
            continue;
        }
        deps.sort();
        deps.dedup();
        for dep in deps {
            if let Some(&at) = position.get(dep.as_str())
                && at > first
            {
                f.lint(
                    "INS-213",
                    Severity::Warning,
                    nodes[first].source.clone(),
                    format!("`{}` is shown or hidden by `{dep}`, but is placed before it; place it after, so it appears when it applies", node.path),
                );
            }
        }
    }
    f
}
