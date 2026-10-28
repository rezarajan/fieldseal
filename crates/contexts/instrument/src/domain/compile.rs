//! Compilation: from the authored definition to the [`CompiledInstrument`] (INS-047,
//! INS-121–INS-129, INS-137), with the semantic checks that need the whole tree: control
//! configuration against data specifications, path uniqueness, rule references and types,
//! evaluation bounds, and an evaluation order free of cycles (INS-044).

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use fieldseal_kernel::Decimal;

use super::codes::CodeList;
use super::compiled::*;
use super::control::{Control, OTHER_CODE, Options, UnitSpec};
use super::definitions::{CheckKind, CheckScopeDef, FieldCheckDef, RuleAction, RuleDef};
use super::element::{ControlOverride, DataSpec, DataType, DisabledDisplay, Element, Group, Question};
use super::finding::{FindingKind, Findings, at, idx};
use super::instrument::InstrumentDefinition;
use super::num::Num;
use super::paths::{MAX_PATH_LEN, is_date, is_segment};
use super::rules::{BinOp, CheckErrorKind, CheckScope, Expr, MAX_RULE_NODES, PathInfo, PathRef, TableShape, Ty};
use super::rules::check::check as check_expr;
use super::text::LocalisedText;

/// The deepest group nesting (INS-122).
pub const MAX_GROUP_DEPTH: usize = 4;
/// The most compiled nodes; an implementation bound so compilation itself is bounded.
pub const MAX_NODES: usize = 100_000;
/// The most compiled rules and field checks, likewise.
pub const MAX_COMPILED_RULES: usize = 100_000;
/// The most rows across all lookup tables (INS-044).
pub const MAX_TABLE_ROWS: usize = 10_000;

#[derive(Clone)]
struct RepeatCtx {
    instance: String,
    siblings: BTreeSet<String>,
}

#[derive(Clone)]
struct Ctx {
    prefix: String,
    parent: Option<usize>,
    depth: usize,
    repeat: Option<RepeatCtx>,
}

struct Pending<'d, T> {
    def: &'d T,
    scope: Option<usize>,
    scope_path: String,
    repeat: Option<RepeatCtx>,
}

/// Compiles `def`. Findings are errors unless stated; the compiled form is only meaningful
/// when there are none.
pub fn compile(def: &InstrumentDefinition) -> (CompiledInstrument, Findings) {
    let mut c = Compiler { def, out: CompiledInstrument::default(), f: Findings::new(), rules: Vec::new(), checks: Vec::new(), aborted: false };
    for d in &def.derived {
        c.out.derived.push(CompiledDerived { path: d.path.clone(), label: d.label.clone(), data: d.data.clone(), record: d.record, rule: None });
    }
    let root = Ctx { prefix: String::new(), parent: None, depth: 0, repeat: None };
    c.walk(&def.elements, &root, "spec.elements", None);
    for r in &def.rules {
        c.rules.push(Pending { def: r, scope: None, scope_path: String::new(), repeat: None });
    }
    for fc in &def.field_checks {
        c.checks.push(Pending { def: fc, scope: None, scope_path: String::new(), repeat: None });
    }
    if c.aborted {
        return (c.out, c.f);
    }
    c.check_derived_paths();
    let rules = std::mem::take(&mut c.rules);
    for p in &rules {
        c.rule(p);
    }
    let checks = std::mem::take(&mut c.checks);
    for p in &checks {
        c.field_check(p);
    }
    for (i, d) in c.out.derived.iter().enumerate() {
        if d.rule.is_none() {
            c.f.lint(
                "INS-045",
                super::finding::Severity::Warning,
                format!("{}[{i}]", "spec.derived"),
                format!("no derive rule computes `{}`; it is always unset", d.path),
            );
        }
    }
    c.type_check();
    c.order();
    (c.out, c.f)
}

struct Compiler<'d> {
    def: &'d InstrumentDefinition,
    out: CompiledInstrument,
    f: Findings,
    rules: Vec<Pending<'d, RuleDef>>,
    checks: Vec<Pending<'d, FieldCheckDef>>,
    aborted: bool,
}

fn join(prefix: &str, path: &str) -> String {
    if prefix.is_empty() { path.to_owned() } else { format!("{prefix}.{path}") }
}

impl<'d> Compiler<'d> {
    fn list(&self, options: &'d Options) -> Option<&'d CodeList> {
        match options {
            Options::Inline(l) => Some(l),
            Options::Named(id) => self.def.code_lists.get(id),
        }
    }

    fn add_node(&mut self, node: Node) -> usize {
        let i = self.out.nodes.len();
        if i >= MAX_NODES {
            if !self.aborted {
                self.f.error_of(FindingKind::UnboundedRule, "INS-044", node.doc_path.clone(), format!("the instrument compiles to more than {MAX_NODES} elements"));
            }
            self.aborted = true;
            return 0;
        }
        if node.path.len() > MAX_PATH_LEN {
            self.f.error("INS-012", node.doc_path.clone(), format!("the full path `{}` is longer than {MAX_PATH_LEN} characters", node.path));
        }
        if node.path.split('.').next() == Some("roster") {
            self.f.error("INS-012", node.doc_path.clone(), "paths may not start with `roster`, which names roster fields in rules");
        }
        match self.out.index.get(&node.path) {
            Some(&other) => {
                let first = self.out.nodes[other].doc_path.clone();
                self.f.error("INS-011", node.doc_path.clone(), format!("path `{}` is already used at {first}", node.path));
            }
            None => {
                self.out.index.insert(node.path.clone(), i);
            }
        }
        match node.parent {
            Some(p) => self.out.nodes[p].children.push(i),
            None => self.out.roots.push(i),
        }
        self.out.nodes.push(node);
        i
    }

    /// Replaces `@id` with the instance path (INS-047).
    fn resolve(&mut self, expr: &Expr, repeat: Option<&RepeatCtx>, doc: &str) -> Expr {
        let derived: BTreeSet<&str> = self.def.derived.iter().map(|d| d.path.as_str()).collect();
        let mut errors = Vec::new();
        let e = expr.map_paths(&mut |p| match (p, repeat) {
            (PathRef::Sibling(id), Some(r)) => {
                let full = join(&r.instance, id);
                if !r.siblings.contains(id) && !derived.contains(full.as_str()) {
                    errors.push(format!("`@{id}` is not a question of this repeat group"));
                }
                PathRef::Item(full)
            }
            (PathRef::Sibling(id), None) => {
                errors.push(format!("`@{id}` is only allowed in rules declared inside a repeat group"));
                p.clone()
            }
            _ => p.clone(),
        });
        for m in errors {
            self.f.error_of(FindingKind::UnknownItemPath, "INS-047", doc, m);
        }
        if e.node_count() > MAX_RULE_NODES {
            self.f.error_of(FindingKind::UnboundedRule, "INS-044", doc, format!("the expression has {} nodes; the limit is {MAX_RULE_NODES}", e.node_count()));
        }
        e
    }

    fn walk(&mut self, elements: &'d [Element], ctx: &Ctx, doc: &str, overrides: Option<&'d BTreeMap<String, ControlOverride>>) {
        for (i, e) in elements.iter().enumerate() {
            if self.aborted {
                return;
            }
            let doc_i = idx(doc, i);
            match e {
                Element::Question(q) => self.question(q, ctx, &doc_i, overrides.and_then(|o| o.get(&q.path))),
                Element::Display(d) => {
                    let when = d.when.as_ref().map(|w| self.resolve(&w.expr, ctx.repeat.as_ref(), &at(&doc_i, "when")));
                    self.add_node(Node {
                        path: join(&ctx.prefix, &d.id),
                        parent: ctx.parent,
                        children: Vec::new(),
                        when,
                        skipped_by: Vec::new(),
                        disabled_display: DisabledDisplay::Hidden,
                        doc_path: doc_i,
                        kind: NodeKind::Display(DisplayNode { id: d.id.clone(), role: d.role, text: d.text.clone(), media: d.media.clone() }),
                    });
                }
                Element::Group(g) => self.group(g, ctx, &doc_i),
            }
        }
    }

    fn group(&mut self, g: &'d Group, ctx: &Ctx, doc: &str) {
        let path = join(&ctx.prefix, &g.id);
        let depth = ctx.depth + 1;
        if depth > MAX_GROUP_DEPTH {
            self.f.error("INS-122", doc, format!("groups nest {depth} deep; the limit is {MAX_GROUP_DEPTH}"));
        }
        let when = g.when.as_ref().map(|w| self.resolve(&w.expr, ctx.repeat.as_ref(), &at(doc, "when")));
        let list = match &g.repeat {
            Some(r) => match self.def.code_lists.get(&r.over) {
                Some(l) => Some(l),
                None => {
                    self.f.error_of(FindingKind::UnknownItemPath, "INS-126", at(doc, "repeat.over"), format!("no code list `{}`", r.over));
                    return;
                }
            },
            None => None,
        };
        let node = self.add_node(Node {
            path: path.clone(),
            parent: ctx.parent,
            children: Vec::new(),
            when,
            skipped_by: Vec::new(),
            disabled_display: g.disabled_display,
            doc_path: doc.to_owned(),
            kind: NodeKind::Group(GroupNode {
                id: g.id.clone(),
                label: g.label.clone(),
                description: g.description.clone(),
                reference_period: g.reference_period.clone(),
                media: g.media.clone(),
                icon: None,
                concept: g.concept.clone(),
                repeat_over: g.repeat.as_ref().map(|r| r.over.clone()),
                instance_code: None,
            }),
        });
        let children_doc = at(doc, "elements");
        let (Some(repeat), Some(list)) = (&g.repeat, list) else {
            let inner = Ctx { prefix: path.clone(), parent: Some(node), depth, repeat: ctx.repeat.clone() };
            self.walk(&g.elements, &inner, &children_doc, None);
            for r in &g.rules {
                self.rules.push(Pending { def: r, scope: Some(node), scope_path: path.clone(), repeat: ctx.repeat.clone() });
            }
            for fc in &g.field_checks {
                self.checks.push(Pending { def: fc, scope: Some(node), scope_path: path.clone(), repeat: ctx.repeat.clone() });
            }
            return;
        };
        let siblings: BTreeSet<String> = g
            .elements
            .iter()
            .filter_map(|e| match e {
                Element::Question(q) if is_segment(&q.path) => Some(q.path.clone()),
                _ => None,
            })
            .collect();
        for (code, children) in &repeat.overrides {
            if !list.contains(code) {
                self.f.error("INS-128", at(&at(doc, "overrides"), code), format!("`{code}` is not a code of `{}`", repeat.over));
            }
            for child in children.keys() {
                let ok = g.elements.iter().any(|e| matches!(e, Element::Question(q) if q.path == *child && q.control.is_some()));
                if !ok {
                    self.f.error_of(FindingKind::UnknownItemPath, "INS-128", at(&at(&at(doc, "overrides"), code), child), format!("`{child}` is not a question of this repeat group"));
                }
            }
        }
        for code in &list.codes {
            if !is_segment(&code.code) {
                self.f.error("INS-126", at(doc, "repeat.over"), format!("code `{}` of `{}` is not a valid path segment, so it can't be repeated over", code.code, repeat.over));
                continue;
            }
            let instance_path = join(&path, &code.code);
            let instance = self.add_node(Node {
                path: instance_path.clone(),
                parent: Some(node),
                children: Vec::new(),
                when: None,
                skipped_by: Vec::new(),
                disabled_display: g.disabled_display,
                doc_path: doc.to_owned(),
                kind: NodeKind::Group(GroupNode {
                    id: code.code.clone(),
                    label: code.label.clone(),
                    description: code.description.clone(),
                    reference_period: g.reference_period.clone(),
                    media: code.media.clone(),
                    icon: code.icon.clone(),
                    concept: code.concept.clone(),
                    repeat_over: None,
                    instance_code: Some(code.code.clone()),
                }),
            });
            if let Some(other) = list.other.as_ref().filter(|o| o.code == code.code) {
                self.add_node(Node {
                    path: join(&instance_path, "other"),
                    parent: Some(instance),
                    children: Vec::new(),
                    when: None,
                    skipped_by: Vec::new(),
                    disabled_display: DisabledDisplay::Hidden,
                    doc_path: at(doc, "repeat.over"),
                    kind: NodeKind::Question(Box::new(text_question(other.label.clone(), other.max_length, true, QuestionOrigin::InstanceName))),
                });
            }
            let rctx = RepeatCtx { instance: instance_path.clone(), siblings: siblings.clone() };
            let inner = Ctx { prefix: instance_path.clone(), parent: Some(instance), depth, repeat: Some(rctx.clone()) };
            self.walk(&g.elements, &inner, &children_doc, repeat.overrides.get(&code.code));
            for r in &g.rules {
                self.rules.push(Pending { def: r, scope: Some(instance), scope_path: instance_path.clone(), repeat: Some(rctx.clone()) });
            }
            for fc in &g.field_checks {
                self.checks.push(Pending { def: fc, scope: Some(instance), scope_path: instance_path.clone(), repeat: Some(rctx.clone()) });
            }
        }
    }

    fn question(&mut self, q: &'d Question, ctx: &Ctx, doc: &str, ov: Option<&'d ControlOverride>) {
        let path = join(&ctx.prefix, &q.path);
        let mut control = q.control.clone();
        let mut data = q.data.clone();
        if let (Some(ov), Some(c)) = (ov, control.as_mut()) {
            apply_override(c, &mut data, ov, doc, &mut self.f);
        }
        let when = q.when.as_ref().map(|w| self.resolve(&w.expr, ctx.repeat.as_ref(), &at(doc, "when")));
        let nonresponse = if q.from_roster.is_some() {
            Vec::new()
        } else {
            q.nonresponse.clone().unwrap_or_else(|| self.def.default_nonresponse.clone())
        };
        let node = QuestionNode {
            label: q.label.clone(),
            prefix: q.prefix.clone(),
            short_label: q.short_label.clone(),
            help: q.help.clone(),
            guidance: q.guidance.clone(),
            control,
            data,
            nonresponse,
            optional: q.optional,
            from_roster: q.from_roster.clone(),
            record: q.record,
            concept: q.concept.clone(),
            media: q.media.clone(),
            origin: QuestionOrigin::Authored,
        };
        self.check_question(&node, doc);
        let other = self.other_of(&node);
        let multi = matches!(node.control, Some(Control::MultiChoice { .. }));
        self.add_node(Node {
            path: path.clone(),
            parent: ctx.parent,
            children: Vec::new(),
            when,
            skipped_by: Vec::new(),
            disabled_display: q.disabled_display,
            doc_path: doc.to_owned(),
            kind: NodeKind::Question(Box::new(node)),
        });
        if let Some((code, label, max)) = other {
            // INS-137: the text of the `other` code, shown when the code is chosen.
            let item = Expr::Path(PathRef::Item(path.clone()));
            let lit = Expr::Text(code);
            let when = if multi { Expr::Binary(BinOp::In, Box::new(lit), Box::new(item)) } else { Expr::Binary(BinOp::Eq, Box::new(item), Box::new(lit)) };
            self.add_node(Node {
                path: join(&path, "other"),
                parent: ctx.parent,
                children: Vec::new(),
                when: Some(when),
                skipped_by: Vec::new(),
                disabled_display: DisabledDisplay::Hidden,
                doc_path: doc.to_owned(),
                kind: NodeKind::Question(Box::new(text_question(label, max, false, QuestionOrigin::OtherText { of: path }))),
            });
        }
    }

    /// The `other` code, its label and maximum length, if the question can record one.
    fn other_of(&self, q: &QuestionNode) -> Option<(String, LocalisedText, u32)> {
        match q.control.as_ref()? {
            Control::CodedListWithOther { other_label, max_length, .. } => Some((OTHER_CODE.to_owned(), other_label.clone(), *max_length)),
            c => {
                let other = self.list(c.options()?)?.other.as_ref()?;
                Some((other.code.clone(), other.label.clone(), other.max_length))
            }
        }
    }

    fn check_question(&mut self, q: &QuestionNode, doc: &str) {
        let f = &mut self.f;
        let cdoc = at(doc, "control");
        let data_doc = at(doc, "data");
        let dt = q.data.data_type;
        let Some(control) = &q.control else { return };
        let allowed: &[DataType] = match control {
            Control::Choice { .. } | Control::Scale { .. } | Control::CodedListWithOther { .. } => &[DataType::Code],
            Control::MultiChoice { .. } => &[DataType::Codes],
            Control::Stepper(_) | Control::Number(_) | Control::MeasurementPair(_) => &[DataType::Integer, DataType::Decimal],
            Control::Money(_) => &[DataType::Money],
            Control::Text { .. } => &[DataType::String],
            Control::YesNo { .. } => &[DataType::Boolean],
            Control::Date { .. } => &[DataType::Date],
            Control::PhotoEvidence { .. } => &[DataType::Evidence],
        };
        if !allowed.contains(&dt) {
            let names: Vec<&str> = allowed.iter().map(|d| d.name()).collect();
            f.error("INS-070", at(&data_doc, "type"), format!("a `{}` control records {}, not `{}`", control.control_type().name(), names.join(" or "), dt.name()));
        }
        // Coded controls.
        if let Some(options) = control.options() {
            let key = if matches!(control, Control::Scale { .. }) { "steps" } else { "options" };
            match options {
                Options::Named(id) => match self.def.code_lists.get(id) {
                    None => f.error_of(FindingKind::UnknownItemPath, "INS-131", at(&cdoc, "codes"), format!("no code list `{id}`")),
                    Some(list) => {
                        if matches!(control, Control::Scale { .. }) && !list.ordered {
                            f.error("INS-135", at(&cdoc, "codes"), format!("a scale needs an `ordered: true` list; `{id}` is not ordered"));
                        }
                        if q.data.code_list.as_ref().is_some_and(|c| c != id) {
                            f.error("INS-070", at(&data_doc, "codeList"), format!("data.codeList must be the control's list `{id}`"));
                        }
                    }
                },
                Options::Inline(list) => {
                    if list.codes.is_empty() {
                        f.error("INS-131", at(&cdoc, key), "a coded control needs at least one option");
                    }
                    if q.data.code_list.is_some() {
                        f.error("INS-070", at(&data_doc, "codeList"), "data.codeList names a list, but the control's options are inline");
                    }
                }
            }
        }
        if let Control::MultiChoice { options, max: Some(max) } = control {
            let n = match options {
                Options::Inline(l) => Some(l.codes.len()),
                Options::Named(id) => self.def.code_lists.get(id).map(|l| l.codes.len()),
            };
            if *max == 0 || n.is_some_and(|n| *max as usize > n) {
                f.error("INS-025", at(&cdoc, "max"), "`max` must be between 1 and the number of codes");
            }
        }
        if let Control::CodedListWithOther { options, .. } = control
            && options.contains(OTHER_CODE) {
                f.error("INS-134", at(&cdoc, "options"), "options can't use the code `other`; it is the control's own other option");
            }
        // Units (INS-160, INS-161).
        if let Some(spec) = control.unit() {
            if spec.unit.needs_label() && spec.label.is_none() {
                f.error("INS-160", at(&cdoc, "unitLabel"), format!("unit `{}` isn't readable; give a localised unitLabel", spec.unit));
            }
            match &q.data.unit {
                Some(u) if *u != spec.unit => f.error("INS-070", at(&data_doc, "unit"), format!("data.unit `{u}` must be the control's unit `{}`", spec.unit)),
                _ => {}
            }
        }
        if control.unit().is_none()
            && let Some(u) = &q.data.unit {
                f.error("INS-070", at(&data_doc, "unit"), format!("data.unit `{u}` needs the control to record in that unit"));
            }
        if !control.entry_units().is_empty() {
            match control.unit() {
                None => f.error("INS-161", at(&cdoc, "entryUnits"), "entryUnits need a `unit` to convert to"),
                Some(spec) => {
                    for (i, u) in control.entry_units().iter().enumerate() {
                        if u.factor_to(&spec.unit).is_none() || u.is_annotation() || *u == spec.unit {
                            f.error("INS-161", idx(&at(&cdoc, "entryUnits"), i), format!("`{u}` can't be converted exactly to `{}`", spec.unit));
                        }
                    }
                }
            }
        }
        let num = |d: &Decimal| Num::from_decimal(*d);
        let range = |f: &mut Findings, min: Option<&Decimal>, max: Option<&Decimal>| {
            if let (Some(a), Some(b)) = (min.and_then(num), max.and_then(num))
                && a > b {
                    f.error("INS-027", at(&cdoc, "min"), "`min` is greater than `max`");
                }
        };
        let integral = |d: &Decimal| num(d).is_some_and(Num::is_integer);
        match control {
            Control::Stepper(s) => {
                range(f, Some(&s.min), Some(&s.max));
                let (min, max, start, step) = (num(&s.min), num(&s.max), num(&s.start), num(&s.step));
                if step.is_none_or(|s| s <= Num::ZERO) {
                    f.error("INS-163", at(&cdoc, "step"), "`step` must be greater than zero");
                }
                if let (Some(min), Some(max), Some(start)) = (min, max, start)
                    && (start < min || start > max) {
                        f.error("INS-163", at(&cdoc, "start"), "`start` must be within min..max");
                    }
                if dt == DataType::Integer && !(integral(&s.min) && integral(&s.max) && integral(&s.start) && integral(&s.step)) {
                    f.error("INS-070", at(&data_doc, "type"), "an integer stepper needs whole-number min, max, start and step");
                }
            }
            Control::Number(n) => {
                range(f, n.min.as_ref(), n.max.as_ref());
                if dt == DataType::Integer && n.decimals != 0 {
                    f.error("INS-070", at(&cdoc, "decimals"), "an integer has no decimals");
                }
            }
            Control::MeasurementPair(m) => {
                range(f, m.reading.min.as_ref(), m.reading.max.as_ref());
                if dt == DataType::Integer && m.reading.decimals != 0 {
                    f.error("INS-070", at(&cdoc, "decimals"), "an integer has no decimals");
                }
                if num(&m.tolerance).is_none_or(Num::is_negative) {
                    f.error("INS-026", at(&cdoc, "tolerance"), "`tolerance` must be zero or more");
                }
            }
            Control::Money(m) => {
                range(f, m.min.as_ref(), m.max.as_ref());
                let digits = m.currency.minor_digits();
                for (key, v) in [("min", &m.min), ("max", &m.max), ("step", &m.step)] {
                    if let Some(v) = v.as_ref().and_then(num)
                        && !v.fits_scale(digits) {
                            f.error("INS-162", at(&cdoc, key), format!("{} has at most {digits} minor-unit digits", m.currency.code()));
                        }
                }
                if m.step.as_ref().and_then(num).is_some_and(|s| s <= Num::ZERO) {
                    f.error("INS-163", at(&cdoc, "step"), "`step` must be greater than zero");
                }
                if m.min.as_ref().and_then(num).is_some_and(Num::is_negative) {
                    f.lint("INS-162", super::finding::Severity::Warning, at(&cdoc, "min"), "a negative amount of money is unusual");
                }
            }
            Control::Date { min, max } => {
                for (key, v) in [("min", min), ("max", max)] {
                    if v.as_ref().is_some_and(|d| !is_date(d)) {
                        f.error("INS-025", at(&cdoc, key), "a date must be YYYY-MM-DD");
                    }
                }
                if let (Some(a), Some(b)) = (min, max)
                    && is_date(a) && is_date(b) && a > b {
                        f.error("INS-025", at(&cdoc, "min"), "`min` is after `max`");
                    }
            }
            Control::PhotoEvidence { .. } if !self.def.consent.allows_evidence() => {
                f.error("INS-061", at(&cdoc, "type"), "photo-evidence needs a consent requirement that allows evidence");
            }
            _ => {}
        }
    }

    /// Derived paths must not collide with elements (INS-045).
    fn check_derived_paths(&mut self) {
        for (i, d) in self.def.derived.iter().enumerate() {
            if self.out.index.contains_key(&d.path) {
                self.f.error("INS-045", at(&idx("spec.derived", i), "path"), format!("`{}` is already an element's path", d.path));
            }
        }
    }

    fn compiled_id(scope_path: &str, id: &str) -> String {
        join(scope_path, id)
    }

    fn rule(&mut self, p: &Pending<'d, RuleDef>) {
        if self.out.rules.len() >= MAX_COMPILED_RULES {
            self.f.error_of(FindingKind::UnboundedRule, "INS-044", p.def.doc_path.clone(), format!("more than {MAX_COMPILED_RULES} compiled rules"));
            return;
        }
        let doc = &p.def.doc_path;
        let when = self.resolve(&p.def.when.expr, p.repeat.as_ref(), &at(doc, "when"));
        let id = Self::compiled_id(&p.scope_path, &p.def.id);
        if self.out.rules.iter().any(|r| r.id == id) {
            self.f.error("INS-049", at(doc, "id"), format!("the compiled rule id `{id}` is not unique"));
        }
        let index = self.out.rules.len();
        let mut refs_from = vec![when.clone()];
        let action = match &p.def.action {
            RuleAction::Hard { message } => CompiledAction::Hard { message: message.clone() },
            RuleAction::Soft { message, reasons } => CompiledAction::Soft { message: message.clone(), reasons: reasons.clone() },
            RuleAction::Skip { targets } => {
                let mut nodes = Vec::new();
                for (i, t) in targets.iter().enumerate() {
                    let tdoc = idx(&at(doc, "targets"), i);
                    let Some(path) = self.target_path(t, p.repeat.as_ref(), &tdoc) else { continue };
                    match self.out.index.get(&path) {
                        Some(&n) => {
                            nodes.push(n);
                            self.out.nodes[n].skipped_by.push(index);
                        }
                        None => self.f.error_of(FindingKind::UnknownItemPath, "INS-124", tdoc, format!("no element at `{path}`")),
                    }
                }
                CompiledAction::Skip { targets: nodes }
            }
            RuleAction::Derive { target, value } => {
                let value = self.resolve(&value.expr, p.repeat.as_ref(), &at(doc, "value"));
                refs_from.push(value.clone());
                let tdoc = at(doc, "target");
                let target = self.target_path(target, p.repeat.as_ref(), &tdoc).and_then(|path| {
                    let found = self.out.derived.iter().position(|d| d.path == path);
                    if found.is_none() {
                        self.f.error_of(FindingKind::UnknownItemPath, "INS-045", tdoc.clone(), format!("`{path}` is not declared in spec.derived"));
                    }
                    found
                });
                let Some(target) = target else { return };
                if let Some(other) = self.out.derived[target].rule {
                    let first = self.out.rules[other].doc_path.clone();
                    self.f.error("INS-045", tdoc, format!("`{}` is already computed by the rule at {first}", self.out.derived[target].path));
                } else {
                    self.out.derived[target].rule = Some(index);
                }
                CompiledAction::Derive { target, value }
            }
        };
        let mut refs = BTreeSet::new();
        let mut roster = BTreeSet::new();
        for e in &refs_from {
            for p in e.paths() {
                match p {
                    PathRef::Item(path) => {
                        refs.insert(path);
                    }
                    PathRef::Roster(field) => {
                        roster.insert(field);
                    }
                    PathRef::Sibling(_) => {}
                }
            }
        }
        self.out.rules.push(CompiledRule {
            id,
            rule_id: p.def.id.clone(),
            scope: p.scope,
            when,
            action,
            refs: refs.into_iter().collect(),
            roster_refs: roster.into_iter().collect(),
            doc_path: doc.clone(),
        });
    }

    fn target_path(&mut self, t: &PathRef, repeat: Option<&RepeatCtx>, doc: &str) -> Option<String> {
        match (t, repeat) {
            (PathRef::Item(p), _) => Some(p.clone()),
            (PathRef::Sibling(id), Some(r)) => Some(join(&r.instance, id)),
            (PathRef::Sibling(id), None) => {
                self.f.error_of(FindingKind::UnknownItemPath, "INS-047", doc, format!("`@{id}` is only allowed inside a repeat group"));
                None
            }
            (PathRef::Roster(_), _) => None,
        }
    }

    fn field_check(&mut self, p: &Pending<'d, FieldCheckDef>) {
        let doc = &p.def.doc_path;
        let id = Self::compiled_id(&p.scope_path, &p.def.id);
        if self.out.field_checks.iter().any(|c| c.id == id) {
            self.f.error("INS-050", at(doc, "id"), format!("the compiled field-check id `{id}` is not unique"));
        }
        let repeat = p.repeat.as_ref();
        let item = |c: &mut Self, t: &PathRef, key: &str, numeric: bool| -> PathRef {
            let pdoc = at(doc, key);
            let Some(path) = c.target_path(t, repeat, &pdoc) else { return t.clone() };
            let data = c.out.question(&path).map(|q| q.data.data_type).or_else(|| c.out.derived_value(&path).map(|d| d.data.data_type));
            match data {
                None => c.f.error_of(FindingKind::UnknownItemPath, "INS-050", pdoc, format!("no item at `{path}`")),
                Some(dt) if numeric && !dt.is_numeric() => c.f.error("INS-050", pdoc, format!("`{path}` is not numeric")),
                _ => {}
            }
            PathRef::Item(path)
        };
        let group = |c: &mut Self, t: &PathRef, key: &str| -> PathRef {
            let pdoc = at(doc, key);
            let Some(path) = c.target_path(t, repeat, &pdoc) else { return t.clone() };
            if !matches!(c.out.node(&path).map(|n| &n.kind), Some(NodeKind::Group(_))) {
                c.f.error_of(FindingKind::UnknownItemPath, "INS-050", pdoc, format!("no group at `{path}`"));
            }
            PathRef::Item(path)
        };
        let kind = match &p.def.kind {
            CheckKind::Distribution { path, expected, min_count, bound } => {
                CheckKind::Distribution { path: item(self, path, "path", true), expected: expected.clone(), min_count: *min_count, bound: *bound }
            }
            CheckKind::Drift { path, window, threshold } => CheckKind::Drift { path: item(self, path, "path", true), window: *window, threshold: *threshold },
            CheckKind::Duplicates { paths, min_match } => {
                CheckKind::Duplicates { paths: paths.iter().enumerate().map(|(i, t)| item(self, t, &format!("paths[{i}]"), false)).collect(), min_match: *min_match }
            }
            CheckKind::Timing { min_seconds, max_seconds } => CheckKind::Timing { min_seconds: *min_seconds, max_seconds: *max_seconds },
            CheckKind::Completeness { scope, threshold } => CheckKind::Completeness {
                scope: match scope {
                    CheckScopeDef::Group(s) => CheckScopeDef::Group(group(self, s, "group")),
                    CheckScopeDef::Paths(ps) => CheckScopeDef::Paths(ps.iter().enumerate().map(|(i, t)| item(self, t, &format!("paths[{i}]"), false)).collect()),
                },
                threshold: *threshold,
            },
            CheckKind::Straightlining { group: g, threshold } => CheckKind::Straightlining { group: group(self, g, "group"), threshold: *threshold },
        };
        self.out.field_checks.push(CompiledFieldCheck { id, check_id: p.def.id.clone(), kind, message: p.def.message.clone(), doc_path: doc.clone() });
    }

    fn type_check(&mut self) {
        let scope = Scope::new(self.def, &self.out);
        let mut findings = Findings::new();
        let report = |f: &mut Findings, errors: Vec<super::rules::CheckError>, doc: &str| {
            for e in errors {
                let (kind, req) = match e.kind {
                    CheckErrorKind::UnknownPath => (FindingKind::UnknownItemPath, "INS-040"),
                    CheckErrorKind::Invalid => (FindingKind::SchemaViolation, "INS-040"),
                    CheckErrorKind::UnknownTable => (FindingKind::UnknownItemPath, "INS-043"),
                    CheckErrorKind::DeriveInput => (FindingKind::SchemaViolation, "INS-045"),
                };
                f.error_of(kind, req, doc, e.message);
            }
        };
        let boolean = |f: &mut Findings, ty: &Ty, doc: &str| {
            if !matches!(ty, Ty::Bool | Ty::Any) {
                f.error("INS-040", doc, "a `when` must be true or false");
            }
        };
        for n in &self.out.nodes {
            if let Some(w) = &n.when {
                let (ty, errors) = check_expr(w, &scope, false);
                let doc = at(&n.doc_path, "when");
                report(&mut findings, errors, &doc);
                boolean(&mut findings, &ty, &doc);
            }
        }
        for r in &self.out.rules {
            let derive = matches!(r.action, CompiledAction::Derive { .. });
            let doc = at(&r.doc_path, "when");
            let (ty, errors) = check_expr(&r.when, &scope, derive);
            report(&mut findings, errors, &doc);
            boolean(&mut findings, &ty, &doc);
            if let CompiledAction::Derive { target, value } = &r.action {
                let doc = at(&r.doc_path, "value");
                let (ty, errors) = check_expr(value, &scope, true);
                report(&mut findings, errors, &doc);
                let want = data_ty(self.out.derived[*target].data.data_type, None);
                let ok = matches!((&ty, &want), (Ty::Any, _) | (_, Ty::Any))
                    || ty == want
                    || (matches!(ty, Ty::Text | Ty::Code(_)) && matches!(want, Ty::Text | Ty::Code(_)));
                if !ok {
                    findings.error("INS-045", doc, format!("the value doesn't match the derived value's data type `{}`", self.out.derived[*target].data.data_type.name()));
                }
            }
        }
        self.f.extend(findings);
    }

    /// Topologically orders visibility, skip and derive steps; reports cycles (INS-044).
    fn order(&mut self) {
        let mut steps: Vec<Step> = (0..self.out.nodes.len()).map(Step::Node).collect();
        for (i, r) in self.out.rules.iter().enumerate() {
            match r.action {
                CompiledAction::Skip { .. } => steps.push(Step::Skip(i)),
                CompiledAction::Derive { .. } => steps.push(Step::Derive(i)),
                _ => {}
            }
        }
        let position: BTreeMap<Step, usize> = steps.iter().enumerate().map(|(i, s)| (*s, i)).collect();
        let ref_step = |path: &str| -> Option<Step> {
            if let Some(&n) = self.out.index.get(path) {
                return Some(Step::Node(n));
            }
            let d = self.out.derived.iter().find(|d| d.path == path)?;
            d.rule.map(Step::Derive)
        };
        let expr_deps = |e: &Expr, out: &mut Vec<Step>| {
            for p in e.paths() {
                if let PathRef::Item(path) = p
                    && let Some(s) = ref_step(&path) {
                        out.push(s);
                    }
            }
        };
        let mut deps: Vec<Vec<Step>> = Vec::with_capacity(steps.len());
        for s in &steps {
            let mut d = Vec::new();
            match *s {
                Step::Node(i) => {
                    let n = &self.out.nodes[i];
                    if let Some(p) = n.parent {
                        d.push(Step::Node(p));
                    }
                    d.extend(n.skipped_by.iter().map(|k| Step::Skip(*k)));
                    if let Some(w) = &n.when {
                        expr_deps(w, &mut d);
                    }
                }
                Step::Skip(k) | Step::Derive(k) => {
                    let r = &self.out.rules[k];
                    if let Some(sc) = r.scope {
                        d.push(Step::Node(sc));
                    }
                    expr_deps(&r.when, &mut d);
                    if let CompiledAction::Derive { value, .. } = &r.action {
                        expr_deps(value, &mut d);
                    }
                }
            }
            deps.push(d);
        }
        let mut indegree = vec![0usize; steps.len()];
        let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); steps.len()];
        for (i, d) in deps.iter().enumerate() {
            let unique: BTreeSet<usize> = d.iter().filter_map(|s| position.get(s).copied()).collect();
            indegree[i] = unique.len();
            for j in unique {
                dependents[j].push(i);
            }
        }
        let mut ready: BTreeSet<usize> = (0..steps.len()).filter(|i| indegree[*i] == 0).collect();
        let mut order = Vec::with_capacity(steps.len());
        while let Some(i) = ready.pop_first() {
            order.push(steps[i]);
            for &j in &dependents[i] {
                indegree[j] -= 1;
                if indegree[j] == 0 {
                    ready.insert(j);
                }
            }
        }
        if order.len() < steps.len() {
            let stuck: Vec<String> = (0..steps.len())
                .filter(|i| indegree[*i] > 0)
                .map(|i| match steps[i] {
                    Step::Node(n) => self.out.nodes[n].path.clone(),
                    Step::Skip(k) | Step::Derive(k) => format!("rule {}", self.out.rules[k].id),
                })
                .take(6)
                .collect();
            let doc = (0..steps.len())
                .find(|i| indegree[*i] > 0)
                .map(|i| match steps[i] {
                    Step::Node(n) => at(&self.out.nodes[n].doc_path, "when"),
                    Step::Skip(k) | Step::Derive(k) => at(&self.out.rules[k].doc_path, "when"),
                })
                .unwrap_or_default();
            self.f.error_of(FindingKind::UnboundedRule, "INS-044", doc, format!("visibility or derived values depend on themselves: {}", stuck.join(", ")));
        }
        self.out.order = order;
    }
}

fn text_question(label: LocalisedText, max_length: u32, optional: bool, origin: QuestionOrigin) -> QuestionNode {
    QuestionNode {
        label,
        prefix: None,
        short_label: None,
        help: None,
        guidance: None,
        control: Some(Control::Text { max_length: Some(max_length), multiline: false }),
        data: DataSpec { data_type: DataType::String, unit: None, code_list: None, concept: Vec::new(), sensitivity: super::element::Sensitivity::Normal, description: None },
        nonresponse: Vec::new(),
        optional,
        from_roster: None,
        record: false,
        concept: Vec::new(),
        media: None,
        origin,
    }
}

fn apply_override(c: &mut Control, data: &mut DataSpec, ov: &ControlOverride, doc: &str, f: &mut Findings) {
    let odoc = at(doc, "control");
    let bad = |f: &mut Findings, key: &str| f.error("INS-128", at(&odoc, key), format!("this control has no `{key}` to override"));
    if let Some(unit) = &ov.unit {
        let spec = UnitSpec { unit: unit.clone(), label: ov.unit_label.clone() };
        match c {
            Control::Stepper(s) => s.unit = Some(spec),
            Control::Number(n) => n.unit = Some(spec),
            Control::MeasurementPair(m) => m.reading.unit = Some(spec),
            _ => bad(f, "unit"),
        }
        data.unit = Some(unit.clone());
    } else if let Some(label) = &ov.unit_label {
        let unit = match c {
            Control::Stepper(s) => s.unit.as_mut(),
            Control::Number(n) => n.unit.as_mut(),
            Control::MeasurementPair(m) => m.reading.unit.as_mut(),
            _ => None,
        };
        match unit {
            Some(u) => u.label = Some(label.clone()),
            None => bad(f, "unitLabel"),
        }
    }
    if let Some(step) = ov.step {
        match c {
            Control::Stepper(s) => s.step = step,
            Control::Money(m) => m.step = Some(step),
            _ => bad(f, "step"),
        }
    }
    for (key, v) in [("min", ov.min), ("max", ov.max)] {
        let Some(v) = v else { continue };
        let is_min = key == "min";
        match c {
            Control::Stepper(s) => *(if is_min { &mut s.min } else { &mut s.max }) = v,
            Control::Number(n) => *(if is_min { &mut n.min } else { &mut n.max }) = Some(v),
            Control::MeasurementPair(m) => *(if is_min { &mut m.reading.min } else { &mut m.reading.max }) = Some(v),
            Control::Money(m) => *(if is_min { &mut m.min } else { &mut m.max }) = Some(v),
            _ => bad(f, key),
        }
    }
}

/// The rule-language type of a data type, with the codes of its list.
pub(crate) fn data_ty(dt: DataType, codes: Option<Rc<BTreeSet<String>>>) -> Ty {
    match dt {
        DataType::Code => codes.map_or(Ty::Text, Ty::Code),
        DataType::Codes => codes.map_or(Ty::List(Box::new(Ty::Text)), Ty::Codes),
        DataType::Integer | DataType::Decimal | DataType::Money => Ty::Num,
        DataType::String => Ty::Text,
        DataType::Boolean => Ty::Bool,
        DataType::Date => Ty::Date,
        DataType::Evidence => Ty::Evidence,
    }
}

/// The [`CheckScope`] of a compiled instrument.
pub(crate) struct Scope<'a> {
    def: &'a InstrumentDefinition,
    out: &'a CompiledInstrument,
    codes: BTreeMap<String, Rc<BTreeSet<String>>>,
}

impl<'a> Scope<'a> {
    pub(crate) fn new(def: &'a InstrumentDefinition, out: &'a CompiledInstrument) -> Self {
        let codes = def.code_lists.iter().map(|(k, l)| (k.clone(), Rc::new(l.codes.iter().map(|c| c.code.clone()).collect()))).collect();
        Self { def, out, codes }
    }

    fn question_codes(&self, q: &QuestionNode) -> (Option<Rc<BTreeSet<String>>>, bool) {
        match q.control.as_ref() {
            Some(Control::CodedListWithOther { options, .. }) => {
                let mut set: BTreeSet<String> = options.codes.iter().map(|c| c.code.clone()).collect();
                set.insert(OTHER_CODE.to_owned());
                (Some(Rc::new(set)), options.codes.iter().any(|c| c.value.is_some()))
            }
            Some(c) => match c.options() {
                Some(Options::Named(id)) => {
                    let values = self.def.code_lists.get(id).is_some_and(|l| l.codes.iter().any(|c| c.value.is_some()));
                    (self.codes.get(id).cloned(), values)
                }
                Some(Options::Inline(l)) => (Some(Rc::new(l.codes.iter().map(|c| c.code.clone()).collect())), l.codes.iter().any(|c| c.value.is_some())),
                None => (None, false),
            },
            None => (None, false),
        }
    }
}

impl CheckScope for Scope<'_> {
    fn path(&self, path: &str) -> Option<PathInfo> {
        if let Some(q) = self.out.question(path) {
            let (codes, coded_values) = self.question_codes(q);
            return Some(PathInfo::Question { ty: data_ty(q.data.data_type, codes), nonresponse: !q.nonresponse.is_empty(), coded_values });
        }
        self.out.derived_value(path).map(|d| PathInfo::Derived(data_ty(d.data.data_type, None)))
    }

    fn table(&self, name: &str) -> Option<TableShape> {
        let table = self.def.tables.get(name)?;
        let ty = |v: &super::rules::Val| match v {
            super::rules::Val::Num(_) => Ty::Num,
            super::rules::Val::Text(_) => Ty::Text,
            super::rules::Val::Bool(_) => Ty::Bool,
            _ => Ty::Any,
        };
        let (k, v) = table.rows.first().map_or((Ty::Any, Ty::Any), |(k, v)| (ty(k), ty(v)));
        Some(TableShape { keys: vec![k], value: v })
    }
}
