//! `CompileRenderPlan` and `ResolveVisibility` (INS §3, INS-206–INS-208).
//!
//! The plan's node types are documented in [`crate::domain::render_plan`].

use fieldseal_kernel::id::ContentAddress;

use super::layout::default_layout;
use crate::domain::codes::{CodeList, MediaRef};
use crate::domain::compiled::{CompiledInstrument, NodeKind, QuestionOrigin};
use crate::domain::control::{Control, MoneyPresentation, Options, ScalePresentation, UnitSpec, YesNoPresentation};
use crate::domain::element::DisabledDisplay;
use crate::domain::evaluation::{RecordInput, Visibility, evaluate_record};
use crate::domain::language::{LanguageTag, lookup};
use crate::domain::layout::{Content, Layout, Presentation, RepeatAs, WindowClass};
use crate::domain::metadata::Administration;
use crate::domain::render_plan::*;
use crate::domain::rules::EvaluationLimitExceeded;
use crate::domain::text::LocalisedText;
use crate::domain::Instrument;

/// The layout a plan is compiled from.
#[derive(Clone, Copy, Debug)]
pub enum PlanLayout<'a> {
    /// The generated default layout (INS-206).
    Default,
    /// A validated layout, with the content address the format core computed for it.
    Layout {
        /// The layout.
        layout: &'a Layout,
        /// Its content address (INS-209).
        address: ContentAddress,
    },
}

/// The locale and window a plan is compiled for.
#[derive(Clone, Copy, Debug)]
pub struct PlanRequest<'a> {
    /// The collector's chosen languages, most preferred first, as BCP 47 language ranges.
    /// RFC 4647 lookup picks the instrument language, falling back to its default (INS-087).
    pub languages: &'a [&'a str],
    /// The device's current window class (INS-207).
    pub window_class: WindowClass,
}

/// Why a plan couldn't be compiled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    /// The layout was validated against a different instrument: its questions differ.
    #[error("the layout was validated against a different instrument")]
    LayoutMismatch,
}

/// `CompileRenderPlan`: the render plan for `instrument` with `layout`, in the language and
/// window class of `request`. Pure and deterministic: the same inputs give the same plan
/// on every platform (INS-208).
pub fn compile_render_plan(instrument: &Instrument, layout: PlanLayout<'_>, request: PlanRequest<'_>) -> Result<RenderPlan, PlanError> {
    let def = instrument.definition();
    let compiled = instrument.compiled();
    let generated;
    let (layout, identity) = match layout {
        PlanLayout::Default => {
            generated = default_layout(instrument);
            (&generated, LayoutIdentity::Default)
        }
        PlanLayout::Layout { layout, address } => (layout, LayoutIdentity::Address(address)),
    };
    if !layout.questions.iter().map(String::as_str).eq(compiled.questions().map(|(p, _)| p)) {
        return Err(PlanError::LayoutMismatch);
    }
    let language = lookup(request.languages, &def.languages.languages, &def.languages.default).clone();
    let b = Builder { ins: instrument, c: compiled, lang: &language, default: &def.languages.default, self_admin: def.metadata.administration == Administration::SelfAdministered };
    let mut steps: Vec<PlanNode> = layout
        .steps()
        .iter()
        .map(|s| {
            let children = b.contents(&s.contents);
            container(PlanKind::Step { title: b.text(&s.title), navigation: s.navigation, emphasis: s.emphasis }, children, &s.doc_path)
        })
        .collect();
    if layout.is_default() {
        steps.push(container(PlanKind::Review, Vec::new(), "default.review"));
    }
    let mut next = 0;
    for s in &mut steps {
        number(s, &mut next);
    }
    Ok(RenderPlan {
        instrument: PlanInstrument {
            name: def.name.clone(),
            version: def.version.to_string(),
            title: b.text(&def.metadata.title),
            administration: match def.metadata.administration {
                Administration::Interviewer => "interviewer",
                Administration::SelfAdministered => "self",
                Administration::Both => "both",
            },
        },
        direction: language.direction(),
        language,
        window_class: request.window_class,
        layout_window_class: layout.window_class(),
        layout: identity,
        steps,
    })
}

/// `ResolveVisibility`: each node of `plan` (compiled from `instrument`) visible, protected or
/// hidden for the record's current values, using the instrument's rules (INS-124, INS-125).
/// A bound node takes its path's visibility; a container from the layout is visible if any
/// child is, else protected if any child is, else hidden.
pub fn resolve_visibility(instrument: &Instrument, plan: &RenderPlan, input: RecordInput<'_>) -> Result<PlanVisibility, EvaluationLimitExceeded> {
    let evaluation = evaluate_record(instrument, input)?;
    let mut nodes = vec![Visibility::Visible; plan.node_count()];
    fn resolve(n: &PlanNode, e: &crate::domain::Evaluation, out: &mut [Visibility]) -> Visibility {
        let children: Vec<Visibility> = n.children.iter().map(|c| resolve(c, e, out)).collect();
        let v = match &n.bind {
            Some(path) => e.visibility_of(path).unwrap_or(Visibility::Visible),
            None if children.is_empty() => Visibility::Visible,
            None if children.contains(&Visibility::Visible) => Visibility::Visible,
            None if children.contains(&Visibility::Protected) => Visibility::Protected,
            None => Visibility::Hidden,
        };
        out[n.id] = v;
        v
    }
    for s in &plan.steps {
        resolve(s, &evaluation, &mut nodes);
    }
    Ok(PlanVisibility { nodes })
}

fn container(kind: PlanKind, children: Vec<PlanNode>, source: &str) -> PlanNode {
    PlanNode { id: 0, bind: None, disabled_display: DisabledDisplay::Hidden, kind, children, source: source.to_owned() }
}

fn number(n: &mut PlanNode, next: &mut usize) {
    n.id = *next;
    *next += 1;
    for c in &mut n.children {
        number(c, next);
    }
}

struct Builder<'a> {
    ins: &'a Instrument,
    c: &'a CompiledInstrument,
    lang: &'a LanguageTag,
    default: &'a LanguageTag,
    self_admin: bool,
}

impl Builder<'_> {
    fn text(&self, t: &LocalisedText) -> PlanText {
        let text = t.get(self.lang).or_else(|| t.get(self.default)).unwrap_or_default().to_owned();
        PlanText { text, variables: t.variables().iter().cloned().collect() }
    }

    fn opt_text(&self, t: Option<&LocalisedText>) -> Option<PlanText> {
        t.map(|t| self.text(t))
    }

    fn media(&self, m: Option<&MediaRef>) -> Option<PlanMedia> {
        let id = match m? {
            MediaRef::Same(id) => id,
            MediaRef::PerLanguage(by) => by.get(self.lang).or_else(|| by.get(self.default))?,
        };
        let asset = self.ins.definition().media.get(id)?;
        Some(PlanMedia { id: id.clone(), media_type: asset.media_type.clone(), sha256: asset.sha256.clone(), alt: self.text(&asset.alt) })
    }

    fn list<'l>(&'l self, o: &'l Options) -> Option<&'l CodeList> {
        match o {
            Options::Inline(l) => Some(l),
            Options::Named(id) => self.ins.code_list(id),
        }
    }

    fn options(&self, list: Option<&CodeList>) -> Vec<PlanOption> {
        list.map(|l| {
            l.codes
                .iter()
                .map(|c| PlanOption {
                    code: c.code.clone(),
                    label: self.text(&c.label),
                    description: self.opt_text(c.description.as_ref()),
                    icon: c.icon.clone(),
                    media: self.media(c.media.as_ref()),
                    exclusive: c.exclusive,
                })
                .collect()
        })
        .unwrap_or_default()
    }

    fn other(&self, list: Option<&CodeList>) -> Option<PlanOther> {
        let o = list?.other.as_ref()?;
        Some(PlanOther { code: o.code.clone(), label: self.text(&o.label), max_length: o.max_length })
    }

    fn unit(&self, u: Option<&UnitSpec>) -> Option<PlanUnit> {
        u.map(|u| PlanUnit { code: u.unit.as_str().to_owned(), label: self.opt_text(u.label.as_ref()) })
    }

    fn control(&self, c: &Control) -> PlanControl {
        match c {
            Control::Choice { options } => {
                let l = self.list(options);
                PlanControl::Choice { options: self.options(l), other: self.other(l) }
            }
            Control::MultiChoice { options, max } => {
                let l = self.list(options);
                PlanControl::MultiChoice { options: self.options(l), other: self.other(l), max: *max }
            }
            Control::Scale { steps, .. } => PlanControl::Scale { steps: self.options(self.list(steps)) },
            Control::Stepper(s) => PlanControl::Stepper { min: s.min, max: s.max, start: s.start, step: s.step, unit: self.unit(s.unit.as_ref()) },
            Control::Number(n) => PlanControl::Number {
                min: n.min,
                max: n.max,
                decimals: n.decimals,
                unit: self.unit(n.unit.as_ref()),
                entry_units: n.entry_units.iter().map(|u| u.as_str().to_owned()).collect(),
            },
            Control::Money(m) => PlanControl::Money { currency: m.currency.code().to_owned(), minor_digits: m.currency.minor_digits(), min: m.min, max: m.max, step: m.step },
            Control::MeasurementPair(m) => PlanControl::MeasurementPair {
                min: m.reading.min,
                max: m.reading.max,
                decimals: m.reading.decimals,
                unit: self.unit(m.reading.unit.as_ref()),
                entry_units: m.reading.entry_units.iter().map(|u| u.as_str().to_owned()).collect(),
                tolerance: m.tolerance,
            },
            Control::Text { max_length, multiline } => PlanControl::Text { max_length: *max_length, multiline: *multiline },
            Control::CodedListWithOther { options, other_label, max_length } => PlanControl::CodedListWithOther {
                options: self.options(Some(options)),
                other: PlanOther { code: crate::domain::control::OTHER_CODE.to_owned(), label: self.text(other_label), max_length: *max_length },
            },
            Control::YesNo { .. } => PlanControl::YesNo,
            Control::Date { min, max } => PlanControl::Date { min: min.clone(), max: max.clone() },
            Control::PhotoEvidence { max_dimension } => PlanControl::PhotoEvidence { max_dimension: *max_dimension },
        }
    }

    /// The path of `i` relative to its nearest repeat instance.
    fn column(&self, i: usize) -> Option<String> {
        let path = &self.c.nodes()[i].path;
        let mut cur = self.c.nodes()[i].parent;
        while let Some(p) = cur {
            let n = &self.c.nodes()[p];
            if matches!(&n.kind, NodeKind::Group(g) if g.instance_code.is_some()) {
                return path.strip_prefix(&format!("{}.", n.path)).map(str::to_owned);
            }
            cur = n.parent;
        }
        None
    }

    fn heading(&self, i: usize) -> PlanHeading {
        let NodeKind::Group(g) = &self.c.nodes()[i].kind else { unreachable!("headings come from groups") };
        PlanHeading {
            label: self.text(&g.label),
            description: self.opt_text(g.description.as_ref()),
            reference_period: self.opt_text(g.reference_period.as_ref()),
            media: self.media(g.media.as_ref()),
            icon: g.icon.clone(),
        }
    }

    fn bound(&self, i: usize, kind: PlanKind, children: Vec<PlanNode>, source: &str) -> PlanNode {
        let n = &self.c.nodes()[i];
        PlanNode { id: 0, bind: Some(n.path.clone()), disabled_display: n.disabled_display, kind, children, source: source.to_owned() }
    }

    fn question(&self, i: usize, presentation: Option<Presentation>, source: &str) -> PlanNode {
        let Some(q) = self.c.nodes()[i].question() else { unreachable!("a question node") };
        let own = match &q.control {
            Some(Control::Scale { presentation: Some(p), .. }) => Some(match p {
                ScalePresentation::Slider => Presentation::Slider,
                ScalePresentation::Segments => Presentation::Segments,
            }),
            Some(Control::YesNo { presentation: Some(p) }) => Some(match p {
                YesNoPresentation::Switch => Presentation::Switch,
                YesNoPresentation::Buttons => Presentation::Buttons,
            }),
            Some(Control::Money(m)) => m.presentation.map(|p| match p {
                MoneyPresentation::Stepper => Presentation::Stepper,
                MoneyPresentation::Entry => Presentation::Entry,
            }),
            _ => None,
        };
        let plan = PlanQuestion {
            label: self.text(&q.label),
            prefix: q.prefix.clone(),
            short_label: self.opt_text(q.short_label.as_ref()),
            help: self.opt_text(q.help.as_ref()),
            guidance: if self.self_admin { None } else { self.opt_text(q.guidance.as_ref()) },
            media: self.media(q.media.as_ref()),
            control: q.control.as_ref().map(|c| self.control(c)),
            presentation: presentation.or(own),
            roster_field: q.from_roster.clone(),
            data_type: q.data.data_type,
            nonresponse: q.nonresponse.clone(),
            optional: q.optional,
            origin: match &q.origin {
                QuestionOrigin::Authored => PlanOrigin::Authored,
                QuestionOrigin::OtherText { of } => PlanOrigin::OtherText { of: of.clone() },
                QuestionOrigin::InstanceName => PlanOrigin::InstanceName,
            },
            column: self.column(i),
        };
        self.bound(i, PlanKind::Question(Box::new(plan)), Vec::new(), source)
    }

    /// A node of the instrument laid out as the default layout lays it out (INS-201).
    fn node(&self, i: usize, source: &str) -> PlanNode {
        let n = &self.c.nodes()[i];
        match &n.kind {
            NodeKind::Question(_) => self.question(i, None, source),
            NodeKind::Display(d) => self.bound(
                i,
                PlanKind::Display { role: d.role, text: self.opt_text(d.text.as_ref()), media: self.media(d.media.as_ref()) },
                Vec::new(),
                source,
            ),
            NodeKind::Group(g) if g.repeat_over.is_some() => self.repeat(i, RepeatAs::List, source),
            NodeKind::Group(g) if g.instance_code.is_some() => {
                let code = g.instance_code.clone().unwrap_or_default();
                self.bound(i, PlanKind::Instance { code, heading: self.heading(i) }, self.children(i, source), source)
            }
            NodeKind::Group(_) => self.bound(i, PlanKind::Group(self.heading(i)), self.children(i, source), source),
        }
    }

    fn children(&self, i: usize, source: &str) -> Vec<PlanNode> {
        self.c.nodes()[i].children.iter().map(|&c| self.node(c, source)).collect()
    }

    fn repeat(&self, i: usize, repeat_as: RepeatAs, source: &str) -> PlanNode {
        let instances = self.children(i, source);
        let heading = self.heading(i);
        let kind = match repeat_as {
            RepeatAs::List => PlanKind::List(heading),
            RepeatAs::Table => {
                let mut columns: Vec<PlanColumn> = Vec::new();
                for inst in &instances {
                    for n in inst.walk() {
                        let Some(q) = n.question() else { continue };
                        let Some(key) = &q.column else { continue };
                        if q.origin == PlanOrigin::InstanceName || columns.iter().any(|c| c.key == *key) {
                            continue;
                        }
                        columns.push(PlanColumn { key: key.clone(), label: q.label.clone(), prefix: q.prefix.clone() });
                    }
                }
                PlanKind::Table { heading, columns }
            }
        };
        self.bound(i, kind, instances, source)
    }

    fn contents(&self, contents: &[Content]) -> Vec<PlanNode> {
        let mut out = Vec::new();
        for c in contents {
            match c {
                Content::Element { path, presentation, doc_path } => {
                    let Some(i) = self.c.node_index(path) else { continue };
                    match &self.c.nodes()[i].kind {
                        NodeKind::Question(_) => {
                            out.push(self.question(i, *presentation, doc_path));
                            let other = format!("{path}.other");
                            if let Some(o) = self.c.node_index(&other)
                                && matches!(self.c.nodes()[o].question().map(|q| &q.origin), Some(QuestionOrigin::OtherText { .. }))
                            {
                                out.push(self.question(o, None, doc_path));
                            }
                        }
                        _ => out.push(self.node(i, doc_path)),
                    }
                }
                Content::Group { path, doc_path } => {
                    if let Some(i) = self.c.node_index(path) {
                        out.push(self.node(i, doc_path));
                    }
                }
                Content::Repeat { path, repeat_as, doc_path } => {
                    if let Some(i) = self.c.node_index(path) {
                        out.push(self.repeat(i, *repeat_as, doc_path));
                    }
                }
                Content::Tabs { tabs, doc_path } => {
                    let children = tabs
                        .iter()
                        .map(|t| {
                            let title = t.title.as_ref().map(|t| self.text(t)).unwrap_or(PlanText { text: String::new(), variables: Vec::new() });
                            container(PlanKind::Tab { title, icon: t.icon.clone(), emphasis: t.emphasis }, self.contents(&t.contents), &t.doc_path)
                        })
                        .collect();
                    out.push(container(PlanKind::Tabs, children, doc_path));
                }
                Content::Card(card) => out.push(container(
                    PlanKind::Card { title: card.title.as_ref().map(|t| self.text(t)), icon: card.icon.clone(), emphasis: card.emphasis },
                    self.contents(&card.contents),
                    &card.doc_path,
                )),
                Content::Row(row) => out.push(container(PlanKind::Row { emphasis: row.emphasis }, self.contents(&row.contents), &row.doc_path)),
            }
        }
        out
    }
}
