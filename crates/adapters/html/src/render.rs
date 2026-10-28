//! Drawing the plan, node by node, in plan order.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use fieldseal_instrument::domain::codes::Nonresponse;
use fieldseal_instrument::domain::element::DisplayRole;
use fieldseal_instrument::domain::layout::Emphasis;
use fieldseal_instrument::domain::locale::LocaleFormatter;
use fieldseal_instrument::domain::render_plan::{
    PlanColumn, PlanControl, PlanHeading, PlanMedia, PlanOption, PlanOrigin, PlanQuestion, PlanText, PlanUnit, display_role_name,
};
use fieldseal_instrument::domain::{LayoutIdentity, PlanKind, PlanNode, Visibility};
use fieldseal_kernel::{Decimal, Value};

use crate::escape::{attr, base64, multiline, text};
use crate::message::{Segment, segments};
use crate::strings::{Strings, fill, for_language};
use crate::{Page, SCRIPT, STYLE};

/// The media types a page may embed (INS-180).
const MEDIA_TYPES: [&str; 3] = ["image/png", "image/webp", "image/svg+xml"];

pub(crate) fn page(p: &Page<'_>) -> String {
    let mut r = R {
        p,
        s: for_language(p.plan.language.as_str()),
        loc: LocaleFormatter::new(p.plan.language.as_str()),
        out: String::with_capacity(64 * 1024),
        disabled: false,
        row_label: None,
        list_period: None,
    };
    r.document();
    r.out
}

/// How a question is drawn.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// On its own, with its label.
    Block,
    /// In a table cell: the label is the column heading, read with the row's heading.
    Cell,
}

struct R<'a> {
    p: &'a Page<'a>,
    s: &'static Strings,
    /// CLDR formatting for the plan's language (INS-088).
    loc: LocaleFormatter,
    out: String,
    /// Inside a protected node: every control is disabled (INS-125).
    disabled: bool,
    /// The id of the current table row's heading, for cell labels.
    row_label: Option<String>,
    /// The reference period of the list or table being drawn: its instances don't repeat it.
    list_period: Option<PlanText>,
}

/// How a value becomes text.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Show {
    /// Locale-free (`1234.5`): for matching message variants.
    Raw,
    /// For reading: grouped, in the locale's digits.
    Display,
    /// For a field the collector types in: the locale's digits and decimal separator, ungrouped.
    Input,
}

fn level(l: u8) -> u8 {
    l.clamp(2, 6)
}

impl R<'_> {
    fn w(&mut self, s: &str) {
        self.out.push_str(s);
    }

    fn vis(&self, id: usize) -> Visibility {
        self.p.visibility.map_or(Visibility::Visible, |v| v.of(id))
    }

    fn dis(&self) -> &'static str {
        if self.disabled { " disabled" } else { "" }
    }

    /// ` data-node="…" data-bind="…"` for a node.
    fn node_attrs(&self, n: &PlanNode) -> String {
        let mut a = format!(" data-node=\"{}\"", n.id);
        if let Some(b) = &n.bind {
            let _ = write!(a, " data-bind=\"{}\"", attr(b));
        }
        a
    }

    fn protected_class(&self, n: &PlanNode) -> &'static str {
        if self.vis(n.id) == Visibility::Protected { " is-protected" } else { "" }
    }

    fn protected_badge(&self, n: &PlanNode) -> String {
        if self.vis(n.id) == Visibility::Protected { format!(" <span class=\"badge\">{}</span>", text(self.s.protected)) } else { String::new() }
    }

    // ---- texts and values ---------------------------------------------------------------

    /// A variable's value for display, if one was supplied: `roster.<field>` from the roster,
    /// else the record value at that item path.
    fn variable(&self, name: &str) -> Option<String> {
        self.variable_as(name, Show::Display)
    }

    fn variable_as(&self, name: &str, show: Show) -> Option<String> {
        let v = match name.strip_prefix("roster.") {
            Some(field) => self.p.roster.get(field),
            None => self.p.values.get(name),
        }?;
        self.text_of(v, show)
    }

    /// A value for display.
    fn value_text(&self, v: &Value) -> Option<String> {
        self.text_of(v, Show::Display)
    }

    fn text_of(&self, v: &Value, show: Show) -> Option<String> {
        let number = |d: Decimal| match show {
            Show::Raw => d.to_string(),
            Show::Display => self.loc.number(d),
            Show::Input => self.loc.input_number(d),
        };
        Some(match v {
            Value::Text(t) => t.clone(),
            Value::Int(i) => number(Decimal { mantissa: *i, exponent: 0 }),
            Value::Decimal(d) => number(*d),
            Value::Bool(b) => (if *b { self.s.yes } else { self.s.no }).to_owned(),
            Value::Array(a) => a.iter().filter_map(|x| self.text_of(x, show)).collect::<Vec<_>>().join(", "),
            Value::Map(m) => match m.get("nr").and_then(Value::as_text).and_then(Nonresponse::from_code) {
                Some(nr) => self.nr_label(nr).to_owned(),
                None => return None,
            },
            _ => return None,
        })
    }

    /// The CLDR plural category of a locale-free number given as text (INS-088).
    fn plural_of(&self, raw: &str) -> Option<&'static str> {
        Decimal::parse(raw).ok().map(|d| self.loc.plural(d).name())
    }

    /// A message cut into segments, with variants chosen by exact value, then plural category.
    fn cut(&self, message: &str) -> Vec<Segment> {
        segments(message, &|n| self.variable_as(n, Show::Raw), &|v| self.plural_of(v))
    }

    /// A whole number for display (counts, step numbers).
    fn count(&self, n: impl Into<i128>) -> String {
        self.loc.number(Decimal { mantissa: n.into(), exponent: 0 })
    }

    /// A plan text as HTML: escaped, line breaks kept, variables shown as their value or as a
    /// `<var>` placeholder.
    fn t(&self, pt: &PlanText) -> String {
        if pt.variables.is_empty() {
            return multiline(&pt.text);
        }
        let mut out = String::new();
        for seg in self.cut(&pt.text) {
            match seg {
                Segment::Literal(l) => out.push_str(&multiline(&l)),
                Segment::Variable(name) => match self.variable(&name) {
                    Some(v) => {
                        let _ = write!(out, "<bdi class=\"value\">{}</bdi>", text(&v));
                    }
                    None => {
                        let _ = write!(out, "<var>{}</var>", text(&name));
                    }
                },
            }
        }
        out
    }

    /// A plan text as plain text (for `<title>`, `alt` and attributes; the caller escapes).
    fn plain(&self, pt: &PlanText) -> String {
        if pt.variables.is_empty() {
            return pt.text.clone();
        }
        self.cut(&pt.text)
            .into_iter()
            .map(|seg| match seg {
                Segment::Literal(l) => l,
                Segment::Variable(name) => self.variable(&name).unwrap_or_else(|| format!("{{{name}}}")),
            })
            .collect()
    }

    fn nr_label(&self, nr: Nonresponse) -> &'static str {
        match nr {
            Nonresponse::DontKnow => self.s.dont_know,
            Nonresponse::Refused => self.s.refused,
        }
    }

    fn img(&self, m: &PlanMedia) -> String {
        let alt = attr(&self.plain(&m.alt));
        match self.p.instrument.definition().media.get(&m.id) {
            Some(asset) if MEDIA_TYPES.contains(&asset.media_type.as_str()) && asset.media_type == m.media_type => {
                format!("<img src=\"data:{};base64,{}\" alt=\"{alt}\" decoding=\"async\">", attr(&asset.media_type), base64(&asset.bytes))
            }
            _ => format!("<span class=\"media-missing\">{alt}</span>"),
        }
    }

    fn figure(&mut self, m: Option<&PlanMedia>) {
        if let Some(m) = m {
            let img = self.img(m);
            self.w(&format!("<figure>{img}</figure>"));
        }
    }

    fn icon(icon: Option<&str>) -> String {
        icon.map(|i| format!("<span class=\"icon\" aria-hidden=\"true\">{}</span>", text(i))).unwrap_or_default()
    }

    fn value_of(&self, n: &PlanNode) -> Option<&Value> {
        self.p.values.get(n.bind.as_deref()?)
    }

    // ---- document -----------------------------------------------------------------------

    fn document(&mut self) {
        let plan = self.p.plan;
        let title = self.plain(&plan.instrument.title);
        let steps: Vec<&PlanNode> = plan.steps.iter().filter(|s| self.vis(s.id) != Visibility::Hidden).collect();
        let csp = format!(
            "default-src 'none'; img-src data:; font-src data:; style-src 'sha256-{}'; script-src 'sha256-{}'; form-action 'none'; base-uri 'none'",
            base64(fieldseal_kernel::digest::sha256(STYLE.as_bytes()).as_bytes()),
            base64(fieldseal_kernel::digest::sha256(SCRIPT.as_bytes()).as_bytes()),
        );
        // The language's number symbols, for the script that reads typed numbers (INS-088).
        let numbers = format!(
            " data-digits=\"{}\" data-decimal=\"{}\" data-group=\"{}\" data-minus=\"{}\" data-msg-number=\"{}\" data-msg-decimals=\"{}\" data-msg-step=\"{}\"",
            attr(&self.loc.digits().iter().collect::<String>()),
            attr(self.loc.decimal_separator()),
            attr(self.loc.grouping_separator()),
            attr(self.loc.minus_sign()),
            attr(self.s.not_a_number),
            attr(self.s.decimals_max),
            attr(self.s.on_step),
        );
        let _ = write!(
            self.out,
            "<!DOCTYPE html>\n<html lang=\"{}\" dir=\"{}\" class=\"no-js\">\n<head>\n<meta charset=\"utf-8\">\n\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
             <meta http-equiv=\"Content-Security-Policy\" content=\"{csp}\">\n\
             <meta name=\"color-scheme\" content=\"light\">\n<meta name=\"generator\" content=\"fieldseal\">\n\
             <title>{}</title>\n<style>{STYLE}</style>\n</head>\n<body class=\"wc-{}\"{numbers}>\n<div class=\"page\">\n",
            attr(plan.language.as_str()),
            plan.direction.name(),
            text(&title),
            plan.window_class.name(),
        );

        // Header: the instrument's labels and how this plan was compiled.
        let layout = match plan.layout {
            LayoutIdentity::Default => text(self.s.default_layout),
            LayoutIdentity::Address(a) => {
                let full = a.to_text();
                format!("<code title=\"{}\">{}…</code>", attr(&full), text(&full[..19]))
            }
        };
        let fingerprint = self
            .p
            .fingerprint
            .map(|f| format!(" <code class=\"fingerprint\" title=\"{}\">{}</code>", attr(self.s.fingerprint), text(f)))
            .unwrap_or_default();
        let _ = write!(
            self.out,
            "<div class=\"bar\">\n<header class=\"top\">\n<p class=\"banner\">{}</p>\n<h1>{}</h1>\n<p class=\"meta\"><span>{} {}{fingerprint}</span><span>{}: {layout}</span><span>{} · {}</span></p>\n</header>\n",
            text(self.s.preview),
            self.t(&plan.instrument.title),
            text(&plan.instrument.name),
            text(&plan.instrument.version),
            text(self.s.layout),
            text(plan.language.as_str()),
            plan.window_class.name(),
        );

        // The stepper: links work without script (every step is shown), and switch steps with it.
        let _ = write!(self.out, "<nav class=\"stepper\" aria-label=\"{}\">\n<ol>\n", attr(self.s.progress));
        for (k, s) in steps.iter().enumerate() {
            let label = match &s.kind {
                PlanKind::Step { title, .. } => self.t(title),
                _ => text(self.s.review),
            };
            let _ = writeln!(self.out, "<li><a href=\"#step-{k}\" data-step=\"{k}\">{label}</a></li>");
        }
        self.w("</ol>\n</nav>\n</div>\n<main id=\"main\">\n");
        let total = steps.len();
        for (k, s) in steps.iter().enumerate() {
            self.step(s, k, total);
        }
        let _ = write!(self.out, "</main>\n</div>\n<script>{SCRIPT}</script>\n</body>\n</html>\n");
    }

    fn step(&mut self, n: &PlanNode, k: usize, total: usize) {
        let count = text(&fill(self.s.step_of, &[("n", &self.count((k + 1) as i128)), ("total", &self.count(total as i128))]));
        let (title, navigation, dense, review) = match &n.kind {
            PlanKind::Step { title, navigation, emphasis } => (self.t(title), navigation.name(), *emphasis == Some(Emphasis::Compact), false),
            _ => (text(self.s.review), "linear", false, true),
        };
        let saved = self.disabled;
        self.disabled |= self.vis(n.id) == Visibility::Protected;
        let _ = write!(
            self.out,
            "<section class=\"step{}{}{}\" id=\"step-{k}\" data-step=\"{k}\" data-navigation=\"{navigation}\"{} aria-labelledby=\"t{}\">\n\
             <header class=\"step-head\"><h2 class=\"step-title\" id=\"t{}\" tabindex=\"-1\"><span class=\"step-count\">{count}</span>{title}</h2></header>\n",
            if review { " review" } else { "" },
            if dense { " dense" } else { "" },
            self.protected_class(n),
            self.node_attrs(n),
            n.id,
            n.id,
        );
        if review {
            self.review();
        } else {
            for c in &n.children {
                self.node(c, 3);
            }
        }
        let _ = write!(
            self.out,
            "<nav class=\"step-nav\" aria-label=\"{}\"><button type=\"button\" class=\"btn back\"><span class=\"arrow\" aria-hidden=\"true\">←</span> {}</button>\
             <button type=\"button\" class=\"btn primary next\">{} <span class=\"arrow\" aria-hidden=\"true\">→</span></button></nav>\n</section>\n",
            attr(&fill(self.s.step_of, &[("n", &self.count((k + 1) as i128)), ("total", &self.count(total as i128))])),
            text(self.s.back),
            text(self.s.next),
        );
        self.disabled = saved;
    }

    // ---- nodes --------------------------------------------------------------------------

    fn node(&mut self, n: &PlanNode, lvl: u8) {
        let vis = self.vis(n.id);
        if vis == Visibility::Hidden {
            return;
        }
        let saved = self.disabled;
        self.disabled |= vis == Visibility::Protected;
        match &n.kind {
            PlanKind::Step { .. } | PlanKind::Review => {}
            PlanKind::Tabs => self.tabs(n, lvl),
            PlanKind::Tab { .. } => {}
            PlanKind::Card { title, icon, emphasis } => {
                let dense = if *emphasis == Some(Emphasis::Compact) { " dense" } else { "" };
                let _ = write!(self.out, "<section class=\"card{dense}{}\"{}", self.protected_class(n), self.node_attrs(n));
                match title {
                    Some(t) => {
                        let h = level(lvl);
                        let _ = write!(
                            self.out,
                            " aria-labelledby=\"t{}\">\n<h{h} class=\"box-title\" id=\"t{}\">{}{}{}</h{h}>\n",
                            n.id,
                            n.id,
                            Self::icon(icon.as_deref()),
                            self.t(t),
                            self.protected_badge(n)
                        );
                    }
                    None => self.w(">\n"),
                }
                self.children(n, lvl + 1);
                self.w("</section>\n");
            }
            PlanKind::Row { emphasis } => {
                let dense = if *emphasis == Some(Emphasis::Compact) { " dense" } else { "" };
                let _ = writeln!(self.out, "<div class=\"row{dense}{}\"{}>", self.protected_class(n), self.node_attrs(n));
                self.children(n, lvl);
                self.w("</div>\n");
            }
            PlanKind::Group(h) => {
                let _ = writeln!(self.out, "<section class=\"card group{}\"{} aria-labelledby=\"t{}\">", self.protected_class(n), self.node_attrs(n), n.id);
                self.heading(n, h, lvl);
                self.children(n, lvl + 1);
                self.w("</section>\n");
            }
            PlanKind::List(h) => {
                let _ = writeln!(self.out, "<section class=\"list{}\"{} aria-labelledby=\"t{}\">", self.protected_class(n), self.node_attrs(n), n.id);
                self.heading(n, h, lvl);
                self.w("<div class=\"instances\">\n");
                let saved = std::mem::replace(&mut self.list_period, h.reference_period.clone());
                self.children(n, lvl + 1);
                self.list_period = saved;
                self.w("</div>\n</section>\n");
            }
            PlanKind::Table { heading, columns } => self.table(n, heading, columns, lvl),
            PlanKind::Instance { code, heading } => self.instance_card(n, code, heading, lvl),
            PlanKind::Question(q) => self.question(n, q, Mode::Block),
            PlanKind::Display { role, text: body, media } => {
                let _ = write!(self.out, "<div class=\"display {}{}\"{}>", display_role_name(*role), self.protected_class(n), self.node_attrs(n));
                if let Some(b) = body {
                    let tag = if *role == DisplayRole::Introduction || *role == DisplayRole::End { "p class=\"lead\"" } else { "p" };
                    let _ = write!(self.out, "<{tag}>{}</p>", self.t(b));
                }
                self.figure(media.as_ref());
                self.w("</div>\n");
            }
        }
        self.disabled = saved;
    }

    fn children(&mut self, n: &PlanNode, lvl: u8) {
        for c in &n.children {
            self.node(c, lvl);
        }
    }

    /// The heading of a group, list or table: label, description, reference period, media.
    fn heading(&mut self, n: &PlanNode, h: &PlanHeading, lvl: u8) {
        let l = level(lvl);
        let _ = write!(
            self.out,
            "<header class=\"box-head\"><h{l} class=\"box-title\" id=\"t{}\">{}{}{}</h{l}>",
            n.id,
            Self::icon(h.icon.as_deref()),
            self.t(&h.label),
            self.protected_badge(n)
        );
        if let Some(d) = &h.description {
            let _ = write!(self.out, "<p class=\"desc\">{}</p>", self.t(d));
        }
        if let Some(p) = &h.reference_period {
            let _ = write!(self.out, "<p class=\"period\">{}</p>", self.t(p));
        }
        self.figure(h.media.as_ref());
        self.w("</header>\n");
    }

    /// An instance's reference period, unless it is the one its list or table already shows.
    fn instance_period(&self, h: &PlanHeading) -> Option<String> {
        let p = h.reference_period.as_ref()?;
        (self.list_period.as_ref() != Some(p)).then(|| format!("<p class=\"period\">{}</p>", self.t(p)))
    }

    fn tabs(&mut self, n: &PlanNode, lvl: u8) {
        let tabs: Vec<&PlanNode> = n.children.iter().filter(|c| self.vis(c.id) != Visibility::Hidden).collect();
        let _ = write!(self.out, "<div class=\"tabs{}\"{}>\n<div class=\"tablist\" role=\"tablist\">", self.protected_class(n), self.node_attrs(n));
        for (i, t) in tabs.iter().enumerate() {
            if let PlanKind::Tab { title, icon, .. } = &t.kind {
                let _ = write!(
                    self.out,
                    "<button type=\"button\" class=\"tab\" role=\"tab\" id=\"tab-{}\" aria-controls=\"panel-{}\" aria-selected=\"{}\" tabindex=\"{}\">{}{}</button>",
                    t.id,
                    t.id,
                    if i == 0 { "true" } else { "false" },
                    if i == 0 { 0 } else { -1 },
                    Self::icon(icon.as_deref()),
                    self.t(title)
                );
            }
        }
        self.w("</div>\n");
        for t in tabs {
            let PlanKind::Tab { title, icon, emphasis } = &t.kind else { continue };
            let saved = self.disabled;
            self.disabled |= self.vis(t.id) == Visibility::Protected;
            let dense = if *emphasis == Some(Emphasis::Compact) { " dense" } else { "" };
            let h = level(lvl);
            let _ = write!(
                self.out,
                "<section class=\"tabpanel{dense}{}\" role=\"tabpanel\" id=\"panel-{}\" aria-labelledby=\"tab-{}\" tabindex=\"0\"{}>\n<h{h} class=\"panel-title box-title\">{}{}{}</h{h}>\n",
                self.protected_class(t),
                t.id,
                t.id,
                self.node_attrs(t),
                Self::icon(icon.as_deref()),
                self.t(title),
                self.protected_badge(t),
            );
            self.children(t, lvl + 1);
            self.w("</section>\n");
            self.disabled = saved;
        }
        self.w("</div>\n");
    }

    /// The first visible child of an instance, if it is the instance-name question.
    fn instance_name<'n>(&self, n: &'n PlanNode) -> Option<&'n PlanNode> {
        let first = n.children.iter().find(|c| self.vis(c.id) != Visibility::Hidden)?;
        matches!(first.question()?.origin, PlanOrigin::InstanceName).then_some(first)
    }

    /// An instance drawn as a card (in a `list`).
    fn instance_card(&mut self, n: &PlanNode, code: &str, h: &PlanHeading, lvl: u8) {
        let l = level(lvl);
        let _ = write!(
            self.out,
            "<article class=\"card instance{}\"{} data-code=\"{}\" aria-labelledby=\"r{}\">\n<header class=\"instance-head\"><h{l} class=\"box-title\" id=\"r{}\">{}{}{}</h{l}>",
            self.protected_class(n),
            self.node_attrs(n),
            attr(code),
            n.id,
            n.id,
            Self::icon(h.icon.as_deref()),
            self.t(&h.label),
            self.protected_badge(n),
        );
        if let Some(d) = &h.description {
            let _ = write!(self.out, "<p class=\"desc\">{}</p>", self.t(d));
        }
        if let Some(p) = self.instance_period(h) {
            self.w(&p);
        }
        self.figure(h.media.as_ref());
        let name = self.instance_name(n);
        if let Some(q) = name {
            self.node(q, lvl + 1);
        }
        self.w("</header>\n");
        for c in &n.children {
            if name.is_some_and(|q| q.id == c.id) {
                continue;
            }
            self.node(c, lvl + 1);
        }
        self.w("</article>\n");
    }

    /// A repeat group as a real table: one row per instance, one column per question.
    fn table(&mut self, n: &PlanNode, heading: &PlanHeading, columns: &[PlanColumn], lvl: u8) {
        let _ = writeln!(self.out, "<section class=\"table-box list{}\"{} aria-labelledby=\"t{}\">", self.protected_class(n), self.node_attrs(n), n.id);
        self.heading(n, heading, lvl);
        let _ = write!(
            self.out,
            "<div class=\"table-wrap\">\n<table aria-labelledby=\"t{}\">\n<thead><tr><th scope=\"col\">{}</th>",
            n.id,
            text(self.s.item)
        );
        for (k, c) in columns.iter().enumerate() {
            let prefix = c.prefix.as_deref().map(|p| format!("<span class=\"prefix\">{}</span> ", text(p))).unwrap_or_default();
            let _ = write!(self.out, "<th scope=\"col\" id=\"c{}-{k}\">{prefix}{}</th>", n.id, self.t(&c.label));
        }
        self.w("</tr></thead>\n<tbody>\n");
        for inst in &n.children {
            if self.vis(inst.id) == Visibility::Hidden {
                continue;
            }
            let saved = self.disabled;
            self.disabled |= self.vis(inst.id) == Visibility::Protected;
            self.table_row(inst, columns);
            self.disabled = saved;
        }
        self.w("</tbody>\n</table>\n</div>\n</section>\n");
    }

    fn table_row(&mut self, inst: &PlanNode, columns: &[PlanColumn]) {
        let (code, h) = match &inst.kind {
            PlanKind::Instance { code, heading } => (code.as_str(), heading),
            _ => return,
        };
        let _ = write!(
            self.out,
            "<tr class=\"{}\"{} data-code=\"{}\"><th scope=\"row\"><span class=\"box-title\" id=\"r{}\">{}{}</span>{}",
            self.protected_class(inst).trim(),
            self.node_attrs(inst),
            attr(code),
            inst.id,
            Self::icon(h.icon.as_deref()),
            self.t(&h.label),
            self.protected_badge(inst),
        );
        let name = self.instance_name(inst);
        let row_label = format!("r{}", inst.id);
        self.row_label = Some(row_label);
        if let Some(q) = name
            && let PlanKind::Question(pq) = &q.kind
        {
            self.question(q, pq, Mode::Cell);
        }
        self.w("</th>");
        // Cells in plan order: a child starts the cell of its column; anything else (an
        // "other" text, a display) joins the current cell, so nothing is ever reordered.
        let mut cells = vec![String::new(); columns.len().max(1)];
        let mut cur = 0usize;
        for c in &inst.children {
            if name.is_some_and(|q| q.id == c.id) || self.vis(c.id) == Visibility::Hidden {
                continue;
            }
            if let Some(col) = c.question().and_then(|q| q.column.as_deref())
                && let Some(pos) = columns.iter().position(|k| k.key == col)
                && pos >= cur
            {
                cur = pos;
            }
            let outer = std::mem::take(&mut self.out);
            match &c.kind {
                PlanKind::Question(q) => {
                    let saved = self.disabled;
                    self.disabled |= self.vis(c.id) == Visibility::Protected;
                    self.question(c, q, Mode::Cell);
                    self.disabled = saved;
                }
                _ => self.node(c, 6),
            }
            let cell = std::mem::replace(&mut self.out, outer);
            cells[cur].push_str(&cell);
        }
        for c in cells.into_iter().take(columns.len()) {
            let _ = write!(self.out, "<td>{c}</td>");
        }
        self.w("</tr>\n");
        self.row_label = None;
    }

    // ---- questions ----------------------------------------------------------------------

    fn question(&mut self, n: &PlanNode, q: &PlanQuestion, mode: Mode) {
        let id = n.id;
        let protected = self.protected_class(n);
        let other = if matches!(q.origin, PlanOrigin::OtherText { .. }) { " other-text" } else { "" };
        let control = q.control.as_ref();
        let ctype = control.map_or("read-only", |c| c.control_type().name());
        let grouped = matches!(
            control,
            Some(
                PlanControl::Choice { .. }
                    | PlanControl::MultiChoice { .. }
                    | PlanControl::Scale { .. }
                    | PlanControl::YesNo
                    | PlanControl::CodedListWithOther { .. }
                    | PlanControl::MeasurementPair { .. }
            )
        );
        let label_html = {
            let mut l = String::new();
            if let Some(p) = &q.prefix {
                let _ = write!(l, "<span class=\"prefix\">{}</span> ", text(p));
            }
            let _ = write!(l, "<span>{}</span>", self.t(&q.label));
            if q.optional {
                let _ = write!(l, " <span class=\"badge\">{}</span>", text(self.s.optional));
            }
            l.push_str(&self.protected_badge(n));
            l
        };
        let mut described = Vec::new();
        if q.help.is_some() && mode == Mode::Block {
            described.push(format!("h{id}"));
        }
        let hint = self.hint(control);
        if hint.is_some() && mode == Mode::Block {
            described.push(format!("d{id}"));
        }
        if matches!(control, Some(c) if !matches!(c, PlanControl::PhotoEvidence { .. })) {
            // The inline message the page script fills when a value is refused (INS-027).
            described.push(format!("e{id}"));
        }
        if let Some(PlanControl::MultiChoice { max: Some(_), .. }) = control {
            described.push(format!("c{id}"));
        }
        let describedby = if described.is_empty() { String::new() } else { format!(" aria-describedby=\"{}\"", described.join(" ")) };
        let labelledby = match (&self.row_label, mode) {
            (Some(r), Mode::Cell) => format!(" aria-labelledby=\"{r} l{id}\""),
            _ => String::new(),
        };
        let presentation = q.presentation.map(|p| format!(" data-presentation=\"{}\"", p.name())).unwrap_or_default();
        let vh = if mode == Mode::Cell { " class=\"vh\"" } else { " class=\"q-label\"" };

        if grouped {
            let _ = write!(
                self.out,
                "<fieldset class=\"q{protected}{other}\" id=\"q{id}\"{} data-control=\"{ctype}\"{presentation}{labelledby}{describedby}{}>\n<legend id=\"l{id}\"{}>{label_html}</legend>\n",
                self.node_attrs(n),
                self.dis(),
                if mode == Mode::Cell { " class=\"vh\"" } else { "" },
            );
        } else {
            let _ = writeln!(self.out, "<div class=\"q{protected}{other}{}\" id=\"q{id}\"{} data-control=\"{ctype}\"{presentation}>", if control.is_none() { " readonly" } else { "" }, self.node_attrs(n));
            if control.is_some() {
                let _ = writeln!(self.out, "<label for=\"i{id}\" id=\"l{id}\"{vh}>{label_html}</label>");
            } else {
                let _ = writeln!(self.out, "<span id=\"l{id}\"{vh}>{label_html}</span>");
            }
        }
        if mode == Mode::Block {
            if let Some(h) = &q.help {
                let _ = writeln!(self.out, "<p class=\"help\" id=\"h{id}\">{}</p>", self.t(h));
            }
            if let (Some(g), true) = (&q.guidance, self.p.plan.instrument.administration != "self") {
                let _ = writeln!(self.out, "<aside class=\"guidance\"><strong>{}</strong>{}</aside>", text(self.s.guidance), self.t(g));
            }
            self.figure(q.media.as_ref());
        }
        let value = self.value_of(n).cloned();
        let nr_value = value.as_ref().and_then(|v| v.as_map()).and_then(|m| m.get("nr")).and_then(Value::as_text).map(str::to_owned);
        let value = if nr_value.is_some() { None } else { value };
        let ctx = Ctl { id, labelledby: if grouped { String::new() } else { labelledby.clone() }, describedby: if grouped { String::new() } else { describedby.clone() } };
        match control {
            None => {
                let shown = match &q.roster_field {
                    Some(f) => match self.p.roster.get(f).and_then(|v| self.value_text(v)) {
                        Some(v) => format!("<bdi class=\"value\">{}</bdi>", text(&v)),
                        None => format!("<var>roster.{}</var>", text(f)),
                    },
                    None => String::new(),
                };
                let _ = writeln!(
                    self.out,
                    "<output aria-labelledby=\"l{id}\">{shown}</output><span class=\"from-roster\">{}</span>",
                    text(self.s.from_roster)
                );
            }
            Some(c) => self.control(c, &ctx, value.as_ref(), n),
        }
        if matches!(control, Some(c) if !matches!(c, PlanControl::PhotoEvidence { .. })) {
            let _ = writeln!(self.out, "<p class=\"field-error\" id=\"e{id}\" hidden></p>");
        }
        if let (Some(h), Mode::Block) = (hint, mode) {
            let _ = writeln!(self.out, "<p class=\"hint\" id=\"d{id}\">{}</p>", text(&h));
        }
        if !q.nonresponse.is_empty() {
            let _ = write!(self.out, "<div class=\"nr\" role=\"group\" aria-label=\"{}\">", attr(self.s.nonresponse));
            for nr in &q.nonresponse {
                let pressed = nr_value.as_deref() == Some(nr.code());
                let _ = write!(
                    self.out,
                    "<button type=\"button\" class=\"nr-btn\" data-nr=\"{}\" aria-pressed=\"{pressed}\"{}>{}</button>",
                    nr.code(),
                    self.dis(),
                    text(self.nr_label(*nr))
                );
            }
            self.w("</div>\n");
        }
        self.w(if grouped { "</fieldset>\n" } else { "</div>\n" });
    }

    /// The hint under a control: bounds, limits and how it behaves.
    fn hint(&self, control: Option<&PlanControl>) -> Option<String> {
        let bounds = |min: Option<Decimal>, max: Option<Decimal>, unit: &str| -> Option<String> {
            let f = |d: Decimal| if unit.is_empty() { self.loc.number(d) } else { format!("{} {unit}", self.loc.number(d)) };
            match (min, max) {
                (Some(a), Some(b)) => Some(fill(self.s.between, &[("min", &f(a)), ("max", &f(b))])),
                (Some(a), None) => Some(fill(self.s.at_least, &[("min", &f(a))])),
                (None, Some(b)) => Some(fill(self.s.at_most, &[("max", &f(b))])),
                (None, None) => None,
            }
        };
        match control? {
            PlanControl::MultiChoice { max: Some(m), .. } => Some(fill(self.s.choose_up_to, &[("n", &self.count(*m as i128))])),
            PlanControl::MultiChoice { max: None, .. } => Some(self.s.choose_any.to_owned()),
            // The stepper's start value is not announced: it is not an answer, and saying so
            // under every stepper only adds noise.
            PlanControl::Stepper { min, max, unit, .. } => bounds(Some(*min), Some(*max), &self.unit_plain(unit.as_ref())),
            PlanControl::Number { min, max, unit, .. } => bounds(*min, *max, &self.unit_plain(unit.as_ref())),
            PlanControl::Money { min, max, currency, minor_digits, .. } => {
                let f = |d: Decimal| self.loc.money(d, currency, *minor_digits);
                match (min, max) {
                    (Some(a), Some(b)) => Some(fill(self.s.between, &[("min", &f(*a)), ("max", &f(*b))])),
                    (Some(a), None) => Some(fill(self.s.at_least, &[("min", &f(*a))])),
                    (None, Some(b)) => Some(fill(self.s.at_most, &[("max", &f(*b))])),
                    (None, None) => None,
                }
            }
            PlanControl::MeasurementPair { min, max, unit, tolerance, .. } => {
                let u = self.unit_plain(unit.as_ref());
                let t = fill(self.s.tolerance, &[("n", &if u.is_empty() { self.loc.number(*tolerance) } else { format!("{} {u}", self.loc.number(*tolerance)) })]);
                Some(match bounds(*min, *max, &u) {
                    Some(b) => format!("{b} {t}"),
                    None => t,
                })
            }
            PlanControl::Text { max_length: Some(m), .. } => Some(fill(self.s.max_chars, &[("n", &self.count(*m as i128))])),
            PlanControl::Date { min, max } => {
                let f = |d: &String| self.loc.date(d).unwrap_or_else(|| d.clone());
                match (min, max) {
                    (Some(a), Some(b)) => Some(fill(self.s.between, &[("min", &f(a)), ("max", &f(b))])),
                    (Some(a), None) => Some(fill(self.s.at_least, &[("min", &f(a))])),
                    (None, Some(b)) => Some(fill(self.s.at_most, &[("max", &f(b))])),
                    (None, None) => None,
                }
            }
            PlanControl::PhotoEvidence { max_dimension: Some(m) } => Some(fill(self.s.max_side, &[("n", &self.count(*m as i128))])),
            _ => None,
        }
    }

    /// ` value="…"` for a current value, if there is one, as the collector types it: the
    /// language's digits and decimal separator.
    fn val_attr(&self, v: Option<&Value>) -> String {
        self.val_attr_as(v, Show::Input)
    }

    /// ` value="…"` in locale-free form, for controls the browser itself localises.
    fn val_attr_raw(&self, v: Option<&Value>) -> String {
        self.val_attr_as(v, Show::Raw)
    }

    fn val_attr_as(&self, v: Option<&Value>, show: Show) -> String {
        v.and_then(|v| self.text_of(v, show)).map(|t| format!(" value=\"{}\"", attr(&t))).unwrap_or_default()
    }

    fn unit_plain(&self, u: Option<&PlanUnit>) -> String {
        match u {
            Some(PlanUnit { label: Some(l), .. }) => self.plain(l),
            Some(PlanUnit { code, label: None }) => code.clone(),
            None => String::new(),
        }
    }

    fn unit_html(&self, u: Option<&PlanUnit>) -> String {
        match u {
            Some(PlanUnit { code, label: Some(l) }) => format!("<span class=\"unit\" title=\"{}\">{}</span>", attr(code), self.t(l)),
            Some(PlanUnit { code, label: None }) => format!("<span class=\"unit\">{}</span>", text(code)),
            None => String::new(),
        }
    }

    fn control(&mut self, c: &PlanControl, x: &Ctl, value: Option<&Value>, n: &PlanNode) {
        let id = x.id;
        let dis = self.dis();
        match c {
            PlanControl::Choice { options, .. } | PlanControl::CodedListWithOther { options, .. } => {
                let chosen = value.and_then(Value::as_text);
                self.options(id, "radio", options, None, &|o| chosen == Some(o.code.as_str()));
            }
            PlanControl::MultiChoice { options, max, .. } => {
                let max = *max;
                let chosen: Vec<&str> = value.and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_text).collect()).unwrap_or_default();
                self.options(id, "checkbox", options, max, &|o| chosen.contains(&o.code.as_str()));
                if let Some(m) = max {
                    // The live count (INS-025): the script keeps it, and disables the rest at the limit.
                    let template = fill(self.s.chosen_of, &[("max", &self.count(m as i128))]);
                    let shown = fill(&template, &[("n", &self.count(chosen.len() as i128))]);
                    let _ = writeln!(
                        self.out,
                        "<output class=\"choice-count\" id=\"c{id}\" aria-live=\"polite\" data-template=\"{}\" data-msg-high=\"{}\">{}</output>",
                        attr(&template),
                        attr(&fill(self.s.choose_up_to, &[("n", &self.count(m as i128))])),
                        text(&shown)
                    );
                }
            }
            PlanControl::Scale { steps } => {
                let chosen = value.and_then(Value::as_text);
                let _ = write!(self.out, "<div class=\"segments\" data-steps=\"{}\">", steps.len());
                for (k, o) in steps.iter().enumerate() {
                    let checked = if chosen == Some(o.code.as_str()) { " checked" } else { "" };
                    let _ = write!(
                        self.out,
                        "<label class=\"segment\"><input type=\"radio\" name=\"n{id}\" id=\"i{id}-{k}\" value=\"{}\"{checked}{dis}>{}<span>{}</span></label>",
                        attr(&o.code),
                        Self::icon(o.icon.as_deref()),
                        // A frequency label breaks only after a slash ("2-3/<wbr>month"), never mid-word.
                        self.t(&o.label).replace('/', "/<wbr>")
                    );
                }
                self.w("</div>\n");
            }
            PlanControl::YesNo => {
                let chosen = value.and_then(Value::as_bool);
                self.w("<div class=\"binary\">");
                for (k, (v, label)) in [(true, self.s.yes), (false, self.s.no)].into_iter().enumerate() {
                    let checked = if chosen == Some(v) { " checked" } else { "" };
                    let _ = write!(
                        self.out,
                        "<label class=\"opt\"><input type=\"radio\" name=\"n{id}\" id=\"i{id}-{k}\" value=\"{v}\"{checked}{dis}><span class=\"opt-label\">{}</span></label>",
                        text(label)
                    );
                }
                self.w("</div>\n");
            }
            PlanControl::Stepper { min, max, step, unit, start } => {
                // INS-027, INS-163: bounded, on the grid `start + k x step`; the value is a
                // canonical number the script keeps in `data-canonical`.
                let limits = self.limits(Some(*min), Some(*max), &|d| self.stepper_number(d, unit.as_ref()));
                // As wide as the widest value the stepper allows, so - and + sit beside it.
                let fraction = |d: &Decimal| d.to_string().split_once('.').map_or(0, |(_, f)| f.len());
                let width = (min.to_string().len().max(max.to_string().len()) + fraction(step).saturating_sub(fraction(max)) + 1).clamp(3, 12);
                let _ = writeln!(
                    self.out,
                    "<div class=\"affix\"><div class=\"num-stepper\">{}<input class=\"field num-stepper__value w{width}\" type=\"number\" inputmode=\"decimal\" id=\"i{id}\" name=\"n{id}\" min=\"{min}\" max=\"{max}\" step=\"{step}\" data-number data-bounded data-start=\"{start}\" data-step=\"{step}\"{limits}{}{}{}{dis}>{}</div>{}</div>",
                    self.stepper_button(-1, dis),
                    self.val_attr_raw(value),
                    x.labelledby,
                    x.describedby,
                    self.stepper_button(1, dis),
                    self.unit_html(unit.as_ref())
                );
            }
            PlanControl::Number { min, max, decimals, unit, entry_units } => {
                let mode = if *decimals == 0 { "numeric" } else { "decimal" };
                let limits = self.limits(*min, *max, &|d| self.stepper_number(d, unit.as_ref()));
                // A small bounded whole number is a stepper (the wireframe's - / value / +).
                let bounded = match (min, max) {
                    (Some(a), Some(b)) if *decimals == 0 && entry_units.is_empty() => a.to_string().parse::<f64>().ok().zip(b.to_string().parse::<f64>().ok()).is_some_and(|(a, b)| b - a <= 30.0),
                    _ => false,
                };
                let (open, close, bounded_attrs) = if bounded {
                    let start = min.map(|m| m.to_string()).unwrap_or_default();
                    (format!("<div class=\"num-stepper\">{}", self.stepper_button(-1, dis)), self.stepper_button(1, dis), format!(" data-bounded data-start=\"{start}\" data-step=\"1\""))
                } else {
                    (String::new(), String::new(), String::new())
                };
                let wrap_class = if bounded { " num-stepper__value" } else { "" };
                let _ = write!(
                    self.out,
                    "<div class=\"affix\">{open}<input class=\"field{wrap_class}\" type=\"text\" inputmode=\"{mode}\" autocomplete=\"off\" id=\"i{id}\" name=\"n{id}\" data-number data-decimals=\"{decimals}\"{bounded_attrs}{limits}{}{}{}{dis}>{close}{}",
                    self.val_attr(value),
                    x.labelledby,
                    x.describedby,
                    self.unit_html(unit.as_ref())
                );
                if bounded {
                    self.w("</div>");
                }
                self.entry_units(id, unit.as_ref(), entry_units, n);
                self.w("</div>\n");
            }
            PlanControl::Money { currency, minor_digits, min, max, step } => {
                let limits = self.limits(*min, *max, &|d| self.loc.money(d, currency, *minor_digits));
                let step = step.map(|s| format!(" data-step=\"{s}\"")).unwrap_or_default();
                let _ = writeln!(
                    self.out,
                    "<div class=\"affix\"><span class=\"currency\">{}</span><input class=\"field\" type=\"text\" inputmode=\"decimal\" autocomplete=\"off\" id=\"i{id}\" name=\"n{id}\" data-number data-currency=\"{}\" data-minor-digits=\"{minor_digits}\"{step}{limits}{}{}{}{dis}></div>",
                    text(currency),
                    attr(currency),
                    self.val_attr(value),
                    x.labelledby,
                    x.describedby
                );
            }
            PlanControl::MeasurementPair { min, max, decimals, unit, entry_units, tolerance } => {
                let limits = self.limits(*min, *max, &|d| self.stepper_number(d, unit.as_ref()));
                let readings: Vec<Option<&Value>> = match value.and_then(Value::as_array) {
                    Some(a) => vec![a.first(), a.get(1)],
                    None => vec![None, None],
                };
                let mode = if *decimals == 0 { "numeric" } else { "decimal" };
                let _ = write!(self.out, "<div class=\"pair\" data-tolerance=\"{tolerance}\" data-msg-tolerance=\"{}\">", attr(&fill(self.s.tolerance, &[("n", &self.stepper_number(*tolerance, unit.as_ref()))])));
                for (k, label) in [self.s.reading_1, self.s.reading_2].into_iter().enumerate() {
                    let _ = write!(
                        self.out,
                        "<label for=\"i{id}-{k}\"><span>{}</span><span class=\"affix\"><input class=\"field\" type=\"text\" inputmode=\"{mode}\" autocomplete=\"off\" id=\"i{id}-{k}\" name=\"n{id}-{k}\" data-number data-decimals=\"{decimals}\"{limits}{}{dis}>{}</span></label>",
                        text(label),
                        self.val_attr(readings[k]),
                        self.unit_html(unit.as_ref())
                    );
                }
                self.w("</div>\n");
                if !entry_units.is_empty() {
                    self.w("<div class=\"affix\">");
                    self.entry_units(id, unit.as_ref(), entry_units, n);
                    self.w("</div>\n");
                }
            }
            PlanControl::Text { max_length, multiline: many } => {
                let max = max_length.map(|m| format!(" maxlength=\"{m}\"")).unwrap_or_default();
                if *many {
                    let body = value.and_then(|v| self.value_text(v)).map(|t| text(&t)).unwrap_or_default();
                    let _ = writeln!(self.out, "<textarea class=\"field\" id=\"i{id}\" name=\"n{id}\" rows=\"4\"{max}{}{}{dis}>{body}</textarea>", x.labelledby, x.describedby);
                } else {
                    let _ = writeln!(
                        self.out,
                        "<input class=\"field text-field\" type=\"text\" id=\"i{id}\" name=\"n{id}\" autocomplete=\"off\"{max}{}{}{}{dis}>",
                        self.val_attr(value),
                        x.labelledby,
                        x.describedby
                    );
                }
            }
            PlanControl::Date { min, max } => {
                let (lo, hi) = (min.as_ref(), max.as_ref());
                let min = min.as_deref().map(|m| format!(" min=\"{}\"", attr(m))).unwrap_or_default();
                let max = max.as_deref().map(|m| format!(" max=\"{}\"", attr(m))).unwrap_or_default();
                let low = lo.map(|m| format!(" data-msg-low=\"{}\"", attr(&fill(self.s.at_least, &[("min", &self.loc.date(m).unwrap_or_else(|| m.clone()))])))).unwrap_or_default();
                let high = hi.map(|m| format!(" data-msg-high=\"{}\"", attr(&fill(self.s.at_most, &[("max", &self.loc.date(m).unwrap_or_else(|| m.clone()))])))).unwrap_or_default();
                let _ = writeln!(self.out, "<input class=\"field\" type=\"date\" id=\"i{id}\" name=\"n{id}\"{min}{max}{low}{high}{}{}{}{dis}>", self.val_attr_raw(value), x.labelledby, x.describedby);
            }
            PlanControl::PhotoEvidence { .. } => {
                let _ = writeln!(
                    self.out,
                    "<input class=\"field\" type=\"file\" accept=\"image/*\" capture=\"environment\" id=\"i{id}\" name=\"n{id}\"{}{}{dis}>",
                    x.labelledby,
                    x.describedby
                );
            }
        }
    }

    /// A number as the messages show it: formatted for the language, with the unit.
    fn stepper_number(&self, d: Decimal, unit: Option<&PlanUnit>) -> String {
        let u = self.unit_plain(unit);
        if u.is_empty() { self.loc.number(d) } else { format!("{} {u}", self.loc.number(d)) }
    }

    /// `data-min`/`data-max` (canonical) and the localised messages the script shows for a
    /// value below or above them (INS-027).
    fn limits(&self, min: Option<Decimal>, max: Option<Decimal>, f: &dyn Fn(Decimal) -> String) -> String {
        let mut a = String::new();
        if let Some(m) = min {
            let _ = write!(a, " data-min=\"{m}\" data-msg-low=\"{}\"", attr(&fill(self.s.at_least, &[("min", &f(m))])));
        }
        if let Some(m) = max {
            let _ = write!(a, " data-max=\"{m}\" data-msg-high=\"{}\"", attr(&fill(self.s.at_most, &[("max", &f(m))])));
        }
        a
    }

    /// A stepper's decrease (-1) or increase (+1) button.
    fn stepper_button(&self, dir: i8, dis: &str) -> String {
        let (label, glyph) = if dir < 0 { (self.s.decrease, "\u{2212}") } else { (self.s.increase, "+") };
        format!("<button type=\"button\" class=\"num-stepper__btn\" data-dir=\"{dir}\" aria-label=\"{}\"{dis}>{glyph}</button>", attr(label))
    }

    /// The unit the value is entered in (INS-161): the item's unit first, then the others.
    /// Choosing a unit is not an answer, so the item's own unit is shown selected.
    fn entry_units(&mut self, id: usize, unit: Option<&PlanUnit>, entry_units: &[String], n: &PlanNode) {
        if entry_units.is_empty() {
            return;
        }
        let chosen = n.bind.as_deref().and_then(|b| self.p.values.get(&format!("{b}.unit"))).and_then(Value::as_text).map(str::to_owned);
        let _ = write!(self.out, "<label class=\"vh\" for=\"u{id}\">{}</label><select class=\"field\" id=\"u{id}\" name=\"u{id}\"{}>", text(self.s.entry_unit), self.dis());
        let mut all: Vec<(String, String)> = Vec::new();
        if let Some(u) = unit {
            all.push((u.code.clone(), self.unit_plain(Some(u))));
        }
        all.extend(entry_units.iter().map(|u| (u.clone(), u.clone())));
        for (code, label) in all {
            let sel = if chosen.as_deref() == Some(code.as_str()) { " selected" } else { "" };
            let _ = write!(self.out, "<option value=\"{}\"{sel}>{}</option>", attr(&code), text(&label));
        }
        self.w("</select>");
    }

    fn options(&mut self, id: usize, kind: &str, options: &[PlanOption], max: Option<u32>, checked: &dyn Fn(&PlanOption) -> bool) {
        let dis = self.dis();
        let limit = max.map(|m| format!(" data-max=\"{m}\"")).unwrap_or_default();
        let _ = write!(self.out, "<div class=\"options\"{limit}>");
        for (k, o) in options.iter().enumerate() {
            let c = if checked(o) { " checked" } else { "" };
            let exclusive = if o.exclusive { " data-exclusive=\"true\"" } else { "" };
            let _ = write!(
                self.out,
                "<label class=\"opt\"><input type=\"{kind}\" name=\"n{id}\" id=\"i{id}-{k}\" value=\"{}\"{exclusive}{c}{dis}>",
                attr(&o.code)
            );
            if let Some(m) = &o.media {
                let img = self.img(m);
                self.w(&img);
            }
            let _ = write!(self.out, "<span class=\"opt-body\"><span class=\"opt-label\">{}{}</span>", Self::icon(o.icon.as_deref()), self.t(&o.label));
            if let Some(d) = &o.description {
                let _ = write!(self.out, "<span class=\"opt-desc\">{}</span>", self.t(d));
            }
            if o.exclusive && kind == "checkbox" {
                let _ = write!(self.out, "<span class=\"opt-flag\">{}</span>", text(self.s.exclusive));
            }
            self.w("</span></label>");
        }
        self.w("</div>\n");
    }

    // ---- review -------------------------------------------------------------------------

    /// The platform's review of the record (COL-060): every question that is not hidden, in
    /// plan order, with its current answer.
    fn review(&mut self) {
        let _ = writeln!(self.out, "<p>{}</p>\n<dl class=\"review-list\">", text(self.s.review_intro));
        let mut items: Vec<&PlanNode> = Vec::new();
        fn collect<'n>(n: &'n PlanNode, r: &R<'_>, out: &mut Vec<&'n PlanNode>) {
            if r.vis(n.id) == Visibility::Hidden {
                return;
            }
            if n.question().is_some() {
                out.push(n);
            }
            for c in &n.children {
                collect(c, r, out);
            }
        }
        for s in &self.p.plan.steps {
            collect(s, self, &mut items);
        }
        for n in items {
            let Some(q) = n.question() else { continue };
            let label = q.short_label.as_ref().map_or_else(|| self.t(&q.label), |l| self.t(l));
            let prefix = q.prefix.as_deref().map(|p| format!("<span class=\"prefix\">{}</span> ", text(p))).unwrap_or_default();
            let shown = self.review_value(n, q);
            let (class, body) = match shown {
                Some(v) => ("", text(&v)),
                None => (" class=\"unset\"", text(self.s.not_answered)),
            };
            let _ = writeln!(self.out, "<div class=\"review-item\" data-review-for=\"{}\"><dt>{prefix}{label}</dt><dd{class}>{body}</dd></div>", n.id);
        }
        self.w("</dl>\n");
    }

    fn review_value(&self, n: &PlanNode, q: &PlanQuestion) -> Option<String> {
        if q.control.is_none() {
            return q.roster_field.as_ref().and_then(|f| self.p.roster.get(f)).and_then(|v| self.value_text(v));
        }
        let v = self.value_of(n)?;
        let label_of = |code: &str| {
            q.control.as_ref().and_then(|c| c.options().iter().find(|o| o.code == code)).map_or_else(|| code.to_owned(), |o| self.plain(&o.label))
        };
        match (v, q.control.as_ref()) {
            (Value::Text(code), Some(c)) if !c.options().is_empty() => Some(label_of(code)),
            (Value::Array(a), Some(PlanControl::MultiChoice { .. })) => {
                Some(a.iter().filter_map(Value::as_text).map(label_of).collect::<Vec<_>>().join(", "))
            }
            (v, Some(PlanControl::Money { currency, minor_digits, .. })) => match v.as_decimal() {
                Some(d) => Some(self.loc.money(d, currency, *minor_digits)),
                None => self.value_text(v),
            },
            (Value::Text(iso), Some(PlanControl::Date { .. })) => Some(self.loc.date(iso).unwrap_or_else(|| iso.clone())),
            (v, Some(PlanControl::Number { unit, .. } | PlanControl::MeasurementPair { unit, .. } | PlanControl::Stepper { unit, .. })) => {
                let u = self.unit_plain(unit.as_ref());
                self.value_text(v).map(|t| if u.is_empty() || v.as_map().is_some() { t } else { format!("{t} {u}") })
            }
            (v, _) => self.value_text(v),
        }
    }
}

/// Attributes shared by a question's inputs.
struct Ctl {
    id: usize,
    labelledby: String,
    describedby: String,
}

/// The empty value map, for pages drawn without values.
pub(crate) static EMPTY: BTreeMap<String, Value> = BTreeMap::new();
