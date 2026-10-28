//! `ValidateLayout` (INS §3, §5.21): from a layout document, decoded by an adapter into a
//! [`Value`] tree, and the [`Instrument`] it is bound to, to a validated [`Layout`] or every
//! finding. Also the default layout (INS-206) and layout selection by window class (INS-207).

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_kernel::Value;
use fieldseal_kernel::id::Fingerprint;

use super::decode::Decoder;
use crate::domain::compiled::{CompiledInstrument, NodeKind, QuestionOrigin};
use crate::domain::control::Control;
use crate::domain::finding::{FindingKind, Findings, at, idx};
use crate::domain::layout::{Container, Content, Emphasis, InstrumentReference, Layout, LayoutStep, Navigation, Presentation, RepeatAs, WindowClass};
use crate::domain::media::is_single_emoji;
use crate::domain::paths::is_segment;
use crate::domain::text::LocalisedText;
use crate::domain::version::{Compatibility, IMPLEMENTED_SCHEMA, SchemaRange, SemVer, check_compatibility};
use crate::domain::Instrument;

/// How `ValidateLayout` checks that a layout names the instrument it is validated against
/// (INS-200). Fingerprints are computed by the format core, so both parts are supplied by the
/// caller.
#[derive(Clone, Copy)]
pub struct LayoutBinding<'a> {
    /// The fingerprint of the instrument the layout is validated against.
    pub expected: Fingerprint,
    /// Resolves the layout's `spec.instrument` to a fingerprint: a source path is resolved by
    /// loading and fingerprinting that instrument. Called only for
    /// [`InstrumentReference::Source`]; a fingerprint is compared directly.
    pub resolve: &'a dyn Fn(&InstrumentReference) -> Option<Fingerprint>,
}

/// Optional collaborators for layout validation.
#[derive(Clone, Copy, Default)]
pub struct LayoutOptions<'a> {
    /// The binding check. Without it, `spec.instrument` is only checked for form, and the
    /// layout is checked against the instrument it is given.
    pub binding: Option<LayoutBinding<'a>>,
}

/// Keys that would carry instrument content if a layout could set them (INS-203).
const CONTENT_KEYS: &[&str] = &[
    "label", "text", "title", "prefix", "shortLabel", "help", "guidance", "description", "referencePeriod", "options", "codes", "steps", "order",
    "unit", "unitLabel", "entryUnits", "min", "max", "start", "step", "decimals", "currency", "tolerance", "maxLength", "rules", "when", "nonresponse",
    "default", "value", "initial", "selected", "preselect", "preselected", "highlight", "highlighted", "recommend", "recommended", "required",
    "optional", "disabledDisplay", "control", "data", "media", "alt", "placeholder", "hint", "message", "concept", "randomise", "otherLabel",
];

/// Validates `layout` against `instrument` without a fingerprint binding.
pub fn validate_layout(layout: &Value, instrument: &Instrument) -> Result<Layout, Findings> {
    validate_layout_with(layout, instrument, LayoutOptions::default())
}

/// Validates `layout` against `instrument`: decodes it (rejecting unknown fields), checks its
/// binding (INS-200), that it places every question exactly once (INS-202) in the
/// instrument's order (INS-214), that it changes no content (INS-203), its presentations
/// (INS-204), navigation (INS-205), window class (INS-207) and tabs (INS-215), and that every
/// title has every instrument language (INS-082). Returns every finding when any is an error.
pub fn validate_layout_with(layout: &Value, instrument: &Instrument, options: LayoutOptions<'_>) -> Result<Layout, Findings> {
    let langs = &instrument.definition().languages;
    let mut d = LayoutDecoder { d: Decoder::with_languages(langs.languages.clone(), langs.default.clone()) };
    let decoded = d.document(layout);
    let mut f = std::mem::take(&mut d.d.f);

    // Message variables in titles name roster fields or items (INS-084).
    for (doc, vars) in &d.d.refs.variables {
        for var in vars {
            let ok = match var.strip_prefix("roster.") {
                Some(field) => is_segment(field),
                None => instrument.compiled().question(var).is_some() || instrument.compiled().derived_value(var).is_some(),
            };
            if !ok {
                f.error_of(FindingKind::UnknownItemPath, "INS-084", doc.clone(), format!("`${var}` is neither `$roster.<field>` nor an item path"));
            }
        }
    }
    let Some(mut layout) = decoded else {
        return Err(f);
    };
    if let Some(b) = options.binding {
        let named = match &layout.instrument {
            InstrumentReference::Fingerprint(fp) => Some(*fp),
            r @ InstrumentReference::Source(_) => (b.resolve)(r),
        };
        match named {
            None => f.error_of(FindingKind::FingerprintMismatch, "INS-200", "spec.instrument", "the instrument this layout names can't be found"),
            Some(fp) if fp != b.expected => {
                f.error_of(FindingKind::FingerprintMismatch, "INS-200", "spec.instrument", "the layout is bound to a different instrument (its fingerprint differs)");
            }
            Some(fp) => layout.bound = Some(fp),
        }
    }
    check_placement(&layout, instrument.compiled(), &mut f);
    if f.has_errors() {
        return Err(f);
    }
    layout.questions = instrument.compiled().questions().map(|(p, _)| p.to_owned()).collect();
    Ok(layout)
}

/// Picks the layout for a window class (INS-207): one declaring exactly that class, else one
/// declaring no class, else the one declaring the nearest smaller class. `None` means the
/// default layout (INS-206). Ties go to the earliest in `layouts`.
pub fn select_layout<'a>(layouts: &[&'a Layout], class: WindowClass) -> Option<&'a Layout> {
    if let Some(l) = layouts.iter().find(|l| l.window_class == Some(class)) {
        return Some(l);
    }
    if let Some(l) = layouts.iter().find(|l| l.window_class.is_none()) {
        return Some(l);
    }
    WindowClass::ALL.iter().rev().filter(|c| **c < class).find_map(|c| layouts.iter().find(|l| l.window_class == Some(*c)).copied())
}

/// The default layout (INS-206), generated deterministically from the compiled tree: one
/// `linear` step per top-level group, titled with the group's label, holding the group's
/// children in tree order (questions and displays as elements, nested groups as `{group}`
/// leaves, which are drawn as cards, and repeats as `list`s). Top-level displays (and
/// top-level questions) join the step of the group that follows them, or the last step if
/// none follows; an instrument with no top-level group gets one step titled with the
/// instrument's title. The render plan adds the final review step.
pub fn default_layout(instrument: &Instrument) -> Layout {
    let def = instrument.definition();
    let compiled = instrument.compiled();
    let mut steps: Vec<LayoutStep> = Vec::new();
    let mut pending: Vec<Content> = Vec::new();
    for &root in compiled.roots() {
        let node = &compiled.nodes()[root];
        let doc_path = idx("default.steps", steps.len());
        match &node.kind {
            NodeKind::Group(g) => {
                let mut contents = std::mem::take(&mut pending);
                if g.repeat_over.is_some() {
                    contents.push(Content::Repeat { path: node.path.clone(), repeat_as: RepeatAs::List, doc_path: node.doc_path.clone() });
                } else {
                    for &c in &node.children {
                        contents.extend(default_leaf(compiled, c));
                    }
                }
                steps.push(LayoutStep { title: g.label.clone(), navigation: Navigation::Linear, emphasis: None, contents, doc_path });
            }
            _ => pending.extend(default_leaf(compiled, root)),
        }
    }
    if !pending.is_empty() {
        match steps.last_mut() {
            Some(last) => last.contents.append(&mut pending),
            None => steps.push(LayoutStep {
                title: def.metadata.title.clone(),
                navigation: Navigation::Linear,
                emphasis: None,
                contents: pending,
                doc_path: idx("default.steps", 0),
            }),
        }
    }
    Layout {
        name: format!("{}-default", def.name),
        version: def.version.clone(),
        schema: def.schema,
        instrument: InstrumentReference::Source(def.name.clone()),
        window_class: None,
        steps,
        bound: None,
        questions: compiled.questions().map(|(p, _)| p.to_owned()).collect(),
        is_default: true,
    }
}

/// The default leaf for one child node, or none for a synthesised `other` text (it follows
/// its question).
fn default_leaf(compiled: &CompiledInstrument, i: usize) -> Option<Content> {
    let node = &compiled.nodes()[i];
    let doc_path = node.doc_path.clone();
    let path = node.path.clone();
    Some(match &node.kind {
        NodeKind::Group(g) if g.repeat_over.is_some() => Content::Repeat { path, repeat_as: RepeatAs::List, doc_path },
        NodeKind::Group(_) => Content::Group { path, doc_path },
        NodeKind::Question(q) if matches!(q.origin, QuestionOrigin::OtherText { .. }) => return None,
        _ => Content::Element { path, presentation: None, doc_path },
    })
}

// ---- decoding -------------------------------------------------------------------------------

struct LayoutDecoder {
    d: Decoder,
}

type Map = BTreeMap<String, Value>;

/// Where a content item sits, which decides what it may hold (the container table, §5.21).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Parent {
    Step,
    Tab,
    Card,
    Row,
}

impl LayoutDecoder {
    /// A map whose keys are all in `allowed`; other keys are content overrides (INS-203) or
    /// unknown fields (INS-006).
    fn obj<'v>(&mut self, v: &'v Value, path: &str, allowed: &[&str], req: &'static str) -> Option<&'v Map> {
        let Some(m) = v.as_map() else {
            self.d.f.error(req, path, format!("expected a map, not {}", v.kind()));
            return None;
        };
        for key in m.keys() {
            if allowed.contains(&key.as_str()) {
                continue;
            }
            if CONTENT_KEYS.contains(&key.as_str()) {
                self.d.f.error_of(
                    FindingKind::ContentOverride,
                    "INS-203",
                    at(path, key),
                    format!("a layout must not set `{key}` here: it carries only container titles, and never changes instrument content"),
                );
            } else {
                self.d.f.error("INS-006", at(path, key), format!("unknown field `{key}`; expected one of: {}", allowed.join(", ")));
            }
        }
        Some(m)
    }

    fn document(&mut self, doc: &Value) -> Option<Layout> {
        let top = self.obj(doc, "", &["apiVersion", "kind", "metadata", "spec"], "INS-200")?;
        if let Some(v) = self.d.req(top, "apiVersion", "", "INS-200")
            && v.as_text() != Some("fieldseal.dev/v1alpha1")
        {
            self.d.f.error("INS-200", "apiVersion", "must be `fieldseal.dev/v1alpha1`");
        }
        if let Some(v) = self.d.req(top, "kind", "", "INS-200")
            && v.as_text() != Some("Layout")
        {
            self.d.f.error("INS-200", "kind", "must be `Layout`");
        }
        let (name, version) = match self.d.req(top, "metadata", "", "INS-200") {
            Some(m) => self.metadata(m),
            None => (None, None),
        };
        let spec_v = self.d.req(top, "spec", "", "INS-200")?;
        let spec = self.obj(spec_v, "spec", &["schema", "instrument", "windowClass", "steps"], "INS-200")?;
        let schema = self.schema(spec);
        let instrument = self.d.req(spec, "instrument", "spec", "INS-200").and_then(|v| match v {
            Value::Text(t) if !t.trim().is_empty() => Some(InstrumentReference::Source(t.clone())),
            Value::Bytes(b) => match Fingerprint::from_bytes(b) {
                Ok(fp) => Some(InstrumentReference::Fingerprint(fp)),
                Err(_) => {
                    self.d.f.error("INS-200", "spec.instrument", "a fingerprint is 32 bytes");
                    None
                }
            },
            _ => {
                self.d.f.error("INS-200", "spec.instrument", "expected the instrument's source path or its fingerprint");
                None
            }
        });
        let window_class = spec.get("windowClass").and_then(|v| {
            self.d.keyword(v, "spec.windowClass", "INS-207", &[("compact", WindowClass::Compact), ("medium", WindowClass::Medium), ("expanded", WindowClass::Expanded)])
        });
        let mut steps = Vec::new();
        if let Some(list) = self.d.req(spec, "steps", "spec", "INS-200").and_then(|v| self.d.array(v, "spec.steps", "INS-200")) {
            if list.is_empty() {
                self.d.f.error("INS-200", "spec.steps", "a layout has at least one step");
            }
            for (i, v) in list.iter().enumerate() {
                if let Some(s) = self.step(v, &idx("spec.steps", i)) {
                    steps.push(s);
                }
            }
        }
        Some(Layout {
            name: name?,
            version: version?,
            schema: schema?,
            instrument: instrument?,
            window_class,
            steps,
            bound: None,
            questions: Vec::new(),
            is_default: false,
        })
    }

    fn metadata(&mut self, v: &Value) -> (Option<String>, Option<SemVer>) {
        let Some(m) = self.obj(v, "metadata", &["name", "version"], "INS-200") else { return (None, None) };
        let name = self.d.req(m, "name", "metadata", "INS-200").and_then(|v| self.d.text(v, "metadata.name", "INS-200"));
        if let Some(n) = &name {
            let ok = n.len() <= 63 && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') && !n.starts_with('-') && !n.ends_with('-');
            if !ok {
                self.d.f.error("INS-200", "metadata.name", "a name is lowercase letters, digits and `-`, at most 63 characters");
            }
        }
        let version = self.d.req(m, "version", "metadata", "INS-200").and_then(|v| {
            let t = self.d.text(v, "metadata.version", "INS-200")?;
            match SemVer::parse(&t) {
                Ok(s) => Some(s),
                Err(e) => {
                    self.d.f.error("INS-200", "metadata.version", e.to_string());
                    None
                }
            }
        });
        (name, version)
    }

    fn schema(&mut self, spec: &Map) -> Option<SchemaRange> {
        let t = self.d.req(spec, "schema", "spec", "INS-200").and_then(|v| self.d.text(v, "spec.schema", "INS-091"))?;
        let range = match SchemaRange::parse(&t) {
            Ok(r) => r,
            Err(e) => {
                self.d.f.error("INS-091", "spec.schema", e.to_string());
                return None;
            }
        };
        if let Compatibility::Incompatible(why) = check_compatibility(range, IMPLEMENTED_SCHEMA) {
            self.d.f.error_of(FindingKind::IncompatibleSchemaRange, "INS-092", "spec.schema", format!("{why} (this format core implements {IMPLEMENTED_SCHEMA})"));
        }
        Some(range)
    }

    fn emphasis(&mut self, m: &Map, p: &str) -> Option<Emphasis> {
        m.get("emphasis").and_then(|v| self.d.keyword(v, &at(p, "emphasis"), "INS-204", &[("normal", Emphasis::Normal), ("compact", Emphasis::Compact)]))
    }

    fn icon(&mut self, m: &Map, p: &str) -> Option<String> {
        let icon = self.d.opt_text(m, "icon", p, "INS-183")?;
        if !is_single_emoji(&icon) {
            self.d.f.error("INS-183", at(p, "icon"), "an icon is a single Unicode emoji");
        }
        Some(icon)
    }

    fn title(&mut self, m: &Map, p: &str, required: bool) -> Option<LocalisedText> {
        match m.get("title") {
            Some(v) => self.d.localised(v, &at(p, "title"), "INS-200"),
            None => {
                if required {
                    self.d.f.error("INS-200", p, "missing `title`");
                }
                None
            }
        }
    }

    fn step(&mut self, v: &Value, p: &str) -> Option<LayoutStep> {
        let m = self.obj(v, p, &["title", "navigation", "emphasis", "contents"], "INS-200")?;
        let title = self.title(m, p, true);
        let navigation = match m.get("navigation") {
            Some(v) => self.d.keyword(v, &at(p, "navigation"), "INS-205", &[("linear", Navigation::Linear), ("free", Navigation::Free)]),
            None => {
                self.d.f.error("INS-205", p, "missing `navigation`: every step declares `linear` or `free`");
                None
            }
        };
        let emphasis = self.emphasis(m, p);
        let contents = self.contents(m, p, Parent::Step);
        Some(LayoutStep { title: title?, navigation: navigation?, emphasis, contents, doc_path: p.to_owned() })
    }

    fn contents(&mut self, m: &Map, p: &str, parent: Parent) -> Vec<Content> {
        let cp = at(p, "contents");
        let Some(list) = self.d.req(m, "contents", p, "INS-200").and_then(|v| self.d.array(v, &cp, "INS-200")) else { return Vec::new() };
        if list.is_empty() {
            self.d.f.error("INS-200", cp.clone(), "a container holds at least one element");
        }
        list.iter().enumerate().filter_map(|(i, v)| self.content(v, &idx(&cp, i), parent)).collect()
    }

    fn container(&mut self, v: &Value, p: &str, parent: Parent, title: Option<bool>) -> Option<Container> {
        let allowed: &[&str] = if title.is_some() { &["title", "icon", "emphasis", "contents"] } else { &["emphasis", "contents"] };
        let m = self.obj(v, p, allowed, "INS-200")?;
        let title = match title {
            Some(required) => self.title(m, p, required),
            None => None,
        };
        let icon = self.icon(m, p);
        let emphasis = self.emphasis(m, p);
        let contents = self.contents(m, p, parent);
        Some(Container { title, icon, emphasis, contents, doc_path: p.to_owned() })
    }

    fn content(&mut self, v: &Value, p: &str, parent: Parent) -> Option<Content> {
        const KINDS: [&str; 6] = ["element", "group", "repeat", "card", "tabs", "row"];
        let Some(m) = v.as_map() else {
            self.d.f.error("INS-201", p, format!("expected a leaf (`element`, `group`, `repeat`) or a container (`card`, `tabs`, `row`), not {}", v.kind()));
            return None;
        };
        let kinds: Vec<&str> = KINDS.iter().copied().filter(|k| m.contains_key(*k)).collect();
        let [kind] = kinds[..] else {
            if m.contains_key("tab") {
                self.d.f.error("INS-200", p, "a `tab` belongs inside `tabs`");
            } else {
                self.d.f.error("INS-201", p, "each entry is exactly one of `element`, `group`, `repeat`, `card`, `tabs` or `row`");
            }
            return None;
        };
        let allowed_here = match parent {
            Parent::Step | Parent::Tab => true,
            Parent::Card => matches!(kind, "element" | "group" | "repeat" | "row"),
            Parent::Row => kind == "element",
        };
        if !allowed_here {
            let what = match parent {
                Parent::Row => "a `row` holds only `{element}` leaves",
                _ => "a `card` holds only leaves and `row`s",
            };
            self.d.f.error("INS-200", p, what);
        }
        match kind {
            "element" => {
                let m = self.obj(v, p, &["element", "presentation"], "INS-201")?;
                let path = self.d.text(&m["element"], &at(p, "element"), "INS-201")?;
                let presentation = m.get("presentation").and_then(|pv| {
                    let name = self.d.text(pv, &at(p, "presentation"), "INS-204")?;
                    let found = Presentation::from_name(&name);
                    if found.is_none() {
                        self.d.f.error_of(FindingKind::UnsupportedPresentation, "INS-204", at(p, "presentation"), format!("`{name}` is not a presentation of the control catalogue"));
                    }
                    found
                });
                Some(Content::Element { path, presentation, doc_path: p.to_owned() })
            }
            "group" => {
                let m = self.obj(v, p, &["group"], "INS-201")?;
                let path = self.d.text(&m["group"], &at(p, "group"), "INS-201")?;
                Some(Content::Group { path, doc_path: p.to_owned() })
            }
            "repeat" => {
                let m = self.obj(v, p, &["repeat", "as"], "INS-201")?;
                let path = self.d.text(&m["repeat"], &at(p, "repeat"), "INS-201")?;
                let repeat_as = match m.get("as") {
                    Some(a) => self.d.keyword(a, &at(p, "as"), "INS-201", &[("table", RepeatAs::Table), ("list", RepeatAs::List)])?,
                    None => {
                        self.d.f.error("INS-201", p, "a `{repeat}` leaf declares `as: table | list`");
                        return None;
                    }
                };
                Some(Content::Repeat { path, repeat_as, doc_path: p.to_owned() })
            }
            "card" => {
                self.obj(v, p, &["card"], "INS-200")?;
                self.container(&m["card"], &at(p, "card"), Parent::Card, Some(false)).map(Content::Card)
            }
            "row" => {
                self.obj(v, p, &["row"], "INS-200")?;
                self.container(&m["row"], &at(p, "row"), Parent::Row, None).map(Content::Row)
            }
            _ => {
                self.obj(v, p, &["tabs"], "INS-200")?;
                let tp = at(p, "tabs");
                let list = self.d.array(&m["tabs"], &tp, "INS-215")?;
                if list.is_empty() {
                    self.d.f.error("INS-215", tp.clone(), "`tabs` holds at least one `tab`");
                }
                let mut tabs = Vec::new();
                for (i, t) in list.iter().enumerate() {
                    let ip = idx(&tp, i);
                    let Some(tm) = self.obj(t, &ip, &["tab"], "INS-215") else { continue };
                    let Some(tv) = tm.get("tab") else {
                        self.d.f.error("INS-215", ip, "`tabs` holds only `tab` entries");
                        continue;
                    };
                    if let Some(c) = self.container(tv, &at(&ip, "tab"), Parent::Tab, Some(true)) {
                        tabs.push(c);
                    }
                }
                Some(Content::Tabs { tabs, doc_path: p.to_owned() })
            }
        }
    }
}

// ---- placement --------------------------------------------------------------------------------

/// One element a leaf places: a question or display node, with the leaf that placed it.
struct Placed<'l> {
    node: usize,
    leaf: &'l str,
}

/// What a tab places, to find the one group it holds (INS-215).
#[derive(Default)]
struct TabInfo {
    /// For each leaf: the group it is inside, or the group or repeat it places.
    anchors: Vec<Option<usize>>,
}

struct Placement<'c, 'l> {
    compiled: &'c CompiledInstrument,
    placed: Vec<Placed<'l>>,
    f: Findings,
    /// The stack of tabs being walked, innermost last.
    tabs: Vec<TabInfo>,
}

fn check_placement(layout: &Layout, compiled: &CompiledInstrument, f: &mut Findings) {
    let mut pl = Placement { compiled, placed: Vec::new(), f: Findings::new(), tabs: Vec::new() };
    for step in &layout.steps {
        pl.contents(&step.contents);
    }
    let Placement { placed, f: found, .. } = pl;
    f.extend(found);

    // Exactly once (INS-202) and in tree order (INS-214).
    let mut count: BTreeMap<usize, usize> = BTreeMap::new();
    let mut highest: Option<usize> = None;
    let mut order_reported: BTreeSet<&str> = BTreeSet::new();
    for p in &placed {
        let n = count.entry(p.node).or_insert(0);
        *n += 1;
        let path = &compiled.nodes()[p.node].path;
        if *n == 2 {
            f.error_of(FindingKind::DuplicatePlacement, "INS-202", p.leaf, format!("`{path}` is already placed; every element is placed once"));
        }
        if *n > 1 {
            continue;
        }
        match highest {
            Some(h) if p.node < h => {
                if order_reported.insert(p.leaf) {
                    let after = &compiled.nodes()[h].path;
                    f.error_of(
                        FindingKind::OrderChanged,
                        "INS-214",
                        p.leaf,
                        format!("`{path}` comes before `{after}` in the instrument, but is placed after it; a layout partitions, never permutes"),
                    );
                }
            }
            _ => highest = Some(p.node),
        }
    }
    // Unplaced questions, reported once for the largest wholly unplaced group.
    let mut stack: Vec<usize> = compiled.roots().iter().rev().copied().collect();
    while let Some(i) = stack.pop() {
        let node = &compiled.nodes()[i];
        let questions = compiled.questions_under(i);
        let unplaced: Vec<usize> = questions.iter().copied().filter(|q| !count.contains_key(q)).collect();
        if unplaced.is_empty() {
            continue;
        }
        match &node.kind {
            NodeKind::Group(_) if unplaced.len() == questions.len() => {
                f.error_of(FindingKind::UnplacedQuestion, "INS-202", "spec.steps", format!("no question of `{}` is placed; every question is placed exactly once", node.path));
            }
            NodeKind::Question(_) => {
                f.error_of(FindingKind::UnplacedQuestion, "INS-202", "spec.steps", format!("question `{}` is not placed; every question is placed exactly once", node.path));
            }
            _ => stack.extend(node.children.iter().rev()),
        }
    }
}

impl<'l> Placement<'_, 'l> {
    fn contents(&mut self, contents: &'l [Content]) {
        for c in contents {
            self.content(c);
        }
    }

    fn anchor(&mut self, a: Option<usize>) {
        if let Some(t) = self.tabs.last_mut() {
            t.anchors.push(a);
        }
    }

    fn place_subtree(&mut self, i: usize, leaf: &'l str) {
        let mut stack = vec![i];
        while let Some(n) = stack.pop() {
            if matches!(self.compiled.nodes()[n].kind, NodeKind::Question(_) | NodeKind::Display(_)) {
                self.placed.push(Placed { node: n, leaf });
            }
            stack.extend(self.compiled.nodes()[n].children.iter().rev());
        }
    }

    fn content(&mut self, c: &'l Content) {
        let compiled = self.compiled;
        match c {
            Content::Element { path, presentation, doc_path } => {
                let Some(i) = compiled.node_index(path) else {
                    self.f.error_of(FindingKind::UnknownItemPath, "INS-201", at(doc_path, "element"), format!("no question or display element at `{path}`"));
                    return;
                };
                let node = &compiled.nodes()[i];
                match &node.kind {
                    NodeKind::Group(g) => {
                        let use_ = if g.repeat_over.is_some() { "`{repeat}`" } else { "`{group}`" };
                        self.f.error("INS-201", at(doc_path, "element"), format!("`{path}` is a group; place it with {use_}"));
                        return;
                    }
                    NodeKind::Question(q) => {
                        if let QuestionOrigin::OtherText { of } = &q.origin {
                            self.f.error("INS-201", at(doc_path, "element"), format!("`{path}` is the text of the `other` code of `{of}`, and is placed with it"));
                            return;
                        }
                        self.placed.push(Placed { node: i, leaf: doc_path });
                        // The text of an `other` code follows its question (INS-137).
                        let other = format!("{path}.other");
                        if let Some(o) = compiled.node_index(&other)
                            && matches!(compiled.nodes()[o].question().map(|q| &q.origin), Some(QuestionOrigin::OtherText { .. }))
                        {
                            self.placed.push(Placed { node: o, leaf: doc_path });
                        }
                        if let Some(p) = presentation {
                            check_presentation(q.control.as_ref(), *p, path, &at(doc_path, "presentation"), &mut self.f);
                        }
                    }
                    NodeKind::Display(_) => {
                        self.placed.push(Placed { node: i, leaf: doc_path });
                        if presentation.is_some() {
                            self.f.error_of(FindingKind::UnsupportedPresentation, "INS-204", at(doc_path, "presentation"), format!("`{path}` is a display element; only a question's control has a presentation"));
                        }
                    }
                }
                self.anchor(node.parent);
            }
            Content::Group { path, doc_path } => {
                let Some(i) = compiled.node_index(path) else {
                    self.f.error_of(FindingKind::UnknownItemPath, "INS-201", at(doc_path, "group"), format!("no group at `{path}`"));
                    return;
                };
                let problem = match &compiled.nodes()[i].kind {
                    NodeKind::Group(g) if g.repeat_over.is_some() => Some(format!("`{path}` is a repeat group; place it with `{{repeat: {path}, as: table | list}}`")),
                    NodeKind::Group(g) if g.instance_code.is_some() => Some(format!("`{path}` is a repeat instance; place its repeat with `{{repeat}}`, or its questions with `{{element}}`")),
                    NodeKind::Group(_) => None,
                    _ => Some(format!("`{path}` is not a group; place it with `{{element}}`")),
                };
                if let Some(m) = problem {
                    self.f.error("INS-201", at(doc_path, "group"), m);
                    return;
                }
                self.place_subtree(i, doc_path);
                self.anchor(Some(i));
            }
            Content::Repeat { path, doc_path, .. } => {
                let Some(i) = compiled.node_index(path) else {
                    self.f.error_of(FindingKind::UnknownItemPath, "INS-201", at(doc_path, "repeat"), format!("no repeat group at `{path}`"));
                    return;
                };
                if !matches!(&compiled.nodes()[i].kind, NodeKind::Group(g) if g.repeat_over.is_some()) {
                    self.f.error("INS-201", at(doc_path, "repeat"), format!("`{path}` is not a repeat group"));
                    return;
                }
                self.place_subtree(i, doc_path);
                self.anchor(Some(i));
            }
            Content::Card(c) | Content::Row(c) => self.contents(&c.contents),
            Content::Tabs { tabs, .. } => {
                let mut groups: Vec<(usize, &str)> = Vec::new();
                for tab in tabs {
                    self.tabs.push(TabInfo::default());
                    self.contents(&tab.contents);
                    let info = self.tabs.pop().unwrap_or_default();
                    // Nested tabs' anchors also belong to the enclosing tab.
                    if let Some(outer) = self.tabs.last_mut() {
                        outer.anchors.extend(info.anchors.iter().copied());
                    }
                    match tab_group(compiled, &info) {
                        Ok(g) => groups.push((g, &tab.doc_path)),
                        Err(m) => self.f.error("INS-215", tab.doc_path.clone(), m),
                    }
                }
                for w in groups.windows(2) {
                    let ((a, _), (b, bp)) = (w[0], w[1]);
                    let (na, nb) = (&compiled.nodes()[a], &compiled.nodes()[b]);
                    if na.parent != nb.parent {
                        self.f.error("INS-215", bp, format!("the groups of one `tabs` are siblings; `{}` and `{}` are not", na.path, nb.path));
                    } else if a == b {
                        self.f.error("INS-215", bp, format!("each tab holds a different group; `{}` is already a tab", nb.path));
                    } else if b < a {
                        self.f.error_of(FindingKind::OrderChanged, "INS-215", bp, format!("tabs follow the instrument's order; `{}` comes before `{}`", nb.path, na.path));
                    }
                }
            }
        }
    }
}

/// The one group a tab holds: the deepest group containing everything it places.
fn tab_group(compiled: &CompiledInstrument, info: &TabInfo) -> Result<usize, String> {
    if info.anchors.is_empty() {
        return Err("a tab holds exactly one group of the instrument; this one places nothing".into());
    }
    let chain = |a: usize| {
        let mut out = vec![a];
        let mut cur = compiled.nodes()[a].parent;
        while let Some(p) = cur {
            out.push(p);
            cur = compiled.nodes()[p].parent;
        }
        out.reverse();
        out
    };
    let mut common: Option<Vec<usize>> = None;
    for a in &info.anchors {
        let Some(a) = a else {
            return Err("a tab holds exactly one group of the instrument; this one places a top-level element".into());
        };
        let c = chain(*a);
        common = Some(match common {
            None => c,
            Some(prev) => prev.iter().zip(c.iter()).take_while(|(x, y)| x == y).map(|(x, _)| *x).collect(),
        });
    }
    common.and_then(|c| c.last().copied()).ok_or_else(|| "a tab holds exactly one group of the instrument; this one places elements of several top-level groups".into())
}

/// INS-204: the presentations each control allows (§5.3).
fn check_presentation(control: Option<&Control>, p: Presentation, path: &str, doc: &str, f: &mut Findings) {
    let allowed: &[Presentation] = match control {
        Some(Control::Scale { .. }) => &[Presentation::Slider, Presentation::Segments],
        Some(Control::YesNo { .. }) => &[Presentation::Switch, Presentation::Buttons],
        Some(Control::Money(_)) => &[Presentation::Stepper, Presentation::Entry],
        _ => &[],
    };
    if !allowed.contains(&p) {
        let control = control.map_or("a read-only item", |c| c.control_type().name());
        let names: Vec<&str> = allowed.iter().map(|a| a.name()).collect();
        let options = if names.is_empty() { "none".to_owned() } else { names.join(", ") };
        f.error_of(FindingKind::UnsupportedPresentation, "INS-204", doc, format!("`{path}` is {control}, whose presentations are: {options}; not `{}`", p.name()));
    }
}
