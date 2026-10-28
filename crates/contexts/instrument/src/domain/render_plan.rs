//! The render plan (INS-206–INS-208, ADR 0033): the platform-neutral tree compiled from an
//! instrument and a layout (or the default layout) for one language and window class.
//!
//! Every platform draws the same plan. A renderer MUST draw the nodes in order and MUST NOT
//! regroup, reorder or omit them (INS-208); it decides only how each node kind looks.
//!
//! # Shape
//!
//! A [`RenderPlan`] carries metadata (language and direction, INS-087; window class; layout
//! identity, INS-209; instrument labels) and a list of root [`PlanNode`]s, each a `step` or
//! the final `review` step. Every node has:
//! - `id`: its position in a pre-order walk of the whole plan, from 0. [`PlanVisibility`] is
//!   indexed by it.
//! - `bind`: the instrument path it shows (an item path, a group, repeat or instance path,
//!   or a display path), or none for containers that come from the layout.
//! - `disabled_display`: how it is drawn while hidden (INS-125): `hidden` (not drawn) or
//!   `protected` (drawn visibly disabled).
//! - `kind`: one of [`PlanKind`], with its kind-specific fields.
//! - `children`: its children, in drawing order.
//!
//! Containment: `step` holds anything but steps; `tabs` holds only `tab`s; `tab`, `card`,
//! `group` and `instance` hold anything but steps; `row` holds `question`s and `display`s;
//! `table` and `list` hold only `instance`s. `question` and `display` are leaves.
//!
//! # Visibility
//!
//! A plan is static. [`resolve_visibility`](crate::application::resolve_visibility) gives each
//! node's current [`Visibility`](super::Visibility) from the record's values: a bound node takes
//! its path's visibility from the rules (INS-124, INS-125); a container without a binding is
//! visible if any child is visible, otherwise protected if any child is protected, otherwise
//! hidden. A renderer draws `Visible` nodes normally, `Protected` nodes disabled, and skips
//! `Hidden` nodes (and their subtrees).
//!
//! # Texts and numbers
//!
//! Every text is resolved to the plan's language ([`PlanText`]). A text with variables is a
//! MessageFormat 2 message (INS-084) to be formatted with the roster and record values.
//! Numbers (bounds, steps, tolerances) are decimals, not formatted for the locale: locale
//! formatting with CLDR (INS-088) is the renderer's job until the format core provides it.
//! Nonresponse actions carry codes only; their labels are platform text.

use std::collections::BTreeMap;

use fieldseal_kernel::id::ContentAddress;
use fieldseal_kernel::{Decimal, Value};

use super::codes::Nonresponse;
use super::control::ControlType;
use super::element::{DataType, DisabledDisplay, DisplayRole};
use super::evaluation::Visibility;
use super::language::{Direction, LanguageTag};
use super::layout::{Emphasis, Navigation, Presentation, WindowClass};

/// Which layout a plan was compiled from (INS-209, WIRE-051).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LayoutIdentity {
    /// The generated default layout (INS-206); records name `"default"`.
    Default,
    /// A published layout, by its content address.
    Address(ContentAddress),
}

/// A text in the plan's language.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlanText {
    /// The text. Without variables, it is shown as it is.
    pub text: String,
    /// The message variables (`roster.<field>` or item paths), sorted. When not empty, `text`
    /// is a MessageFormat 2 message to format with their values (INS-084, INS-088).
    pub variables: Vec<String>,
}

/// An embedded image (INS-180, INS-181), chosen for the plan's language (INS-086).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlanMedia {
    /// The media id in the instrument's `spec.media`; its bytes are in the instrument.
    pub id: String,
    /// `image/png`, `image/webp` or `image/svg+xml`.
    pub media_type: String,
    /// The SHA-256 of its bytes, lowercase hex.
    pub sha256: String,
    /// Its alternative text.
    pub alt: PlanText,
}

/// A unit with its label (INS-160).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlanUnit {
    /// The UCUM code the value is recorded in.
    pub code: String,
    /// The label to show, where the code isn't readable.
    pub label: Option<PlanText>,
}

/// One option of a coded control (INS-131).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlanOption {
    /// The code recorded.
    pub code: String,
    /// Its label.
    pub label: PlanText,
    /// A longer description.
    pub description: Option<PlanText>,
    /// A single emoji (INS-183).
    pub icon: Option<String>,
    /// An image.
    pub media: Option<PlanMedia>,
    /// Whether selecting it deselects every other code, in a multi-choice (INS-133).
    pub exclusive: bool,
}

/// The "other, specify" code of a coded control (INS-134). Its text is asked by the
/// `question` node that follows, whose origin is [`PlanOrigin::OtherText`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlanOther {
    /// The code that asks for text.
    pub code: String,
    /// The label of the text answer.
    pub label: PlanText,
    /// The longest text, in characters.
    pub max_length: u32,
}

/// A question's control, with its configuration resolved (INS §5.3). Options are in the
/// instrument's order; a renderer MUST NOT reorder them or preselect one (INS-020, INS-203).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PlanControl {
    /// One code.
    Choice {
        /// The options.
        options: Vec<PlanOption>,
        /// The "other" code, if the list has one.
        other: Option<PlanOther>,
    },
    /// A set of codes, written as a whole (INS-030, INS-133).
    MultiChoice {
        /// The options.
        options: Vec<PlanOption>,
        /// The "other" code, if the list has one.
        other: Option<PlanOther>,
        /// The most codes that may be selected.
        max: Option<u32>,
    },
    /// An ordinal scale; steps in order, none preselected.
    Scale {
        /// The steps.
        steps: Vec<PlanOption>,
    },
    /// A stepper (INS-163): the first press sets `start`.
    Stepper {
        /// The lowest value.
        min: Decimal,
        /// The highest value.
        max: Decimal,
        /// The value of the first press.
        start: Decimal,
        /// The grid step.
        step: Decimal,
        /// The unit.
        unit: Option<PlanUnit>,
    },
    /// A typed number.
    Number {
        /// The lowest value, in `unit`.
        min: Option<Decimal>,
        /// The highest value, in `unit`.
        max: Option<Decimal>,
        /// The most fraction digits.
        decimals: u32,
        /// The unit.
        unit: Option<PlanUnit>,
        /// UCUM codes the collector may enter instead (INS-161).
        entry_units: Vec<String>,
    },
    /// Money (INS-162).
    Money {
        /// The ISO 4217 code.
        currency: String,
        /// The currency's minor-unit digits.
        minor_digits: u32,
        /// The lowest amount.
        min: Option<Decimal>,
        /// The highest amount.
        max: Option<Decimal>,
        /// The grid step, if any.
        step: Option<Decimal>,
    },
    /// Two readings (INS-026).
    MeasurementPair {
        /// The lowest reading.
        min: Option<Decimal>,
        /// The highest reading.
        max: Option<Decimal>,
        /// The most fraction digits.
        decimals: u32,
        /// The unit.
        unit: Option<PlanUnit>,
        /// UCUM codes the collector may enter instead.
        entry_units: Vec<String>,
        /// The largest allowed difference.
        tolerance: Decimal,
    },
    /// Free text.
    Text {
        /// The longest text.
        max_length: Option<u32>,
        /// Whether line breaks are allowed.
        multiline: bool,
    },
    /// A code, or `other` with text.
    CodedListWithOther {
        /// The options.
        options: Vec<PlanOption>,
        /// The `other` option.
        other: PlanOther,
    },
    /// Yes or no; neither lit until set.
    YesNo,
    /// A date, `YYYY-MM-DD`.
    Date {
        /// The earliest date.
        min: Option<String>,
        /// The latest date.
        max: Option<String>,
    },
    /// An evidence photo.
    PhotoEvidence {
        /// The longest side, in pixels.
        max_dimension: Option<u32>,
    },
}

impl PlanControl {
    /// The control's catalogue type.
    pub fn control_type(&self) -> ControlType {
        match self {
            PlanControl::Choice { .. } => ControlType::Choice,
            PlanControl::MultiChoice { .. } => ControlType::MultiChoice,
            PlanControl::Scale { .. } => ControlType::Scale,
            PlanControl::Stepper { .. } => ControlType::Stepper,
            PlanControl::Number { .. } => ControlType::Number,
            PlanControl::Money { .. } => ControlType::Money,
            PlanControl::MeasurementPair { .. } => ControlType::MeasurementPair,
            PlanControl::Text { .. } => ControlType::Text,
            PlanControl::CodedListWithOther { .. } => ControlType::CodedListWithOther,
            PlanControl::YesNo => ControlType::YesNo,
            PlanControl::Date { .. } => ControlType::Date,
            PlanControl::PhotoEvidence { .. } => ControlType::PhotoEvidence,
        }
    }

    /// The options or steps of a coded control.
    pub fn options(&self) -> &[PlanOption] {
        match self {
            PlanControl::Choice { options, .. } | PlanControl::MultiChoice { options, .. } | PlanControl::CodedListWithOther { options, .. } => options,
            PlanControl::Scale { steps } => steps,
            _ => &[],
        }
    }
}

/// Where a question came from.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PlanOrigin {
    /// Written by the author.
    Authored,
    /// The text of the "other" code of the question at `of` (INS-137); it follows that
    /// question, and is visible only while the code is chosen.
    OtherText {
        /// The question it belongs to.
        of: String,
    },
    /// The text naming the item of a repeat instance whose code is the list's "other" code
    /// (INS-134); the first child of that instance, drawn with the instance's heading.
    InstanceName,
}

/// A question node's content.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlanQuestion {
    /// The question as asked.
    pub label: PlanText,
    /// The printed number.
    pub prefix: Option<String>,
    /// A short label (review summaries).
    pub short_label: Option<PlanText>,
    /// Help for whoever answers.
    pub help: Option<PlanText>,
    /// Guidance for the collector only; absent when the instrument is self-administered
    /// (INS-151). With administration `both`, show it only to a collector.
    pub guidance: Option<PlanText>,
    /// An image.
    pub media: Option<PlanMedia>,
    /// The control; absent for a read-only roster item (INS-013a).
    pub control: Option<PlanControl>,
    /// The presentation: the layout's choice (INS-204), else the instrument's, else none
    /// (the platform's usual one).
    pub presentation: Option<Presentation>,
    /// For a read-only item, the roster field it shows (INS-013).
    pub roster_field: Option<String>,
    /// The value type recorded (INS-070).
    pub data_type: DataType,
    /// The nonresponse actions offered next to the control, in this order (INS-140).
    pub nonresponse: Vec<Nonresponse>,
    /// Excluded from the unanswered count (INS-014).
    pub optional: bool,
    /// Where it came from.
    pub origin: PlanOrigin,
    /// Inside a repeat instance: the path relative to the instance (for example `freq`),
    /// which is the column key in a `table`.
    pub column: Option<String>,
}

/// A column of a `table` (a question of the repeated group).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlanColumn {
    /// The key: a question's path relative to its instance.
    pub key: String,
    /// The heading: the question's label.
    pub label: PlanText,
    /// The question's printed number.
    pub prefix: Option<String>,
}

/// A heading taken from an instrument group, repeat group or instance.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlanHeading {
    /// The label.
    pub label: PlanText,
    /// The description.
    pub description: Option<PlanText>,
    /// The reference period, for example "in the last month".
    pub reference_period: Option<PlanText>,
    /// An image.
    pub media: Option<PlanMedia>,
    /// A single emoji (a repeat instance's code icon).
    pub icon: Option<String>,
}

/// What a node is, with its kind-specific fields.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PlanKind {
    /// One stage of navigation (`kind: step`).
    Step {
        /// The title.
        title: PlanText,
        /// `linear`: visited in order, may go back; `free`: any step (INS-205).
        navigation: Navigation,
        /// The density.
        emphasis: Option<Emphasis>,
    },
    /// The final review step of the default layout (INS-206, COL-060): the platform draws its
    /// own review of the record here. It has no children (`kind: review`).
    Review,
    /// Tabs between sibling groups, always freely navigable (`kind: tabs`, INS-205, INS-215).
    Tabs,
    /// One tab (`kind: tab`).
    Tab {
        /// The title.
        title: PlanText,
        /// A single emoji.
        icon: Option<String>,
        /// The density.
        emphasis: Option<Emphasis>,
    },
    /// A visually bounded group from the layout (`kind: card`).
    Card {
        /// The heading.
        title: Option<PlanText>,
        /// A single emoji.
        icon: Option<String>,
        /// The density.
        emphasis: Option<Emphasis>,
    },
    /// Controls side by side on wide screens, stacked on compact ones (`kind: row`).
    Row {
        /// The density.
        emphasis: Option<Emphasis>,
    },
    /// An instrument group, drawn as a card with its heading (`kind: group`).
    Group(PlanHeading),
    /// A repeat group as a grid: children are `instance` rows, questions are cells keyed by
    /// [`PlanQuestion::column`] (`kind: table`).
    Table {
        /// The repeat group's heading.
        heading: PlanHeading,
        /// The columns, in order.
        columns: Vec<PlanColumn>,
    },
    /// A repeat group item by item: children are `instance`s, each drawn as a card
    /// (`kind: list`).
    List(PlanHeading),
    /// One repeat instance (`kind: instance`).
    Instance {
        /// The code of the instance.
        code: String,
        /// Its heading, from the code (INS-127).
        heading: PlanHeading,
    },
    /// A question (`kind: question`).
    Question(Box<PlanQuestion>),
    /// Text or media that records nothing (`kind: display`).
    Display {
        /// Its role.
        role: DisplayRole,
        /// Its text.
        text: Option<PlanText>,
        /// Its image.
        media: Option<PlanMedia>,
    },
}

impl PlanKind {
    /// The kind's name in the serialised plan.
    pub fn name(&self) -> &'static str {
        match self {
            PlanKind::Step { .. } => "step",
            PlanKind::Review => "review",
            PlanKind::Tabs => "tabs",
            PlanKind::Tab { .. } => "tab",
            PlanKind::Card { .. } => "card",
            PlanKind::Row { .. } => "row",
            PlanKind::Group(_) => "group",
            PlanKind::Table { .. } => "table",
            PlanKind::List(_) => "list",
            PlanKind::Instance { .. } => "instance",
            PlanKind::Question(_) => "question",
            PlanKind::Display { .. } => "display",
        }
    }
}

/// One node of a render plan.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlanNode {
    /// Its pre-order position in the plan, from 0.
    pub id: usize,
    /// The instrument path it shows, if it shows one.
    pub bind: Option<String>,
    /// How it is drawn while hidden (INS-125).
    pub disabled_display: DisabledDisplay,
    /// What it is.
    pub kind: PlanKind,
    /// Its children, in drawing order.
    pub children: Vec<PlanNode>,
    /// The layout document path it came from (for lint findings). Not part of the
    /// serialised plan.
    pub source: String,
}

impl PlanNode {
    /// The question, if this is one.
    pub fn question(&self) -> Option<&PlanQuestion> {
        match &self.kind {
            PlanKind::Question(q) => Some(q),
            _ => None,
        }
    }

    /// This node and its descendants, in pre-order (ascending `id`).
    pub fn walk(&self) -> Vec<&PlanNode> {
        let mut out = Vec::new();
        let mut stack = vec![self];
        while let Some(n) = stack.pop() {
            out.push(n);
            stack.extend(n.children.iter().rev());
        }
        out
    }
}

/// Labels of the instrument a plan was compiled from.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlanInstrument {
    /// `metadata.name`: a label (INS-101).
    pub name: String,
    /// `metadata.version`: a label.
    pub version: String,
    /// The title.
    pub title: PlanText,
    /// `interviewer`, `self` or `both` (INS-110).
    pub administration: &'static str,
}

/// A compiled render plan (`CompileRenderPlan`, INS-206–INS-208).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RenderPlan {
    /// The instrument's labels.
    pub instrument: PlanInstrument,
    /// The selected language (INS-087).
    pub language: LanguageTag,
    /// Its text direction (INS-087).
    pub direction: Direction,
    /// The window class the plan was compiled for (INS-207).
    pub window_class: WindowClass,
    /// The window class the layout declares, if any.
    pub layout_window_class: Option<WindowClass>,
    /// The layout (INS-209).
    pub layout: LayoutIdentity,
    /// The steps, in order; the default layout ends with a `review` step.
    pub steps: Vec<PlanNode>,
}

impl RenderPlan {
    /// Every node, in pre-order: `nodes()[i].id == i`.
    pub fn nodes(&self) -> Vec<&PlanNode> {
        self.steps.iter().flat_map(PlanNode::walk).collect()
    }

    /// The number of nodes.
    pub fn node_count(&self) -> usize {
        self.steps.iter().map(|s| s.walk().len()).sum()
    }

    /// The first node bound to `path`.
    pub fn node_bound_to(&self, path: &str) -> Option<&PlanNode> {
        self.nodes().into_iter().find(|n| n.bind.as_deref() == Some(path))
    }

    /// The serialised plan, for adapters to emit as JSON or CBOR. Keys are camelCase; absent
    /// optional fields and `false` flags are left out. The same plan always gives the same
    /// value (INS-208).
    ///
    /// ```text
    /// { instrument: {name, version, title, administration},
    ///   language, direction: ltr|rtl, windowClass, layoutWindowClass?,
    ///   layout: "default" | bytes(32),
    ///   steps: [node] }
    /// node = { id, kind, bind?, disabledDisplay: hidden|protected, children?: [node], …kind fields }
    /// ```
    pub fn to_value(&self) -> Value {
        let mut m = Obj::default();
        let mut ins = Obj::default();
        ins.text("name", &self.instrument.name);
        ins.text("version", &self.instrument.version);
        ins.put("title", text_value(&self.instrument.title));
        ins.text("administration", self.instrument.administration);
        m.put("instrument", ins.done());
        m.text("language", self.language.as_str());
        m.text("direction", self.direction.name());
        m.text("windowClass", self.window_class.name());
        if let Some(c) = self.layout_window_class {
            m.text("layoutWindowClass", c.name());
        }
        m.put(
            "layout",
            match self.layout {
                LayoutIdentity::Default => Value::Text("default".into()),
                LayoutIdentity::Address(a) => Value::Bytes(a.as_bytes().to_vec()),
            },
        );
        m.put("steps", Value::Array(self.steps.iter().map(node_value).collect()));
        m.done()
    }
}

/// Each plan node's current visibility (`ResolveVisibility`), indexed by node `id`.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct PlanVisibility {
    pub(crate) nodes: Vec<Visibility>,
}

impl PlanVisibility {
    /// The visibility of node `id` (`Visible` for an id outside the plan).
    pub fn of(&self, id: usize) -> Visibility {
        self.nodes.get(id).copied().unwrap_or(Visibility::Visible)
    }

    /// Every node's visibility, by id.
    pub fn as_slice(&self) -> &[Visibility] {
        &self.nodes
    }

    /// The serialised form: an array of `visible`, `protected` or `hidden`, by node id.
    pub fn to_value(&self) -> Value {
        Value::Array(self.nodes.iter().map(|v| Value::Text(visibility_name(*v).into())).collect())
    }
}

/// `visible`, `protected` or `hidden`.
pub fn visibility_name(v: Visibility) -> &'static str {
    match v {
        Visibility::Visible => "visible",
        Visibility::Protected => "protected",
        Visibility::Hidden => "hidden",
    }
}

/// `instruction`, `note`, `introduction` or `end`.
pub fn display_role_name(r: DisplayRole) -> &'static str {
    match r {
        DisplayRole::Instruction => "instruction",
        DisplayRole::Note => "note",
        DisplayRole::Introduction => "introduction",
        DisplayRole::End => "end",
    }
}

// ---- serialisation ------------------------------------------------------------------------

#[derive(Default)]
struct Obj(BTreeMap<String, Value>);

impl Obj {
    fn put(&mut self, k: &str, v: Value) {
        self.0.insert(k.to_owned(), v);
    }
    fn text(&mut self, k: &str, v: &str) {
        self.put(k, Value::Text(v.to_owned()));
    }
    fn opt_text(&mut self, k: &str, v: Option<&str>) {
        if let Some(v) = v {
            self.text(k, v);
        }
    }
    fn plan_text(&mut self, k: &str, v: Option<&PlanText>) {
        if let Some(v) = v {
            self.put(k, text_value(v));
        }
    }
    fn dec(&mut self, k: &str, v: Option<Decimal>) {
        if let Some(v) = v {
            self.put(k, Value::Decimal(v));
        }
    }
    fn uint(&mut self, k: &str, v: Option<u32>) {
        if let Some(v) = v {
            self.put(k, Value::Int(i128::from(v)));
        }
    }
    fn flag(&mut self, k: &str, v: bool) {
        if v {
            self.put(k, Value::Bool(true));
        }
    }
    fn media(&mut self, k: &str, v: Option<&PlanMedia>) {
        if let Some(media) = v {
            let mut o = Obj::default();
            o.text("id", &media.id);
            o.text("mediaType", &media.media_type);
            o.text("sha256", &media.sha256);
            o.put("alt", text_value(&media.alt));
            self.put(k, o.done());
        }
    }
    fn emphasis(&mut self, v: Option<Emphasis>) {
        self.opt_text("emphasis", v.map(Emphasis::name));
    }
    fn unit(&mut self, v: Option<&PlanUnit>) {
        if let Some(u) = v {
            let mut o = Obj::default();
            o.text("code", &u.code);
            o.plan_text("label", u.label.as_ref());
            self.put("unit", o.done());
        }
    }
    fn heading(&mut self, h: &PlanHeading) {
        self.put("label", text_value(&h.label));
        self.plan_text("description", h.description.as_ref());
        self.plan_text("referencePeriod", h.reference_period.as_ref());
        self.media("media", h.media.as_ref());
        self.opt_text("icon", h.icon.as_deref());
    }
    fn done(self) -> Value {
        Value::Map(self.0)
    }
}

fn text_value(t: &PlanText) -> Value {
    if t.variables.is_empty() {
        return Value::Text(t.text.clone());
    }
    let mut o = Obj::default();
    o.text("message", &t.text);
    o.put("variables", Value::Array(t.variables.iter().map(|v| Value::Text(v.clone())).collect()));
    o.done()
}

fn option_value(o: &PlanOption) -> Value {
    let mut m = Obj::default();
    m.text("code", &o.code);
    m.put("label", text_value(&o.label));
    m.plan_text("description", o.description.as_ref());
    m.opt_text("icon", o.icon.as_deref());
    m.media("media", o.media.as_ref());
    m.flag("exclusive", o.exclusive);
    m.done()
}

fn options_value(options: &[PlanOption]) -> Value {
    Value::Array(options.iter().map(option_value).collect())
}

fn other_value(o: &PlanOther) -> Value {
    let mut m = Obj::default();
    m.text("code", &o.code);
    m.put("label", text_value(&o.label));
    m.uint("maxLength", Some(o.max_length));
    m.done()
}

fn entry_units_value(units: &[String]) -> Option<Value> {
    (!units.is_empty()).then(|| Value::Array(units.iter().map(|u| Value::Text(u.clone())).collect()))
}

fn control_value(c: &PlanControl) -> Value {
    let mut m = Obj::default();
    m.text("type", c.control_type().name());
    match c {
        PlanControl::Choice { options, other } => {
            m.put("options", options_value(options));
            if let Some(o) = other {
                m.put("other", other_value(o));
            }
        }
        PlanControl::MultiChoice { options, other, max } => {
            m.put("options", options_value(options));
            if let Some(o) = other {
                m.put("other", other_value(o));
            }
            m.uint("max", *max);
        }
        PlanControl::Scale { steps } => m.put("steps", options_value(steps)),
        PlanControl::Stepper { min, max, start, step, unit } => {
            m.dec("min", Some(*min));
            m.dec("max", Some(*max));
            m.dec("start", Some(*start));
            m.dec("step", Some(*step));
            m.unit(unit.as_ref());
        }
        PlanControl::Number { min, max, decimals, unit, entry_units } => {
            m.dec("min", *min);
            m.dec("max", *max);
            m.uint("decimals", Some(*decimals));
            m.unit(unit.as_ref());
            if let Some(v) = entry_units_value(entry_units) {
                m.put("entryUnits", v);
            }
        }
        PlanControl::Money { currency, minor_digits, min, max, step } => {
            m.text("currency", currency);
            m.uint("minorDigits", Some(*minor_digits));
            m.dec("min", *min);
            m.dec("max", *max);
            m.dec("step", *step);
        }
        PlanControl::MeasurementPair { min, max, decimals, unit, entry_units, tolerance } => {
            m.dec("min", *min);
            m.dec("max", *max);
            m.uint("decimals", Some(*decimals));
            m.unit(unit.as_ref());
            if let Some(v) = entry_units_value(entry_units) {
                m.put("entryUnits", v);
            }
            m.dec("tolerance", Some(*tolerance));
        }
        PlanControl::Text { max_length, multiline } => {
            m.uint("maxLength", *max_length);
            m.flag("multiline", *multiline);
        }
        PlanControl::CodedListWithOther { options, other } => {
            m.put("options", options_value(options));
            m.put("other", other_value(other));
        }
        PlanControl::YesNo => {}
        PlanControl::Date { min, max } => {
            m.opt_text("min", min.as_deref());
            m.opt_text("max", max.as_deref());
        }
        PlanControl::PhotoEvidence { max_dimension } => m.uint("maxDimension", *max_dimension),
    }
    m.done()
}

fn question_fields(m: &mut Obj, q: &PlanQuestion) {
    m.put("label", text_value(&q.label));
    m.opt_text("prefix", q.prefix.as_deref());
    m.plan_text("shortLabel", q.short_label.as_ref());
    m.plan_text("help", q.help.as_ref());
    m.plan_text("guidance", q.guidance.as_ref());
    m.media("media", q.media.as_ref());
    if let Some(c) = &q.control {
        m.put("control", control_value(c));
    }
    m.opt_text("presentation", q.presentation.map(Presentation::name));
    m.opt_text("rosterField", q.roster_field.as_deref());
    m.text("dataType", q.data_type.name());
    if !q.nonresponse.is_empty() {
        m.put("nonresponse", Value::Array(q.nonresponse.iter().map(|n| Value::Text(n.code().into())).collect()));
    }
    m.flag("optional", q.optional);
    match &q.origin {
        PlanOrigin::Authored => {}
        PlanOrigin::OtherText { of } => {
            m.text("origin", "other-text");
            m.text("otherOf", of);
        }
        PlanOrigin::InstanceName => m.text("origin", "instance-name"),
    }
    m.opt_text("column", q.column.as_deref());
}

fn node_value(n: &PlanNode) -> Value {
    let mut m = Obj::default();
    m.put("id", Value::Int(n.id as i128));
    m.text("kind", n.kind.name());
    m.opt_text("bind", n.bind.as_deref());
    m.text(
        "disabledDisplay",
        match n.disabled_display {
            DisabledDisplay::Hidden => "hidden",
            DisabledDisplay::Protected => "protected",
        },
    );
    let mut leaf = false;
    match &n.kind {
        PlanKind::Step { title, navigation, emphasis } => {
            m.put("title", text_value(title));
            m.text("navigation", navigation.name());
            m.emphasis(*emphasis);
        }
        PlanKind::Review | PlanKind::Tabs => {}
        PlanKind::Tab { title, icon, emphasis } => {
            m.put("title", text_value(title));
            m.opt_text("icon", icon.as_deref());
            m.emphasis(*emphasis);
        }
        PlanKind::Card { title, icon, emphasis } => {
            m.plan_text("title", title.as_ref());
            m.opt_text("icon", icon.as_deref());
            m.emphasis(*emphasis);
        }
        PlanKind::Row { emphasis } => m.emphasis(*emphasis),
        PlanKind::Group(h) | PlanKind::List(h) => m.heading(h),
        PlanKind::Table { heading, columns } => {
            m.heading(heading);
            let cols = columns
                .iter()
                .map(|c| {
                    let mut o = Obj::default();
                    o.text("key", &c.key);
                    o.put("label", text_value(&c.label));
                    o.opt_text("prefix", c.prefix.as_deref());
                    o.done()
                })
                .collect();
            m.put("columns", Value::Array(cols));
        }
        PlanKind::Instance { code, heading } => {
            m.text("code", code);
            m.heading(heading);
        }
        PlanKind::Question(q) => {
            leaf = true;
            question_fields(&mut m, q);
        }
        PlanKind::Display { role, text, media } => {
            leaf = true;
            m.text("role", display_role_name(*role));
            m.plan_text("text", text.as_ref());
            m.media("media", media.as_ref());
        }
    }
    if !leaf {
        m.put("children", Value::Array(n.children.iter().map(node_value).collect()));
    }
    m.done()
}
