//! The compiled instrument: the element tree with repeats expanded, every question at its
//! full item path, and every rule and field check scoped and expanded so the evaluator sees
//! only `$` paths (INS-047, INS-126–INS-129, INS-137).
//!
//! Elements are kept in one arena in tree order (pre-order), which is the order layouts
//! must preserve (INS-214).

use std::collections::BTreeMap;

use fieldseal_kernel::Value;

use super::codes::{Concept, MediaRef, Nonresponse};
use super::control::Control;
use super::definitions::{CheckKind, Reason};
use super::element::{DataSpec, DisabledDisplay, DisplayRole};
use super::rules::Expr;
use super::text::LocalisedText;

/// A group or a repeat instance.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GroupNode {
    /// The authored id, or the code for a repeat instance.
    pub id: String,
    /// The label; an instance's is its code's label (INS-127).
    pub label: LocalisedText,
    /// The description; an instance's is its code's description.
    pub description: Option<LocalisedText>,
    /// The reference period (instances inherit the repeat group's).
    pub reference_period: Option<LocalisedText>,
    /// Media; an instance's is its code's media.
    pub media: Option<MediaRef>,
    /// An instance's code's icon.
    pub icon: Option<String>,
    /// External terminology codes.
    pub concept: Vec<Concept>,
    /// For a repeat group: the code list it repeats over. Its children are its instances.
    pub repeat_over: Option<String>,
    /// For a repeat instance: its code.
    pub instance_code: Option<String>,
}

/// Where a compiled question came from.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum QuestionOrigin {
    /// Written by the author.
    Authored,
    /// Synthesised at `<path>.other` for the text of a question's `other` code (INS-137).
    OtherText {
        /// The question whose `other` code it describes.
        of: String,
    },
    /// Synthesised at `<instance path>.other` to name the item of a repeat instance whose
    /// code is the list's `other` code (INS-134, INS-137).
    InstanceName,
}

/// A question at its full item path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct QuestionNode {
    /// The question as asked.
    pub label: LocalisedText,
    /// The printed number.
    pub prefix: Option<String>,
    /// A short label.
    pub short_label: Option<LocalisedText>,
    /// Help for whoever answers.
    pub help: Option<LocalisedText>,
    /// Guidance for the collector.
    pub guidance: Option<LocalisedText>,
    /// The control, with repeat overrides applied (INS-128); absent for roster items.
    pub control: Option<Control>,
    /// The data specification, with an overridden unit applied.
    pub data: DataSpec,
    /// The nonresponse codes offered, after the instrument default (INS-140).
    pub nonresponse: Vec<Nonresponse>,
    /// Excluded from the unanswered count.
    pub optional: bool,
    /// The roster field a read-only item shows.
    pub from_roster: Option<String>,
    /// Whether a roster item is written to records.
    pub record: bool,
    /// External terminology codes.
    pub concept: Vec<Concept>,
    /// Media.
    pub media: Option<MediaRef>,
    /// Where it came from.
    pub origin: QuestionOrigin,
}

impl QuestionNode {
    /// Whether the collector can set it (not a roster item).
    pub fn is_editable(&self) -> bool {
        self.from_roster.is_none()
    }
}

/// A display element.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DisplayNode {
    /// Its id.
    pub id: String,
    /// Its role.
    pub role: DisplayRole,
    /// Its text.
    pub text: Option<LocalisedText>,
    /// Its media.
    pub media: Option<MediaRef>,
}

/// What a node is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NodeKind {
    /// A group, repeat group or repeat instance.
    Group(GroupNode),
    /// A question.
    Question(Box<QuestionNode>),
    /// A display.
    Display(DisplayNode),
}

/// One node of the compiled tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Node {
    /// Its full path: a group or instance path, an item path, or a display's path.
    pub path: String,
    /// Its parent.
    pub parent: Option<usize>,
    /// Its children, in order.
    pub children: Vec<usize>,
    /// Its own `when`, with `@` paths resolved.
    pub when: Option<Expr>,
    /// The skip rules that target it.
    pub skipped_by: Vec<usize>,
    /// How it is shown while hidden.
    pub disabled_display: DisabledDisplay,
    /// Where it was authored, for findings.
    pub doc_path: String,
    /// What it is.
    pub kind: NodeKind,
}

impl Node {
    /// The question, if this is one.
    pub fn question(&self) -> Option<&QuestionNode> {
        match &self.kind {
            NodeKind::Question(q) => Some(q),
            _ => None,
        }
    }
}

/// What a compiled rule does.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CompiledAction {
    /// Blocks sealing.
    Hard {
        /// The message.
        message: LocalisedText,
    },
    /// Asks again.
    Soft {
        /// The message.
        message: LocalisedText,
        /// The reasons offered.
        reasons: Vec<Reason>,
    },
    /// Hides nodes.
    Skip {
        /// The nodes hidden.
        targets: Vec<usize>,
    },
    /// Computes a derived value.
    Derive {
        /// The index into [`CompiledInstrument::derived`].
        target: usize,
        /// The value.
        value: Expr,
    },
}

/// A rule after expansion: one per repeat instance for rules declared in a repeat.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CompiledRule {
    /// The compiled identifier: scope path and id joined by `.` (INS-049).
    pub id: String,
    /// The authored id.
    pub rule_id: String,
    /// The group or instance it is scoped to.
    pub scope: Option<usize>,
    /// When it applies.
    pub when: Expr,
    /// What it does.
    pub action: CompiledAction,
    /// The item paths it references (INS-042).
    pub refs: Vec<String>,
    /// The roster fields it references.
    pub roster_refs: Vec<String>,
    /// Where it was authored.
    pub doc_path: String,
}

/// A field check after expansion, with every path absolute.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CompiledFieldCheck {
    /// The compiled identifier, as for rules.
    pub id: String,
    /// The authored id.
    pub check_id: String,
    /// Its type and parameters, every path a [`super::rules::PathRef::Item`].
    pub kind: CheckKind,
    /// Its message.
    pub message: LocalisedText,
    /// Where it was authored.
    pub doc_path: String,
}

/// A derived value (INS-045).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CompiledDerived {
    /// Its path.
    pub path: String,
    /// Its label.
    pub label: LocalisedText,
    /// Its data specification.
    pub data: DataSpec,
    /// Whether it is written to records.
    pub record: bool,
    /// The derive rule that computes it, if any.
    pub rule: Option<usize>,
}

/// One step of the evaluation order.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Step {
    /// Decide a node's visibility.
    Node(usize),
    /// Decide whether a skip rule fires.
    Skip(usize),
    /// Compute a derive rule.
    Derive(usize),
}

/// The compiled instrument.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct CompiledInstrument {
    pub(crate) nodes: Vec<Node>,
    pub(crate) roots: Vec<usize>,
    pub(crate) rules: Vec<CompiledRule>,
    pub(crate) field_checks: Vec<CompiledFieldCheck>,
    pub(crate) derived: Vec<CompiledDerived>,
    pub(crate) index: BTreeMap<String, usize>,
    pub(crate) order: Vec<Step>,
}

impl CompiledInstrument {
    /// Every node, in tree order.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// The top-level nodes.
    pub fn roots(&self) -> &[usize] {
        &self.roots
    }

    /// The node at `path`.
    pub fn node(&self, path: &str) -> Option<&Node> {
        self.index.get(path).map(|i| &self.nodes[*i])
    }

    /// The index of the node at `path`.
    pub fn node_index(&self, path: &str) -> Option<usize> {
        self.index.get(path).copied()
    }

    /// The question at `path`.
    pub fn question(&self, path: &str) -> Option<&QuestionNode> {
        self.node(path).and_then(Node::question)
    }

    /// Every question with its path, in tree order: the flat list of items.
    pub fn questions(&self) -> impl Iterator<Item = (&str, &QuestionNode)> {
        self.nodes.iter().filter_map(|n| n.question().map(|q| (n.path.as_str(), q)))
    }

    /// The node indices of every question under `node` (inclusive), in tree order.
    pub fn questions_under(&self, node: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut stack = vec![node];
        while let Some(i) = stack.pop() {
            if self.nodes[i].question().is_some() {
                out.push(i);
            }
            stack.extend(self.nodes[i].children.iter().rev());
        }
        out
    }

    /// The compiled rules, in declaration order with instances in list order.
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// The rule with compiled identifier `id`.
    pub fn rule(&self, id: &str) -> Option<&CompiledRule> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// The compiled field checks.
    pub fn field_checks(&self) -> &[CompiledFieldCheck] {
        &self.field_checks
    }

    /// The derived values.
    pub fn derived(&self) -> &[CompiledDerived] {
        &self.derived
    }

    /// The derived value at `path`.
    pub fn derived_value(&self, path: &str) -> Option<&CompiledDerived> {
        self.derived.iter().find(|d| d.path == path)
    }

    /// The order in which visibility, skip and derive steps are evaluated.
    pub fn evaluation_order(&self) -> &[Step] {
        &self.order
    }

    /// The compiled tree as a value, for `fieldseal instrument compile` (INS §5.12–5.14):
    /// every node nested in tree order at its full path, then the expanded rules, field
    /// checks, derived values and the evaluation order. Keys are camelCase; absent optional
    /// fields and `false` flags are left out; texts are maps of language tag to text.
    ///
    /// ```text
    /// { nodes: [node], rules: [rule], fieldChecks: [check], derived: [derived],
    ///   evaluationOrder: ["node:<path>" | "skip:<rule id>" | "derive:<rule id>"] }
    /// node = { path, kind: group|repeat|instance|question|display, disabledDisplay?,
    ///          when?, skippedBy?: [rule id], children?: [node], …kind fields }
    /// rule = { id, ruleId, kind: hard|soft|skip|derive, scope?, when, refs, rosterRefs?,
    ///          message? | targets? | target?, value? }
    /// ```
    pub fn to_value(&self) -> Value {
        let path_of = |i: usize| Value::Text(self.nodes.get(i).map_or_else(String::new, |n| n.path.clone()));
        let rule_of = |i: usize| self.rules.get(i).map_or("", |r| r.id.as_str());
        let mut m = Obj::default();
        m.put("nodes", Value::Array(self.roots.iter().map(|i| self.node_value(*i)).collect()));
        let rules = self
            .rules
            .iter()
            .map(|r| {
                let mut o = Obj::default();
                o.text("id", &r.id);
                o.text("ruleId", &r.rule_id);
                if let Some(s) = r.scope {
                    o.put("scope", path_of(s));
                }
                o.text("when", &r.when.to_string());
                let kind = match &r.action {
                    CompiledAction::Hard { message } => {
                        o.put("message", message.to_value());
                        "hard"
                    }
                    CompiledAction::Soft { message, .. } => {
                        o.put("message", message.to_value());
                        "soft"
                    }
                    CompiledAction::Skip { targets } => {
                        o.put("targets", Value::Array(targets.iter().map(|t| path_of(*t)).collect()));
                        "skip"
                    }
                    CompiledAction::Derive { target, value } => {
                        o.text("target", self.derived.get(*target).map_or("", |d| d.path.as_str()));
                        o.text("value", &value.to_string());
                        "derive"
                    }
                };
                o.text("kind", kind);
                o.put("refs", texts(&r.refs));
                if !r.roster_refs.is_empty() {
                    o.put("rosterRefs", texts(&r.roster_refs));
                }
                o.done()
            })
            .collect();
        m.put("rules", Value::Array(rules));
        let checks = self
            .field_checks
            .iter()
            .map(|c| {
                let mut o = Obj::default();
                o.text("id", &c.id);
                o.text("checkId", &c.check_id);
                o.put("message", c.message.to_value());
                o.done()
            })
            .collect();
        m.put("fieldChecks", Value::Array(checks));
        let derived = self
            .derived
            .iter()
            .map(|d| {
                let mut o = Obj::default();
                o.text("path", &d.path);
                o.put("label", d.label.to_value());
                o.text("dataType", d.data.data_type.name());
                if d.record {
                    o.put("record", Value::Bool(true));
                }
                if let Some(r) = d.rule {
                    o.text("rule", rule_of(r));
                }
                o.done()
            })
            .collect();
        m.put("derived", Value::Array(derived));
        let order = self
            .order
            .iter()
            .map(|s| {
                Value::Text(match s {
                    Step::Node(i) => format!("node:{}", self.nodes.get(*i).map_or("", |n| n.path.as_str())),
                    Step::Skip(i) => format!("skip:{}", rule_of(*i)),
                    Step::Derive(i) => format!("derive:{}", rule_of(*i)),
                })
            })
            .collect();
        m.put("evaluationOrder", Value::Array(order));
        m.done()
    }

    fn node_value(&self, i: usize) -> Value {
        let n = &self.nodes[i];
        let mut o = Obj::default();
        o.text("path", &n.path);
        if n.disabled_display == DisabledDisplay::Protected {
            o.text("disabledDisplay", "protected");
        }
        if let Some(w) = &n.when {
            o.text("when", &w.to_string());
        }
        if !n.skipped_by.is_empty() {
            let ids = n.skipped_by.iter().filter_map(|r| self.rules.get(*r)).map(|r| Value::Text(r.id.clone())).collect();
            o.put("skippedBy", Value::Array(ids));
        }
        let kind = match &n.kind {
            NodeKind::Group(g) => {
                o.put("label", g.label.to_value());
                if let Some(over) = &g.repeat_over {
                    o.text("repeatOver", over);
                }
                if let Some(code) = &g.instance_code {
                    o.text("code", code);
                }
                if g.repeat_over.is_some() {
                    "repeat"
                } else if g.instance_code.is_some() {
                    "instance"
                } else {
                    "group"
                }
            }
            NodeKind::Question(q) => {
                o.put("label", q.label.to_value());
                if let Some(p) = &q.prefix {
                    o.text("prefix", p);
                }
                if let Some(c) = &q.control {
                    o.text("control", c.control_type().name());
                }
                o.text("dataType", q.data.data_type.name());
                if let Some(u) = &q.data.unit {
                    o.text("unit", &u.to_string());
                }
                if let Some(l) = &q.data.code_list {
                    o.text("codeList", l);
                }
                if !q.nonresponse.is_empty() {
                    o.put("nonresponse", Value::Array(q.nonresponse.iter().map(|n| Value::Text(n.code().to_owned())).collect()));
                }
                if q.optional {
                    o.put("optional", Value::Bool(true));
                }
                if let Some(f) = &q.from_roster {
                    o.text("fromRoster", f);
                    if q.record {
                        o.put("record", Value::Bool(true));
                    }
                }
                match &q.origin {
                    QuestionOrigin::Authored => {}
                    QuestionOrigin::OtherText { of } => {
                        o.text("origin", "other-text");
                        o.text("otherOf", of);
                    }
                    QuestionOrigin::InstanceName => o.text("origin", "instance-name"),
                }
                "question"
            }
            NodeKind::Display(d) => {
                o.text("role", super::render_plan::display_role_name(d.role));
                "display"
            }
        };
        o.text("kind", kind);
        if !n.children.is_empty() {
            o.put("children", Value::Array(n.children.iter().map(|c| self.node_value(*c)).collect()));
        }
        o.done()
    }
}

#[derive(Default)]
struct Obj(BTreeMap<String, Value>);

impl Obj {
    fn put(&mut self, k: &str, v: Value) {
        self.0.insert(k.to_owned(), v);
    }
    fn text(&mut self, k: &str, v: &str) {
        self.put(k, Value::Text(v.to_owned()));
    }
    fn done(self) -> Value {
        Value::Map(self.0)
    }
}

fn texts(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::Text(s.clone())).collect())
}
