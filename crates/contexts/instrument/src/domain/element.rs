//! The element tree as authored: groups, questions and displays (INS §5.12–5.16), with
//! their data specifications (INS §5.8).

use std::collections::BTreeMap;

use fieldseal_kernel::Decimal;

use super::codes::{Concept, MediaRef, Nonresponse};
use super::control::Control;
use super::definitions::{FieldCheckDef, RuleDef};
use super::rules::Expr;
use super::text::LocalisedText;
use super::units::Unit;

/// The value type of a question's data (INS-070).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DataType {
    /// One code.
    Code,
    /// A set of codes.
    Codes,
    /// A whole number.
    Integer,
    /// A decimal number.
    Decimal,
    /// An amount of money.
    Money,
    /// Text.
    String,
    /// A boolean.
    Boolean,
    /// A calendar date.
    Date,
    /// An evidence reference.
    Evidence,
}

impl DataType {
    /// The type named `name` in documents.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "code" => Self::Code,
            "codes" => Self::Codes,
            "integer" => Self::Integer,
            "decimal" => Self::Decimal,
            "money" => Self::Money,
            "string" => Self::String,
            "boolean" => Self::Boolean,
            "date" => Self::Date,
            "evidence" => Self::Evidence,
            _ => return None,
        })
    }

    /// The type's name in documents.
    pub fn name(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Codes => "codes",
            Self::Integer => "integer",
            Self::Decimal => "decimal",
            Self::Money => "money",
            Self::String => "string",
            Self::Boolean => "boolean",
            Self::Date => "date",
            Self::Evidence => "evidence",
        }
    }

    /// Whether values are numbers.
    pub fn is_numeric(self) -> bool {
        matches!(self, Self::Integer | Self::Decimal | Self::Money)
    }
}

/// How sensitive an item's data is (INS-070).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Sensitivity {
    /// Ordinary personal data.
    Normal,
    /// A special category of personal data.
    SpecialCategory,
}

/// A question's data specification, for intake's data contract (INS-070).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DataSpec {
    /// The value type.
    pub data_type: DataType,
    /// The UCUM unit.
    pub unit: Option<Unit>,
    /// The code list, for coded items.
    pub code_list: Option<String>,
    /// External terminology codes (INS-170).
    pub concept: Vec<Concept>,
    /// The sensitivity; `normal` when not given.
    pub sensitivity: Sensitivity,
    /// A description for analysts.
    pub description: Option<String>,
}

/// How a hidden element is shown (INS-125).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum DisabledDisplay {
    /// Not shown (the default).
    #[default]
    Hidden,
    /// Shown visibly disabled.
    Protected,
}

/// The role of a display element (INS-123).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DisplayRole {
    /// Instructions.
    Instruction,
    /// A note.
    Note,
    /// An introduction.
    Introduction,
    /// The end message.
    End,
}

/// A parsed expression with the text it came from.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Condition {
    /// The source text.
    pub source: String,
    /// The parsed tree.
    pub expr: Expr,
}

/// One question as authored (INS-011, INS-150).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Question {
    /// The path relative to the enclosing group (possibly dotted).
    pub path: String,
    /// The question as asked.
    pub label: LocalisedText,
    /// The printed number, for example `10a`.
    pub prefix: Option<String>,
    /// A short label for summaries and the data contract.
    pub short_label: Option<LocalisedText>,
    /// Help for whoever answers.
    pub help: Option<LocalisedText>,
    /// Guidance for the collector only (INS-151).
    pub guidance: Option<LocalisedText>,
    /// The control; absent for a roster item (INS-013a).
    pub control: Option<Control>,
    /// The data specification.
    pub data: DataSpec,
    /// When it is shown (INS-124).
    pub when: Option<Condition>,
    /// How it is shown while hidden (INS-125).
    pub disabled_display: DisabledDisplay,
    /// The nonresponse codes it offers; `None` means the instrument default (INS-140).
    pub nonresponse: Option<Vec<Nonresponse>>,
    /// Whether it is excluded from the unanswered count (INS-014).
    pub optional: bool,
    /// The roster field it reads, for read-only items (INS-013).
    pub from_roster: Option<String>,
    /// Whether a roster item is written to records (INS-013).
    pub record: bool,
    /// External terminology codes (INS-170).
    pub concept: Vec<Concept>,
    /// Embedded media.
    pub media: Option<MediaRef>,
}

/// Overridable control options of one repeat child for one code (INS-128).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ControlOverride {
    /// A different unit; also the instance's `data.unit`.
    pub unit: Option<Unit>,
    /// A different unit label.
    pub unit_label: Option<LocalisedText>,
    /// A different step.
    pub step: Option<Decimal>,
    /// A different minimum.
    pub min: Option<Decimal>,
    /// A different maximum.
    pub max: Option<Decimal>,
}

/// A static repeat over a code list (INS-126).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Repeat {
    /// The code list repeated over.
    pub over: String,
    /// Per-code, per-child control overrides (INS-128).
    pub overrides: BTreeMap<String, BTreeMap<String, ControlOverride>>,
}

/// A group as authored (INS-121).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Group {
    /// Its path segment.
    pub id: String,
    /// Its label.
    pub label: LocalisedText,
    /// A description.
    pub description: Option<LocalisedText>,
    /// The reference period, for example "in the last 30 days".
    pub reference_period: Option<LocalisedText>,
    /// The repeat, if it repeats.
    pub repeat: Option<Repeat>,
    /// When it is shown (INS-124).
    pub when: Option<Condition>,
    /// How it is shown while hidden (INS-125).
    pub disabled_display: DisabledDisplay,
    /// External terminology codes (INS-170).
    pub concept: Vec<Concept>,
    /// Embedded media.
    pub media: Option<MediaRef>,
    /// Its children, in order.
    pub elements: Vec<Element>,
    /// Rules scoped to it (INS-047).
    pub rules: Vec<RuleDef>,
    /// Field checks scoped to it (INS-129).
    pub field_checks: Vec<FieldCheckDef>,
}

/// A display element (INS-123).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Display {
    /// Its id, a path segment.
    pub id: String,
    /// Its role.
    pub role: DisplayRole,
    /// Its text.
    pub text: Option<LocalisedText>,
    /// Its media.
    pub media: Option<MediaRef>,
    /// When it is shown (INS-124).
    pub when: Option<Condition>,
}

/// A node of the element tree (INS-120).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Element {
    /// A group.
    Group(Box<Group>),
    /// A question.
    Question(Box<Question>),
    /// A display.
    Display(Display),
}
