//! The data contract generated from an instrument (INT-056, INT-071, INS-070–072, INS-171).
//!
//! The contract describes, for each item path, the column's type, allowed codes with their
//! numeric values and labels in every language, unit, concepts, nonresponse column and
//! quality expectations derived from the instrument's rules. It is generated from the
//! published definition alone: intake holds no instrument-specific code (INT-058).

use std::collections::BTreeMap;

use fieldseal_instrument::domain::codes::{CodeList, Concept};
use fieldseal_instrument::domain::compiled::{CompiledAction, NodeKind, QuestionOrigin};
use fieldseal_instrument::domain::control::{Control, Options};
use fieldseal_instrument::domain::definitions::{CheckKind, CheckScopeDef};
use fieldseal_instrument::domain::element::Sensitivity;
use fieldseal_instrument::domain::rules::PathRef;
use fieldseal_instrument::domain::{Instrument, LocalisedText};
use fieldseal_kernel::cbor;
use fieldseal_kernel::id::Fingerprint;
use fieldseal_kernel::{Decimal, Value};

/// A column of the generic long format (§6 of the intake spec, plus the columns INT-071 and
/// INS-072 add).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LongColumn {
    /// The column name.
    pub name: &'static str,
    /// Its logical type.
    pub logical_type: &'static str,
    /// What it holds.
    pub description: &'static str,
}

/// The columns of the generic long format, in order. Values are landed locale-free
/// (ADR 0034): numbers as canonical decimals, dates as `YYYY-MM-DD`, codes as their code.
pub const LONG_COLUMNS: [LongColumn; 20] = [
    LongColumn { name: "instrument", logical_type: "content-address", description: "the instrument's fingerprint, never its name (INT-070)" },
    LongColumn { name: "layout", logical_type: "string", description: "the layout's content address, or `default` (INS-209)" },
    LongColumn { name: "lang", logical_type: "string", description: "BCP 47 tags of the languages administered, in order of first use (INT-071)" },
    LongColumn { name: "subject", logical_type: "pseudonymous-id", description: "the pseudonymous subject (INT-060)" },
    LongColumn { name: "item_path", logical_type: "string", description: "the item's path in the instrument" },
    LongColumn { name: "value", logical_type: "variant", description: "the landed value, empty when the item has a nonresponse or was retracted" },
    LongColumn { name: "value_type", logical_type: "string", description: "the item's data type from the instrument" },
    LongColumn { name: "nonresponse", logical_type: "string", description: "`dont-know`, `refused` or `not-applicable`; empty when answered (INS-072, INS-142)" },
    LongColumn { name: "retracted", logical_type: "boolean", description: "the earlier value was withdrawn with no replacement (WIRE-052)" },
    LongColumn { name: "unit", logical_type: "string", description: "the UCUM unit or ISO 4217 currency the value is landed in (INS-161)" },
    LongColumn { name: "record_id", logical_type: "uuid", description: "the source record" },
    LongColumn { name: "tenancy", logical_type: "tenancy-id", description: "the source tenancy" },
    LongColumn { name: "generation", logical_type: "integer", description: "the tenancy's generation for the subject's cohort (INT-053)" },
    LongColumn { name: "seq", logical_type: "integer", description: "the record's sequence number (INT-053)" },
    LongColumn { name: "tick_lower_bound", logical_type: "authority-time", description: "earliest authority time the record can have been written, in ms (INT-051)" },
    LongColumn { name: "received_at", logical_type: "authority-time", description: "authority time the record was received, in ms" },
    LongColumn { name: "consent_basis", logical_type: "string", description: "`not-required`, `roster:<version>` or `attestation:<code>`" },
    LongColumn { name: "flags", logical_type: "set<string>", description: "the record's flags, for example `late` or `above-cutoff`" },
    LongColumn { name: "excluded", logical_type: "boolean", description: "excluded by consent or custodian decision (INT-055)" },
    LongColumn { name: "exclusion_reason", logical_type: "string", description: "why it is excluded" },
];

/// The typed value columns of the results export, which replace `value` in its JSON Lines
/// form: an answered row fills the one that matches its `value_type`, and a free-text,
/// nonresponse or retracted row fills none (INT-085).
pub const TYPED_VALUE_COLUMNS: [&str; 5] = ["value_number", "value_text", "value_date", "value_bool", "value_codes"];

/// The version of the results export's columns and files (semver): a minor version only adds
/// columns (INT-085).
pub const EXPORT_SCHEMA_VERSION: &str = "1.0.0";

/// A code of a coded item (INS-131, INS-132).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ContractCode {
    /// The code recorded.
    pub code: String,
    /// Its numeric meaning for analysis, as canonical decimal text (INS-132).
    pub value: Option<String>,
    /// Its label in every language of the instrument (INT-071).
    pub labels: BTreeMap<String, String>,
    /// Whether it deselects every other code.
    pub exclusive: bool,
    /// External terminology codes (INS-171).
    pub concepts: Vec<ContractConcept>,
}

/// An external terminology code, carried and never interpreted (INS-171).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ContractConcept {
    /// The terminology's URI.
    pub system: String,
    /// The code.
    pub code: String,
    /// The display text, if given.
    pub display: Option<String>,
}

/// A code list.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ContractCodeList {
    /// Its id (the authored id, or the item path for inline options).
    pub id: String,
    /// Whether the codes are ordered.
    pub ordered: bool,
    /// The codes, in order.
    pub codes: Vec<ContractCode>,
    /// The `other` code and the label of its text answer in every language (INS-134).
    pub other: Option<(String, BTreeMap<String, String>)>,
}

/// One item's columns.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ContractItem {
    /// The item path; also the value column's name in a wide view.
    pub path: String,
    /// The nonresponse column's name, separate from the value column (INS-072).
    pub nonresponse_column: String,
    /// The data type: `code`, `codes`, `integer`, `decimal`, `money`, `string`, `boolean`,
    /// `date` or `evidence`.
    pub value_type: &'static str,
    /// The label in every language (INT-071); empty for derived items.
    pub labels: BTreeMap<String, String>,
    /// The unit the value is landed in (UCUM), or the currency for `money`.
    pub unit: Option<String>,
    /// The ISO 4217 currency, for `money`.
    pub currency: Option<String>,
    /// The code list the item draws on.
    pub code_list: Option<String>,
    /// The most codes selectable, for `codes`.
    pub max_codes: Option<u32>,
    /// The lowest allowed value, as canonical text.
    pub min: Option<String>,
    /// The highest allowed value, as canonical text.
    pub max: Option<String>,
    /// External terminology codes (INS-171).
    pub concepts: Vec<ContractConcept>,
    /// `normal` or `special-category`.
    pub sensitivity: &'static str,
    /// A description for analysts.
    pub description: Option<String>,
    /// Whether the item must have a value or a nonresponse whenever it is shown.
    pub required: bool,
    /// Whether a `when` or `skip` can hide it, so `not-applicable` is possible (INS-142).
    pub conditional: bool,
    /// The nonresponse codes the item offers (INS-140).
    pub nonresponse: Vec<&'static str>,
    /// Whether it is computed by a `derive` rule.
    pub derived: bool,
    /// Whether it is written to records (derived items only land if so).
    pub landed: bool,
    /// For a repeat instance, the repeat's code list and the instance's code.
    pub repeat: Option<(String, String)>,
    /// For a synthesised `other` text item, the item it describes.
    pub other_text_of: Option<String>,
    /// Whether the answer is free text: true when the data type is `string`, which includes
    /// an `other` text item (INT-088).
    pub free_text: bool,
}

/// A group and the items it requires.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ContractGroup {
    /// The group's path.
    pub path: String,
    /// The label in every language.
    pub labels: BTreeMap<String, String>,
    /// Items under it that are required whenever it is shown.
    pub required_items: Vec<String>,
    /// For a repeat group, its code list.
    pub repeat_over: Option<String>,
}

/// How serious an expectation's failure is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    /// A `hard` rule: the record should not have been sealed.
    Error,
    /// A `soft` rule: the collector should have confirmed.
    Warning,
    /// A field check: advisory (INS-053).
    Advisory,
}

impl Severity {
    fn name(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Advisory => "advisory",
        }
    }
}

/// A data-quality expectation derived from the instrument (INT-056, INT-057).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Expectation {
    /// The rule's or check's compiled id, or a generated id for column expectations.
    pub id: String,
    /// `hard`, `soft`, `field-check:<type>`, `allowed-values`, `range` or `required`.
    pub kind: String,
    /// How serious.
    pub severity: Severity,
    /// The items it concerns.
    pub items: Vec<String>,
    /// The message in every language, where the instrument gives one.
    pub message: BTreeMap<String, String>,
}

/// The data contract of one instrument.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DataContract {
    /// The instrument's fingerprint.
    pub instrument: Fingerprint,
    /// Every language of the instrument.
    pub languages: Vec<String>,
    /// The default language.
    pub default_language: String,
    /// The items, in instrument order.
    pub items: Vec<ContractItem>,
    /// The code lists in use.
    pub code_lists: Vec<ContractCodeList>,
    /// The groups with their required items.
    pub groups: Vec<ContractGroup>,
    /// The expectations.
    pub expectations: Vec<Expectation>,
}

fn labels(t: &LocalisedText) -> BTreeMap<String, String> {
    t.iter().map(|(k, v)| (k.as_str().to_owned(), v.to_owned())).collect()
}

fn concepts(c: &[Concept]) -> Vec<ContractConcept> {
    c.iter()
        .map(|c| ContractConcept { system: c.system.clone(), code: c.code.clone(), display: c.display.clone() })
        .collect()
}

/// A decimal as canonical text: the digits of the mantissa with the decimal point placed by
/// the exponent, never in scientific notation, with no trailing fraction zeros beyond the
/// declared scale.
pub fn decimal_text(d: Decimal) -> String {
    if d.exponent >= 0 {
        let zeros = "0".repeat(usize::try_from(d.exponent).unwrap_or(0));
        return format!("{}{}", d.mantissa, if d.mantissa == 0 { String::new() } else { zeros });
    }
    let scale = usize::try_from(-d.exponent).unwrap_or(0);
    let neg = d.mantissa < 0;
    let mut digits = d.mantissa.unsigned_abs().to_string();
    while digits.len() <= scale {
        digits.insert(0, '0');
    }
    let split = digits.len() - scale;
    format!("{}{}.{}", if neg { "-" } else { "" }, &digits[..split], &digits[split..])
}

fn code_list(id: &str, list: &CodeList) -> ContractCodeList {
    ContractCodeList {
        id: id.to_owned(),
        ordered: list.ordered,
        codes: list
            .codes
            .iter()
            .map(|c| ContractCode {
                code: c.code.clone(),
                value: c.value.map(decimal_text),
                labels: labels(&c.label),
                exclusive: c.exclusive,
                concepts: concepts(&c.concept),
            })
            .collect(),
        other: list.other.as_ref().map(|o| (o.code.clone(), labels(&o.label))),
    }
}

fn path_of(p: &PathRef) -> String {
    match p {
        PathRef::Item(s) | PathRef::Sibling(s) | PathRef::Roster(s) => s.clone(),
    }
}

/// Generates the data contract of `instrument`, whose fingerprint is `fingerprint`
/// (INT-056, INS-071).
pub fn generate_data_contract(fingerprint: Fingerprint, instrument: &Instrument) -> DataContract {
    let def = instrument.definition();
    let compiled = instrument.compiled();
    let mut items = Vec::new();
    let mut lists: BTreeMap<String, ContractCodeList> = BTreeMap::new();
    let mut groups = Vec::new();

    // A node is conditional if it or an ancestor has a `when` or is the target of a `skip`.
    let conditional = |mut idx: usize| -> bool {
        loop {
            let n = &compiled.nodes()[idx];
            if n.when.is_some() || !n.skipped_by.is_empty() {
                return true;
            }
            match n.parent {
                Some(p) => idx = p,
                None => return false,
            }
        }
    };

    for (idx, node) in compiled.nodes().iter().enumerate() {
        match &node.kind {
            NodeKind::Group(g) => {
                let required_items: Vec<String> = compiled
                    .questions_under(idx)
                    .into_iter()
                    .filter_map(|q| {
                        let n = &compiled.nodes()[q];
                        let qn = n.question()?;
                        (qn.is_editable() && !qn.optional && !conditional(q)).then(|| n.path.clone())
                    })
                    .collect();
                groups.push(ContractGroup {
                    path: node.path.clone(),
                    labels: labels(&g.label),
                    required_items,
                    repeat_over: g.repeat_over.clone(),
                });
            }
            NodeKind::Question(q) => {
                let options: Option<(String, CodeList)> = q.control.as_ref().and_then(|c| match c {
                    Control::Choice { options } | Control::MultiChoice { options, .. } | Control::Scale { steps: options, .. } => {
                        Some(match options {
                            Options::Named(id) => (id.clone(), def.code_lists.get(id).cloned()?),
                            Options::Inline(l) => (q.data.code_list.clone().unwrap_or_else(|| node.path.clone()), l.clone()),
                        })
                    }
                    Control::CodedListWithOther { options, .. } => {
                        Some((q.data.code_list.clone().unwrap_or_else(|| node.path.clone()), options.clone()))
                    }
                    _ => None,
                });
                let list_id = options.as_ref().map(|(id, _)| id.clone()).or_else(|| q.data.code_list.clone());
                if let Some((id, l)) = &options {
                    lists.entry(id.clone()).or_insert_with(|| code_list(id, l));
                } else if let Some(id) = &q.data.code_list
                    && let Some(l) = def.code_lists.get(id)
                {
                    lists.entry(id.clone()).or_insert_with(|| code_list(id, l));
                }
                let (mut min, mut max, mut currency, mut max_codes) = (None, None, None, None);
                let mut unit = q.data.unit.as_ref().map(|u| u.as_str().to_owned());
                match q.control.as_ref() {
                    Some(Control::Number(n)) => {
                        min = n.min.map(decimal_text);
                        max = n.max.map(decimal_text);
                    }
                    Some(Control::MeasurementPair(m)) => {
                        min = m.reading.min.map(decimal_text);
                        max = m.reading.max.map(decimal_text);
                    }
                    Some(Control::Stepper(s)) => {
                        min = Some(decimal_text(s.min));
                        max = Some(decimal_text(s.max));
                    }
                    Some(Control::Money(m)) => {
                        min = m.min.map(decimal_text);
                        max = m.max.map(decimal_text);
                        currency = Some(m.currency.code().to_owned());
                        unit = currency.clone();
                    }
                    Some(Control::Date { min: lo, max: hi }) => {
                        min = lo.clone();
                        max = hi.clone();
                    }
                    Some(Control::MultiChoice { max: m, .. }) => max_codes = *m,
                    _ => {}
                }
                let repeat = node.parent.and_then(|p| match &compiled.nodes()[p].kind {
                    NodeKind::Group(g) => g.repeat_over.clone().zip(g.instance_code.clone()).or_else(|| {
                        // An instance group's parent is the repeat group.
                        compiled.nodes()[p].parent.and_then(|pp| match &compiled.nodes()[pp].kind {
                            NodeKind::Group(rg) => rg.repeat_over.clone().zip(g.instance_code.clone()),
                            _ => None,
                        })
                    }),
                    _ => None,
                });
                let other_text_of = match &q.origin {
                    QuestionOrigin::OtherText { of } => Some(of.clone()),
                    QuestionOrigin::InstanceName => node.path.strip_suffix(".other").map(str::to_owned),
                    QuestionOrigin::Authored => None,
                };
                items.push(ContractItem {
                    path: node.path.clone(),
                    nonresponse_column: format!("{}#nr", node.path),
                    value_type: q.data.data_type.name(),
                    labels: labels(&q.label),
                    unit,
                    currency,
                    code_list: list_id,
                    max_codes,
                    min,
                    max,
                    concepts: concepts(&q.data.concept),
                    sensitivity: if q.data.sensitivity == Sensitivity::SpecialCategory { "special-category" } else { "normal" },
                    description: q.data.description.clone(),
                    required: q.is_editable() && !q.optional && !conditional(idx),
                    conditional: conditional(idx),
                    nonresponse: q.nonresponse.iter().map(|n| n.code()).collect(),
                    derived: false,
                    landed: q.is_editable() || q.record,
                    repeat,
                    other_text_of,
                    free_text: q.data.data_type.name() == "string",
                });
            }
            NodeKind::Display(_) => {}
        }
    }
    for d in compiled.derived() {
        items.push(ContractItem {
            path: d.path.clone(),
            nonresponse_column: format!("{}#nr", d.path),
            value_type: d.data.data_type.name(),
            labels: labels(&d.label),
            unit: d.data.unit.as_ref().map(|u| u.as_str().to_owned()),
            currency: None,
            code_list: d.data.code_list.clone(),
            max_codes: None,
            min: None,
            max: None,
            concepts: concepts(&d.data.concept),
            sensitivity: if d.data.sensitivity == Sensitivity::SpecialCategory { "special-category" } else { "normal" },
            description: d.data.description.clone(),
            required: false,
            conditional: true,
            nonresponse: vec![],
            derived: true,
            landed: d.record,
            repeat: None,
            other_text_of: None,
            free_text: d.data.data_type.name() == "string",
        });
    }

    let mut expectations = Vec::new();
    for it in &items {
        if it.required && !it.derived {
            expectations.push(Expectation {
                id: format!("{}#required", it.path),
                kind: "required".into(),
                severity: Severity::Advisory,
                items: vec![it.path.clone()],
                message: BTreeMap::new(),
            });
        }
        if let Some(list) = &it.code_list {
            expectations.push(Expectation {
                id: format!("{}#allowed-values", it.path),
                kind: "allowed-values".into(),
                severity: Severity::Error,
                items: vec![it.path.clone()],
                message: BTreeMap::from([("list".to_owned(), list.clone())]),
            });
        }
        if it.min.is_some() || it.max.is_some() {
            expectations.push(Expectation {
                id: format!("{}#range", it.path),
                kind: "range".into(),
                severity: Severity::Error,
                items: vec![it.path.clone()],
                message: BTreeMap::from([
                    ("min".to_owned(), it.min.clone().unwrap_or_default()),
                    ("max".to_owned(), it.max.clone().unwrap_or_default()),
                ]),
            });
        }
    }
    for r in compiled.rules() {
        let (kind, severity, message) = match &r.action {
            CompiledAction::Hard { message } => ("hard", Severity::Error, labels(message)),
            CompiledAction::Soft { message, .. } => ("soft", Severity::Warning, labels(message)),
            _ => continue,
        };
        expectations.push(Expectation {
            id: r.id.clone(),
            kind: kind.into(),
            severity,
            items: r.refs.clone(),
            message,
        });
    }
    for c in compiled.field_checks() {
        let (name, paths): (&str, Vec<String>) = match &c.kind {
            CheckKind::Distribution { path, .. } => ("distribution", vec![path_of(path)]),
            CheckKind::Drift { path, .. } => ("drift", vec![path_of(path)]),
            CheckKind::Duplicates { paths, .. } => ("duplicates", paths.iter().map(path_of).collect()),
            CheckKind::Timing { .. } => ("timing", vec![]),
            CheckKind::Completeness { scope, .. } => (
                "completeness",
                match scope {
                    CheckScopeDef::Group(p) => vec![path_of(p)],
                    CheckScopeDef::Paths(ps) => ps.iter().map(path_of).collect(),
                },
            ),
            CheckKind::Straightlining { group, .. } => ("straightlining", vec![path_of(group)]),
        };
        expectations.push(Expectation {
            id: c.id.clone(),
            kind: format!("field-check:{name}"),
            severity: Severity::Advisory,
            items: paths,
            message: labels(&c.message),
        });
    }

    DataContract {
        instrument: fingerprint,
        languages: def.languages.languages.iter().map(|l| l.as_str().to_owned()).collect(),
        default_language: def.languages.default.as_str().to_owned(),
        items,
        code_lists: lists.into_values().collect(),
        groups,
        expectations,
    }
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn text_map(m: &BTreeMap<String, String>) -> Value {
    Value::Map(m.iter().map(|(k, v)| (k.clone(), text(v))).collect())
}

fn texts<S: AsRef<str>>(v: &[S]) -> Value {
    Value::Array(v.iter().map(|s| text(s.as_ref())).collect())
}

fn concept_value(c: &ContractConcept) -> Value {
    let mut e = vec![("system", text(&c.system)), ("code", text(&c.code))];
    if let Some(d) = &c.display {
        e.push(("display", text(d)));
    }
    cbor::map(e)
}

impl DataContract {
    /// The contract as a value tree (rendered to JSON by the file adapter and the CLI).
    /// Absent options are omitted.
    pub fn to_value(&self) -> Value {
        let columns = LONG_COLUMNS
            .iter()
            .map(|c| cbor::map([("name", text(c.name)), ("type", text(c.logical_type)), ("description", text(c.description))]))
            .collect();
        let items = self
            .items
            .iter()
            .map(|i| {
                let mut e: Vec<(&str, Value)> = vec![
                    ("path", text(&i.path)),
                    ("value_type", text(i.value_type)),
                    ("nonresponse_column", text(&i.nonresponse_column)),
                    ("labels", text_map(&i.labels)),
                    ("sensitivity", text(i.sensitivity)),
                    ("required", Value::Bool(i.required)),
                    ("conditional", Value::Bool(i.conditional)),
                    ("derived", Value::Bool(i.derived)),
                    ("free_text", Value::Bool(i.free_text)),
                    ("landed", Value::Bool(i.landed)),
                    ("nonresponse", texts(&i.nonresponse)),
                    ("concepts", Value::Array(i.concepts.iter().map(concept_value).collect())),
                ];
                let opt = |e: &mut Vec<(&str, Value)>, k: &'static str, v: &Option<String>| {
                    if let Some(v) = v {
                        e.push((k, text(v)));
                    }
                };
                opt(&mut e, "unit", &i.unit);
                opt(&mut e, "currency", &i.currency);
                opt(&mut e, "code_list", &i.code_list);
                opt(&mut e, "min", &i.min);
                opt(&mut e, "max", &i.max);
                opt(&mut e, "description", &i.description);
                opt(&mut e, "other_text_of", &i.other_text_of);
                if let Some(m) = i.max_codes {
                    e.push(("max_codes", Value::Int(i128::from(m))));
                }
                if let Some((list, code)) = &i.repeat {
                    e.push(("repeat", cbor::map([("over", text(list)), ("instance", text(code))])));
                }
                cbor::map(e)
            })
            .collect();
        let lists = self
            .code_lists
            .iter()
            .map(|l| {
                let codes = l
                    .codes
                    .iter()
                    .map(|c| {
                        let mut e = vec![
                            ("code", text(&c.code)),
                            ("labels", text_map(&c.labels)),
                            ("exclusive", Value::Bool(c.exclusive)),
                            ("concepts", Value::Array(c.concepts.iter().map(concept_value).collect())),
                        ];
                        if let Some(v) = &c.value {
                            e.push(("value", text(v)));
                        }
                        cbor::map(e)
                    })
                    .collect();
                let mut e = vec![("id", text(&l.id)), ("ordered", Value::Bool(l.ordered)), ("codes", Value::Array(codes))];
                if let Some((code, lab)) = &l.other {
                    e.push(("other", cbor::map([("code", text(code)), ("labels", text_map(lab))])));
                }
                cbor::map(e)
            })
            .collect();
        let groups = self
            .groups
            .iter()
            .map(|g| {
                let mut e = vec![
                    ("path", text(&g.path)),
                    ("labels", text_map(&g.labels)),
                    ("required_items", texts(&g.required_items)),
                ];
                if let Some(r) = &g.repeat_over {
                    e.push(("repeat_over", text(r)));
                }
                cbor::map(e)
            })
            .collect();
        let expectations = self
            .expectations
            .iter()
            .map(|x| {
                cbor::map([
                    ("id", text(&x.id)),
                    ("kind", text(&x.kind)),
                    ("severity", text(x.severity.name())),
                    ("items", texts(&x.items)),
                    ("message", text_map(&x.message)),
                ])
            })
            .collect();
        cbor::map([
            ("instrument", text(&fieldseal_kernel::digest::lower_hex(self.instrument.as_bytes()))),
            ("exportSchemaVersion", text(EXPORT_SCHEMA_VERSION)),
            ("languages", texts(&self.languages)),
            ("default_language", text(&self.default_language)),
            ("long_format", Value::Array(columns)),
            ("items", Value::Array(items)),
            ("code_lists", Value::Array(lists)),
            ("groups", Value::Array(groups)),
            ("expectations", Value::Array(expectations)),
        ])
    }
}
