//! Evaluating one record's values against a compiled instrument: visibility from `when` and
//! `skip` (INS-124, INS-125), derived values (INS-045), `hard` and `soft` verdicts (INS-041,
//! INS-042), and the built-in value checks of the control catalogue (INS-026, INS-027,
//! INS-133, INS-134, INS-140, INS-161–INS-163).
//!
//! Values are read as recorded (WIRE-052): codes as text, sets of codes as arrays, numbers
//! as integers or decimals, `measurement-pair` as an array of two readings, dates as
//! `YYYY-MM-DD` text, and nonresponse as `{"nr": …}`. A value entered in an entry unit carries
//! its unit at `<path>.unit` and is converted exactly before bounds and rules see it
//! (INS-161). Rules see a `measurement-pair` as the mean of its two readings.

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_kernel::Value;

use super::codes::{CodeList, Nonresponse};
use super::compiled::{CompiledAction, NodeKind, QuestionNode, QuestionOrigin, Step};
use super::control::{Control, NumberEntry, OTHER_CODE, Options};
use super::definitions::RuleKind;
use super::element::{DataType, DisabledDisplay};
use super::instrument::Instrument;
use super::metadata::LookupTable;
use super::num::Num;
use super::paths::is_date;
use super::rules::{EvalScope, EvaluationLimitExceeded, Slot, Val, evaluate};
use super::units::Unit;

/// Whether an element is shown now.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Visibility {
    /// Shown and editable.
    Visible,
    /// Hidden by `when` or `skip`, but shown visibly disabled (INS-125).
    Protected,
    /// Hidden.
    Hidden,
}

impl Visibility {
    /// Whether a `when` or `skip` hides it (so it is cleared and not applicable, INS-142).
    pub fn is_hidden(self) -> bool {
        self != Visibility::Visible
    }
}

/// The outcome of one rule.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Verdict {
    /// A `hard` or `soft` rule whose `when` is false (or unset).
    Pass,
    /// A `hard` rule fired: sealing is blocked.
    Hard,
    /// A `soft` rule fired: ask again.
    Soft,
    /// A `hard` or `soft` rule that didn't run: an item it references is unset (INS-042),
    /// or its scope is hidden.
    NotRun,
    /// A `skip` rule: whether it hides its targets.
    Skip {
        /// Whether it fired.
        fired: bool,
    },
    /// A `derive` rule: whether it computed a value.
    Derive {
        /// Whether the value is set.
        set: bool,
    },
}

/// One rule's outcome (`RuleEvaluated`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RuleOutcome {
    /// The compiled rule id (INS-049).
    pub id: String,
    /// The rule's kind.
    pub kind: RuleKind,
    /// The verdict.
    pub verdict: Verdict,
}

/// A recorded value the instrument doesn't accept. Every problem blocks sealing, like a
/// `hard` verdict (for example readings further apart than `tolerance`, INS-026).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValueProblem {
    /// The item path.
    pub path: String,
    /// The requirement broken.
    pub requirement: &'static str,
    /// What is wrong.
    pub message: String,
}

/// The values one record holds.
#[derive(Clone, Copy, Debug)]
pub struct RecordInput<'a> {
    /// Item path to recorded value (WIRE-051).
    pub values: &'a BTreeMap<String, Value>,
    /// Roster field to value, for `roster.` references and read-only items.
    pub roster: &'a BTreeMap<String, Value>,
}

/// The result of evaluating one record (`EvaluateRules`).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Evaluation {
    /// Each rule's outcome, in compiled order.
    pub rules: Vec<RuleOutcome>,
    /// Each element's visibility, by path.
    pub visibility: BTreeMap<String, Visibility>,
    /// Paths present in the input that a `when` or `skip` hides: they must be cleared from
    /// the pending record (INS-124), and intake derives `not-applicable` for them (INS-142).
    pub cleared: Vec<String>,
    /// The effective values rules saw: visible, set, converted to the item's unit;
    /// nonresponses excluded. Includes derived values.
    pub values: BTreeMap<String, Val>,
    /// The nonresponses held by visible items.
    pub nonresponse: BTreeMap<String, Nonresponse>,
    /// Derived values that were computed (INS-045).
    pub derived: BTreeMap<String, Val>,
    /// Recorded values the instrument doesn't accept.
    pub problems: Vec<ValueProblem>,
    /// Visible, editable, non-optional questions with neither a value nor a nonresponse
    /// (COL-109, INS-014, INS-141).
    pub unanswered: Vec<String>,
}

impl Evaluation {
    /// The ids of rules with this verdict.
    pub fn with_verdict(&self, verdict: Verdict) -> Vec<&str> {
        self.rules.iter().filter(|r| r.verdict == verdict).map(|r| r.id.as_str()).collect()
    }

    /// Whether sealing is blocked: a hard verdict or a value problem.
    pub fn blocks_sealing(&self) -> bool {
        !self.problems.is_empty() || self.rules.iter().any(|r| r.verdict == Verdict::Hard)
    }

    /// The visibility of the element at `path`.
    pub fn visibility_of(&self, path: &str) -> Option<Visibility> {
        self.visibility.get(path).copied()
    }
}

/// Converts a recorded or roster value to a rule value.
pub fn value_to_val(v: &Value) -> Val {
    match v {
        Value::Int(i) => Val::Num(Num::int(*i)),
        Value::Decimal(d) => Num::from_decimal(*d).map_or(Val::Unset, Val::Num),
        Value::Text(t) => Val::Text(t.clone()),
        Value::Bool(b) => Val::Bool(*b),
        Value::Array(items) => {
            let vals: Vec<Val> = items.iter().map(value_to_val).collect();
            if vals.iter().all(Val::is_set) { Val::List(vals) } else { Val::Unset }
        }
        Value::Bytes(_) | Value::Map(_) => Val::Unset,
    }
}

struct Env<'a> {
    slots: &'a BTreeMap<String, Slot>,
    roster: &'a BTreeMap<String, Value>,
    tables: &'a BTreeMap<String, LookupTable>,
}

impl EvalScope for Env<'_> {
    fn item(&self, path: &str) -> Option<&Slot> {
        self.slots.get(path)
    }
    fn roster(&self, field: &str) -> Val {
        self.roster.get(field).map_or(Val::Unset, value_to_val)
    }
    fn lookup(&self, table: &str, key: &Val) -> Val {
        self.tables.get(table).and_then(|t| t.get(key)).cloned().unwrap_or(Val::Unset)
    }
}

/// Evaluates one record (`EvaluateRules`).
pub fn evaluate_record(instrument: &Instrument, input: RecordInput<'_>) -> Result<Evaluation, EvaluationLimitExceeded> {
    let def = instrument.definition();
    let compiled = instrument.compiled();
    let mut out = Evaluation::default();
    let mut slots: BTreeMap<String, Slot> = BTreeMap::new();
    let mut problems: BTreeMap<String, Vec<ValueProblem>> = BTreeMap::new();
    let mut consumed: BTreeSet<String> = BTreeSet::new();

    for (path, q) in compiled.questions() {
        let mut reader = Reader { path, q, lists: &def.code_lists, values: input.values, problems: Vec::new(), consumed: &mut consumed };
        if let Some(slot) = reader.read(input.roster) {
            slots.insert(path.to_owned(), slot);
        }
        if !reader.problems.is_empty() {
            problems.insert(path.to_owned(), reader.problems);
        }
    }
    let mut unknown = Vec::new();
    for key in input.values.keys() {
        if consumed.contains(key) {
            continue;
        }
        match compiled.derived_value(key) {
            Some(d) if !d.record => unknown.push(ValueProblem {
                path: key.clone(),
                requirement: "INS-045",
                message: "a derived value without `record: true` must not be written to records".into(),
            }),
            Some(_) => {}
            None => unknown.push(ValueProblem { path: key.clone(), requirement: "WIRE-051", message: "not an item path of the instrument".into() }),
        }
    }

    let n = compiled.nodes().len();
    let mut state: Vec<Visibility> = vec![Visibility::Visible; n];
    let mut fired: BTreeMap<usize, bool> = BTreeMap::new();
    for step in compiled.evaluation_order() {
        match *step {
            Step::Node(i) => {
                let node = &compiled.nodes()[i];
                let mut vis = Visibility::Visible;
                if let Some(p) = node.parent
                    && state[p].is_hidden() {
                        vis = state[p];
                    }
                if vis == Visibility::Visible {
                    let env = Env { slots: &slots, roster: input.roster, tables: &def.tables };
                    let own = match &node.when {
                        Some(w) => !evaluate(w, &env)?.truthy(),
                        None => false,
                    };
                    let skipped = node.skipped_by.iter().any(|k| fired.get(k).copied().unwrap_or(false));
                    if own || skipped {
                        vis = match node.disabled_display {
                            DisabledDisplay::Hidden => Visibility::Hidden,
                            DisabledDisplay::Protected => Visibility::Protected,
                        };
                    }
                }
                state[i] = vis;
                if vis.is_hidden() && matches!(node.kind, NodeKind::Question(_)) {
                    slots.remove(&node.path);
                    if input.values.contains_key(&node.path) {
                        out.cleared.push(node.path.clone());
                    }
                    let unit = format!("{}.unit", node.path);
                    if input.values.contains_key(&unit) && compiled.question(&unit).is_none() {
                        out.cleared.push(unit);
                    }
                }
            }
            Step::Skip(k) => {
                let r = &compiled.rules()[k];
                let in_scope = r.scope.is_none_or(|s| !state[s].is_hidden());
                let env = Env { slots: &slots, roster: input.roster, tables: &def.tables };
                fired.insert(k, in_scope && evaluate(&r.when, &env)?.truthy());
            }
            Step::Derive(k) => {
                let r = &compiled.rules()[k];
                let CompiledAction::Derive { target, value } = &r.action else { continue };
                let in_scope = r.scope.is_none_or(|s| !state[s].is_hidden());
                let env = Env { slots: &slots, roster: input.roster, tables: &def.tables };
                let v = if in_scope && evaluate(&r.when, &env)?.truthy() { evaluate(value, &env)? } else { Val::Unset };
                if v.is_set() {
                    let path = compiled.derived()[*target].path.clone();
                    out.derived.insert(path.clone(), v.clone());
                    slots.insert(path, Slot { value: v, nonresponse: None, code_value: None });
                }
            }
        }
    }

    for (i, node) in compiled.nodes().iter().enumerate() {
        out.visibility.insert(node.path.clone(), state[i]);
    }

    for r in compiled.rules() {
        let kind = match &r.action {
            CompiledAction::Hard { .. } => RuleKind::Hard,
            CompiledAction::Soft { .. } => RuleKind::Soft,
            CompiledAction::Skip { .. } => RuleKind::Skip,
            CompiledAction::Derive { .. } => RuleKind::Derive,
        };
        let index = out.rules.len();
        let verdict = match kind {
            RuleKind::Skip => Verdict::Skip { fired: fired.get(&index).copied().unwrap_or(false) },
            RuleKind::Derive => {
                let set = matches!(&r.action, CompiledAction::Derive { target, .. } if out.derived.contains_key(&compiled.derived()[*target].path));
                Verdict::Derive { set }
            }
            RuleKind::Hard | RuleKind::Soft => {
                let in_scope = r.scope.is_none_or(|s| !state[s].is_hidden());
                let all_set = r.refs.iter().all(|p| slots.get(p).is_some_and(|s| s.value.is_set() || s.nonresponse.is_some()))
                    && r.roster_refs.iter().all(|f| input.roster.contains_key(f));
                if !in_scope || !all_set {
                    Verdict::NotRun
                } else {
                    let env = Env { slots: &slots, roster: input.roster, tables: &def.tables };
                    match (evaluate(&r.when, &env)?.truthy(), kind) {
                        (false, _) => Verdict::Pass,
                        (true, RuleKind::Hard) => Verdict::Hard,
                        (true, _) => Verdict::Soft,
                    }
                }
            }
        };
        out.rules.push(RuleOutcome { id: r.id.clone(), kind, verdict });
    }

    for (i, node) in compiled.nodes().iter().enumerate() {
        let Some(q) = node.question() else { continue };
        if state[i].is_hidden() {
            continue;
        }
        if let Some(ps) = problems.remove(&node.path) {
            out.problems.extend(ps);
        }
        let slot = slots.get(&node.path);
        if matches!(q.origin, QuestionOrigin::OtherText { .. }) && slot.is_none_or(|s| !s.value.is_set()) {
            out.problems.push(ValueProblem {
                path: node.path.clone(),
                requirement: "INS-134",
                message: "the `other` code is selected, so its text is required".into(),
            });
        }
        if let Some(nr) = slot.and_then(|s| s.nonresponse) {
            out.nonresponse.insert(node.path.clone(), nr);
        }
        if q.is_editable() && !q.optional && slot.is_none_or(|s| !s.value.is_set() && s.nonresponse.is_none()) {
            out.unanswered.push(node.path.clone());
        }
    }
    out.problems.extend(unknown);
    for (path, slot) in slots {
        if slot.value.is_set() {
            out.values.insert(path, slot.value);
        }
    }
    Ok(out)
}

struct Reader<'a> {
    path: &'a str,
    q: &'a QuestionNode,
    lists: &'a BTreeMap<String, CodeList>,
    values: &'a BTreeMap<String, Value>,
    problems: Vec<ValueProblem>,
    consumed: &'a mut BTreeSet<String>,
}

impl Reader<'_> {
    fn problem(&mut self, requirement: &'static str, message: impl Into<String>) {
        self.problems.push(ValueProblem { path: self.path.to_owned(), requirement, message: message.into() });
    }

    fn read(&mut self, roster: &BTreeMap<String, Value>) -> Option<Slot> {
        let raw = self.values.get(self.path);
        if raw.is_some() {
            self.consumed.insert(self.path.to_owned());
        }
        if let Some(field) = &self.q.from_roster {
            if raw.is_some() && !self.q.record {
                self.problem("INS-013", "a roster item is written to records only with `record: true`");
            }
            let v = roster.get(field).map_or(Val::Unset, value_to_val);
            return v.is_set().then_some(Slot { value: v, nonresponse: None, code_value: None });
        }
        let unit_key = format!("{}.unit", self.path);
        let entered_unit = self.values.get(&unit_key);
        if entered_unit.is_some() {
            self.consumed.insert(unit_key.clone());
            if raw.is_none() {
                self.problem("INS-030", format!("`{unit_key}` is written without the value it qualifies"));
            }
        }
        let raw = raw?;
        if let Value::Map(m) = raw {
            if m.len() == 1 {
                if let Some(code) = m.get("nr").and_then(Value::as_text) {
                    if code == "not-applicable" {
                        self.problem("INS-142", "`not-applicable` is derived at intake, never entered");
                        return None;
                    }
                    return match Nonresponse::from_code(code) {
                        Some(nr) if self.q.nonresponse.contains(&nr) => Some(Slot { value: Val::Unset, nonresponse: Some(nr), code_value: None }),
                        _ => {
                            self.problem("INS-140", format!("nonresponse `{code}` is not offered by this question"));
                            None
                        }
                    };
                }
                if m.get("retracted") == Some(&Value::Bool(true)) {
                    return None;
                }
            }
            self.problem("WIRE-052", "the only map values are {\"nr\": …} and {\"retracted\": true}");
            return None;
        }
        let control = self.q.control.as_ref()?;
        if entered_unit.is_some() && !matches!(control, Control::Number(_) | Control::MeasurementPair(_)) {
            self.problem("INS-161", "this control records no entry unit; `.unit` belongs to `number` and `measurement-pair` only");
            return None;
        }
        let value = match control {
            Control::Choice { options } | Control::Scale { steps: options, .. } => {
                let list = self.list(options)?;
                let code = self.code(raw, &list)?;
                let code_value = list.code(&code).and_then(|c| c.value).and_then(Num::from_decimal);
                return Some(Slot { value: Val::Text(code), nonresponse: None, code_value });
            }
            Control::CodedListWithOther { options, .. } => {
                let mut list = options.clone();
                if raw.as_text() == Some(OTHER_CODE) {
                    return Some(Slot { value: Val::Text(OTHER_CODE.into()), nonresponse: None, code_value: None });
                }
                list.other = None;
                let code = self.code(raw, &list)?;
                let code_value = list.code(&code).and_then(|c| c.value).and_then(Num::from_decimal);
                return Some(Slot { value: Val::Text(code), nonresponse: None, code_value });
            }
            Control::MultiChoice { options, max } => {
                let list = self.list(options)?;
                let Some(items) = raw.as_array() else {
                    self.problem("WIRE-052", "a multi-choice value is an array of codes");
                    return None;
                };
                let mut codes = Vec::new();
                for item in items {
                    let code = self.code(item, &list)?;
                    if codes.contains(&code) {
                        self.problem("INS-030", format!("code `{code}` appears twice"));
                        return None;
                    }
                    codes.push(code);
                }
                if codes.is_empty() {
                    self.problem("INS-021", "an empty set is not a value; leave the item unset");
                    return None;
                }
                if max.is_some_and(|m| codes.len() > m as usize) {
                    self.problem("INS-025", format!("at most {} codes may be selected", max.unwrap_or(0)));
                }
                if codes.len() > 1 && codes.iter().any(|c| list.code(c).is_some_and(|c| c.exclusive)) {
                    self.problem("INS-133", "an exclusive code can't be selected with other codes");
                }
                Val::List(codes.into_iter().map(Val::Text).collect())
            }
            Control::Stepper(s) => {
                let v = self.number(raw)?;
                let (min, max, start, step) = (num(s.min), num(s.max), num(s.start), num(s.step));
                if !(min <= v && v <= max) {
                    self.problem("INS-027", format!("{v} is outside {}..{}", s.min, s.max));
                }
                if step > Num::ZERO && v.sub(start).and_then(|d| d.div(step)).is_ok_and(|k| !k.is_integer()) {
                    self.problem("INS-163", format!("{v} is not start + k × step ({} + k × {})", s.start, s.step));
                }
                Val::Num(v)
            }
            Control::Number(n) => Val::Num(self.entry(raw, n, entered_unit)?),
            Control::MeasurementPair(m) => {
                let Some([a, b]) = raw.as_array().map(|a| a.iter().collect::<Vec<_>>()).and_then(|v| <[&Value; 2]>::try_from(v).ok()) else {
                    self.problem("INS-026", "a measurement pair records both readings as an array of two numbers");
                    return None;
                };
                let a = self.entry(a, &m.reading, entered_unit)?;
                let b = self.entry(b, &m.reading, entered_unit)?;
                if a.sub(b).and_then(Num::abs).is_ok_and(|d| d > num(m.tolerance)) {
                    self.problem("INS-026", format!("the readings differ by more than {}", m.tolerance));
                }
                Val::Num(a.mean2(b).ok()?)
            }
            Control::Money(m) => {
                let v = self.number(raw)?;
                if !v.fits_scale(m.currency.minor_digits()) {
                    self.problem("INS-162", format!("{} has at most {} minor-unit digits", m.currency.code(), m.currency.minor_digits()));
                }
                self.bounds(v, m.min.map(num), m.max.map(num));
                Val::Num(v)
            }
            Control::Text { max_length, multiline } => {
                let Some(t) = raw.as_text() else {
                    self.problem("WIRE-052", "expected text");
                    return None;
                };
                if t.is_empty() {
                    self.problem("INS-021", "empty text is not a value; leave the item unset");
                    return None;
                }
                if max_length.is_some_and(|m| t.chars().count() > m as usize) {
                    self.problem("INS-025", format!("longer than {} characters", max_length.unwrap_or(0)));
                }
                if !multiline && t.contains('\n') {
                    self.problem("INS-025", "line breaks are not allowed");
                }
                Val::Text(t.to_owned())
            }
            Control::YesNo { .. } => match raw {
                Value::Bool(b) => Val::Bool(*b),
                _ => {
                    self.problem("WIRE-052", "expected a boolean");
                    return None;
                }
            },
            Control::Date { min, max } => {
                let Some(t) = raw.as_text().filter(|t| is_date(t)) else {
                    self.problem("WIRE-052", "expected a date YYYY-MM-DD");
                    return None;
                };
                if min.as_deref().is_some_and(|m| t < m) || max.as_deref().is_some_and(|m| t > m) {
                    self.problem("INS-027", format!("{t} is outside the allowed dates"));
                }
                Val::Text(t.to_owned())
            }
            Control::PhotoEvidence { .. } => match raw.as_text() {
                Some(t) if !t.is_empty() => Val::Text(t.to_owned()),
                _ => {
                    self.problem("WIRE-052", "expected an evidence reference");
                    return None;
                }
            },
        };
        Some(Slot { value, nonresponse: None, code_value: None })
    }

    fn list(&mut self, options: &Options) -> Option<CodeList> {
        match options {
            Options::Inline(l) => Some(l.clone()),
            Options::Named(id) => self.lists.get(id).cloned(),
        }
    }

    fn code(&mut self, raw: &Value, list: &CodeList) -> Option<String> {
        let Some(code) = raw.as_text() else {
            self.problem("WIRE-052", "a code is recorded as text");
            return None;
        };
        if !list.contains(code) {
            self.problem("INS-081", format!("`{code}` is not one of the item's codes"));
            return None;
        }
        Some(code.to_owned())
    }

    fn number(&mut self, raw: &Value) -> Option<Num> {
        let Some(v) = raw.as_decimal().and_then(Num::from_decimal) else {
            self.problem("WIRE-052", "expected a number");
            return None;
        };
        if self.q.data.data_type == DataType::Integer && (!v.is_integer() || matches!(raw, Value::Decimal(_))) {
            self.problem("INS-070", "expected a whole number written as an integer");
        }
        Some(v)
    }

    fn bounds(&mut self, v: Num, min: Option<Num>, max: Option<Num>) {
        if min.is_some_and(|m| v < m) || max.is_some_and(|m| v > m) {
            self.problem("INS-027", format!("{v} is outside the allowed range"));
        }
    }

    /// A typed number, possibly in an entry unit, converted to the control's unit.
    fn entry(&mut self, raw: &Value, n: &NumberEntry, entered_unit: Option<&Value>) -> Option<Num> {
        let v = self.number(raw)?;
        if !v.fits_scale(n.decimals) {
            self.problem("INS-070", format!("at most {} decimal places", n.decimals));
        }
        let v = match (entered_unit, &n.unit) {
            (None, _) => v,
            (Some(u), Some(spec)) => {
                let entered = u.as_text().and_then(|t| Unit::parse(t).ok());
                match entered {
                    Some(e) if e == spec.unit => v,
                    Some(e) if n.entry_units.contains(&e) => match e.convert(v, &spec.unit) {
                        Some(c) => c,
                        None => {
                            self.problem("INS-161", format!("`{e}` doesn't convert to `{}`", spec.unit));
                            return None;
                        }
                    },
                    _ => {
                        self.problem("INS-161", "the entered unit is not one of the control's entryUnits");
                        return None;
                    }
                }
            }
            (Some(_), None) => {
                self.problem("INS-161", "this item has no unit");
                return None;
            }
        };
        self.bounds(v, n.min.map(num), n.max.map(num));
        Some(v)
    }
}

fn num(d: fieldseal_kernel::Decimal) -> Num {
    Num::from_decimal(d).unwrap_or(Num::ZERO)
}
