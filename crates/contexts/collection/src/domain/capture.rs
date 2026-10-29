//! A capture: one in-progress collection for one subject (COL §2, COL-030–COL-038,
//! COL-108, COL-109). It lives only in memory; nothing here touches storage.
//!
//! The instrument's rules are evaluated by the format core (`EvaluateRules`) after every
//! change. Values a `when` or `skip` hides are cleared from the pending record (INS-124).
//! Sealing is refused while a hard verdict or a value problem holds, while a soft verdict
//! has neither a changed answer nor a reason (COL-035), and, in a first capture, until the
//! collector acknowledges the unanswered count (COL-036, COL-109).
//!
//! A soft verdict counts as answered by a *changed answer* once any item the rule reads
//! differs from what it held when the verdict was first raised: the collector asked again
//! and confirmed. Otherwise it needs a reason from the rule's `reasons`.

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_instrument::application::evaluate_rules;
use fieldseal_instrument::domain::compiled::CompiledAction;
use fieldseal_instrument::domain::evaluation::{Evaluation, RecordInput, Verdict, Visibility};
use fieldseal_instrument::domain::{EvaluationLimitExceeded, Instrument};
use fieldseal_kernel::Value;
use fieldseal_kernel::cbor;
use fieldseal_kernel::id::{Fingerprint, ItemPath, SubjectId};
use fieldseal_kernel::payload::{ConsentRef, Layout, Mode};
use fieldseal_kernel::time::ElapsedReading;

/// The questions a rule reads, directly or through derived values (INS-045): what a
/// changed answer or an override reason is about.
pub fn question_refs(instrument: &Instrument, rule: &str) -> Vec<String> {
    let compiled = instrument.compiled();
    let mut out: Vec<String> = Vec::new();
    let mut todo: Vec<String> = compiled.rule(rule).map(|r| r.refs.clone()).unwrap_or_default();
    let mut seen = BTreeSet::new();
    while let Some(p) = todo.pop() {
        if !seen.insert(p.clone()) {
            continue;
        }
        if compiled.question(&p).is_some() {
            out.push(p);
        } else if let Some(i) = compiled.derived_value(&p).and_then(|d| d.rule) {
            todo.extend(compiled.rules()[i].refs.iter().cloned());
        }
    }
    out.sort();
    out
}

/// How a capture starts (COL-032, COL-033, COL-037).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CaptureMode {
    /// A first collection: every control starts unselected (INS-020).
    First,
    /// Continuing a paused capture from its stored position (COL-033).
    Resume,
    /// A resurvey: controls start from the subject's current values, and the record holds
    /// only what changed (COL-032).
    Resurvey,
    /// A correction of an earlier record, made like a resurvey (COL-037).
    Correction,
}

impl CaptureMode {
    /// The mode written in the `items` payload (WIRE-051).
    pub fn wire(self) -> Mode {
        match self {
            Self::First => Mode::First,
            Self::Resume => Mode::Resume,
            Self::Resurvey => Mode::Resurvey,
            Self::Correction => Mode::Correction,
        }
    }

    /// The mode's name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Resume => "resume",
            Self::Resurvey => "resurvey",
            Self::Correction => "correction",
        }
    }
}

/// Why a change to a capture was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaptureError {
    /// The path is not an item the collector may set now: unknown, read-only from the
    /// roster, or hidden by a rule.
    #[error("not editable: {0}")]
    NotEditable(String),
    /// The value is not one the control accepts (INS-027 and the control catalogue).
    #[error("value not accepted for {path}: {message} ({requirement})")]
    NotAccepted {
        /// The item path.
        path: String,
        /// The requirement the value breaks.
        requirement: &'static str,
        /// What is wrong.
        message: String,
    },
    /// The rule isn't a soft rule raised now, or the reason isn't one it offers.
    #[error("no such soft verdict or reason: {0}")]
    NoSuchOverride(String),
    /// The acknowledged count doesn't match the unanswered count shown.
    #[error("unanswered count is {0}")]
    WrongCount(usize),
    /// The instrument's rules exceeded the evaluation bounds (INS-044).
    #[error("evaluation limit exceeded: {0}")]
    Limit(String),
}

impl From<EvaluationLimitExceeded> for CaptureError {
    fn from(e: EvaluationLimitExceeded) -> Self {
        Self::Limit(e.0)
    }
}

/// Why a capture can't be sealed now (COL-035, COL-036).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealBlock {
    /// Hard verdicts and value problems, by rule id or item path.
    Hard(Vec<String>),
    /// Soft verdicts with neither a changed answer nor a reason, by rule id.
    Soft(Vec<String>),
    /// Unanswered items not yet acknowledged, with their count.
    Incomplete(usize),
    /// Nothing was set or changed.
    NothingToSeal,
}

/// What a sealed `items` record will carry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SealContent {
    /// Only the items set or changed (WIRE-051); a withdrawn value is `{"retracted": true}`.
    pub values: BTreeMap<ItemPath, Value>,
    /// Soft rules confirmed with a reason: each item path the rule reads, to the reason.
    pub overrides: BTreeMap<ItemPath, String>,
    /// Soft rules raised at sealing.
    pub flags: Vec<String>,
}

/// What a capture starts from.
#[derive(Clone, Debug)]
pub struct CaptureStart {
    /// The subject.
    pub subject: SubjectId,
    /// The instrument being conducted: the survey.
    pub instrument: Fingerprint,
    /// The mode.
    pub mode: CaptureMode,
    /// The subject's current values from the local record (empty in `first` mode).
    pub baseline: BTreeMap<String, Value>,
    /// Soft-rule reasons already sealed for the subject, item path to reason (from the
    /// local record): a soft verdict whose items all carry a reason stays confirmed.
    pub prior_overrides: BTreeMap<String, String>,
    /// The subject's roster fields (memory only, COL-090).
    pub roster: BTreeMap<String, Value>,
    /// The consent the capture relies on (COL-041).
    pub consent_ref: ConsentRef,
    /// The layout the render plan was compiled from (COL-108).
    pub layout: Layout,
    /// The language the plan was compiled in.
    pub language: String,
    /// The stored position, when resuming.
    pub step: usize,
    /// When the capture started, for its elapsed time.
    pub started: ElapsedReading,
}

/// One in-progress capture. Never written to storage (COL-034).
#[derive(Clone, Debug)]
pub struct Capture {
    subject: SubjectId,
    instrument: Fingerprint,
    mode: CaptureMode,
    baseline: BTreeMap<String, Value>,
    values: BTreeMap<String, Value>,
    roster: BTreeMap<String, Value>,
    consent_ref: ConsentRef,
    layout: Layout,
    languages: Vec<String>,
    step: usize,
    started: ElapsedReading,
    overrides: BTreeMap<String, String>,
    snapshots: BTreeMap<String, BTreeMap<String, Option<Value>>>,
    acknowledged: Option<usize>,
    evaluation: Evaluation,
}

impl Capture {
    /// Starts a capture and evaluates the starting values.
    pub fn new(instrument: &Instrument, start: CaptureStart) -> Result<Self, CaptureError> {
        let values = match start.mode {
            CaptureMode::First => BTreeMap::new(),
            _ => start.baseline.clone(),
        };
        let mut c = Self {
            subject: start.subject,
            instrument: start.instrument,
            mode: start.mode,
            baseline: if start.mode == CaptureMode::First { BTreeMap::new() } else { start.baseline },
            values,
            roster: start.roster,
            consent_ref: start.consent_ref,
            layout: start.layout,
            languages: vec![start.language],
            step: start.step,
            started: start.started,
            overrides: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            acknowledged: None,
            evaluation: Evaluation::default(),
        };
        c.evaluate(instrument)?;
        for id in c.evaluation.with_verdict(Verdict::Soft) {
            let refs = question_refs(instrument, id);
            let reasons: BTreeSet<Option<&String>> = refs.iter().map(|p| start.prior_overrides.get(p)).collect();
            if let [Some(reason)] = reasons.into_iter().collect::<Vec<_>>()[..] {
                c.overrides.insert(id.to_owned(), reason.clone());
            }
        }
        Ok(c)
    }

    /// The subject.
    pub fn subject(&self) -> &SubjectId {
        &self.subject
    }

    /// The instrument being conducted.
    pub fn instrument(&self) -> &Fingerprint {
        &self.instrument
    }

    /// The mode.
    pub fn mode(&self) -> CaptureMode {
        self.mode
    }

    /// The layout the capture follows.
    pub fn layout(&self) -> Layout {
        self.layout
    }

    /// Every instrument language shown, in order of first use (INS-087, WIRE-051).
    pub fn languages(&self) -> &[String] {
        &self.languages
    }

    /// The consent reference the record will carry.
    pub fn consent_ref(&self) -> &ConsentRef {
        &self.consent_ref
    }

    /// When the capture started.
    pub fn started(&self) -> ElapsedReading {
        self.started
    }

    /// The current position in the render plan.
    pub fn step(&self) -> usize {
        self.step
    }

    /// Moves to a step of the render plan.
    pub fn go_to(&mut self, step: usize) {
        self.step = step;
    }

    /// Notes that the collector switched instrument language (PLAT-051): the change takes
    /// effect at once and clears nothing.
    pub fn note_language(&mut self, language: &str) {
        if !self.languages.iter().any(|l| l == language) {
            self.languages.push(language.to_owned());
        }
    }

    /// The working values: starting values plus every change.
    pub fn values(&self) -> &BTreeMap<String, Value> {
        &self.values
    }

    /// The latest evaluation.
    pub fn evaluation(&self) -> &Evaluation {
        &self.evaluation
    }

    /// The unanswered count (COL-109): visible, editable, non-optional questions with
    /// neither a value nor a nonresponse; hidden questions don't count.
    pub fn unanswered(&self) -> usize {
        self.evaluation.unanswered.len()
    }

    /// Whether anything would be lost by leaving now (COL-038).
    pub fn has_unsealed_changes(&self) -> bool {
        self.values != self.baseline
    }

    fn evaluate(&mut self, instrument: &Instrument) -> Result<(), CaptureError> {
        let evaluation = evaluate_rules(instrument, RecordInput { values: &self.values, roster: &self.roster })?;
        for path in &evaluation.cleared {
            self.values.remove(path);
        }
        let soft: BTreeSet<&str> = evaluation.with_verdict(Verdict::Soft).into_iter().collect();
        self.snapshots.retain(|id, _| soft.contains(id.as_str()));
        self.overrides.retain(|id, _| soft.contains(id.as_str()));
        for id in soft {
            if !self.snapshots.contains_key(id) {
                let snap = question_refs(instrument, id).into_iter().map(|p| {
                    let v = self.values.get(&p).cloned();
                    (p, v)
                }).collect();
                self.snapshots.insert(id.to_owned(), snap);
            }
        }
        if self.acknowledged != Some(evaluation.unanswered.len()) {
            self.acknowledged = None;
        }
        self.evaluation = evaluation;
        Ok(())
    }

    fn editable(&self, instrument: &Instrument, path: &str) -> Result<(), CaptureError> {
        let compiled = instrument.compiled();
        let base = path.strip_suffix(".unit").filter(|b| compiled.question(path).is_none() && compiled.question(b).is_some()).unwrap_or(path);
        let Some(q) = compiled.question(base) else {
            return Err(CaptureError::NotEditable(path.to_owned()));
        };
        if !q.is_editable() || self.evaluation.visibility_of(base).is_some_and(|v| v != Visibility::Visible) {
            return Err(CaptureError::NotEditable(path.to_owned()));
        }
        Ok(())
    }

    /// Sets an item's value, as recorded (WIRE-052); a nonresponse is `{"nr": code}`
    /// (INS-141). A value the control doesn't accept is refused and the capture unchanged.
    pub fn set_value(&mut self, instrument: &Instrument, path: &ItemPath, value: Value) -> Result<(), CaptureError> {
        let path = path.as_str();
        self.editable(instrument, path)?;
        let previous = self.values.insert(path.to_owned(), value);
        let evaluation = evaluate_rules(instrument, RecordInput { values: &self.values, roster: &self.roster })?;
        let base = path.strip_suffix(".unit").unwrap_or(path);
        if let Some(p) = evaluation.problems.iter().find(|p| (p.path == path || p.path == base) && p.requirement != "INS-026") {
            let err = CaptureError::NotAccepted { path: p.path.clone(), requirement: p.requirement, message: p.message.clone() };
            match previous {
                Some(v) => self.values.insert(path.to_owned(), v),
                None => self.values.remove(path),
            };
            return Err(err);
        }
        self.evaluate(instrument)
    }

    /// Clears an item's value.
    pub fn clear_value(&mut self, instrument: &Instrument, path: &ItemPath) -> Result<(), CaptureError> {
        self.editable(instrument, path.as_str())?;
        self.values.remove(path.as_str());
        self.evaluate(instrument)
    }

    /// Confirms a soft verdict with one of the rule's reasons (stored as `override_reason`).
    pub fn override_soft(&mut self, instrument: &Instrument, rule: &str, reason: &str) -> Result<(), CaptureError> {
        let raised = self.evaluation.with_verdict(Verdict::Soft).contains(&rule);
        let offers = instrument.compiled().rule(rule).is_some_and(|r| match &r.action {
            CompiledAction::Soft { reasons, .. } => reasons.iter().any(|x| x.code == reason),
            _ => false,
        });
        if !raised || !offers {
            return Err(CaptureError::NoSuchOverride(format!("{rule}: {reason}")));
        }
        self.overrides.insert(rule.to_owned(), reason.to_owned());
        Ok(())
    }

    /// Acknowledges the unanswered count shown (COL-036). It must match the current count;
    /// any later change that alters the count needs a new acknowledgement.
    pub fn acknowledge_incomplete(&mut self, count: usize) -> Result<(), CaptureError> {
        if count != self.unanswered() {
            return Err(CaptureError::WrongCount(self.unanswered()));
        }
        self.acknowledged = Some(count);
        Ok(())
    }

    fn soft_unresolved(&self) -> Vec<String> {
        self.evaluation
            .with_verdict(Verdict::Soft)
            .into_iter()
            .filter(|id| {
                if self.overrides.contains_key(*id) {
                    return false;
                }
                let changed = self.snapshots.get(*id).is_some_and(|snap| snap.iter().any(|(p, v)| v.as_ref() != self.values.get(p)));
                !changed
            })
            .map(str::to_owned)
            .collect()
    }

    /// What sealing now would write, or why it can't. `pause` seals what has been set so
    /// far without the unanswered acknowledgement (COL-034); verdicts still apply.
    pub fn readiness(&self, instrument: &Instrument, pause: bool) -> Result<SealContent, SealBlock> {
        let e = &self.evaluation;
        if e.blocks_sealing() {
            let mut hard: Vec<String> = e.with_verdict(Verdict::Hard).into_iter().map(str::to_owned).collect();
            hard.extend(e.problems.iter().map(|p| format!("{} ({})", p.path, p.requirement)));
            return Err(SealBlock::Hard(hard));
        }
        let soft = self.soft_unresolved();
        if !soft.is_empty() {
            return Err(SealBlock::Soft(soft));
        }
        if !pause && matches!(self.mode, CaptureMode::First | CaptureMode::Resume) && self.unanswered() > 0 && self.acknowledged != Some(self.unanswered()) {
            return Err(SealBlock::Incomplete(self.unanswered()));
        }
        let content = self.content(instrument);
        if content.values.is_empty() {
            return Err(SealBlock::NothingToSeal);
        }
        Ok(content)
    }

    fn content(&self, instrument: &Instrument) -> SealContent {
        let def = instrument.definition();
        let compiled = instrument.compiled();
        let mut values: BTreeMap<String, Value> = BTreeMap::new();
        for (path, v) in &self.values {
            if self.baseline.get(path) != Some(v) {
                values.insert(path.clone(), v.clone());
            }
        }
        for path in self.baseline.keys() {
            if !self.values.contains_key(path) {
                values.insert(path.clone(), cbor::map([("retracted", Value::Bool(true))]));
            }
        }
        // INS-031: a group written in part is written whole.
        for group in &def.atomic_groups {
            if group.paths.iter().any(|p| values.contains_key(p)) {
                for p in &group.paths {
                    if let Some(v) = self.values.get(p) {
                        values.entry(p.clone()).or_insert_with(|| v.clone());
                    }
                }
            }
        }
        // Roster items the instrument records (`record: true`), in a first capture.
        if self.mode == CaptureMode::First && !values.is_empty() {
            for (path, q) in compiled.questions() {
                if let (Some(field), true) = (&q.from_roster, q.record)
                    && let Some(v) = self.roster.get(field)
                {
                    values.insert(path.to_owned(), v.clone());
                }
            }
        }
        let mut overrides = BTreeMap::new();
        let mut flags = Vec::new();
        for id in self.evaluation.with_verdict(Verdict::Soft) {
            flags.push(id.to_owned());
            if let Some(reason) = self.overrides.get(id) {
                for p in question_refs(instrument, id) {
                    if let Ok(path) = ItemPath::new(p) {
                        overrides.insert(path, reason.clone());
                    }
                }
            }
        }
        let values = values.into_iter().filter_map(|(k, v)| ItemPath::new(k).ok().map(|p| (p, v))).collect();
        SealContent { values, overrides, flags }
    }

    /// After a pause, the capture continues with what was sealed as its new baseline.
    pub fn sealed(&mut self) {
        self.baseline = self.values.clone();
        if self.mode == CaptureMode::First {
            self.mode = CaptureMode::Resume;
        }
    }
}
