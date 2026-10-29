//! `StartCapture`, `SetValue`, `ClearValue`, `AcknowledgeIncomplete`, `Seal`,
//! `RecordConsent`, `RecordStatus` (COL-030–COL-044, COL-108, COL-109).

use std::collections::BTreeMap;

use fieldseal_distribution::domain::ConsentState;
use fieldseal_instrument::application::{PlanLayout, PlanRequest, compile_render_plan, select_layout};
use fieldseal_instrument::domain::metadata::{ConsentRequirement, EvidencePolicy};
use fieldseal_instrument::domain::{LayoutIdentity, RenderPlan};
use fieldseal_kernel::Value;
use fieldseal_kernel::cbor;
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{Digest, Fingerprint, ItemPath, Seq, SubjectId};
use fieldseal_kernel::local_record::LocalEntry;
use fieldseal_kernel::payload::{ConsentRef, ItemsPayload, Layout};
use fieldseal_kernel::structure::Fields;

/// The `seq` the paused-capture positions are encrypted under: no record ever takes it.
const PROGRESS_SEQ: u64 = u64::MAX - 1;
use super::{CollectionError, CollectionEvent, Held, HeldInstrument, Runtime, names};
use crate::domain::bundle::HeldRoster;
use crate::domain::capture::{Capture, CaptureError, CaptureMode, CaptureStart, SealBlock};
use crate::domain::payload::{EvidenceRef, Payload, StatusCode};
use crate::domain::{CaptureConstraints, TenancyState};

/// A subject's status outcome (COL §3 `RecordStatus`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StatusOutcome {
    /// Absent.
    Absent,
    /// Declines.
    Declines,
    /// Not the expected person.
    NotThem,
}

/// What `RecordConsent` records (COL-040).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConsentInput {
    /// The survey the consent is for.
    pub instrument: Fingerprint,
    /// The basis code, from the instrument's list.
    pub basis: String,
    /// The statement version the collector confirmed.
    pub statement_version: u32,
    /// Whether to capture an evidence image with the camera (COL-042).
    pub capture_evidence: bool,
}

/// A capture's state, for the shell to draw.
#[derive(Clone, Debug)]
pub struct CaptureView {
    /// The subject.
    pub subject: SubjectId,
    /// The survey being conducted.
    pub instrument: Fingerprint,
    /// The mode.
    pub mode: CaptureMode,
    /// The render plan the capture is drawn from (COL-108).
    pub plan: RenderPlan,
    /// The working values.
    pub values: BTreeMap<String, Value>,
    /// Hard verdicts and value problems.
    pub hard: Vec<String>,
    /// Soft verdicts raised.
    pub soft: Vec<String>,
    /// Unanswered items (COL-109).
    pub unanswered: Vec<String>,
    /// The current step.
    pub step: usize,
}

fn capture_error(e: CaptureError) -> CollectionError {
    match e {
        CaptureError::NotEditable(p) => CollectionError::NotEditable(p),
        CaptureError::NotAccepted { path, requirement, message } => CollectionError::OutOfRange(format!("{path}: {message} ({requirement})")),
        CaptureError::NoSuchOverride(r) => CollectionError::NotAllowed(format!("no soft verdict or reason {r}")),
        CaptureError::WrongCount(n) => CollectionError::IncompleteNotAcknowledged(n),
        CaptureError::Limit(m) => CollectionError::Failed(format!("evaluation limit: {m}")),
    }
}

/// A survey is conducted only with the cohorts it is assigned to (COL-111).
fn not_assigned(held: &Held, survey: &HeldInstrument, roster: &HeldRoster) -> Result<(), CollectionError> {
    if held.is_assigned(survey, roster) {
        Ok(())
    } else {
        Err(CollectionError::NotAllowed("this survey is not assigned to this person's cohort".into()))
    }
}

fn subject_bytes(s: &SubjectId) -> Vec<u8> {
    s.as_str().as_bytes().to_vec()
}

/// The consent statement's content address: SHA-256 of `{version, text}` in canonical
/// CBOR (WIRE-055).
pub(crate) fn statement_address(version: u32, text: &fieldseal_instrument::domain::LocalisedText) -> Digest {
    let v = cbor::map([("version", Value::Int(i128::from(version))), ("text", text.to_value())]);
    sha256(&cbor::encode(&v).expect("encodable"))
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct Progress {
    subject: SubjectId,
    instrument: Fingerprint,
    step: u64,
}

impl Runtime<'_> {
    fn require_collection(&mut self) -> Result<(), CollectionError> {
        self.active()?;
        let state = self.meta()?.state;
        let held = self.held().ok_or(CollectionError::NoBundle)?;
        if state != TenancyState::Registered || held.is_practice() {
            // COL-003: no collection about real subjects before registration.
            return Err(CollectionError::NotAllowed("collection about real subjects needs a registered tenancy and a bundle with rosters".into()));
        }
        Ok(())
    }

    /// The held instrument with this fingerprint.
    fn held_instrument(&self, instrument: &Fingerprint) -> Result<&HeldInstrument, CollectionError> {
        let held = self.held().ok_or(CollectionError::NoBundle)?;
        held.instrument(instrument).ok_or_else(|| CollectionError::NotAllowed("the bundle holds no such survey".into()))
    }

    fn plan_for(&self, instrument: &Fingerprint) -> Result<(RenderPlan, Layout), CollectionError> {
        let session = self.session.as_ref().ok_or(CollectionError::Locked)?;
        let held = self.held_instrument(instrument)?;
        let layouts: Vec<_> = held.layouts.iter().map(|(l, _)| l).collect();
        let chosen = select_layout(&layouts, session.window_class);
        let plan_layout = match chosen {
            Some(l) => {
                let address = held.layouts.iter().find(|(x, _)| std::ptr::eq(x, l)).map(|(_, a)| *a).expect("chosen from the list");
                PlanLayout::Layout { layout: l, address }
            }
            None => PlanLayout::Default,
        };
        let langs: Vec<&str> = session.languages.iter().map(String::as_str).collect();
        let plan = compile_render_plan(&held.instrument, plan_layout, PlanRequest { languages: &langs, window_class: session.window_class })
            .map_err(|e| CollectionError::BundleRejected(format!("render plan: {e}")))?;
        let layout = match plan.layout {
            LayoutIdentity::Default => Layout::Default,
            LayoutIdentity::Address(a) => Layout::Published(a),
        };
        Ok((plan, layout))
    }

    pub(crate) fn relanguage_capture(&mut self) -> Result<(), CollectionError> {
        if self.capture.is_none() {
            return Ok(());
        }
        let instrument = *self.capture.as_ref().map(Capture::instrument).ok_or(CollectionError::NoCapture)?;
        let (plan, _) = self.plan_for(&instrument)?;
        if let Some(c) = self.capture.as_mut() {
            c.note_language(plan.language.as_str());
        }
        Ok(())
    }

    /// `StartCapture` (COL-030–COL-033, COL-108): checks the subject's roster consent, picks
    /// the starting values for the mode, compiles the render plan for the device's window
    /// class and the session's languages, and opens the capture in memory.
    ///
    /// `instrument` names the survey to conduct: a bundle may carry several, each with its own
    /// record of the subject.
    pub fn start_capture(&mut self, subject: &SubjectId, instrument: &Fingerprint, mode: CaptureMode) -> Result<CaptureView, CollectionError> {
        self.require_collection()?;
        if self.capture.as_ref().is_some_and(Capture::has_unsealed_changes) {
            return Err(CollectionError::CaptureOpen);
        }
        let consent_ref = self.consent_ref_for(subject, instrument)?;
        let local = self.local_state()?;
        let state = local.get(&(subject_bytes(subject), *instrument)).cloned().unwrap_or_default();
        let progress = self.read_progress()?.into_iter().find(|p| &p.subject == subject && &p.instrument == instrument);
        let step = match mode {
            CaptureMode::Resume => usize::try_from(progress.ok_or_else(|| CollectionError::NotAllowed("no paused capture to resume".into()))?.step).unwrap_or(0),
            CaptureMode::Resurvey | CaptureMode::Correction if state.items.is_empty() => {
                return Err(CollectionError::NotAllowed("nothing recorded to resurvey".into()));
            }
            _ => 0,
        };
        let (plan, layout) = self.plan_for(instrument)?;
        let held = self.held().ok_or(CollectionError::NoBundle)?;
        let (_, entry) = held.subject(subject).ok_or(CollectionError::NotInRoster)?;
        let start = CaptureStart {
            subject: subject.clone(),
            instrument: *instrument,
            mode,
            baseline: state.current.clone(),
            prior_overrides: state.overrides.clone(),
            roster: entry.fields(),
            consent_ref,
            layout,
            language: plan.language.as_str().to_owned(),
            step,
            started: self.now(),
        };
        let capture = Capture::new(&self.held_instrument(instrument)?.instrument, start).map_err(capture_error)?;
        self.capture = Some(capture);
        self.capture_view_with(plan)
    }

    /// The consent a record about `subject` relies on (COL-030, COL-031, COL-041).
    fn consent_ref_for(&mut self, subject: &SubjectId, instrument: &Fingerprint) -> Result<ConsentRef, CollectionError> {
        let local = self.local_state()?;
        let held = self.held().ok_or(CollectionError::NoBundle)?;
        let survey = held.instrument(instrument).ok_or_else(|| CollectionError::NotAllowed("the bundle holds no such survey".into()))?;
        let (roster, entry) = held.subject(subject).ok_or(CollectionError::NotInRoster)?;
        not_assigned(held, survey, roster)?;
        if entry.consent == ConsentState::Refused {
            return Err(CollectionError::ConsentRefused);
        }
        Ok(match &survey.instrument.definition().consent {
            ConsentRequirement::NotRequired => ConsentRef::NotRequired,
            ConsentRequirement::Required { .. } => match (entry.consent, local.get(&(subject_bytes(subject), *instrument)).and_then(|s| s.consent_record)) {
                (_, Some(id)) => ConsentRef::Record(id),
                // A roster's `granted` covers only the surveys its version names (COL-031).
                (ConsentState::Granted, None) if roster.covers(&survey.instrument.definition().name) => ConsentRef::Roster { roster: roster.address, version: roster.version },
                _ => return Err(CollectionError::ConsentNeeded),
            },
        })
    }

    fn capture_view_with(&self, plan: RenderPlan) -> Result<CaptureView, CollectionError> {
        let c = self.capture.as_ref().ok_or(CollectionError::NoCapture)?;
        let e = c.evaluation();
        let mut hard: Vec<String> = e.with_verdict(fieldseal_instrument::domain::Verdict::Hard).into_iter().map(str::to_owned).collect();
        hard.extend(e.problems.iter().map(|p| format!("{} ({}): {}", p.path, p.requirement, p.message)));
        Ok(CaptureView {
            subject: c.subject().clone(),
            instrument: *c.instrument(),
            mode: c.mode(),
            plan,
            values: c.values().clone(),
            hard,
            soft: e.with_verdict(fieldseal_instrument::domain::Verdict::Soft).into_iter().map(str::to_owned).collect(),
            unanswered: e.unanswered.clone(),
            step: c.step(),
        })
    }

    /// The capture in progress.
    pub fn capture_view(&mut self) -> Result<CaptureView, CollectionError> {
        self.active()?;
        if self.capture.is_none() {
            return Err(CollectionError::NoCapture);
        }
        let instrument = *self.capture.as_ref().map(Capture::instrument).ok_or(CollectionError::NoCapture)?;
        let (plan, _) = self.plan_for(&instrument)?;
        self.capture_view_with(plan)
    }

    fn with_capture<T>(&mut self, f: impl FnOnce(&mut Capture, &fieldseal_instrument::domain::Instrument) -> Result<T, CaptureError>) -> Result<T, CollectionError> {
        self.active()?;
        let session = self.session.as_ref().ok_or(CollectionError::Locked)?;
        let held = session.held.as_ref().ok_or(CollectionError::NoBundle)?;
        let capture = self.capture.as_mut().ok_or(CollectionError::NoCapture)?;
        let survey = held.instrument(capture.instrument()).ok_or_else(|| CollectionError::NotAllowed("the bundle holds no such survey".into()))?;
        f(capture, &survey.instrument).map_err(capture_error)
    }

    /// `SetValue`: sets an item's value as recorded (WIRE-052). A nonresponse is
    /// `{"nr": "dont-know"}` or `{"nr": "refused"}` (INS-141).
    pub fn set_value(&mut self, path: &ItemPath, value: Value) -> Result<(), CollectionError> {
        self.with_capture(|c, i| c.set_value(i, path, value))
    }

    /// `ClearValue`.
    pub fn clear_value(&mut self, path: &ItemPath) -> Result<(), CollectionError> {
        self.with_capture(|c, i| c.clear_value(i, path))
    }

    /// Confirms a soft verdict with one of its reasons (COL-035).
    pub fn override_soft(&mut self, rule: &str, reason: &str) -> Result<(), CollectionError> {
        self.with_capture(|c, i| c.override_soft(i, rule, reason))
    }

    /// `AcknowledgeIncomplete` (COL-036): the collector acknowledges the unanswered count
    /// shown, which must be the current count.
    pub fn acknowledge_incomplete(&mut self, count: usize) -> Result<(), CollectionError> {
        self.with_capture(|c, _| c.acknowledge_incomplete(count))
    }

    /// Moves the capture to a step of its render plan (the position a pause stores).
    pub fn go_to_step(&mut self, step: usize) -> Result<(), CollectionError> {
        self.with_capture(|c, _| {
            c.go_to(step);
            Ok(())
        })
    }

    /// Discards the capture in progress, erasing its values from memory (COL-038). The
    /// shell asks the collector first.
    pub fn discard_capture(&mut self) {
        self.capture = None;
    }

    /// `Seal` (COL-035–COL-037, COL-050, COL-108): seals the capture as an `items` record
    /// carrying its layout and languages, and closes it.
    pub fn seal(&mut self) -> Result<Seq, CollectionError> {
        let seq = self.seal_capture(false)?.ok_or(CollectionError::NothingToSeal)?;
        let who = self.capture.take().map(|c| (c.subject().clone(), *c.instrument()));
        // The record is sealed: a paused position that can't be cleared is reported, not an error.
        if let Some((s, i)) = who
            && let Err(e) = self.forget_progress(&s, &i)
        {
            self.events.push(CollectionEvent::ProgressNotCleared(e.to_string()));
        }
        Ok(seq)
    }

    /// Pauses the capture (COL-034): seals what has been set so far as a normal record and
    /// stores the position for `resume`. Unsealed values are never written to storage.
    pub fn pause(&mut self) -> Result<Option<Seq>, CollectionError> {
        let seq = match self.seal_capture(true) {
            Ok(s) => s,
            Err(CollectionError::NothingToSeal) => None,
            Err(e) => return Err(e),
        };
        let capture = self.capture.take().ok_or(CollectionError::NoCapture)?;
        let mut all = self.read_progress()?;
        all.retain(|p| !(&p.subject == capture.subject() && &p.instrument == capture.instrument()));
        all.push(Progress { subject: capture.subject().clone(), instrument: *capture.instrument(), step: capture.step() as u64 });
        self.write_progress(&all)?;
        Ok(seq)
    }

    fn seal_capture(&mut self, pause: bool) -> Result<Option<Seq>, CollectionError> {
        self.active()?;
        let session = self.session.as_ref().ok_or(CollectionError::Locked)?;
        let held = session.held.as_ref().ok_or(CollectionError::NoBundle)?;
        let capture = self.capture.as_ref().ok_or(CollectionError::NoCapture)?;
        let survey = held.instrument(capture.instrument()).ok_or_else(|| CollectionError::NotAllowed("the bundle holds no such survey".into()))?;
        let content = match capture.readiness(&survey.instrument, pause) {
            Ok(c) => c,
            Err(SealBlock::Hard(h)) => return Err(CollectionError::HardVerdict(h.join(", "))),
            Err(SealBlock::Soft(s)) => return Err(CollectionError::SoftVerdict(s.join(", "))),
            Err(SealBlock::Incomplete(n)) => return Err(CollectionError::IncompleteNotAcknowledged(n)),
            Err(SealBlock::NothingToSeal) => return Err(CollectionError::NothingToSeal),
        };
        let items = ItemsPayload {
            tick: fieldseal_kernel::payload::Tick { anchor: Digest::from([0; 32]), slot: 0, boot: 0, wall: None },
            instrument: survey.fingerprint,
            layout: capture.layout(),
            lang: capture.languages().to_vec(),
            subject: subject_bytes(capture.subject()),
            consent_ref: capture.consent_ref().clone(),
            mode: capture.mode().wire(),
            values: content.values,
            overrides: (!content.overrides.is_empty()).then_some(content.overrides),
            flags: (!content.flags.is_empty()).then_some(content.flags),
        };
        items.to_value()?;
        let capture_ms = self.now().elapsed_ms.saturating_sub(capture.started().elapsed_ms);
        let sealed = self.seal_record(
            move |tick| {
                let mut items = items;
                items.tick = tick;
                Payload::Items(items)
            },
            Some(capture_ms),
        )?;
        if let Some(c) = self.capture.as_mut() {
            c.sealed();
        }
        Ok(Some(sealed.seq))
    }

    /// `RecordStatus` (COL-030): seals a status record. Refused for a subject whose roster
    /// consent is `refused`: nothing at all may be recorded about them.
    pub fn record_status(&mut self, subject: &SubjectId, instrument: &Fingerprint, outcome: StatusOutcome) -> Result<Seq, CollectionError> {
        self.require_collection()?;
        let held = self.held().ok_or(CollectionError::NoBundle)?;
        let survey = held.instrument(instrument).ok_or_else(|| CollectionError::NotAllowed("the bundle holds no such survey".into()))?;
        let instrument = survey.fingerprint;
        let (roster, entry) = held.subject(subject).ok_or(CollectionError::NotInRoster)?;
        not_assigned(held, survey, roster)?;
        if entry.consent == ConsentState::Refused {
            return Err(CollectionError::ConsentRefused);
        }
        let status = match outcome {
            StatusOutcome::Absent => StatusCode::Absent,
            StatusOutcome::Declines => StatusCode::Declined,
            StatusOutcome::NotThem => StatusCode::NotSubject,
        };
        let subject = subject_bytes(subject);
        Ok(self.seal_record(|tick| Payload::Status { tick, instrument, subject, status }, None)?.seq)
    }

    /// `RecordConsent` (COL-040–COL-044): seals the consent the collector attests, with a
    /// basis from the instrument's list and the statement version. With evidence, the image
    /// comes straight from the camera into memory and is sealed only into the journal as an
    /// `evidence` record; the local record notes only that it exists. Hold-to-confirm is the
    /// shell's (INS-024).
    pub fn record_consent(&mut self, subject: &SubjectId, input: &ConsentInput) -> Result<Seq, CollectionError> {
        self.require_collection()?;
        let held = self.held().ok_or(CollectionError::NoBundle)?;
        let (roster, entry) = held.subject(subject).ok_or(CollectionError::NotInRoster)?;
        let survey = held.instrument(&input.instrument).ok_or_else(|| CollectionError::NotAllowed("the bundle holds no such survey".into()))?;
        not_assigned(held, survey, roster)?;
        if entry.consent == ConsentState::Refused {
            return Err(CollectionError::ConsentRefused);
        }
        let ConsentRequirement::Required { bases, statement, evidence } = &survey.instrument.definition().consent else {
            return Err(CollectionError::NotAllowed("the instrument requires no consent (INS-062)".into()));
        };
        if !bases.iter().any(|b| b.code == input.basis) {
            return Err(CollectionError::NotAllowed(format!("basis {} is not in the instrument's list", input.basis)));
        }
        if input.statement_version != statement.version {
            return Err(CollectionError::NotAllowed(format!("statement version {} is not the current {}", input.statement_version, statement.version)));
        }
        match (evidence, input.capture_evidence) {
            (EvidencePolicy::None, true) => return Err(CollectionError::NotAllowed("the instrument allows no consent evidence".into())),
            (EvidencePolicy::Required, false) => return Err(CollectionError::NotAllowed("the instrument requires consent evidence".into())),
            _ => {}
        }
        let statement = statement_address(statement.version, &statement.text);
        let instrument = survey.fingerprint;
        let max_edge = self.session.as_ref().map_or(2000, |s| s.policy.policy().max_image_edge);
        let mut refs = Vec::new();
        if input.capture_evidence {
            let image = self
                .p
                .camera
                .capture(CaptureConstraints { max_edge: u32::try_from(max_edge).unwrap_or(u32::MAX) })
                .map_err(|e| CollectionError::NotAllowed(format!("camera: {e}")))?;
            if image.0.len() > 3 * 1024 * 1024 {
                return Err(CollectionError::NotAllowed("evidence image exceeds 3 MiB (WIRE-042)".into()));
            }
            let blob_id: [u8; 16] = self.random();
            let media_type = "image/jpeg".to_owned();
            refs.push(EvidenceRef { blob_id, sha256: sha256(&image.0), media_type: media_type.clone(), size: image.0.len() as u64 });
            let bytes = image.0;
            self.seal_record(|tick| Payload::Evidence { tick, blob_id, media_type, bytes }, None)?;
            self.events.push(CollectionEvent::EvidenceCaptured);
        }
        let basis = input.basis.clone();
        let subject_b = subject_bytes(subject);
        let seq = self.seal_record(|tick| Payload::Consent { tick, instrument, subject: subject_b, basis, statement, evidence: refs }, None)?.seq;
        self.events.push(CollectionEvent::ConsentRecorded(subject.clone()));
        Ok(seq)
    }

    fn read_progress(&self) -> Result<Vec<Progress>, CollectionError> {
        let Some(bytes) = self.p.storage.read(names::SESSION, &names::progress())? else {
            return Ok(Vec::new());
        };
        let session = self.session.as_ref().ok_or(CollectionError::Locked)?;
        let plain = LocalEntry::decode(&bytes)?.open(&session.key, &self.meta()?.tenancy)?;
        let mut out = Vec::new();
        let Value::Array(items) = cbor::decode(&plain)? else {
            return Err(CollectionError::Failed("progress data is not an array".into()));
        };
        for v in items {
            let mut f = Fields::new(v)?;
            let subject = SubjectId::new(f.text("subject")?).map_err(|e| CollectionError::Failed(e.to_string()))?;
            let instrument = Fingerprint::from(f.bytes_n::<32>("instrument")?);
            let step = f.uint("step")?;
            f.finish()?;
            out.push(Progress { subject, instrument, step });
        }
        Ok(out)
    }

    fn write_progress(&mut self, all: &[Progress]) -> Result<(), CollectionError> {
        if all.is_empty() {
            self.p.storage.delete(names::SESSION, &names::progress())?;
            return Ok(());
        }
        let value = Value::Array(
            all.iter()
                .map(|p| {
                    cbor::map([
                        ("subject", Value::Text(p.subject.as_str().to_owned())),
                        ("instrument", Value::Bytes(p.instrument.as_bytes().to_vec())),
                        ("step", Value::Int(i128::from(p.step))),
                    ])
                })
                .collect(),
        );
        let plain = zeroize::Zeroizing::new(cbor::encode(&value)?);
        let session = self.session.as_ref().ok_or(CollectionError::Locked)?;
        let entry = LocalEntry::seal(&session.key, &self.meta()?.tenancy, PROGRESS_SEQ, self.random(), &plain);
        self.p.storage.write(names::SESSION, &names::progress(), &entry.encode())?;
        if let Some(m) = self.meta.as_mut() {
            m.encryptions += 1;
        }
        self.save_meta()
    }

    fn forget_progress(&mut self, subject: &SubjectId, instrument: &Fingerprint) -> Result<(), CollectionError> {
        let mut all = self.read_progress()?;
        let before = all.len();
        all.retain(|p| !(&p.subject == subject && &p.instrument == instrument));
        if all.len() != before {
            self.write_progress(&all)?;
        }
        Ok(())
    }

    /// Subjects with a paused capture, with the survey of each.
    pub fn paused(&mut self) -> Result<Vec<(SubjectId, Fingerprint)>, CollectionError> {
        self.active()?;
        Ok(self.read_progress()?.into_iter().map(|p| (p.subject, p.instrument)).collect())
    }
}
