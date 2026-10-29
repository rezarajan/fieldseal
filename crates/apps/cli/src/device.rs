//! `fieldseal device simulate` (CLI §device, COL §7, COL §8): runs a headless runtime
//! tenancy from a YAML scenario against the in-memory adapters and a simulated authority,
//! and prints the journal summary.
//!
//! ```text
//! fieldseal device simulate --script <file> [--review] [--json]
//! fieldseal device simulate --scenario <name> [--review] [--json]
//! ```
//!
//! Built-in scenarios: `household-water-access` (alias `capture`), `school-meals-baseline`
//! (alias `consent`), and `clear` (alias `lifecycle`). With `--review`, every review step
//! prints its subjects and raised field checks. Output never contains names, roster
//! contents or item values (CLI-008): only subject IDs, record kinds, counts and checks.
//!
//! A scenario:
//!
//! ```yaml
//! pin: "246810"
//! instrument: ../instruments/household-water-access.yaml
//! layouts: [../layouts/household-water-access.compact.yaml]
//! languages: [es]               # optional, most preferred first
//! window: compact               # optional: compact, medium, expanded
//! rosters:
//!   - cohort: village-a
//!     version: 1
//!     subjects:
//!       - { subject: h-001, consent: unknown, display: { head_name: Ana }, attributes: {} }
//! steps:
//!   - capture: { subject: h-001, mode: first, set: { household.members: 4 },
//!                nonresponse: { water.monthly_cost: refused }, clear: [ … ],
//!                override: { low-use: dry-season }, acknowledge: true, then: seal }
//!   - status: { subject: h-002, outcome: absent }      # absent, declines, not-them
//!   - consent: { subject: h-003, basis: form-seen, statement: 1, evidence: true }
//!   - wait: 90                                         # seconds on the monotonic clock (idle lock applies)
//!   - review: {}
//!   - receipt: { through: 5 }                          # the authority receives through seq 5
//!   - clear: { through: 5, pins: ["246810", "246810"] }
//!   - lock: {}
//!   - unlock: {}
//!   - reboot: {}
//!   - close: {}
//! ```
//!
//! Any step may carry `expect: <text>`: the step must then fail with an error containing
//! the text (for example a clear with mismatched PINs).

mod stack;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fieldseal_adapters_authoring::{Format, decode};
use fieldseal_adapters_memory::collection::roster_address;
use fieldseal_adapters_memory::delivery_world::{Bench, Enrolled, Enrolment};
use fieldseal_collection::application::{
    CaptureMode, CollectionError, ConsentInput, OutboxEntry, ReviewFilter, ReviewReport, Runtime, StatusOutcome,
};
use fieldseal_collection::domain::bundle::{HeldRoster, RosterSubject};
use fieldseal_collection::domain::payload::Payload;
use fieldseal_collection::domain::ticks::first_non_monotonic;
use fieldseal_collection::domain::RuntimePin;
use fieldseal_distribution::domain::ConsentState;
use fieldseal_instrument::domain::WindowClass;
use fieldseal_kernel::Value;
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::id::{CohortId, Digest, ItemPath, Seq, SubjectId};
use fieldseal_kernel::payload::{Layout, Tick};
use fieldseal_kernel::record::read_journal;

const SCENARIOS: &[(&str, &str, &str)] = &[
    ("household-water-access", "capture", include_str!("../../../../examples/scenarios/household-water-access.yaml")),
    ("school-meals-baseline", "consent", include_str!("../../../../examples/scenarios/school-meals-baseline.yaml")),
    ("clear", "lifecycle", include_str!("../../../../examples/scenarios/clear.yaml")),
];

const EMBEDDED: &[(&str, &str)] = &[
    ("household-water-access.yaml", include_str!("../../../../examples/instruments/household-water-access.yaml")),
    ("school-meals-baseline.yaml", include_str!("../../../../examples/instruments/school-meals-baseline.yaml")),
    ("household-water-access.compact.yaml", include_str!("../../../../examples/layouts/household-water-access.compact.yaml")),
    ("school-meals-baseline.compact.yaml", include_str!("../../../../examples/layouts/school-meals-baseline.compact.yaml")),
    ("school-meals-baseline.expanded.yaml", include_str!("../../../../examples/layouts/school-meals-baseline.expanded.yaml")),
];

/// Checks `device` arguments strictly (CLI-022): the words `device simulate`, the valued flags
/// `--script`, `--scenario` and `--export` once each with a value that is not itself a flag,
/// and the switches `--review`, `--no-parity`, `--upload` and `--json`. Nothing else.
fn check_args(args: &[String]) -> Result<(), String> {
    let mut words = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--script" | "--scenario" | "--export" => {
                if !seen.insert(a.as_str()) {
                    return Err(format!("`{a}` was given more than once"));
                }
                if it.next().is_none_or(|v| v.starts_with("--")) {
                    return Err(format!("`{a}` needs a value"));
                }
            }
            "--review" | "--no-parity" | "--upload" | "--json" => {}
            f if f.starts_with('-') => return Err(format!("`device simulate` doesn't take `{f}`")),
            w => words.push(w),
        }
    }
    match words.as_slice() {
        ["device", "simulate"] => Ok(()),
        [_, _, extra, ..] => Err(format!("unexpected argument `{extra}`")),
        _ => Err("usage: fieldseal device simulate (--script <file> | --scenario <name>) [--review] [--export <file> [--no-parity]] [--upload] [--json]".into()),
    }
}

/// Runs `fieldseal device …`; `args` are the arguments after the binary name.
pub fn run(args: &[String], json: bool) -> ExitCode {
    // `device capture` (the stack's registered device) has its own closed flag set (CLI-030).
    if args.get(1).map(String::as_str) == Some("capture") {
        return stack::run(args, json);
    }
    if let Err(m) = check_args(args) {
        eprintln!("fieldseal: {m}");
        return ExitCode::from(2);
    }
    let positional: Vec<&str> = args.iter().map(String::as_str).filter(|a| !a.starts_with("--")).collect();
    if positional.get(1) != Some(&"simulate") {
        eprintln!("usage: fieldseal device simulate (--script <file> | --scenario <name>) [--review] [--export <file> [--no-parity]] [--upload] [--json]");
        return ExitCode::from(2);
    }
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let review = args.iter().any(|a| a == "--review");
    // `--export <file>` builds the final export (parity on unless `--no-parity`) and writes it;
    // `--upload` then uploads to the in-process intake (docs/reference/spec/delivery.md §8).
    let mut extra: Vec<Value> = Vec::new();
    if let Some(path) = flag("--export") {
        let parity = if args.iter().any(|a| a == "--no-parity") { "off" } else { "on" };
        extra.push(fieldseal_kernel::cbor::map([(
            "export",
            fieldseal_kernel::cbor::map([("out", Value::Text(path)), ("parity", Value::Text(parity.into())), ("ingest", Value::Bool(true))]),
        )]));
    }
    if args.iter().any(|a| a == "--upload") {
        extra.push(fieldseal_kernel::cbor::map([("upload", fieldseal_kernel::cbor::map([]))]));
    }
    let source = match (flag("--script"), flag("--scenario")) {
        (Some(path), None) => match std::fs::read(&path) {
            Ok(b) => Source { text: b, base: Path::new(&path).parent().map(Path::to_path_buf) },
            Err(e) => {
                eprintln!("fieldseal: {path}: {e}");
                return ExitCode::from(4);
            }
        },
        (None, Some(name)) => match SCENARIOS.iter().find(|(n, alias, _)| *n == name || *alias == name) {
            Some((_, _, text)) => Source { text: text.as_bytes().to_vec(), base: None },
            None => {
                let names: Vec<&str> = SCENARIOS.iter().flat_map(|(n, a, _)| [*n, *a]).collect();
                eprintln!("fieldseal: unknown scenario {name} (available: {})", names.join(", "));
                return ExitCode::from(4);
            }
        },
        _ => {
            eprintln!("usage: fieldseal device simulate (--script <file> | --scenario <name>) [--review] [--export <file> [--no-parity]] [--upload] [--json]");
            return ExitCode::from(2);
        }
    };
    match simulate(&source, review, &extra) {
        Ok(outcome) => {
            if json {
                println!("{}", outcome.to_json());
            } else {
                for line in &outcome.lines {
                    println!("{line}");
                }
            }
            if outcome.failures.is_empty() {
                ExitCode::SUCCESS
            } else {
                for f in &outcome.failures {
                    eprintln!("fieldseal: {f}");
                }
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("fieldseal: {e}");
            ExitCode::from(3)
        }
    }
}

struct Source {
    text: Vec<u8>,
    base: Option<PathBuf>,
}

impl Source {
    fn load(&self, reference: &str) -> Result<Value, String> {
        let bytes = match &self.base {
            Some(base) => return fieldseal_adapters_authoring::decode_path(&base.join(reference)).map_err(|e| format!("{reference}: {e}")),
            None => {
                let name = Path::new(reference).file_name().and_then(|n| n.to_str()).unwrap_or(reference);
                EMBEDDED.iter().find(|(n, _)| *n == name).map(|(_, t)| t.as_bytes().to_vec()).ok_or_else(|| format!("{reference}: not embedded"))?
            }
        };
        // The embedded surveys carry their Spanish catalogues too (ADR 0040).
        let mut catalogues = fieldseal_adapters_authoring::compact::Catalogues::new();
        let po = if reference.ends_with("household-water-access.yaml") {
            Some(include_str!("../../../../examples/instruments/i18n/household-water-access/es.po"))
        } else if reference.ends_with("household-water-access.compact.yaml") {
            Some(include_str!("../../../../examples/layouts/i18n/household-water-access.compact/es.po"))
        } else if reference.ends_with("school-meals-baseline.yaml") {
            Some(include_str!("../../../../examples/instruments/i18n/school-meals-baseline/es.po"))
        } else if reference.ends_with("school-meals-baseline.compact.yaml") {
            Some(include_str!("../../../../examples/layouts/i18n/school-meals-baseline.compact/es.po"))
        } else if reference.ends_with("school-meals-baseline.expanded.yaml") {
            Some(include_str!("../../../../examples/layouts/i18n/school-meals-baseline.expanded/es.po"))
        } else {
            None
        };
        if let Some(po) = po {
            let es = fieldseal_adapters_authoring::compact::parse_po(po).map_err(|e| e.to_string())?;
            catalogues.insert("es".into(), es);
        }
        let raw = fieldseal_adapters_authoring::decode_raw(&bytes, Format::Yaml).map_err(|e| format!("{reference}: {e}"))?;
        fieldseal_adapters_authoring::compact::expand_with(raw, &catalogues).map_err(|e| format!("{reference}: {e}"))
    }
}

#[derive(Default)]
struct Outcome {
    lines: Vec<String>,
    failures: Vec<String>,
    journal: Vec<(u64, String, String)>,
    verified: bool,
    ticks_monotonic: bool,
    outbox_parts: u64,
    reviews: Vec<String>,
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl Outcome {
    fn to_json(&self) -> String {
        let records: Vec<String> =
            self.journal.iter().map(|(s, k, d)| format!("{{\"seq\":{s},\"type\":{},\"detail\":{}}}", json_str(k), json_str(d))).collect();
        let steps: Vec<String> = self.lines.iter().filter(|l| l.starts_with("step ")).map(|l| json_str(l)).collect();
        let failures: Vec<String> = self.failures.iter().map(|f| json_str(f)).collect();
        let reviews: Vec<String> = self.reviews.iter().map(|r| json_str(r)).collect();
        format!(
            "{{\"command\":\"device simulate\",\"exitCode\":{},\"findings\":[],\"attested\":false,\"keys\":\"software\",\"ok\":{},\"steps\":[{}],\"journal\":{{\"records\":{},\"verified\":{},\"ticks_monotonic\":{},\"entries\":[{}]}},\"outbox_parts\":{},\"reviews\":[{}],\"failures\":[{}]}}",
            u8::from(!self.failures.is_empty()),
            self.failures.is_empty(),
            steps.join(","),
            self.journal.len(),
            self.verified,
            self.ticks_monotonic,
            records.join(","),
            self.outbox_parts,
            reviews.join(","),
            failures.join(",")
        )
    }
}

fn map(v: &Value) -> Option<&BTreeMap<String, Value>> {
    v.as_map()
}

fn field<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    map(v).and_then(|m| m.get(key))
}

fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    field(v, key).and_then(Value::as_text)
}

fn int(v: &Value, key: &str) -> Option<u64> {
    field(v, key).and_then(Value::as_int).and_then(|i| u64::try_from(i).ok())
}

fn list<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    field(v, key).and_then(Value::as_array).unwrap_or(&[])
}

pub(crate) fn pin(s: &str) -> Result<RuntimePin, String> {
    RuntimePin::new(s).map_err(|e| format!("PIN: {e}"))
}

fn subject(v: &Value) -> Result<SubjectId, String> {
    let s = text(v, "subject").ok_or("step needs `subject`")?;
    SubjectId::new(s).map_err(|e| e.to_string())
}

fn rosters(scenario: &Value) -> Result<Vec<HeldRoster>, String> {
    let mut out = Vec::new();
    for r in list(scenario, "rosters") {
        let cohort = text(r, "cohort").ok_or("roster needs `cohort`")?;
        let version = int(r, "version").unwrap_or(1);
        let mut subjects = Vec::new();
        for (i, s) in list(r, "subjects").iter().enumerate() {
            let consent = match text(s, "consent").unwrap_or("unknown") {
                "granted" => ConsentState::Granted,
                "refused" => ConsentState::Refused,
                "unknown" => ConsentState::Unknown,
                other => return Err(format!("unknown consent state {other}")),
            };
            let display = field(s, "display")
                .and_then(map)
                .map(|m| m.iter().filter_map(|(k, v)| v.as_text().map(|t| (k.clone(), t.to_owned()))).collect())
                .unwrap_or_default();
            let attributes = field(s, "attributes").and_then(map).cloned().unwrap_or_default();
            subjects.push(RosterSubject { ordinal: i as u64 + 1, subject: subject(s)?, display, attributes, consent, prior_status: None });
        }
        out.push(HeldRoster {
            cohort: CohortId::new(cohort).map_err(|e| e.to_string())?,
            version,
            generation: 1,
            address: roster_address(cohort, version, &subjects),
            subjects,
        });
    }
    Ok(out)
}

fn mode(s: &str) -> Result<CaptureMode, String> {
    Ok(match s {
        "first" => CaptureMode::First,
        "resume" => CaptureMode::Resume,
        "resurvey" => CaptureMode::Resurvey,
        "correction" => CaptureMode::Correction,
        _ => return Err(format!("unknown mode {s}")),
    })
}

fn item(p: &str) -> Result<ItemPath, CollectionError> {
    ItemPath::new(p).map_err(|e| CollectionError::NotEditable(format!("{p}: {e}")))
}

fn describe(p: &Payload) -> String {
    match p {
        Payload::Items(i) => format!(
            "{} {} values={} layout={} lang={}{}{}",
            String::from_utf8_lossy(&i.subject),
            match i.mode {
                fieldseal_kernel::payload::Mode::First => "first",
                fieldseal_kernel::payload::Mode::Resume => "resume",
                fieldseal_kernel::payload::Mode::Resurvey => "resurvey",
                fieldseal_kernel::payload::Mode::Correction => "correction",
            },
            i.values.len(),
            match i.layout {
                Layout::Default => "default".to_owned(),
                Layout::Published(a) => format!("sha256:{}…", &lower_hex(a.as_bytes())[..12]),
            },
            i.lang.join(","),
            i.overrides.as_ref().map_or(String::new(), |o| format!(" overrides={}", o.len())),
            i.flags.as_ref().map_or(String::new(), |f| format!(" flags={}", f.join(","))),
        ),
        Payload::Status { subject, status, .. } => format!("{} {}", String::from_utf8_lossy(subject), status.as_str()),
        Payload::Consent { subject, basis, evidence, .. } => format!("{} basis={basis} evidence={}", String::from_utf8_lossy(subject), evidence.len()),
        Payload::Evidence { media_type, bytes, .. } => format!("{media_type} {} bytes", bytes.len()),
        Payload::Anchor { kind, authority_time, .. } => format!("{} at {authority_time}", fieldseal_collection::domain::payload::anchor_kind_str(*kind)),
        Payload::Import { artefacts, rosters, .. } => format!("{} artefacts, {} rosters", artefacts.len(), rosters.len()),
        Payload::Checkpoint { cleared_through, .. } => format!("cleared_through={cleared_through}"),
        Payload::Closing { last_seq, reason, .. } => format!("last_seq={last_seq} reason={}", reason.as_str()),
        Payload::Open { .. } => "tenancy opened".to_owned(),
    }
}

fn review_lines(r: &ReviewReport) -> Vec<String> {
    let mut out = Vec::new();
    for s in &r.subjects {
        let kinds: Vec<String> = s.records.iter().map(|x| format!("{}#{}{}", x.kind, x.seq.0, x.mode.map_or(String::new(), |m| format!("({m})")))).collect();
        out.push(format!(
            "  {} / {}: {} values, {} unanswered, {} kept soft, records [{}]{}",
            s.cohort.as_ref().map_or("-", CohortId::as_str),
            s.subject.as_str(),
            s.current.len(),
            s.unanswered,
            s.kept_soft.len(),
            kinds.join(" "),
            s.status.map_or(String::new(), |x| format!(", status {}", x.as_str()))
        ));
    }
    for c in &r.checks {
        let subjects: Vec<&str> = c.subjects.iter().map(SubjectId::as_str).collect();
        out.push(format!("  field check {} raised for {}", c.check, subjects.join(", ")));
    }
    out.push(format!("  cleared: {} delivered, {} awaiting delivery", r.cleared.delivered, r.cleared.awaiting));
    out
}

/// The `capture` step: start a capture for a subject, set the values, seal.
fn step_capture(rt: &mut Runtime<'_>, body: &Value) -> Result<String, CollectionError> {
            let s = subject(body).map_err(CollectionError::NotAllowed)?;
            let m = mode(text(body, "mode").unwrap_or("first")).map_err(CollectionError::NotAllowed)?;
            rt.start_capture(&s, m)?;
            // A map has no order: set what can be set, then what that made visible.
            let mut pending: Vec<(&String, &Value)> = field(body, "set").and_then(map).into_iter().flatten().collect();
            while !pending.is_empty() {
                let mut left = Vec::new();
                let mut last = None;
                for (p, v) in pending.iter().copied() {
                    match rt.set_value(&item(p)?, v.clone()) {
                        Ok(()) => {}
                        Err(e @ CollectionError::NotEditable(_)) => {
                            left.push((p, v));
                            last = Some(e);
                        }
                        Err(e) => return Err(e),
                    }
                }
                if left.len() == pending.len() {
                    return Err(last.expect("something failed"));
                }
                pending = left;
            }
            for (p, code) in field(body, "nonresponse").and_then(map).into_iter().flatten() {
                let nr = fieldseal_kernel::cbor::map([("nr", code.clone())]);
                rt.set_value(&item(p)?, nr)?;
            }
            for p in list(body, "clear").iter().filter_map(Value::as_text) {
                rt.clear_value(&item(p)?)?;
            }
            for (rule, reason) in field(body, "override").and_then(map).into_iter().flatten() {
                rt.override_soft(rule, reason.as_text().unwrap_or_default())?;
            }
            let view = rt.capture_view()?;
            let unanswered = view.unanswered.len();
            let soft = view.soft.join(",");
            if field(body, "acknowledge") == Some(&Value::Bool(true)) {
                rt.acknowledge_incomplete(unanswered)?;
            }
            let seq = match text(body, "then").unwrap_or("seal") {
                "seal" => Some(rt.seal()?),
                "pause" => rt.pause()?,
                "discard" => {
                    rt.discard_capture();
                    None
                }
                other => return Err(CollectionError::NotAllowed(format!("unknown `then: {other}`"))),
            };
            Ok(format!(
                "capture {} {}: {} unanswered{}{}",
                s.as_str(),
                m.as_str(),
                unanswered,
                if soft.is_empty() { String::new() } else { format!(", soft {soft}") },
                seq.map_or(", nothing sealed".to_owned(), |q| format!(", sealed seq {}", q.0))
            ))
}

/// The `status` step: record that a subject was absent, declines or is not them.
fn step_status(rt: &mut Runtime<'_>, body: &Value) -> Result<String, CollectionError> {
            let s = subject(body).map_err(CollectionError::NotAllowed)?;
            let outcome = match text(body, "outcome").unwrap_or("absent") {
                "absent" => StatusOutcome::Absent,
                "declines" => StatusOutcome::Declines,
                "not-them" => StatusOutcome::NotThem,
                o => return Err(CollectionError::NotAllowed(format!("unknown outcome {o}"))),
            };
            let seq = rt.record_status(&s, outcome)?;
            Ok(format!("status {} sealed seq {}", s.as_str(), seq.0))
}

/// The `consent` step: record a subject's consent with the collector's basis.
fn step_consent(rt: &mut Runtime<'_>, body: &Value) -> Result<String, CollectionError> {
            let s = subject(body).map_err(CollectionError::NotAllowed)?;
            let input = ConsentInput {
                basis: text(body, "basis").unwrap_or_default().to_owned(),
                statement_version: int(body, "statement").unwrap_or(1) as u32,
                capture_evidence: field(body, "evidence") == Some(&Value::Bool(true)),
            };
            let seq = rt.record_consent(&s, &input)?;
            Ok(format!("consent {} basis {} sealed seq {}{}", s.as_str(), input.basis, seq.0, if input.capture_evidence { " (evidence sealed to the journal only)" } else { "" }))
}

// ---- the scenario schema ----------------------------------------------------------------------

type Obj = BTreeMap<String, Value>;

fn obj<'a>(v: &'a Value, what: &str, allowed: &[&str]) -> Result<&'a Obj, String> {
    let m = v.as_map().ok_or_else(|| format!("{what} must be a map"))?;
    if let Some(k) = m.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("{what}: unknown field `{k}`"));
    }
    Ok(m)
}

fn want_text<'a>(m: &'a Obj, key: &str, what: &str, required: bool) -> Result<Option<&'a str>, String> {
    match m.get(key) {
        Some(Value::Text(t)) => Ok(Some(t)),
        Some(_) => Err(format!("{what}: `{key}` must be text")),
        None if required => Err(format!("{what}: `{key}` is required")),
        None => Ok(None),
    }
}

fn want_uint(m: &Obj, key: &str, what: &str, required: bool, max: u64) -> Result<Option<u64>, String> {
    match m.get(key) {
        Some(Value::Int(i)) => u64::try_from(*i).ok().filter(|n| *n <= max).map(Some).ok_or_else(|| format!("{what}: `{key}` is out of range")),
        Some(_) => Err(format!("{what}: `{key}` must be a whole number")),
        None if required => Err(format!("{what}: `{key}` is required")),
        None => Ok(None),
    }
}

fn want_bool(m: &Obj, key: &str, what: &str) -> Result<(), String> {
    match m.get(key) {
        None | Some(Value::Bool(_)) => Ok(()),
        Some(_) => Err(format!("{what}: `{key}` must be true or false")),
    }
}

fn want_enum(m: &Obj, key: &str, what: &str, allowed: &[&str]) -> Result<(), String> {
    match want_text(m, key, what, false)? {
        Some(t) if !allowed.contains(&t) => Err(format!("{what}: `{key}` must be one of {}", allowed.join(", "))),
        _ => Ok(()),
    }
}

fn want_texts(m: &Obj, key: &str, what: &str) -> Result<(), String> {
    match m.get(key) {
        None => Ok(()),
        Some(Value::Array(a)) if a.iter().all(|v| matches!(v, Value::Text(_))) => Ok(()),
        Some(_) => Err(format!("{what}: `{key}` must be a list of text")),
    }
}

fn want_map<'a>(m: &'a Obj, key: &str, what: &str) -> Result<Option<&'a Obj>, String> {
    match m.get(key) {
        None => Ok(None),
        Some(Value::Map(x)) => Ok(Some(x)),
        Some(_) => Err(format!("{what}: `{key}` must be a map")),
    }
}

/// Checks a scenario against its closed schema before anything runs: unknown fields,
/// wrong types, bad enum values and missing required fields are errors, never defaults.
fn validate_scenario(scenario: &Value, extra_steps: &[Value]) -> Result<(), String> {
    let m = obj(scenario, "scenario", &["pin", "instrument", "layouts", "languages", "window", "rosters", "steps", "seed"])?;
    want_text(m, "pin", "scenario", true)?;
    want_text(m, "instrument", "scenario", true)?;
    want_texts(m, "layouts", "scenario")?;
    want_texts(m, "languages", "scenario")?;
    want_enum(m, "window", "scenario", &["compact", "medium", "expanded"])?;
    want_uint(m, "seed", "scenario", false, u64::MAX)?;
    match m.get("rosters") {
        None => {}
        Some(Value::Array(rosters)) => {
            for (i, r) in rosters.iter().enumerate() {
                let what = format!("roster {}", i + 1);
                let r = obj(r, &what, &["cohort", "version", "subjects"])?;
                want_text(r, "cohort", &what, true)?;
                want_uint(r, "version", &what, false, u64::MAX)?;
                match r.get("subjects") {
                    None => {}
                    Some(Value::Array(subjects)) => {
                        for (j, s) in subjects.iter().enumerate() {
                            let what = format!("roster {} subject {}", i + 1, j + 1);
                            let s = obj(s, &what, &["subject", "consent", "display", "attributes"])?;
                            want_text(s, "subject", &what, true)?;
                            want_enum(s, "consent", &what, &["granted", "refused", "unknown"])?;
                            if let Some(d) = want_map(s, "display", &what)?
                                && d.values().any(|v| !matches!(v, Value::Text(_)))
                            {
                                return Err(format!("{what}: `display` values must be text"));
                            }
                            want_map(s, "attributes", &what)?;
                        }
                    }
                    Some(_) => return Err(format!("{what}: `subjects` must be a list")),
                }
            }
        }
        Some(_) => return Err("scenario: `rosters` must be a list".into()),
    }
    let own = match m.get("steps") {
        None => &[][..],
        Some(Value::Array(a)) => a.as_slice(),
        Some(_) => return Err("scenario: `steps` must be a list".into()),
    };
    for (n, step) in own.iter().chain(extra_steps).enumerate() {
        validate_step(step, n + 1)?;
    }
    Ok(())
}

fn validate_step(step: &Value, n: usize) -> Result<(), String> {
    let what = format!("step {n}");
    let m = step.as_map().ok_or_else(|| format!("{what} must be a map"))?;
    want_text(m, "expect", &what, false)?;
    let mut actions = m.iter().filter(|(k, _)| k.as_str() != "expect");
    let (Some((kind, body)), None) = (actions.next(), actions.next()) else {
        return Err(format!("{what} must have exactly one action"));
    };
    let what = format!("step {n} ({kind})");
    let keys: &[&str] = match kind.as_str() {
        "capture" => &["subject", "mode", "set", "nonresponse", "clear", "override", "acknowledge", "then", "expect"],
        "status" => &["subject", "outcome", "expect"],
        "consent" => &["subject", "basis", "statement", "evidence", "expect"],
        "receipt" => &["through", "expect"],
        "clear" => &["through", "pins", "expect"],
        "unlock" => &["pin", "expect"],
        "export" => &["to", "parity", "outbox", "ingest", "out", "expect"],
        "upload" => &["outbox", "expect"],
        "review" | "lock" | "reboot" | "close" | "import-receipt" => &["expect"],
        "wait" => {
            return match body {
                Value::Int(i) if u64::try_from(*i).is_ok_and(|s| s <= 31_536_000) => Ok(()),
                _ => Err(format!("{what}: expected a number of seconds")),
            };
        }
        other => return Err(format!("{what}: unknown step `{other}`")),
    };
    let b = obj(body, &what, keys)?;
    want_text(b, "expect", &what, false)?;
    match kind.as_str() {
        "capture" => {
            want_text(b, "subject", &what, true)?;
            want_enum(b, "mode", &what, &["first", "resume", "resurvey", "correction"])?;
            want_map(b, "set", &what)?;
            if let Some(nr) = want_map(b, "nonresponse", &what)?
                && nr.values().any(|v| !matches!(v, Value::Text(t) if t == "dont-know" || t == "refused"))
            {
                return Err(format!("{what}: `nonresponse` values must be dont-know or refused"));
            }
            want_texts(b, "clear", &what)?;
            if let Some(o) = want_map(b, "override", &what)?
                && o.values().any(|v| !matches!(v, Value::Text(_)))
            {
                return Err(format!("{what}: `override` reasons must be text"));
            }
            want_bool(b, "acknowledge", &what)?;
            want_enum(b, "then", &what, &["seal", "pause", "discard"])?;
        }
        "status" => {
            want_text(b, "subject", &what, true)?;
            want_enum(b, "outcome", &what, &["absent", "declines", "not-them"])?;
        }
        "consent" => {
            want_text(b, "subject", &what, true)?;
            want_text(b, "basis", &what, false)?;
            want_uint(b, "statement", &what, false, u64::from(u32::MAX))?;
            want_bool(b, "evidence", &what)?;
        }
        "receipt" => {
            want_uint(b, "through", &what, true, u64::MAX)?;
        }
        "clear" => {
            want_uint(b, "through", &what, true, u64::MAX)?;
            match b.get("pins") {
                None => {}
                Some(Value::Array(p)) if p.len() == 2 && p.iter().all(|v| matches!(v, Value::Text(_))) => {}
                Some(_) => return Err(format!("{what}: `pins` must be two PINs")),
            }
        }
        "unlock" => {
            want_text(b, "pin", &what, false)?;
        }
        "export" => {
            want_enum(b, "to", &what, &["removable", "local", "cloud", "share"])?;
            want_enum(b, "parity", &what, &["on", "off"])?;
            want_bool(b, "outbox", &what)?;
            want_bool(b, "ingest", &what)?;
            want_text(b, "out", &what, false)?;
        }
        "upload" => want_bool(b, "outbox", &what)?,
        _ => {}
    }
    Ok(())
}

fn simulate(source: &Source, show_review: bool, extra_steps: &[Value]) -> Result<Outcome, String> {
    let scenario = decode(&source.text, Format::Yaml).map_err(|e| format!("scenario: {e}"))?;
    validate_scenario(&scenario, extra_steps)?;
    let pin_text = text(&scenario, "pin").ok_or("scenario needs `pin`")?.to_owned();
    let instrument = source.load(text(&scenario, "instrument").ok_or("scenario needs `instrument`")?)?;
    let layouts = list(&scenario, "layouts").iter().filter_map(Value::as_text).map(|l| source.load(l)).collect::<Result<Vec<_>, _>>()?;
    let rosters = rosters(&scenario)?;
    let seed = int(&scenario, "seed").unwrap_or(1);

    // The simulated authority publishes; the practice authority's keys receive, so what the
    // device writes passes the real intake gate (CLI-015).
    let bench = Bench::new(seed);
    let (authority, device) = (&bench.sim, &bench.device);
    let provisioning = bench.provisioning();
    let mut out = Outcome::default();
    let mut rt = Runtime::load(device.platform(), provisioning).map_err(|e| e.to_string())?;
    rt.create_tenancy(&pin(&pin_text)?).map_err(|e| e.to_string())?;
    let tenancy = rt.tenancy().ok_or("no tenancy")?;
    out.lines.push(format!("tenancy {} created (local, unattested software keys)", &lower_hex(tenancy.as_bytes())[..16]));
    let sign_pub = rt.key_history().remove(0);
    let handle = fieldseal_kernel::id::TenancyHandle::from([(seed as u8) ^ 0x42; 16]);
    let cohorts: Vec<String> = rosters.iter().map(|r| r.cohort.as_str().to_owned()).collect();
    let cohort_refs: Vec<&str> = cohorts.iter().map(String::as_str).collect();
    let (contents, fingerprint) = bench.registration(tenancy, handle, &sign_pub, Enrolment { instrument: &instrument, layouts: &layouts, rosters: rosters.clone(), cohorts: &cohort_refs })?;
    let file = device.bundles.register(contents);
    rt.import_bundle(&file).map_err(|e| e.to_string())?;
    out.lines.push(format!("bundle imported: instrument verified, {} layout(s), tenancy registered", layouts.len()));
    let enrolled = Enrolled { tenancy, handle, sign_pub, fingerprint, cohorts, rosters };
    let instrument_model = fieldseal_instrument::application::validate_instrument(&instrument).map_err(|f| format!("instrument: {} finding(s)", f.iter().count()))?.instrument;
    let mut delivery = crate::device_delivery::DeliveryBench::new(&bench, &enrolled, instrument_model)?;
    let languages: Vec<&str> = list(&scenario, "languages").iter().filter_map(Value::as_text).collect();
    if !languages.is_empty() {
        rt.set_languages(&languages).map_err(|e| e.to_string())?;
    }
    if let Some(w) = text(&scenario, "window") {
        let class = match w {
            "compact" => WindowClass::Compact,
            "medium" => WindowClass::Medium,
            "expanded" => WindowClass::Expanded,
            _ => return Err(format!("unknown window class {w}")),
        };
        rt.set_window_class(class).map_err(|e| e.to_string())?;
    }

    let mut last_receipt = None;
    let mut closed = false;
    let mut history = rt.key_history();
    let mut held_checkpoints = rt.checkpoints();
    let mut held_anchors = rt.anchors();
    let steps: Vec<Value> = list(&scenario, "steps").iter().cloned().chain(extra_steps.iter().cloned()).collect();
    for (n, step) in steps.iter().enumerate() {
        let n = n + 1;
        let Some((kind, body)) = map(step).and_then(|m| m.iter().find(|(k, _)| k.as_str() != "expect")) else {
            return Err(format!("step {n} is not a map"));
        };
        let expect = text(step, "expect").or_else(|| text(body, "expect"));
        let result: Result<String, CollectionError> = (|| -> Result<String, CollectionError> {
            match kind.as_str() {
                "capture" => step_capture(&mut rt, body),
                "status" => step_status(&mut rt, body),
                "consent" => step_consent(&mut rt, body),
                "wait" => {
                    let secs = field(step, "wait").and_then(Value::as_int).unwrap_or(0) as u64;
                    device.clock.advance_ms(secs * 1000);
                    Ok(format!("waited {secs} s"))
                }
                "review" => {
                    let r = rt.review(&ReviewFilter::default())?;
                    let mut lines = vec![format!("review: {} subject(s), {} field check(s) raised", r.subjects.len(), r.checks.len())];
                    let detail = review_lines(&r);
                    out.reviews.extend(detail.iter().map(|l| l.trim().to_owned()));
                    if show_review {
                        lines.extend(detail);
                    }
                    Ok(lines.join("\n"))
                }
                "receipt" => {
                    let through = int(body, "through").ok_or_else(|| CollectionError::NotAllowed("receipt needs `through`".into()))?;
                    let report = read_journal(&rt.journal()?, &rt.key_history(), &rt.checkpoints());
                    let hash = report.entries.iter().find(|e| e.record.header.seq == through).map_or(Digest::from([0; 32]), |e| e.hash);
                    let coverage = authority.receipt(tenancy, Seq(through), hash, fieldseal_kernel::time::AuthorityTime(fieldseal_adapters_memory::collection::SIMULATION_T0.0 + 30 * 86_400_000));
                    let r = rt.apply_receipt(&coverage)?;
                    last_receipt = Some(coverage);
                    Ok(format!(
                        "receipt through seq {through}: {} cleared frame(s) deleted{}",
                        r.journal_deleted,
                        r.offer_clear_through.map_or(String::new(), |s| format!(", clear offered through {}", s.0))
                    ))
                }
                "clear" => {
                    let through = int(body, "through").ok_or_else(|| CollectionError::NotAllowed("clear needs `through`".into()))?;
                    let pins: Vec<&str> = list(body, "pins").iter().filter_map(Value::as_text).collect();
                    let (a, b) = match pins[..] {
                        [a, b] => (a, b),
                        _ => (pin_text.as_str(), pin_text.as_str()),
                    };
                    let preview = rt.clear_preview(Seq(through))?;
                    let first = pin(a).map_err(CollectionError::NotAllowed)?;
                    let second = pin(b).map_err(CollectionError::NotAllowed)?;
                    let c = rt.clear(Seq(through), &first, &second, last_receipt.as_ref())?;
                    Ok(format!(
                        "clear through seq {through}: {} record(s), {} not yet received; checkpoint seq {}, {} journal frame(s) deleted, {} kept until a receipt",
                        preview.records, preview.not_received, c.checkpoint.0, c.journal_deleted, c.journal_kept
                    ))
                }
                "lock" => {
                    rt.lock("scenario");
                    Ok("session locked".into())
                }
                "unlock" => {
                    let p = pin(text(body, "pin").unwrap_or(&pin_text)).map_err(CollectionError::NotAllowed)?;
                    let info = rt.open_session(&p)?;
                    Ok(format!("session opened, {} posture finding(s)", info.posture.len()))
                }
                "reboot" => {
                    device.clock.reboot();
                    Ok("device rebooted (boot count incremented)".into())
                }
                "close" => {
                    history = rt.key_history();
                    held_checkpoints = rt.checkpoints();
                    held_anchors = rt.anchors();
                    let s = rt.end_tenancy()?;
                    closed = true;
                    Ok(format!("tenancy closed: keys deleted, {} outbox part(s), {} bytes", s.parts, s.bytes))
                }
                "export" => delivery.export(&mut rt, body).map_err(CollectionError::NotAllowed),
                "import-receipt" => delivery.import_receipt(&mut rt).map_err(CollectionError::NotAllowed),
                "upload" => {
                    let (line, coverage) = delivery.upload(&mut rt, body).map_err(CollectionError::NotAllowed)?;
                    if coverage.is_some() {
                        last_receipt = coverage;
                    }
                    Ok(line)
                }
                other => Err(CollectionError::NotAllowed(format!("unknown step `{other}`"))),
            }
        })();
        if kind == "capture" && result.is_err() && expect.is_some() {
            // A refused capture the scenario expected leaves nothing open behind it.
            rt.discard_capture();
        }
        match (result, expect) {
            (Ok(line), None) => out.lines.push(format!("step {n}: {line}")),
            (Err(e), Some(want)) if e.to_string().contains(want) => out.lines.push(format!("step {n}: {kind} refused as expected: {e}")),
            (Ok(line), Some(want)) => {
                out.lines.push(format!("step {n}: {line}"));
                out.failures.push(format!("step {n} ({kind}) succeeded; expected an error containing `{want}`"));
            }
            (Err(e), _) => {
                out.lines.push(format!("step {n}: {kind} failed: {e}"));
                out.failures.push(format!("step {n} ({kind}): {e}"));
            }
        }
    }

    // The journal, as intake would read it: verify, then open payloads with the record key.
    let journal = if closed {
        match rt.outbox().map_err(|e| e.to_string())?.into_iter().next() {
            Some(OutboxEntry::Closed { export, .. }) => {
                let file = fieldseal_kernel::export::ExportFile::decode(&export).map_err(|e| e.to_string())?;
                file.parts.first().map(|p| p.journal.clone()).unwrap_or_default()
            }
            Some(OutboxEntry::Certified { journal, .. }) => journal,
            None => Vec::new(),
        }
    } else {
        rt.journal().map_err(|e| e.to_string())?
    };
    let history = if rt.key_history().is_empty() { history } else { rt.key_history() };
    let checkpoints = if closed { held_checkpoints } else { rt.checkpoints() };
    let report = read_journal(&journal, &history, &checkpoints);
    out.verified = report.is_clean();
    let mut ticks: Vec<Tick> = Vec::new();
    let mut anchors: Vec<Digest> = vec![provisioning.build_anchor];
    // Frames cleared before the journal left the device took their anchors with them.
    for a in if closed { held_anchors } else { rt.anchors() } {
        if !anchors.contains(&a) {
            anchors.push(a);
        }
    }
    for e in &report.entries {
        let p = bench.open_payload(&e.record.payload).map_err(|e| e.to_string())?;
        if let Payload::Anchor { address, .. } = &p
            && !anchors.contains(address)
        {
            anchors.push(*address);
        }
        ticks.push(*p.tick());
        out.journal.push((e.record.header.seq, p.kind().to_owned(), describe(&p)));
    }
    out.ticks_monotonic = first_non_monotonic(&ticks, |d| anchors.iter().position(|a| a == d)).is_none();
    out.outbox_parts = rt.outbox_summary().map_err(|e| e.to_string())?.parts;
    if !out.verified {
        out.failures.push(format!("journal does not verify: {:?}", report.errors));
    }
    if !out.ticks_monotonic {
        out.failures.push("ticks are not monotonic".into());
    }
    out.lines.push(String::new());
    out.lines.push(format!(
        "journal: {} record(s) present{}, signatures and chain {}, ticks {}",
        out.journal.len(),
        if checkpoints.is_empty() { String::new() } else { format!(" (checkpoints at {:?})", checkpoints.iter().map(|c| c.0).collect::<Vec<_>>()) },
        if out.verified { "verified" } else { "FAILED" },
        if out.ticks_monotonic { "strictly increasing" } else { "NOT monotonic" },
    ));
    for (seq, kind, detail) in &out.journal {
        out.lines.push(format!("  {seq:>4}  {kind:<10} {detail}"));
    }
    out.lines.push(format!("outbox: {} part(s)", out.outbox_parts));
    Ok(out)
}
