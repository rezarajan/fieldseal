//! `fieldseal instrument …` and `fieldseal layout …` (CLI §5): read files, decode them with
//! the authoring adapter, and call the Instrument context's use cases. Reading files is the
//! CLI's job; the context sees only canonical values.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fieldseal_adapters_authoring::{ErrorKind, Format};
use fieldseal_adapters_html::Page;
use fieldseal_instrument::application::{
    LayoutBinding, LayoutLintThresholds, LayoutOptions, PlanLayout, PlanRequest, ValidationOptions, compile_render_plan, evaluate_rules, lint_instrument,
    lint_layout, resolve_visibility, select_layout, validate_instrument_with, validate_layout_with,
};
use fieldseal_instrument::domain::evaluation::RecordInput;
use fieldseal_instrument::domain::{Instrument, InstrumentReference, Layout, LayoutIdentity, RenderPlan, Severity, Verdict, WindowClass};
use fieldseal_kernel::Value;
use fieldseal_kernel::digest::{instrument_fingerprint, lower_hex};
use fieldseal_kernel::id::{ContentAddress, Fingerprint, Salt};
use fieldseal_policy::application::{PolicyValidator, ValidatePolicy};
use fieldseal_policy::domain::Controls;

use crate::args::{Args, UsageError};
use crate::composition::{AuthoringTools, LogFormat};
use crate::json;
use crate::messages::msg;
use crate::outcome::{Outcome, exit};

/// What every command is given.
pub struct Ctx {
    /// The authoring and presentation adapters.
    pub tools: AuthoringTools,
    /// The stderr event format.
    pub log_format: LogFormat,
}

impl Ctx {
    /// Writes one structured event to stderr (CLI-004, ADR 0025).
    fn event(&self, name: &str, fields: &[(&str, &str)]) {
        match self.log_format {
            LogFormat::Json => {
                let mut m = BTreeMap::from([("event".to_owned(), Value::Text(name.to_owned()))]);
                for (k, v) in fields {
                    m.insert((*k).to_owned(), Value::Text((*v).to_owned()));
                }
                eprintln!("{}", json::compact(&Value::Map(m)));
            }
            LogFormat::Text => {
                let rest: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
                eprintln!("{name} {}", rest.join(" "));
            }
        }
    }
}

/// Runs `fieldseal <noun> <verb> …`. Returns the outcome, or `None` if the command is not one
/// of these.
pub fn run(ctx: &Ctx, noun: &str, verb: &str, raw: &[String]) -> Option<(Outcome, bool)> {
    const SALT: &str = "--salt";
    let (command, valued, switches): (&'static str, &[&str], &[&str]) = match (noun, verb) {
        ("instrument", "validate") => ("instrument validate", &[], &[]),
        ("instrument", "lint") => ("instrument lint", &[], &[]),
        ("instrument", "compile") => ("instrument compile", &[], &[]),
        ("instrument", "hash") => ("instrument hash", &[SALT], &[]),
        ("instrument", "preview") => (
            "instrument preview",
            &["--layout", "--lang", "--window", "--answers", "--roster", "--format", "-o", "--output", SALT],
            &[],
        ),
        ("layout", "validate") => ("layout validate", &["--instrument", SALT], &[]),
        ("layout", "lint") => ("layout lint", &["--instrument", "--policy", SALT], &[]),
        ("layout", "compile") => ("layout compile", &["--instrument", "--lang", "--window", SALT], &[]),
        _ => return None,
    };
    let mut out = Outcome::new(command);
    let args = match Args::parse(command, raw, valued, switches) {
        Ok(a) => a,
        Err(UsageError(m)) => {
            out.error(exit::USAGE, m);
            return Some((out, raw.iter().any(|a| a == "--json")));
        }
    };
    let as_json = args.has("--json");
    if args.has("--help") {
        out.lines.push(msg("usage", &[]));
        return Some((out, as_json));
    }
    let result = match command {
        "instrument validate" => instrument_validate(ctx, &args, &mut out),
        "instrument lint" => instrument_lint(ctx, &args, &mut out),
        "instrument compile" => instrument_compile(ctx, &args, &mut out),
        "instrument hash" => instrument_hash(ctx, &args, &mut out),
        "instrument preview" => instrument_preview(ctx, &args, &mut out),
        "layout validate" => layout_validate(ctx, &args, &mut out),
        "layout lint" => layout_lint(ctx, &args, &mut out),
        _ => layout_compile(ctx, &args, &mut out),
    };
    if let Err(UsageError(m)) = result {
        out.error(exit::USAGE, m);
    }
    Some((out, as_json))
}

type Result<T = ()> = std::result::Result<T, UsageError>;

// ---- loading ------------------------------------------------------------------------------

/// Reads and decodes an authoring document. On failure the outcome records why (not found:
/// 4; not decodable: a finding, 1).
fn load(ctx: &Ctx, path: &str, out: &mut Outcome) -> Result<Option<Value>> {
    let ext = Path::new(path).extension().and_then(|e| e.to_str()).unwrap_or("");
    let Some(format) = Format::from_extension(ext) else {
        return Err(UsageError(msg("bad-extension", &[("file", path)])));
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            out.error(exit::NOT_FOUND, msg("not-found", &[("file", path), ("reason", &e.to_string())]));
            return Ok(None);
        }
    };
    let _ = (&bytes, format);
    // decode_path: a compact survey (ADR 0040) also reads its i18n/<lang>.po catalogues.
    match ctx.tools.decode_path(Path::new(path)) {
        Ok(v) => Ok(Some(v)),
        Err(e) => {
            // Decoding is the first step of canonicalisation (INS-002); text that isn't NFC
            // breaks WIRE-004.
            let id = if e.kind == ErrorKind::NotNfc { "WIRE-004" } else { "INS-002" };
            let at = format!("{}:{}", e.line, e.column);
            out.raw_finding(id, "error", path, &at, &e.message);
            Ok(None)
        }
    }
}

/// A validated instrument with its canonical bytes.
struct Loaded {
    instrument: Instrument,
    canonical: Vec<u8>,
}

impl Loaded {
    fn address(&self) -> ContentAddress {
        ContentAddress::of(&self.canonical)
    }
}

/// Loads and validates an instrument, reporting its findings (warnings included when
/// `warnings`).
fn load_instrument(ctx: &Ctx, path: &str, out: &mut Outcome, warnings: bool) -> Result<Option<Loaded>> {
    let Some(doc) = load(ctx, path, out)? else { return Ok(None) };
    let digest = |b: &[u8]| ctx.tools.sha256(b);
    match validate_instrument_with(&doc, ValidationOptions { media_digest: Some(&digest) }) {
        Ok(v) => {
            if warnings {
                for f in &v.warnings {
                    out.finding(path, f);
                }
            }
            match ctx.tools.canonical(&v.instrument.to_value()) {
                Ok(canonical) => Ok(Some(Loaded { instrument: v.instrument, canonical })),
                Err(e) => {
                    // A validated instrument always encodes; failing here is a defect.
                    out.error(exit::INTERNAL, format!("fieldseal: {path}: {e}"));
                    Ok(None)
                }
            }
        }
        Err(findings) => {
            for f in &findings {
                out.finding(path, f);
            }
            Ok(None)
        }
    }
}

fn parse_salt(args: &Args) -> Result<Option<Salt>> {
    let Some(hex) = args.value("--salt") else { return Ok(None) };
    let bad = || UsageError(msg("bad-salt", &[]));
    let bytes = crate::support::unhex(hex).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or_else(bad)?;
    Ok(Some(Salt::from(bytes)))
}

/// The identity a layout binds to (INS-200): the salted fingerprint when a salt is given
/// (WIRE-185), otherwise the unsalted content address of the canonical bytes (WIRE-011),
/// since an instrument has no salt until it is published.
pub(crate) fn identity(canonical: &[u8], salt: Option<&Salt>) -> Fingerprint {
    match salt {
        Some(s) => instrument_fingerprint(s, canonical),
        None => Fingerprint::from(*ContentAddress::of(canonical).as_bytes()),
    }
}

/// Loads and validates a layout against `ins`, resolving its `spec.instrument` source path
/// relative to the layout file and comparing identities (INS-200). Returns the layout and its
/// content address.
fn load_layout(ctx: &Ctx, path: &str, ins: &Loaded, salt: Option<&Salt>, out: &mut Outcome) -> Result<Option<(Layout, ContentAddress)>> {
    let Some(doc) = load(ctx, path, out)? else { return Ok(None) };
    let dir = Path::new(path).parent().map(Path::to_path_buf).unwrap_or_default();
    let resolve = |r: &InstrumentReference| -> Option<Fingerprint> {
        let InstrumentReference::Source(source) = r else { return None };
        let file: PathBuf = dir.join(source);
        let value = ctx.tools.decode_path(&file).ok()?;
        let canonical = ctx.tools.canonical(&value).ok()?;
        Some(identity(&canonical, salt))
    };
    let binding = LayoutBinding { expected: identity(&ins.canonical, salt), resolve: &resolve };
    match validate_layout_with(&doc, &ins.instrument, LayoutOptions { binding: Some(binding) }) {
        Ok(layout) => match ctx.tools.canonical(&layout.to_value()) {
            Ok(bytes) => Ok(Some((layout, ContentAddress::of(&bytes)))),
            Err(e) => {
                out.raw_finding("INS-200", "error", path, "", &e.to_string());
                Ok(None)
            }
        },
        Err(findings) => {
            for f in &findings {
                out.finding(path, f);
            }
            Ok(None)
        }
    }
}

/// Reads a YAML or JSON map of text keys (answers, roster).
fn load_map(ctx: &Ctx, path: &str, what: &str, out: &mut Outcome) -> Result<Option<BTreeMap<String, Value>>> {
    match load(ctx, path, out)? {
        Some(Value::Map(m)) => Ok(Some(m)),
        Some(_) => {
            out.error(exit::FAILED, msg("not-a-map", &[("file", path), ("what", what)]));
            Ok(None)
        }
        None => Ok(None),
    }
}

fn parse_window(args: &Args) -> Result<Option<WindowClass>> {
    match args.value("--window") {
        None => Ok(None),
        Some(w) => WindowClass::from_name(w).map(Some).ok_or_else(|| UsageError(msg("bad-window", &[("value", w)]))),
    }
}

/// `--lang es --lang en` or `--lang es,en`: the collector's languages, most preferred first.
fn languages(args: &Args) -> Vec<String> {
    args.values("--lang").iter().flat_map(|v| v.split(',')).map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect()
}

/// The window class when none is given: the one the only layout declares, else `expanded`
/// (a preview is usually opened on a wide screen).
fn default_window(layouts: &[(Layout, ContentAddress)]) -> WindowClass {
    match layouts {
        [(l, _)] => l.window_class().unwrap_or(WindowClass::Expanded),
        _ => WindowClass::Expanded,
    }
}

/// The plan as JSON-ready value: the layout's content address in its text form.
fn plan_value(plan: &RenderPlan) -> Value {
    let mut v = plan.to_value();
    if let (Value::Map(m), LayoutIdentity::Address(a)) = (&mut v, plan.layout) {
        m.insert("layout".to_owned(), Value::Text(a.to_text()));
    }
    v
}

fn layout_name(plan: &RenderPlan) -> String {
    match plan.layout {
        LayoutIdentity::Default => "default".to_owned(),
        LayoutIdentity::Address(a) => a.to_text(),
    }
}

fn summary(out: &mut Outcome, file: &str, warnings_only: bool) {
    let errors = out.findings.iter().filter(|f| f.as_map().and_then(|m| m.get("severity")).and_then(Value::as_text) == Some("error")).count();
    let line = if errors > 0 {
        msg("invalid", &[("file", file), ("errors", &errors.to_string())])
    } else if warnings_only && !out.findings.is_empty() {
        msg("findings", &[("file", file), ("count", &out.findings.len().to_string())])
    } else if warnings_only {
        msg("no-findings", &[("file", file)])
    } else {
        msg("valid", &[("file", file)])
    };
    out.lines.insert(0, line);
}

// ---- instrument ---------------------------------------------------------------------------

/// `instrument validate <file>` (CLI-010): exit 1 on any error.
fn instrument_validate(ctx: &Ctx, args: &Args, out: &mut Outcome) -> Result {
    let file = args.file(out.command)?;
    let loaded = load_instrument(ctx, file, out, true)?;
    if let Some(l) = &loaded {
        out.set("address", Value::Text(l.address().to_text()));
    }
    if out.exit <= exit::FAILED {
        summary(out, file, false);
    }
    Ok(())
}

/// `instrument lint <file>`: validation, then the advisory lints.
fn instrument_lint(ctx: &Ctx, args: &Args, out: &mut Outcome) -> Result {
    let file = args.file(out.command)?;
    if let Some(l) = load_instrument(ctx, file, out, true)? {
        for f in &lint_instrument(&l.instrument) {
            out.finding(file, f);
        }
    }
    if out.exit <= exit::FAILED {
        summary(out, file, true);
    }
    Ok(())
}

/// `instrument compile <file>`: the compiled tree as JSON.
fn instrument_compile(ctx: &Ctx, args: &Args, out: &mut Outcome) -> Result {
    let file = args.file(out.command)?;
    if let Some(l) = load_instrument(ctx, file, out, false)? {
        let tree = l.instrument.compiled().to_value();
        out.body = Some(json::pretty(&tree));
        out.set("compiled", tree);
    }
    Ok(())
}

/// `instrument hash <file> [--salt <hex32>]`: the content address of the canonical bytes
/// (WIRE-011); with a salt, also the fingerprint (WIRE-185) and its short form (WIRE-187).
fn instrument_hash(ctx: &Ctx, args: &Args, out: &mut Outcome) -> Result {
    let file = args.file(out.command)?;
    let salt = parse_salt(args)?;
    if let Some(l) = load_instrument(ctx, file, out, false)? {
        let address = l.address().to_text();
        out.lines.push(address.clone());
        out.set("address", Value::Text(address));
        if let Some(s) = salt {
            let fp = instrument_fingerprint(&s, &l.canonical);
            out.lines.push(format!("fingerprint {}", lower_hex(fp.as_bytes())));
            out.lines.push(format!("short {}", fp.short_form()));
            out.set("fingerprint", Value::Text(lower_hex(fp.as_bytes())));
            out.set("short", Value::Text(fp.short_form()));
        }
    }
    Ok(())
}

/// `instrument preview <file> …` (CLI-011): the render plan drawn as an HTML page, or the
/// plan itself with `--format plan`; with `--answers`, rules are evaluated and the page shows
/// resolved visibility and the values.
fn instrument_preview(ctx: &Ctx, args: &Args, out: &mut Outcome) -> Result {
    let file = args.file(out.command)?;
    let salt = parse_salt(args)?;
    let window = parse_window(args)?;
    let as_plan = match args.value("--format").unwrap_or("html") {
        "html" => false,
        "plan" => true,
        other => return Err(UsageError(msg("bad-format", &[("value", other)]))),
    };
    let output = args.value("-o").or_else(|| args.value("--output"));
    if args.value("--roster").is_some() && output.is_none() && !as_plan {
        return Err(UsageError(msg("roster-needs-output", &[])));
    }
    let Some(ins) = load_instrument(ctx, file, out, false)? else { return Ok(()) };
    let mut layouts = Vec::new();
    for path in args.values("--layout") {
        if let Some(l) = load_layout(ctx, path, &ins, salt.as_ref(), out)? {
            layouts.push(l);
        }
    }
    if out.exit != exit::OK {
        return Ok(());
    }
    let values = match args.value("--answers") {
        Some(p) => match load_map(ctx, p, "item paths to values", out)? {
            Some(m) => Some(m),
            None => return Ok(()),
        },
        None => None,
    };
    let roster = match args.value("--roster") {
        Some(p) => match load_map(ctx, p, "roster fields to values", out)? {
            Some(m) => Some(m),
            None => return Ok(()),
        },
        None => None,
    };
    let window = window.unwrap_or_else(|| default_window(&layouts));
    let refs: Vec<&Layout> = layouts.iter().map(|(l, _)| l).collect();
    let chosen = select_layout(&refs, window);
    if chosen.is_none() && !layouts.is_empty() {
        ctx.event("layout.default", &[("window", window.name()), ("message", &msg("layout-default", &[("window", window.name())]))]);
    }
    let plan_layout = match chosen {
        Some(l) => {
            let address = layouts.iter().find(|(x, _)| std::ptr::eq(x, l)).map(|(_, a)| *a).unwrap_or(ContentAddress::from([0; 32]));
            PlanLayout::Layout { layout: l, address }
        }
        None => PlanLayout::Default,
    };
    let langs = languages(args);
    let lang_refs: Vec<&str> = langs.iter().map(String::as_str).collect();
    let plan = match compile_render_plan(&ins.instrument, plan_layout, PlanRequest { languages: &lang_refs, window_class: window }) {
        Ok(p) => p,
        Err(_) => {
            out.raw_finding("INS-208", "error", file, "", &msg("layout-mismatch", &[("file", file)]));
            return Ok(());
        }
    };
    let empty = BTreeMap::new();
    let vals = values.as_ref().unwrap_or(&empty);
    let ros = roster.as_ref().unwrap_or(&empty);
    let mut visibility = None;
    if values.is_some() || roster.is_some() {
        let input = RecordInput { values: vals, roster: ros };
        match (resolve_visibility(&ins.instrument, &plan, input), evaluate_rules(&ins.instrument, input)) {
            (Ok(v), Ok(e)) => {
                visibility = Some(v);
                let ids = |verdict| Value::Array(e.with_verdict(verdict).into_iter().map(|s| Value::Text(s.to_owned())).collect());
                let problems: Vec<Value> = e
                    .problems
                    .iter()
                    .map(|p| {
                        Value::Map(BTreeMap::from([
                            ("path".to_owned(), Value::Text(p.path.clone())),
                            ("id".to_owned(), Value::Text(p.requirement.to_owned())),
                            ("message".to_owned(), Value::Text(p.message.clone())),
                        ]))
                    })
                    .collect();
                // A value the instrument does not accept is a failure, not a note (INS-164).
                for p in &e.problems {
                    out.raw_finding(p.requirement, "error", file, &p.path, &p.message);
                }
                let hard = e.with_verdict(Verdict::Hard).len();
                let soft = e.with_verdict(Verdict::Soft).len();
                out.set(
                    "verdicts",
                    Value::Map(BTreeMap::from([
                        ("hard".to_owned(), ids(Verdict::Hard)),
                        ("soft".to_owned(), ids(Verdict::Soft)),
                        ("problems".to_owned(), Value::Array(problems)),
                        ("unanswered".to_owned(), Value::Array(e.unanswered.iter().map(|p| Value::Text(p.clone())).collect())),
                    ])),
                );
                out.lines.push(msg(
                    "verdicts",
                    &[
                        ("hard", &hard.to_string()),
                        ("soft", &soft.to_string()),
                        ("problems", &e.problems.len().to_string()),
                        ("unanswered", &e.unanswered.len().to_string()),
                    ],
                ));
            }
            _ => {
                out.error(exit::FAILED, msg("evaluation-limit", &[]));
                return Ok(());
            }
        }
    }
    out.set("language", Value::Text(plan.language.as_str().to_owned()));
    out.set("direction", Value::Text(plan.direction.name().to_owned()));
    out.set("windowClass", Value::Text(window.name().to_owned()));
    out.set("layout", Value::Text(layout_name(&plan)));
    out.set("nodes", Value::Int(plan.node_count() as i128));

    let (body, field) = if as_plan {
        let v = plan_value(&plan);
        (json::pretty(&v), ("plan", v))
    } else {
        // The short fingerprint is shown once a salt is given (INS-104); without one the
        // instrument has no fingerprint yet.
        let short = salt.as_ref().map(|s| instrument_fingerprint(s, &ins.canonical).short_form());
        let page = Page { plan: &plan, instrument: &ins.instrument, visibility: visibility.as_ref(), values: vals, roster: ros, fingerprint: short.as_deref() };
        let html = ctx.tools.render_html(&page);
        (html.clone(), ("html", Value::Text(html)))
    };
    match output {
        Some(path) => {
            let p = Path::new(path);
            if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Err(e) = std::fs::write(p, body.as_bytes()) {
                out.error(exit::CONFIG, msg("write-failed", &[("file", path), ("reason", &e.to_string())]));
                return Ok(());
            }
            out.set("output", Value::Text(path.to_owned()));
            out.lines.insert(
                0,
                msg(
                    "wrote",
                    &[
                        ("file", path),
                        ("nodes", &plan.node_count().to_string()),
                        ("language", plan.language.as_str()),
                        ("window", window.name()),
                        ("layout", &layout_name(&plan)),
                    ],
                ),
            );
        }
        None => {
            // The page (or plan) is the human output; summary lines would corrupt it.
            out.lines.clear();
            out.body = Some(body);
            out.set(field.0, field.1);
        }
    }
    Ok(())
}

// ---- layout -------------------------------------------------------------------------------

/// `layout validate <file> --instrument <file>` (CLI-011a): exit 1 on any error.
fn layout_validate(ctx: &Ctx, args: &Args, out: &mut Outcome) -> Result {
    let file = args.file(out.command)?;
    let ins_path = args.required(out.command, "--instrument")?;
    let salt = parse_salt(args)?;
    let Some(ins) = load_instrument(ctx, ins_path, out, false)? else {
        if out.exit <= exit::FAILED {
            out.lines.insert(0, msg("instrument-invalid", &[("file", ins_path)]));
        }
        return Ok(());
    };
    if let Some((_, address)) = load_layout(ctx, file, &ins, salt.as_ref(), out)? {
        out.set("address", Value::Text(address.to_text()));
        out.set("instrument", Value::Text(ins.address().to_text()));
    }
    if out.exit <= exit::FAILED {
        summary(out, file, false);
    }
    Ok(())
}

/// `layout lint <file> --instrument <file> [--policy <file>]` (INS-210–INS-213): thresholds
/// from the policy's `publishing.layoutLint` controls (over the schema defaults); lints the
/// policy lists as `blocking` are reported as errors.
fn layout_lint(ctx: &Ctx, args: &Args, out: &mut Outcome) -> Result {
    let file = args.file(out.command)?;
    let ins_path = args.required(out.command, "--instrument")?;
    let salt = parse_salt(args)?;
    let mut thresholds = LayoutLintThresholds::default();
    let mut blocking: Vec<&'static str> = Vec::new();
    if let Some(policy_path) = args.value("--policy") {
        let Some(doc) = load(ctx, policy_path, out)? else { return Ok(()) };
        let report = PolicyValidator.validate(&doc);
        for f in &report.findings {
            let sev = match f.severity {
                fieldseal_policy::domain::Severity::Error => "error",
                fieldseal_policy::domain::Severity::Warning => "warning",
            };
            out.raw_finding(f.requirement, sev, policy_path, &f.path, &f.message);
        }
        let Some(policy) = report.document.filter(|_| report.findings.iter().all(|f| f.severity != fieldseal_policy::domain::Severity::Error)) else {
            out.lines.insert(0, msg("policy-invalid", &[("file", policy_path)]));
            return Ok(());
        };
        let p = Controls::from_map(policy.controls).publishing().layout_lint;
        let clamp = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
        thresholds = LayoutLintThresholds {
            max_decisions_per_screen: clamp(p.max_decisions_per_screen),
            max_visible_options: clamp(p.max_visible_options),
            max_scale_steps_compact: clamp(p.max_scale_steps_compact),
        };
        blocking = p.blocking.iter().map(|l| l.as_str()).collect();
    }
    let Some(ins) = load_instrument(ctx, ins_path, out, false)? else {
        if out.exit <= exit::FAILED {
            out.lines.insert(0, msg("instrument-invalid", &[("file", ins_path)]));
        }
        return Ok(());
    };
    if let Some((layout, _)) = load_layout(ctx, file, &ins, salt.as_ref(), out)? {
        for mut f in lint_layout(&ins.instrument, &layout, thresholds) {
            if blocking.contains(&f.requirement) {
                f.severity = Severity::Error;
            }
            out.finding(file, &f);
        }
    }
    out.set(
        "thresholds",
        Value::Map(BTreeMap::from([
            ("maxDecisionsPerScreen".to_owned(), Value::Int(thresholds.max_decisions_per_screen.into())),
            ("maxVisibleOptions".to_owned(), Value::Int(thresholds.max_visible_options.into())),
            ("maxScaleStepsCompact".to_owned(), Value::Int(thresholds.max_scale_steps_compact.into())),
        ])),
    );
    if out.exit <= exit::FAILED {
        summary(out, file, true);
    }
    Ok(())
}

/// `layout compile [<file>] --instrument <file> [--lang] [--window]` (INS-206–INS-208): the
/// render plan as JSON; with no layout, the default layout's.
fn layout_compile(ctx: &Ctx, args: &Args, out: &mut Outcome) -> Result {
    let file = args.optional_file()?;
    let ins_path = args.required(out.command, "--instrument")?;
    let salt = parse_salt(args)?;
    let window = parse_window(args)?;
    let Some(ins) = load_instrument(ctx, ins_path, out, false)? else { return Ok(()) };
    let mut layouts = Vec::new();
    if let Some(f) = file {
        match load_layout(ctx, f, &ins, salt.as_ref(), out)? {
            Some(l) => layouts.push(l),
            None => return Ok(()),
        }
    }
    let window = window.unwrap_or_else(|| default_window(&layouts));
    let plan_layout = match layouts.first() {
        Some((layout, address)) => PlanLayout::Layout { layout, address: *address },
        None => PlanLayout::Default,
    };
    let langs = languages(args);
    let lang_refs: Vec<&str> = langs.iter().map(String::as_str).collect();
    match compile_render_plan(&ins.instrument, plan_layout, PlanRequest { languages: &lang_refs, window_class: window }) {
        Ok(plan) => {
            let v = plan_value(&plan);
            out.body = Some(json::pretty(&v));
            out.set("plan", v);
        }
        Err(_) => out.raw_finding("INS-208", "error", file.unwrap_or(ins_path), "", &msg("layout-mismatch", &[("file", file.unwrap_or(ins_path))])),
    }
    Ok(())
}
