//! The instrument workbench: one instrument, its layouts, and the same render path as
//! `fieldseal instrument preview` (CLI-011, INS-208), plus live rule evaluation (INS-040 and
//! following). No I/O: the caller hands in the document bytes.

use std::collections::BTreeMap;

use fieldseal_adapters_authoring::{Format, decode};
use fieldseal_adapters_html::Page;
use fieldseal_instrument::application::{
    LayoutBinding, LayoutOptions, PlanLayout, PlanRequest, ValidationOptions, compile_render_plan, evaluate_rules, lint_instrument, resolve_visibility, select_layout,
    validate_instrument_with, validate_layout_with,
};
use fieldseal_instrument::domain::evaluation::RecordInput;
use fieldseal_instrument::domain::{Finding, Instrument, InstrumentReference, Layout, LayoutIdentity, RenderPlan, Severity, Verdict, WindowClass};
use fieldseal_kernel::Value;
use fieldseal_kernel::digest::{instrument_fingerprint, sha256};
use fieldseal_kernel::id::{ContentAddress, Fingerprint, Salt};

use crate::json::{from_json, quote, to_json};

/// Why a document could not be loaded: findings (already formatted) or a decoding error.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LoadError {
    /// One line per finding or the decoding error.
    pub messages: Vec<String>,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.messages.join("; "))
    }
}

fn finding_lines(findings: impl IntoIterator<Item = Finding>) -> Vec<String> {
    findings.into_iter().map(|f| f.to_string()).collect()
}

/// What to draw (the options of `instrument preview`).
#[derive(Clone, Debug, Default)]
pub struct RenderOptions {
    /// The index of the layout to use among those added; `None` selects by window class as
    /// `instrument preview` does, falling back to the default layout.
    pub layout: Option<usize>,
    /// The collector's languages, most preferred first.
    pub languages: Vec<String>,
    /// The window class; `None` is the only layout's declared class, else `expanded`.
    pub window: Option<WindowClass>,
}

/// What was drawn.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Rendered {
    /// The HTML page, or the empty string when only the plan was asked for.
    pub html: String,
    /// The language the plan was compiled for.
    pub language: String,
    /// `ltr` or `rtl`.
    pub direction: String,
    /// The window class used.
    pub window_class: String,
    /// `default` or the layout's content address.
    pub layout: String,
    /// The number of plan nodes.
    pub nodes: usize,
}

/// One instrument and its layouts, validated.
pub struct Workbench {
    instrument: Instrument,
    canonical: Vec<u8>,
    layouts: Vec<(Layout, ContentAddress)>,
    warnings: Vec<Finding>,
    salt: Option<Salt>,
}

/// The identity a layout binds to (INS-200): the salted fingerprint when a salt is given,
/// else the unsalted content address of the canonical bytes.
fn identity(canonical: &[u8], salt: Option<&Salt>) -> Fingerprint {
    match salt {
        Some(s) => instrument_fingerprint(s, canonical),
        None => Fingerprint::from(*ContentAddress::of(canonical).as_bytes()),
    }
}

impl Workbench {
    /// Decodes and validates an instrument document.
    pub fn load(source: &[u8], format: Format) -> Result<Self, LoadError> {
        let doc = decode(source, format).map_err(|e| LoadError { messages: vec![format!("{}:{}: {}", e.line, e.column, e.message)] })?;
        let digest = |b: &[u8]| *sha256(b).as_bytes();
        let validated = validate_instrument_with(&doc, ValidationOptions { media_digest: Some(&digest) }).map_err(|f| LoadError { messages: finding_lines(f.iter().cloned()) })?;
        let canonical = fieldseal_kernel::cbor::encode(&validated.instrument.to_value()).map_err(|e| LoadError { messages: vec![e.to_string()] })?;
        Ok(Self { instrument: validated.instrument, canonical, layouts: Vec::new(), warnings: validated.warnings.iter().cloned().collect(), salt: None })
    }

    /// A workbench over an instrument the runtime already holds (validated when the bundle was
    /// imported) and its layouts.
    pub fn from_parts(instrument: Instrument, layouts: Vec<(Layout, ContentAddress)>) -> Self {
        let canonical = fieldseal_kernel::cbor::encode(&instrument.to_value()).unwrap_or_default();
        Self { instrument, canonical, layouts, warnings: Vec::new(), salt: None }
    }

    /// Uses a salt for layout identities and the short fingerprint (INS-104).
    pub fn with_salt(mut self, salt: Salt) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Adds a layout. `resolve` maps the layout's `spec.instrument` source reference to the
    /// identity of the instrument it names (the server resolves it against its files; the
    /// browser, which holds only the paired instrument, passes [`Workbench::trust_pairing`]).
    pub fn add_layout(&mut self, source: &[u8], format: Format, resolve: &dyn Fn(&InstrumentReference) -> Option<Fingerprint>) -> Result<usize, LoadError> {
        let doc = decode(source, format).map_err(|e| LoadError { messages: vec![format!("{}:{}: {}", e.line, e.column, e.message)] })?;
        let binding = LayoutBinding { expected: identity(&self.canonical, self.salt.as_ref()), resolve };
        let layout = validate_layout_with(&doc, &self.instrument, LayoutOptions { binding: Some(binding) }).map_err(|f| LoadError { messages: finding_lines(f.iter().cloned()) })?;
        let bytes = fieldseal_kernel::cbor::encode(&layout.to_value()).map_err(|e| LoadError { messages: vec![e.to_string()] })?;
        self.layouts.push((layout, ContentAddress::of(&bytes)));
        Ok(self.layouts.len() - 1)
    }

    /// The identity layouts must bind to, for a resolver that accepts every source reference.
    pub fn identity(&self) -> Fingerprint {
        identity(&self.canonical, self.salt.as_ref())
    }

    /// The validated instrument.
    pub fn instrument(&self) -> &Instrument {
        &self.instrument
    }

    /// The instrument's content address (WIRE-011).
    pub fn address(&self) -> ContentAddress {
        ContentAddress::of(&self.canonical)
    }

    /// The layouts added, with their content addresses.
    pub fn layouts(&self) -> &[(Layout, ContentAddress)] {
        &self.layouts
    }

    /// Validation warnings.
    pub fn warnings(&self) -> &[Finding] {
        &self.warnings
    }

    /// The advisory lints (`instrument lint`).
    pub fn lints(&self) -> Vec<Finding> {
        lint_instrument(&self.instrument).iter().cloned().collect()
    }

    fn window(&self, options: &RenderOptions) -> WindowClass {
        options.window.unwrap_or(match self.layouts.as_slice() {
            [(l, _)] => l.window_class().unwrap_or(WindowClass::Expanded),
            _ => WindowClass::Expanded,
        })
    }

    /// Compiles the render plan exactly as `instrument preview` does.
    pub fn plan(&self, options: &RenderOptions) -> Result<(RenderPlan, WindowClass), String> {
        let window = self.window(options);
        let chosen: Option<usize> = match options.layout {
            Some(i) => Some(i),
            None => {
                let refs: Vec<&Layout> = self.layouts.iter().map(|(l, _)| l).collect();
                select_layout(&refs, window).and_then(|l| self.layouts.iter().position(|(x, _)| std::ptr::eq(x, l)))
            }
        };
        let plan_layout = match chosen {
            Some(i) => {
                let (l, address) = self.layouts.get(i).ok_or_else(|| format!("no layout {i}"))?;
                PlanLayout::Layout { layout: l, address: *address }
            }
            None => PlanLayout::Default,
        };
        let langs: Vec<&str> = options.languages.iter().map(String::as_str).collect();
        let plan = compile_render_plan(&self.instrument, plan_layout, PlanRequest { languages: &langs, window_class: window }).map_err(|_| "the layout does not fit the instrument (INS-208)".to_owned())?;
        Ok((plan, window))
    }

    /// Draws the page. With `values` or `roster`, rules are evaluated and the page shows the
    /// resolved visibility and the values, as `instrument preview --answers` does.
    pub fn render(&self, options: &RenderOptions, values: Option<&BTreeMap<String, Value>>, roster: Option<&BTreeMap<String, Value>>, as_html: bool) -> Result<Rendered, String> {
        let (plan, window) = self.plan(options)?;
        let empty = BTreeMap::new();
        let vals = values.unwrap_or(&empty);
        let ros = roster.unwrap_or(&empty);
        let visibility = if values.is_some() || roster.is_some() {
            Some(resolve_visibility(&self.instrument, &plan, RecordInput { values: vals, roster: ros }).map_err(|_| "evaluation limit exceeded".to_owned())?)
        } else {
            None
        };
        let short = self.salt.as_ref().map(|s| instrument_fingerprint(s, &self.canonical).short_form());
        let html = if as_html {
            fieldseal_adapters_html::render_html(&Page { plan: &plan, instrument: &self.instrument, visibility: visibility.as_ref(), values: vals, roster: ros, fingerprint: short.as_deref() })
        } else {
            String::new()
        };
        let layout = match plan.layout {
            LayoutIdentity::Default => "default".to_owned(),
            LayoutIdentity::Address(a) => a.to_text(),
        };
        Ok(Rendered { html, language: plan.language.as_str().to_owned(), direction: plan.direction.name().to_owned(), window_class: window.name().to_owned(), layout, nodes: plan.node_count() })
    }

    /// Evaluates the rules over `values` and `roster` and returns the result as JSON:
    /// `{"visibility":{"<node id>":"visible|protected|hidden"},"byPath":{...},"hard":[...],"soft":[...],"problems":[{path,id,message}],"unanswered":[...],"cleared":[...]}`.
    /// Visibility is by plan node id for the plan the options select, and by item path.
    pub fn evaluate_json(&self, options: &RenderOptions, values: &BTreeMap<String, Value>, roster: &BTreeMap<String, Value>) -> Result<String, String> {
        let (plan, _) = self.plan(options)?;
        let input = RecordInput { values, roster };
        let visibility = resolve_visibility(&self.instrument, &plan, input).map_err(|_| "evaluation limit exceeded".to_owned())?;
        let evaluation = evaluate_rules(&self.instrument, input).map_err(|_| "evaluation limit exceeded".to_owned())?;
        let list = |items: Vec<&str>| format!("[{}]", items.iter().map(|s| quote(s)).collect::<Vec<_>>().join(","));
        let nodes = visibility
            .as_slice()
            .iter()
            .enumerate()
            .map(|(i, v)| format!("\"{i}\":{}", quote(fieldseal_instrument::domain::render_plan::visibility_name(*v))))
            .collect::<Vec<_>>()
            .join(",");
        let by_path = evaluation
            .visibility
            .iter()
            .map(|(p, v)| format!("{}:{}", quote(p), quote(fieldseal_instrument::domain::render_plan::visibility_name(*v))))
            .collect::<Vec<_>>()
            .join(",");
        let problems = evaluation
            .problems
            .iter()
            .map(|p| format!("{{\"path\":{},\"id\":{},\"message\":{}}}", quote(&p.path), quote(p.requirement), quote(&p.message)))
            .collect::<Vec<_>>()
            .join(",");
        let unanswered = list(evaluation.unanswered.iter().map(String::as_str).collect());
        let cleared = list(evaluation.cleared.iter().map(String::as_str).collect());
        Ok(format!(
            "{{\"visibility\":{{{nodes}}},\"byPath\":{{{by_path}}},\"hard\":{},\"soft\":{},\"problems\":[{problems}],\"unanswered\":{unanswered},\"cleared\":{cleared},\"blocksSealing\":{}}}",
            list(evaluation.with_verdict(Verdict::Hard)),
            list(evaluation.with_verdict(Verdict::Soft)),
            evaluation.blocks_sealing()
        ))
    }
}

/// Parses a JSON object of text keys to values (answers or roster fields), as `--answers`
/// reads a YAML or JSON file.
pub fn parse_map(json: &str) -> Result<BTreeMap<String, Value>, String> {
    match from_json(json) {
        Ok(Value::Map(m)) => Ok(m),
        Ok(_) => Err("expected a JSON object".to_owned()),
        Err(e) => Err(format!("{}:{}: {}", e.line, e.column, e.message)),
    }
}

/// Re-exported for callers that print a map back.
pub fn map_json(m: &BTreeMap<String, Value>) -> String {
    to_json(&Value::Map(m.clone()))
}

/// Severity name as the CLI prints it.
pub fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Advice => "advice",
    }
}
