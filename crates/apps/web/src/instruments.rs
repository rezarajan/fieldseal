//! The instruments pages: the list, the detail page with its picker, panels and live
//! evaluation, the rendered instrument (the html adapter's own page) and the raw documents.

use fieldseal_adapters_web::json::to_json;
use fieldseal_adapters_web::workbench::{RenderOptions, parse_map};
use fieldseal_instrument::domain::{LayoutIdentity, RenderPlan, WindowClass};
use fieldseal_kernel::Value;

use crate::catalogue::{self, Entry};
use crate::http::{Request, Response, url_encode};
use crate::panels;
use crate::state::AppState;
use crate::ui::{self, escape};

/// The picker's choices, from the query.
#[derive(Clone, Debug, Default)]
pub struct Choice {
    /// `default`, a layout index, or absent for selection by window class.
    pub layout: Option<String>,
    /// The language tag.
    pub lang: Option<String>,
    /// The window class name.
    pub window: Option<String>,
}

impl Choice {
    /// Reads `layout`, `lang` and `window` from the query.
    pub fn of(req: &Request) -> Self {
        let get = |k| req.param(k).map(str::to_owned);
        Self { layout: get("layout"), lang: get("lang"), window: get("window") }
    }

    /// The query string (with `?`) that repeats this choice, or empty.
    pub fn query(&self) -> String {
        let parts: Vec<String> = [("layout", &self.layout), ("lang", &self.lang), ("window", &self.window)]
            .iter()
            .filter_map(|(k, v)| v.as_ref().map(|v| format!("{k}={}", url_encode(v))))
            .collect();
        if parts.is_empty() { String::new() } else { format!("?{}", parts.join("&")) }
    }

    /// The layouts to give the workbench, as `instrument preview` is given them: none for
    /// `default`, only the one asked for, else all (chosen by window class).
    pub fn layouts(&self, entry: &Entry) -> Result<Vec<usize>, String> {
        match self.layout.as_deref() {
            None => Ok(entry.all_layouts()),
            Some("default") => Ok(Vec::new()),
            Some(i) => i.parse::<usize>().ok().filter(|i| *i < entry.layouts.len()).map(|i| vec![i]).ok_or_else(|| format!("There is no layout {i}.")),
        }
    }

    /// The window class asked for.
    pub fn window_class(&self) -> Result<Option<WindowClass>, String> {
        match self.window.as_deref() {
            None => Ok(None),
            Some(w) => WindowClass::from_name(w).map(Some).ok_or_else(|| format!("Unknown window class {w}.")),
        }
    }

    /// The render options (languages and window; layouts are chosen by what is added).
    pub fn options(&self) -> Result<RenderOptions, String> {
        Ok(RenderOptions { layout: None, languages: self.lang.iter().cloned().collect(), window: self.window_class()? })
    }
}

/// Handles `/instruments` and below.
pub fn handle(state: &AppState, req: &Request) -> Option<Response> {
    let rest = req.path.strip_prefix("/instruments")?;
    if req.method != "GET" {
        return None;
    }
    let segments: Vec<&str> = rest.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    if !(rest.is_empty() || rest.starts_with('/')) {
        return None;
    }
    Some(match segments.as_slice() {
        [] => list(state),
        [id] => with_entry(state, id, |e| detail(state, e, req)),
        [id, "render"] => with_entry(state, id, |e| render(e, req)),
        [id, "plan"] => with_entry(state, id, |e| plan(e, req)),
        [id, "source"] => with_entry(state, id, |e| Response::text(200, String::from_utf8_lossy(&e.source).into_owned())),
        [id, "roster"] => with_entry(state, id, roster),
        [id, "layout", i, "source"] => with_entry(state, id, |e| match i.parse::<usize>().ok().and_then(|i| e.layouts.get(i)) {
            Some(l) => Response::text(200, String::from_utf8_lossy(&l.source).into_owned()),
            None => ui::error_page(404, "There is no such layout."),
        }),
        _ => return None,
    })
}

fn with_entry(state: &AppState, id: &str, f: impl FnOnce(&Entry) -> Response) -> Response {
    match catalogue::load(&state.examples_dir, id, &state.survey_cohorts) {
        Some(e) => f(&e),
        None => ui::error_page(404, "There is no such instrument."),
    }
}

/// The list: a short stack of instrument cards, each with one action. The first card is the
/// recommended one and carries the page's only filled button.
fn list(state: &AppState) -> Response {
    let entries = catalogue::load_all(&state.examples_dir, &state.survey_cohorts);
    let mut cards = String::new();
    for (n, e) in entries.iter().enumerate() {
        let id = escape(&e.id);
        let open = if n == 0 { "btn btn-primary" } else { "btn" };
        let (name, meta, status) = match &e.status {
            Ok(s) => (
                escape(&s.name),
                format!("version {} &middot; {} &middot; {} elements, {} layout{}", escape(&s.version), escape(&s.languages.join(", ")), s.elements, e.layouts.len(), if e.layouts.len() == 1 { "" } else { "s" }),
                "<span class=\"chip chip-ok\">Valid</span>".to_owned(),
            ),
            Err(errors) => (
                id.clone(),
                format!("not available: the instrument is invalid &middot; {} layout{}", e.layouts.len() + e.layout_errors.len(), if e.layouts.len() + e.layout_errors.len() == 1 { "" } else { "s" }),
                format!("<span class=\"chip chip-bad\">Invalid: {} error{}</span>", errors.len(), if errors.len() == 1 { "" } else { "s" }),
            ),
        };
        cards.push_str(&format!(
            "<article class=\"card instrument-card\">\n<div class=\"card-top\"><h2>{name}</h2>{status}</div>\n<p class=\"muted\"><code>{id}</code></p>\n<p class=\"muted\">{meta}</p>\n<p class=\"card-action\"><a class=\"{open}\" href=\"/instruments/{id}\">Open</a></p>\n</article>\n"
        ));
    }
    let body = if entries.is_empty() {
        "<p>No instruments were found in the examples directory.</p>".to_owned()
    } else {
        format!("<div class=\"card-grid\">\n{cards}</div>")
    };
    ui::page("Instruments", "/instruments", &format!("<div class=\"page-head\"><div><h1>Instruments</h1>\n<p class=\"lede\">Pick an instrument to see it drawn and checked.</p></div></div>\n{body}"), &[])
}

fn detail(state: &AppState, entry: &Entry, req: &Request) -> Response {
    let choice = Choice::of(req);
    let wasm = state.wasm_available();
    let body = panels::detail(entry, &choice, wasm);
    let scripts: &[&str] = if wasm && entry.status.is_ok() { &["/assets/instrument.js"] } else { &[] };
    ui::page(&format!("Instrument {}", entry.id), "/instruments", &body, scripts)
}

/// Draws the page for `entry` exactly as `fieldseal instrument preview` is given the same
/// layouts, language, window class and answers.
fn render(entry: &Entry, req: &Request) -> Response {
    let choice = Choice::of(req);
    let (which, options) = match (choice.layouts(entry), choice.options()) {
        (Ok(w), Ok(o)) => (w, o),
        (Err(m), _) | (_, Err(m)) => return ui::error_page(400, &m),
    };
    let values = match req.param("answers").map(parse_map) {
        Some(Ok(m)) => Some(m),
        Some(Err(e)) => return ui::error_page(400, &format!("The answers are not a JSON object: {e}")),
        None => None,
    };
    let bench = match entry.workbench(&which) {
        Ok(b) => b,
        Err(e) => return ui::error_page(422, &e.to_string()),
    };
    match bench.render(&options, values.as_ref(), None, true) {
        // The full page (`full=1`, from "Open full page") has a way back to the instrument.
        Ok(r) if req.param("full") == Some("1") => {
            let back = format!("<a class=\"bar-back\" href=\"/instruments/{}\">\u{2190} Back</a>", ui::escape(&entry.id));
            let html = match r.html.find("<div class=\"bar\"").and_then(|i| r.html[i..].find('>').map(|j| i + j + 1)) {
                Some(at) => format!("{}{back}{}", &r.html[..at], &r.html[at..]),
                None => r.html,
            };
            Response::document(html)
        }
        Ok(r) => Response::document(r.html),
        Err(e) => ui::error_page(422, &e),
    }
}

/// The render plan as JSON (`instrument preview --format plan`).
fn plan(entry: &Entry, req: &Request) -> Response {
    let choice = Choice::of(req);
    let (which, options) = match (choice.layouts(entry), choice.options()) {
        (Ok(w), Ok(o)) => (w, o),
        (Err(m), _) | (_, Err(m)) => return ui::error_page(400, &m),
    };
    let result = entry.workbench(&which).map_err(|e| e.to_string()).and_then(|b| b.plan(&options));
    match result {
        Ok((plan, _)) => Response::json(200, to_json(&plan_value(&plan))).with("Content-Disposition", &format!("attachment; filename=\"{}.plan.json\"", entry.id)),
        Err(e) => ui::error_page(422, &e),
    }
}

/// The plan as a value, the layout's content address in its text form.
fn plan_value(plan: &RenderPlan) -> Value {
    let mut v = plan.to_value();
    if let (Value::Map(m), LayoutIdentity::Address(a)) = (&mut v, plan.layout) {
        m.insert("layout".to_owned(), Value::Text(a.to_text()));
    }
    v
}

/// The roster as JSON, `{}` when the instrument has none.
fn roster(entry: &Entry) -> Response {
    let Some(path) = &entry.roster else { return Response::json(200, "{}") };
    let parsed = fieldseal_adapters_authoring::decode_path(path).map_err(|e| e.message);
    match parsed {
        Ok(v) => Response::json(200, to_json(&v)),
        Err(e) => ui::error_page(422, &format!("The roster could not be read: {e}")),
    }
}

