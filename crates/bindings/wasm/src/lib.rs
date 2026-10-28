//! The Fieldseal core compiled to WebAssembly (ADR 0036).
//!
//! Two surfaces, both thin: every decision is made by the same Rust code the CLI and the
//! services run.
//!
//! - [`Workbench`]: an instrument and its layouts, drawn and evaluated exactly as
//!   `fieldseal instrument preview` does (CLI-011).
//! - [`device`]: the browser device (the `web` platform profile, PLAT-100 and following).
//!
//! Values cross the boundary as JSON text; the Rust side parses them with the strict
//! authoring decoder.

pub mod device;

use fieldseal_adapters_authoring::Format;
use fieldseal_adapters_web::json::quote;
use fieldseal_adapters_web::workbench::{self, RenderOptions};
use fieldseal_instrument::domain::WindowClass;
use wasm_bindgen::prelude::*;

fn js(e: impl ToString) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn format_of(name: &str) -> Result<Format, JsValue> {
    match name {
        "yaml" | "yml" => Ok(Format::Yaml),
        "json" => Ok(Format::Json),
        other => Err(js(format!("unknown format {other}"))),
    }
}

/// Parses `{"layout": 0|null, "languages": ["es"], "window": "compact"}`.
fn options_of(json: &str) -> Result<RenderOptions, JsValue> {
    let map = if json.trim().is_empty() { Default::default() } else { workbench::parse_map(json).map_err(js)? };
    let mut o = RenderOptions::default();
    if let Some(fieldseal_kernel::Value::Int(i)) = map.get("layout") {
        o.layout = Some(*i as usize);
    }
    if let Some(fieldseal_kernel::Value::Array(a)) = map.get("languages") {
        o.languages = a.iter().filter_map(|v| v.as_text().map(str::to_owned)).collect();
    }
    if let Some(w) = map.get("window").and_then(|v| v.as_text()) {
        o.window = Some(WindowClass::from_name(w).ok_or_else(|| js(format!("bad window class {w}")))?);
    }
    Ok(o)
}

/// An instrument and its layouts in the browser.
#[wasm_bindgen]
pub struct Workbench {
    inner: workbench::Workbench,
}

#[wasm_bindgen]
impl Workbench {
    /// Validates an instrument document (`format` is `yaml` or `json`). Throws the findings.
    #[wasm_bindgen(constructor)]
    pub fn new(source: &str, format: &str) -> Result<Workbench, JsValue> {
        let inner = workbench::Workbench::load(source.as_bytes(), format_of(format)?).map_err(js)?;
        Ok(Workbench { inner })
    }

    /// Adds a layout document, bound to this instrument; returns its index. The pairing was
    /// checked by the server that supplied both documents; here the layout is validated
    /// against the instrument's elements.
    #[wasm_bindgen(js_name = addLayout)]
    pub fn add_layout(&mut self, source: &str, format: &str) -> Result<usize, JsValue> {
        let id = self.inner.identity();
        self.inner.add_layout(source.as_bytes(), format_of(format)?, &move |_| Some(id)).map_err(js)
    }

    /// The instrument's content address.
    pub fn address(&self) -> String {
        self.inner.address().to_text()
    }

    /// Draws the page: the same bytes as `instrument preview` for the same inputs. `options`
    /// is `{"layout":0,"languages":["es"],"window":"compact"}`; `values` and `roster` are JSON
    /// objects (or empty) as `--answers` and `--roster` files.
    pub fn render(&self, options: &str, values: &str, roster: &str) -> Result<String, JsValue> {
        let o = options_of(options)?;
        let vals = if values.trim().is_empty() { None } else { Some(workbench::parse_map(values).map_err(js)?) };
        let ros = if roster.trim().is_empty() { None } else { Some(workbench::parse_map(roster).map_err(js)?) };
        let r = self.inner.render(&o, vals.as_ref(), ros.as_ref(), true).map_err(js)?;
        Ok(r.html)
    }

    /// Evaluates the rules over the answers, live: visibility by plan node id and by item
    /// path, hard and soft verdicts, value problems and unanswered questions, as JSON.
    pub fn evaluate(&self, options: &str, values: &str, roster: &str) -> Result<String, JsValue> {
        let o = options_of(options)?;
        let vals = if values.trim().is_empty() { Default::default() } else { workbench::parse_map(values).map_err(js)? };
        let ros = if roster.trim().is_empty() { Default::default() } else { workbench::parse_map(roster).map_err(js)? };
        self.inner.evaluate_json(&o, &vals, &ros).map_err(js)
    }

    /// The validation warnings and lints, as a JSON array of `{severity, id, path, message}`.
    pub fn findings(&self) -> String {
        let items: Vec<String> = self
            .inner
            .warnings()
            .iter()
            .chain(self.inner.lints().iter())
            .map(|f| {
                format!(
                    "{{\"severity\":{},\"id\":{},\"path\":{},\"message\":{}}}",
                    quote(workbench::severity_name(f.severity)),
                    quote(f.requirement),
                    quote(&f.path),
                    quote(&f.message)
                )
            })
            .collect();
        format!("[{}]", items.join(","))
    }
}
