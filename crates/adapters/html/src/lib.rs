//! Draws a render plan as one self-contained HTML page: the platform adapter behind
//! `fieldseal instrument preview` (ADR 0033, INS-208).
//!
//! The page is faithful to the plan: every node is drawn in plan order and none is regrouped,
//! reordered or left out, except nodes that resolved visibility hides. It decides only how each
//! node kind looks:
//!
//! | Plan node | Drawn as |
//! |---|---|
//! | `step`, `review` | One section per step behind a stepper (back and next); the review lists every answer |
//! | `tabs`, `tab` | The ARIA tabs pattern |
//! | `card`, `group` | A bordered card with its heading |
//! | `row` | A grid, side by side on wide windows, stacked on compact ones |
//! | `list`, `instance` | One card per instance, the instance-name input in its header |
//! | `table`, `instance` | A real `<table>` with column headers, one row per instance |
//! | `question` | A labelled control; coded controls are a `fieldset` with a `legend` |
//! | `display` | Text styled by role (introduction, instruction, note, end) |
//!
//! Controls: options and scale steps in the instrument's order with none selected unless a
//! current value is supplied (INS-020, INS-021); nonresponse as separate buttons, never options
//! (INS-140); units with their labels; money with its currency; measurement pairs as two inputs;
//! scales as segmented controls; collector guidance only when the instrument isn't
//! self-administered (INS-151); media embedded from the instrument as `data:` URIs with their
//! `alt` text.
//!
//! Numbers, currencies, dates and plural variants are formatted for the plan's language with
//! CLDR data (INS-088, `fieldseal_instrument::domain::locale`). Inputs show and accept the
//! language's digits and separators (Arabic-Indic digits in `ar`); the stored value stays
//! locale-free.
//!
//! The page makes no requests: its style and script are inline and pinned by a content
//! security policy of their hashes, images are `data:` URIs, and forms submit nowhere. The
//! script switches steps and tabs and reads typed numbers in the language's digits; without it every step and tab is shown. Text direction
//! comes from the plan (`dir`), and the style uses logical properties, so right-to-left plans
//! mirror. Every text is escaped; instrument content never reaches the script or the style.
//! The same inputs always give the same bytes.

mod escape;
mod message;
mod render;
mod strings;

use std::collections::BTreeMap;

use fieldseal_instrument::domain::{Instrument, PlanVisibility, RenderPlan};
use fieldseal_kernel::Value;

pub use message::{Segment, segments};

/// The page's style sheet (inline; never contains instrument content).
///
/// Nunito Sans (SIL OFL 1.1, `fonts/OFL.txt`) is embedded as `data:` URIs by `fonts.css`, which
/// `tools/build-adapter-font.sh` generates; the page still makes no request.
pub const STYLE: &str = concat!(include_str!("fonts.css"), include_str!("page.css"));

/// The page's script: step and tab switching only (inline; never contains instrument content).
pub const SCRIPT: &str = include_str!("page.js");

/// What to draw.
#[derive(Clone, Copy, Debug)]
pub struct Page<'a> {
    /// The plan, compiled by the format core.
    pub plan: &'a RenderPlan,
    /// The instrument it was compiled from: its media bytes are embedded.
    pub instrument: &'a Instrument,
    /// Each node's current visibility (`ResolveVisibility`). Without it, every node is drawn
    /// as visible.
    pub visibility: Option<&'a PlanVisibility>,
    /// Current values by item path (WIRE-052): controls show them, and message variables are
    /// replaced by them.
    pub values: &'a BTreeMap<String, Value>,
    /// Roster fields, for read-only items and `$roster.<field>` variables.
    pub roster: &'a BTreeMap<String, Value>,
    /// The instrument's short fingerprint (WIRE-187), shown beside its name (INS-104). An
    /// instrument has none until it is published with a salt, so it is optional.
    pub fingerprint: Option<&'a str>,
}

impl<'a> Page<'a> {
    /// A page for `plan` with no values: every node visible, nothing selected.
    pub fn new(plan: &'a RenderPlan, instrument: &'a Instrument) -> Self {
        Self { plan, instrument, visibility: None, values: &render::EMPTY, roster: &render::EMPTY, fingerprint: None }
    }
}

/// Draws the page. Deterministic: the same page always gives the same bytes.
pub fn render_html(page: &Page<'_>) -> String {
    render::page(page)
}
