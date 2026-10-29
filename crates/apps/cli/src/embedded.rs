//! The example surveys and scenarios built into the binary, for `device simulate --scenario` and
//! the conformance suite. `build.rs` writes the table from the survey folders in `examples/`.

use fieldseal_adapters_authoring::po::{EntryCatalogues, parse_po};
use fieldseal_adapters_authoring::{Format, compact, decode_raw};
use fieldseal_kernel::Value;

include!(concat!(env!("OUT_DIR"), "/embedded_surveys.rs"));

/// The text of the built-in scenario `name`.
pub fn scenario(name: &str) -> Option<&'static str> {
    SCENARIO_FILES.iter().find(|(n, _)| *n == name).map(|(_, text)| *text)
}

/// A survey as the resolver loads it: the expanded instrument and its layouts by window class,
/// all expanded with the survey's catalogues.
pub struct Embedded {
    pub instrument: Value,
    pub layouts: Vec<(String, Value)>,
}

impl Embedded {
    /// The layout for `window`.
    pub fn layout(&self, window: &str) -> Option<&Value> {
        self.layouts.iter().find(|(w, _)| w == window).map(|(_, v)| v)
    }
}

/// Expands the embedded survey `name`.
pub fn survey(name: &str) -> Result<Embedded, String> {
    let files = |role: &'static str| SURVEY_FILES.iter().filter(move |(s, r, _, _)| *s == name && *r == role);
    let mut catalogues = EntryCatalogues::new();
    for (_, _, language, bytes) in files("catalogue") {
        let text = std::str::from_utf8(bytes).map_err(|_| format!("{name}: {language}.po is not UTF-8"))?;
        let entries = parse_po(text).map_err(|e| format!("{name}: {language}.po: {e}"))?;
        catalogues.insert((*language).to_owned(), entries.into_iter().map(|e| (e.msgctxt.clone(), e)).collect());
    }
    let expand = |bytes: &[u8], what: &str| {
        let raw = decode_raw(bytes, Format::Yaml).map_err(|e| format!("{name}: {what}: {e}"))?;
        compact::expand_with_entries(raw, &catalogues).map_err(|e| format!("{name}: {what}: {e}"))
    };
    let (_, _, _, instrument) = files("instrument").next().ok_or_else(|| format!("{name}: not embedded"))?;
    let layouts = files("layout").map(|(_, _, window, bytes)| expand(bytes, &format!("{window} layout")).map(|v| ((*window).to_owned(), v))).collect::<Result<Vec<_>, _>>()?;
    Ok(Embedded { instrument: expand(instrument, "instrument")?, layouts })
}
