//! `fieldseal localisation validate` (CLI §5; PLAT-050, PLAT-053).
//!
//! `localisation validate` checks a runtime UI catalogue against the runtime's reference
//! catalogue: every message ID present, none unknown, the same variables, valid MessageFormat 2
//! (PLAT-050, PLAT-053). A catalogue is `kind: Localisation` with `spec.language`,
//! `spec.referenceVersion` and `spec.messages` (message ID to message). Survey translations
//! are `.po` catalogues, checked by `instrument validate` (INS-082–INS-085).

use std::collections::BTreeMap;

use fieldseal_instrument::domain::LanguageTag;
use fieldseal_instrument::domain::message::{check_plain_text, parse_message};
use fieldseal_kernel::Value;

use crate::args::Args;
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::support::{Res, load_doc, run_command};

/// Runs `localisation <verb>`; `None` if the verb is not one of these.
pub fn run_localisation(verb: &str, raw: &[String]) -> Option<u8> {
    match verb {
        "validate" => Some(run_command("localisation validate", raw, &["--reference"], &[], validate_catalogue)),
        _ => None,
    }
}

/// A JSON Pointer segment, escaped (`~` as `~0`, `/` as `~1`).
fn escape(seg: &str) -> String {
    seg.replace('~', "~0").replace('/', "~1")
}

// ---- runtime UI catalogues --------------------------------------------------------------------

pub(crate) struct Catalogue {
    language: String,
    version: String,
    messages: BTreeMap<String, String>,
}

/// One schema problem in a catalogue: requirement ID, JSON pointer, reason.
pub(crate) type CatalogueIssue = (&'static str, String, String);

/// Reads a `Localisation` catalogue strictly (PLAT-053), from a file.
fn catalogue(path: &str, out: &mut Outcome) -> Res<Option<Catalogue>> {
    let Some(doc) = load_doc(path, out)? else { return Ok(None) };
    match read_catalogue(&doc) {
        Ok(c) => Ok(Some(c)),
        Err(issues) => {
            for (id, at, why) in &issues {
                out.raw_finding(id, "error", path, at, why);
            }
            Ok(None)
        }
    }
}

/// Reads a `Localisation` catalogue strictly (PLAT-053): the resource envelope with exactly
/// `apiVersion`, `kind`, `metadata` and `spec`; `spec` with exactly `language` (a language
/// tag), `referenceVersion` and `messages` (message ID to MessageFormat 2 text). Returns every
/// issue found.
pub(crate) fn read_catalogue(doc: &Value) -> Result<Catalogue, Vec<CatalogueIssue>> {
    let mut issues: Vec<CatalogueIssue> = Vec::new();
    let mut bad = |at: &str, why: &str| issues.push(("PLAT-053", at.to_owned(), why.to_owned()));
    let Some(top) = doc.as_map() else {
        return Err(vec![("PLAT-053", String::new(), "a catalogue is a map".to_owned())]);
    };
    for k in top.keys().filter(|k| !["apiVersion", "kind", "metadata", "spec"].contains(&k.as_str())) {
        bad(&format!("/{}", escape(k)), "unknown field; expected apiVersion, kind, metadata, spec");
    }
    if top.get("apiVersion").and_then(Value::as_text) != Some("fieldseal.dev/v1alpha1") {
        bad("/apiVersion", "must be `fieldseal.dev/v1alpha1`");
    }
    if top.get("kind").and_then(Value::as_text) != Some("Localisation") {
        bad("/kind", "must be `Localisation`");
    }
    match top.get("metadata").and_then(Value::as_map) {
        Some(m) => {
            for k in m.keys().filter(|k| !["name", "version"].contains(&k.as_str())) {
                bad(&format!("/metadata/{}", escape(k)), "unknown field; expected name, version");
            }
            for k in ["name", "version"] {
                if m.get(k).and_then(Value::as_text).is_none_or(str::is_empty) {
                    bad(&format!("/metadata/{k}"), "required text");
                }
            }
        }
        None => bad("/metadata", "required map with name and version"),
    }
    let Some(spec) = top.get("spec").and_then(Value::as_map) else {
        bad("/spec", "a catalogue needs `spec` with `language`, `referenceVersion` and `messages`");
        return Err(issues);
    };
    for k in spec.keys().filter(|k| !["language", "referenceVersion", "messages"].contains(&k.as_str())) {
        bad(&format!("/spec/{}", escape(k)), "unknown field; expected language, referenceVersion, messages");
    }
    let language = match spec.get("language").and_then(Value::as_text) {
        Some(l) if LanguageTag::parse(l).is_ok() => l.to_owned(),
        _ => {
            bad("/spec/language", "required: a BCP 47 language tag");
            String::new()
        }
    };
    let version = match spec.get("referenceVersion").and_then(Value::as_text) {
        Some(v) if !v.is_empty() => v.to_owned(),
        _ => {
            bad("/spec/referenceVersion", "required text");
            String::new()
        }
    };
    let mut msgs = BTreeMap::new();
    match spec.get("messages").and_then(Value::as_map) {
        Some(messages) => {
            for (id, m) in messages {
                match m.as_text() {
                    Some(t) => {
                        msgs.insert(id.clone(), t.to_owned());
                    }
                    None => issues.push(("PLAT-050", format!("/spec/messages/{}", escape(id)), "a message is MessageFormat 2 text".to_owned())),
                }
            }
        }
        None => issues.push(("PLAT-053", "/spec/messages".to_owned(), "a catalogue needs `spec.messages`".to_owned())),
    }
    if issues.is_empty() { Ok(Catalogue { language, version, messages: msgs }) } else { Err(issues) }
}

fn validate_catalogue(args: &Args, out: &mut Outcome) -> Res {
    let file = args.file("localisation validate")?;
    let reference_path = args.required("localisation validate", "--reference")?;
    let Some(cat) = catalogue(file, out)? else { return Ok(()) };
    let Some(reference) = catalogue(reference_path, out)? else { return Ok(()) };
    if cat.version != reference.version {
        out.raw_finding("PLAT-053", "error", file, "/spec/referenceVersion", &format!("`{}` is not the runtime's reference version `{}`", cat.version, reference.version));
    }
    let vars = |s: &str| parse_message(s).map(|m| m.variables);
    for (id, ref_text) in &reference.messages {
        let at = format!("/spec/messages/{}", escape(id));
        let Some(text) = cat.messages.get(id) else {
            out.raw_finding("PLAT-053", "error", file, &at, "the message is missing from the catalogue");
            continue;
        };
        if let Err(e) = check_plain_text(text) {
            out.raw_finding("PLAT-050", "error", file, &at, &e.to_string());
            continue;
        }
        match (vars(text), vars(ref_text)) {
            (Ok(a), Ok(b)) if a != b => out.raw_finding("PLAT-053", "error", file, &at, &format!("variables {a:?} differ from the reference's {b:?}")),
            (Err(e), _) => out.raw_finding("PLAT-050", "error", file, &at, &e.to_string()),
            _ => {}
        }
    }
    for id in cat.messages.keys().filter(|id| !reference.messages.contains_key(*id)) {
        out.raw_finding("PLAT-053", "error", file, &format!("/spec/messages/{}", escape(id)), "the reference catalogue has no such message");
    }
    if out.exit == exit::OK {
        out.lines.push(msg("catalogue-valid", &[("file", file), ("lang", &cat.language), ("count", &cat.messages.len().to_string())]));
    }
    out.set("language", Value::Text(cat.language));
    out.set("messages", Value::Int(cat.messages.len() as i128));
    Ok(())
}
