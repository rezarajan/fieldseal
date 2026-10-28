//! `fieldseal instrument i18n extract|merge` and `fieldseal localisation validate` (CLI §5
//! `instrument`; INS-082–INS-086, PLAT-050, PLAT-053).
//!
//! * `extract` writes each target language's texts to an XLIFF 2.1 file for translators, one
//!   `<unit>` per localised text, named by its JSON Pointer in the authoring document.
//! * `merge` reads reviewed XLIFF files back into the authoring form and checks completeness
//!   (INS-082), declarations (INS-083), message variables and syntax (INS-084) and plain text
//!   (INS-085). It writes the updated form as JSON, because the authoring adapter decodes
//!   YAML but does not emit it.
//! * `localisation validate` checks a runtime UI catalogue against the runtime's reference
//!   catalogue: every message ID present, none unknown, the same variables, valid MessageFormat 2
//!   (PLAT-050, PLAT-053). A catalogue is `kind: Localisation` with `spec.language`,
//!   `spec.referenceVersion` and `spec.messages` (message ID to message).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fieldseal_instrument::domain::LanguageTag;
use fieldseal_instrument::domain::message::{check_plain_text, parse_message};
use fieldseal_kernel::Value;

use crate::args::Args;
use crate::json;
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::support::{Res, load_doc, read, run_command, text, usage, write};

/// Runs `instrument i18n <verb>`; `None` if the verb is not one of these.
pub fn run_i18n(verb: &str, raw: &[String]) -> Option<u8> {
    Some(match verb {
        "extract" => run_command("instrument i18n extract", raw, &["--lang", "--out", "-o"], &[], extract),
        "merge" => run_command("instrument i18n merge", raw, &["--out", "-o"], &[], merge),
        _ => return None,
    })
}

/// Runs `localisation <verb>`; `None` if the verb is not one of these.
pub fn run_localisation(verb: &str, raw: &[String]) -> Option<u8> {
    match verb {
        "validate" => Some(run_command("localisation validate", raw, &["--reference"], &[], validate_catalogue)),
        _ => None,
    }
}

// ---- finding localised texts in an authoring document -----------------------------------------

/// A JSON Pointer segment, escaped (`~` as `~0`, `/` as `~1`).
fn escape(seg: &str) -> String {
    seg.replace('~', "~0").replace('/', "~1")
}

fn unescape(seg: &str) -> String {
    seg.replace("~1", "/").replace("~0", "~")
}

/// Every localised text: a map holding the default language, whose keys are all among
/// `languages` and whose values are all text. `media` maps (language to media ID) are not texts.
fn localised_texts(v: &Value, languages: &BTreeSet<String>, default: &str, path: &str, found: &mut Vec<(String, BTreeMap<String, String>)>) {
    match v {
        Value::Map(m) => {
            let texts: Option<BTreeMap<String, String>> = m.iter().map(|(k, x)| x.as_text().map(|t| (k.clone(), t.to_owned()))).collect::<Option<_>>();
            if let Some(t) = texts.filter(|t| t.contains_key(default) && t.keys().all(|k| languages.contains(k))) {
                found.push((path.to_owned(), t));
                return;
            }
            for (k, x) in m {
                if k != "media" && k != "translations" {
                    localised_texts(x, languages, default, &format!("{path}/{}", escape(k)), found);
                }
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                localised_texts(x, languages, default, &format!("{path}/{i}"), found);
            }
        }
        _ => {}
    }
}

fn get_mut<'a>(v: &'a mut Value, pointer: &str) -> Option<&'a mut Value> {
    let mut cur = v;
    for seg in pointer.split('/').skip(1) {
        let seg = unescape(seg);
        cur = match cur {
            Value::Map(m) => m.get_mut(&seg)?,
            Value::Array(a) => a.get_mut(usize::try_from(crate::support::parse_uint(&seg)?).ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

struct Doc {
    value: Value,
    default: String,
    declared: Vec<String>,
}

fn load_instrument_doc(path: &str, out: &mut Outcome) -> Res<Option<Doc>> {
    let Some(value) = load_doc(path, out)? else { return Ok(None) };
    let spec = value.as_map().and_then(|m| m.get("spec")).and_then(Value::as_map);
    let Some(spec) = spec else {
        return Err(usage("not-an-artefact", &[("file", path)]));
    };
    let default = text(spec, "defaultLanguage").map(str::to_owned);
    let declared: Vec<String> = spec.get("languages").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_text().map(str::to_owned)).collect()).unwrap_or_default();
    match default {
        Some(default) if !declared.is_empty() => Ok(Some(Doc { value, default, declared })),
        _ => Err(usage("no-languages", &[("file", path)])),
    }
}

// ---- XLIFF 2.1 --------------------------------------------------------------------------------

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

fn xliff(original: &str, source: &str, target: &str, texts: &[(String, BTreeMap<String, String>)]) -> String {
    let mut x = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    x.push_str(&format!(
        "<xliff xmlns=\"urn:oasis:names:tc:xliff:document:2.1\" version=\"2.1\" srcLang=\"{}\" trgLang=\"{}\">\n  <file id=\"f1\" original=\"{}\">\n",
        xml_escape(source),
        xml_escape(target),
        xml_escape(original)
    ));
    for (i, (path, t)) in texts.iter().enumerate() {
        let src = &t[source];
        let vars = parse_message(src).map(|m| m.variables).unwrap_or_default();
        x.push_str(&format!("    <unit id=\"u{}\" name=\"{}\">\n", i + 1, xml_escape(path)));
        if !vars.is_empty() {
            x.push_str(&format!("      <notes><note category=\"variables\">{}</note></notes>\n", xml_escape(&vars.into_iter().collect::<Vec<_>>().join(" "))));
        }
        match t.get(target) {
            Some(existing) => x.push_str(&format!(
                "      <segment state=\"translated\"><source>{}</source><target>{}</target></segment>\n",
                xml_escape(src),
                xml_escape(existing)
            )),
            None => x.push_str(&format!("      <segment state=\"initial\"><source>{}</source></segment>\n", xml_escape(src))),
        }
        x.push_str("    </unit>\n");
    }
    x.push_str("  </file>\n</xliff>\n");
    x
}

/// The text between `<tag ...>` and `</tag>` at or after `from`, and where the element ends.
fn element<'a>(s: &'a str, tag: &str, from: usize) -> Option<(&'a str, &'a str, usize)> {
    let open = s[from..].find(&format!("<{tag}")).map(|i| i + from)?;
    let head_end = s[open..].find('>').map(|i| i + open)?;
    let close = s[head_end..].find(&format!("</{tag}>")).map(|i| i + head_end)?;
    Some((&s[open + tag.len() + 1..head_end], &s[head_end + 1..close], close + tag.len() + 3))
}

fn attr(head: &str, name: &str) -> Option<String> {
    let key = format!("{name}=\"");
    let start = head.find(&key)? + key.len();
    let end = head[start..].find('"')? + start;
    Some(xml_unescape(&head[start..end]))
}

struct Translations {
    target: String,
    units: Vec<(String, String)>,
}

/// Reads an XLIFF 2.1 file strictly (INS-082, INS-086): the root must be `<xliff version="2.1">`
/// with `srcLang` equal to the instrument's default language and a valid `trgLang` that differs
/// from it; every `<unit>` must carry a `name`, a `<source>` that equals the instrument's current
/// default text (a stale source means the translator worked from other text), and at most one
/// `<target>`; unit names are unique; the file ends with `</xliff>`.
fn parse_xliff(s: &str, default: &str, current: &BTreeMap<String, String>) -> Result<Translations, String> {
    let head_start = s.find("<xliff").ok_or("not an XLIFF 2.1 file: no <xliff> element")?;
    let head = &s[head_start..s[head_start..].find('>').ok_or("unterminated <xliff> element")? + head_start];
    if attr(head, "version").as_deref() != Some("2.1") {
        return Err("not XLIFF 2.1: `version` must be \"2.1\"".into());
    }
    if !s.trim_end().ends_with("</xliff>") {
        return Err("the file does not end with </xliff>".into());
    }
    match attr(head, "srcLang") {
        Some(src) if src == default => {}
        Some(src) => return Err(format!("srcLang `{src}` is not the instrument's default language `{default}`")),
        None => return Err("the <xliff> element has no `srcLang`".into()),
    }
    let target = attr(head, "trgLang").ok_or("the <xliff> element has no `trgLang`")?;
    LanguageTag::parse(&target).map_err(|e| format!("trgLang `{target}`: {e}"))?;
    if target == default {
        return Err("trgLang is the default language; there is nothing to translate".into());
    }
    let mut units: Vec<(String, String)> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut at = 0;
    while let Some((uhead, body, next)) = element(s, "unit", at) {
        at = next;
        let name = attr(uhead, "name").ok_or("a <unit> has no `name`")?;
        if !seen.insert(name.clone()) {
            return Err(format!("unit `{name}` appears twice"));
        }
        let source = element(body, "source", 0).map(|(_, t, _)| xml_unescape(t)).ok_or_else(|| format!("unit `{name}` has no <source>"))?;
        if let Some(text) = current.get(&name)
            && *text != source
        {
            return Err(format!("unit `{name}`: the <source> is not the instrument's current `{default}` text"));
        }
        if let Some((_, _, after)) = element(body, "target", 0)
            && element(body, "target", after).is_some()
        {
            return Err(format!("unit `{name}` has more than one <target>"));
        }
        if let Some((_, t, _)) = element(body, "target", 0) {
            units.push((name, xml_unescape(t)));
        }
    }
    Ok(Translations { target, units })
}

fn extract(args: &Args, out: &mut Outcome) -> Res {
    let file = args.file("instrument i18n extract")?;
    let Some(doc) = load_instrument_doc(file, out)? else { return Ok(()) };
    let mut targets: Vec<String> = args.values("--lang").to_vec();
    if targets.is_empty() {
        targets = doc.declared.iter().filter(|l| **l != doc.default).cloned().collect();
    }
    if targets.is_empty() {
        return Err(usage("no-target-languages", &[("file", file)]));
    }
    let mut languages: BTreeSet<String> = doc.declared.iter().cloned().collect();
    languages.extend(targets.iter().cloned());
    let mut texts = Vec::new();
    localised_texts(&doc.value, &languages, &doc.default, "", &mut texts);
    let dir = args.value("--out").or_else(|| args.value("-o")).map_or_else(|| Path::new(file).parent().map(Path::to_path_buf).unwrap_or_default(), PathBuf::from);
    let stem = Path::new(file).file_stem().and_then(|s| s.to_str()).unwrap_or("instrument");
    let original = Path::new(file).file_name().and_then(|s| s.to_str()).unwrap_or(file);
    let mut written = Vec::new();
    for target in &targets {
        if *target == doc.default {
            continue;
        }
        let path = dir.join(format!("{stem}.{target}.xlf"));
        if !write(&path, xliff(original, &doc.default, target, &texts).as_bytes(), false, out) {
            return Ok(());
        }
        out.lines.push(msg("xliff-written", &[("file", &path.to_string_lossy()), ("units", &texts.len().to_string()), ("lang", target)]));
        written.push(Value::Text(path.to_string_lossy().into_owned()));
    }
    out.set("files", Value::Array(written));
    out.set("units", Value::Int(texts.len() as i128));
    Ok(())
}

fn merge(args: &Args, out: &mut Outcome) -> Res {
    let [file, xlfs @ ..] = args.positionals.as_slice() else {
        return Err(usage("missing-file", &[("command", "instrument i18n merge")]));
    };
    if xlfs.is_empty() {
        return Err(usage("merge-needs-xliff", &[]));
    }
    let Some(mut doc) = load_instrument_doc(file, out)? else { return Ok(()) };
    let mut languages: BTreeSet<String> = doc.declared.iter().cloned().collect();
    let mut incoming: Vec<(String, Translations)> = Vec::new();
    let current: BTreeMap<String, String> = {
        let declared: BTreeSet<String> = doc.declared.iter().cloned().collect();
        let mut base = Vec::new();
        localised_texts(&doc.value, &declared, &doc.default, "", &mut base);
        base.into_iter().filter_map(|(p, t)| t.get(&doc.default).map(|d| (p, d.clone()))).collect()
    };
    for x in xlfs {
        let Some(bytes) = read(x, out) else { return Ok(()) };
        let Ok(content) = String::from_utf8(bytes) else {
            out.raw_finding("INS-082", "error", x, "", "the XLIFF file is not valid UTF-8");
            continue;
        };
        match parse_xliff(&content, &doc.default, &current) {
            Ok(t) => {
                languages.insert(t.target.clone());
                incoming.push((x.clone(), t));
            }
            Err(why) => out.raw_finding("INS-082", "error", x, "", &why),
        }
    }
    if out.exit != exit::OK {
        return Ok(());
    }
    let mut known = Vec::new();
    localised_texts(&doc.value, &languages, &doc.default, "", &mut known);
    let known_paths: BTreeSet<String> = known.iter().map(|(p, _)| p.clone()).collect();
    // Texts that the new languages are not yet in don't match `languages` containing them, so
    // find them against the declared set and let merging add the new language.
    let mut base = Vec::new();
    let declared: BTreeSet<String> = doc.declared.iter().cloned().collect();
    localised_texts(&doc.value, &declared, &doc.default, "", &mut base);
    let base_paths: BTreeSet<String> = base.iter().map(|(p, _)| p.clone()).collect();
    let mut merged = 0usize;
    for (xfile, t) in &incoming {
        for (name, target) in &t.units {
            if !base_paths.contains(name) && !known_paths.contains(name) {
                out.raw_finding("INS-082", "error", xfile, name, "this unit names no localised text in the instrument");
                continue;
            }
            if let Some(Value::Map(m)) = get_mut(&mut doc.value, name) {
                m.insert(t.target.clone(), Value::Text(target.clone()));
                merged += 1;
            }
        }
    }
    // Declare the new languages in `spec.languages`; their `spec.translations` entry (method,
    // reviewers) is the author's to write, and INS-083 is reported until they do.
    let new_languages: Vec<String> = incoming.iter().map(|(_, t)| t.target.clone()).filter(|l| !declared.contains(l)).collect::<BTreeSet<_>>().into_iter().collect();
    if let Some(Value::Map(spec)) = get_mut(&mut doc.value, "/spec") {
        if let Some(Value::Array(l)) = spec.get_mut("languages") {
            for n in &new_languages {
                l.push(Value::Text(n.clone()));
            }
        }
        for n in &new_languages {
            let has = spec.get("translations").and_then(Value::as_map).is_some_and(|t| t.contains_key(n));
            if !has {
                out.raw_finding("INS-083", "error", file, "/spec/translations", &format!("declare `spec.translations.{n}` with a method and reviewers"));
            }
        }
    }
    // Completeness and message variables, over every text and every declared language.
    let all: BTreeSet<String> = languages.clone();
    let mut texts = Vec::new();
    localised_texts(&doc.value, &all, &doc.default, "", &mut texts);
    for (path, t) in &texts {
        for lang in &all {
            if !t.contains_key(lang) {
                out.raw_finding("INS-082", "error", file, path, &format!("no text in `{lang}`"));
            }
        }
        let mut vars: BTreeMap<&String, BTreeSet<String>> = BTreeMap::new();
        for (lang, s) in t {
            if let Err(e) = check_plain_text(s) {
                out.raw_finding("INS-085", "error", file, &format!("{path}/{}", escape(lang)), &e.to_string());
            }
            match parse_message(s) {
                Ok(info) => {
                    vars.insert(lang, info.variables);
                }
                Err(e) => out.raw_finding("INS-084", "error", file, &format!("{path}/{}", escape(lang)), &e.to_string()),
            }
        }
        if let Some(first) = vars.values().next()
            && vars.values().any(|v| v != first)
        {
            out.raw_finding("INS-084", "error", file, path, "the languages of this text use different message variables");
        }
    }
    out.set("merged", Value::Int(merged as i128));
    if out.exit != exit::OK {
        out.lines.push(msg("merge-incomplete", &[("file", file)]));
        return Ok(());
    }
    let path = args.value("--out").or_else(|| args.value("-o")).map_or_else(|| Path::new(file).with_extension("merged.json"), PathBuf::from);
    if write(&path, json::pretty(&doc.value).as_bytes(), false, out) {
        out.lines.push(msg("merged", &[("count", &merged.to_string()), ("file", &path.to_string_lossy())]));
        out.set("file", Value::Text(path.to_string_lossy().into_owned()));
    }
    Ok(())
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
