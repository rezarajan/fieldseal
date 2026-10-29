//! The compact authoring dialect (ADR 0040): surveys, layouts and rosters written as typed keys,
//! expanded deterministically into the canonical documents (`kind: Instrument`, `Layout`,
//! `Roster`) that every reader validates. Nothing is parsed out of free text: every setting is a
//! key with a closed set of names and an exact type, declared once in `fieldseal_kernel::schema`.
//! Expansion first checks the document against that schema, so an unknown, missing or ill-typed
//! key is a finding naming its JSON Pointer (WIRE-211); the code below reads keys through the
//! schema's accessors and keeps only the rules the schema cannot say (a name that resolves to
//! nothing, the number of operands). Ordered content (sections, questions, categories) is a YAML
//! sequence of single-key maps, because a map's order is not kept (WIRE-001).
//!
//! The source language is written inline; other languages come from gettext catalogues
//! (`i18n/<lang>.po`), merged by [`expand_with_entries`] (`instrument/<path>` and
//! `layout/<window>/<id>`, applied only while the entry's `msgid` is the current English text).

use std::cell::RefCell;
use std::collections::BTreeMap;

use fieldseal_kernel::schema::{self, DocKind, Reader, SchemaError, SchemaErrorKind, ShapeId};
use fieldseal_kernel::value::{Decimal, Value};

use crate::error::{LocatedFinding, Position};
use crate::po::EntryCatalogues;
use crate::spans::Spans;
use crate::{AuthoringError, ErrorKind};

type Map = BTreeMap<String, Value>;
type Res<T> = Result<T, AuthoringError>;

/// Whether `doc` is a compact document this module expands (a top-level `survey`, `layout` or
/// `roster` key).
#[must_use]
pub fn is_compact(doc: &Value) -> bool {
    DocKind::detect(doc).is_some()
}

/// Expands a compact document with no translations; any other document is returned unchanged.
///
/// # Errors
///
/// An [`AuthoringError`] of kind [`ErrorKind::Compact`] naming the offending path.
pub fn expand(doc: Value) -> Res<Value> {
    expand_with_entries(doc, &EntryCatalogues::new())
}

/// Expands a compact document, merging the catalogue entries of a survey folder. The document is
/// checked against its schema first. An entry applies only while its `msgid` is the current English
/// text; a stale or empty entry is treated as missing. Contexts are `instrument/<path>` for a
/// survey and `layout/<window>/<id>` for a layout step, card or tab that has an `id:`. A language
/// declared under `translations:` that has no catalogue is not an error here: the resolver reports
/// it. A `Value` has no positions, so the errors have line 0, column 0; `decode` and `decode_path`
/// give them the position in the file.
///
/// # Errors
///
/// An [`AuthoringError`] of kind [`ErrorKind::Compact`] naming the offending path, with the
/// findings of a schema failure.
pub fn expand_with_entries(doc: Value, catalogues: &EntryCatalogues) -> Res<Value> {
    expand_seen(doc, &Texts::entries(catalogues), None, None).map(|(v, _)| v)
}

/// [`expand_with_entries`], with the positions of `doc` in its file when they are known.
pub(crate) fn expand_in(doc: Value, catalogues: &EntryCatalogues, spans: Option<&Spans>, file: Option<&str>) -> Res<Value> {
    expand_seen(doc, &Texts::entries(catalogues), spans, file).map(|(v, _)| v)
}

/// One translatable text the expander met: its catalogue key, its English text and, when the
/// expander knew it, the JSON Pointer of the text in the source document.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub key: String,
    pub text: String,
    pub pointer: Option<String>,
}

/// The catalogues the expander reads and the texts it asked for.
pub(crate) struct Texts<'c> {
    entries: &'c EntryCatalogues,
    seen: RefCell<Vec<Seen>>,
}

impl<'c> Texts<'c> {
    pub(crate) fn entries(c: &'c EntryCatalogues) -> Self {
        Self { entries: c, seen: RefCell::new(Vec::new()) }
    }

    /// The languages the document is translated into: those whose catalogue translates something.
    /// A catalogue with every `msgstr` empty (the stub `new survey --lang` writes) is a to-do list,
    /// not a language yet, so it adds nothing to the document; the report lists what it lacks.
    fn languages(&self) -> Vec<&'c String> {
        self.entries.iter().filter(|(_, c)| c.values().any(|e| !e.msgstr.is_empty())).map(|(l, _)| l).collect()
    }

    fn has_language(&self, lang: &str) -> bool {
        self.languages().iter().any(|l| l.as_str() == lang)
    }

    /// The translation of `text` in language `lang` under `key`, if there is one to apply.
    fn translation(&self, lang: &str, key: &str, text: &str) -> Option<&'c str> {
        self.entries.get(lang)?.get(key).filter(|e| !e.msgstr.is_empty() && e.msgid == text).map(|e| e.msgstr.as_str())
    }

    /// `{ <source>: text, <lang>: translation, … }`, noting that `key` was asked for.
    fn value(&self, source: &str, key: &str, text: &str, pointer: Option<String>) -> Value {
        self.seen.borrow_mut().push(Seen { key: key.to_owned(), text: text.to_owned(), pointer });
        let mut m = Map::new();
        m.insert(source.to_owned(), t(text));
        for lang in self.languages() {
            if let Some(s) = self.translation(lang, key, text) {
                m.insert(lang.clone(), t(s));
            }
        }
        Value::Map(m)
    }
}

/// [`expand_in`] over either catalogue form; also returns the texts the expander asked for.
pub(crate) fn expand_seen(doc: Value, texts: &Texts<'_>, spans: Option<&Spans>, file: Option<&str>) -> Res<(Value, Vec<Seen>)> {
    let Some(kind) = DocKind::detect(&doc) else {
        return Ok((doc, Vec::new()));
    };
    let errors = schema::check(&doc, kind);
    if !errors.is_empty() {
        return Err(failure(errors, spans, file));
    }
    let m = doc.as_map().expect("a compact document is a map");
    let expanded = match kind {
        DocKind::Survey => Survey::new(texts).expand(m),
        DocKind::Layout => layout(m, texts),
        DocKind::Roster => roster(m),
    };
    expanded.map(|v| (v, texts.seen.take())).map_err(|e| locate(e, spans))
}

/// A schema failure as one error that holds every finding, in the order they appear in the file.
fn failure(errors: Vec<SchemaError>, spans: Option<&Spans>, file: Option<&str>) -> AuthoringError {
    let mut findings: Vec<LocatedFinding> = errors
        .into_iter()
        .map(|e| {
            let position = spans.map_or(Position { line: 0, column: 0 }, |s| match e.kind {
                SchemaErrorKind::UnknownField => s.key(&e.pointer).unwrap_or_else(|| s.nearest(&e.pointer)),
                SchemaErrorKind::MissingField => s.nearest(&e.pointer),
                _ => s.value(&e.pointer).unwrap_or_else(|| s.nearest(&e.pointer)),
            });
            LocatedFinding { file: file.map(str::to_owned), pointer: e.pointer, position, kind: e.kind, message: e.message }
        })
        .collect();
    findings.sort_by_key(|f| f.position);
    let first = &findings[0];
    AuthoringError {
        kind: ErrorKind::Compact,
        line: first.position.line,
        column: first.position.column,
        message: format!("{}: {}", first.pointer, first.message),
        position: (first.position.line > 0).then_some(first.position),
        findings,
    }
}

/// Gives a rule error ("`/lists/x/items/2`: …") the position of its path.
fn locate(mut e: AuthoringError, spans: Option<&Spans>) -> AuthoringError {
    if let (Some(spans), ErrorKind::Compact, 0) = (spans, e.kind, e.line)
        && let Some((path, _)) = e.message.split_once(": ")
        && path.starts_with('/')
    {
        let at = spans.nearest(path);
        (e.line, e.column, e.position) = (at.line, at.column, Some(at));
    }
    e
}

// ---- small helpers -------------------------------------------------------------------------

fn err(path: &str, message: impl Into<String>) -> AuthoringError {
    AuthoringError::new(ErrorKind::Compact, 0, 0, format!("{path}: {}", message.into()))
}

fn t(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn map<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    Value::Map(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

const SURVEY: ShapeId = ShapeId("survey");
const QUESTION: ShapeId = ShapeId("survey.question");

/// The reader of a map that the schema has accepted as `shape`.
fn read<'a>(v: &'a Value, shape: &'static str) -> Reader<'a> {
    Reader::new(v.as_map().expect("the schema accepted a map here"), ShapeId(shape))
}

fn owned(s: Option<&str>) -> Option<String> {
    s.map(str::to_owned)
}

/// A key the schema requires, so present once the document is accepted.
fn required<T>(v: Option<T>) -> T {
    v.expect("the schema requires this key")
}

fn texts(v: Option<&[Value]>) -> Option<Vec<String>> {
    v.map(|a| a.iter().filter_map(|x| x.as_text().map(str::to_owned)).collect())
}

/// The one key of a single-key map in an ordered sequence (`- id: {…}`).
fn entry<'a>(v: &'a Value, path: &str) -> Res<(&'a str, &'a Value)> {
    let m = v.as_map().ok_or_else(|| err(path, "expected `- <id>: <value>`"))?;
    if m.len() != 1 {
        return Err(err(path, "expected exactly one key, `- <id>: <value>`"));
    }
    let (k, v) = m.iter().next().expect("one key");
    Ok((k.as_str(), v))
}

fn seq<'a>(v: &'a Value, path: &str) -> Res<&'a Vec<Value>> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(err(path, "expected a list")),
    }
}

/// The code a label generates: lower case, every run of other characters one `_` (ADR 0040).
#[must_use]
pub fn slug(label: &str) -> String {
    let mut out = String::new();
    let mut gap = false;
    for c in label.chars() {
        if c.is_ascii_alphanumeric() {
            if gap && !out.is_empty() {
                out.push('_');
            }
            gap = false;
            out.push(c.to_ascii_lowercase());
        } else {
            gap = true;
        }
    }
    out
}

fn dec(mantissa: i128, exponent: i32) -> Value {
    Value::Decimal(Decimal { mantissa, exponent })
}

/// `num / den` rounded half-even to three decimals, trailing zeros dropped (a scale's per-day value).
fn per_day(num: i128, den: i128) -> Value {
    let scaled = num * 1000;
    let (q, r) = (scaled / den, scaled % den);
    let q = if 2 * r > den || (2 * r == den && q % 2 == 1) { q + 1 } else { q };
    if q % 1000 == 0 {
        return Value::Int(q / 1000);
    }
    let (mut m, mut e) = (q, -3);
    while m % 10 == 0 {
        m /= 10;
        e += 1;
    }
    dec(m, e)
}

/// The UCUM unit and the label a compact unit name stands for.
fn unit(name: &str) -> (String, Option<String>) {
    match name {
        "oz" => ("[oz_av]".into(), Some("oz".into())),
        "lb" => ("[lb_av]".into(), Some("lbs".into())),
        "each" | "piece" => ("{each}".into(), Some("each".into())),
        "gal" => ("[gal_us]".into(), None),
        "year" => ("a".into(), None),
        other => (other.into(), None),
    }
}

// ---- surveys ---------------------------------------------------------------------------------

struct Survey<'c> {
    texts: &'c Texts<'c>,
    source: String,
    languages: Vec<String>,
    lists: BTreeMap<String, Value>,
    /// Every question's absolute path by its id, for conditions.
    questions: BTreeMap<String, Vec<String>>,
    other_max: Option<Value>,
    disabled_display: Option<String>,
}

/// A text in the source language plus every catalogue's translation of `ctx`.
impl Survey<'_> {
    fn new<'c>(texts: &'c Texts<'c>) -> Survey<'c> {
        Survey { texts, source: "en".into(), languages: vec![], lists: BTreeMap::new(), questions: BTreeMap::new(), other_max: None, disabled_display: None }
    }

    fn lt(&self, ctx: &str, source: &str) -> Value {
        self.texts.value(&self.source, &format!("instrument/{ctx}"), source, None)
    }

    fn expand(mut self, top: &Map) -> Res<Value> {
        let o = Reader::new(top, SURVEY);
        let id = read(required(o.raw("survey")), "survey.id");
        let (name, version) = (required(id.text("name")), required(id.text("version")));
        if let Some(l) = o.text("language") {
            self.source = l.to_owned();
        }
        self.languages = std::iter::once(self.source.clone()).chain(self.texts.languages().into_iter().filter(|l| **l != self.source).cloned()).collect();
        let mut spec = Map::new();
        spec.insert("schema".into(), t("^1.0"));
        for key in ["title", "description", "purpose"] {
            if let Some(s) = o.text(key) {
                spec.insert(key.into(), self.lt(key, s));
            }
        }
        for key in ["administration", "publisher"] {
            if let Some(s) = o.text(key) {
                spec.insert(key.into(), t(s));
            }
        }
        if let Some(v) = o.raw("copyright") {
            spec.insert("copyright".into(), v.clone());
        }
        if let Some(v) = o.raw("derived-from") {
            spec.insert("derivedFrom".into(), v.clone());
        }
        spec.insert("languages".into(), Value::Array(self.languages.iter().map(|l| t(l)).collect()));
        spec.insert("defaultLanguage".into(), t(&self.source));
        if let Some(v) = o.map("translations") {
            let mut tr = Map::new();
            for (lang, meta) in v {
                // The translation report has a `no catalogue` finding for a language without one.
                if !self.texts.has_language(lang) {
                    continue;
                }
                let mo = read(meta, "survey.translation");
                let mut out = Map::new();
                if let Some(s) = mo.text("method") {
                    out.insert("method".into(), t(s));
                }
                if let Some(n) = mo.raw("reviewed-by") {
                    out.insert("reviewedBy".into(), n.clone());
                }
                if let Some(s) = mo.text("notes") {
                    out.insert("notes".into(), t(s));
                }
                tr.insert(lang.clone(), Value::Map(out));
            }
            spec.insert("translations".into(), Value::Map(tr));
        }
        if let Some(nr) = texts(o.list("nonresponse")) {
            spec.insert("nonresponse".into(), Value::Array(nr.iter().map(|s| t(s)).collect()));
        }
        if let Some(d) = o.raw("defaults") {
            let d = read(d, "survey.defaults");
            if let Some(ot) = d.raw("other-text") {
                self.other_max = read(ot, "survey.other-text").raw("max-length").cloned();
            }
            self.disabled_display = owned(d.text("disabled-display"));
        }
        if let Some(c) = o.raw("consent") {
            spec.insert("consent".into(), self.consent(c)?);
        }
        if let Some(l) = o.map("lists") {
            for (k, v) in l {
                let list = self.list(k, v)?;
                self.lists.insert(k.clone(), list);
            }
        }
        if let Some(s) = o.map("scales") {
            for (k, v) in s {
                let sc = scale(v, &format!("/scales/{k}"), &|code, label| self.lt(&format!("lists.{k}.{code}"), label))?;
                self.lists.insert(k.clone(), sc);
            }
        }
        if let Some(tb) = o.map("tables") {
            let mut tables = Map::new();
            for (k, v) in tb {
                let rows = v.as_map().expect("the schema accepted a map here");
                let rows = rows.iter().map(|(key, value)| map([("key", t(key)), ("value", value.clone())])).collect();
                tables.insert(k.clone(), map([("rows", Value::Array(rows))]));
            }
            spec.insert("tables".into(), Value::Map(tables));
        }
        // Every question's path first, so a condition may name a later question.
        let body = required(o.raw("sections"));
        self.index(body, "", "/sections", &mut Vec::new())?;
        let elements = self.elements(body, "", "/sections", None)?;
        let mut rules = Vec::new();
        if let Some(r) = o.raw("checks") {
            for (i, c) in seq(r, "/checks")?.iter().enumerate() {
                rules.push(self.check(c, &format!("/checks/{i}"), "checks", None)?);
            }
        }
        if !rules.is_empty() {
            spec.insert("rules".into(), Value::Array(rules));
        }
        if let Some(fc) = o.raw("field-checks") {
            spec.insert("fieldChecks".into(), self.field_checks(fc)?);
        }
        if !self.lists.is_empty() {
            spec.insert("codeLists".into(), Value::Map(std::mem::take(&mut self.lists)));
        }
        spec.insert("elements".into(), Value::Array(elements));
        Ok(map([("apiVersion", t("fieldseal.dev/v1alpha1")), ("kind", t("Instrument")), ("metadata", map([("name", t(name)), ("version", t(version))])), ("spec", Value::Map(spec))]))
    }

    fn consent(&self, v: &Value) -> Res<Value> {
        let c = read(v, "survey.consent");
        let mut out = Map::new();
        out.insert("required".into(), Value::Bool(c.flag("required").unwrap_or(false)));
        if let Some(b) = c.list("bases") {
            let mut bases = Vec::new();
            for (i, item) in b.iter().enumerate() {
                let (code, label) = entry(item, &format!("/consent/bases/{i}"))?;
                let label = label.as_text().ok_or_else(|| err(&format!("/consent/bases/{i}"), "expected `- code: label`"))?;
                bases.push(map([("code", t(code)), ("label", self.lt(&format!("consent.bases.{code}"), label))]));
            }
            out.insert("bases".into(), Value::Array(bases));
        }
        if let Some(s) = c.raw("statement") {
            let so = read(s, "survey.consent-statement");
            let (version, text) = (required(so.raw("version")).clone(), required(so.text("text")));
            out.insert("statement".into(), map([("version", version), ("text", self.lt("consent.statement", text))]));
        }
        if let Some(e) = c.text("evidence") {
            out.insert("evidence".into(), t(e));
        }
        Ok(Value::Map(out))
    }

    /// A list: `[items]`, or `{ ordered?, other?, items }`. An item is a label (its code is the
    /// label's slug) or `{ label, code?, description?, icon?, concept?, exclusive? }`.
    fn list(&self, name: &str, v: &Value) -> Res<Value> {
        let (items, ordered, other) = match v {
            Value::Array(a) => (a.as_slice(), None, None),
            _ => {
                let o = read(v, "survey.list");
                let items = required(o.list("items"));
                let ordered = o.flag("ordered");
                let other = match o.raw("other") {
                    None => None,
                    Some(Value::Text(label)) => Some((label.clone(), self.other_max.clone())),
                    Some(ov) => {
                        let oo = read(ov, "survey.list-other");
                        let max = oo.raw("max-length").cloned().or_else(|| self.other_max.clone());
                        Some((required(oo.text("label")).to_owned(), max))
                    }
                };
                (items, ordered, other)
            }
        };
        let mut out = Map::new();
        // Every list states whether it is ordered (INS-131): unordered unless it says so.
        out.insert("ordered".into(), Value::Bool(ordered.unwrap_or(false)));
        let mut codes = Vec::new();
        for item in items {
            codes.push(match item {
                Value::Text(label) => {
                    let code = slug(label);
                    map([("code", t(&code)), ("label", self.lt(&format!("lists.{name}.{code}"), label))])
                }
                _ => {
                    let io = read(item, "survey.item");
                    let label = required(io.text("label"));
                    let code = io.text("code").map_or_else(|| slug(label), str::to_owned);
                    let mut c = Map::new();
                    c.insert("code".into(), t(&code));
                    c.insert("label".into(), self.lt(&format!("lists.{name}.{code}"), label));
                    if let Some(d) = io.text("description") {
                        c.insert("description".into(), self.lt(&format!("lists.{name}.{code}.description"), d));
                    }
                    if let Some(icon) = io.text("icon") {
                        c.insert("icon".into(), t(icon));
                    }
                    if let Some(con) = io.raw("concept") {
                        c.insert("concept".into(), con.clone());
                    }
                    if let Some(x) = io.flag("exclusive") {
                        c.insert("exclusive".into(), Value::Bool(x));
                    }
                    Value::Map(c)
                }
            });
        }
        if let Some((label, max)) = other {
            let mut o = map([("code", t("other")), ("label", self.lt(&format!("lists.{name}.other"), &label))]);
            if let (Some(max), Value::Map(m)) = (max, &mut o) {
                m.insert("maxLength".into(), max);
            }
            codes.push(map([("code", t("other")), ("label", self.lt(&format!("lists.{name}.other"), &label))]));
            out.insert("other".into(), o);
        }
        out.insert("codes".into(), Value::Array(codes));
        Ok(Value::Map(out))
    }

    /// Records every question's absolute path by id (for conditions).
    fn index(&mut self, v: &Value, prefix: &str, path: &str, stack: &mut Vec<String>) -> Res<()> {
        for (i, item) in seq(v, path)?.iter().enumerate() {
            let p = format!("{path}/{i}");
            let (id, body) = entry(item, &p)?;
            let full = if prefix.is_empty() { id.to_owned() } else { format!("{prefix}.{id}") };
            let m = body.as_map().ok_or_else(|| err(&p, "expected a map"))?;
            if m.contains_key("type") {
                self.questions.entry(id.to_owned()).or_default().push(full.clone());
            } else if let Some(e) = m.get("elements") {
                stack.push(id.into());
                self.index(e, &full, &format!("{p}/{id}/elements"), stack)?;
                stack.pop();
            }
            if let Some(cats) = m.get("categories") {
                // Food categories: each a repeat group whose questions are the block's `ask`.
                let co = read(cats, "survey.categories");
                let ask = co.raw("ask").cloned();
                for (b, block) in co.list("blocks").into_iter().flatten().enumerate() {
                    let bp = format!("{p}/{id}/categories/blocks/{b}");
                    let bm = block.as_map().ok_or_else(|| err(&bp, "expected a map"))?;
                    for (j, cat) in bm.get("categories").and_then(Value::as_array).into_iter().flatten().enumerate() {
                        let (cid, _) = entry(cat, &format!("{bp}/categories/{j}"))?;
                        let gpath = format!("{full}.{cid}");
                        if let Some(Value::Array(qs)) = &ask {
                            for q in qs {
                                if let Ok((qid, _)) = entry(q, &bp) {
                                    self.questions.entry(qid.to_owned()).or_default().push(format!("{gpath}.{qid}"));
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn elements(&mut self, v: &Value, prefix: &str, path: &str, repeat: Option<&[String]>) -> Res<Vec<Value>> {
        let mut out = Vec::new();
        for (i, item) in seq(v, path)?.iter().enumerate() {
            let p = format!("{path}/{i}");
            let (id, body) = entry(item, &p)?;
            let full = if prefix.is_empty() { id.to_owned() } else { format!("{prefix}.{id}") };
            let p = format!("{p}/{id}");
            let m = body.as_map().ok_or_else(|| err(&p, "expected a map"))?;
            if m.contains_key("type") {
                out.push(self.question(id, &full, body, &p, repeat)?);
            } else if m.contains_key("display") {
                let o = read(body, "survey.display");
                let text = required(o.text("display"));
                let mut d = map([("kind", t("display")), ("id", t(id)), ("text", self.lt(&full, text))]);
                if let (Some(role), Value::Map(dm)) = (o.text("role"), &mut d) {
                    dm.insert("role".into(), t(role));
                }
                out.push(d);
            } else {
                out.extend(self.group(id, &full, body, &p, repeat)?);
            }
        }
        Ok(out)
    }

    fn group(&mut self, id: &str, full: &str, body: &Value, p: &str, repeat: Option<&[String]>) -> Res<Vec<Value>> {
        let o = read(body, "survey.group");
        let label = required(o.text("group"));
        let mut g = Map::new();
        g.insert("kind".into(), t("group"));
        g.insert("id".into(), t(id));
        g.insert("label".into(), self.lt(full, label));
        if let Some(d) = o.text("description") {
            g.insert("description".into(), self.lt(&format!("{full}.description"), d));
        }
        if let Some(c) = o.raw("concept") {
            g.insert("concept".into(), c.clone());
        }
        if let Some(cond) = o.raw("if") {
            g.insert("when".into(), t(&self.condition(cond, &format!("{p}/if"), repeat)?));
        }
        if let Some(d) = owned(o.text("disabled-display")).or_else(|| g.contains_key("when").then(|| self.disabled_display.clone()).flatten()) {
            g.insert("disabledDisplay".into(), t(&d));
        }
        let mut elements = match o.raw("elements") {
            Some(e) => self.elements(e, full, &format!("{p}/elements"), repeat)?,
            None => vec![],
        };
        if let Some(cats) = o.raw("categories") {
            elements.extend(self.categories(full, cats, &format!("{p}/categories"))?);
        }
        let mut after = Vec::new();
        if let Some(r) = o.raw("checks") {
            let mut rules = Vec::new();
            for (i, c) in seq(r, &format!("{p}/checks"))?.iter().enumerate() {
                rules.push(self.check(c, &format!("{p}/checks/{i}"), full, repeat)?);
            }
            g.insert("rules".into(), Value::Array(rules));
        }
        if let Some(text) = o.text("end") {
            after.push(map([("kind", t("display")), ("id", t(&format!("{id}_end"))), ("role", t("end")), ("text", self.lt(&format!("{full}.end"), text))]));
        }
        g.insert("elements".into(), Value::Array(elements));
        let mut out = vec![Value::Map(g)];
        out.extend(after);
        Ok(out)
    }

    /// Food categories: each becomes a code list of its foods and a repeat group over it whose
    /// questions are the block's `ask` (with the block's overrides) and whose rules are `checks`.
    fn categories(&mut self, parent: &str, v: &Value, p: &str) -> Res<Vec<Value>> {
        let o = read(v, "survey.categories");
        let ask = required(o.list("ask")).to_vec();
        let checks = o.raw("checks").cloned();
        let mut out = Vec::new();
        for (b, block) in required(o.list("blocks")).iter().enumerate() {
            let bp = format!("{p}/blocks/{b}");
            let bo = read(block, "survey.block");
            let period = required(bo.text("period"));
            let overrides: Map = match bo.list("ask") {
                Some(a) => a.iter().map(|q| entry(q, &bp).map(|(k, v)| (k.to_owned(), v.clone()))).collect::<Res<_>>()?,
                None => Map::new(),
            };
            for (j, cat) in required(bo.list("categories")).iter().enumerate() {
                let cp = format!("{bp}/categories/{j}");
                let (cid, body) = entry(cat, &cp)?;
                let full = format!("{parent}.{cid}");
                let co = read(body, "survey.category");
                let label = required(co.text("label"));
                // A food may override the block's questions for itself (`ask:` on the food): the
                // canonical repeat overrides, keyed by the food's code.
                let mut item_overrides = Map::new();
                let mut foods = Vec::new();
                for (k, food) in required(co.list("foods")).iter().enumerate() {
                    let fp = format!("{cp}/{cid}/foods/{k}");
                    match food.as_map().and_then(|m| m.get("ask").map(|a| (m, a))) {
                        Some((m, a)) => {
                            let label = m.get("label").and_then(Value::as_text).ok_or_else(|| err(&fp, "a food with `ask` needs a label"))?;
                            let code = m.get("code").and_then(Value::as_text).map_or_else(|| slug(label), str::to_owned);
                            item_overrides.insert(code.clone(), self.item_override(a, &format!("{fp}/ask"), &format!("{parent}.{cid}.{code}"))?);
                            let mut rest = m.clone();
                            rest.remove("ask");
                            foods.push(Value::Map(rest));
                        }
                        None => foods.push(food.clone()),
                    }
                }
                let foods = Value::Array(foods);
                let other = co.text("other");
                let mut list = Map::new();
                list.insert("ordered".into(), Value::Bool(false));
                list.insert("items".into(), foods);
                if let Some(other) = other {
                    list.insert("other".into(), t(other));
                }
                let expanded = self.list(cid, &Value::Map(list))?;
                self.lists.insert(cid.to_owned(), expanded);
                let mut questions = Vec::new();
                for q in &ask {
                    let (qid, base) = entry(q, &bp)?;
                    let merged = match (base, overrides.get(qid)) {
                        (Value::Map(b), Some(Value::Map(o))) => { let mut m = b.clone(); for (k, v) in o { m.insert(k.clone(), v.clone()); } Value::Map(m) }
                        _ => base.clone(),
                    };
                    // The block's overrides are not in the schema's reach until they are merged.
                    if overrides.contains_key(qid)
                        && let Some(e) = schema::check_shape(&merged, QUESTION, "").into_iter().next()
                    {
                        return Err(err(&format!("{bp}/ask"), format!("{qid}{}: {}", e.pointer, e.message)));
                    }
                    questions.push(map([(qid, merged)]));
                }
                let siblings: Vec<String> = questions.iter().filter_map(|q| entry(q, "").ok().map(|(k, _)| k.to_owned())).collect();
                let mut g = Map::new();
                g.insert("kind".into(), t("group"));
                g.insert("id".into(), t(cid));
                g.insert("label".into(), self.lt(&full, label));
                g.insert("referencePeriod".into(), self.lt(&format!("{parent}.periods.{b}"), period));
                g.insert("repeat".into(), map([("over", t(cid))]));
                if !item_overrides.is_empty() {
                    g.insert("overrides".into(), Value::Map(item_overrides));
                }
                g.insert("elements".into(), Value::Array(self.elements(&Value::Array(questions), &full, &format!("{p}/ask"), Some(&siblings))?));
                if let Some(c) = &checks {
                    let mut rules = Vec::new();
                    for (i, c) in seq(c, &format!("{p}/checks"))?.iter().enumerate() {
                        rules.push(self.check(c, &format!("{p}/checks/{i}"), parent, Some(&siblings))?);
                    }
                    g.insert("rules".into(), Value::Array(rules));
                }
                out.push(Value::Map(g));
            }
        }
        Ok(out)
    }

    /// One food's overrides of the block's questions: `{ <question>: { unit?, unit-label?, min?, max?, step?, start? } }`,
    /// in the control's canonical terms.
    fn item_override(&self, v: &Value, p: &str, ctx: &str) -> Res<Value> {
        let mut out = Map::new();
        for (qid, settings) in v.as_map().ok_or_else(|| err(p, "expected { <question>: { settings } }"))? {
            let o = read(settings, "survey.override");
            let mut c = Map::new();
            if let Some(u) = o.text("unit") {
                let (ucum, label) = unit(u);
                c.insert("unit".into(), t(&ucum));
                if let Some(l) = owned(o.text("unit-label")).or(label) {
                    c.insert("unitLabel".into(), self.lt(&format!("{ctx}.{qid}.unit"), &l));
                }
            }
            for k in ["min", "max", "step", "start"] {
                if let Some(n) = o.raw(k) {
                    c.insert(k.into(), n.clone());
                }
            }
            out.insert(qid.clone(), Value::Map(c));
        }
        Ok(Value::Map(out))
    }

    fn question(&mut self, id: &str, full: &str, body: &Value, p: &str, repeat: Option<&[String]>) -> Res<Value> {
        let o = Reader::new(body.as_map().expect("the schema accepted a map here"), QUESTION);
        let ty = required(o.text("type"));
        let mut q = Map::new();
        q.insert("kind".into(), t("question"));
        q.insert("path".into(), t(id));
        if let Some(prefix) = o.text("prefix") {
            q.insert("prefix".into(), t(prefix));
        }
        let label = owned(o.text("label")).unwrap_or_else(|| {
            let words = id.replace('_', " ");
            let mut c = words.chars();
            c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
        });
        q.insert("label".into(), self.lt(full, &label));
        for (key, out) in [("help", "help"), ("guidance", "guidance")] {
            if let Some(s) = o.text(key) {
                q.insert(out.into(), self.lt(&format!("{full}.{key}"), s));
            }
        }
        if let Some(cond) = o.raw("if") {
            q.insert("when".into(), t(&self.condition(cond, &format!("{p}/if"), repeat)?));
        }
        if let Some(d) = owned(o.text("disabled-display")).or_else(|| q.contains_key("when").then(|| self.disabled_display.clone()).flatten()) {
            q.insert("disabledDisplay".into(), t(&d));
        }
        if let Some(b) = o.flag("optional") {
            q.insert("optional".into(), Value::Bool(b));
        }
        if let Some(nr) = texts(o.list("nonresponse")) {
            q.insert("nonresponse".into(), Value::Array(nr.iter().map(|s| t(s)).collect()));
        }
        let sensitive = o.flag("sensitive").unwrap_or(false);
        let concept = o.raw("concept");
        let mut data = Map::new();
        let mut control = Map::new();
        let presentation = o.text("presentation");
        let number = |k: &str| o.raw(k).cloned();
        let need_list = |s: &Self, name: &str, path: &str| -> Res<()> {
            if s.lists.contains_key(name) { Ok(()) } else { Err(err(path, format!("no list or scale named `{name}`"))) }
        };
        match ty {
            "choice" | "choices" => {
                let list = required(o.text("list"));
                need_list(self, list, &format!("{p}/list"))?;
                control.insert("type".into(), t(if ty == "choice" { "choice" } else { "multi-choice" }));
                control.insert("codes".into(), t(list));
                if let Some(max) = number("max") {
                    control.insert("max".into(), max);
                }
                data.insert("type".into(), t(if ty == "choice" { "code" } else { "codes" }));
                data.insert("codeList".into(), t(list));
            }
            "scale" => {
                let s = required(o.text("scale"));
                need_list(self, s, &format!("{p}/scale"))?;
                control.insert("type".into(), t("scale"));
                control.insert("codes".into(), t(s));
                data.insert("type".into(), t("code"));
                data.insert("codeList".into(), t(s));
            }
            "binary" => {
                control.insert("type".into(), t("yes-no"));
                data.insert("type".into(), t("boolean"));
            }
            "stepper" => {
                let (u, label) = unit(required(o.text("unit")));
                control.insert("type".into(), t("stepper"));
                for k in ["min", "max", "start", "step"] {
                    if let Some(n) = number(k) {
                        control.insert(k.into(), n);
                    }
                }
                control.insert("unit".into(), t(&u));
                if let Some(l) = label {
                    control.insert("unitLabel".into(), self.lt(&format!("{full}.unit"), &l));
                }
                data.insert("type".into(), t("decimal"));
                data.insert("unit".into(), t(&u));
            }
            "number" => {
                control.insert("type".into(), t("number"));
                for k in ["min", "max", "decimals"] {
                    if let Some(n) = number(k) {
                        control.insert(k.into(), n);
                    }
                }
                let integer = matches!(control.get("decimals"), Some(Value::Int(0)));
                if let Some(u) = o.text("unit") {
                    let (u, _) = unit(u);
                    control.insert("unit".into(), t(&u));
                    data.insert("unit".into(), t(&u));
                }
                if let Some(also) = texts(o.list("also")) {
                    control.insert("entryUnits".into(), Value::Array(also.iter().map(|a| t(&unit(a).0)).collect()));
                }
                let value = o.text("value").unwrap_or(if integer { "integer" } else { "decimal" });
                data.insert("type".into(), t(value));
            }
            "money" => {
                control.insert("type".into(), t("money"));
                control.insert("currency".into(), t(required(o.text("currency"))));
                for k in ["min", "max", "step"] {
                    if let Some(n) = number(k) {
                        control.insert(k.into(), n);
                    }
                }
                data.insert("type".into(), t("money"));
            }
            "measure-twice" => {
                let (u, label) = unit(required(o.text("unit")));
                control.insert("type".into(), t("measurement-pair"));
                control.insert("unit".into(), t(&u));
                if let Some(l) = label {
                    control.insert("unitLabel".into(), self.lt(&format!("{full}.unit"), &l));
                }
                if let Some(also) = texts(o.list("also")) {
                    control.insert("entryUnits".into(), Value::Array(also.iter().map(|a| t(&unit(a).0)).collect()));
                }
                for k in ["min", "max", "decimals", "tolerance"] {
                    if let Some(n) = number(k) {
                        control.insert(k.into(), n);
                    }
                }
                data.insert("type".into(), t("decimal"));
                data.insert("unit".into(), t(&u));
            }
            "text" => {
                control.insert("type".into(), t("text"));
                if let Some(n) = number("max-length") {
                    control.insert("maxLength".into(), n);
                }
                if let Some(b) = o.flag("multiline") {
                    control.insert("multiline".into(), Value::Bool(b));
                }
                data.insert("type".into(), t("string"));
                if let Some(d) = o.text("description") {
                    data.insert("description".into(), t(d));
                }
            }
            "date" => {
                control.insert("type".into(), t("date"));
                for k in ["min", "max"] {
                    if let Some(s) = o.text(k) {
                        control.insert(k.into(), t(s));
                    }
                }
                data.insert("type".into(), t("date"));
            }
            "roster" => {
                let field = required(o.text("field"));
                q.insert("from".into(), t(&format!("roster.{field}")));
                q.insert("nonresponse".into(), Value::Array(vec![]));
                let value = o.text("value").unwrap_or("string");
                data.insert("type".into(), t(value));
                if let Some(u) = o.text("unit") {
                    data.insert("unit".into(), t(&unit(u).0));
                }
            }
            other => return Err(err(&format!("{p}/type"), format!("unknown type `{other}`"))),
        }
        if let Some(pr) = presentation {
            control.insert("presentation".into(), t(pr));
        }
        if sensitive {
            data.insert("sensitivity".into(), t("special-category"));
        }
        if let Some(c) = concept {
            data.insert("concept".into(), c.clone());
        }
        if !control.is_empty() {
            q.insert("control".into(), Value::Map(control));
        }
        q.insert("data".into(), Value::Map(data));
        Ok(Value::Map(q))
    }

    /// `{ when, soft, reasons }` or `{ skip, when }` (a rule; ADR 0037: nothing is derived).
    fn check(&self, v: &Value, p: &str, scope: &str, repeat: Option<&[String]>) -> Res<Value> {
        let o = read(v, "survey.check");
        let id = required(o.text("id"));
        let when = self.condition(required(o.raw("when")), &format!("{p}/when"), repeat)?;
        let mut r = Map::new();
        r.insert("id".into(), t(id));
        r.insert("when".into(), t(&when));
        if let Some(targets) = texts(o.list("skip")) {
            // A skip rule has no message to warn with.
            if let Some(k) = ["soft", "reasons"].into_iter().find(|k| o.raw(k).is_some()) {
                return Err(err(&format!("{p}/{k}"), "unknown key"));
            }
            r.insert("kind".into(), t("skip"));
            let paths = targets.iter().map(|q| self.resolve(q, &format!("{p}/skip"), None).map(|s| t(s.trim_start_matches('$')))).collect::<Res<Vec<_>>>()?;
            r.insert("targets".into(), Value::Array(paths));
        } else {
            let message = o.text("soft").ok_or_else(|| err(&format!("{p}/soft"), "is required"))?;
            r.insert("kind".into(), t("soft"));
            r.insert("message".into(), self.lt(&format!("{scope}.{id}"), message));
            if let Some(rs) = o.list("reasons") {
                let mut reasons = Vec::new();
                for reason in rs.iter().filter_map(Value::as_text) {
                    let code = slug(reason).replace('_', "-");
                    reasons.push(map([("code", t(&code)), ("label", self.lt(&format!("{scope}.{id}.{code}"), reason))]));
                }
                r.insert("reasons".into(), Value::Array(reasons));
            }
        }
        Ok(Value::Map(r))
    }

    fn field_checks(&self, v: &Value) -> Res<Value> {
        let mut out = Vec::new();
        for c in v.as_array().into_iter().flatten() {
            let o = read(c, "survey.field-check");
            let (id, ty) = (required(o.text("id")), required(o.text("type")));
            let mut f = Map::new();
            f.insert("id".into(), t(id));
            f.insert("type".into(), t(ty));
            if let Some(q) = o.text("question") {
                let at = format!("/field-checks/{}/question", out.len());
                f.insert("path".into(), t(self.resolve(q, &at, None)?.trim_start_matches('$')));
            }
            for (k, out_k) in [("window", "window"), ("threshold", "threshold"), ("min-seconds", "minSeconds"), ("max-seconds", "maxSeconds")] {
                if let Some(n) = o.raw(k) {
                    f.insert(out_k.into(), n.clone());
                }
            }
            f.insert("message".into(), self.lt(&format!("field-checks.{id}"), required(o.text("message"))));
            out.push(Value::Map(f));
        }
        Ok(Value::Array(out))
    }

    /// A question id as the rule language names it: `@id` for a sibling in the same repeat,
    /// otherwise `$absolute.path`.
    fn resolve(&self, id: &str, p: &str, repeat: Option<&[String]>) -> Res<String> {
        if repeat.is_some_and(|s| s.iter().any(|x| x == id)) {
            return Ok(format!("@{id}"));
        }
        match self.questions.get(id).map(Vec::as_slice) {
            Some([one]) => Ok(format!("${one}")),
            Some(_) => Err(err(p, format!("`{id}` names more than one question; use its full path"))),
            None => self.questions.values().flatten().find(|full| full.as_str() == id).map(|f| format!("${f}")).ok_or_else(|| err(p, format!("no question `{id}`"))),
        }
    }

    /// A condition, a tree of typed operators (ADR 0040), as the rule language's text.
    fn condition(&self, v: &Value, p: &str, repeat: Option<&[String]>) -> Res<String> {
        let (op, arg) = entry(v, p)?;
        let ap = format!("{p}/{op}");
        let list = |n: Option<usize>| -> Res<&Vec<Value>> {
            let a = seq(arg, &ap)?;
            match n {
                Some(n) if a.len() != n => Err(err(&ap, format!("expected {n} operands"))),
                _ => Ok(a),
            }
        };
        Ok(match op {
            "all" | "any" => {
                let parts = list(None)?.iter().enumerate().map(|(i, c)| self.condition(c, &format!("{ap}/{i}"), repeat)).collect::<Res<Vec<_>>>()?;
                if parts.len() < 2 {
                    return Err(err(&ap, "expected at least two conditions"));
                }
                let parts: Vec<String> = parts.into_iter().map(|c| if c.contains(" and ") || c.contains(" or ") { format!("({c})") } else { c }).collect();
                parts.join(if op == "all" { " and " } else { " or " })
            }
            "not" => format!("not ({})", self.condition(arg, &ap, repeat)?),
            "is" => format!("{} == true", self.operand(arg, &ap, repeat)?),
            "answered" => format!("answered({})", self.operand(arg, &ap, repeat)?),
            "eq" | "ne" | "lt" | "le" | "gt" | "ge" => {
                let a = list(Some(2))?;
                let sym = match op { "eq" => "==", "ne" => "!=", "lt" => "<", "le" => "<=", "gt" => ">", _ => ">=" };
                let left = self.operand(&a[0], &format!("{ap}/0"), repeat)?;
                format!("{left} {sym} {}", self.literal_or_operand(&a[1], &format!("{ap}/1"), repeat)?)
            }
            "in" => {
                let a = list(Some(2))?;
                let set = seq(&a[1], &format!("{ap}/1"))?.iter().enumerate().map(|(i, x)| self.literal_or_operand(x, &format!("{ap}/1/{i}"), repeat)).collect::<Res<Vec<_>>>()?;
                format!("{} in [{}]", self.operand(&a[0], &format!("{ap}/0"), repeat)?, set.join(", "))
            }
            other => return Err(err(p, format!("unknown operator `{other}` (all, any, not, is, answered, eq, ne, lt, le, gt, ge, in)"))),
        })
    }

    /// An operand: a question id, a number, or an arithmetic or lookup node.
    fn operand(&self, v: &Value, p: &str, repeat: Option<&[String]>) -> Res<String> {
        match v {
            Value::Text(id) => self.resolve(id, p, repeat),
            Value::Int(i) => Ok(i.to_string()),
            Value::Decimal(d) => Ok(d.to_string()),
            Value::Map(_) => {
                let (op, arg) = entry(v, p)?;
                let ap = format!("{p}/{op}");
                let a = seq(arg, &ap)?;
                match op {
                    "add" | "sub" | "mul" | "div" if a.len() == 2 => {
                        let sym = match op { "add" => "+", "sub" => "-", "mul" => "*", _ => "/" };
                        Ok(format!("({} {sym} {})", self.operand(&a[0], &format!("{ap}/0"), repeat)?, self.operand(&a[1], &format!("{ap}/1"), repeat)?))
                    }
                    "lookup" if a.len() == 2 => {
                        let table = a[0].as_text().ok_or_else(|| err(&format!("{ap}/0"), "expected a table name"))?;
                        Ok(format!("lookup(\"{table}\", {})", self.operand(&a[1], &format!("{ap}/1"), repeat)?))
                    }
                    _ => Err(err(p, format!("unknown or ill-formed operand `{op}` (add, sub, mul, div, lookup, each with two operands)"))),
                }
            }
            _ => Err(err(p, "expected a question id, a number or an operand node")),
        }
    }

    /// The right side of a comparison: a code (quoted) of the left question's list, `true`/`false`,
    /// a number, a question id or an operand node.
    fn literal_or_operand(&self, v: &Value, p: &str, repeat: Option<&[String]>) -> Res<String> {
        match v {
            Value::Bool(b) => Ok(b.to_string()),
            Value::Text(s) if self.resolve(s, p, repeat).is_err() => Ok(format!("\"{s}\"")),
            _ => self.operand(v, p, repeat),
        }
    }
}

/// A frequency scale from structured steps (ADR 0040): codes, labels and per-day values generated.
fn scale(v: &Value, path: &str, lt: &dyn Fn(&str, &str) -> Value) -> Res<Value> {
    let mut codes = Vec::new();
    for (i, step) in seq(v, path)?.iter().enumerate() {
        let p = format!("{path}/{i}");
        if step.as_text() == Some("never") {
            codes.push(map([("code", t("never")), ("label", lt("never", "Never")), ("value", Value::Int(0))]));
            continue;
        }
        let o = read(step, "survey.scale-step");
        let per = required(o.text("per"));
        let (u, days) = match per {
            "day" => ('d', 1),
            "week" => ('w', 7),
            "month" => ('m', 30),
            other => return Err(err(&format!("{p}/per"), format!("`{other}`: per day, week or month"))),
        };
        let int = |r: &Reader<'_>, k: &'static str, at: &str| -> Res<Option<i128>> {
            Ok(match r.int(k) { Some(n) if n > 0 => Some(n), Some(_) => return Err(err(&format!("{at}/{k}"), "expected a positive whole number")), None => None })
        };
        let mut push = |code: String, label: String, value: Value| codes.push(map([("code", t(&code)), ("label", lt(&code, &label)), ("value", value)]));
        if let Some(n) = int(&o, "at-most", &p)? {
            push(format!("{u}_le{n}"), format!("≤ {n} per {per}"), per_day(n, days));
        } else if let Some(n) = int(&o, "exactly", &p)? {
            push(format!("{u}_{n}"), format!("{n}/{per}"), per_day(n, days));
        } else if let Some(n) = int(&o, "more-than", &p)? {
            push(format!("{u}_gt{n}"), format!(">{n}/{per}"), per_day(n + 1, days));
        } else if let Some(each) = o.raw("each") {
            let eo = read(each, "survey.scale-each");
            let ep = format!("{p}/each");
            let (a, b) = (required(int(&eo, "from", &ep)?), required(int(&eo, "to", &ep)?));
            for k in a..=b {
                push(format!("{u}{k}"), format!("{k}/{per}"), per_day(k, days));
            }
        } else {
            let (a, b) = (int(&o, "from", &p)?.ok_or_else(|| err(&p, "expected at-most, exactly, more-than, each or from/to"))?, int(&o, "to", &p)?.ok_or_else(|| err(&format!("{p}/to"), "is required"))?);
            push(format!("{u}_{a}_{b}"), format!("{a}-{b}/{per}"), per_day(a + b, days * 2));
        }
    }
    Ok(map([("ordered", Value::Bool(true)), ("codes", Value::Array(codes))]))
}

// ---- layouts ---------------------------------------------------------------------------------

/// `{ layout: { name, version?, instrument, window, language? }, steps: [ … ] }`. A step is
/// `{ title, navigation?, contents: [ … ] }`; a content item is `{ element: <path> }`,
/// `{ group: <path> }`, `{ repeat: <path>, as? }` (default `list`), `{ show: [<paths>] }` (each an
/// element), `{ card: { title, icon?, contents } }` or `{ tabs: [ { title, icon?, contents } ] }`.
/// Titles are in the source language; translations come from the catalogues (`msgctxt` =
/// `layout/<window>/<id>`, the `id:` of the step, card or tab).
fn layout(top: &Map, texts: &Texts<'_>) -> Res<Value> {
    let o = Reader::new(top, ShapeId("layout"));
    let lo = read(required(o.raw("layout")), "layout.id");
    let name = required(lo.text("name"));
    let version = lo.text("version").unwrap_or("1.0.0");
    let instrument = required(lo.text("instrument"));
    let window = required(lo.text("window"));
    let source = lo.text("language").unwrap_or("en");
    let titles = Titles { texts, window, source };
    let mut steps = Vec::new();
    for (i, s) in required(o.list("steps")).iter().enumerate() {
        let p = format!("/steps/{i}");
        let so = read(s, "layout.step");
        let title = required(so.text("title"));
        let navigation = so.text("navigation").unwrap_or("linear");
        let contents = layout_contents(required(so.raw("contents")), &format!("{p}/contents"), &titles)?;
        steps.push(map([("title", titles.title(so.text("id"), title, &p)), ("navigation", t(navigation)), ("contents", Value::Array(contents))]));
    }
    Ok(map([
        ("apiVersion", t("fieldseal.dev/v1alpha1")),
        ("kind", t("Layout")),
        ("metadata", map([("name", t(name)), ("version", t(version))])),
        ("spec", map([("schema", t("^1.0")), ("instrument", t(instrument)), ("windowClass", t(window)), ("steps", Value::Array(steps))])),
    ]))
}

/// How a layout's titles are translated. A step, card or tab with an `id:` is keyed
/// `layout/<window>/<id>`; one without has no key, so it is not translated (the resolver requires
/// the `id:` of a step and a card).
struct Titles<'a> {
    texts: &'a Texts<'a>,
    window: &'a str,
    source: &'a str,
}

impl Titles<'_> {
    fn title(&self, id: Option<&str>, text: &str, pointer: &str) -> Value {
        match id {
            Some(id) => self.texts.value(self.source, &format!("layout/{}/{id}", self.window), text, Some(format!("{pointer}/title"))),
            None => map([(self.source, t(text))]),
        }
    }
}

fn layout_contents(v: &Value, p: &str, lt: &Titles<'_>) -> Res<Vec<Value>> {
    let mut out = Vec::new();
    for (i, item) in seq(v, p)?.iter().enumerate() {
        let ip = format!("{p}/{i}");
        let r = read(item, "layout.content");
        match r.shape().0 {
            "layout.content.element" => out.push(map([("element", t(required(r.text("element"))))])),
            "layout.content.group" => out.push(map([("group", t(required(r.text("group"))))])),
            "layout.content.repeat" => out.push(map([("repeat", t(required(r.text("repeat")))), ("as", t(r.text("as").unwrap_or("list")))])),
            "layout.content.show" => {
                for e in required(r.list("show")).iter().filter_map(Value::as_text) {
                    out.push(map([("element", t(e))]));
                }
            }
            "layout.content.card" => out.push(map([("card", titled(required(r.raw("card")), &format!("{ip}/card"), lt)?)])),
            "layout.content.tabs" => {
                let mut tabs = Vec::new();
                for (j, tab) in required(r.list("tabs")).iter().enumerate() {
                    tabs.push(map([("tab", titled(tab, &format!("{ip}/tabs/{j}"), lt)?)]));
                }
                out.push(map([("tabs", Value::Array(tabs))]));
            }
            other => return Err(err(&ip, format!("unknown content `{other}`"))),
        }
    }
    Ok(out)
}

/// A card or tab: `{ title, icon?, contents }`.
fn titled(v: &Value, p: &str, lt: &Titles<'_>) -> Res<Value> {
    let o = read(v, "layout.titled");
    let mut m = Map::new();
    m.insert("title".into(), lt.title(o.text("id"), required(o.text("title")), p));
    if let Some(icon) = o.text("icon") {
        m.insert("icon".into(), t(icon));
    }
    m.insert("contents".into(), Value::Array(layout_contents(required(o.raw("contents")), &format!("{p}/contents"), lt)?));
    Ok(Value::Map(m))
}

// ---- rosters ---------------------------------------------------------------------------------

/// `{ roster: { cohort, version }, columns: [subject, display, consent?, …fields], rows: [[…]] }`.
fn roster(top: &Map) -> Res<Value> {
    let o = Reader::new(top, ShapeId("roster"));
    let ro = read(required(o.raw("roster")), "roster.id");
    let (cohort, version) = (required(ro.text("cohort")), required(ro.raw("version")).clone());
    let columns = required(texts(o.list("columns")));
    if columns.first().map(String::as_str) != Some("subject") || columns.get(1).map(String::as_str) != Some("display") {
        return Err(err("/columns", "must start with subject, display"));
    }
    let mut subjects = Vec::new();
    for (i, row) in required(o.list("rows")).iter().enumerate() {
        let p = format!("/rows/{i}");
        let cells = seq(row, &p)?;
        if cells.len() != columns.len() {
            return Err(err(&p, format!("has {} cells for {} columns", cells.len(), columns.len())));
        }
        let mut s = Map::new();
        let mut fields = Map::new();
        for (col, cell) in columns.iter().zip(cells) {
            match col.as_str() {
                "subject" | "display" | "consent" => {
                    s.insert(col.clone(), t(cell.as_text().ok_or_else(|| err(&format!("{p}/{col}"), "expected text"))?));
                }
                _ => {
                    fields.insert(col.clone(), cell.clone());
                }
            }
        }
        if !fields.is_empty() {
            s.insert("fields".into(), Value::Map(fields));
        }
        subjects.push(Value::Map(s));
    }
    Ok(map([("cohort", t(cohort)), ("version", version), ("subjects", Value::Array(subjects))]))
}
