//! The compact authoring dialect (ADR 0040): surveys, layouts and rosters written as typed keys,
//! expanded deterministically into the canonical documents (`kind: Instrument`, `Layout`,
//! `Roster`) that every reader validates. Nothing is parsed out of free text: every setting is a
//! key with a closed set of names and an exact type, and an unknown or ill-typed key is an error
//! naming its path. Ordered content (sections, questions, categories) is a YAML sequence of
//! single-key maps, because a map's order is not kept (WIRE-001).
//!
//! The source language is written inline; other languages come from gettext catalogues
//! (`i18n/<lang>.po`, `msgctxt` = the text's path), merged by [`expand_with`].

use std::collections::BTreeMap;

use fieldseal_kernel::value::{Decimal, Value};

use crate::{AuthoringError, ErrorKind};

type Map = BTreeMap<String, Value>;
type Res<T> = Result<T, AuthoringError>;

/// Translations by language, then by `msgctxt` (the text's path).
pub type Catalogues = BTreeMap<String, BTreeMap<String, String>>;

/// Whether `doc` is a compact document this module expands (a top-level `survey`, `layout` or
/// `roster` key).
#[must_use]
pub fn is_compact(doc: &Value) -> bool {
    doc.as_map().is_some_and(|m| (m.contains_key("survey") || m.contains_key("layout") || m.contains_key("roster")) && !m.contains_key("apiVersion"))
}

/// Expands a compact document with no translations; any other document is returned unchanged.
///
/// # Errors
///
/// An [`AuthoringError`] of kind [`ErrorKind::Compact`] naming the offending path.
pub fn expand(doc: Value) -> Res<Value> {
    expand_with(doc, &Catalogues::new())
}

/// Expands a compact document, merging the translations in `catalogues`.
///
/// # Errors
///
/// An [`AuthoringError`] of kind [`ErrorKind::Compact`] naming the offending path.
pub fn expand_with(doc: Value, catalogues: &Catalogues) -> Res<Value> {
    if !is_compact(&doc) {
        return Ok(doc);
    }
    let m = doc.as_map().expect("checked");
    if m.contains_key("survey") {
        Survey::new(catalogues).expand(m)
    } else if m.contains_key("layout") {
        layout(m, catalogues)
    } else {
        roster(m)
    }
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

/// A typed view of one compact map: every key must be consumed, so an unknown key is an error.
struct Obj<'a> {
    path: String,
    m: &'a Map,
    used: Vec<&'a str>,
}

impl<'a> Obj<'a> {
    fn new(v: &'a Value, path: &str) -> Res<Self> {
        let m = v.as_map().ok_or_else(|| err(path, "expected a map"))?;
        Ok(Self { path: path.to_owned(), m, used: Vec::new() })
    }
    fn at(&self, key: &str) -> String {
        format!("{}/{key}", self.path)
    }
    fn get(&mut self, key: &'a str) -> Option<&'a Value> {
        let v = self.m.get(key);
        if v.is_some() {
            self.used.push(key);
        }
        v
    }
    fn req(&mut self, key: &'a str) -> Res<&'a Value> {
        let p = self.at(key);
        self.get(key).ok_or_else(|| err(&p, "is required"))
    }
    fn text(&mut self, key: &'a str) -> Res<Option<String>> {
        let p = self.at(key);
        match self.get(key) {
            None => Ok(None),
            Some(Value::Text(s)) if !s.is_empty() => Ok(Some(s.clone())),
            Some(_) => Err(err(&p, "expected non-empty text")),
        }
    }
    fn req_text(&mut self, key: &'a str) -> Res<String> {
        let p = self.at(key);
        self.text(key)?.ok_or_else(|| err(&p, "is required"))
    }
    fn bool(&mut self, key: &'a str) -> Res<Option<bool>> {
        let p = self.at(key);
        match self.get(key) {
            None => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(err(&p, "expected true or false")),
        }
    }
    fn number(&mut self, key: &'a str) -> Res<Option<Value>> {
        let p = self.at(key);
        match self.get(key) {
            None => Ok(None),
            Some(v @ (Value::Int(_) | Value::Decimal(_))) => Ok(Some(v.clone())),
            Some(_) => Err(err(&p, "expected a number")),
        }
    }
    fn any(&mut self, key: &'a str) -> Option<Value> {
        self.get(key).cloned()
    }
    fn texts(&mut self, key: &'a str) -> Res<Option<Vec<String>>> {
        let p = self.at(key);
        match self.get(key) {
            None => Ok(None),
            Some(Value::Array(a)) => a.iter().map(|v| v.as_text().map(str::to_owned).ok_or_else(|| err(&p, "expected a list of text"))).collect::<Res<_>>().map(Some),
            Some(_) => Err(err(&p, "expected a list of text")),
        }
    }
    /// Fails on any key that was not read.
    fn done(&self) -> Res<()> {
        if let Some(k) = self.m.keys().find(|k| !self.used.contains(&k.as_str())) {
            return Err(err(&self.at(k), "unknown key"));
        }
        Ok(())
    }
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
    catalogues: &'c Catalogues,
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
    fn new(catalogues: &Catalogues) -> Survey<'_> {
        Survey { catalogues, source: "en".into(), languages: vec![], lists: BTreeMap::new(), questions: BTreeMap::new(), other_max: None, disabled_display: None }
    }

    fn lt(&self, ctx: &str, source: &str) -> Value {
        let mut m = Map::new();
        m.insert(self.source.clone(), t(source));
        for (lang, cat) in self.catalogues {
            if let Some(s) = cat.get(ctx) {
                m.insert(lang.clone(), t(s));
            }
        }
        Value::Map(m)
    }

    fn expand(mut self, top: &Map) -> Res<Value> {
        let root = Value::Map(top.clone());
        let mut o = Obj::new(&root, "")?;
        let mut id = Obj::new(o.req("survey")?, "/survey")?;
        let (name, version) = (id.req_text("name")?, id.req_text("version")?);
        id.done()?;
        if let Some(l) = o.text("language")? {
            self.source = l;
        }
        self.languages = std::iter::once(self.source.clone()).chain(self.catalogues.keys().filter(|l| **l != self.source).cloned()).collect();
        let mut spec = Map::new();
        spec.insert("schema".into(), t("^1.0"));
        for key in ["title", "description", "purpose"] {
            if let Some(s) = o.text(key)? {
                spec.insert(key.into(), self.lt(key, &s));
            }
        }
        for key in ["administration", "publisher"] {
            if let Some(s) = o.text(key)? {
                spec.insert(key.into(), t(&s));
            }
        }
        if let Some(v) = o.any("copyright") {
            spec.insert("copyright".into(), v);
        }
        if let Some(v) = o.any("derived-from") {
            spec.insert("derivedFrom".into(), v);
        }
        spec.insert("languages".into(), Value::Array(self.languages.iter().map(|l| t(l)).collect()));
        spec.insert("defaultLanguage".into(), t(&self.source));
        if let Some(v) = o.get("translations") {
            let mut tr = Map::new();
            for (lang, meta) in v.as_map().ok_or_else(|| err("/translations", "expected a map of languages"))? {
                // A declared translation needs its catalogue: never drop a language silently.
                if !self.catalogues.contains_key(lang) {
                    return Err(err(&format!("/translations/{lang}"), format!("no catalogue for `{lang}`: expected i18n/<survey>/{lang}.po beside the survey (copy it with the survey)")));
                }
                let p = format!("/translations/{lang}");
                let mut mo = Obj::new(meta, &p)?;
                let mut out = Map::new();
                if let Some(s) = mo.text("method")? {
                    out.insert("method".into(), t(&s));
                }
                if let Some(n) = mo.number("reviewed-by")? {
                    out.insert("reviewedBy".into(), n);
                }
                if let Some(s) = mo.text("notes")? {
                    out.insert("notes".into(), t(&s));
                }
                mo.done()?;
                tr.insert(lang.clone(), Value::Map(out));
            }
            spec.insert("translations".into(), Value::Map(tr));
        }
        if let Some(nr) = o.texts("nonresponse")? {
            spec.insert("nonresponse".into(), Value::Array(nr.iter().map(|s| t(s)).collect()));
        }
        if let Some(d) = o.get("defaults") {
            let mut d = Obj::new(d, "/defaults")?;
            if let Some(ot) = d.get("other-text") {
                let mut ot = Obj::new(ot, "/defaults/other-text")?;
                self.other_max = ot.number("max-length")?;
                ot.done()?;
            }
            self.disabled_display = d.text("disabled-display")?;
            d.done()?;
        }
        if let Some(c) = o.get("consent") {
            spec.insert("consent".into(), self.consent(c)?);
        }
        if let Some(l) = o.get("lists") {
            for (k, v) in l.as_map().ok_or_else(|| err("/lists", "expected a map of lists"))? {
                let list = self.list(k, v, &format!("/lists/{k}"))?;
                self.lists.insert(k.clone(), list);
            }
        }
        if let Some(s) = o.get("scales") {
            for (k, v) in s.as_map().ok_or_else(|| err("/scales", "expected a map of scales"))? {
                let sc = scale(v, &format!("/scales/{k}"), &|code, label| self.lt(&format!("lists.{k}.{code}"), label))?;
                self.lists.insert(k.clone(), sc);
            }
        }
        if let Some(tb) = o.get("tables") {
            let mut tables = Map::new();
            for (k, v) in tb.as_map().ok_or_else(|| err("/tables", "expected a map of tables"))? {
                let rows = v.as_map().ok_or_else(|| err(&format!("/tables/{k}"), "expected key: value rows"))?;
                let rows = rows.iter().map(|(key, value)| map([("key", t(key)), ("value", value.clone())])).collect();
                tables.insert(k.clone(), map([("rows", Value::Array(rows))]));
            }
            spec.insert("tables".into(), Value::Map(tables));
        }
        // Every question's path first, so a condition may name a later question.
        let body = o.req("sections")?;
        self.index(body, "", "/sections", &mut Vec::new())?;
        let elements = self.elements(body, "", "/sections", None)?;
        let mut rules = Vec::new();
        if let Some(r) = o.get("checks") {
            for (i, c) in seq(r, "/checks")?.iter().enumerate() {
                rules.push(self.check(c, &format!("/checks/{i}"), "checks", None)?);
            }
        }
        if !rules.is_empty() {
            spec.insert("rules".into(), Value::Array(rules));
        }
        if let Some(fc) = o.get("field-checks") {
            spec.insert("fieldChecks".into(), self.field_checks(fc)?);
        }
        o.done()?;
        if !self.lists.is_empty() {
            spec.insert("codeLists".into(), Value::Map(std::mem::take(&mut self.lists)));
        }
        spec.insert("elements".into(), Value::Array(elements));
        Ok(map([("apiVersion", t("fieldseal.dev/v1alpha1")), ("kind", t("Instrument")), ("metadata", map([("name", t(&name)), ("version", t(&version))])), ("spec", Value::Map(spec))]))
    }

    fn consent(&self, v: &Value) -> Res<Value> {
        let mut c = Obj::new(v, "/consent")?;
        let mut out = Map::new();
        out.insert("required".into(), Value::Bool(c.bool("required")?.unwrap_or(false)));
        if let Some(b) = c.get("bases") {
            let mut bases = Vec::new();
            for (i, item) in seq(b, "/consent/bases")?.iter().enumerate() {
                let (code, label) = entry(item, &format!("/consent/bases/{i}"))?;
                let label = label.as_text().ok_or_else(|| err(&format!("/consent/bases/{i}"), "expected `- code: label`"))?;
                bases.push(map([("code", t(code)), ("label", self.lt(&format!("consent.bases.{code}"), label))]));
            }
            out.insert("bases".into(), Value::Array(bases));
        }
        if let Some(s) = c.get("statement") {
            let mut so = Obj::new(s, "/consent/statement")?;
            let version = so.number("version")?.ok_or_else(|| err("/consent/statement/version", "is required"))?;
            let text = so.req_text("text")?;
            so.done()?;
            out.insert("statement".into(), map([("version", version), ("text", self.lt("consent.statement", &text))]));
        }
        if let Some(e) = c.text("evidence")? {
            out.insert("evidence".into(), t(&e));
        }
        c.done()?;
        Ok(Value::Map(out))
    }

    /// A list: `[items]`, or `{ ordered?, other?, items }`. An item is a label (its code is the
    /// label's slug) or `{ label, code?, description?, icon?, concept?, exclusive? }`.
    fn list(&self, name: &str, v: &Value, path: &str) -> Res<Value> {
        let (items, ordered, other) = match v {
            Value::Array(a) => (a, None, None),
            _ => {
                let mut o = Obj::new(v, path)?;
                let items = seq(o.req("items")?, &o.at("items"))?;
                let ordered = o.bool("ordered")?;
                let other = match o.get("other") {
                    None => None,
                    Some(Value::Text(label)) => Some((label.clone(), self.other_max.clone())),
                    Some(ov) => {
                        let mut oo = Obj::new(ov, &format!("{path}/other"))?;
                        let label = oo.req_text("label")?;
                        let max = oo.number("max-length")?.or_else(|| self.other_max.clone());
                        oo.done()?;
                        Some((label, max))
                    }
                };
                o.done()?;
                (items, ordered, other)
            }
        };
        let mut out = Map::new();
        // Every list states whether it is ordered (INS-131): unordered unless it says so.
        out.insert("ordered".into(), Value::Bool(ordered.unwrap_or(false)));
        let mut codes = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let p = format!("{path}/items/{i}");
            codes.push(match item {
                Value::Text(label) => {
                    let code = slug(label);
                    map([("code", t(&code)), ("label", self.lt(&format!("lists.{name}.{code}"), label))])
                }
                _ => {
                    let mut io = Obj::new(item, &p)?;
                    let label = io.req_text("label")?;
                    let code = io.text("code")?.unwrap_or_else(|| slug(&label));
                    let mut c = Map::new();
                    c.insert("code".into(), t(&code));
                    c.insert("label".into(), self.lt(&format!("lists.{name}.{code}"), &label));
                    if let Some(d) = io.text("description")? {
                        c.insert("description".into(), self.lt(&format!("lists.{name}.{code}.description"), &d));
                    }
                    if let Some(icon) = io.text("icon")? {
                        c.insert("icon".into(), t(&icon));
                    }
                    if let Some(con) = io.any("concept") {
                        c.insert("concept".into(), con);
                    }
                    if let Some(x) = io.bool("exclusive")? {
                        c.insert("exclusive".into(), Value::Bool(x));
                    }
                    io.done()?;
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
                let mut co = Obj::new(cats, &format!("{p}/{id}/categories"))?;
                let ask = co.get("ask").cloned();
                for (b, block) in co.get("blocks").and_then(Value::as_array).into_iter().flatten().enumerate() {
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
                let mut o = Obj::new(body, &p)?;
                let text = o.req_text("display")?;
                let mut d = map([("kind", t("display")), ("id", t(id)), ("text", self.lt(&full, &text))]);
                if let (Some(role), Value::Map(dm)) = (o.text("role")?, &mut d) {
                    dm.insert("role".into(), t(&role));
                }
                o.done()?;
                out.push(d);
            } else {
                out.extend(self.group(id, &full, body, &p, repeat)?);
            }
        }
        Ok(out)
    }

    fn group(&mut self, id: &str, full: &str, body: &Value, p: &str, repeat: Option<&[String]>) -> Res<Vec<Value>> {
        let mut o = Obj::new(body, p)?;
        let label = o.req_text("group")?;
        let mut g = Map::new();
        g.insert("kind".into(), t("group"));
        g.insert("id".into(), t(id));
        g.insert("label".into(), self.lt(full, &label));
        if let Some(d) = o.text("description")? {
            g.insert("description".into(), self.lt(&format!("{full}.description"), &d));
        }
        if let Some(c) = o.any("concept") {
            g.insert("concept".into(), c);
        }
        if let Some(cond) = o.get("if") {
            g.insert("when".into(), t(&self.condition(cond, &format!("{p}/if"), repeat)?));
        }
        if let Some(d) = o.text("disabled-display")?.or_else(|| g.contains_key("when").then(|| self.disabled_display.clone()).flatten()) {
            g.insert("disabledDisplay".into(), t(&d));
        }
        let mut elements = match o.get("elements") {
            Some(e) => self.elements(e, full, &format!("{p}/elements"), repeat)?,
            None => vec![],
        };
        if let Some(cats) = o.get("categories") {
            elements.extend(self.categories(full, cats, &format!("{p}/categories"))?);
        }
        let mut after = Vec::new();
        if let Some(r) = o.get("checks") {
            let mut rules = Vec::new();
            for (i, c) in seq(r, &format!("{p}/checks"))?.iter().enumerate() {
                rules.push(self.check(c, &format!("{p}/checks/{i}"), full, repeat)?);
            }
            g.insert("rules".into(), Value::Array(rules));
        }
        if let Some(e) = o.get("end") {
            let text = e.as_text().ok_or_else(|| err(&format!("{p}/end"), "expected text"))?;
            after.push(map([("kind", t("display")), ("id", t(&format!("{id}_end"))), ("role", t("end")), ("text", self.lt(&format!("{full}.end"), text))]));
        }
        o.done()?;
        g.insert("elements".into(), Value::Array(elements));
        let mut out = vec![Value::Map(g)];
        out.extend(after);
        Ok(out)
    }

    /// Food categories: each becomes a code list of its foods and a repeat group over it whose
    /// questions are the block's `ask` (with the block's overrides) and whose rules are `checks`.
    fn categories(&mut self, parent: &str, v: &Value, p: &str) -> Res<Vec<Value>> {
        let mut o = Obj::new(v, p)?;
        let ask = seq(o.req("ask")?, &o.at("ask"))?.clone();
        let checks = o.get("checks").cloned();
        let blocks = seq(o.req("blocks")?, &o.at("blocks"))?;
        let mut out = Vec::new();
        for (b, block) in blocks.iter().enumerate() {
            let bp = format!("{p}/blocks/{b}");
            let mut bo = Obj::new(block, &bp)?;
            let period = bo.req_text("period")?;
            let overrides: Map = match bo.get("ask") {
                Some(a) => seq(a, &format!("{bp}/ask"))?.iter().map(|q| entry(q, &bp).map(|(k, v)| (k.to_owned(), v.clone()))).collect::<Res<_>>()?,
                None => Map::new(),
            };
            for (j, cat) in seq(bo.req("categories")?, &format!("{bp}/categories"))?.iter().enumerate() {
                let cp = format!("{bp}/categories/{j}");
                let (cid, body) = entry(cat, &cp)?;
                let full = format!("{parent}.{cid}");
                let mut co = Obj::new(body, &format!("{cp}/{cid}"))?;
                let label = co.req_text("label")?;
                // A food may override the block's questions for itself (`ask:` on the food): the
                // canonical repeat overrides, keyed by the food's code.
                let mut item_overrides = Map::new();
                let mut foods = Vec::new();
                for (k, food) in seq(co.req("foods")?, &format!("{cp}/{cid}/foods"))?.iter().enumerate() {
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
                let other = co.text("other")?;
                co.done()?;
                let mut list = Map::new();
                list.insert("ordered".into(), Value::Bool(false));
                list.insert("items".into(), foods);
                if let Some(other) = other {
                    list.insert("other".into(), t(&other));
                }
                let expanded = self.list(cid, &Value::Map(list), &format!("{cp}/{cid}/foods"))?;
                self.lists.insert(cid.to_owned(), expanded);
                let questions: Vec<Value> = ask.iter().map(|q| {
                    let (qid, base) = entry(q, &bp).expect("checked in index");
                    let merged = match (base, overrides.get(qid)) {
                        (Value::Map(b), Some(Value::Map(o))) => { let mut m = b.clone(); for (k, v) in o { m.insert(k.clone(), v.clone()); } Value::Map(m) }
                        _ => base.clone(),
                    };
                    map([(qid, merged)])
                }).collect();
                let siblings: Vec<String> = questions.iter().filter_map(|q| entry(q, "").ok().map(|(k, _)| k.to_owned())).collect();
                let mut g = Map::new();
                g.insert("kind".into(), t("group"));
                g.insert("id".into(), t(cid));
                g.insert("label".into(), self.lt(&full, &label));
                g.insert("referencePeriod".into(), self.lt(&format!("{parent}.periods.{b}"), &period));
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
            bo.done()?;
        }
        o.done()?;
        Ok(out)
    }

    /// One food's overrides of the block's questions: `{ <question>: { unit?, unit-label?, min?, max?, step?, start? } }`,
    /// in the control's canonical terms.
    fn item_override(&self, v: &Value, p: &str, ctx: &str) -> Res<Value> {
        let mut out = Map::new();
        for (qid, settings) in v.as_map().ok_or_else(|| err(p, "expected { <question>: { settings } }"))? {
            let qp = format!("{p}/{qid}");
            let mut o = Obj::new(settings, &qp)?;
            let mut c = Map::new();
            if let Some(u) = o.text("unit")? {
                let (ucum, label) = unit(&u);
                c.insert("unit".into(), t(&ucum));
                if let Some(l) = o.text("unit-label")?.or(label) {
                    c.insert("unitLabel".into(), self.lt(&format!("{ctx}.{qid}.unit"), &l));
                }
            }
            for k in ["min", "max", "step", "start"] {
                if let Some(n) = o.number(k)? {
                    c.insert(k.into(), n);
                }
            }
            o.done()?;
            out.insert(qid.clone(), Value::Map(c));
        }
        Ok(Value::Map(out))
    }

    fn question(&mut self, id: &str, full: &str, body: &Value, p: &str, repeat: Option<&[String]>) -> Res<Value> {
        let mut o = Obj::new(body, p)?;
        let ty = o.req_text("type")?;
        let mut q = Map::new();
        q.insert("kind".into(), t("question"));
        q.insert("path".into(), t(id));
        if let Some(prefix) = o.text("prefix")? {
            q.insert("prefix".into(), t(&prefix));
        }
        let label = o.text("label")?.unwrap_or_else(|| {
            let words = id.replace('_', " ");
            let mut c = words.chars();
            c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
        });
        q.insert("label".into(), self.lt(full, &label));
        for (key, out) in [("help", "help"), ("guidance", "guidance")] {
            if let Some(s) = o.text(key)? {
                q.insert(out.into(), self.lt(&format!("{full}.{key}"), &s));
            }
        }
        if let Some(cond) = o.get("if") {
            q.insert("when".into(), t(&self.condition(cond, &format!("{p}/if"), repeat)?));
        }
        if let Some(d) = o.text("disabled-display")?.or_else(|| q.contains_key("when").then(|| self.disabled_display.clone()).flatten()) {
            q.insert("disabledDisplay".into(), t(&d));
        }
        if let Some(b) = o.bool("optional")? {
            q.insert("optional".into(), Value::Bool(b));
        }
        if let Some(nr) = o.texts("nonresponse")? {
            q.insert("nonresponse".into(), Value::Array(nr.iter().map(|s| t(s)).collect()));
        }
        let sensitive = o.bool("sensitive")?.unwrap_or(false);
        let concept = o.any("concept");
        let mut data = Map::new();
        let mut control = Map::new();
        let presentation = o.text("presentation")?;
        let need_list = |s: &Self, name: &str, path: &str| -> Res<()> {
            if s.lists.contains_key(name) { Ok(()) } else { Err(err(path, format!("no list or scale named `{name}`"))) }
        };
        match ty.as_str() {
            "choice" | "choices" => {
                let list = o.req_text("list")?;
                need_list(self, &list, &o.at("list"))?;
                control.insert("type".into(), t(if ty == "choice" { "choice" } else { "multi-choice" }));
                control.insert("codes".into(), t(&list));
                if let Some(max) = o.number("max")? {
                    control.insert("max".into(), max);
                }
                data.insert("type".into(), t(if ty == "choice" { "code" } else { "codes" }));
                data.insert("codeList".into(), t(&list));
            }
            "scale" => {
                let s = o.req_text("scale")?;
                need_list(self, &s, &o.at("scale"))?;
                control.insert("type".into(), t("scale"));
                control.insert("codes".into(), t(&s));
                data.insert("type".into(), t("code"));
                data.insert("codeList".into(), t(&s));
            }
            "binary" => {
                control.insert("type".into(), t("yes-no"));
                data.insert("type".into(), t("boolean"));
            }
            "stepper" => {
                let (u, label) = unit(&o.req_text("unit")?);
                control.insert("type".into(), t("stepper"));
                for k in ["min", "max", "start", "step"] {
                    if let Some(n) = o.number(k)? {
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
                    if let Some(n) = o.number(k)? {
                        control.insert(k.into(), n);
                    }
                }
                let integer = matches!(control.get("decimals"), Some(Value::Int(0)));
                if let Some(u) = o.text("unit")? {
                    let (u, _) = unit(&u);
                    control.insert("unit".into(), t(&u));
                    data.insert("unit".into(), t(&u));
                }
                if let Some(also) = o.texts("also")? {
                    control.insert("entryUnits".into(), Value::Array(also.iter().map(|a| t(&unit(a).0)).collect()));
                }
                let value = o.text("value")?.unwrap_or_else(|| if integer { "integer".into() } else { "decimal".into() });
                data.insert("type".into(), t(&value));
            }
            "money" => {
                control.insert("type".into(), t("money"));
                control.insert("currency".into(), t(&o.req_text("currency")?));
                for k in ["min", "max", "step"] {
                    if let Some(n) = o.number(k)? {
                        control.insert(k.into(), n);
                    }
                }
                data.insert("type".into(), t("money"));
            }
            "measure-twice" => {
                let (u, label) = unit(&o.req_text("unit")?);
                control.insert("type".into(), t("measurement-pair"));
                control.insert("unit".into(), t(&u));
                if let Some(l) = label {
                    control.insert("unitLabel".into(), self.lt(&format!("{full}.unit"), &l));
                }
                if let Some(also) = o.texts("also")? {
                    control.insert("entryUnits".into(), Value::Array(also.iter().map(|a| t(&unit(a).0)).collect()));
                }
                for k in ["min", "max", "decimals", "tolerance"] {
                    if let Some(n) = o.number(k)? {
                        control.insert(k.into(), n);
                    }
                }
                data.insert("type".into(), t("decimal"));
                data.insert("unit".into(), t(&u));
            }
            "text" => {
                control.insert("type".into(), t("text"));
                if let Some(n) = o.number("max-length")? {
                    control.insert("maxLength".into(), n);
                }
                if let Some(b) = o.bool("multiline")? {
                    control.insert("multiline".into(), Value::Bool(b));
                }
                data.insert("type".into(), t("string"));
                if let Some(d) = o.text("description")? {
                    data.insert("description".into(), t(&d));
                }
            }
            "date" => {
                control.insert("type".into(), t("date"));
                for k in ["min", "max"] {
                    if let Some(s) = o.text(k)? {
                        control.insert(k.into(), t(&s));
                    }
                }
                data.insert("type".into(), t("date"));
            }
            "roster" => {
                let field = o.req_text("field")?;
                q.insert("from".into(), t(&format!("roster.{field}")));
                q.insert("nonresponse".into(), Value::Array(vec![]));
                let value = o.text("value")?.unwrap_or_else(|| "string".into());
                data.insert("type".into(), t(&value));
                if let Some(u) = o.text("unit")? {
                    data.insert("unit".into(), t(&unit(&u).0));
                }
            }
            other => return Err(err(&o.at("type"), format!("unknown type `{other}` (choice, choices, scale, binary, stepper, number, money, measure-twice, text, date, roster)"))),
        }
        if let Some(pr) = presentation {
            control.insert("presentation".into(), t(&pr));
        }
        if sensitive {
            data.insert("sensitivity".into(), t("special-category"));
        }
        if let Some(c) = concept {
            data.insert("concept".into(), c);
        }
        o.done()?;
        if !control.is_empty() {
            q.insert("control".into(), Value::Map(control));
        }
        q.insert("data".into(), Value::Map(data));
        Ok(Value::Map(q))
    }

    /// `{ when, soft, reasons }` or `{ skip, when }` (a rule; ADR 0037: nothing is derived).
    fn check(&self, v: &Value, p: &str, scope: &str, repeat: Option<&[String]>) -> Res<Value> {
        let mut o = Obj::new(v, p)?;
        let id = o.req_text("id")?;
        let when = self.condition(o.req("when")?, &format!("{p}/when"), repeat)?;
        let mut r = Map::new();
        r.insert("id".into(), t(&id));
        r.insert("when".into(), t(&when));
        if let Some(targets) = o.texts("skip")? {
            r.insert("kind".into(), t("skip"));
            let paths = targets.iter().map(|q| self.resolve(q, &format!("{p}/skip"), None).map(|s| t(s.trim_start_matches('$')))).collect::<Res<Vec<_>>>()?;
            r.insert("targets".into(), Value::Array(paths));
        } else {
            let message = o.req_text("soft")?;
            r.insert("kind".into(), t("soft"));
            r.insert("message".into(), self.lt(&format!("{scope}.{id}"), &message));
            if let Some(rs) = o.get("reasons") {
                let mut reasons = Vec::new();
                for (i, reason) in seq(rs, &format!("{p}/reasons"))?.iter().enumerate() {
                    let label = reason.as_text().ok_or_else(|| err(&format!("{p}/reasons/{i}"), "expected a label"))?;
                    let code = slug(label).replace('_', "-");
                    reasons.push(map([("code", t(&code)), ("label", self.lt(&format!("{scope}.{id}.{code}"), label))]));
                }
                r.insert("reasons".into(), Value::Array(reasons));
            }
        }
        o.done()?;
        Ok(Value::Map(r))
    }

    fn field_checks(&self, v: &Value) -> Res<Value> {
        let mut out = Vec::new();
        for (i, c) in seq(v, "/field-checks")?.iter().enumerate() {
            let p = format!("/field-checks/{i}");
            let mut o = Obj::new(c, &p)?;
            let id = o.req_text("id")?;
            let ty = o.req_text("type")?;
            let mut f = Map::new();
            f.insert("id".into(), t(&id));
            f.insert("type".into(), t(&ty));
            if let Some(q) = o.text("question")? {
                f.insert("path".into(), t(self.resolve(&q, &o.at("question"), None)?.trim_start_matches('$')));
            }
            for (k, out_k) in [("window", "window"), ("threshold", "threshold"), ("min-seconds", "minSeconds"), ("max-seconds", "maxSeconds")] {
                if let Some(n) = o.number(k)? {
                    f.insert(out_k.into(), n);
                }
            }
            f.insert("message".into(), self.lt(&format!("field-checks.{id}"), &o.req_text("message")?));
            o.done()?;
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
        let mut o = Obj::new(step, &p)?;
        let per = o.req_text("per")?;
        let (u, days) = match per.as_str() {
            "day" => ('d', 1),
            "week" => ('w', 7),
            "month" => ('m', 30),
            other => return Err(err(&o.at("per"), format!("`{other}`: per day, week or month"))),
        };
        let int = |o: &mut Obj<'_>, k: &'static str| -> Res<Option<i128>> {
            Ok(match o.number(k)? { Some(Value::Int(n)) if n > 0 => Some(n), Some(_) => return Err(err(&o.at(k), "expected a positive whole number")), None => None })
        };
        let mut push = |code: String, label: String, value: Value| codes.push(map([("code", t(&code)), ("label", lt(&code, &label)), ("value", value)]));
        if let Some(n) = int(&mut o, "at-most")? {
            push(format!("{u}_le{n}"), format!("≤ {n} per {per}"), per_day(n, days));
        } else if let Some(n) = int(&mut o, "exactly")? {
            push(format!("{u}_{n}"), format!("{n}/{per}"), per_day(n, days));
        } else if let Some(n) = int(&mut o, "more-than")? {
            push(format!("{u}_gt{n}"), format!(">{n}/{per}"), per_day(n + 1, days));
        } else if let Some(each) = o.get("each") {
            let mut eo = Obj::new(each, &o.at("each"))?;
            let (a, b) = (int(&mut eo, "from")?.ok_or_else(|| err(&eo.at("from"), "is required"))?, int(&mut eo, "to")?.ok_or_else(|| err(&eo.at("to"), "is required"))?);
            eo.done()?;
            for k in a..=b {
                push(format!("{u}{k}"), format!("{k}/{per}"), per_day(k, days));
            }
        } else {
            let (a, b) = (int(&mut o, "from")?.ok_or_else(|| err(&p, "expected at-most, exactly, more-than, each or from/to"))?, int(&mut o, "to")?.ok_or_else(|| err(&o.at("to"), "is required"))?);
            push(format!("{u}_{a}_{b}"), format!("{a}-{b}/{per}"), per_day(a + b, days * 2));
        }
        o.done()?;
    }
    Ok(map([("ordered", Value::Bool(true)), ("codes", Value::Array(codes))]))
}

// ---- layouts ---------------------------------------------------------------------------------

/// `{ layout: { name, version?, instrument, window, language? }, steps: [ … ] }`. A step is
/// `{ title, navigation?, contents: [ … ] }`; a content item is `{ element: <path> }`,
/// `{ group: <path> }`, `{ repeat: <path>, as? }` (default `list`), `{ show: [<paths>] }` (each an
/// element), `{ card: { title, icon?, contents } }` or `{ tabs: [ { title, icon?, contents } ] }`.
/// Titles are in the source language; translations come from the catalogues (`msgctxt` = the
/// title's position, for example `steps.0.contents.1.card`).
fn layout(top: &Map, catalogues: &Catalogues) -> Res<Value> {
    let root = Value::Map(top.clone());
    let mut o = Obj::new(&root, "")?;
    let mut lo = Obj::new(o.req("layout")?, "/layout")?;
    let name = lo.req_text("name")?;
    let version = lo.text("version")?.unwrap_or_else(|| "1.0.0".into());
    let instrument = lo.req_text("instrument")?;
    let window = lo.req_text("window")?;
    let source = lo.text("language")?.unwrap_or_else(|| "en".into());
    lo.done()?;
    let lt = |ctx: &str, text: &str| -> Value {
        let mut m = Map::new();
        m.insert(source.clone(), t(text));
        for (lang, cat) in catalogues {
            if let Some(s) = cat.get(ctx) {
                m.insert(lang.clone(), t(s));
            }
        }
        Value::Map(m)
    };
    let mut steps = Vec::new();
    for (i, s) in seq(o.req("steps")?, "/steps")?.iter().enumerate() {
        let p = format!("/steps/{i}");
        let ctx = format!("steps.{i}");
        let mut so = Obj::new(s, &p)?;
        let title = so.req_text("title")?;
        let navigation = so.text("navigation")?.unwrap_or_else(|| "linear".into());
        let contents = layout_contents(so.req("contents")?, &format!("{p}/contents"), &format!("{ctx}.contents"), &lt)?;
        so.done()?;
        steps.push(map([("title", lt(&ctx, &title)), ("navigation", t(&navigation)), ("contents", Value::Array(contents))]));
    }
    o.done()?;
    Ok(map([
        ("apiVersion", t("fieldseal.dev/v1alpha1")),
        ("kind", t("Layout")),
        ("metadata", map([("name", t(&name)), ("version", t(&version))])),
        ("spec", map([("schema", t("^1.0")), ("instrument", t(&instrument)), ("windowClass", t(&window)), ("steps", Value::Array(steps))])),
    ]))
}

fn layout_contents(v: &Value, p: &str, ctx: &str, lt: &dyn Fn(&str, &str) -> Value) -> Res<Vec<Value>> {
    let mut out = Vec::new();
    for (i, item) in seq(v, p)?.iter().enumerate() {
        let ip = format!("{p}/{i}");
        let ictx = format!("{ctx}.{i}");
        let (kind, body) = entry(item, &ip).or_else(|_| {
            // `{ repeat: x, as: list }` is the one two-key item.
            let m = item.as_map().ok_or_else(|| err(&ip, "expected a content item"))?;
            m.get("repeat").map(|r| ("repeat", r)).ok_or_else(|| err(&ip, "expected one of element, group, repeat, show, card, tabs"))
        })?;
        match kind {
            "element" | "group" => {
                let path = body.as_text().ok_or_else(|| err(&ip, "expected a path"))?;
                out.push(map([(kind, t(path))]));
            }
            "repeat" => {
                let m = item.as_map().expect("checked");
                let path = body.as_text().ok_or_else(|| err(&ip, "expected a path"))?;
                let as_ = match m.get("as") {
                    None => "list",
                    Some(Value::Text(a)) => a.as_str(),
                    Some(_) => return Err(err(&format!("{ip}/as"), "expected list, table or cards")),
                };
                if let Some(k) = m.keys().find(|k| *k != "repeat" && *k != "as") {
                    return Err(err(&format!("{ip}/{k}"), "unknown key"));
                }
                out.push(map([("repeat", t(path)), ("as", t(as_))]));
            }
            "show" => {
                for (j, e) in seq(body, &format!("{ip}/show"))?.iter().enumerate() {
                    out.push(map([("element", t(e.as_text().ok_or_else(|| err(&format!("{ip}/show/{j}"), "expected a path"))?))]));
                }
            }
            "card" => out.push(map([("card", titled(body, &format!("{ip}/card"), &format!("{ictx}.card"), lt)?)])),
            "tabs" => {
                let mut tabs = Vec::new();
                for (j, tab) in seq(body, &format!("{ip}/tabs"))?.iter().enumerate() {
                    tabs.push(map([("tab", titled(tab, &format!("{ip}/tabs/{j}"), &format!("{ictx}.tabs.{j}"), lt)?)]));
                }
                out.push(map([("tabs", Value::Array(tabs))]));
            }
            other => return Err(err(&ip, format!("unknown content `{other}` (element, group, repeat, show, card, tabs)"))),
        }
    }
    Ok(out)
}

/// A card or tab: `{ title, icon?, contents }`.
fn titled(v: &Value, p: &str, ctx: &str, lt: &dyn Fn(&str, &str) -> Value) -> Res<Value> {
    let mut o = Obj::new(v, p)?;
    let title = o.req_text("title")?;
    let mut m = Map::new();
    m.insert("title".into(), lt(ctx, &title));
    if let Some(icon) = o.text("icon")? {
        m.insert("icon".into(), t(&icon));
    }
    m.insert("contents".into(), Value::Array(layout_contents(o.req("contents")?, &format!("{p}/contents"), &format!("{ctx}.contents"), lt)?));
    o.done()?;
    Ok(Value::Map(m))
}

// ---- rosters ---------------------------------------------------------------------------------

/// `{ roster: { cohort, version }, columns: [subject, display, consent?, …fields], rows: [[…]] }`.
fn roster(top: &Map) -> Res<Value> {
    let root = Value::Map(top.clone());
    let mut o = Obj::new(&root, "")?;
    let mut ro = Obj::new(o.req("roster")?, "/roster")?;
    let cohort = ro.req_text("cohort")?;
    let version = ro.number("version")?.ok_or_else(|| err("/roster/version", "is required"))?;
    ro.done()?;
    let columns = o.texts("columns")?.ok_or_else(|| err("/columns", "is required"))?;
    if columns.first().map(String::as_str) != Some("subject") || columns.get(1).map(String::as_str) != Some("display") {
        return Err(err("/columns", "must start with subject, display"));
    }
    let mut subjects = Vec::new();
    for (i, row) in seq(o.req("rows")?, "/rows")?.iter().enumerate() {
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
    o.done()?;
    Ok(map([("cohort", t(&cohort)), ("version", version), ("subjects", Value::Array(subjects))]))
}

/// Parses a gettext catalogue strictly: `msgctxt`, `msgid` and `msgstr` lines with quoted text
/// (`\"`, `\\` and `\n` escapes), comments, blank lines; entries with an empty `msgstr` are left out.
///
/// # Errors
///
/// An [`AuthoringError`] with the line of the first malformed entry.
pub fn parse_po(text: &str) -> Res<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let (mut ctx, mut id, mut s): (Option<String>, Option<String>, Option<String>) = (None, None, None);
    let mut flush = |ctx: &mut Option<String>, id: &mut Option<String>, s: &mut Option<String>, line: usize| -> Res<()> {
        if let (Some(c), Some(_), Some(v)) = (ctx.take(), id.take(), s.take())
            && !v.is_empty()
            && out.insert(c.clone(), v).is_some()
        {
            return Err(AuthoringError::new(ErrorKind::Compact, line, 1, format!("msgctxt \"{c}\" appears twice")));
        }
        Ok(())
    };
    let unquote = |rest: &str, line: usize| -> Res<String> {
        let r = rest.trim();
        let inner = r.strip_prefix('"').and_then(|x| x.strip_suffix('"')).ok_or_else(|| AuthoringError::new(ErrorKind::Compact, line, 1, "expected a quoted string"))?;
        let mut o = String::new();
        let mut it = inner.chars();
        while let Some(c) = it.next() {
            if c == '\\' {
                match it.next() {
                    Some('n') => o.push('\n'),
                    Some('"') => o.push('"'),
                    Some('\\') => o.push('\\'),
                    _ => return Err(AuthoringError::new(ErrorKind::Compact, line, 1, "unknown escape")),
                }
            } else {
                o.push(c);
            }
        }
        Ok(o)
    };
    for (n, raw) in text.lines().enumerate() {
        let line = n + 1;
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some(r) = l.strip_prefix("msgctxt ") {
            flush(&mut ctx, &mut id, &mut s, line)?;
            ctx = Some(unquote(r, line)?);
        } else if let Some(r) = l.strip_prefix("msgid ") {
            id = Some(unquote(r, line)?);
        } else if let Some(r) = l.strip_prefix("msgstr ") {
            s = Some(unquote(r, line)?);
        } else if l.starts_with('"') {
            let more = unquote(l, line)?;
            match (&mut s, &mut id) {
                (Some(v), _) => v.push_str(&more),
                (None, Some(v)) => v.push_str(&more),
                _ => return Err(AuthoringError::new(ErrorKind::Compact, line, 1, "a continuation line outside an entry")),
            }
        } else {
            return Err(AuthoringError::new(ErrorKind::Compact, line, 1, "expected msgctxt, msgid, msgstr, a quoted continuation or a comment"));
        }
    }
    flush(&mut ctx, &mut id, &mut s, text.lines().count())?;
    Ok(out)
}
