//! Decoding an instrument document (a [`Value`] tree from an authoring adapter) into an
//! [`InstrumentDefinition`], rejecting unknown fields everywhere (INS-006) and collecting
//! every finding rather than stopping at the first.

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_kernel::{Decimal, Value};

use crate::domain::codes::{Code, CodeList, Concept, MediaRef, Nonresponse, OtherCode};
use crate::domain::control::{Control, MeasurementPair, Money, MoneyPresentation, NumberEntry, Options, ScalePresentation, Stepper, UnitSpec, YesNoPresentation};
use crate::domain::definitions::{CheckKind, CheckScopeDef, Expected, FieldCheckDef, Reason, RuleAction, RuleDef};
use crate::domain::element::{Condition, ControlOverride, DataSpec, DataType, DisabledDisplay, Display, DisplayRole, Element, Group, Question, Repeat, Sensitivity};
use crate::domain::finding::{FindingKind, Findings, at, idx};
use crate::domain::instrument::InstrumentDefinition;
use crate::domain::language::{LanguageTag, LanguageTagError};
use crate::domain::media::{MAX_IMAGE_BYTES, MAX_TOTAL_MEDIA_BYTES, MEDIA_TYPES, image_problem, is_single_emoji};
use crate::domain::message::{MessageError, parse_message};
use crate::domain::metadata::*;
use crate::domain::paths::{is_code, is_id, is_item_path, is_segment};
use crate::domain::rules::{Expr, PathRef, Val, parse_expr, parse_target};
use crate::domain::text::{LocalisedText, NameText};
use crate::domain::units::{Currency, Unit};
use crate::domain::version::{Compatibility, IMPLEMENTED_SCHEMA, SchemaRange, SemVer, check_compatibility};
use crate::domain::compile::MAX_TABLE_ROWS;
use crate::domain::control::ControlType;

/// References found while decoding that can only be checked against the compiled form.
#[derive(Default)]
pub(crate) struct References {
    /// (document path, message variables) for every text.
    pub variables: Vec<(String, BTreeSet<String>)>,
    /// (document path, media id) for every media reference.
    pub media: Vec<(String, String)>,
    /// (document path, item path) for atomic-group members.
    pub atomic: Vec<(String, String)>,
}

pub(crate) struct Decoder {
    pub f: Findings,
    pub refs: References,
    languages: Vec<LanguageTag>,
    default: Option<LanguageTag>,
}

type Map = BTreeMap<String, Value>;

/// Decodes `doc`. Returns a definition only if every required part could be read; findings
/// may still contain errors.
pub(crate) fn decode(doc: &Value) -> (Option<InstrumentDefinition>, References, Findings) {
    let mut d = Decoder { f: Findings::new(), refs: References::default(), languages: Vec::new(), default: None };
    let def = d.document(doc);
    (def, d.refs, d.f)
}

impl Decoder {
    /// A decoder for a document whose texts must have exactly `languages`, with `default`
    /// among them (INS-080, INS-082): used for layouts, whose titles follow the instrument's
    /// languages.
    pub(crate) fn with_languages(languages: Vec<LanguageTag>, default: LanguageTag) -> Self {
        Self { f: Findings::new(), refs: References::default(), languages, default: Some(default) }
    }

    // ---- primitives -------------------------------------------------------------------

    pub(crate) fn obj<'v>(&mut self, v: &'v Value, path: &str, allowed: &[&str], req: &'static str) -> Option<&'v Map> {
        let Some(m) = v.as_map() else {
            self.f.error(req, path, format!("expected a map, not {}", v.kind()));
            return None;
        };
        for key in m.keys() {
            if !allowed.contains(&key.as_str()) {
                self.f.error("INS-006", at(path, key), format!("unknown field `{key}`; expected one of: {}", allowed.join(", ")));
            }
        }
        Some(m)
    }

    pub(crate) fn req<'v>(&mut self, m: &'v Map, key: &str, path: &str, req: &'static str) -> Option<&'v Value> {
        let v = m.get(key);
        if v.is_none() {
            self.f.error(req, path, format!("missing `{key}`"));
        }
        v
    }

    pub(crate) fn text(&mut self, v: &Value, path: &str, req: &'static str) -> Option<String> {
        match v.as_text() {
            Some(t) if !t.is_empty() => Some(t.to_owned()),
            Some(_) => {
                self.f.error(req, path, "must not be empty");
                None
            }
            None => {
                self.f.error(req, path, format!("expected text, not {}", v.kind()));
                None
            }
        }
    }

    pub(crate) fn opt_text(&mut self, m: &Map, key: &str, path: &str, req: &'static str) -> Option<String> {
        m.get(key).and_then(|v| self.text(v, &at(path, key), req))
    }

    fn boolean(&mut self, v: &Value, path: &str, req: &'static str) -> Option<bool> {
        let b = v.as_bool();
        if b.is_none() {
            self.f.error(req, path, format!("expected true or false, not {}", v.kind()));
        }
        b
    }

    fn opt_bool(&mut self, m: &Map, key: &str, path: &str, req: &'static str) -> bool {
        m.get(key).and_then(|v| self.boolean(v, &at(path, key), req)).unwrap_or(false)
    }

    fn uint(&mut self, v: &Value, path: &str, req: &'static str) -> Option<u32> {
        match v.as_int().map(u32::try_from) {
            Some(Ok(n)) => Some(n),
            _ => {
                self.f.error(req, path, "expected a whole number 0 or more");
                None
            }
        }
    }

    fn opt_uint(&mut self, m: &Map, key: &str, path: &str, req: &'static str) -> Option<u32> {
        m.get(key).and_then(|v| self.uint(v, &at(path, key), req))
    }

    fn decimal(&mut self, v: &Value, path: &str, req: &'static str) -> Option<Decimal> {
        let d = v.as_decimal();
        if d.is_none() {
            self.f.error(req, path, format!("expected a number, not {}", v.kind()));
        }
        d
    }

    fn opt_decimal(&mut self, m: &Map, key: &str, path: &str, req: &'static str) -> Option<Decimal> {
        m.get(key).and_then(|v| self.decimal(v, &at(path, key), req))
    }

    pub(crate) fn array<'v>(&mut self, v: &'v Value, path: &str, req: &'static str) -> Option<&'v [Value]> {
        let a = v.as_array();
        if a.is_none() {
            self.f.error(req, path, format!("expected a list, not {}", v.kind()));
        }
        a
    }

    pub(crate) fn keyword<T: Copy>(&mut self, v: &Value, path: &str, req: &'static str, options: &[(&str, T)]) -> Option<T> {
        let t = self.text(v, path, req)?;
        let found = options.iter().find(|(name, _)| *name == t).map(|(_, x)| *x);
        if found.is_none() {
            let names: Vec<&str> = options.iter().map(|(n, _)| *n).collect();
            self.f.error(req, path, format!("`{t}` is not one of: {}", names.join(", ")));
        }
        found
    }

    fn condition(&mut self, v: &Value, path: &str) -> Option<Condition> {
        let source = self.text(v, path, "INS-040")?;
        match parse_expr(&source) {
            Ok(expr) => Some(Condition { source, expr }),
            Err(e) => {
                self.f.error("INS-040", path, e.to_string());
                None
            }
        }
    }

    // ---- text ---------------------------------------------------------------------------

    pub(crate) fn localised(&mut self, v: &Value, path: &str, req: &'static str) -> Option<LocalisedText> {
        let Some(m) = v.as_map() else {
            self.f.error(req, path, format!("expected localised text (a map of language tag to text), not {}", v.kind()));
            return None;
        };
        let mut texts = BTreeMap::new();
        let mut variables: Option<BTreeSet<String>> = None;
        let mut ok = true;
        for (tag, text) in m {
            let tpath = at(path, tag);
            let tag = match LanguageTag::parse(tag) {
                Ok(t) => t,
                Err(e) => {
                    self.f.error("INS-080", tpath, e.to_string());
                    ok = false;
                    continue;
                }
            };
            if !self.languages.is_empty() && !self.languages.contains(&tag) {
                self.f.error("INS-082", tpath.clone(), format!("`{tag}` is not in spec.languages; a language is either complete or not declared"));
                ok = false;
            }
            let Some(text) = text.as_text() else {
                self.f.error(req, tpath, format!("expected text, not {}", text.kind()));
                ok = false;
                continue;
            };
            match parse_message(text) {
                Ok(info) => match &variables {
                    None => variables = Some(info.variables),
                    Some(vars) if *vars != info.variables => {
                        self.f.error("INS-084", tpath.clone(), "every language of a text must use the same message variables");
                        ok = false;
                    }
                    Some(_) => {}
                },
                Err(MessageError::NotPlainText(m)) => {
                    self.f.error("INS-085", tpath.clone(), m);
                    ok = false;
                }
                Err(MessageError::Syntax(m)) => {
                    self.f.error("INS-084", tpath.clone(), m);
                    ok = false;
                }
            }
            if text.trim().is_empty() {
                self.f.error(req, tpath, "text must not be empty");
                ok = false;
            }
            texts.insert(tag, text.to_owned());
        }
        if let Some(default) = &self.default
            && !texts.contains_key(default) {
                self.f.error("INS-080", path, format!("missing the default language `{default}`"));
                ok = false;
            }
        for lang in &self.languages {
            if Some(lang) != self.default.as_ref() && !texts.contains_key(lang) {
                self.f.error("INS-082", path, format!("missing `{lang}`; every declared language must be complete"));
                ok = false;
            }
        }
        let variables = variables.unwrap_or_default();
        if !variables.is_empty() {
            self.refs.variables.push((path.to_owned(), variables.clone()));
        }
        ok.then(|| LocalisedText::from_parts(texts, variables))
    }

    pub(crate) fn opt_localised(&mut self, m: &Map, key: &str, path: &str, req: &'static str) -> Option<LocalisedText> {
        m.get(key).and_then(|v| self.localised(v, &at(path, key), req))
    }

    fn name_text(&mut self, v: &Value, path: &str, req: &'static str) -> Option<NameText> {
        match v {
            Value::Text(_) => {
                let t = self.text(v, path, req)?;
                if let Err(MessageError::NotPlainText(m)) = crate::domain::message::check_plain_text(&t) {
                    self.f.error("INS-085", path, m);
                }
                Some(NameText::Plain(t))
            }
            _ => self.localised(v, path, req).map(NameText::Localised),
        }
    }

    fn media_ref(&mut self, v: &Value, path: &str) -> Option<MediaRef> {
        match v {
            Value::Text(id) => {
                self.refs.media.push((path.to_owned(), id.clone()));
                Some(MediaRef::Same(id.clone()))
            }
            Value::Map(m) => {
                let mut out = BTreeMap::new();
                for (tag, id) in m {
                    let tpath = at(path, tag);
                    let Ok(tag) = LanguageTag::parse(tag) else {
                        self.f.error("INS-086", tpath, "not a language tag");
                        continue;
                    };
                    if !self.languages.contains(&tag) {
                        self.f.error("INS-086", tpath.clone(), format!("`{tag}` is not in spec.languages"));
                    }
                    if let Some(id) = self.text(id, &tpath, "INS-086") {
                        self.refs.media.push((tpath, id.clone()));
                        out.insert(tag, id);
                    }
                }
                for lang in &self.languages {
                    if !out.contains_key(lang) {
                        self.f.error("INS-086", path, format!("per-language media is missing `{lang}`"));
                    }
                }
                Some(MediaRef::PerLanguage(out))
            }
            _ => {
                self.f.error("INS-180", path, "a media reference is a media id, or a map of language tag to media id");
                None
            }
        }
    }

    fn concepts(&mut self, m: &Map, path: &str) -> Vec<Concept> {
        let Some(v) = m.get("concept") else { return Vec::new() };
        let cpath = at(path, "concept");
        let Some(items) = self.array(v, &cpath, "INS-170") else { return Vec::new() };
        let mut out = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let ipath = idx(&cpath, i);
            let Some(c) = self.obj(item, &ipath, &["system", "code", "display"], "INS-170") else { continue };
            let system = self.req(c, "system", &ipath, "INS-170").and_then(|v| self.text(v, &at(&ipath, "system"), "INS-170"));
            let code = self.req(c, "code", &ipath, "INS-170").and_then(|v| self.text(v, &at(&ipath, "code"), "INS-170"));
            let display = self.opt_text(c, "display", &ipath, "INS-170");
            if let Some(s) = &system
                && !s.contains(':') {
                    self.f.error("INS-170", at(&ipath, "system"), "a concept system is a URI");
                }
            if let (Some(system), Some(code)) = (system, code) {
                out.push(Concept { system, code, display });
            }
        }
        out
    }

    // ---- the document -------------------------------------------------------------------

    fn document(&mut self, doc: &Value) -> Option<InstrumentDefinition> {
        let top = self.obj(doc, "", &["apiVersion", "kind", "metadata", "spec"], "INS-001")?;
        if let Some(v) = self.req(top, "apiVersion", "", "INS-001")
            && v.as_text() != Some("fieldseal.dev/v1alpha1") {
                self.f.error("INS-001", "apiVersion", "must be `fieldseal.dev/v1alpha1`");
            }
        if let Some(v) = self.req(top, "kind", "", "INS-001")
            && v.as_text() != Some("Instrument") {
                self.f.error("INS-001", "kind", "must be `Instrument`");
            }
        let (name, version) = match self.req(top, "metadata", "", "INS-001") {
            Some(m) => self.metadata(m),
            None => (None, None),
        };
        let spec_v = self.req(top, "spec", "", "INS-001")?;
        let spec = self.obj(
            spec_v,
            "spec",
            &[
                "schema", "title", "description", "purpose", "publisher", "copyright", "derivedFrom", "administration", "languages",
                "defaultLanguage", "translations", "nonresponse", "consent", "codeLists", "media", "tables", "derived", "elements", "rules",
                "fieldChecks", "atomicGroups",
            ],
            "INS-001",
        )?;
        let schema = self.schema(spec);
        let languages = self.languages(spec);
        let title = self.req(spec, "title", "spec", "INS-110").and_then(|v| self.localised(v, "spec.title", "INS-110"));
        let description = self.opt_localised(spec, "description", "spec", "INS-111");
        let purpose = self.opt_localised(spec, "purpose", "spec", "INS-111");
        let publisher = spec.get("publisher").and_then(|v| self.name_text(v, "spec.publisher", "INS-111"));
        let copyright = spec.get("copyright").and_then(|v| self.copyright(v));
        let derived_from = spec.get("derivedFrom").map(|v| self.derived_from(v)).unwrap_or_default();
        let administration = self.req(spec, "administration", "spec", "INS-110").and_then(|v| {
            self.keyword(v, "spec.administration", "INS-110", &[("interviewer", Administration::Interviewer), ("self", Administration::SelfAdministered), ("both", Administration::Both)])
        });
        let default_nonresponse = spec.get("nonresponse").map(|v| self.nonresponse(v, "spec.nonresponse")).unwrap_or_default();
        let consent = self.req(spec, "consent", "spec", "INS-060").and_then(|v| self.consent(v));
        let code_lists = spec.get("codeLists").map(|v| self.code_lists(v)).unwrap_or_default();
        let media = spec.get("media").map(|v| self.media(v)).unwrap_or_default();
        let tables = spec.get("tables").map(|v| self.tables(v)).unwrap_or_default();
        let derived = spec.get("derived").map(|v| self.derived(v)).unwrap_or_default();
        let elements = match self.req(spec, "elements", "spec", "INS-120") {
            Some(v) => self.elements(v, "spec.elements"),
            None => Vec::new(),
        };
        let rules = spec.get("rules").map(|v| self.rules(v, "spec.rules")).unwrap_or_default();
        let field_checks = spec.get("fieldChecks").map(|v| self.field_checks(v, "spec.fieldChecks")).unwrap_or_default();
        let atomic_groups = spec.get("atomicGroups").map(|v| self.atomic_groups(v)).unwrap_or_default();
        Some(InstrumentDefinition {
            name: name?,
            version: version?,
            schema: schema?,
            metadata: InstrumentMetadata { title: title?, description, purpose, publisher, copyright, derived_from, administration: administration? },
            languages: languages?,
            default_nonresponse,
            consent: consent?,
            code_lists,
            media,
            tables,
            derived,
            elements,
            rules,
            field_checks,
            atomic_groups,
        })
    }

    fn metadata(&mut self, v: &Value) -> (Option<String>, Option<SemVer>) {
        let Some(m) = self.obj(v, "metadata", &["name", "version"], "INS-001") else { return (None, None) };
        let name = self.req(m, "name", "metadata", "INS-001").and_then(|v| self.text(v, "metadata.name", "INS-001"));
        if let Some(n) = &name {
            let ok = n.len() <= 63
                && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !n.starts_with('-')
                && !n.ends_with('-');
            if !ok {
                self.f.error("INS-001", "metadata.name", "a name is lowercase letters, digits and `-`, at most 63 characters");
            }
        }
        let version = self.req(m, "version", "metadata", "INS-001").and_then(|v| {
            let t = self.text(v, "metadata.version", "INS-001")?;
            match SemVer::parse(&t) {
                Ok(s) => Some(s),
                Err(e) => {
                    self.f.error("INS-001", "metadata.version", e.to_string());
                    None
                }
            }
        });
        (name, version)
    }

    fn schema(&mut self, spec: &Map) -> Option<SchemaRange> {
        let t = self.req(spec, "schema", "spec", "INS-001").and_then(|v| self.text(v, "spec.schema", "INS-091"))?;
        let range = match SchemaRange::parse(&t) {
            Ok(r) => r,
            Err(e) => {
                self.f.error("INS-091", "spec.schema", e.to_string());
                return None;
            }
        };
        if let Compatibility::Incompatible(why) = check_compatibility(range, IMPLEMENTED_SCHEMA) {
            self.f.error_of(FindingKind::IncompatibleSchemaRange, "INS-092", "spec.schema", format!("{why} (this format core implements {IMPLEMENTED_SCHEMA})"));
        }
        Some(range)
    }

    fn languages(&mut self, spec: &Map) -> Option<Languages> {
        let list = self.req(spec, "languages", "spec", "INS-080").and_then(|v| self.array(v, "spec.languages", "INS-080"))?;
        let mut languages = Vec::new();
        for (i, v) in list.iter().enumerate() {
            let p = idx("spec.languages", i);
            let Some(t) = self.text(v, &p, "INS-080") else { continue };
            match LanguageTag::parse(&t) {
                Ok(tag) if languages.contains(&tag) => self.f.error("INS-080", p, format!("`{tag}` is listed twice")),
                Ok(tag) => languages.push(tag),
                Err(e @ (LanguageTagError::Malformed(_) | LanguageTagError::NotCanonical(..))) => self.f.error("INS-080", p, e.to_string()),
            }
        }
        if list.is_empty() {
            self.f.error("INS-080", "spec.languages", "declare at least one language");
        }
        let default = self.req(spec, "defaultLanguage", "spec", "INS-080").and_then(|v| self.text(v, "spec.defaultLanguage", "INS-080"))?;
        let default = match LanguageTag::parse(&default) {
            Ok(t) if languages.contains(&t) => t,
            Ok(t) => {
                self.f.error("INS-080", "spec.defaultLanguage", format!("`{t}` is not in spec.languages"));
                return None;
            }
            Err(e) => {
                self.f.error("INS-080", "spec.defaultLanguage", e.to_string());
                return None;
            }
        };
        self.languages = languages.clone();
        self.default = Some(default.clone());
        let mut translations = BTreeMap::new();
        if let Some(v) = spec.get("translations") {
            if let Some(m) = v.as_map() {
                for (tag, t) in m {
                    let p = at("spec.translations", tag);
                    let Ok(tag) = LanguageTag::parse(tag) else {
                        self.f.error("INS-083", p, "not a language tag");
                        continue;
                    };
                    if tag == default || !languages.contains(&tag) {
                        self.f.error("INS-083", p.clone(), "declare translations only for declared languages other than the default");
                    }
                    let Some(o) = self.obj(t, &p, &["method", "reviewedBy", "notes"], "INS-083") else { continue };
                    let method = self
                        .req(o, "method", &p, "INS-083")
                        .and_then(|v| self.keyword(v, &at(&p, "method"), "INS-083", &[("human", TranslationMethod::Human), ("machine-assisted", TranslationMethod::MachineAssisted)]));
                    let reviewed_by = self.req(o, "reviewedBy", &p, "INS-083").and_then(|v| self.uint(v, &at(&p, "reviewedBy"), "INS-083"));
                    let notes = self.opt_text(o, "notes", &p, "INS-083");
                    if let (Some(method), Some(reviewed_by)) = (method, reviewed_by) {
                        translations.insert(tag, Translation { method, reviewed_by, notes });
                    }
                }
            } else {
                self.f.error("INS-083", "spec.translations", "expected a map of language tag to translation");
            }
        }
        for lang in &languages {
            if *lang != default && !translations.contains_key(lang) && !spec.get("translations").and_then(Value::as_map).is_some_and(|m| m.contains_key(lang.as_str())) {
                self.f.error("INS-083", "spec.translations", format!("`{lang}` needs a translation declaration {{method, reviewedBy}}"));
            }
        }
        Some(Languages { languages, default, translations })
    }

    fn copyright(&mut self, v: &Value) -> Option<Copyright> {
        let p = "spec.copyright";
        let m = self.obj(v, p, &["notice", "licence"], "INS-112")?;
        let notice = self.req(m, "notice", p, "INS-112").and_then(|v| self.name_text(v, &at(p, "notice"), "INS-112"));
        let licence = self.req(m, "licence", p, "INS-112").and_then(|v| self.text(v, &at(p, "licence"), "INS-112"));
        if let Some(l) = &licence
            && !l.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b':')) {
                self.f.error("INS-112", at(p, "licence"), "a licence is an SPDX identifier or a LicenseRef-… identifier");
            }
        Some(Copyright { notice: notice?, licence: licence? })
    }

    fn derived_from(&mut self, v: &Value) -> Vec<Derivation> {
        let p = "spec.derivedFrom";
        let Some(items) = self.array(v, p, "INS-112") else { return Vec::new() };
        let mut out = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let ip = idx(p, i);
            let Some(m) = self.obj(item, &ip, &["title", "version", "citation", "url"], "INS-112") else { continue };
            let title = self.req(m, "title", &ip, "INS-112").and_then(|v| self.text(v, &at(&ip, "title"), "INS-112"));
            let citation = self.req(m, "citation", &ip, "INS-112").and_then(|v| self.text(v, &at(&ip, "citation"), "INS-112"));
            let version = self.opt_text(m, "version", &ip, "INS-112");
            let url = self.opt_text(m, "url", &ip, "INS-112");
            if let (Some(title), Some(citation)) = (title, citation) {
                out.push(Derivation { title, version, citation, url });
            }
        }
        out
    }

    fn nonresponse(&mut self, v: &Value, path: &str) -> Vec<Nonresponse> {
        let Some(items) = self.array(v, path, "INS-140") else { return Vec::new() };
        let mut out = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let p = idx(path, i);
            let Some(t) = self.text(item, &p, "INS-140") else { continue };
            match Nonresponse::from_code(&t) {
                Some(nr) if out.contains(&nr) => self.f.error("INS-140", p, format!("`{t}` is listed twice")),
                Some(nr) => out.push(nr),
                None if t == "not-applicable" => self.f.error("INS-142", p, "`not-applicable` is derived from skip logic, never offered"),
                None => self.f.error("INS-140", p, format!("`{t}` is not a nonresponse code; use dont-know or refused")),
            }
        }
        out
    }

    fn consent(&mut self, v: &Value) -> Option<ConsentRequirement> {
        let p = "spec.consent";
        let m = self.obj(v, p, &["required", "bases", "statement", "evidence"], "INS-060")?;
        let required = self.req(m, "required", p, "INS-060").and_then(|v| self.boolean(v, &at(p, "required"), "INS-060"))?;
        if !required {
            for key in ["bases", "statement", "evidence"] {
                if m.contains_key(key) {
                    self.f.error("INS-062", at(p, key), format!("`{key}` applies only when consent is required"));
                }
            }
            return Some(ConsentRequirement::NotRequired);
        }
        let mut bases = Vec::new();
        if let Some(list) = self.req(m, "bases", p, "INS-061").and_then(|v| self.array(v, &at(p, "bases"), "INS-061")) {
            if list.is_empty() {
                self.f.error("INS-061", at(p, "bases"), "list at least one consent basis");
            }
            for (i, b) in list.iter().enumerate() {
                let bp = idx(&at(p, "bases"), i);
                let Some(bm) = self.obj(b, &bp, &["code", "label"], "INS-061") else { continue };
                let code = self.req(bm, "code", &bp, "INS-061").and_then(|v| self.text(v, &at(&bp, "code"), "INS-061"));
                let label = self.req(bm, "label", &bp, "INS-061").and_then(|v| self.localised(v, &at(&bp, "label"), "INS-061"));
                if let Some(c) = &code {
                    if !is_code(c) || c == "not-required" {
                        self.f.error("INS-061", at(&bp, "code"), "not a valid basis code (`not-required` is reserved, INS-062)");
                    }
                    if bases.iter().any(|b: &ConsentBasis| b.code == *c) {
                        self.f.error("INS-061", at(&bp, "code"), format!("basis `{c}` is listed twice"));
                    }
                }
                if let (Some(code), Some(label)) = (code, label) {
                    bases.push(ConsentBasis { code, label });
                }
            }
        }
        let statement = self.req(m, "statement", p, "INS-061").and_then(|v| {
            let sp = at(p, "statement");
            let s = self.obj(v, &sp, &["version", "text"], "INS-061")?;
            let version = self.req(s, "version", &sp, "INS-061").and_then(|v| self.uint(v, &at(&sp, "version"), "INS-061"));
            let text = self.req(s, "text", &sp, "INS-061").and_then(|v| self.localised(v, &at(&sp, "text"), "INS-061"));
            if version == Some(0) {
                self.f.error("INS-061", at(&sp, "version"), "statement versions start at 1");
            }
            Some(ConsentStatement { version: version?, text: text? })
        });
        let evidence = self.req(m, "evidence", p, "INS-061").and_then(|v| {
            self.keyword(v, &at(p, "evidence"), "INS-061", &[("none", EvidencePolicy::None), ("optional", EvidencePolicy::Optional), ("required", EvidencePolicy::Required)])
        });
        Some(ConsentRequirement::Required { bases, statement: statement?, evidence: evidence? })
    }

    // ---- code lists ---------------------------------------------------------------------

    fn code_lists(&mut self, v: &Value) -> BTreeMap<String, CodeList> {
        let p = "spec.codeLists";
        let Some(m) = v.as_map() else {
            self.f.error("INS-131", p, "expected a map of list id to code list");
            return BTreeMap::new();
        };
        let mut out = BTreeMap::new();
        for (id, list) in m {
            let lp = at(p, id);
            if !is_id(id) {
                self.f.error("INS-131", lp.clone(), "a code-list id is lowercase letters, digits, `_` and `-`");
            }
            let Some(lm) = self.obj(list, &lp, &["ordered", "codes", "other"], "INS-131") else { continue };
            let ordered = self.req(lm, "ordered", &lp, "INS-131").and_then(|v| self.boolean(v, &at(&lp, "ordered"), "INS-131"));
            let codes = match self.req(lm, "codes", &lp, "INS-131") {
                Some(v) => self.codes(v, &at(&lp, "codes")),
                None => Vec::new(),
            };
            let other = lm.get("other").and_then(|v| self.other(v, &at(&lp, "other"), &codes));
            if let Some(ordered) = ordered {
                out.insert(id.clone(), CodeList { ordered, codes, other });
            }
        }
        out
    }

    fn other(&mut self, v: &Value, p: &str, codes: &[Code]) -> Option<OtherCode> {
        let m = self.obj(v, p, &["code", "label", "maxLength"], "INS-134")?;
        let code = self.req(m, "code", p, "INS-134").and_then(|v| self.text(v, &at(p, "code"), "INS-134"));
        let label = self.req(m, "label", p, "INS-134").and_then(|v| self.localised(v, &at(p, "label"), "INS-134"));
        let max_length = self.req(m, "maxLength", p, "INS-134").and_then(|v| self.uint(v, &at(p, "maxLength"), "INS-134"));
        if max_length == Some(0) {
            self.f.error("INS-134", at(p, "maxLength"), "maxLength must be at least 1");
        }
        if let Some(c) = &code
            && !codes.iter().any(|x| x.code == *c) {
                self.f.error("INS-137", at(p, "code"), format!("the other code `{c}` must also appear in the list's codes"));
            }
        Some(OtherCode { code: code?, label: label?, max_length: max_length? })
    }

    fn codes(&mut self, v: &Value, p: &str) -> Vec<Code> {
        let Some(items) = self.array(v, p, "INS-131") else { return Vec::new() };
        if items.is_empty() {
            self.f.error("INS-131", p, "a code list needs at least one code");
        }
        let mut out: Vec<Code> = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let cp = idx(p, i);
            let Some(m) = self.obj(item, &cp, &["code", "label", "description", "value", "exclusive", "media", "icon", "concept"], "INS-131") else { continue };
            let code = self.req(m, "code", &cp, "INS-131").and_then(|v| self.text(v, &at(&cp, "code"), "INS-131"));
            if let Some(c) = &code {
                if !is_code(c) {
                    self.f.error("INS-136", at(&cp, "code"), format!("`{c}` is not a code: use letters, digits, `_` and `-`"));
                }
                if out.iter().any(|x| x.code == *c) {
                    self.f.error("INS-136", at(&cp, "code"), format!("code `{c}` is not unique in its list"));
                }
            }
            let label = self.req(m, "label", &cp, "INS-131").and_then(|v| self.localised(v, &at(&cp, "label"), "INS-131"));
            let description = self.opt_localised(m, "description", &cp, "INS-131");
            let value = self.opt_decimal(m, "value", &cp, "INS-132");
            let exclusive = self.opt_bool(m, "exclusive", &cp, "INS-133");
            let media = m.get("media").and_then(|v| self.media_ref(v, &at(&cp, "media")));
            let icon = self.opt_text(m, "icon", &cp, "INS-183");
            if icon.as_deref().is_some_and(|i| !is_single_emoji(i)) {
                self.f.error("INS-183", at(&cp, "icon"), "an icon is a single Unicode emoji");
            }
            let concept = self.concepts(m, &cp);
            if let (Some(code), Some(label)) = (code, label) {
                out.push(Code { code, label, description, value, exclusive, media, icon, concept });
            }
        }
        out
    }

    // ---- media, tables, derived values, atomic groups ------------------------------------

    fn media(&mut self, v: &Value) -> BTreeMap<String, MediaAsset> {
        let p = "spec.media";
        let Some(m) = v.as_map() else {
            self.f.error("INS-180", p, "expected a map of media id to image");
            return BTreeMap::new();
        };
        let mut out = BTreeMap::new();
        let mut total = 0usize;
        for (id, item) in m {
            let mp = at(p, id);
            if !is_id(id) {
                self.f.error("INS-180", mp.clone(), "a media id is lowercase letters, digits, `_` and `-`");
            }
            let Some(mm) = self.obj(item, &mp, &["mediaType", "sha256", "bytes", "alt"], "INS-180") else { continue };
            let media_type = self.req(mm, "mediaType", &mp, "INS-180").and_then(|v| self.text(v, &at(&mp, "mediaType"), "INS-180"));
            if let Some(t) = &media_type
                && !MEDIA_TYPES.contains(&t.as_str()) {
                    self.f.error("INS-180", at(&mp, "mediaType"), format!("`{t}` is not one of: {}", MEDIA_TYPES.join(", ")));
                }
            let sha256 = self.req(mm, "sha256", &mp, "INS-180").and_then(|v| self.text(v, &at(&mp, "sha256"), "INS-180"));
            if let Some(h) = &sha256
                && (h.len() != 64 || !h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) {
                    self.f.error("INS-180", at(&mp, "sha256"), "a SHA-256 is 64 lowercase hex digits");
                }
            let bytes = match self.req(mm, "bytes", &mp, "INS-180") {
                Some(Value::Bytes(b)) => Some(b.clone()),
                Some(other) => {
                    self.f.error("INS-180", at(&mp, "bytes"), format!("expected bytes, not {}", other.kind()));
                    None
                }
                None => None,
            };
            let alt = self.req(mm, "alt", &mp, "INS-181").and_then(|v| self.localised(v, &at(&mp, "alt"), "INS-181"));
            if let Some(b) = &bytes {
                total += b.len();
                if b.len() > MAX_IMAGE_BYTES {
                    self.f.error("INS-182", at(&mp, "bytes"), format!("{} bytes; each image is at most 1 MiB", b.len()));
                }
                if let Some(problem) = media_type.as_deref().and_then(|t| image_problem(t, b)) {
                    self.f.error("INS-182", at(&mp, "bytes"), problem);
                }
            }
            if let (Some(media_type), Some(sha256), Some(bytes), Some(alt)) = (media_type, sha256, bytes, alt) {
                out.insert(id.clone(), MediaAsset { media_type, sha256, bytes, alt });
            }
        }
        if total > MAX_TOTAL_MEDIA_BYTES {
            self.f.error("INS-182", p, format!("media total {total} bytes; the limit is 8 MiB"));
        }
        out
    }

    fn scalar(&mut self, v: &Value, p: &str, allow_bool: bool) -> Option<Val> {
        match v {
            Value::Int(_) | Value::Decimal(_) => match crate::domain::evaluation::value_to_val(v) {
                Val::Num(n) => Some(Val::Num(n)),
                _ => None,
            },
            Value::Text(t) => Some(Val::Text(t.clone())),
            Value::Bool(b) if allow_bool => Some(Val::Bool(*b)),
            _ => {
                self.f.error("INS-043", p, format!("expected a number or text, not {}", v.kind()));
                None
            }
        }
    }

    fn tables(&mut self, v: &Value) -> BTreeMap<String, LookupTable> {
        let p = "spec.tables";
        let Some(m) = v.as_map() else {
            self.f.error("INS-043", p, "expected a map of table id to table");
            return BTreeMap::new();
        };
        let mut out = BTreeMap::new();
        let mut total = 0usize;
        for (id, t) in m {
            let tp = at(p, id);
            if !is_id(id) {
                self.f.error("INS-043", tp.clone(), "a table id is lowercase letters, digits, `_` and `-`");
            }
            let Some(tm) = self.obj(t, &tp, &["rows"], "INS-043") else { continue };
            let Some(rows) = self.req(tm, "rows", &tp, "INS-043").and_then(|v| self.array(v, &at(&tp, "rows"), "INS-043")) else { continue };
            total += rows.len();
            let mut table = LookupTable { rows: Vec::new() };
            for (i, row) in rows.iter().enumerate() {
                let rp = idx(&at(&tp, "rows"), i);
                let Some(rm) = self.obj(row, &rp, &["key", "value"], "INS-043") else { continue };
                let key = self.req(rm, "key", &rp, "INS-043").and_then(|v| self.scalar(v, &at(&rp, "key"), false));
                let value = self.req(rm, "value", &rp, "INS-043").and_then(|v| self.scalar(v, &at(&rp, "value"), true));
                let (Some(key), Some(value)) = (key, value) else { continue };
                if let Some((k0, v0)) = table.rows.first() {
                    if std::mem::discriminant(k0) != std::mem::discriminant(&key) {
                        self.f.error("INS-043", at(&rp, "key"), "every key in a table has the same type");
                    }
                    if std::mem::discriminant(v0) != std::mem::discriminant(&value) {
                        self.f.error("INS-043", at(&rp, "value"), "every value in a table has the same type");
                    }
                }
                if table.get(&key).is_some() {
                    self.f.error("INS-043", at(&rp, "key"), "keys in a table must not repeat");
                }
                table.rows.push((key, value));
            }
            out.insert(id.clone(), table);
        }
        if total > MAX_TABLE_ROWS {
            self.f.error_of(FindingKind::UnboundedRule, "INS-044", p, format!("tables have {total} rows in total; the limit is {MAX_TABLE_ROWS}"));
        }
        out
    }

    fn derived(&mut self, v: &Value) -> Vec<DerivedDef> {
        let p = "spec.derived";
        let Some(items) = self.array(v, p, "INS-045") else { return Vec::new() };
        let mut out: Vec<DerivedDef> = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let dp = idx(p, i);
            let Some(m) = self.obj(item, &dp, &["path", "label", "data", "record"], "INS-045") else { continue };
            let path = self.req(m, "path", &dp, "INS-045").and_then(|v| self.text(v, &at(&dp, "path"), "INS-045"));
            if let Some(path) = &path {
                if !is_item_path(path) {
                    self.f.error("INS-012", at(&dp, "path"), format!("`{path}` is not an item path"));
                }
                if out.iter().any(|d| d.path == *path) {
                    self.f.error("INS-045", at(&dp, "path"), format!("`{path}` is declared twice"));
                }
            }
            let label = self.req(m, "label", &dp, "INS-045").and_then(|v| self.localised(v, &at(&dp, "label"), "INS-045"));
            let data = self.req(m, "data", &dp, "INS-045").and_then(|v| self.data(v, &at(&dp, "data")));
            let record = self.opt_bool(m, "record", &dp, "INS-045");
            if let (Some(path), Some(label), Some(data)) = (path, label, data) {
                out.push(DerivedDef { path, label, data, record, doc_path: dp });
            }
        }
        out
    }

    fn atomic_groups(&mut self, v: &Value) -> Vec<AtomicGroup> {
        let p = "spec.atomicGroups";
        let Some(items) = self.array(v, p, "INS-031") else { return Vec::new() };
        let mut out: Vec<AtomicGroup> = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let gp = idx(p, i);
            let Some(m) = self.obj(item, &gp, &["id", "paths"], "INS-031") else { continue };
            let id = self.req(m, "id", &gp, "INS-031").and_then(|v| self.text(v, &at(&gp, "id"), "INS-031"));
            if let Some(id) = &id
                && (!is_id(id) || out.iter().any(|g| g.id == *id)) {
                    self.f.error("INS-031", at(&gp, "id"), "an atomic-group id must be a unique identifier");
                }
            let mut paths = Vec::new();
            if let Some(list) = self.req(m, "paths", &gp, "INS-031").and_then(|v| self.array(v, &at(&gp, "paths"), "INS-031")) {
                if list.len() < 2 {
                    self.f.error("INS-031", at(&gp, "paths"), "an atomic group has at least two paths");
                }
                for (j, pv) in list.iter().enumerate() {
                    let pp = idx(&at(&gp, "paths"), j);
                    if let Some(path) = self.text(pv, &pp, "INS-031") {
                        self.refs.atomic.push((pp, path.clone()));
                        paths.push(path);
                    }
                }
            }
            if let Some(id) = id {
                out.push(AtomicGroup { id, paths });
            }
        }
        out
    }

    // ---- elements ---------------------------------------------------------------------

    fn elements(&mut self, v: &Value, p: &str) -> Vec<Element> {
        let Some(items) = self.array(v, p, "INS-120") else { return Vec::new() };
        if items.is_empty() {
            self.f.error("INS-120", p, "the element list must not be empty");
        }
        items.iter().enumerate().filter_map(|(i, e)| self.element(e, &idx(p, i))).collect()
    }

    fn element(&mut self, v: &Value, p: &str) -> Option<Element> {
        let Some(m) = v.as_map() else {
            self.f.error("INS-120", p, format!("expected an element (a map), not {}", v.kind()));
            return None;
        };
        let kind = self.req(m, "kind", p, "INS-120").and_then(|k| self.text(k, &at(p, "kind"), "INS-120"))?;
        match kind.as_str() {
            "question" => self.question(v, p).map(|q| Element::Question(Box::new(q))),
            "group" => self.group(v, p).map(|g| Element::Group(Box::new(g))),
            "display" => self.display(v, p).map(Element::Display),
            other => {
                self.f.error("INS-120", at(p, "kind"), format!("`{other}` is not an element kind; use group, question or display"));
                None
            }
        }
    }

    fn disabled_display(&mut self, m: &Map, p: &str) -> DisabledDisplay {
        m.get("disabledDisplay")
            .and_then(|v| self.keyword(v, &at(p, "disabledDisplay"), "INS-125", &[("hidden", DisabledDisplay::Hidden), ("protected", DisabledDisplay::Protected)]))
            .unwrap_or_default()
    }

    fn question(&mut self, v: &Value, p: &str) -> Option<Question> {
        let m = self.obj(
            v,
            p,
            &[
                "kind", "path", "label", "prefix", "shortLabel", "help", "guidance", "control", "data", "when", "disabledDisplay", "nonresponse",
                "optional", "from", "record", "concept", "media",
            ],
            "INS-011",
        )?;
        let path = self.req(m, "path", p, "INS-011").and_then(|v| self.text(v, &at(p, "path"), "INS-011"));
        if let Some(path) = &path
            && !is_item_path(path) {
                self.f.error("INS-012", at(p, "path"), format!("`{path}` is not an item path: dot-separated [a-z][a-z0-9_]* segments"));
            }
        let label = self.req(m, "label", p, "INS-011").and_then(|v| self.localised(v, &at(p, "label"), "INS-011"));
        let prefix = self.opt_text(m, "prefix", p, "INS-150");
        let short_label = self.opt_localised(m, "shortLabel", p, "INS-150");
        let help = self.opt_localised(m, "help", p, "INS-150");
        let guidance = self.opt_localised(m, "guidance", p, "INS-150");
        let from_roster = m.get("from").and_then(|v| {
            let t = self.text(v, &at(p, "from"), "INS-013")?;
            match t.strip_prefix("roster.") {
                Some(f) if is_segment(f) => Some(f.to_owned()),
                _ => {
                    self.f.error("INS-013", at(p, "from"), "write `from: roster.<field>`");
                    None
                }
            }
        });
        let record = self.opt_bool(m, "record", p, "INS-013");
        if record && !m.contains_key("from") {
            self.f.error("INS-013", at(p, "record"), "`record` applies only to roster items (`from: roster.<field>`)");
        }
        let data = self.req(m, "data", p, "INS-071").and_then(|v| self.data(v, &at(p, "data")));
        let control = match (m.get("control"), m.contains_key("from")) {
            (Some(_), true) => {
                self.f.error("INS-013a", at(p, "control"), "a roster item (`from`) has no control; it is read-only");
                None
            }
            (Some(c), false) => self.control(c, &at(p, "control")),
            (None, true) => None,
            (None, false) => {
                self.f.error("INS-011", p, "missing `control`");
                None
            }
        };
        let when = m.get("when").and_then(|v| self.condition(v, &at(p, "when")));
        let disabled_display = self.disabled_display(m, p);
        let nonresponse = m.get("nonresponse").map(|v| self.nonresponse(v, &at(p, "nonresponse")));
        let optional = self.opt_bool(m, "optional", p, "INS-014");
        let concept = self.concepts(m, p);
        let media = m.get("media").and_then(|v| self.media_ref(v, &at(p, "media")));
        let control_ok = control.is_some() || m.contains_key("from");
        if !control_ok {
            return None;
        }
        Some(Question {
            path: path?,
            label: label?,
            prefix,
            short_label,
            help,
            guidance,
            control,
            data: data?,
            when,
            disabled_display,
            nonresponse,
            optional,
            from_roster,
            record,
            concept,
            media,
        })
    }

    fn data(&mut self, v: &Value, p: &str) -> Option<DataSpec> {
        let m = self.obj(v, p, &["type", "unit", "codeList", "concept", "sensitivity", "description"], "INS-070")?;
        let data_type = self.req(m, "type", p, "INS-070").and_then(|v| {
            let t = self.text(v, &at(p, "type"), "INS-070")?;
            let dt = DataType::from_name(&t);
            if dt.is_none() {
                self.f.error("INS-070", at(p, "type"), format!("`{t}` is not a data type; use code, codes, integer, decimal, money, string, boolean, date or evidence"));
            }
            dt
        });
        let unit = m.get("unit").and_then(|v| self.unit(v, &at(p, "unit")));
        let code_list = self.opt_text(m, "codeList", p, "INS-070");
        let concept = self.concepts(m, p);
        let sensitivity = m
            .get("sensitivity")
            .and_then(|v| self.keyword(v, &at(p, "sensitivity"), "INS-070", &[("normal", Sensitivity::Normal), ("special-category", Sensitivity::SpecialCategory)]))
            .unwrap_or(Sensitivity::Normal);
        let description = self.opt_text(m, "description", p, "INS-070");
        if let (Some(dt), Some(_)) = (data_type, &unit)
            && !dt.is_numeric() {
                self.f.error("INS-070", at(p, "unit"), format!("a `{}` has no unit", dt.name()));
            }
        if let (Some(dt), Some(_)) = (data_type, &code_list)
            && !matches!(dt, DataType::Code | DataType::Codes) {
                self.f.error("INS-070", at(p, "codeList"), format!("a `{}` has no code list", dt.name()));
            }
        Some(DataSpec { data_type: data_type?, unit, code_list, concept, sensitivity, description })
    }

    fn unit(&mut self, v: &Value, p: &str) -> Option<Unit> {
        let t = self.text(v, p, "INS-160")?;
        match Unit::parse(&t) {
            Ok(u) => Some(u),
            Err(e) => {
                self.f.error("INS-160", p, e.to_string());
                None
            }
        }
    }

    fn group(&mut self, v: &Value, p: &str) -> Option<Group> {
        let m = self.obj(
            v,
            p,
            &[
                "kind", "id", "label", "description", "referencePeriod", "repeat", "overrides", "when", "disabledDisplay", "elements", "rules",
                "fieldChecks", "concept", "media",
            ],
            "INS-121",
        )?;
        let id = self.req(m, "id", p, "INS-121").and_then(|v| self.text(v, &at(p, "id"), "INS-121"));
        if let Some(id) = &id
            && !is_segment(id) {
                self.f.error("INS-121", at(p, "id"), format!("`{id}` is not a path segment [a-z][a-z0-9_]*"));
            }
        let label = self.req(m, "label", p, "INS-121").and_then(|v| self.localised(v, &at(p, "label"), "INS-121"));
        let description = self.opt_localised(m, "description", p, "INS-121");
        let reference_period = self.opt_localised(m, "referencePeriod", p, "INS-121");
        let repeat = m.get("repeat").and_then(|v| {
            let rp = at(p, "repeat");
            let r = self.obj(v, &rp, &["over", "count", "open"], "INS-126")?;
            if r.contains_key("count") || r.contains_key("open") {
                self.f.error("INS-130", rp.clone(), "dynamic repeats (`count`, `open`) need schema 1.1; this core implements 1.0");
                return None;
            }
            let over = self.req(r, "over", &rp, "INS-126").and_then(|v| self.text(v, &at(&rp, "over"), "INS-126"))?;
            Some(Repeat { over, overrides: BTreeMap::new() })
        });
        let overrides = m.get("overrides").map(|v| self.overrides(v, &at(p, "overrides"))).unwrap_or_default();
        if !overrides.is_empty() && !m.contains_key("repeat") {
            self.f.error("INS-128", at(p, "overrides"), "overrides apply only to repeat groups");
        }
        let repeat = repeat.map(|r| Repeat { overrides, ..r });
        let when = m.get("when").and_then(|v| self.condition(v, &at(p, "when")));
        let disabled_display = self.disabled_display(m, p);
        let elements = match m.get("elements") {
            Some(v) => {
                let ep = at(p, "elements");
                let items = self.array(v, &ep, "INS-121");
                if items.is_some_and(|i| i.is_empty()) {
                    self.f.error("INS-121", ep.clone(), "a group needs at least one element");
                    Vec::new()
                } else {
                    self.elements(v, &ep)
                }
            }
            None => {
                self.f.error("INS-121", p, "missing `elements`");
                Vec::new()
            }
        };
        let rules = m.get("rules").map(|v| self.rules(v, &at(p, "rules"))).unwrap_or_default();
        let field_checks = m.get("fieldChecks").map(|v| self.field_checks(v, &at(p, "fieldChecks"))).unwrap_or_default();
        let concept = self.concepts(m, p);
        let media = m.get("media").and_then(|v| self.media_ref(v, &at(p, "media")));
        Some(Group {
            id: id?,
            label: label?,
            description,
            reference_period,
            repeat,
            when,
            disabled_display,
            concept,
            media,
            elements,
            rules,
            field_checks,
        })
    }

    fn overrides(&mut self, v: &Value, p: &str) -> BTreeMap<String, BTreeMap<String, ControlOverride>> {
        let mut out = BTreeMap::new();
        let Some(codes) = v.as_map() else {
            self.f.error("INS-128", p, "expected a map of code to child overrides");
            return out;
        };
        for (code, children) in codes {
            let cp = at(p, code);
            let Some(children) = children.as_map() else {
                self.f.error("INS-128", cp, "expected a map of child path to control options");
                continue;
            };
            let mut per = BTreeMap::new();
            for (child, opts) in children {
                let op = at(&cp, child);
                let Some(o) = self.obj(opts, &op, &["unit", "unitLabel", "step", "min", "max"], "INS-128") else { continue };
                per.insert(
                    child.clone(),
                    ControlOverride {
                        unit: o.get("unit").and_then(|v| self.unit(v, &at(&op, "unit"))),
                        unit_label: self.opt_localised(o, "unitLabel", &op, "INS-160"),
                        step: self.opt_decimal(o, "step", &op, "INS-128"),
                        min: self.opt_decimal(o, "min", &op, "INS-128"),
                        max: self.opt_decimal(o, "max", &op, "INS-128"),
                    },
                );
            }
            out.insert(code.clone(), per);
        }
        out
    }

    fn display(&mut self, v: &Value, p: &str) -> Option<Display> {
        let m = self.obj(v, p, &["kind", "id", "role", "text", "media", "when"], "INS-123")?;
        let id = self.req(m, "id", p, "INS-123").and_then(|v| self.text(v, &at(p, "id"), "INS-123"));
        if let Some(id) = &id
            && !is_segment(id) {
                self.f.error("INS-123", at(p, "id"), format!("`{id}` is not a path segment [a-z][a-z0-9_]*"));
            }
        let role = self.req(m, "role", p, "INS-123").and_then(|v| {
            self.keyword(
                v,
                &at(p, "role"),
                "INS-123",
                &[("instruction", DisplayRole::Instruction), ("note", DisplayRole::Note), ("introduction", DisplayRole::Introduction), ("end", DisplayRole::End)],
            )
        });
        let text = self.opt_localised(m, "text", p, "INS-123");
        let media = m.get("media").and_then(|v| self.media_ref(v, &at(p, "media")));
        if !m.contains_key("text") && !m.contains_key("media") {
            self.f.error("INS-123", p, "a display needs `text`, `media` or both");
        }
        let when = m.get("when").and_then(|v| self.condition(v, &at(p, "when")));
        Some(Display { id: id?, role: role?, text, media, when })
    }

    // ---- controls ---------------------------------------------------------------------

    fn control(&mut self, v: &Value, p: &str) -> Option<Control> {
        let Some(m) = v.as_map() else {
            self.f.error("INS-011", p, format!("expected a control (a map), not {}", v.kind()));
            return None;
        };
        let t = self.req(m, "type", p, "INS-025").and_then(|v| self.text(v, &at(p, "type"), "INS-025"))?;
        let Some(ct) = ControlType::from_name(&t) else {
            self.f.error_of(FindingKind::UnknownControl, "INS-025", at(p, "type"), format!("`{t}` is not a control of catalogue v1"));
            return None;
        };
        let keys: &[&str] = match ct {
            ControlType::Choice => &["type", "options", "codes"],
            ControlType::MultiChoice => &["type", "options", "codes", "max"],
            ControlType::Scale => &["type", "steps", "codes", "presentation"],
            ControlType::Stepper => &["type", "min", "max", "start", "step", "unit", "unitLabel"],
            ControlType::Number => &["type", "min", "max", "decimals", "unit", "unitLabel", "entryUnits"],
            ControlType::Money => &["type", "currency", "min", "max", "step", "presentation"],
            ControlType::MeasurementPair => &["type", "min", "max", "decimals", "unit", "unitLabel", "entryUnits", "tolerance"],
            ControlType::Text => &["type", "maxLength", "multiline"],
            ControlType::CodedListWithOther => &["type", "options", "otherLabel", "maxLength"],
            ControlType::YesNo => &["type", "presentation"],
            ControlType::Date => &["type", "min", "max"],
            ControlType::PhotoEvidence => &["type", "maxDimension"],
            ControlType::ConsentAttestation => {
                self.f.error("INS-025", at(p, "type"), "`consent-attestation` is used only by the consent step (§5.7), not in the element tree");
                return None;
            }
        };
        let m = self.obj(v, p, keys, "INS-025")?;
        Some(match ct {
            ControlType::Choice => Control::Choice { options: self.options(m, p, "options", false)? },
            ControlType::MultiChoice => Control::MultiChoice { options: self.options(m, p, "options", false)?, max: self.opt_uint(m, "max", p, "INS-025") },
            ControlType::Scale => Control::Scale {
                steps: self.options(m, p, "steps", true)?,
                presentation: m.get("presentation").and_then(|v| self.keyword(v, &at(p, "presentation"), "INS-025", &[("slider", ScalePresentation::Slider), ("segments", ScalePresentation::Segments)])),
            },
            ControlType::Stepper => {
                let min = self.req(m, "min", p, "INS-163").and_then(|v| self.decimal(v, &at(p, "min"), "INS-163"));
                let max = self.req(m, "max", p, "INS-163").and_then(|v| self.decimal(v, &at(p, "max"), "INS-163"));
                let start = self.opt_decimal(m, "start", p, "INS-163");
                let step = self.opt_decimal(m, "step", p, "INS-163").unwrap_or(Decimal { mantissa: 1, exponent: 0 });
                let unit = self.unit_spec(m, p);
                let (min, max) = (min?, max?);
                Control::Stepper(Stepper { min, max, start: start.unwrap_or(min), step, unit })
            }
            ControlType::Number => Control::Number(self.number_entry(m, p)),
            ControlType::Money => {
                let currency = self.req(m, "currency", p, "INS-162").and_then(|v| {
                    let t = self.text(v, &at(p, "currency"), "INS-162")?;
                    Currency::parse(&t).map_err(|e| self.f.error("INS-162", at(p, "currency"), e.to_string())).ok()
                });
                Control::Money(Money {
                    currency: currency?,
                    min: self.opt_decimal(m, "min", p, "INS-027"),
                    max: self.opt_decimal(m, "max", p, "INS-027"),
                    step: self.opt_decimal(m, "step", p, "INS-163"),
                    presentation: m.get("presentation").and_then(|v| self.keyword(v, &at(p, "presentation"), "INS-025", &[("stepper", MoneyPresentation::Stepper), ("entry", MoneyPresentation::Entry)])),
                })
            }
            ControlType::MeasurementPair => {
                let reading = self.number_entry(m, p);
                let tolerance = self.req(m, "tolerance", p, "INS-026").and_then(|v| self.decimal(v, &at(p, "tolerance"), "INS-026"))?;
                Control::MeasurementPair(MeasurementPair { reading, tolerance })
            }
            ControlType::Text => {
                let max_length = self.opt_uint(m, "maxLength", p, "INS-025");
                if max_length == Some(0) {
                    self.f.error("INS-025", at(p, "maxLength"), "maxLength must be at least 1");
                }
                Control::Text { max_length, multiline: self.opt_bool(m, "multiline", p, "INS-025") }
            }
            ControlType::CodedListWithOther => {
                let options = match self.req(m, "options", p, "INS-131") {
                    Some(v) => CodeList { ordered: false, codes: self.codes(v, &at(p, "options")), other: None },
                    None => return None,
                };
                let other_label = self.req(m, "otherLabel", p, "INS-134").and_then(|v| self.localised(v, &at(p, "otherLabel"), "INS-134"));
                let max_length = self.req(m, "maxLength", p, "INS-134").and_then(|v| self.uint(v, &at(p, "maxLength"), "INS-134"));
                if max_length == Some(0) {
                    self.f.error("INS-134", at(p, "maxLength"), "maxLength must be at least 1");
                }
                Control::CodedListWithOther { options, other_label: other_label?, max_length: max_length? }
            }
            ControlType::YesNo => Control::YesNo {
                presentation: m.get("presentation").and_then(|v| self.keyword(v, &at(p, "presentation"), "INS-025", &[("switch", YesNoPresentation::Switch), ("buttons", YesNoPresentation::Buttons)])),
            },
            ControlType::Date => Control::Date { min: self.opt_text(m, "min", p, "INS-025"), max: self.opt_text(m, "max", p, "INS-025") },
            ControlType::PhotoEvidence => Control::PhotoEvidence { max_dimension: self.opt_uint(m, "maxDimension", p, "INS-025") },
            ControlType::ConsentAttestation => return None,
        })
    }

    fn options(&mut self, m: &Map, p: &str, inline_key: &str, ordered: bool) -> Option<Options> {
        match (m.get(inline_key), m.get("codes")) {
            (Some(_), Some(_)) => {
                self.f.error("INS-131", p, format!("give `{inline_key}` or `codes`, not both"));
                None
            }
            (Some(v), None) => Some(Options::Inline(CodeList { ordered, codes: self.codes(v, &at(p, inline_key)), other: None })),
            (None, Some(v)) => self.text(v, &at(p, "codes"), "INS-131").map(Options::Named),
            (None, None) => {
                self.f.error("INS-131", p, format!("a coded control needs `{inline_key}` or `codes`"));
                None
            }
        }
    }

    fn unit_spec(&mut self, m: &Map, p: &str) -> Option<UnitSpec> {
        let unit = m.get("unit").and_then(|v| self.unit(v, &at(p, "unit")));
        let label = self.opt_localised(m, "unitLabel", p, "INS-160");
        if label.is_some() && !m.contains_key("unit") {
            self.f.error("INS-160", at(p, "unitLabel"), "a unitLabel needs a unit");
        }
        unit.map(|unit| UnitSpec { unit, label })
    }

    fn number_entry(&mut self, m: &Map, p: &str) -> NumberEntry {
        let mut entry_units = Vec::new();
        if let Some(list) = m.get("entryUnits").and_then(|v| self.array(v, &at(p, "entryUnits"), "INS-161")) {
            for (i, u) in list.iter().enumerate() {
                if let Some(u) = self.unit(u, &idx(&at(p, "entryUnits"), i)) {
                    entry_units.push(u);
                }
            }
        }
        NumberEntry {
            min: self.opt_decimal(m, "min", p, "INS-027"),
            max: self.opt_decimal(m, "max", p, "INS-027"),
            decimals: self.opt_uint(m, "decimals", p, "INS-025").unwrap_or(0),
            unit: self.unit_spec(m, p),
            entry_units,
        }
    }

    // ---- rules and field checks -----------------------------------------------------------

    fn rules(&mut self, v: &Value, p: &str) -> Vec<RuleDef> {
        let Some(items) = self.array(v, p, "INS-040") else { return Vec::new() };
        let mut out: Vec<RuleDef> = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let rp = idx(p, i);
            if let Some(r) = self.rule(item, &rp) {
                if out.iter().any(|x| x.id == r.id) {
                    self.f.error("INS-049", at(&rp, "id"), format!("rule id `{}` is not unique in its scope", r.id));
                }
                out.push(r);
            }
        }
        out
    }

    fn rule(&mut self, v: &Value, p: &str) -> Option<RuleDef> {
        let m = v.as_map().or_else(|| {
            self.f.error("INS-040", p, "expected a rule (a map)");
            None
        })?;
        let kind = self.req(m, "kind", p, "INS-040").and_then(|v| self.text(v, &at(p, "kind"), "INS-040"))?;
        let keys: &[&str] = match kind.as_str() {
            "hard" => &["id", "kind", "when", "message"],
            "soft" => &["id", "kind", "when", "message", "reasons"],
            "skip" => &["id", "kind", "when", "targets"],
            "derive" => &["id", "kind", "when", "target", "value"],
            other => {
                self.f.error("INS-040", at(p, "kind"), format!("`{other}` is not a rule kind; use hard, soft, skip or derive"));
                return None;
            }
        };
        let m = self.obj(v, p, keys, "INS-040")?;
        let id = self.req(m, "id", p, "INS-049").and_then(|v| self.text(v, &at(p, "id"), "INS-049"));
        if let Some(id) = &id
            && !is_id(id) {
                self.f.error("INS-049", at(p, "id"), "a rule id is lowercase letters, digits, `_` and `-`");
            }
        let when = if kind == "derive" && !m.contains_key("when") {
            Some(Condition { source: "true".into(), expr: Expr::Bool(true) })
        } else {
            self.req(m, "when", p, "INS-040").and_then(|v| self.condition(v, &at(p, "when")))
        };
        let message = |d: &mut Self| d.req(m, "message", p, "INS-040").and_then(|v| d.localised(v, &at(p, "message"), "INS-040"));
        let action = match kind.as_str() {
            "hard" => RuleAction::Hard { message: message(self)? },
            "soft" => {
                let message = message(self);
                let mut reasons = Vec::new();
                if let Some(list) = self.req(m, "reasons", p, "INS-040").and_then(|v| self.array(v, &at(p, "reasons"), "INS-040")) {
                    if list.is_empty() {
                        self.f.error("INS-040", at(p, "reasons"), "a soft rule offers at least one reason");
                    }
                    for (i, r) in list.iter().enumerate() {
                        let rp = idx(&at(p, "reasons"), i);
                        let Some(rm) = self.obj(r, &rp, &["code", "label"], "INS-040") else { continue };
                        let code = self.req(rm, "code", &rp, "INS-040").and_then(|v| self.text(v, &at(&rp, "code"), "INS-040"));
                        if code.as_deref().is_some_and(|c| !is_code(c)) {
                            self.f.error("INS-040", at(&rp, "code"), "not a valid reason code");
                        }
                        let label = self.req(rm, "label", &rp, "INS-040").and_then(|v| self.localised(v, &at(&rp, "label"), "INS-040"));
                        if let (Some(code), Some(label)) = (code, label) {
                            reasons.push(Reason { code, label });
                        }
                    }
                }
                RuleAction::Soft { message: message?, reasons }
            }
            "skip" => {
                let mut targets = Vec::new();
                if let Some(list) = self.req(m, "targets", p, "INS-124").and_then(|v| self.array(v, &at(p, "targets"), "INS-124")) {
                    if list.is_empty() {
                        self.f.error("INS-124", at(p, "targets"), "a skip rule hides at least one element");
                    }
                    for (i, t) in list.iter().enumerate() {
                        let tp = idx(&at(p, "targets"), i);
                        if let Some(t) = self.path_ref(t, &tp, "INS-124") {
                            targets.push(t);
                        }
                    }
                }
                RuleAction::Skip { targets }
            }
            _ => {
                let target = self.req(m, "target", p, "INS-045").and_then(|v| self.path_ref(v, &at(p, "target"), "INS-045"));
                let value = self.req(m, "value", p, "INS-045").and_then(|v| self.condition(v, &at(p, "value")));
                RuleAction::Derive { target: target?, value: value? }
            }
        };
        Some(RuleDef { id: id?, when: when?, action, doc_path: p.to_owned() })
    }

    fn path_ref(&mut self, v: &Value, p: &str, req: &'static str) -> Option<PathRef> {
        let t = self.text(v, p, req)?;
        let r = parse_target(&t);
        if r.is_none() {
            self.f.error(req, p, format!("`{t}` is not an item path or `@sibling`"));
        }
        r
    }

    fn field_checks(&mut self, v: &Value, p: &str) -> Vec<FieldCheckDef> {
        let Some(items) = self.array(v, p, "INS-050") else { return Vec::new() };
        let mut out: Vec<FieldCheckDef> = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let cp = idx(p, i);
            if let Some(c) = self.field_check(item, &cp) {
                if out.iter().any(|x| x.id == c.id) {
                    self.f.error("INS-050", at(&cp, "id"), format!("field-check id `{}` is not unique in its scope", c.id));
                }
                out.push(c);
            }
        }
        out
    }

    fn share(&mut self, m: &Map, p: &str) -> Option<Decimal> {
        let t = self.req(m, "threshold", p, "INS-050").and_then(|v| self.decimal(v, &at(p, "threshold"), "INS-050"))?;
        let n = crate::domain::num::Num::from_decimal(t)?;
        if n.is_negative() || n > crate::domain::num::Num::ONE {
            self.f.error("INS-050", at(p, "threshold"), "a share is between 0 and 1");
        }
        Some(t)
    }

    fn field_check(&mut self, v: &Value, p: &str) -> Option<FieldCheckDef> {
        let m = v.as_map().or_else(|| {
            self.f.error("INS-050", p, "expected a field check (a map)");
            None
        })?;
        let t = self.req(m, "type", p, "INS-050").and_then(|v| self.text(v, &at(p, "type"), "INS-050"))?;
        let params: &[&str] = match t.as_str() {
            "distribution" => &["path", "expected", "minCount", "bound"],
            "drift" => &["path", "window", "threshold"],
            "duplicates" => &["paths", "minMatch"],
            "timing" => &["minSeconds", "maxSeconds"],
            "completeness" => &["group", "paths", "threshold"],
            "straightlining" => &["group", "threshold"],
            other => {
                self.f.error("INS-050", at(p, "type"), format!("`{other}` is not a field-check type"));
                return None;
            }
        };
        let mut keys = vec!["id", "type", "message"];
        keys.extend_from_slice(params);
        let m = self.obj(v, p, &keys, "INS-050")?;
        let id = self.req(m, "id", p, "INS-050").and_then(|v| self.text(v, &at(p, "id"), "INS-050"));
        if id.as_deref().is_some_and(|i| !is_id(i)) {
            self.f.error("INS-050", at(p, "id"), "a field-check id is lowercase letters, digits, `_` and `-`");
        }
        let message = self.req(m, "message", p, "INS-050").and_then(|v| self.localised(v, &at(p, "message"), "INS-050"));
        let path = |d: &mut Self, key: &str| d.req(m, key, p, "INS-050").and_then(|v| d.path_ref(v, &at(p, key), "INS-050"));
        let paths = |d: &mut Self| -> Option<Vec<PathRef>> {
            let list = d.req(m, "paths", p, "INS-050").and_then(|v| d.array(v, &at(p, "paths"), "INS-050"))?;
            if list.is_empty() {
                d.f.error("INS-050", at(p, "paths"), "list at least one path");
            }
            Some(list.iter().enumerate().filter_map(|(i, v)| d.path_ref(v, &idx(&at(p, "paths"), i), "INS-050")).collect())
        };
        let kind = match t.as_str() {
            "distribution" => {
                let ep = at(p, "expected");
                let expected = self.req(m, "expected", p, "INS-050").and_then(|v| {
                    let e = self.obj(v, &ep, &["mean", "sd", "min", "max"], "INS-050")?;
                    match (e.contains_key("mean") || e.contains_key("sd"), e.contains_key("min") || e.contains_key("max")) {
                        (true, false) => {
                            let mean = self.req(e, "mean", &ep, "INS-050").and_then(|v| self.decimal(v, &at(&ep, "mean"), "INS-050"));
                            let sd = self.req(e, "sd", &ep, "INS-050").and_then(|v| self.decimal(v, &at(&ep, "sd"), "INS-050"));
                            Some(Expected::MeanSd { mean: mean?, sd: sd? })
                        }
                        (false, true) => {
                            let min = self.req(e, "min", &ep, "INS-050").and_then(|v| self.decimal(v, &at(&ep, "min"), "INS-050"));
                            let max = self.req(e, "max", &ep, "INS-050").and_then(|v| self.decimal(v, &at(&ep, "max"), "INS-050"));
                            Some(Expected::Range { min: min?, max: max? })
                        }
                        _ => {
                            self.f.error("INS-050", ep.clone(), "give either {mean, sd} or {min, max}");
                            None
                        }
                    }
                });
                let min_count = self.req(m, "minCount", p, "INS-050").and_then(|v| self.uint(v, &at(p, "minCount"), "INS-050"));
                let bound = self.opt_decimal(m, "bound", p, "INS-050").unwrap_or(Decimal { mantissa: 3, exponent: 0 });
                CheckKind::Distribution { path: path(self, "path")?, expected: expected?, min_count: min_count?, bound }
            }
            "drift" => {
                let window = self.req(m, "window", p, "INS-050").and_then(|v| self.uint(v, &at(p, "window"), "INS-050"));
                if window.is_some_and(|w| w < 2) {
                    self.f.error("INS-050", at(p, "window"), "a drift window covers at least 2 values");
                }
                let threshold = self.req(m, "threshold", p, "INS-050").and_then(|v| self.decimal(v, &at(p, "threshold"), "INS-050"));
                CheckKind::Drift { path: path(self, "path")?, window: window?, threshold: threshold? }
            }
            "duplicates" => {
                let paths = paths(self)?;
                let min_match = self.req(m, "minMatch", p, "INS-050").and_then(|v| self.uint(v, &at(p, "minMatch"), "INS-050"))?;
                if min_match == 0 || min_match as usize > paths.len() {
                    self.f.error("INS-050", at(p, "minMatch"), "minMatch is between 1 and the number of paths");
                }
                CheckKind::Duplicates { paths, min_match }
            }
            "timing" => {
                let min_seconds = m.get("minSeconds").and_then(|v| self.uint(v, &at(p, "minSeconds"), "INS-050")).map(u64::from);
                let max_seconds = m.get("maxSeconds").and_then(|v| self.uint(v, &at(p, "maxSeconds"), "INS-050")).map(u64::from);
                if min_seconds.is_none() && max_seconds.is_none() {
                    self.f.error("INS-050", p, "a timing check needs minSeconds, maxSeconds or both");
                }
                if let (Some(a), Some(b)) = (min_seconds, max_seconds)
                    && a > b {
                        self.f.error("INS-050", at(p, "minSeconds"), "minSeconds is greater than maxSeconds");
                    }
                CheckKind::Timing { min_seconds, max_seconds }
            }
            "completeness" => {
                let scope = match (m.contains_key("group"), m.contains_key("paths")) {
                    (true, false) => CheckScopeDef::Group(path(self, "group")?),
                    (false, true) => CheckScopeDef::Paths(paths(self)?),
                    _ => {
                        self.f.error("INS-050", p, "give `group` or `paths`, not both or neither");
                        return None;
                    }
                };
                CheckKind::Completeness { scope, threshold: self.share(m, p)? }
            }
            _ => CheckKind::Straightlining { group: path(self, "group")?, threshold: self.share(m, p)? },
        };
        Some(FieldCheckDef { id: id?, kind, message: message?, doc_path: p.to_owned() })
    }
}
