//! The declarative schema of the compact authoring dialect (WIRE-209 to WIRE-211, ADR 0040).
//!
//! Every authoring key of a survey, a layout and a compact roster is declared once, in the table
//! at the end of this file: its type, whether it is required, a one-line description, and whether
//! it has a rule the table cannot say. Two readers use that table and nothing else: [`check`]
//! validates a decoded document and reports each problem as a [`SchemaError`], and
//! [`json_schema`] generates the closed JSON Schema that editors read. The expander in the
//! authoring adapter reads keys through [`Reader`], which refuses (in debug builds) a key the
//! table does not declare.
//!
//! The module is pure. It reads no file and holds no clock; the decoders in the authoring adapter
//! do the I/O and the position tracking, and report [`SchemaErrorKind::DuplicateKey`] and
//! [`SchemaErrorKind::CoercionRefused`] themselves, because those problems are gone by the time a
//! [`Value`] exists.
//!
//! # Shapes
//!
//! A [`Shape`] is the set of keys one map may hold. Most shapes are *closed*: any other key is an
//! [`SchemaErrorKind::UnknownField`]. Two forms select a shape from the document instead:
//!
//! - *tagged*: the text under one key (a question's `type`) names the shape;
//! - *present*: the first listed key that the map holds names the shape (a section entry is a
//!   question when it has `type`, a display when it has `display`, otherwise a group).
//!
//! A *single* shape is a map of exactly one key, which names an operator (a condition or an
//! operand). A shape may `include` others, so keys shared by the question types are declared once.
//! Where a position can hold more than one kind of value (a list that is written as a bare list of
//! items or as a map with `items`), [`Ty::OneOf`] chooses the alternative by the kind of the value
//! (text, number, boolean, list, map), so the alternatives never overlap.

use std::collections::{BTreeMap, BTreeSet};

use crate::value::Value;

type Map = BTreeMap<String, Value>;

/// Which family of authoring documents a schema describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DocKind {
    /// `instrument.yaml`: a survey in the compact dialect.
    Survey,
    /// A layout in the compact dialect.
    Layout,
    /// A roster in the compact dialect.
    Roster,
}

impl DocKind {
    /// The kind of a compact document: its top-level `survey`, `layout` or `roster` key. A
    /// canonical document (it has `apiVersion`) has no compact kind.
    #[must_use]
    pub fn detect(doc: &Value) -> Option<Self> {
        let m = doc.as_map()?;
        if m.contains_key("apiVersion") {
            None
        } else if m.contains_key("survey") {
            Some(Self::Survey)
        } else if m.contains_key("layout") {
            Some(Self::Layout)
        } else if m.contains_key("roster") {
            Some(Self::Roster)
        } else {
            None
        }
    }

    /// The name used in `fieldseal schema export --kind`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Survey => "survey",
            Self::Layout => "layout",
            Self::Roster => "roster",
        }
    }
}

/// The name of one shape, for example `survey.item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShapeId(pub &'static str);

/// A position in a document, from its root, with `*` for any map key or array index (for example
/// `lists/*/items/*/label`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PathPattern(pub Vec<&'static str>);

impl std::fmt::Display for PathPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "/{}", self.0.join("/"))
    }
}

/// The type of one declared key.
#[derive(Debug, Clone, Copy)]
pub enum Ty {
    /// Non-empty text.
    Text,
    /// Text, possibly empty (a label that is copied as written).
    AnyText,
    /// A whole number.
    Integer,
    /// A whole number or a decimal.
    Number,
    /// `true` or `false`.
    Boolean,
    /// Anything: the value is copied through and checked by a later reader.
    Any,
    /// One of the listed texts.
    Enum(&'static [&'static str]),
    /// A list whose items all have the type.
    List(&'static Ty),
    /// A map of the shape.
    Map(ShapeId),
    /// A map of a shape declared elsewhere (a shared or recursive shape).
    Ref(ShapeId),
    /// A map whose keys are chosen by the author (names of lists, tables, languages) and whose
    /// values all have the type.
    Dict(&'static Ty),
    /// An ordered list written as single-key maps (`- id: value`); the values have the type.
    Entries(&'static Ty),
    /// One of several kinds of value, chosen by the value's own kind.
    OneOf(&'static [Ty]),
}

/// One key a map may hold.
#[derive(Debug, Clone, Copy)]
pub struct KeySpec {
    /// The key as written.
    pub name: &'static str,
    /// What its value is.
    pub ty: Ty,
    /// Whether the map must hold it.
    pub required: bool,
    /// One line for the author.
    pub doc: &'static str,
    /// The rule about this key that the table cannot state and the expander checks in code.
    pub cross_key: Option<&'static str>,
}

/// How the shape that applies to a map is chosen.
#[derive(Debug, Clone, Copy)]
pub enum Select {
    /// The shape itself: a closed set of keys.
    Closed,
    /// A map of exactly one key, which names an operator.
    Single,
    /// The text under `key` picks the shape.
    Tagged {
        /// The key that holds the tag.
        key: &'static str,
        /// Each tag and the shape it selects.
        cases: &'static [(&'static str, ShapeId)],
    },
    /// The first listed key the map holds picks the shape.
    Present {
        /// Each key and the shape it selects.
        cases: &'static [(&'static str, ShapeId)],
        /// The shape when none of the keys is held; none means the map is refused.
        otherwise: Option<ShapeId>,
    },
}

/// The keys one map may hold.
#[derive(Debug, Clone, Copy)]
pub struct Shape {
    /// The shape's name.
    pub id: ShapeId,
    /// How a map is matched to a shape.
    pub select: Select,
    /// The keys this shape declares itself.
    pub keys: &'static [KeySpec],
    /// Other shapes whose keys this shape also holds.
    pub includes: &'static [ShapeId],
    /// One line for the author.
    pub doc: &'static str,
}

/// What was wrong with a document (WIRE-211, and no other).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SchemaErrorKind {
    /// A key the schema does not declare.
    UnknownField,
    /// A required key is absent.
    MissingField,
    /// A value of the wrong kind.
    TypeMismatch,
    /// Text outside the allowed values.
    EnumValue,
    /// A key written twice (reported by the decoders).
    DuplicateKey,
    /// A value the decoder refused to read as a number, boolean or null (reported by the decoders).
    CoercionRefused,
}

impl SchemaErrorKind {
    /// All six kinds.
    pub const ALL: [Self; 6] = [Self::UnknownField, Self::MissingField, Self::TypeMismatch, Self::EnumValue, Self::DuplicateKey, Self::CoercionRefused];

    /// The kind's name as findings print it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::UnknownField => "UnknownField",
            Self::MissingField => "MissingField",
            Self::TypeMismatch => "TypeMismatch",
            Self::EnumValue => "EnumValue",
            Self::DuplicateKey => "DuplicateKey",
            Self::CoercionRefused => "CoercionRefused",
        }
    }

    /// The kind with the given name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
}

impl std::fmt::Display for SchemaErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// One problem found in a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError {
    /// Where, as an RFC 6901 JSON Pointer. A missing key is named by the pointer it would have.
    pub pointer: String,
    /// What kind of problem.
    pub kind: SchemaErrorKind,
    /// A message for the author, without the pointer.
    pub message: String,
}

/// A JSON Pointer segment: `~` is written `~0` and `/` is written `~1` (RFC 6901).
#[must_use]
pub fn escape_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

/// The pointer of a child of `parent`.
#[must_use]
pub fn child_pointer(parent: &str, segment: &str) -> String {
    format!("{parent}/{}", escape_segment(segment))
}

// ---- API --------------------------------------------------------------------------------------

/// Every shape of every kind.
#[must_use]
pub fn shapes() -> &'static [Shape] {
    SHAPES
}

/// The shape with this id.
#[must_use]
pub fn shape(id: ShapeId) -> Option<&'static Shape> {
    SHAPES.iter().find(|s| s.id == id)
}

/// The root shape of a kind.
#[must_use]
pub fn root(kind: DocKind) -> ShapeId {
    match kind {
        DocKind::Survey => ShapeId("survey"),
        DocKind::Layout => ShapeId("layout"),
        DocKind::Roster => ShapeId("roster"),
    }
}

/// Validates a decoded document against the schema of `kind`, reporting every problem.
#[must_use]
pub fn check(doc: &Value, kind: DocKind) -> Vec<SchemaError> {
    check_shape(doc, root(kind), "")
}

/// Validates `value`, found at `pointer`, as a map of `shape`.
#[must_use]
pub fn check_shape(value: &Value, shape: ShapeId, pointer: &str) -> Vec<SchemaError> {
    let mut walk = Walk::default();
    walk.ty(&Ty::Map(shape), value, pointer);
    walk.errors
}

/// Every map in `doc` and the concrete shape it is read as, by pointer, in document order of the
/// walk. A map that does not match any shape is left out.
#[must_use]
pub fn shapes_in(doc: &Value, kind: DocKind) -> Vec<(String, ShapeId)> {
    let mut walk = Walk { visits: Some(Vec::new()), ..Walk::default() };
    walk.ty(&Ty::Map(root(kind)), doc, "");
    walk.visits.unwrap_or_default()
}

/// The keys a concrete shape holds, its included shapes' keys too.
#[must_use]
pub fn keys_of(id: ShapeId) -> Vec<&'static KeySpec> {
    let mut out = Vec::new();
    collect_keys(id, &mut out);
    out
}

fn collect_keys(id: ShapeId, out: &mut Vec<&'static KeySpec>) {
    if let Some(s) = shape(id) {
        out.extend(s.keys.iter());
        for inc in s.includes {
            collect_keys(*inc, out);
        }
    }
}

/// The shape a map is read as: the shape itself, or the case a tagged or present shape selects.
/// None when the map selects nothing.
#[must_use]
pub fn resolve(map: &Map, id: ShapeId) -> Option<ShapeId> {
    let s = shape(id)?;
    match s.select {
        Select::Closed | Select::Single => Some(id),
        Select::Tagged { key, cases } => {
            let tag = map.get(key)?.as_text()?;
            cases.iter().find(|(t, _)| *t == tag).and_then(|(_, c)| resolve(map, *c))
        }
        Select::Present { cases, otherwise } => {
            let case = cases.iter().find(|(k, _)| map.contains_key(*k)).map(|(_, c)| *c).or(otherwise)?;
            resolve(map, case)
        }
    }
}

/// Whether the shallow kind of `value` (text, number, boolean, list or map) is one `ty` takes.
#[must_use]
pub fn accepts_kind(ty: &Ty, value: &Value) -> bool {
    match ty {
        Ty::Any => true,
        Ty::OneOf(alts) => alts.iter().any(|a| accepts_kind(a, value)),
        _ => class_of_ty(ty).is_some_and(|c| c == class_of(value)),
    }
}

/// Every path pattern at which each shape applies, found by walking from the root of `kind`.
#[must_use]
pub fn paths(kind: DocKind) -> Vec<(PathPattern, ShapeId)> {
    let mut out = Vec::new();
    let mut on_path = Vec::new();
    paths_of_shape(root(kind), &mut Vec::new(), &mut on_path, &mut out);
    out.sort();
    out.dedup();
    out
}

fn paths_of_shape(id: ShapeId, at: &mut Vec<&'static str>, on_path: &mut Vec<ShapeId>, out: &mut Vec<(PathPattern, ShapeId)>) {
    let Some(s) = shape(id) else { return };
    out.push((PathPattern(at.clone()), id));
    if on_path.contains(&id) {
        return;
    }
    on_path.push(id);
    match s.select {
        Select::Tagged { cases, .. } => cases.iter().for_each(|(_, c)| paths_of_shape(*c, at, on_path, out)),
        Select::Present { cases, otherwise } => cases.iter().map(|(_, c)| *c).chain(otherwise).for_each(|c| paths_of_shape(c, at, on_path, out)),
        Select::Closed | Select::Single => {}
    }
    for k in keys_of(id) {
        at.push(k.name);
        paths_of_ty(&k.ty, at, on_path, out);
        at.pop();
    }
    on_path.pop();
}

fn paths_of_ty(ty: &Ty, at: &mut Vec<&'static str>, on_path: &mut Vec<ShapeId>, out: &mut Vec<(PathPattern, ShapeId)>) {
    match ty {
        Ty::Map(id) | Ty::Ref(id) => paths_of_shape(*id, at, on_path, out),
        Ty::List(inner) | Ty::Dict(inner) | Ty::Entries(inner) => {
            at.push("*");
            paths_of_ty(inner, at, on_path, out);
            if matches!(ty, Ty::Entries(_)) {
                at.push("*");
                paths_of_ty(inner, at, on_path, out);
                at.pop();
            }
            at.pop();
        }
        Ty::OneOf(alts) => alts.iter().for_each(|a| paths_of_ty(a, at, on_path, out)),
        Ty::Text | Ty::AnyText | Ty::Integer | Ty::Number | Ty::Boolean | Ty::Any | Ty::Enum(_) => {}
    }
}

// ---- the validator ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Text,
    Number,
    Bool,
    Array,
    Map,
    Bytes,
}

fn class_of(v: &Value) -> Class {
    match v {
        Value::Text(_) => Class::Text,
        Value::Int(_) | Value::Decimal(_) => Class::Number,
        Value::Bool(_) => Class::Bool,
        Value::Array(_) => Class::Array,
        Value::Map(_) => Class::Map,
        Value::Bytes(_) => Class::Bytes,
    }
}

fn class_of_ty(ty: &Ty) -> Option<Class> {
    match ty {
        Ty::Text | Ty::AnyText | Ty::Enum(_) => Some(Class::Text),
        Ty::Integer | Ty::Number => Some(Class::Number),
        Ty::Boolean => Some(Class::Bool),
        Ty::List(_) | Ty::Entries(_) => Some(Class::Array),
        Ty::Map(_) | Ty::Ref(_) | Ty::Dict(_) => Some(Class::Map),
        Ty::Any | Ty::OneOf(_) => None,
    }
}

fn describe(ty: &Ty) -> String {
    match ty {
        Ty::Text => "non-empty text".into(),
        Ty::AnyText => "text".into(),
        Ty::Integer => "a whole number".into(),
        Ty::Number => "a number".into(),
        Ty::Boolean => "true or false".into(),
        Ty::Any => "any value".into(),
        Ty::Enum(values) => format!("one of {}", values.join(", ")),
        Ty::List(_) => "a list".into(),
        Ty::Entries(_) => "a list of `- <id>: <value>` entries".into(),
        Ty::Map(_) | Ty::Ref(_) => "a map".into(),
        Ty::Dict(_) => "a map of names".into(),
        Ty::OneOf(alts) => alts.iter().map(describe).collect::<Vec<_>>().join(" or "),
    }
}

#[derive(Default)]
struct Walk {
    errors: Vec<SchemaError>,
    visits: Option<Vec<(String, ShapeId)>>,
}

impl Walk {
    fn error(&mut self, pointer: &str, kind: SchemaErrorKind, message: impl Into<String>) {
        self.errors.push(SchemaError { pointer: pointer.to_owned(), kind, message: message.into() });
    }

    fn mismatch(&mut self, ty: &Ty, pointer: &str) {
        self.error(pointer, SchemaErrorKind::TypeMismatch, format!("expected {}", describe(ty)));
    }

    fn ty(&mut self, ty: &Ty, value: &Value, pointer: &str) {
        match (ty, value) {
            (Ty::Any, _) | (Ty::AnyText, Value::Text(_)) | (Ty::Number, Value::Int(_) | Value::Decimal(_)) | (Ty::Integer, Value::Int(_)) | (Ty::Boolean, Value::Bool(_)) => {}
            (Ty::Text, Value::Text(s)) => {
                if s.is_empty() {
                    self.error(pointer, SchemaErrorKind::TypeMismatch, "expected non-empty text");
                }
            }
            (Ty::Enum(values), Value::Text(s)) => {
                if !values.contains(&s.as_str()) {
                    self.error(pointer, SchemaErrorKind::EnumValue, format!("`{s}` is not allowed; expected {}", values.join(", ")));
                }
            }
            (Ty::List(inner), Value::Array(items)) => {
                for (i, item) in items.iter().enumerate() {
                    self.ty(inner, item, &child_pointer(pointer, &i.to_string()));
                }
            }
            (Ty::Dict(inner), Value::Map(m)) => {
                for (k, v) in m {
                    self.ty(inner, v, &child_pointer(pointer, k));
                }
            }
            (Ty::Entries(inner), Value::Array(items)) => {
                for (i, item) in items.iter().enumerate() {
                    let ip = child_pointer(pointer, &i.to_string());
                    match item.as_map() {
                        Some(m) if m.len() == 1 => {
                            if let Some((k, v)) = m.iter().next() {
                                self.ty(inner, v, &child_pointer(&ip, k));
                            }
                        }
                        _ => self.error(&ip, SchemaErrorKind::TypeMismatch, "expected exactly one key, `- <id>: <value>`"),
                    }
                }
            }
            (Ty::Map(id) | Ty::Ref(id), Value::Map(m)) => self.shape(*id, m, pointer),
            (Ty::OneOf(alts), v) => match alts.iter().find(|a| accepts_kind(a, v)) {
                Some(alt) => self.ty(alt, v, pointer),
                None => self.mismatch(ty, pointer),
            },
            _ => self.mismatch(ty, pointer),
        }
    }

    fn shape(&mut self, id: ShapeId, m: &Map, pointer: &str) {
        let Some(s) = shape(id) else {
            self.error(pointer, SchemaErrorKind::TypeMismatch, format!("no shape {}", id.0));
            return;
        };
        match s.select {
            Select::Closed => self.closed(id, m, pointer, false),
            Select::Single => self.closed(id, m, pointer, true),
            Select::Tagged { key, cases } => match m.get(key) {
                None => self.error(&child_pointer(pointer, key), SchemaErrorKind::MissingField, "is required"),
                Some(Value::Text(tag)) => match cases.iter().find(|(t, _)| t == tag) {
                    Some((_, case)) => self.shape(*case, m, pointer),
                    None => {
                        let allowed: Vec<&str> = cases.iter().map(|(t, _)| *t).collect();
                        self.error(&child_pointer(pointer, key), SchemaErrorKind::EnumValue, format!("`{tag}` is not allowed; expected {}", allowed.join(", ")));
                    }
                },
                Some(_) => self.error(&child_pointer(pointer, key), SchemaErrorKind::TypeMismatch, "expected text"),
            },
            Select::Present { cases, otherwise } => match cases.iter().find(|(k, _)| m.contains_key(*k)).map(|(_, c)| *c).or(otherwise) {
                Some(case) => self.shape(case, m, pointer),
                None => {
                    let allowed: Vec<&str> = cases.iter().map(|(k, _)| *k).collect();
                    self.error(pointer, SchemaErrorKind::TypeMismatch, format!("expected one of {}", allowed.join(", ")));
                }
            },
        }
    }

    fn closed(&mut self, id: ShapeId, m: &Map, pointer: &str, single: bool) {
        if let Some(visits) = &mut self.visits {
            visits.push((pointer.to_owned(), id));
        }
        let keys = keys_of(id);
        if single && m.len() != 1 {
            let names: Vec<&str> = keys.iter().map(|k| k.name).collect();
            self.error(pointer, SchemaErrorKind::TypeMismatch, format!("expected exactly one of {}", names.join(", ")));
        }
        for (k, v) in m {
            let kp = child_pointer(pointer, k);
            match keys.iter().find(|spec| spec.name == k) {
                Some(spec) => self.ty(&spec.ty, v, &kp),
                None => self.error(&kp, SchemaErrorKind::UnknownField, "unknown key"),
            }
        }
        for spec in keys.iter().filter(|spec| spec.required && !m.contains_key(spec.name)) {
            self.error(&child_pointer(pointer, spec.name), SchemaErrorKind::MissingField, "is required");
        }
    }
}

// ---- accessors -------------------------------------------------------------------------------

/// Reads the keys of one map that the validator has already accepted. In debug builds a read of a
/// key the shape does not declare panics, so the expander cannot use a key the table lacks.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    map: &'a Map,
    shape: ShapeId,
}

impl<'a> Reader<'a> {
    /// A reader over `map`, read as `shape`. A tagged or present shape is resolved to the case
    /// that `map` selects.
    #[must_use]
    pub fn new(map: &'a Map, shape: ShapeId) -> Self {
        Self { map, shape: resolve(map, shape).unwrap_or(shape) }
    }

    /// The concrete shape this reader was resolved to.
    #[must_use]
    pub fn shape(&self) -> ShapeId {
        self.shape
    }

    fn declared(&self, key: &str) {
        debug_assert!(keys_of(self.shape).iter().any(|k| k.name == key), "key `{key}` is not declared in shape {}", self.shape.0);
    }

    /// The value under `key`, whatever it is.
    #[must_use]
    pub fn raw(&self, key: &str) -> Option<&'a Value> {
        self.declared(key);
        self.map.get(key)
    }

    /// The text under `key`.
    #[must_use]
    pub fn text(&self, key: &str) -> Option<&'a str> {
        self.raw(key).and_then(Value::as_text)
    }

    /// The whole number under `key`.
    #[must_use]
    pub fn int(&self, key: &str) -> Option<i128> {
        self.raw(key).and_then(Value::as_int)
    }

    /// The boolean under `key`.
    #[must_use]
    pub fn flag(&self, key: &str) -> Option<bool> {
        self.raw(key).and_then(Value::as_bool)
    }

    /// The list under `key`.
    #[must_use]
    pub fn list(&self, key: &str) -> Option<&'a [Value]> {
        self.raw(key).and_then(Value::as_array)
    }

    /// The map under `key`.
    #[must_use]
    pub fn map(&self, key: &str) -> Option<&'a Map> {
        self.raw(key).and_then(Value::as_map)
    }
}

// ---- the JSON Schema -------------------------------------------------------------------------

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn obj<const N: usize>(pairs: [(&str, Value); N]) -> Map {
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

fn type_schema(name: &str) -> Map {
    obj([("type", text(name))])
}

fn ty_schema(ty: &Ty) -> Value {
    let m = match ty {
        Ty::Text => obj([("type", text("string")), ("minLength", Value::Int(1))]),
        Ty::AnyText => type_schema("string"),
        Ty::Integer => type_schema("integer"),
        Ty::Number => type_schema("number"),
        Ty::Boolean => type_schema("boolean"),
        Ty::Any => Map::new(),
        Ty::Enum(values) => obj([("type", text("string")), ("enum", Value::Array(values.iter().map(|v| text(v)).collect()))]),
        Ty::List(inner) => obj([("type", text("array")), ("items", ty_schema(inner))]),
        Ty::Map(id) | Ty::Ref(id) => obj([("$ref", text(&format!("#/$defs/{}", id.0)))]),
        Ty::Dict(inner) => obj([("type", text("object")), ("additionalProperties", ty_schema(inner))]),
        Ty::Entries(inner) => {
            let entry = obj([("type", text("object")), ("minProperties", Value::Int(1)), ("maxProperties", Value::Int(1)), ("additionalProperties", ty_schema(inner))]);
            obj([("type", text("array")), ("items", Value::Map(entry))])
        }
        Ty::OneOf(alts) => obj([("anyOf", Value::Array(alts.iter().map(ty_schema).collect()))]),
    };
    Value::Map(m)
}

fn reference(id: ShapeId) -> Value {
    Value::Map(obj([("$ref", text(&format!("#/$defs/{}", id.0)))]))
}

fn shape_schema(s: &Shape) -> Value {
    let mut m = Map::new();
    m.insert("description".into(), text(s.doc));
    match s.select {
        Select::Tagged { cases, .. } => {
            let ids: BTreeSet<ShapeId> = cases.iter().map(|(_, c)| *c).collect();
            m.insert("oneOf".into(), Value::Array(ids.into_iter().map(reference).collect()));
        }
        Select::Present { cases, otherwise } => {
            let ids: BTreeSet<ShapeId> = cases.iter().map(|(_, c)| *c).chain(otherwise).collect();
            m.insert("oneOf".into(), Value::Array(ids.into_iter().map(reference).collect()));
        }
        Select::Closed | Select::Single => {
            let keys = keys_of(s.id);
            m.insert("type".into(), text("object"));
            let mut props = Map::new();
            for k in &keys {
                let Value::Map(mut p) = ty_schema(&k.ty) else { continue };
                p.insert("description".into(), text(k.doc));
                props.insert(k.name.to_owned(), Value::Map(p));
            }
            m.insert("properties".into(), Value::Map(props));
            let mut required: Vec<&str> = keys.iter().filter(|k| k.required).map(|k| k.name).collect();
            required.sort_unstable();
            if !required.is_empty() {
                m.insert("required".into(), Value::Array(required.into_iter().map(text).collect()));
            }
            m.insert("additionalProperties".into(), Value::Bool(false));
            if matches!(s.select, Select::Single) {
                m.insert("minProperties".into(), Value::Int(1));
                m.insert("maxProperties".into(), Value::Int(1));
            }
        }
    }
    Value::Map(m)
}

fn reachable(id: ShapeId, seen: &mut BTreeSet<ShapeId>) {
    if !seen.insert(id) {
        return;
    }
    let Some(s) = shape(id) else { return };
    match s.select {
        Select::Tagged { cases, .. } => cases.iter().for_each(|(_, c)| reachable(*c, seen)),
        Select::Present { cases, otherwise } => cases.iter().map(|(_, c)| *c).chain(otherwise).for_each(|c| reachable(c, seen)),
        Select::Closed | Select::Single => {}
    }
    for inc in s.includes {
        reachable(*inc, seen);
    }
    for k in keys_of(id) {
        ty_shapes(&k.ty, seen);
    }
}

fn ty_shapes(ty: &Ty, seen: &mut BTreeSet<ShapeId>) {
    match ty {
        Ty::Map(id) | Ty::Ref(id) => reachable(*id, seen),
        Ty::List(inner) | Ty::Dict(inner) | Ty::Entries(inner) => ty_shapes(inner, seen),
        Ty::OneOf(alts) => alts.iter().for_each(|a| ty_shapes(a, seen)),
        Ty::Text | Ty::AnyText | Ty::Integer | Ty::Number | Ty::Boolean | Ty::Any | Ty::Enum(_) => {}
    }
}

/// The closed JSON Schema (draft 2020-12) of a kind, generated from the same table [`check`] reads.
#[must_use]
pub fn json_schema(kind: DocKind) -> Value {
    let mut ids = BTreeSet::new();
    reachable(root(kind), &mut ids);
    let defs: Map = ids.iter().filter_map(|id| shape(*id).map(|s| (id.0.to_owned(), shape_schema(s)))).collect();
    let mut m = obj([
        ("$schema", text("https://json-schema.org/draft/2020-12/schema")),
        ("$id", text(&format!("https://fieldseal.dev/schema/authoring/{}.json", kind.name()))),
        ("title", text(&format!("A Fieldseal {} in the compact authoring dialect", kind.name()))),
        ("$ref", text(&format!("#/$defs/{}", root(kind).0))),
    ]);
    m.insert("$defs".into(), Value::Map(defs));
    Value::Map(m)
}

// ---- the table -------------------------------------------------------------------------------

const fn key(name: &'static str, ty: Ty, doc: &'static str) -> KeySpec {
    KeySpec { name, ty, required: false, doc, cross_key: None }
}

const fn req(name: &'static str, ty: Ty, doc: &'static str) -> KeySpec {
    KeySpec { name, ty, required: true, doc, cross_key: None }
}

impl KeySpec {
    const fn cross(self, rule: &'static str) -> Self {
        Self { cross_key: Some(rule), ..self }
    }
}

const fn closed(id: &'static str, doc: &'static str, keys: &'static [KeySpec]) -> Shape {
    Shape { id: ShapeId(id), select: Select::Closed, keys, includes: &[], doc }
}

const fn closed_with(id: &'static str, doc: &'static str, includes: &'static [ShapeId], keys: &'static [KeySpec]) -> Shape {
    Shape { id: ShapeId(id), select: Select::Closed, keys, includes, doc }
}

const fn single(id: &'static str, doc: &'static str, keys: &'static [KeySpec]) -> Shape {
    Shape { id: ShapeId(id), select: Select::Single, keys, includes: &[], doc }
}

const fn tagged(id: &'static str, doc: &'static str, tag: &'static str, cases: &'static [(&'static str, ShapeId)]) -> Shape {
    Shape { id: ShapeId(id), select: Select::Tagged { key: tag, cases }, keys: &[], includes: &[], doc }
}

const fn present(id: &'static str, doc: &'static str, cases: &'static [(&'static str, ShapeId)], otherwise: Option<ShapeId>) -> Shape {
    Shape { id: ShapeId(id), select: Select::Present { cases, otherwise }, keys: &[], includes: &[], doc }
}

const TEXT: Ty = Ty::Text;
const ANY_TEXT: Ty = Ty::AnyText;
const NUMBER: Ty = Ty::Number;
const FLAG: Ty = Ty::Boolean;
const ANY: Ty = Ty::Any;
const TEXTS: Ty = Ty::List(&ANY_TEXT);
const CONDITION: Ty = Ty::Ref(ShapeId("survey.condition"));
const CONDITIONS: Ty = Ty::List(&CONDITION);
const OPERAND_NODE: Ty = Ty::Ref(ShapeId("survey.operand"));
/// An operand: a question id, a number or an arithmetic or lookup node.
const OPERAND: Ty = Ty::OneOf(&[TEXT, NUMBER, OPERAND_NODE]);
/// The right side of a comparison: an operand, or `true` or `false`.
const LITERAL: Ty = Ty::OneOf(&[TEXT, NUMBER, FLAG, OPERAND_NODE]);
const ITEM: Ty = Ty::OneOf(&[ANY_TEXT, Ty::Map(ShapeId("survey.item"))]);
const FOOD: Ty = Ty::OneOf(&[ANY_TEXT, Ty::Map(ShapeId("survey.food"))]);
const LIST: Ty = Ty::OneOf(&[Ty::List(&ITEM), Ty::Map(ShapeId("survey.list"))]);
const SCALE_STEP: Ty = Ty::OneOf(&[Ty::Enum(&["never"]), Ty::Map(ShapeId("survey.scale-step"))]);
const ELEMENT: Ty = Ty::Ref(ShapeId("survey.element"));
const QUESTION: Ty = Ty::Ref(ShapeId("survey.question"));
const CHECKS: Ty = Ty::List(&Ty::Map(ShapeId("survey.check")));
const CONTENT: Ty = Ty::Ref(ShapeId("layout.content"));
const CONTENTS: Ty = Ty::List(&CONTENT);
const TITLED: Ty = Ty::Ref(ShapeId("layout.titled"));

/// The keys every question type holds.
const QUESTION_COMMON: &[KeySpec] = &[
    key("prefix", TEXT, "The number or letter shown before the question, written as text."),
    key("label", TEXT, "The question text; made from the id when omitted."),
    key("help", TEXT, "A line of help under the question."),
    key("guidance", TEXT, "Guidance for the interviewer."),
    key("if", CONDITION, "A condition; the question is asked only when it holds."),
    key("disabled-display", TEXT, "What to show when the condition does not hold."),
    key("optional", FLAG, "True when the question may be left unanswered."),
    key("nonresponse", TEXTS, "The nonresponse codes offered, replacing the survey's."),
    key("sensitive", FLAG, "True for special-category data."),
    key("concept", ANY, "Concept codes that say what the question measures."),
    key("presentation", TEXT, "How a control is drawn."),
];

static SHAPES: &[Shape] = &[
    // ---- survey ----
    closed("survey", "A survey in the compact dialect (ADR 0040).", &[
        req("survey", Ty::Map(ShapeId("survey.id")), "The survey's name and version."),
        key("language", TEXT, "The language the text is written in; `en` when omitted."),
        key("title", TEXT, "The survey's title."),
        key("description", TEXT, "What the survey is."),
        key("purpose", TEXT, "Why the data is collected."),
        key("administration", TEXT, "Who fills it in: interviewer, self or both."),
        key("publisher", TEXT, "Who publishes the survey."),
        key("copyright", ANY, "The copyright notice and licence."),
        key("derived-from", ANY, "The survey this one was derived from."),
        key("translations", Ty::Dict(&Ty::Map(ShapeId("survey.translation"))), "How each translation was made; each language needs a catalogue.").cross("each language needs a catalogue"),
        key("nonresponse", TEXTS, "The nonresponse codes offered by default."),
        key("defaults", Ty::Map(ShapeId("survey.defaults")), "Settings applied to every question."),
        key("consent", Ty::Map(ShapeId("survey.consent")), "The consent the survey asks for."),
        key("lists", Ty::Dict(&LIST), "Code lists by name."),
        key("scales", Ty::Dict(&Ty::List(&SCALE_STEP)), "Frequency scales by name, from steps."),
        key("tables", Ty::Dict(&Ty::Dict(&ANY)), "Lookup tables by name: rows of key and value."),
        req("sections", Ty::Entries(&ELEMENT), "The survey's content, in order: `- id: {…}`."),
        key("checks", CHECKS, "Rules over the whole survey.").cross("a condition may name only questions that exist"),
        key("field-checks", Ty::List(&Ty::Map(ShapeId("survey.field-check"))), "Checks on how the survey was filled in, such as time spent."),
    ]),
    closed("survey.id", "The survey's name and version.", &[
        req("name", TEXT, "The survey's name."),
        req("version", TEXT, "The survey's version."),
    ]),
    closed("survey.translation", "How one translation was made.", &[
        key("method", TEXT, "How the translation was made."),
        key("reviewed-by", NUMBER, "How many people reviewed it."),
        key("notes", TEXT, "Notes on the translation."),
    ]),
    closed("survey.defaults", "Settings applied to every question.", &[
        key("other-text", Ty::Map(ShapeId("survey.other-text")), "The default for every list's `other` entry."),
        key("disabled-display", TEXT, "What a conditional question shows when its condition does not hold."),
    ]),
    closed("survey.other-text", "The default for `other` entries.", &[key("max-length", NUMBER, "The longest text an `other` entry may hold.")]),
    closed("survey.consent", "The consent the survey asks for.", &[
        key("required", FLAG, "True when consent must be given."),
        key("bases", Ty::Entries(&ANY_TEXT), "The legal bases: `- code: label`."),
        key("statement", Ty::Map(ShapeId("survey.consent-statement")), "The statement read to the subject."),
        key("evidence", TEXT, "How consent is evidenced."),
    ]),
    closed("survey.consent-statement", "The consent statement.", &[
        req("version", NUMBER, "The statement's version."),
        req("text", TEXT, "The statement."),
    ]),
    closed("survey.list", "A code list with settings.", &[
        req("items", Ty::List(&ITEM), "The list's items."),
        key("ordered", FLAG, "True when the order of the items has meaning."),
        key("other", Ty::OneOf(&[ANY_TEXT, Ty::Map(ShapeId("survey.list-other"))]), "An `other` entry: its label, or its label and length."),
    ]),
    closed("survey.list-other", "An `other` entry with settings.", &[
        req("label", TEXT, "The entry's label."),
        key("max-length", NUMBER, "The longest text the entry may hold."),
    ]),
    closed("survey.item", "One item of a code list.", &[
        req("label", TEXT, "The item's label."),
        key("code", TEXT, "The item's code; the label's slug when omitted."),
        key("description", TEXT, "A line describing the item."),
        key("icon", TEXT, "The item's icon."),
        key("concept", ANY, "Concept codes for the item."),
        key("exclusive", FLAG, "True when choosing it excludes every other item."),
    ]),
    closed_with("survey.food", "A food of a category: an item that may override the block's questions.", &[ShapeId("survey.item")], &[
        key("ask", Ty::Dict(&Ty::Map(ShapeId("survey.override"))), "Overrides of the block's questions for this food: `{ <question>: { settings } }`."),
    ]),
    closed("survey.override", "A food's settings for one question.", &[
        key("unit", TEXT, "The unit."),
        key("unit-label", TEXT, "The unit's label."),
        key("min", NUMBER, "The smallest value."),
        key("max", NUMBER, "The largest value."),
        key("step", NUMBER, "The step."),
        key("start", NUMBER, "The starting value."),
    ]),
    closed("survey.scale-step", "One step of a frequency scale.", &[
        req("per", Ty::Enum(&["day", "week", "month"]), "The period the step counts in."),
        key("at-most", Ty::Integer, "At most this many per period.").cross("a positive whole number; one of at-most, exactly, more-than, each or from and to"),
        key("exactly", Ty::Integer, "Exactly this many per period.").cross("a positive whole number"),
        key("more-than", Ty::Integer, "More than this many per period.").cross("a positive whole number"),
        key("each", Ty::Map(ShapeId("survey.scale-each")), "One step for each whole number in a range."),
        key("from", Ty::Integer, "The least number in a range.").cross("a positive whole number"),
        key("to", Ty::Integer, "The greatest number in a range.").cross("a positive whole number"),
    ]),
    closed("survey.scale-each", "A range of whole numbers, one step each.", &[
        req("from", Ty::Integer, "The least number.").cross("a positive whole number"),
        req("to", Ty::Integer, "The greatest number.").cross("a positive whole number"),
    ]),
    present("survey.element", "A section entry: a question, a display text or a group.", &[("type", ShapeId("survey.question")), ("display", ShapeId("survey.display"))], Some(ShapeId("survey.group"))),
    closed("survey.display", "A text shown to the person filling in the survey.", &[
        req("display", TEXT, "The text."),
        key("role", TEXT, "The text's role: how it is drawn."),
    ]),
    closed("survey.group", "A group of questions.", &[
        req("group", TEXT, "The group's label."),
        key("description", TEXT, "A line describing the group."),
        key("concept", ANY, "Concept codes for the group."),
        key("if", CONDITION, "A condition; the group is shown only when it holds."),
        key("disabled-display", TEXT, "What to show when the condition does not hold."),
        key("elements", Ty::Entries(&ELEMENT), "The group's content, in order."),
        key("categories", Ty::Map(ShapeId("survey.categories")), "Categories that each become a repeated group of the same questions."),
        key("checks", CHECKS, "Rules over the group."),
        key("end", ANY_TEXT, "A closing text shown after the group."),
    ]),
    closed("survey.categories", "Categories, each a repeat group over its own list of foods.", &[
        req("ask", Ty::Entries(&QUESTION), "The questions asked about every food."),
        key("checks", CHECKS, "Rules over each category."),
        req("blocks", Ty::List(&Ty::Map(ShapeId("survey.block"))), "The blocks of categories, each with its own reference period."),
    ]),
    closed("survey.block", "A block of categories sharing a reference period.", &[
        req("period", TEXT, "The reference period."),
        key("ask", Ty::Entries(&ANY), "Settings that replace the shared questions' for this block.").cross("the merged question is checked against survey.question"),
        req("categories", Ty::Entries(&Ty::Map(ShapeId("survey.category"))), "The categories: `- id: {…}`."),
    ]),
    closed("survey.category", "One category of foods.", &[
        req("label", TEXT, "The category's label."),
        req("foods", Ty::List(&FOOD), "The foods."),
        key("other", TEXT, "The label of an `other` entry."),
    ]),
    tagged("survey.question", "A question; its type decides which other keys it holds.", "type", &[
        ("choice", ShapeId("survey.question.choice")),
        ("choices", ShapeId("survey.question.choice")),
        ("scale", ShapeId("survey.question.scale")),
        ("binary", ShapeId("survey.question.binary")),
        ("stepper", ShapeId("survey.question.stepper")),
        ("number", ShapeId("survey.question.number")),
        ("money", ShapeId("survey.question.money")),
        ("measure-twice", ShapeId("survey.question.measure-twice")),
        ("text", ShapeId("survey.question.text")),
        ("date", ShapeId("survey.question.date")),
        ("roster", ShapeId("survey.question.roster")),
    ]),
    closed("survey.question.common", "The keys every question type holds.", QUESTION_COMMON),
    closed_with("survey.question.choice", "A choice from a list, or several.", &[ShapeId("survey.question.common")], &[
        req("type", Ty::Enum(&["choice", "choices"]), "The question type."),
        req("list", TEXT, "The name of the list.").cross("the list must exist"),
        key("max", NUMBER, "The most choices allowed."),
    ]),
    closed_with("survey.question.scale", "A choice on a frequency scale.", &[ShapeId("survey.question.common")], &[
        req("type", Ty::Enum(&["scale"]), "The question type."),
        req("scale", TEXT, "The name of the scale.").cross("the scale must exist"),
    ]),
    closed_with("survey.question.binary", "A yes or no question.", &[ShapeId("survey.question.common")], &[
        req("type", Ty::Enum(&["binary"]), "The question type."),
    ]),
    closed_with("survey.question.stepper", "A quantity set by steps.", &[ShapeId("survey.question.common")], &[
        req("type", Ty::Enum(&["stepper"]), "The question type."),
        req("unit", TEXT, "The unit."),
        key("min", NUMBER, "The smallest value."),
        key("max", NUMBER, "The largest value."),
        key("start", NUMBER, "The starting value."),
        key("step", NUMBER, "The step."),
    ]),
    closed_with("survey.question.number", "A number.", &[ShapeId("survey.question.common")], &[
        req("type", Ty::Enum(&["number"]), "The question type."),
        key("min", NUMBER, "The smallest value."),
        key("max", NUMBER, "The largest value."),
        key("decimals", NUMBER, "How many decimals are kept."),
        key("unit", TEXT, "The unit."),
        key("also", TEXTS, "Other units the answer may be entered in."),
        key("value", TEXT, "The value type; `integer` when there are no decimals, else `decimal`."),
    ]),
    closed_with("survey.question.money", "An amount of money.", &[ShapeId("survey.question.common")], &[
        req("type", Ty::Enum(&["money"]), "The question type."),
        req("currency", TEXT, "The currency."),
        key("min", NUMBER, "The smallest amount."),
        key("max", NUMBER, "The largest amount."),
        key("step", NUMBER, "The step."),
    ]),
    closed_with("survey.question.measure-twice", "A measurement taken twice.", &[ShapeId("survey.question.common")], &[
        req("type", Ty::Enum(&["measure-twice"]), "The question type."),
        req("unit", TEXT, "The unit."),
        key("also", TEXTS, "Other units the answer may be entered in."),
        key("min", NUMBER, "The smallest value."),
        key("max", NUMBER, "The largest value."),
        key("decimals", NUMBER, "How many decimals are kept."),
        key("tolerance", NUMBER, "How far apart the two measurements may be."),
    ]),
    closed_with("survey.question.text", "Free text.", &[ShapeId("survey.question.common")], &[
        req("type", Ty::Enum(&["text"]), "The question type."),
        key("max-length", NUMBER, "The longest text allowed."),
        key("multiline", FLAG, "True when the answer may span lines."),
        key("description", TEXT, "A description of the data."),
    ]),
    closed_with("survey.question.date", "A date.", &[ShapeId("survey.question.common")], &[
        req("type", Ty::Enum(&["date"]), "The question type."),
        key("min", TEXT, "The earliest date."),
        key("max", TEXT, "The latest date."),
    ]),
    closed_with("survey.question.roster", "A value copied from the roster.", &[ShapeId("survey.question.common")], &[
        req("type", Ty::Enum(&["roster"]), "The question type."),
        req("field", TEXT, "The roster field."),
        key("value", TEXT, "The value type; `string` when omitted."),
        key("unit", TEXT, "The unit."),
    ]),
    single("survey.condition", "A condition: one operator and its operands (ADR 0040).", &[
        key("all", CONDITIONS, "Every condition holds.").cross("at least two conditions"),
        key("any", CONDITIONS, "At least one condition holds.").cross("at least two conditions"),
        key("not", CONDITION, "The condition does not hold."),
        key("is", OPERAND, "The question is true."),
        key("answered", OPERAND, "The question has been answered."),
        key("eq", Ty::List(&LITERAL), "Equal.").cross("two operands"),
        key("ne", Ty::List(&LITERAL), "Not equal.").cross("two operands"),
        key("lt", Ty::List(&LITERAL), "Less than.").cross("two operands"),
        key("le", Ty::List(&LITERAL), "At most.").cross("two operands"),
        key("gt", Ty::List(&LITERAL), "Greater than.").cross("two operands"),
        key("ge", Ty::List(&LITERAL), "At least.").cross("two operands"),
        key("in", Ty::List(&ANY), "The first operand is one of the listed values.").cross("an operand, then a list of values"),
    ]),
    single("survey.operand", "An arithmetic or lookup node.", &[
        key("add", Ty::List(&OPERAND), "The sum of two operands.").cross("two operands"),
        key("sub", Ty::List(&OPERAND), "The difference of two operands.").cross("two operands"),
        key("mul", Ty::List(&OPERAND), "The product of two operands.").cross("two operands"),
        key("div", Ty::List(&OPERAND), "The quotient of two operands.").cross("two operands"),
        key("lookup", Ty::List(&ANY), "A value from a table: the table's name, then the key.").cross("a table name, then an operand"),
    ]),
    closed("survey.check", "A rule: a soft warning, or a skip.", &[
        req("id", TEXT, "The rule's id."),
        req("when", CONDITION, "When the rule applies."),
        key("skip", TEXTS, "The questions skipped when it applies.").cross("a rule has `skip`, or `soft` and optionally `reasons`"),
        key("soft", TEXT, "The warning shown when it applies.").cross("required unless the rule has `skip`"),
        key("reasons", TEXTS, "The reasons a person may give for going on."),
    ]),
    closed("survey.field-check", "A check on how the survey was filled in.", &[
        req("id", TEXT, "The check's id."),
        req("type", TEXT, "The check's type."),
        key("question", TEXT, "The question it applies to.").cross("the question must exist"),
        key("window", NUMBER, "The window."),
        key("threshold", NUMBER, "The threshold."),
        key("min-seconds", NUMBER, "The least time."),
        key("max-seconds", NUMBER, "The most time."),
        req("message", TEXT, "The message shown."),
    ]),
    // ---- layout ----
    closed("layout", "A layout in the compact dialect: how a survey is shown at one window class.", &[
        req("layout", Ty::Map(ShapeId("layout.id")), "The layout's name and the survey it presents."),
        req("steps", Ty::List(&Ty::Map(ShapeId("layout.step"))), "The layout's steps, in order."),
    ]),
    closed("layout.id", "The layout's name and the survey it presents.", &[
        req("name", TEXT, "The layout's name."),
        key("version", TEXT, "The layout's version; `1.0.0` when omitted."),
        req("instrument", TEXT, "The survey the layout presents."),
        req("window", TEXT, "The window class."),
        key("language", TEXT, "The language the titles are written in; `en` when omitted."),
    ]),
    closed("layout.step", "One step of a layout.", &[
        req("title", TEXT, "The step's title."),
        key("navigation", TEXT, "How the step is navigated; `linear` when omitted."),
        req("contents", CONTENTS, "What the step shows."),
    ]),
    present("layout.content", "One thing a step shows.", &[
        ("element", ShapeId("layout.content.element")),
        ("group", ShapeId("layout.content.group")),
        ("repeat", ShapeId("layout.content.repeat")),
        ("show", ShapeId("layout.content.show")),
        ("card", ShapeId("layout.content.card")),
        ("tabs", ShapeId("layout.content.tabs")),
    ], None),
    closed("layout.content.element", "One element.", &[req("element", ANY_TEXT, "The element's path.").cross("the path must exist")]),
    closed("layout.content.group", "One group.", &[req("group", ANY_TEXT, "The group's path.").cross("the path must exist")]),
    closed("layout.content.repeat", "A repeat group.", &[
        req("repeat", ANY_TEXT, "The repeat group's path.").cross("the path must exist"),
        key("as", Ty::Enum(&["list", "table", "cards"]), "How the repeats are drawn; `list` when omitted."),
    ]),
    closed("layout.content.show", "Several elements.", &[req("show", TEXTS, "The elements' paths.").cross("each path must exist")]),
    closed("layout.content.card", "A card.", &[req("card", TITLED, "The card.")]),
    closed("layout.content.tabs", "Tabs.", &[req("tabs", Ty::List(&TITLED), "The tabs.")]),
    closed("layout.titled", "A card or a tab.", &[
        req("title", TEXT, "The title."),
        key("icon", TEXT, "The icon."),
        req("contents", CONTENTS, "What it shows."),
    ]),
    // ---- roster ----
    closed("roster", "A compact roster: columns and rows of cells.", &[
        req("roster", Ty::Map(ShapeId("roster.id")), "The cohort and the roster's version."),
        req("columns", TEXTS, "The columns; they start with `subject` and `display`.").cross("starts with subject, display"),
        req("rows", Ty::List(&Ty::List(&ANY)), "One list of cells per subject.").cross("one cell for each column; `subject`, `display` and `consent` are text"),
    ]),
    closed("roster.id", "The cohort and the roster's version.", &[
        req("cohort", TEXT, "The cohort."),
        req("version", NUMBER, "The roster's version."),
    ]),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn map<const N: usize>(pairs: [(&str, Value); N]) -> Value {
        Value::Map(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    fn walk_tys(ty: &Ty, f: &mut dyn FnMut(&Ty)) {
        f(ty);
        match ty {
            Ty::List(inner) | Ty::Dict(inner) | Ty::Entries(inner) => walk_tys(inner, f),
            Ty::OneOf(alts) => alts.iter().for_each(|a| walk_tys(a, f)),
            _ => {}
        }
    }

    #[test]
    fn wire_209_every_key_of_both_kinds_is_declared_once() {
        let mut ids = BTreeSet::new();
        for s in shapes() {
            assert!(ids.insert(s.id), "shape {} is declared twice", s.id.0);
        }
        for kind in [DocKind::Survey, DocKind::Layout, DocKind::Roster] {
            let mut reached = BTreeSet::new();
            reachable(root(kind), &mut reached);
            for id in reached {
                let mut seen = BTreeSet::new();
                for k in keys_of(id) {
                    assert!(seen.insert(k.name), "key `{}` is declared twice in {}", k.name, id.0);
                }
            }
        }
        // Every shape a type or a selector names is declared, and every shape is reachable.
        let mut reached = BTreeSet::new();
        for kind in [DocKind::Survey, DocKind::Layout, DocKind::Roster] {
            reachable(root(kind), &mut reached);
        }
        for s in shapes() {
            for inc in s.includes {
                assert!(shape(*inc).is_some(), "{} includes the undeclared {}", s.id.0, inc.0);
            }
            for k in s.keys {
                walk_tys(&k.ty, &mut |t| {
                    if let Ty::Map(id) | Ty::Ref(id) = t {
                        assert!(shape(*id).is_some(), "{}.{} names the undeclared {}", s.id.0, k.name, id.0);
                    }
                    if let Ty::OneOf(alts) = t {
                        let classes: Vec<_> = alts.iter().map(class_of_ty).collect();
                        assert!(classes.iter().all(Option::is_some), "{}.{}: a OneOf holds an Any or a nested OneOf", s.id.0, k.name);
                        let distinct: BTreeSet<_> = classes.iter().map(|c| format!("{c:?}")).collect();
                        assert_eq!(distinct.len(), classes.len(), "{}.{}: two alternatives of a OneOf take the same kind of value", s.id.0, k.name);
                    }
                });
            }
            assert!(reached.contains(&s.id), "shape {} is not reachable from any root", s.id.0);
        }
    }

    #[test]
    fn wire_209_the_json_schema_is_generated_from_the_same_table() {
        for kind in [DocKind::Survey, DocKind::Layout, DocKind::Roster] {
            let schema = json_schema(kind);
            assert_eq!(schema, json_schema(kind), "generation is deterministic");
            let defs = schema.as_map().and_then(|m| m.get("$defs")).and_then(Value::as_map).expect("defs");
            let mut reached = BTreeSet::new();
            reachable(root(kind), &mut reached);
            let names: BTreeSet<&str> = defs.keys().map(String::as_str).collect();
            let expected: BTreeSet<&str> = reached.iter().map(|id| id.0).collect();
            assert_eq!(names, expected);
            // Every closed shape lists exactly the keys of the table.
            for id in reached {
                let s = shape(id).expect("declared");
                if matches!(s.select, Select::Closed | Select::Single) {
                    let props = defs[id.0].as_map().and_then(|m| m.get("properties")).and_then(Value::as_map).expect("properties");
                    let declared: BTreeSet<&str> = keys_of(id).iter().map(|k| k.name).collect();
                    assert_eq!(props.keys().map(String::as_str).collect::<BTreeSet<_>>(), declared, "{}", id.0);
                    assert_eq!(defs[id.0].as_map().and_then(|m| m.get("additionalProperties")), Some(&Value::Bool(false)));
                }
            }
        }
    }

    #[test]
    fn wire_211_pointer_segments_escape_tilde_and_slash() {
        assert_eq!(escape_segment("a/b~c"), "a~1b~0c");
        assert_eq!(child_pointer("/lists", "a/b"), "/lists/a~1b");
        let doc = map([("survey", map([("name", text("x")), ("version", text("1"))])), ("sections", Value::Array(vec![])), ("lists", map([("a/b~c", Value::Int(1))]))]);
        let errors = check(&doc, DocKind::Survey);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].pointer, "/lists/a~1b~0c");
        assert_eq!(errors[0].kind, SchemaErrorKind::TypeMismatch);
    }

    #[test]
    fn wire_211_every_error_kind_is_one_of_the_six() {
        let names: Vec<&str> = SchemaErrorKind::ALL.iter().map(|k| k.name()).collect();
        assert_eq!(names, ["UnknownField", "MissingField", "TypeMismatch", "EnumValue", "DuplicateKey", "CoercionRefused"]);
        for k in SchemaErrorKind::ALL {
            assert_eq!(SchemaErrorKind::parse(k.name()), Some(k));
        }
        // The validator reports four of them; the decoders report the other two.
        let doc = map([
            ("survey", map([("name", text("x")), ("extra", text("y"))])),
            ("sections", Value::Array(vec![map([("q", map([("type", text("nonsense"))]))])])),
            ("title", Value::Int(3)),
        ]);
        let kinds: BTreeSet<SchemaErrorKind> = check(&doc, DocKind::Survey).into_iter().map(|e| e.kind).collect();
        assert_eq!(kinds, BTreeSet::from([SchemaErrorKind::UnknownField, SchemaErrorKind::MissingField, SchemaErrorKind::TypeMismatch, SchemaErrorKind::EnumValue]));
    }

    #[test]
    fn wire_210_a_valid_minimal_document_has_no_findings_and_a_reader_resolves_its_shape() {
        let doc = map([
            ("survey", map([("name", text("x")), ("version", text("1"))])),
            ("sections", Value::Array(vec![map([("q", map([("type", text("binary")), ("label", text("Ok?"))]))])])),
        ]);
        assert_eq!(check(&doc, DocKind::Survey), vec![]);
        let shapes = shapes_in(&doc, DocKind::Survey);
        assert!(shapes.contains(&("/sections/0/q".to_owned(), ShapeId("survey.question.binary"))));
        let q = Map::from([("type".to_owned(), text("choice")), ("list".to_owned(), text("l"))]);
        let r = Reader::new(&q, ShapeId("survey.question"));
        assert_eq!(r.text("list"), Some("l"));
    }

    #[test]
    fn wire_210_a_condition_names_exactly_one_operator() {
        let doc = |cond: Value| {
            map([
                ("survey", map([("name", text("x")), ("version", text("1"))])),
                ("sections", Value::Array(vec![map([("q", map([("type", text("binary")), ("if", cond)]))])])),
            ])
        };
        assert_eq!(check(&doc(map([("is", text("a"))])), DocKind::Survey), vec![]);
        let two = check(&doc(map([("is", text("a")), ("answered", text("b"))])), DocKind::Survey);
        assert_eq!(two.len(), 1);
        assert_eq!(two[0].kind, SchemaErrorKind::TypeMismatch);
        let unknown = check(&doc(map([("maybe", text("a"))])), DocKind::Survey);
        assert!(unknown.iter().any(|e| e.kind == SchemaErrorKind::UnknownField && e.pointer == "/sections/0/q/if/maybe"));
    }
}
