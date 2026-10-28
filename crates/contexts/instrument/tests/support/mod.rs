//! Test-only helpers: a compact notation for [`Value`] trees, and fixture editing.
//!
//! The notation is JSON with conveniences so instrument fixtures stay readable:
//! - keys and simple values may be bare words (`kind: question`, `unit: [lb_av]` is NOT
//!   allowed — brackets start lists — so write `unit: "[lb_av]"`);
//! - a bare word that reads as a plain decimal is a number (`0.214` is a decimal with
//!   exponent −3, `40` an integer), `true`/`false` are booleans, anything else is text;
//! - strings may use `"…"` or `'…'`; `#` starts a comment; trailing commas are fine;
//! - `x"89504e47"` is a byte string in hex.
//!
//! It is not YAML and is not an authoring format; production documents are decoded by the
//! authoring adapter.

#![allow(dead_code)]

use std::collections::BTreeMap;

use fieldseal_instrument::application::{validate_instrument, Validated};
use fieldseal_instrument::domain::{Finding, Findings, Severity};
use fieldseal_kernel::{Decimal, Value};

/// Parses the notation; panics with a position on error.
pub fn doc(text: &str) -> Value {
    let mut p = P { s: text.as_bytes(), i: 0, text };
    let v = p.value();
    p.ws();
    assert!(p.i == p.s.len(), "trailing input at byte {}: {:?}", p.i, &text[p.i..text.len().min(p.i + 40)]);
    v
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
    text: &'a str,
}

impl P<'_> {
    fn fail(&self, what: &str) -> ! {
        let end = self.text.len().min(self.i + 40);
        panic!("notation: {what} at byte {}: {:?}", self.i, &self.text[self.i..end]);
    }

    fn ws(&mut self) {
        while self.i < self.s.len() {
            match self.s[self.i] {
                b' ' | b'\n' | b'\r' | b'\t' => self.i += 1,
                b'#' => {
                    while self.i < self.s.len() && self.s[self.i] != b'\n' {
                        self.i += 1;
                    }
                }
                _ => break,
            }
        }
    }

    fn value(&mut self) -> Value {
        self.ws();
        match self.s.get(self.i) {
            Some(b'{') => {
                self.i += 1;
                let mut m = BTreeMap::new();
                loop {
                    self.ws();
                    if self.s.get(self.i) == Some(&b'}') {
                        self.i += 1;
                        break;
                    }
                    let key = match self.value() {
                        Value::Text(t) => t,
                        Value::Int(i) => i.to_string(),
                        _ => self.fail("map keys are text"),
                    };
                    self.ws();
                    if self.s.get(self.i) != Some(&b':') {
                        self.fail("expected `:`");
                    }
                    self.i += 1;
                    let v = self.value();
                    assert!(m.insert(key.clone(), v).is_none(), "duplicate key {key}");
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {}
                        _ => self.fail("expected `,` or `}`"),
                    }
                }
                Value::Map(m)
            }
            Some(b'[') => {
                self.i += 1;
                let mut a = Vec::new();
                loop {
                    self.ws();
                    if self.s.get(self.i) == Some(&b']') {
                        self.i += 1;
                        break;
                    }
                    a.push(self.value());
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {}
                        _ => self.fail("expected `,` or `]`"),
                    }
                }
                Value::Array(a)
            }
            Some(b'x') if self.s.get(self.i + 1) == Some(&b'"') => {
                self.i += 2;
                let start = self.i;
                while self.s.get(self.i) != Some(&b'"') {
                    self.i += 1;
                }
                let hex = &self.text[start..self.i];
                self.i += 1;
                Value::Bytes((0..hex.len()).step_by(2).map(|k| u8::from_str_radix(&hex[k..k + 2], 16).unwrap()).collect())
            }
            Some(&q @ (b'"' | b'\'')) => {
                self.i += 1;
                let mut out = String::new();
                loop {
                    let rest = &self.text[self.i..];
                    let c = rest.chars().next().unwrap_or_else(|| self.fail("unterminated string"));
                    self.i += c.len_utf8();
                    if c as u32 == u32::from(q) {
                        break;
                    }
                    if c == '\\' {
                        let e = self.text[self.i..].chars().next().unwrap();
                        self.i += e.len_utf8();
                        out.push(match e {
                            'n' => '\n',
                            't' => '\t',
                            other => other,
                        });
                    } else {
                        out.push(c);
                    }
                }
                Value::Text(out)
            }
            Some(_) => {
                let start = self.i;
                while self.i < self.s.len() && !matches!(self.s[self.i], b',' | b'}' | b']' | b'\n' | b'#') && !(self.s[self.i] == b':' && self.s.get(self.i + 1).is_none_or(|c| c.is_ascii_whitespace())) {
                    self.i += 1;
                }
                let word = self.text[start..self.i].trim();
                if word.is_empty() {
                    self.fail("expected a value");
                }
                match word {
                    "true" => Value::Bool(true),
                    "false" => Value::Bool(false),
                    w => match Decimal::parse(w) {
                        Ok(d) if d.exponent == 0 => Value::Int(d.mantissa),
                        Ok(d) => Value::Decimal(d),
                        Err(_) => Value::Text(w.to_owned()),
                    },
                }
            }
            None => self.fail("unexpected end"),
        }
    }
}

/// A path step: a map key or an array index.
enum Step<'a> {
    Key(&'a str),
    Index(usize),
}

fn steps(path: &str) -> Vec<Step<'_>> {
    let mut out = Vec::new();
    for part in path.split('.') {
        let (key, rest) = part.split_once('[').map_or((part, ""), |(k, r)| (k, r));
        if !key.is_empty() {
            out.push(Step::Key(key));
        }
        for idx in rest.split('[') {
            if let Some(n) = idx.strip_suffix(']') {
                out.push(Step::Index(n.parse().unwrap()));
            }
        }
    }
    out
}

fn node<'v>(v: &'v mut Value, path: &str) -> &'v mut Value {
    let mut cur = v;
    for s in steps(path) {
        cur = match (s, cur) {
            (Step::Key(k), Value::Map(m)) => m.get_mut(k).unwrap_or_else(|| panic!("no key {k} in {path}")),
            (Step::Index(i), Value::Array(a)) => &mut a[i],
            (_, _) => panic!("bad path {path}"),
        };
    }
    cur
}

/// Sets the value at a dotted path such as `spec.elements[0].control.min` (the last key may
/// be new).
pub fn set(v: &mut Value, path: &str, value: Value) {
    let (parent, last) = path.rsplit_once('.').unwrap_or(("", path));
    let target = if parent.is_empty() { v } else { node(v, parent) };
    if let Some((key, idx)) = last.split_once('[') {
        let i: usize = idx.trim_end_matches(']').parse().unwrap();
        let target = if key.is_empty() { target } else { node(target, key) };
        let Value::Array(a) = target else { panic!("not an array at {path}") };
        a[i] = value;
        return;
    }
    let Value::Map(m) = target else { panic!("not a map at {path}") };
    m.insert(last.to_owned(), value);
}

/// Removes the map entry at a dotted path.
pub fn remove(v: &mut Value, path: &str) {
    let (parent, last) = path.rsplit_once('.').unwrap_or(("", path));
    let target = if parent.is_empty() { v } else { node(v, parent) };
    let Value::Map(m) = target else { panic!("not a map at {path}") };
    assert!(m.remove(last).is_some(), "nothing at {path}");
}

/// Appends to the array at a dotted path.
pub fn push(v: &mut Value, path: &str, value: Value) {
    let Value::Array(a) = node(v, path) else { panic!("not an array at {path}") };
    a.push(value);
}

/// Validates, panicking with every finding if invalid.
pub fn valid(v: &Value) -> Validated {
    match validate_instrument(v) {
        Ok(ok) => ok,
        Err(f) => panic!("expected a valid instrument:\n{}", render(&f)),
    }
}

/// Validates, expecting failure; returns the findings.
pub fn invalid(v: &Value) -> Findings {
    match validate_instrument(v) {
        Ok(_) => panic!("expected the instrument to be invalid"),
        Err(f) => f,
    }
}

/// Every finding, one per line.
pub fn render(f: &Findings) -> String {
    f.iter().map(Finding::to_string).collect::<Vec<_>>().join("\n")
}

/// Asserts an error finding with `requirement` at `path` exists.
#[track_caller]
pub fn assert_finding(f: &Findings, requirement: &str, path: &str) {
    let found = f.iter().any(|x| x.requirement == requirement && x.path == path && x.severity == Severity::Error);
    assert!(found, "expected an error {requirement} at {path}; got:\n{}", render(f));
}

/// Asserts the document fails validation with `requirement` at `path`.
#[track_caller]
pub fn rejects(v: &Value, requirement: &str, path: &str) {
    assert_finding(&invalid(v), requirement, path);
}

/// A record's values from the notation (a map).
pub fn values(text: &str) -> BTreeMap<String, Value> {
    match doc(text) {
        Value::Map(m) => m,
        _ => panic!("values are a map"),
    }
}

/// Localised English text.
pub fn en(text: &str) -> Value {
    let mut m = BTreeMap::new();
    m.insert("en".to_owned(), Value::Text(text.to_owned()));
    Value::Map(m)
}

/// Text.
pub fn t(text: &str) -> Value {
    Value::Text(text.to_owned())
}
pub mod fixtures;
pub mod layouts;
