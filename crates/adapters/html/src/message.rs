//! Formatting the MessageFormat 2 subset of INS-084 for display.
//!
//! The instrument context has already checked every message's syntax; this module only cuts a
//! message into literal text and variable placeholders, choosing a `.match` variant from the
//! values it is given. It never interprets anything else, and whatever it cannot read is shown
//! as literal text (escaped by the caller).
//!
//! Variant selection (INS-084, INS-088) ranks a key per selector: an exact match (as text, or
//! as equal numbers) beats a plural category (`one`, `few`, …, from CLDR for the selected
//! locale, supplied by the caller), which beats the catch-all `*`. Selectors are compared in
//! order, as MessageFormat 2 sorts variants; a selector without a value only matches `*`.

/// A piece of a formatted message.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Segment {
    /// Text shown as it is.
    Literal(String),
    /// A `{$name}` placeholder: a roster field (`roster.<field>`) or an item path.
    Variable(String),
}

/// Cuts `message` into segments. `value` gives a variable's locale-free value as text, for
/// `.match`; `plural` gives the plural category name of such a value (`None` if it isn't a
/// number).
pub fn segments(message: &str, value: &dyn Fn(&str) -> Option<String>, plural: &dyn Fn(&str) -> Option<&'static str>) -> Vec<Segment> {
    let trimmed = message.trim_start();
    let complex = trimmed.starts_with(".input") || trimmed.starts_with(".match") || trimmed.starts_with("{{");
    let parsed = if complex { Parser::new(trimmed).complex(value, plural) } else { Parser::new(message).pattern(false) };
    parsed.unwrap_or_else(|| vec![Segment::Literal(message.to_owned())])
}

struct Parser<'a> {
    s: &'a str,
    i: usize,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        Self { s, i: 0 }
    }

    fn rest(&self) -> &'a str {
        &self.s[self.i..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.i += c.len_utf8();
        Some(c)
    }

    fn ws(&mut self) {
        while self.peek().is_some_and(char::is_whitespace) {
            self.bump();
        }
    }

    fn eat(&mut self, t: &str) -> bool {
        if self.rest().starts_with(t) {
            self.i += t.len();
            true
        } else {
            false
        }
    }

    /// A pattern, up to the end (or, when `quoted`, up to and including `}}`).
    fn pattern(&mut self, quoted: bool) -> Option<Vec<Segment>> {
        let mut out = Vec::new();
        let mut lit = String::new();
        loop {
            if quoted && self.eat("}}") {
                break;
            }
            let Some(c) = self.bump() else {
                if quoted {
                    return None;
                }
                break;
            };
            match c {
                '\\' => lit.push(self.bump()?),
                '{' => {
                    if !lit.is_empty() {
                        out.push(Segment::Literal(std::mem::take(&mut lit)));
                    }
                    out.push(Segment::Variable(self.placeholder()?));
                }
                '}' => return None,
                c => lit.push(c),
            }
        }
        if !lit.is_empty() {
            out.push(Segment::Literal(lit));
        }
        Some(out)
    }

    /// After `{`: `$name`, an optional annotation, then `}`. Returns the name.
    fn placeholder(&mut self) -> Option<String> {
        self.ws();
        if !self.eat("$") {
            return None;
        }
        let name = self.name()?;
        // Skip the annotation (`:number minimumFractionDigits=1`), honouring `|quoted|` literals.
        let mut in_quote = false;
        loop {
            match self.bump()? {
                '|' => in_quote = !in_quote,
                '\\' if in_quote => {
                    self.bump()?;
                }
                '}' if !in_quote => return Some(name),
                _ => {}
            }
        }
    }

    fn name(&mut self) -> Option<String> {
        let start = self.i;
        while self.peek().is_some_and(|c| !c.is_whitespace() && c != '}' && c != '{' && c != ':') {
            self.bump();
        }
        (self.i > start).then(|| self.s[start..self.i].to_owned())
    }

    /// `.input` declarations, then a quoted pattern or a `.match`.
    fn complex(&mut self, value: &dyn Fn(&str) -> Option<String>, plural: &dyn Fn(&str) -> Option<&'static str>) -> Option<Vec<Segment>> {
        loop {
            self.ws();
            if self.eat(".input") {
                self.ws();
                if !self.eat("{") {
                    return None;
                }
                self.placeholder()?;
            } else {
                break;
            }
        }
        if self.eat("{{") {
            return self.pattern(true);
        }
        if !self.eat(".match") {
            return None;
        }
        let mut selectors = Vec::new();
        loop {
            self.ws();
            if self.eat("$") {
                selectors.push(self.name()?);
            } else {
                break;
            }
        }
        if selectors.is_empty() {
            return None;
        }
        let values: Vec<Option<String>> = selectors.iter().map(|s| value(s)).collect();
        let mut best: Option<(Vec<u8>, Vec<Segment>)> = None;
        loop {
            self.ws();
            if self.peek().is_none() {
                break;
            }
            let mut keys = Vec::new();
            while !self.rest().starts_with("{{") {
                keys.push(self.key()?);
                self.ws();
            }
            self.eat("{{");
            let body = self.pattern(true)?;
            if keys.len() != selectors.len() {
                return None;
            }
            // Per selector: 0 exact, 1 plural category, 2 catch-all; a miss rules the variant out.
            let rank: Option<Vec<u8>> = keys
                .iter()
                .zip(&values)
                .map(|(k, v)| match (k, v) {
                    (None, _) => Some(2),
                    (Some(k), Some(v)) if same(k, v) => Some(0),
                    (Some(k), Some(v)) if plural(v) == Some(k.as_str()) => Some(1),
                    _ => None,
                })
                .collect();
            if let Some(rank) = rank
                && best.as_ref().is_none_or(|(r, _)| rank < *r)
            {
                best = Some((rank, body));
            }
        }
        best.map(|(_, b)| b)
    }

    /// A variant key: `*` (`None`), a `|quoted|` literal or an unquoted one.
    fn key(&mut self) -> Option<Option<String>> {
        if self.eat("*") {
            return Some(None);
        }
        if self.eat("|") {
            let mut k = String::new();
            loop {
                match self.bump()? {
                    '|' => return Some(Some(k)),
                    '\\' => k.push(self.bump()?),
                    c => k.push(c),
                }
            }
        }
        let start = self.i;
        while self.peek().is_some_and(|c| !c.is_whitespace() && c != '{') {
            self.bump();
        }
        (self.i > start).then(|| Some(self.s[start..self.i].to_owned()))
    }
}

/// Whether a key matches a value: as text, or as equal numbers (`1` and `1.0`).
fn same(key: &str, value: &str) -> bool {
    if key == value {
        return true;
    }
    match (fieldseal_kernel::Decimal::parse(key), fieldseal_kernel::Decimal::parse(value)) {
        (Ok(a), Ok(b)) => a.numeric_cmp(b) == Some(std::cmp::Ordering::Equal),
        _ => false,
    }
}
