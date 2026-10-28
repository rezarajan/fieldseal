//! The text rules for instrument messages (INS-084, INS-085).
//!
//! Every user-facing text is read as a Unicode MessageFormat 2 message restricted to the
//! subset INS-084 allows: variable placeholders `{$name}`, optionally formatted with
//! `:number`, `:integer` or `:date` and literal options; `.input` declarations; and
//! `.match` selection on those variables (plural categories or exact keys). Variables name
//! roster fields (`$roster.<field>`) or item paths. Literals, markup, `.local`, other
//! functions and attributes are refused. This module checks syntax and extracts variables;
//! formatting with CLDR data is done by [`super::locale`] and the platform adapters (INS-088).
//!
//! A text that doesn't start with `.input`, `.match` or `{{` is a simple message, in which a
//! leading `.` is allowed (so "…5 litres" reads naturally).

use std::collections::BTreeSet;

/// What was found in one message.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct MessageInfo {
    /// Variable names referenced, without `$` (for example `roster.age`, `about.weight`).
    pub variables: BTreeSet<String>,
}

/// Why a message was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    /// Not plain text (INS-085).
    #[error("{0}")]
    NotPlainText(String),
    /// Outside the allowed MessageFormat 2 subset (INS-084).
    #[error("{0}")]
    Syntax(String),
}

/// The functions INS-084 allows.
const FUNCTIONS: [&str; 4] = ["number", "integer", "date", "string"];

/// Checks the plain-text rule (INS-085): no control characters except line feed, no
/// markup or character references, and bidirectional controls limited to the isolates
/// U+2066–U+2069.
pub fn check_plain_text(text: &str) -> Result<(), MessageError> {
    for (i, c) in text.char_indices() {
        let bidi_control = matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}');
        if c.is_control() && c != '\n' {
            return Err(MessageError::NotPlainText(format!("control character U+{:04X} at byte {i}", c as u32)));
        }
        if bidi_control {
            return Err(MessageError::NotPlainText(format!(
                "bidirectional formatting character U+{:04X}; use the isolates U+2066–U+2069",
                c as u32
            )));
        }
        if c == '<' {
            let next = text[i + 1..].chars().next();
            if next.is_some_and(|n| n.is_ascii_alphabetic() || n == '/' || n == '!' || n == '?') {
                return Err(MessageError::NotPlainText("markup is not allowed in text".into()));
            }
        }
        if c == '&' {
            let rest = &text[i + 1..];
            if let Some(end) = rest.find(';') {
                let name = &rest[..end];
                let entity = !name.is_empty()
                    && name.len() <= 32
                    && (name.bytes().all(|b| b.is_ascii_alphanumeric())
                        || (name.starts_with('#') && name.len() > 1 && name[1..].bytes().all(|b| b.is_ascii_hexdigit() || b == b'x')));
                if entity {
                    return Err(MessageError::NotPlainText("character references are not allowed in text".into()));
                }
            }
        }
    }
    Ok(())
}

/// Parses `text` as a message in the allowed subset and returns its variables.
pub fn parse_message(text: &str) -> Result<MessageInfo, MessageError> {
    check_plain_text(text)?;
    let mut p = Parser { chars: text.chars().collect(), pos: 0, info: MessageInfo::default(), inputs: BTreeSet::new() };
    let trimmed = text.trim_start();
    if trimmed.starts_with(".input") || trimmed.starts_with(".match") || trimmed.starts_with(".local") || trimmed.starts_with("{{") {
        p.complex()?;
    } else {
        p.pattern(false)?;
        if p.pos != p.chars.len() {
            return Err(p.err("unexpected `}`; write `\\}` for a literal brace"));
        }
    }
    Ok(p.info)
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    info: MessageInfo,
    inputs: BTreeSet<String>,
}

impl Parser {
    fn err(&self, what: &str) -> MessageError {
        MessageError::Syntax(format!("{what} (at character {})", self.pos))
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, c: char) -> Result<(), MessageError> {
        if self.eat(c) { Ok(()) } else { Err(self.err(&format!("expected `{c}`"))) }
    }

    fn ws(&mut self) -> bool {
        let start = self.pos;
        while self.peek().is_some_and(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{3000}')) {
            self.pos += 1;
        }
        self.pos > start
    }

    fn keyword(&mut self, word: &str) -> bool {
        let w: Vec<char> = word.chars().collect();
        if self.chars[self.pos..].starts_with(&w) {
            self.pos += w.len();
            true
        } else {
            false
        }
    }

    /// Text and placeholders, until end of input or (if `quoted`) `}}`.
    fn pattern(&mut self, quoted: bool) -> Result<(), MessageError> {
        while let Some(c) = self.peek() {
            match c {
                '\\' => {
                    self.pos += 1;
                    match self.peek() {
                        Some('\\' | '{' | '}' | '|') => self.pos += 1,
                        _ => return Err(self.err("`\\` escapes only `\\`, `{`, `}` and `|`")),
                    }
                }
                '{' => {
                    self.pos += 1;
                    self.placeholder()?;
                }
                '}' => {
                    if quoted {
                        return Ok(());
                    }
                    return Err(self.err("unexpected `}`; write `\\}` for a literal brace"));
                }
                _ => self.pos += 1,
            }
        }
        if quoted { Err(self.err("unterminated `{{`")) } else { Ok(()) }
    }

    /// After `{`: `$var [:fn options]` then `}`.
    fn placeholder(&mut self) -> Result<(), MessageError> {
        self.ws();
        match self.peek() {
            Some('$') => {
                let name = self.variable()?;
                self.info.variables.insert(name);
            }
            Some('#' | '/') => return Err(self.err("markup is not allowed (INS-085)")),
            Some(':') => return Err(self.err("a function needs a variable operand")),
            Some('|') | Some(_) => return Err(self.err("only variable placeholders `{$name}` are allowed (INS-084)")),
            None => return Err(self.err("unterminated placeholder")),
        }
        let spaced = self.ws();
        if self.peek() == Some(':') {
            if !spaced {
                return Err(self.err("expected a space before the function"));
            }
            self.annotation()?;
            self.ws();
        }
        if self.peek() == Some('@') {
            return Err(self.err("attributes are not allowed"));
        }
        self.expect('}')
    }

    fn name(&mut self) -> Result<String, MessageError> {
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.')) {
            self.pos += 1;
        }
        if self.pos == start || !self.chars[start].is_alphabetic() && self.chars[start] != '_' {
            return Err(self.err("expected a name"));
        }
        Ok(self.chars[start..self.pos].iter().collect())
    }

    fn variable(&mut self) -> Result<String, MessageError> {
        self.expect('$')?;
        self.name()
    }

    /// `:fn {option=value}`.
    fn annotation(&mut self) -> Result<String, MessageError> {
        self.expect(':')?;
        let f = self.name()?;
        if !FUNCTIONS.contains(&f.as_str()) {
            return Err(self.err(&format!("function `:{f}` is not allowed; use :number, :integer, :date or :string (INS-084)")));
        }
        loop {
            let save = self.pos;
            if !self.ws() || !self.peek().is_some_and(|c| c.is_alphabetic()) {
                self.pos = save;
                break;
            }
            self.name()?;
            self.ws();
            self.expect('=')?;
            self.ws();
            self.literal_value()?;
        }
        Ok(f)
    }

    /// An option value: an unquoted name or number, or a `|quoted|` literal.
    fn literal_value(&mut self) -> Result<(), MessageError> {
        if self.eat('|') {
            while let Some(c) = self.peek() {
                self.pos += 1;
                match c {
                    '|' => return Ok(()),
                    '\\' => self.pos += 1,
                    _ => {}
                }
            }
            return Err(self.err("unterminated `|` literal"));
        }
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '+')) {
            self.pos += 1;
        }
        if self.pos == start {
            return Err(self.err("expected an option value"));
        }
        Ok(())
    }

    fn complex(&mut self) -> Result<(), MessageError> {
        loop {
            self.ws();
            if self.keyword(".input") {
                self.ws();
                self.expect('{')?;
                self.ws();
                let name = self.variable()?;
                self.ws();
                if self.peek() == Some(':') {
                    self.annotation()?;
                    self.ws();
                }
                self.expect('}')?;
                self.info.variables.insert(name.clone());
                self.inputs.insert(name);
            } else if self.keyword(".local") {
                return Err(self.err("`.local` declarations are not allowed (INS-084)"));
            } else {
                break;
            }
        }
        if self.keyword(".match") {
            let mut selectors = 0;
            loop {
                let spaced = self.ws();
                if self.peek() != Some('$') {
                    break;
                }
                if !spaced {
                    return Err(self.err("expected a space before the selector"));
                }
                let name = self.variable()?;
                if !self.inputs.contains(&name) {
                    return Err(self.err(&format!("selector ${name} must be declared with `.input` and a function")));
                }
                selectors += 1;
            }
            if selectors == 0 {
                return Err(self.err("`.match` needs at least one selector"));
            }
            let mut variants = 0;
            let mut has_catchall = false;
            loop {
                self.ws();
                if self.peek().is_none() {
                    break;
                }
                let mut all_star = true;
                for _ in 0..selectors {
                    self.ws();
                    if self.eat('*') {
                        continue;
                    }
                    all_star = false;
                    self.literal_value()?;
                }
                has_catchall |= all_star;
                self.ws();
                self.quoted_pattern()?;
                variants += 1;
            }
            if variants == 0 || !has_catchall {
                return Err(self.err("`.match` needs a catch-all `*` variant"));
            }
        } else {
            self.quoted_pattern()?;
            self.ws();
            if self.peek().is_some() {
                return Err(self.err("unexpected text after the message body"));
            }
        }
        Ok(())
    }

    fn quoted_pattern(&mut self) -> Result<(), MessageError> {
        self.expect('{')?;
        self.expect('{')?;
        self.pattern(true)?;
        self.expect('}')?;
        self.expect('}')
    }
}
