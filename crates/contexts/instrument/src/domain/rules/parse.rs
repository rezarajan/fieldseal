//! Tokenizer and recursive-descent parser for the rule grammar (INS-040).
//!
//! ```text
//! expr  = or ;                     or  = and { "or" and } ;
//! and   = not { "and" not } ;      not = [ "not" ] cmp ;
//! cmp   = sum [ cmpop sum ] ;      sum = term { ("+"|"-") term } ;
//! term  = unary { ("*"|"/") unary } ;  unary = [ "-" ] atom ;
//! atom  = number | string | "true" | "false" | path | call | "(" expr ")" | list ;
//! path  = "$" itempath | "@" ident | "roster." ident ;
//! ```
//!
//! Numbers are plain decimals (`12`, `0.5`); strings are double-quoted with `\"` and `\\`
//! escapes. Comparisons don't chain. Nesting is limited, so parsing is bounded too.

use super::ast::{BinOp, Expr, Function, PathRef};
use crate::domain::num::Num;

/// Why an expression didn't parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message} (at character {position})")]
pub struct ParseError {
    /// What was wrong.
    pub message: String,
    /// The character offset where it was noticed.
    pub position: usize,
}

/// The deepest nesting of parentheses, lists and calls accepted.
const MAX_DEPTH: usize = 64;

#[derive(Clone, PartialEq, Debug)]
enum Tok {
    Num(Num),
    Str(String),
    Word(String),
    Item(String),
    Sibling(String),
    Roster(String),
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Op(&'static str),
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_lowercase()
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'
}

fn tokenize(text: &str) -> Result<Vec<(Tok, usize)>, ParseError> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let err = |message: String, position: usize| ParseError { message, position };
    let ident = |start: usize| -> (String, usize) {
        let mut j = start;
        if j < chars.len() && is_ident_start(chars[j]) {
            j += 1;
            while j < chars.len() && is_ident_char(chars[j]) {
                j += 1;
            }
        }
        (chars[start..j].iter().collect(), j)
    };
    while i < chars.len() {
        let c = chars[i];
        let start = i;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        let tok = match c {
            '(' => { i += 1; Tok::LParen }
            ')' => { i += 1; Tok::RParen }
            '[' => { i += 1; Tok::LBracket }
            ']' => { i += 1; Tok::RBracket }
            ',' => { i += 1; Tok::Comma }
            '+' => { i += 1; Tok::Op("+") }
            '-' => { i += 1; Tok::Op("-") }
            '*' => { i += 1; Tok::Op("*") }
            '/' => { i += 1; Tok::Op("/") }
            '=' | '!' | '<' | '>' => {
                let two = chars.get(i + 1) == Some(&'=');
                i += if two { 2 } else { 1 };
                match (c, two) {
                    ('=', true) => Tok::Op("=="),
                    ('!', true) => Tok::Op("!="),
                    ('<', true) => Tok::Op("<="),
                    ('>', true) => Tok::Op(">="),
                    ('<', false) => Tok::Op("<"),
                    ('>', false) => Tok::Op(">"),
                    _ => return Err(err(format!("unexpected `{c}`; use `==` or `!=`"), start)),
                }
            }
            '"' => {
                i += 1;
                let mut s = String::new();
                loop {
                    match chars.get(i) {
                        None => return Err(err("unterminated string".into(), start)),
                        Some('"') => { i += 1; break; }
                        Some('\\') => {
                            match chars.get(i + 1) {
                                Some(&e @ ('"' | '\\')) => s.push(e),
                                _ => return Err(err("a string escape is `\\\"` or `\\\\`".into(), i)),
                            }
                            i += 2;
                        }
                        Some(&ch) => { s.push(ch); i += 1; }
                    }
                }
                Tok::Str(s)
            }
            '$' => {
                let mut j = i + 1;
                let mut path = String::new();
                loop {
                    let (seg, end) = ident(j);
                    if seg.is_empty() {
                        return Err(err("expected an item path after `$`".into(), j));
                    }
                    path.push_str(&seg);
                    j = end;
                    if chars.get(j) == Some(&'.') && chars.get(j + 1).is_some_and(|c| is_ident_start(*c)) {
                        path.push('.');
                        j += 1;
                    } else {
                        break;
                    }
                }
                i = j;
                Tok::Item(path)
            }
            '@' => {
                let (seg, end) = ident(i + 1);
                if seg.is_empty() {
                    return Err(err("expected an identifier after `@`".into(), i + 1));
                }
                i = end;
                Tok::Sibling(seg)
            }
            c if c.is_ascii_digit() => {
                let mut j = i;
                while j < chars.len() && chars[j].is_ascii_digit() {
                    j += 1;
                }
                if chars.get(j) == Some(&'.') && chars.get(j + 1).is_some_and(|c| c.is_ascii_digit()) {
                    j += 1;
                    while j < chars.len() && chars[j].is_ascii_digit() {
                        j += 1;
                    }
                }
                if chars.get(j).is_some_and(|c| c.is_alphanumeric() || *c == '.' || *c == '_') {
                    return Err(err("malformed number; write plain decimals such as 12 or 0.5".into(), start));
                }
                let lit: String = chars[i..j].iter().collect();
                i = j;
                Tok::Num(Num::parse(&lit).ok_or_else(|| err("number too large".into(), start))?)
            }
            c if is_ident_start(c) => {
                let (word, end) = ident(i);
                i = end;
                if word == "roster" && chars.get(i) == Some(&'.') {
                    let (field, end) = ident(i + 1);
                    if field.is_empty() {
                        return Err(err("expected a roster field after `roster.`".into(), i + 1));
                    }
                    i = end;
                    Tok::Roster(field)
                } else {
                    Tok::Word(word)
                }
            }
            other => return Err(err(format!("unexpected character `{other}`"), start)),
        };
        out.push((tok, start));
    }
    Ok(out)
}

/// Parses one expression.
pub fn parse_expr(text: &str) -> Result<Expr, ParseError> {
    let tokens = tokenize(text)?;
    let mut p = Parser { tokens, pos: 0, depth: 0, end: text.chars().count() };
    if p.tokens.is_empty() {
        return Err(ParseError { message: "empty expression".into(), position: 0 });
    }
    let e = p.or()?;
    if p.pos < p.tokens.len() {
        return Err(p.err("unexpected token after the expression"));
    }
    Ok(e)
}

/// Parses a skip or derive target: `$path`, `@ident` or a plain path.
pub fn parse_target(text: &str) -> Option<PathRef> {
    let valid = |p: &str| super::super::paths::is_item_path(p);
    if let Some(rest) = text.strip_prefix('@') {
        return (!rest.is_empty() && rest.chars().next().is_some_and(is_ident_start) && rest.chars().all(is_ident_char))
            .then(|| PathRef::Sibling(rest.to_owned()));
    }
    let plain = text.strip_prefix('$').unwrap_or(text);
    valid(plain).then(|| PathRef::Item(plain.to_owned()))
}

struct Parser {
    tokens: Vec<(Tok, usize)>,
    pos: usize,
    depth: usize,
    end: usize,
}

impl Parser {
    fn err(&self, message: &str) -> ParseError {
        let position = self.tokens.get(self.pos).map_or(self.end, |(_, p)| *p);
        ParseError { message: message.to_owned(), position }
    }

    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos).map(|(t, _)| t)
    }

    fn is_word(&self, w: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word(x)) if x == w)
    }

    fn is_op(&self, op: &str) -> bool {
        matches!(self.peek(), Some(Tok::Op(x)) if *x == op)
    }

    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.err("expression nested too deeply (INS-044)"));
        }
        Ok(())
    }

    fn or(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.and()?;
        while self.is_word("or") {
            self.pos += 1;
            let rhs = self.and()?;
            lhs = Expr::Binary(BinOp::Or, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn and(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.not()?;
        while self.is_word("and") {
            self.pos += 1;
            let rhs = self.not()?;
            lhs = Expr::Binary(BinOp::And, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn not(&mut self) -> Result<Expr, ParseError> {
        if self.is_word("not") {
            self.pos += 1;
            if self.is_word("not") {
                return Err(self.err("`not not` is not allowed; remove both"));
            }
            return Ok(Expr::Not(Box::new(self.cmp()?)));
        }
        self.cmp()
    }

    fn cmp_op(&self) -> Option<BinOp> {
        Some(match self.peek()? {
            Tok::Op("==") => BinOp::Eq,
            Tok::Op("!=") => BinOp::Ne,
            Tok::Op("<") => BinOp::Lt,
            Tok::Op("<=") => BinOp::Le,
            Tok::Op(">") => BinOp::Gt,
            Tok::Op(">=") => BinOp::Ge,
            Tok::Word(w) if w == "in" => BinOp::In,
            _ => return None,
        })
    }

    fn cmp(&mut self) -> Result<Expr, ParseError> {
        let lhs = self.sum()?;
        if let Some(op) = self.cmp_op() {
            self.pos += 1;
            let rhs = self.sum()?;
            if self.cmp_op().is_some() {
                return Err(self.err("comparisons don't chain; combine them with `and`"));
            }
            return Ok(Expr::Binary(op, Box::new(lhs), Box::new(rhs)));
        }
        Ok(lhs)
    }

    fn sum(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.term()?;
        loop {
            let op = if self.is_op("+") {
                BinOp::Add
            } else if self.is_op("-") {
                BinOp::Sub
            } else {
                break;
            };
            self.pos += 1;
            let rhs = self.term()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn term(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.unary()?;
        loop {
            let op = if self.is_op("*") {
                BinOp::Mul
            } else if self.is_op("/") {
                BinOp::Div
            } else {
                break;
            };
            self.pos += 1;
            let rhs = self.unary()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn unary(&mut self) -> Result<Expr, ParseError> {
        if self.is_op("-") {
            self.pos += 1;
            if self.is_op("-") {
                return Err(self.err("`- -` is not allowed"));
            }
            return Ok(Expr::Neg(Box::new(self.atom()?)));
        }
        self.atom()
    }

    fn args(&mut self, close: Tok) -> Result<Vec<Expr>, ParseError> {
        self.enter()?;
        let mut items = Vec::new();
        if self.peek() == Some(&close) {
            self.pos += 1;
            self.depth -= 1;
            return Ok(items);
        }
        loop {
            items.push(self.or()?);
            match self.peek() {
                Some(Tok::Comma) => self.pos += 1,
                Some(t) if *t == close => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(self.err("expected `,` or a closing bracket")),
            }
        }
        self.depth -= 1;
        Ok(items)
    }

    fn atom(&mut self) -> Result<Expr, ParseError> {
        let Some(tok) = self.peek().cloned() else {
            return Err(self.err("unexpected end of expression"));
        };
        self.pos += 1;
        Ok(match tok {
            Tok::Num(n) => Expr::Number(n),
            Tok::Str(s) => Expr::Text(s),
            Tok::Item(p) => Expr::Path(PathRef::Item(p)),
            Tok::Sibling(p) => Expr::Path(PathRef::Sibling(p)),
            Tok::Roster(p) => Expr::Path(PathRef::Roster(p)),
            Tok::LParen => {
                self.enter()?;
                let e = self.or()?;
                if self.peek() != Some(&Tok::RParen) {
                    return Err(self.err("expected `)`"));
                }
                self.pos += 1;
                self.depth -= 1;
                e
            }
            Tok::LBracket => Expr::List(self.args(Tok::RBracket)?),
            Tok::Word(w) if w == "true" => Expr::Bool(true),
            Tok::Word(w) if w == "false" => Expr::Bool(false),
            Tok::Word(w) => {
                let Some(f) = Function::from_name(&w) else {
                    self.pos -= 1;
                    return Err(self.err(&format!(
                        "unknown name `{w}`; paths start with `$`, `@` or `roster.`, and the only functions are is_set, is_nr, abs, min, max, count_set, round, lookup and value"
                    )));
                };
                if self.peek() != Some(&Tok::LParen) {
                    return Err(self.err(&format!("expected `(` after `{w}`")));
                }
                self.pos += 1;
                Expr::Call(f, self.args(Tok::RParen)?)
            }
            _ => {
                self.pos -= 1;
                return Err(self.err("expected a value"));
            }
        })
    }
}
