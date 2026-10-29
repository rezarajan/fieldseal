//! Gettext catalogues (`i18n/<lang>.po`), the only translation format (ADR 0041).
//!
//! [`parse_po`] reads a catalogue into entries that keep the English `msgid`, so the expander can
//! tell a stale translation from a current one. [`check_context`] holds the `msgctxt` grammar; the
//! parser accepts any `msgctxt`, so a catalogue in the legacy form (the text's path, as in
//! `lists.water-sources.borehole`) still parses, and only the survey resolver enforces the grammar.

use std::collections::{BTreeMap, BTreeSet};

use crate::{AuthoringError, ErrorKind};

/// The end of the message for a repeated `msgctxt`, which the resolver tells apart from a syntax error.
pub(crate) const REPEATED: &str = "appears twice";

/// One catalogue entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoEntry {
    /// The text's place: `instrument/<path>` or `layout/<window>/<id>` (see [`check_context`]).
    pub msgctxt: String,
    /// The English text the translation was written against.
    pub msgid: String,
    /// The translation; empty means not translated yet.
    pub msgstr: String,
    /// The line of the entry's `msgctxt`, counting from 1.
    pub line: usize,
}

/// The entries of a survey's catalogues: language, then `msgctxt`.
pub type EntryCatalogues = BTreeMap<String, BTreeMap<String, PoEntry>>;

/// What a `msgctxt` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextKind {
    /// `instrument/<path>`: a text of the instrument.
    Instrument,
    /// `layout/<window>/<authored id>`: the title of a layout step or card.
    Layout,
}

/// Checks a `msgctxt` against the grammar: `instrument/` and a dotted path, or `layout/`, a window
/// class and the authored id of a step or card. Parts are non-empty and hold no blank.
///
/// # Errors
///
/// A message saying what is wrong with `msgctxt`.
pub fn check_context(msgctxt: &str) -> Result<ContextKind, String> {
    let part_ok = |s: &str, sep: char| !s.is_empty() && !s.contains(char::is_whitespace) && s.split(sep).all(|p| !p.is_empty());
    if let Some(path) = msgctxt.strip_prefix("instrument/") {
        if part_ok(path, '.') && !path.contains('/') {
            return Ok(ContextKind::Instrument);
        }
        return Err(format!("`{msgctxt}`: expected `instrument/` and a path of names joined by dots"));
    }
    if let Some(rest) = msgctxt.strip_prefix("layout/") {
        if let Some((window, id)) = rest.split_once('/')
            && part_ok(window, '/')
            && part_ok(id, '/')
            && !id.contains('/')
        {
            return Ok(ContextKind::Layout);
        }
        return Err(format!("`{msgctxt}`: expected `layout/<window>/<authored id>`"));
    }
    Err(format!("`{msgctxt}`: expected `instrument/<path>` or `layout/<window>/<authored id>`"))
}

/// Parses a gettext catalogue strictly: `msgctxt`, `msgid` and `msgstr` lines with quoted text
/// (`\"`, `\\` and `\n` escapes), comments and blank lines. An empty `msgstr` is kept: it counts as
/// missing. An entry without a `msgctxt` (the header) is left out.
///
/// # Errors
///
/// An [`AuthoringError`] with the line of the first malformed entry, or of the second occurrence of
/// a repeated `msgctxt`.
pub fn parse_po(text: &str) -> Result<Vec<PoEntry>, AuthoringError> {
    let mut out: Vec<PoEntry> = Vec::new();
    let mut seen = BTreeSet::new();
    let (mut ctx, mut id, mut s): (Option<(String, usize)>, Option<String>, Option<String>) = (None, None, None);
    let mut flush = |ctx: &mut Option<(String, usize)>, id: &mut Option<String>, s: &mut Option<String>| -> Result<(), AuthoringError> {
        if let (Some((msgctxt, line)), Some(msgid), Some(msgstr)) = (ctx.take(), id.take(), s.take()) {
            if !seen.insert(msgctxt.clone()) {
                return Err(AuthoringError::new(ErrorKind::Compact, line, 1, format!("msgctxt \"{msgctxt}\" {REPEATED}")));
            }
            out.push(PoEntry { msgctxt, msgid, msgstr, line });
        }
        Ok(())
    };
    let unquote = |rest: &str, line: usize| -> Result<String, AuthoringError> {
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
            flush(&mut ctx, &mut id, &mut s)?;
            ctx = Some((unquote(r, line)?, line));
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
    flush(&mut ctx, &mut id, &mut s)?;
    Ok(out)
}
