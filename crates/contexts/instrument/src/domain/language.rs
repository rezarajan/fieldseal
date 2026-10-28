//! BCP 47 language tags and RFC 4647 lookup (INS-080, INS-087).

use std::fmt;

/// A well-formed BCP 47 language tag in canonical case (`en`, `es-419`, `zh-Hant-TW`,
/// `ar-XB`). Validation refuses tags written in another case, so that each language has
/// exactly one spelling as a map key.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct LanguageTag(String);

/// Why a language tag was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LanguageTagError {
    /// Not a well-formed BCP 47 tag.
    #[error("{0:?} is not a well-formed BCP 47 language tag")]
    Malformed(String),
    /// Well-formed, but not in canonical case.
    #[error("{0:?} is not in canonical case; write {1:?}")]
    NotCanonical(String, String),
}

fn alpha(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphabetic())
}
fn digit(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit())
}
fn alnum(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphanumeric())
}

impl LanguageTag {
    /// Parses a tag: `language[-extlang]{0,3}[-script][-region]{-variant}{-extension}[-x-private]`
    /// (RFC 5646 §2.1, without grandfathered tags).
    pub fn parse(text: &str) -> Result<Self, LanguageTagError> {
        let canonical = canonicalise(text).ok_or_else(|| LanguageTagError::Malformed(text.to_owned()))?;
        if canonical != text {
            return Err(LanguageTagError::NotCanonical(text.to_owned(), canonical));
        }
        Ok(Self(canonical))
    }

    /// The tag text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The primary language subtag, lowercase.
    pub fn language(&self) -> &str {
        self.0.split('-').next().unwrap_or("")
    }

    /// The script subtag, if the tag has one.
    pub fn script(&self) -> Option<&str> {
        self.0.split('-').skip(1).take_while(|s| s.len() != 1).find(|s| s.len() == 4 && alpha(s))
    }

    /// The default text direction of the language, from its script subtag if present and
    /// otherwise from the primary language. This is a small built-in table of right-to-left
    /// scripts and languages; CLDR likely-subtags data replaces it with the locale-formatting
    /// work (INS-087, INS-088).
    pub fn direction(&self) -> Direction {
        const RTL_SCRIPTS: [&str; 9] = ["Arab", "Hebr", "Thaa", "Syrc", "Nkoo", "Adlm", "Rohg", "Mand", "Samr"];
        const RTL_LANGUAGES: [&str; 13] =
            ["ar", "he", "fa", "ur", "ps", "sd", "ug", "yi", "dv", "ckb", "syr", "nqo", "arc"];
        if let Some(script) = self.script() {
            return if RTL_SCRIPTS.contains(&script) { Direction::Rtl } else { Direction::Ltr };
        }
        // Pseudo-locale ar-XB is right-to-left; en-XA is left-to-right (ADR 0034).
        if RTL_LANGUAGES.contains(&self.language()) { Direction::Rtl } else { Direction::Ltr }
    }
}

impl fmt::Display for LanguageTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Text direction.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Direction {
    /// Left to right.
    Ltr,
    /// Right to left.
    Rtl,
}

impl Direction {
    /// `ltr` or `rtl`, as in render plans (INS-087).
    pub fn name(self) -> &'static str {
        match self {
            Direction::Ltr => "ltr",
            Direction::Rtl => "rtl",
        }
    }
}

/// The canonical-case form of a well-formed tag, or `None`.
fn canonicalise(text: &str) -> Option<String> {
    if text.is_empty() || text.len() > 64 {
        return None;
    }
    let subtags: Vec<&str> = text.split('-').collect();
    if subtags.iter().any(|s| s.is_empty() || s.len() > 8 || !alnum(s)) {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    let lang = subtags[0];
    if lang.eq_ignore_ascii_case("x") {
        // A private-use tag on its own.
        if subtags.len() < 2 {
            return None;
        }
        return Some(subtags.iter().map(|s| s.to_ascii_lowercase()).collect::<Vec<_>>().join("-"));
    }
    if !alpha(lang) || !(2..=8).contains(&lang.len()) || lang.len() == 4 {
        return None;
    }
    out.push(lang.to_ascii_lowercase());
    i += 1;
    // extlang: up to three 3-letter subtags, only after a 2-3 letter language.
    let mut ext = 0;
    while lang.len() <= 3 && i < subtags.len() && ext < 3 && subtags[i].len() == 3 && alpha(subtags[i]) {
        out.push(subtags[i].to_ascii_lowercase());
        i += 1;
        ext += 1;
    }
    if i < subtags.len() && subtags[i].len() == 4 && alpha(subtags[i]) {
        let s = subtags[i].to_ascii_lowercase();
        out.push(s[..1].to_ascii_uppercase() + &s[1..]);
        i += 1;
    }
    if i < subtags.len() && ((subtags[i].len() == 2 && alpha(subtags[i])) || (subtags[i].len() == 3 && digit(subtags[i]))) {
        out.push(subtags[i].to_ascii_uppercase());
        i += 1;
    }
    let mut variants = Vec::new();
    while i < subtags.len() {
        let s = subtags[i];
        let is_variant = (5..=8).contains(&s.len()) || (s.len() == 4 && s.as_bytes()[0].is_ascii_digit());
        if !is_variant {
            break;
        }
        let lower = s.to_ascii_lowercase();
        if variants.contains(&lower) {
            return None;
        }
        variants.push(lower.clone());
        out.push(lower);
        i += 1;
    }
    let mut singletons = Vec::new();
    while i < subtags.len() {
        let s = subtags[i].to_ascii_lowercase();
        if s.len() != 1 {
            return None;
        }
        if s == "x" {
            if i + 1 >= subtags.len() {
                return None;
            }
            out.extend(subtags[i..].iter().map(|t| t.to_ascii_lowercase()));
            return Some(out.join("-"));
        }
        if singletons.contains(&s) {
            return None;
        }
        singletons.push(s.clone());
        out.push(s);
        i += 1;
        let start = i;
        while i < subtags.len() && (2..=8).contains(&subtags[i].len()) {
            out.push(subtags[i].to_ascii_lowercase());
            i += 1;
        }
        if i == start {
            return None;
        }
    }
    Some(out.join("-"))
}

/// RFC 4647 §3.4 lookup: for each requested tag in priority order, progressively truncate
/// it (dropping a trailing singleton with the subtag it introduces) until it matches one of
/// `available`, comparing case-insensitively. If nothing matches, returns `default`
/// (INS-087).
pub fn lookup<'a>(requested: &[&str], available: &'a [LanguageTag], default: &'a LanguageTag) -> &'a LanguageTag {
    for range in requested {
        if *range == "*" {
            continue;
        }
        let mut candidate: Vec<&str> = range.split('-').filter(|s| *s != "*").collect();
        while !candidate.is_empty() {
            let text = candidate.join("-");
            if let Some(found) = available.iter().find(|t| t.as_str().eq_ignore_ascii_case(&text)) {
                return found;
            }
            candidate.pop();
            if candidate.last().is_some_and(|s| s.len() == 1) {
                candidate.pop();
            }
        }
    }
    default
}
