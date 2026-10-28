//! Item paths, path segments and codes (INS-012, INS-126, INS-136).

/// The longest item path (INS-012).
pub const MAX_PATH_LEN: usize = 128;

/// Whether `s` is one path segment: `[a-z][a-z0-9_]*`.
pub fn is_segment(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Whether `s` is an item path: dot-separated segments, at most 128 characters (INS-012).
pub fn is_item_path(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_PATH_LEN && s.split('.').all(is_segment)
}

/// Whether `s` is a code: 1–64 characters of ASCII letters, digits, `_` and `-`, starting
/// with a letter or digit. Codes are stable identifiers (INS-136), never display text.
pub fn is_code(s: &str) -> bool {
    let mut chars = s.chars();
    s.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Whether `s` is an identifier for rules, field checks, code lists, tables, media and
/// atomic groups: 1–64 characters of lowercase letters, digits, `_` and `-`, starting with a
/// letter.
pub fn is_id(s: &str) -> bool {
    let mut chars = s.chars();
    s.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Whether `s` is a calendar date `YYYY-MM-DD` (proleptic Gregorian).
pub fn is_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let part = &s[r];
        part.bytes().all(|c| c.is_ascii_digit()).then(|| part.parse().ok()).flatten()
    };
    let (Some(y), Some(m), Some(d)) = (num(0..4), num(5..7), num(8..10)) else { return false };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&d)
}
