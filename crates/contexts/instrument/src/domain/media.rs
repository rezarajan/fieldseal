//! Media rules (INS-180–INS-183): image types, size limits, SVG restrictions and emoji icons.
//!
//! The SVG check is textual, not a parser: the document must be UTF-8, declare
//! `version="1.2"` and `baseProfile="tiny"` on its root `<svg>`, and contain no scripts,
//! event attributes, animation elements, `<foreignObject>`, entity declarations, external
//! `href`s or non-fragment `url(…)` references. A full SVG Tiny 1.2 validator is out of scope.

/// The largest single image (INS-182).
pub const MAX_IMAGE_BYTES: usize = 1024 * 1024;
/// The largest total of all media (INS-182).
pub const MAX_TOTAL_MEDIA_BYTES: usize = 8 * 1024 * 1024;

/// The media types allowed (INS-180).
pub const MEDIA_TYPES: [&str; 3] = ["image/png", "image/webp", "image/svg+xml"];

/// Why an image was refused, if it was.
pub fn image_problem(media_type: &str, bytes: &[u8]) -> Option<String> {
    match media_type {
        "image/png" if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") => Some("the bytes are not a PNG image".into()),
        "image/webp" if !(bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP") => Some("the bytes are not a WebP image".into()),
        "image/svg+xml" => svg_problem(bytes),
        _ => None,
    }
}

fn svg_problem(bytes: &[u8]) -> Option<String> {
    let Ok(text) = std::str::from_utf8(bytes) else { return Some("SVG must be UTF-8 text".into()) };
    let lower = text.to_ascii_lowercase();
    let Some(root_start) = lower.find("<svg") else { return Some("no <svg> root element".into()) };
    let root_end = lower[root_start..].find('>').map_or(lower.len(), |e| root_start + e);
    let root = &lower[root_start..root_end];
    let compact: String = root.chars().filter(|c| !c.is_whitespace()).collect();
    let declares = |attr: &str, value: &str| compact.contains(&format!("{attr}=\"{value}\"")) || compact.contains(&format!("{attr}='{value}'"));
    if !declares("version", "1.2") || !declares("baseprofile", "tiny") {
        return Some("SVG must declare version=\"1.2\" baseProfile=\"tiny\" (SVG Tiny 1.2)".into());
    }
    for banned in ["<script", "<foreignobject", "<!entity", "<!doctype", "<animate", "<set", "<handler", "<listener", "javascript:"] {
        if lower.contains(banned) {
            return Some(format!("SVG must not contain `{banned}`"));
        }
    }
    // Event-handler attributes: whitespace, then `on…=`.
    let b = lower.as_bytes();
    for i in 1..b.len().saturating_sub(3) {
        if b[i - 1].is_ascii_whitespace() && b[i] == b'o' && b[i + 1] == b'n' {
            let rest = &lower[i + 2..];
            let name_len = rest.bytes().take_while(|c| c.is_ascii_alphabetic()).count();
            if name_len > 0 && rest[name_len..].trim_start().starts_with('=') {
                return Some("SVG must not have event-handler attributes".into());
            }
        }
    }
    // References must stay inside the document.
    for (needle, quoted) in [("href=", true), ("url(", false)] {
        let mut from = 0;
        while let Some(pos) = lower[from..].find(needle) {
            let start = from + pos + needle.len();
            let target = lower[start..].trim_start();
            let target = if quoted { target.trim_start_matches(['"', '\'']) } else { target.trim_start_matches(['"', '\'', ' ']) };
            if !target.starts_with('#') {
                return Some("SVG must not reference anything outside itself".into());
            }
            from = start;
        }
    }
    None
}

/// Whether `s` is a single emoji (INS-183): one pictographic base, or a flag of two
/// regional indicators, or a keycap, with optional variation selectors, skin-tone
/// modifiers, tags and zero-width-joined parts.
pub fn is_single_emoji(s: &str) -> bool {
    let pictographic = |c: char| {
        matches!(c as u32,
            0x1F000..=0x1FAFF | 0x2600..=0x27BF | 0x2300..=0x23FF | 0x2B00..=0x2BFF | 0x2190..=0x21FF
            | 0x2934..=0x2935 | 0x3030 | 0x303D | 0x3297 | 0x3299 | 0x00A9 | 0x00AE | 0x203C | 0x2049
            | 0x2122 | 0x2139 | 0x24C2 | 0x25AA..=0x25FE)
    };
    let regional = |c: char| matches!(c as u32, 0x1F1E6..=0x1F1FF);
    let modifier = |c: char| matches!(c as u32, 0xFE0E | 0xFE0F | 0x1F3FB..=0x1F3FF | 0xE0020..=0xE007F | 0x20E3);
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() || chars.len() > 16 {
        return false;
    }
    // Keycap: [0-9#*] FE0F? 20E3
    if matches!(chars[0], '0'..='9' | '#' | '*') {
        return matches!(chars[1..], ['\u{FE0F}', '\u{20E3}'] | ['\u{20E3}']);
    }
    if chars.len() >= 2 && regional(chars[0]) {
        return chars.len() == 2 && regional(chars[1]);
    }
    let mut expect_base = true;
    for c in chars {
        if expect_base {
            if !pictographic(c) || regional(c) {
                return false;
            }
            expect_base = false;
        } else if c == '\u{200D}' {
            expect_base = true;
        } else if !modifier(c) {
            return false;
        }
    }
    !expect_base
}
