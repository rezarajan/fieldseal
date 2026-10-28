//! Escaping and encoding. Every piece of instrument content is untrusted: it reaches the page
//! only through [`text`] or [`attr`], and never inside `<script>` or `<style>`.

/// Escapes text for an HTML text node or a double-quoted attribute value: `&`, `<`, `>`, `"`
/// and `'` become character references. Control characters other than line feed and tab
/// (which INS-085 already refuses) are dropped, so nothing invisible can reach the page. So
/// are the bidirectional embedding and override characters U+202A to U+202E: INS-085 refuses
/// them in instrument texts, but roster fields and answers reach the page without that check,
/// and an override can reorder the text around it to spoof what the collector reads. The
/// isolates U+2066 to U+2069 stay.
pub fn text(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    push_text(&mut out, s);
    out
}

/// Appends `s`, escaped as by [`text`], to `out`.
pub fn push_text(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\n' | '\t' => out.push(c),
            c if c.is_control() || matches!(c, '\u{202A}'..='\u{202E}') => {}
            c => out.push(c),
        }
    }
}

/// Escapes a double-quoted attribute value. Line breaks become spaces.
pub fn attr(s: &str) -> String {
    text(&s.replace(['\n', '\t'], " "))
}

/// Escapes text and turns line feeds into `<br>`, for multi-line texts (INS-085 allows line
/// breaks).
pub fn multiline(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for (i, line) in s.split('\n').enumerate() {
        if i > 0 {
            out.push_str("<br>");
        }
        push_text(&mut out, line);
    }
    out
}

/// Standard base64 with padding (RFC 4648 §4), for `data:` URIs and CSP hashes.
pub fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[n as usize & 63] as char } else { '=' });
    }
    out
}
