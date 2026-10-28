//! A strict well-formedness check for the pages this adapter writes: every element is
//! closed in order (void elements excepted), attribute values are double-quoted, character
//! references are well-formed, `<script>` and `<style>` hold raw text, and ids are unique.
//! Stricter than HTML5 parsing, which repairs what this refuses.

#![allow(dead_code)]

use std::collections::BTreeSet;

const VOID: &[&str] = &["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"];

/// `Ok` if `html` is well-formed, else where and why not.
pub fn check(html: &str) -> Result<(), String> {
    let b = html.as_bytes();
    let mut i = 0;
    let mut stack: Vec<String> = Vec::new();
    let mut ids = BTreeSet::new();
    let at = |i: usize| format!("byte {i}: {:?}", &html[i..html.len().min(i + 60)]);
    if !html.starts_with("<!DOCTYPE html>") {
        return Err("no doctype".into());
    }
    i += "<!DOCTYPE html>".len();
    while i < b.len() {
        match b[i] {
            b'<' if b.get(i + 1) == Some(&b'/') => {
                let end = html[i..].find('>').ok_or_else(|| at(i))? + i;
                let name = &html[i + 2..end];
                match stack.pop() {
                    Some(open) if open == name => {}
                    other => return Err(format!("{}: closes {name} but {other:?} is open", at(i))),
                }
                i = end + 1;
            }
            b'<' if html[i..].starts_with("<!--") => {
                i = html[i..].find("-->").ok_or_else(|| at(i))? + i + 3;
            }
            b'<' => {
                let mut j = i + 1;
                while j < b.len() && (b[j].is_ascii_alphanumeric()) {
                    j += 1;
                }
                let name = html[i + 1..j].to_ascii_lowercase();
                if name.is_empty() {
                    return Err(format!("{}: a bare `<`", at(i)));
                }
                // Attributes.
                loop {
                    while b[j] == b' ' || b[j] == b'\n' {
                        j += 1;
                    }
                    if b[j] == b'>' {
                        j += 1;
                        break;
                    }
                    let s = j;
                    while b[j] != b'=' && b[j] != b' ' && b[j] != b'>' {
                        if !(b[j].is_ascii_alphanumeric() || b[j] == b'-') {
                            return Err(format!("{}: bad attribute name", at(j)));
                        }
                        j += 1;
                    }
                    let attr = &html[s..j];
                    if b[j] == b'=' {
                        if b[j + 1] != b'"' {
                            return Err(format!("{}: unquoted attribute", at(j)));
                        }
                        let v0 = j + 2;
                        let v1 = html[v0..].find('"').ok_or_else(|| at(j))? + v0;
                        let value = &html[v0..v1];
                        if value.contains('<') {
                            return Err(format!("{}: `<` in an attribute", at(v0)));
                        }
                        references(value).map_err(|e| format!("{}: {e}", at(v0)))?;
                        if attr == "id" && !ids.insert(value.to_owned()) {
                            return Err(format!("{}: duplicate id {value}", at(v0)));
                        }
                        j = v1 + 1;
                    }
                }
                if name == "script" || name == "style" {
                    let close = format!("</{name}>");
                    let end = html[j..].find(&close).ok_or_else(|| at(i))? + j;
                    i = end + close.len();
                } else {
                    if !VOID.contains(&name.as_str()) {
                        stack.push(name);
                    }
                    i = j;
                }
            }
            b'>' => return Err(format!("{}: a bare `>`", at(i))),
            _ => {
                let end = html[i..].find('<').map_or(b.len(), |e| e + i);
                references(&html[i..end]).map_err(|e| format!("{}: {e}", at(i)))?;
                if html[i..end].contains('>') {
                    return Err(format!("{}: a bare `>` in text", at(i)));
                }
                i = end;
            }
        }
    }
    if stack.is_empty() { Ok(()) } else { Err(format!("unclosed: {stack:?}")) }
}

fn references(s: &str) -> Result<(), String> {
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        let after = &rest[p + 1..];
        let end = after.find(';').ok_or("an unterminated `&`")?;
        let name = &after[..end];
        let ok = match name.strip_prefix('#') {
            Some(n) => !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()),
            None => ["amp", "lt", "gt", "quot"].contains(&name),
        };
        if !ok {
            return Err(format!("a bad reference `&{name};`"));
        }
        rest = &after[end + 1..];
    }
    Ok(())
}

// covers: INS-208
#[test]
fn the_checker_refuses_broken_markup() {
    let ok = "<!DOCTYPE html><html><body><p class=\"a\">x &amp; y<br></p><script>if (a < b) {}</script></body></html>";
    assert!(check(ok).is_ok());
    for bad in [
        "<!DOCTYPE html><p><b></p></b>",
        "<!DOCTYPE html><p class=a></p>",
        "<!DOCTYPE html><p>a & b</p>",
        "<!DOCTYPE html><p>",
        "<!DOCTYPE html><p id=\"x\"></p><p id=\"x\"></p>",
        "<!DOCTYPE html><p>a > b</p>",
    ] {
        assert!(check(bad).is_err(), "{bad}");
    }
}
