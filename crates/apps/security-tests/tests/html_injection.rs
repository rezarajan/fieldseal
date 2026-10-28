//! HTML preview and portal injection (ADR 0033, INS-085, INS-208, REG portal).
//!
//! Hostile text goes in through every door the preview has: instrument texts (which
//! validation should refuse), and roster fields and answers (which reach the page without
//! that check). The page must come out inert: one inline script, no event handlers, no
//! attribute breakouts, no bidirectional overrides. The portal's pages get the same, plus CSRF.

use std::collections::BTreeMap;

use fieldseal_adapters_authoring::{Format, decode};
use fieldseal_adapters_html::{Page, render_html};
use fieldseal_instrument::application::{PlanLayout, PlanRequest, compile_render_plan, validate_instrument};
use fieldseal_instrument::domain::WindowClass;
use fieldseal_kernel::Value;

const HOSTILE: &[&str] = &[
    "<script>alert(1)</script>",
    "</title><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "' onmouseover='alert(1)",
    "\" autofocus onfocus=\"alert(1)",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "a\u{202E}gnirts evil\u{202C}b",
    "\u{202A}x\u{202B}y\u{202D}z\u{202E}",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "<!--",
    "]]></style><script>alert(1)</script>",
];

fn fixture() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../adapters/html/tests/fixtures/sampler.yaml");
    decode(&std::fs::read(path).unwrap(), Format::Yaml).unwrap()
}

/// Replaces the English text of every label in the document by `hostile` plus a counter, so
/// labels stay unique (a duplicate would be refused for a reason that has nothing to do with
/// hostility).
fn poison(v: &Value, hostile: &str) -> Value {
    fn go(v: &Value, hostile: &str, n: &mut u32) -> Value {
        match v {
            Value::Map(m) => Value::Map(
                m.iter()
                    .map(|(k, x)| {
                        let y = match (k.as_str(), x) {
                            // Complex MF2 messages (`.match …`) are left alone: rewriting them
                            // breaks the message for a reason unrelated to hostile text.
                            ("en", Value::Text(orig)) if orig.trim_start().starts_with('.') => x.clone(),
                            ("en", Value::Text(orig)) => {
                                *n += 1;
                                // Keep message variables: every language must use the same ones.
                                let vars = if orig.contains("{$") { orig.as_str() } else { "" };
                                Value::Text(format!("{hostile} {n} {vars}"))
                            }
                            _ => go(x, hostile, n),
                        };
                        (k.clone(), y)
                    })
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.iter().map(|x| go(x, hostile, n)).collect()),
            other => other.clone(),
        }
    }
    go(v, hostile, &mut 0)
}

/// The page with its one allowed inline `<script>` and `<style>` cut out.
fn markup(html: &str) -> String {
    let cut = |s: &str, open: &str, close: &str| {
        let a = s.find(open).unwrap();
        let b = s[a..].find(close).unwrap() + a + close.len();
        format!("{}{}", &s[..a], &s[b..])
    };
    cut(&cut(html, "<style>", "</style>"), "<script>", "</script>")
}

/// How many times `needle` occurs in `s`.
fn count(s: &str, needle: &str) -> usize {
    s.matches(needle).count()
}

/// Asserts that nothing hostile survives as markup: the page has exactly the elements and
/// attributes the same page has with benign input, and no bidirectional override.
fn assert_inert(what: &str, html: &str) {
    let benign = BENIGN.with(|b| b.clone());
    let (m, base) = (markup(html), markup(&benign));
    for needle in ["<script", "<img", "<svg", "<iframe", "<object", "<embed", "<link", "<meta", "<base", "<a ", "<form", "<!--", "<style", "</title", "<input", "<textarea", "<button"] {
        assert_eq!(count(&m, needle), count(&base, needle), "{what}: the number of {needle} changed");
    }
    assert_eq!(count(html, "<script"), 1, "{what}: more than the page's own script");
    assert_eq!(count(html, "<style"), 1, "{what}: more than the page's own style");
    // Quotes balance inside every tag, and no attribute name outside a quoted value is a handler.
    let (mut in_tag, mut in_quote) = (false, false);
    let chars: Vec<char> = m.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        match c {
            '<' if !in_quote => in_tag = true,
            '>' if in_tag && !in_quote => in_tag = false,
            '"' if in_tag => in_quote = !in_quote,
            c if c.is_whitespace() && in_tag && !in_quote => {
                let rest: String = chars[i + 1..].iter().take(24).collect();
                if rest.starts_with("on") {
                    let name: String = rest.chars().take_while(|c| c.is_ascii_lowercase()).collect();
                    assert!(!rest[name.len()..].starts_with('='), "{what}: event handler attribute {name}");
                }
                assert!(!rest.starts_with("style="), "{what}: inline style attribute");
            }
            _ => {}
        }
    }
    // A scheme in a URL-bearing attribute would be an injection.
    for attr in ["href=\"javascript:", "src=\"javascript:", "action=\"javascript:", "formaction=\"javascript:"] {
        assert!(!m.contains(attr), "{what}: {attr}");
    }
    assert!(!in_tag && !in_quote, "{what}: unbalanced tag or attribute quotes");
    assert!(!html.chars().any(|c| ('\u{202A}'..='\u{202E}').contains(&c)), "{what}: a bidirectional override reached the page");
}

thread_local! {
    static BENIGN: String = {
        let roster = BTreeMap::from([("name".to_owned(), Value::Text("Ann".into()))]);
        render_with(&fixture(), &BTreeMap::new(), &roster).expect("the sampler renders")
    };
}

fn render_with(doc: &Value, values: &BTreeMap<String, Value>, roster: &BTreeMap<String, Value>) -> Result<String, String> {
    let ins = validate_instrument(doc).map_err(|f| format!("{} findings", f.len()))?.instrument;
    let plan = compile_render_plan(&ins, PlanLayout::Default, PlanRequest { languages: &["en"], window_class: WindowClass::Medium }).map_err(|e| format!("{e:?}"))?;
    let mut page = Page::new(&plan, &ins);
    page.values = values;
    page.roster = roster;
    Ok(render_html(&page))
}

/// INS-085 + INS-208: instrument text with markup, entity tricks or bidi overrides is
/// refused at validation; whatever validation lets through is escaped by the renderer.
#[test]
fn ins_085_hostile_instrument_text_is_refused_or_escaped() {
    let doc = fixture();
    let (mut refused, mut rendered) = (0, 0);
    for h in HOSTILE {
        match render_with(&poison(&doc, h), &BTreeMap::new(), &BTreeMap::new()) {
            Err(_) => refused += 1,
            Ok(html) => {
                rendered += 1;
                assert_inert(&format!("instrument text {h:?}"), &html);
            }
        }
    }
    assert!(refused >= 6, "validation refuses markup, references and bidi controls ({refused} refused, {rendered} rendered)");
    assert!(rendered >= 1, "plain quotes still render, escaped");
}

/// INS-208: roster fields and answers reach the page without validation; the renderer alone
/// must keep them inert (the preview is the author's own browser).
#[test]
fn ins_208_hostile_roster_fields_and_answers_are_escaped_by_the_renderer() {
    let doc = fixture();
    for h in HOSTILE {
        let roster = BTreeMap::from([("name".to_owned(), Value::Text((*h).to_owned()))]);
        let values: BTreeMap<String, Value> = ["who", "pick", "pick.other", "things.other", "note", "comment"]
            .iter()
            .map(|k| ((*k).to_owned(), Value::Text((*h).to_owned())))
            .collect();
        let html = render_with(&doc, &values, &roster).expect("the sampler renders");
        assert_inert(&format!("roster/answer {h:?}"), &html);
    }
}

/// Rendering never panics on hostile Unicode (surrogate-adjacent, combining floods, very long).
#[test]
fn ins_208_pathological_text_renders_without_panic() {
    let doc = fixture();
    let long = "x".repeat(200_000);
    let combining = format!("a{}", "\u{0301}".repeat(5000));
    for h in [long.as_str(), combining.as_str(), "\u{FEFF}\u{200B}\u{2028}\u{2029}", "\u{10FFFF}\u{0}"] {
        let roster = BTreeMap::from([("name".to_owned(), Value::Text(h.to_owned()))]);
        let html = render_with(&doc, &BTreeMap::new(), &roster).expect("renders");
        assert_inert("pathological", &html);
    }
}

