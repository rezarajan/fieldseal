//! HTML helpers: escaping, the page frame, fingerprint words with indices, and QR codes as
//! inline SVG.

use fieldseal_registration::domain::FingerprintWords;
use qrcode::{EcLevel, QrCode};

use crate::messages::t;

/// Escapes text for HTML element content and quoted attribute values.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

const STYLE: &str = "body{font-family:system-ui,sans-serif;max-width:52rem;margin:0 auto;padding:1rem;line-height:1.5;color:#111;background:#fff}\
a,button{font-size:1rem}button{padding:.4rem .8rem;cursor:pointer}\
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.4rem;border-bottom:1px solid #ccc;vertical-align:top}\
.words{font-size:1.25rem;font-weight:600}.idx{font-weight:400;color:#333}\
.warning{border:2px solid #a30;padding:.6rem;background:#fff4f0}.token{word-break:break-all;font-family:monospace;font-size:1rem}\
.skip{position:absolute;left:-999px}.skip:focus{left:1rem;top:1rem}svg{max-width:20rem;height:auto}";

/// A complete page: `lang`, a skip link, a heading and `main` landmark, and a sign-out
/// form when `csrf` is given (the person is signed in).
pub fn page(title_id: &str, body: &str, csrf: Option<&str>) -> String {
    let signout = csrf
        .map(|c| {
            format!(
                "<form method=\"post\" action=\"/sign-out\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><button type=\"submit\">{}</button></form>",
                escape(c),
                t("portal.signout.button")
            )
        })
        .unwrap_or_default();
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{title} · {site}</title><style>{STYLE}</style></head><body><a class=\"skip\" href=\"#main\">{skip}</a>\
<header><p>{site}</p>{signout}</header><main id=\"main\"><h1>{title}</h1>{body}</main></body></html>",
        title = t(title_id),
        site = t("portal.title"),
        skip = t("portal.skip"),
    )
}

/// Fingerprint words with each word's index beside it (REG-023), for example
/// `together (1821) · mail (1073) · …`. The list is fixed, whatever the display language.
pub fn words(w: &FingerprintWords) -> String {
    let parts: Vec<String> = w
        .words()
        .iter()
        .zip(w.indices())
        .map(|(word, i)| format!("<span lang=\"en\">{}</span> <span class=\"idx\">({i})</span>", escape(word)))
        .collect();
    format!("<span class=\"words\">{}</span>", parts.join(" · "))
}

/// A QR code for `text` as inline SVG, with a text alternative. Text forms are upper-case
/// Crockford base32, so the encoder picks alphanumeric mode (WIRE-122).
pub fn qr_svg(text: &str, label: &str) -> String {
    match QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M) {
        Ok(code) => {
            let svg = code.render::<qrcode::render::svg::Color>().min_dimensions(256, 256).quiet_zone(true).build();
            // Drop the XML declaration so the SVG can be inlined, and label it.
            svg.split_once("<svg").map(|(_, rest)| format!("<svg role=\"img\" aria-label=\"{}\"{rest}", escape(label))).unwrap_or(svg)
        }
        Err(_) => String::new(),
    }
}
