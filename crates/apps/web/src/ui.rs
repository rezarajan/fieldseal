//! The page shell and small HTML helpers shared by every page.

use crate::http::Response;

/// The navigation: label and path.
pub const NAV: [(&str, &str); 5] =
    [("Instruments", "/instruments"), ("Publishing", "/publishing"), ("Registration", "/registration"), ("Device", "/device"), ("Intake", "/intake")];

/// The line every page carries at the bottom.
pub const FOOTER: &str = "Development showcase: unattested software device, not for production";

/// Escapes text for HTML content and double-quoted attributes.
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

/// The stylesheets every page links, in order: tokens, the bundled font, the app's own rules.
const STYLES: [&str; 3] = ["/assets/tokens.css", "/assets/nunito-sans.css", "/assets/app.css"];

/// The script that switches [`tabs`] panels by URL hash; without it every panel stays open.
pub const TABS_JS: &str = "/assets/tabs.js";

/// Wraps `body` (already HTML) in the page shell. `active` is the nav path to mark current;
/// `scripts` are module script URLs. The shell is a 72px bar with the wordmark and the five
/// pipeline destinations as step pills (HICK: at most five top-level links), the page body and
/// the honest footer. Pages that use [`tabs`] get the tiny tab script.
pub fn shell(title: &str, active: &str, body: &str, scripts: &[&str]) -> String {
    let nav: String = NAV
        .iter()
        .map(|(label, path)| {
            let current = if active == *path { " aria-current=\"page\"" } else { "" };
            format!("<a href=\"{path}\"{current}>{label}</a>")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut scripts: Vec<&str> = scripts.to_vec();
    if body.contains("data-tabs") && !scripts.contains(&TABS_JS) {
        scripts.push(TABS_JS);
    }
    let scripts: String = scripts.iter().map(|s| format!("<script type=\"module\" src=\"{}\"></script>\n", escape(s))).collect();
    let styles: String = STYLES.iter().map(|s| format!("<link rel=\"stylesheet\" href=\"{s}\">\n")).collect();
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>{} - Fieldseal showcase</title>\n{styles}</head>\n<body>\n<header class=\"appbar\"><div class=\"brand\"><span class=\"mark\" aria-hidden=\"true\"></span><span class=\"wordmark\">Fieldseal</span></div>\n<nav class=\"pipeline\" aria-label=\"Pipeline\">\n{nav}\n</nav></header>\n<main class=\"page\">\n{body}\n</main>\n<footer class=\"foot\">{FOOTER}</footer>\n{scripts}</body>\n</html>\n",
        escape(title)
    )
}

/// One tab: the panel id (also its URL hash), the label and the panel's HTML.
pub struct Tab<'a> {
    /// The panel's element id.
    pub id: &'a str,
    /// The tab's label.
    pub label: String,
    /// The panel's content (already HTML).
    pub html: String,
}

/// Secondary content behind tabs (progressive disclosure). Server-rendered: every panel is in
/// the page, so without script each is reachable in turn; with `/assets/tabs.js` only the
/// one named by the URL hash (default the first) shows.
pub fn tabs(label: &str, items: &[Tab<'_>]) -> String {
    let list: String = items
        .iter()
        .enumerate()
        .map(|(i, t)| format!("<a class=\"tab\" role=\"tab\" href=\"#{0}\" aria-controls=\"{0}\" aria-selected=\"{1}\">{2}</a>", t.id, i == 0, escape(&t.label)))
        .collect::<Vec<_>>()
        .join("\n");
    let panels: String = items.iter().map(|t| format!("<section id=\"{}\" class=\"tabpanel\" role=\"tabpanel\">\n{}\n</section>\n", t.id, t.html)).collect();
    format!("<div class=\"tabs\" data-tabs>\n<div class=\"tablist\" role=\"tablist\" aria-label=\"{}\">\n{list}\n</div>\n{panels}</div>\n", escape(label))
}

/// A full page response.
pub fn page(title: &str, active: &str, body: &str, scripts: &[&str]) -> Response {
    Response::page(200, shell(title, active, body, scripts))
}

/// A plain error page: one primary action, back to the instruments.
pub fn error_page(status: u16, message: &str) -> Response {
    let body = format!("<h1>{status}</h1>\n<p>{}</p>\n<p><a class=\"btn btn-primary\" href=\"/instruments\">Back to the instruments</a></p>", escape(message));
    Response::page(status, shell(&format!("Error {status}"), "", &body, &[]))
}

/// The honest placeholder for a page that is not built yet.
pub fn placeholder(title: &str, path: &str, what: &str) -> Response {
    let body = format!("<h1>{}</h1>\n<p>Not built yet in this slice. {}</p>\n<p><a class=\"btn btn-primary\" href=\"/instruments\">Back to the instruments</a></p>", escape(title), escape(what));
    page(title, path, &body, &[])
}
