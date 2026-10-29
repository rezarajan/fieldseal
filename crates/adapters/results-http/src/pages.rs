//! The reader's HTML. It shows what the landing and the export say and computes nothing from
//! the answers (INT-092): counts are the manifest's.

use fieldseal_adapters_portal::{Request, Response, SessionView};

use crate::ResultsHttp;

const STATEMENT: &str = "These files hold free text, special-category items (marked in the data contract), the consent basis and record, and tenancy and sequence ids. They are outside Fieldseal's protection once downloaded: store and share them as personal data.";

/// Rows per page of the table.
const PAGE_ROWS: usize = 50;

pub(crate) fn escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '"' => "&quot;".chars().collect(),
            '\'' => "&#39;".chars().collect(),
            c => vec![c],
        })
        .collect()
}

pub(crate) fn shell(title: &str, body: &str, signed_in: Option<&str>) -> String {
    let out = signed_in
        .map(|csrf| format!("<form method=\"post\" action=\"/sign-out\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><button type=\"submit\">Sign out</button></form>", escape(csrf)))
        .unwrap_or_default();
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{t} - Fieldseal results</title><style>body{{font-family:system-ui,sans-serif;margin:1rem auto;max-width:72rem;padding:0 1rem;line-height:1.5}}table{{border-collapse:collapse;display:block;overflow-x:auto}}td,th{{border:1px solid #888;padding:.2rem .5rem;text-align:left;vertical-align:top}}pre{{overflow-x:auto;background:#f2f2f2;color:#111;padding:.5rem}}.notice{{border:2px solid #b45309;padding:.5rem}}</style></head><body><header><h1>{t}</h1>{out}</header><main>{body}</main></body></html>",
        t = escape(title)
    )
}

/// The records of CSV text (RFC 4180), one at a time, so a page parses only the rows it shows.
fn records(text: &str) -> impl Iterator<Item = Vec<String>> + '_ {
    let mut chars = text.chars().peekable();
    std::iter::from_fn(move || {
        let (mut record, mut field, mut quoted) = (Vec::new(), String::new(), false);
        while let Some(c) = chars.next() {
            match c {
                '"' if quoted && chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => quoted = !quoted,
                ',' if !quoted => record.push(std::mem::take(&mut field)),
                '\n' if !quoted => {
                    record.push(field);
                    return Some(record);
                }
                c => field.push(c),
            }
        }
        // Text that does not end in a newline loses its last, unterminated record.
        None
    })
}

impl ResultsHttp<'_> {
    pub(crate) fn results_page(&self, req: &Request, session: &SessionView) -> Response {
        let held = match self.current() {
            Ok(h) => h,
            Err(e) => return Response::html(503, shell("Results unavailable", &format!("<p>{}</p>", escape(&e)), Some(&session.csrf)), &self.cfg.csp),
        };
        let file = |name: &str| held.export.files.iter().find(|(n, _)| n == name).map(|(_, b)| String::from_utf8_lossy(b)).unwrap_or_default();
        let mark = held.mark;
        let mut body = String::new();
        body.push_str(&format!("<p class=\"notice\">{}</p>", escape(STATEMENT)));
        if !self.cfg.development_adapters.is_empty() {
            let list: Vec<String> = self.cfg.development_adapters.iter().map(|(p, a)| format!("{}: {}", escape(p), escape(a))).collect();
            body.push_str(&format!("<p class=\"notice\">Development adapters in use (not for production): {}</p>", list.join(", ")));
        }
        body.push_str(&format!("<p>Landing mark {mark}. Submissions that start-up replay could not land: {}.</p>", self.cfg.replay_gap));
        body.push_str("<h2>Downloads</h2><table><tr><th>File</th><th>Bytes</th><th>Rows</th></tr>");
        for f in &held.export.result.files {
            let rows = f.rows.map(|r| r.to_string()).unwrap_or_default();
            body.push_str(&format!("<tr><td><a href=\"/results/exports/{mark}/{n}\">{n}</a></td><td>{}</td><td>{rows}</td></tr>", f.bytes, n = escape(&f.name)));
        }
        body.push_str(&format!("<tr><td><a href=\"/results/exports/{mark}/manifest.json\">manifest.json</a></td><td></td><td></td></tr></table>"));
        body.push_str(&format!("<h2>Manifest</h2><pre>{}</pre>", escape(&file("manifest.json"))));
        // The count is the manifest's. A page number past the end is the last page.
        let total = held.export.result.files.iter().find(|f| f.name == "results.csv").and_then(|f| f.rows).unwrap_or(0) as usize;
        let pages = total.div_ceil(PAGE_ROWS).max(1);
        let page: usize = req.query.get("page").and_then(|p| p.parse().ok()).unwrap_or(1).clamp(1, pages);
        body.push_str(&format!("<h2>Results</h2><p>{total} rows. Page {page} of {pages}.</p>"));
        let results = file("results.csv");
        let mut records = records(&results);
        let header = records.next().unwrap_or_default();
        body.push_str("<table><tr>");
        for h in &header {
            body.push_str(&format!("<th>{}</th>", escape(h)));
        }
        body.push_str("</tr>");
        for r in records.skip((page - 1).saturating_mul(PAGE_ROWS)).take(PAGE_ROWS) {
            body.push_str("<tr>");
            for c in &r {
                body.push_str(&format!("<td>{}</td>", escape(c)));
            }
            body.push_str("</tr>");
        }
        body.push_str("</table><p>");
        if page > 1 {
            body.push_str(&format!("<a href=\"/results?page={}\">Previous</a> ", page.saturating_sub(1)));
        }
        if page < pages {
            body.push_str(&format!("<a href=\"/results?page={}\">Next</a>", page.saturating_add(1)));
        }
        body.push_str("</p><h2>Data contracts</h2><ul>");
        for (n, _) in held.export.files.iter().filter(|(n, _)| n.starts_with("contracts/")) {
            body.push_str(&format!("<li><a href=\"/results/exports/{mark}/{n}\">{n}</a></li>", n = escape(n)));
        }
        body.push_str("</ul>");
        Response::html(200, shell("Results", &body, Some(&session.csrf)), &self.cfg.csp)
    }
}
