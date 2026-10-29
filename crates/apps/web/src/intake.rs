//! The Intake page (WEB-160 to WEB-162): runs the real verification gate on an uploaded
//! export, and shows submissions, the loss ledger, the landed long-format rows (paged and
//! filterable by column) and the data contract from the demo authority's intake. The tool
//! derives nothing from the answers: no indicators, scores, conversions or statistics. That
//! is the data platform's job.

use fieldseal_adapters_web_demo::{IngestReport, IntakeReport};

use crate::http::{MAX_INGEST_BODY, Request, Response};
use crate::state::AppState;
use crate::ui::{self, escape};

/// How many long-format rows a page of the table shows; the CSV has all of them.
pub const ROW_PAGE_SIZE: usize = 50;

/// Handles the routes of this page.
pub fn handle(state: &AppState, req: &Request) -> Option<Response> {
    let route = (req.method.as_str(), req.path.as_str());
    if !matches!(route, ("GET", "/intake" | "/intake/rows.csv" | "/intake/contract.json") | ("POST", "/intake/ingest")) {
        return None;
    }
    let Some(demo) = state.demo else {
        return Some(match route {
            ("GET", "/intake") => ui::page("Intake", "/intake", NO_DEMO, &[]),
            ("POST", _) => Response::json(404, "{\"ok\":false,\"error\":\"intake runs inside the demo authority\"}"),
            _ => Response::text(404, "Intake runs inside the demo authority (FIELDSEAL_WEB_DEMO_AUTHORITY=true)."),
        });
    };
    let intake = demo.0.intake();
    Some(match route {
        ("GET", "/intake") => ui::page("Intake", "/intake", &body(state, demo.0, &intake.report(), req), &["/assets/intake.js"]),
        ("GET", "/intake/rows.csv") => csv("rows.csv", intake.report().rows_csv()),
        ("GET", "/intake/contract.json") => Response::json(200, contract_json(state, demo.0)),
        _ => {
            if req.body.len() > MAX_INGEST_BODY {
                return Some(Response::json(413, "{\"ok\":false,\"error\":\"the file is too large\"}"));
            }
            match intake.ingest_export(&req.body) {
                Ok(r) => Response::json(200, ingest_json(&r)),
                Err(e) => Response::json(400, format!("{{\"ok\":false,\"error\":{}}}", json_str(&e))),
            }
        }
    })
}

const NO_DEMO: &str = "<div class=\"page-head\"><div><h1>Intake</h1>\n<p class=\"lede\">Intake runs inside the demo authority (start with FIELDSEAL_WEB_DEMO_AUTHORITY=true) or on the command line with <code>fieldseal intake run</code>. See docs/how-to/use-the-web-app.md.</p></div>\n<div class=\"head-actions\"><a class=\"btn btn-primary\" href=\"/instruments\">Go to the instruments</a></div></div>";

fn csv(name: &str, text: String) -> Response {
    Response::new(200, "text/csv; charset=utf-8", text.into_bytes()).with("Content-Disposition", &format!("attachment; filename=\"{name}\""))
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn opt(s: &Option<String>) -> String {
    s.as_deref().map_or("null".to_owned(), json_str)
}

fn ingest_json(r: &IngestReport) -> String {
    format!(
        "{{\"ok\":true,\"state\":{},\"rejection_stage\":{},\"rejection_code\":{},\"receipts\":{},\"landed\":{},\"duplicates\":{},\"held\":{},\"conflicts\":{},\"observations\":{},\"losses\":{}}}",
        json_str(&r.submission.state),
        opt(&r.submission.rejection_stage),
        opt(&r.submission.rejection_code),
        r.receipts.len(),
        r.landed,
        r.duplicates,
        r.held,
        r.conflicts,
        r.observations,
        r.losses
    )
}

fn body(state: &AppState, demo: &fieldseal_adapters_web_demo::Demo, r: &IntakeReport, req: &Request) -> String {
    let mut b = String::from("<div class=\"page-head\"><div><h1>Intake</h1>\n<p class=\"lede\">The demo authority's intake: the real verification gate, over in-memory ports. Pages are server-rendered snapshots; reload to see new uploads.</p></div></div>\n");
    b.push_str("<section id=\"gate\" class=\"card\">\n<h2>Run the gate on a file</h2>\n<p>Choose an export file made by a device. Its bytes go to the server and through the same gate that handles uploads; what verifies is landed.</p>\n<form id=\"gate-form\" class=\"gate-form\"><input type=\"file\" id=\"gate-file\" aria-label=\"Export file\"> <button type=\"submit\" class=\"btn btn-primary\">Run the gate</button></form>\n<pre id=\"gate-result\" aria-live=\"polite\"></pre>\n</section>\n");

    let mut subs = String::from("<h3>Submissions</h3>\n");
    if r.submissions.is_empty() {
        subs.push_str("<p>Nothing has been submitted yet, by file or by the browser device's upload.</p>\n");
    } else {
        subs.push_str("<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Table, scrolls sideways\"><table>\n<tr><th>Submission</th><th>Source</th><th>Gate state</th><th>Rejection</th></tr>\n");
        for s in &r.submissions {
            let rej = match (&s.rejection_stage, &s.rejection_code) {
                (Some(st), Some(c)) => format!("{} / {}{}", st, c, s.rejection_detail.as_ref().map(|d| format!(": {d}")).unwrap_or_default()),
                (Some(st), None) => st.clone(),
                _ => String::new(),
            };
            subs.push_str(&format!("<tr><td><code class=\"hash\">{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>\n", escape(&s.id), escape(&s.source), escape(&s.state), escape(&rej)));
        }
        subs.push_str("</table></div>\n");
    }

    let mut losses = String::from("<h3>Loss ledger</h3>\n<p>What was not landed, and why.</p>\n");
    if r.losses.is_empty() {
        losses.push_str("<p>No losses recorded.</p>\n");
    } else {
        losses.push_str("<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Table, scrolls sideways\"><table>\n<tr><th>Tenancy</th><th>From seq</th><th>Through seq</th><th>Reason</th></tr>\n");
        for l in &r.losses {
            losses.push_str(&format!("<tr><td><code class=\"hash\">{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>\n", escape(&l.tenancy), l.from_seq, l.through_seq, escape(&l.reason)));
        }
        losses.push_str("</table></div>\n");
    }

    let rows = rows_tab(r, req);
    let contract = contract_tab(state, demo);
    let tabs = [
        ui::Tab { id: "submissions", label: format!("Submissions ({})", r.submissions.len()), html: subs },
        ui::Tab { id: "losses", label: format!("Losses ({})", r.losses.len()), html: losses },
        ui::Tab { id: "rows", label: format!("Rows ({})", r.rows.len()), html: rows },
        ui::Tab { id: "contract", label: "Data contract".to_owned(), html: contract },
    ];
    b.push_str(&ui::tabs("What the intake holds", &tabs));
    b
}

/// The columns of the rows table, with the query parameter that filters each.
const COLUMNS: [(&str, &str); 9] = [("instrument", "Instrument"), ("subject", "Subject"), ("item", "Item"), ("outcome", "Outcome"), ("value", "Value"), ("nonresponse", "Non-response"), ("lang", "Lang"), ("seq", "Seq"), ("excluded", "Excluded")];

fn cell(x: &fieldseal_adapters_web_demo::LongRow, col: &str) -> String {
    match col {
        "instrument" => x.instrument_name.clone(),
        "subject" => x.subject_id.clone(),
        "item" => x.item.clone(),
        "outcome" => x.outcome.clone(),
        "value" => x.value.clone(),
        "nonresponse" => x.nonresponse.clone(),
        "lang" => x.lang.clone(),
        "seq" => x.seq.to_string(),
        _ => x.excluded.clone().unwrap_or_default(),
    }
}

/// The landed rows exactly as landed, filtered by substring per column and paged. Nothing is
/// computed from them.
fn rows_tab(r: &IntakeReport, req: &Request) -> String {
    let filters: Vec<(&str, String)> = COLUMNS.iter().map(|(k, _)| (*k, req.param(&format!("f_{k}")).unwrap_or("").to_owned())).collect();
    let matching: Vec<&fieldseal_adapters_web_demo::LongRow> =
        r.rows.iter().filter(|x| filters.iter().all(|(k, f)| f.is_empty() || cell(x, k).to_lowercase().contains(&f.to_lowercase()))).collect();
    let pages = matching.len().div_ceil(ROW_PAGE_SIZE).max(1);
    let page = req.param("page").and_then(|p| p.parse::<usize>().ok()).unwrap_or(1).clamp(1, pages);
    let mut out = format!(
        "<h3>Landed rows</h3>\n<p>{} landed row(s) in the long format, as landed, keyed by pseudonymous subject. <a class=\"quiet-link\" href=\"/intake/rows.csv\">Download all as CSV</a> (unchanged; spreadsheet formula characters guarded).</p>\n",
        r.rows.len()
    );
    if r.rows.is_empty() {
        return out;
    }
    let mut filter_inputs = String::new();
    for (k, label) in COLUMNS {
        let v = filters.iter().find(|(c, _)| *c == k).map(|(_, v)| v.as_str()).unwrap_or("");
        filter_inputs.push_str(&format!("<label>{label} <input type=\"search\" name=\"f_{k}\" value=\"{}\"></label>\n", escape(v)));
    }
    out.push_str(&format!("<details class=\"quiet\"{}><summary>Filter by column</summary>\n<form method=\"get\" action=\"/intake#rows\" class=\"filters\">\n{filter_inputs}<button type=\"submit\" class=\"btn\">Apply</button> <a class=\"quiet-link\" href=\"/intake#rows\">Clear</a>\n</form></details>\n", if filters.iter().any(|(_, v)| !v.is_empty()) { " open" } else { "" }));
    out.push_str(&format!("<p class=\"note\">{} matching; page {page} of {pages}.</p>\n<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Table, scrolls sideways\"><table>\n<tr>", matching.len()));
    for (_, label) in COLUMNS {
        out.push_str(&format!("<th>{label}</th>"));
    }
    out.push_str("</tr>\n");
    for x in matching.iter().skip((page - 1) * ROW_PAGE_SIZE).take(ROW_PAGE_SIZE) {
        out.push_str("<tr>");
        for (k, _) in COLUMNS {
            out.push_str(&format!("<td>{}</td>", escape(&cell(x, k))));
        }
        out.push_str("</tr>\n");
    }
    out.push_str("</table></div>\n");
    let mut query: String = filters.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| format!("f_{k}={}&", crate::http::url_encode(v))).collect();
    query.push_str("page=");
    out.push_str("<p class=\"pager\">");
    if page > 1 {
        out.push_str(&format!("<a class=\"btn\" href=\"/intake?{query}{}#rows\">Previous</a> ", page - 1));
    }
    if page < pages {
        out.push_str(&format!("<a class=\"btn\" href=\"/intake?{query}{}#rows\">Next</a>", page + 1));
    }
    out.push_str("</p>\n");
    out
}

/// The data contract of each published instrument: the long format's columns and, per item,
/// its type, unit, whether it is required and its nonresponse codes.
fn contract_tab(state: &AppState, demo: &fieldseal_adapters_web_demo::Demo) -> String {
    use fieldseal_intake::data_contract::LONG_COLUMNS;
    let mut out = String::from("<h3>Data contract</h3>\n<p>What the intake lands, for each published instrument: the columns of the long format, then every item with its type and unit. <a class=\"quiet-link\" href=\"/intake/contract.json\">Download as JSON</a></p>\n<details class=\"quiet\" open><summary>Long-format columns</summary>\n<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Table, scrolls sideways\"><table>\n<tr><th>Column</th><th>Type</th><th>What it holds</th></tr>\n");
    for c in LONG_COLUMNS.iter() {
        out.push_str(&format!("<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>\n", escape(c.name), escape(c.logical_type), escape(c.description)));
    }
    out.push_str("</table></div></details>\n");
    for (name, c) in contracts(state, demo) {
        out.push_str(&format!("<details class=\"card disclosure\"><summary><strong>{}</strong> ({} items)</summary>\n<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Table, scrolls sideways\"><table>\n<tr><th>Item</th><th>Type</th><th>Unit</th><th>Required</th><th>Nonresponse</th></tr>\n", escape(&name), c.items.len()));
        for i in &c.items {
            out.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                escape(&i.path),
                escape(i.value_type),
                escape(i.unit.as_deref().unwrap_or("")),
                if i.required { "yes" } else { "" },
                escape(&i.nonresponse.join(", "))
            ));
        }
        out.push_str("</table></div></details>\n");
    }
    out
}

fn contracts(state: &AppState, demo: &fieldseal_adapters_web_demo::Demo) -> Vec<(String, fieldseal_intake::data_contract::DataContract)> {
    let mut out = Vec::new();
    for entry in crate::catalogue::load_all(&state.examples_dir, &state.survey_cohorts) {
        let Ok(summary) = &entry.status else { continue };
        let Some(fp) = demo.fingerprint_of(&summary.name) else { continue };
        if let Ok(bench) = entry.workbench(&[]) {
            out.push((summary.name.clone(), fieldseal_intake::data_contract::generate_data_contract(fp, bench.instrument())));
        }
    }
    out
}

fn contract_json(state: &AppState, demo: &fieldseal_adapters_web_demo::Demo) -> String {
    let all: Vec<fieldseal_kernel::Value> = contracts(state, demo).into_iter().map(|(_, c)| c.to_value()).collect();
    fieldseal_adapters_web::json::to_json(&fieldseal_kernel::Value::Array(all))
}
