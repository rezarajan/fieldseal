//! The Publishing page (WEB-140, WEB-141): the transparency log's checkpoint and entries and
//! one section per published artefact. With the demo authority, every verdict is computed
//! here, by the real publishing context (`Demo::publications`), never taken from the log's
//! own claims. Without it, the page can only show the log's checkpoint text.

use std::time::Duration;

use fieldseal_adapters_web_demo::{Demo, PublicationReport};

use crate::http::{Request, Response};
use crate::state::AppState;
use crate::ui::{self, escape};

/// Handles the routes of this page.
pub fn handle(state: &AppState, req: &Request) -> Option<Response> {
    if req.method != "GET" || req.path != "/publishing" {
        return None;
    }
    let body = match (&state.demo, &state.log_url) {
        (Some(d), _) => demo_body(d.0),
        (None, Some(url)) => log_body(url),
        (None, None) => format!("{}<p>No publishing source is configured; start with FIELDSEAL_WEB_DEMO_AUTHORITY=true or set FIELDSEAL_LOG_URL.</p>", head("")),
    };
    Some(ui::page("Publishing", "/publishing", &body, &[]))
}

/// The page head: the title and the one filled action, a refresh of this snapshot.
fn head(lede: &str) -> String {
    let lede = if lede.is_empty() { String::new() } else { format!("\n<p class=\"lede\">{lede}</p>") };
    format!("<div class=\"page-head\"><div><h1>Publishing</h1>{lede}</div>\n<div class=\"head-actions\"><a class=\"btn btn-primary\" href=\"/publishing\">Refresh</a></div></div>\n")
}

fn verdict(ok: bool) -> String {
    if ok { "<span class=\"ok\">yes</span>".into() } else { "<span class=\"bad\">NO</span>".into() }
}

fn short(hex: &str) -> String {
    format!("<code class=\"hash\" title=\"{0}\">{0}</code>", escape(hex))
}

/// Without a demo: the log's own checkpoint text, unverified.
fn log_body(url: &str) -> String {
    let mut out = head("");
    out.push_str(&format!("<p>Transparency log: <code>{}</code></p>\n", escape(url)));
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(10))).build().into();
    let target = format!("{}/checkpoint", url.trim_end_matches('/'));
    match agent.get(&target).call() {
        Ok(mut resp) if resp.status().as_u16() == 200 => match resp.body_mut().read_to_vec() {
            Ok(bytes) => out.push_str(&format!("<section class=\"card\">\n<h2>Checkpoint, as the log reports it</h2>\n<pre>{}</pre>\n</section>\n", escape(&String::from_utf8_lossy(&bytes)))),
            Err(e) => out.push_str(&format!("<p class=\"error\">The log's answer could not be read: {}</p>\n", escape(&e.to_string()))),
        },
        Ok(resp) => out.push_str(&format!("<p class=\"error\">The log answered {} to GET /checkpoint.</p>\n", resp.status().as_u16())),
        Err(e) => out.push_str(&format!("<p class=\"error\">The log could not be reached: {}</p>\n", escape(&e.to_string()))),
    }
    out.push_str("<p class=\"note\"><strong>Not verified.</strong> This app holds no trust bundle for that log, so it cannot check the checkpoint's signature, entries or inclusion proofs. What is shown is only what the log says about itself. Start the demo authority (FIELDSEAL_WEB_DEMO_AUTHORITY=true) to see the full verification.</p>");
    out
}

fn demo_body(demo: &Demo) -> String {
    let cp = demo.checkpoint();
    let mut out = head("Verified here, in the server, by the real publishing context against the demo authority's trust bundle and publishing policy. Nothing below is taken on the log's word. Development keys.");
    out.push_str("<section id=\"checkpoint\" class=\"card\">\n<h2>Log checkpoint</h2>\n<dl class=\"facts\">\n");
    out.push_str(&format!(
        "<div><dt>Origin</dt><dd>{}</dd></div>\n<div><dt>Size</dt><dd>{}</dd></div>\n<div><dt>Root hash</dt><dd>{}</dd></div>\n<div><dt>Signature verified against the pinned log key</dt><dd>{}</dd></div>\n</dl>\n</section>\n",
        escape(&cp.origin),
        cp.size,
        short(&cp.root_hash),
        verdict(cp.signature_verified)
    ));
    out.push_str("<section id=\"artefacts\">\n<h2>Published artefacts</h2>\n<div class=\"stack\">\n");
    for p in demo.publications() {
        out.push_str(&publication_section(&p));
    }
    out.push_str("</div>\n</section>\n");
    let entries = demo.entries();
    out.push_str(&format!("<details id=\"entries\" class=\"card disclosure\">\n<summary>Log entries ({})</summary>\n<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Table, scrolls sideways\"><table>\n<tr><th>Index</th><th>Kind</th><th>Name</th><th>Version</th><th>Content address</th><th>Signer key</th><th>Leaf hash</th></tr>\n", entries.len()));
    for e in entries {
        out.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            e.index,
            escape(&e.kind),
            escape(&e.name),
            escape(&e.version),
            short(&e.address),
            short(&e.signer_key_id),
            short(&e.leaf_hash)
        ));
    }
    out.push_str("</table></div>\n</details>\n<p class=\"note\">This page is a snapshot; reload to refresh.</p>\n");
    out
}

fn publication_section(p: &PublicationReport) -> String {
    let overall = match &p.verified {
        Ok(()) => "<span class=\"ok\">verified</span>".to_owned(),
        Err(e) => format!("<span class=\"bad\">not verified: {}</span>", escape(e)),
    };
    let mut s = format!(
        "<details class=\"publication card disclosure\">\n<summary><span class=\"kind\">{}</span> <strong>{} {}</strong> <span class=\"verdict\">{}</span></summary>\n<table>\n<tr><th>Kind</th><td>{}</td></tr>\n<tr><th>Content address</th><td>{}</td></tr>\n<tr><th>Verdict</th><td>{}</td></tr>\n",
        escape(&p.kind),
        escape(&p.name),
        escape(&p.version),
        overall,
        escape(&p.kind),
        short(&p.address),
        overall
    );
    s.push_str(&format!(
        "<tr><th>Signature threshold</th><td>{} of {} publishers required; {} valid signatures</td></tr>\n</table>\n",
        p.threshold.required, p.threshold.available, p.threshold.valid_signatures
    ));
    s.push_str("<h3>Signatures</h3>\n<table>\n<tr><th>Signer key</th><th>Certificate</th><th>Valid</th></tr>\n");
    for g in &p.signatures {
        s.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td></tr>\n", short(&g.key_id), escape(g.signer_certificate.as_deref().unwrap_or("none in the trust bundle")), verdict(g.valid)));
    }
    s.push_str("</table>\n<h3>Reviewers</h3>\n<table>\n<tr><th>Reviewer</th><th>Decision</th></tr>\n");
    for r in &p.reviewers {
        s.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>\n", escape(&r.id), escape(&r.decision)));
    }
    s.push_str("</table>\n<h3>Log inclusion proofs</h3>\n<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Table, scrolls sideways\"><table>\n<tr><th>Leaf index</th><th>Tree size</th><th>Root</th><th>Leaf hash</th><th>Verified</th></tr>\n");
    for l in &p.log_entries {
        s.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n", l.leaf_index, l.tree_size, short(&l.root_hash), short(&l.leaf_hash), verdict(l.verified)));
    }
    s.push_str(&format!(
        "</table></div>\n<h3>Provenance</h3>\n<table>\n<tr><th>Builder</th><td>{}</td></tr>\n<tr><th>Source</th><td>{}</td></tr>\n<tr><th>Revision</th><td>{}</td></tr>\n</table>\n</details>\n",
        escape(&p.build.builder),
        escape(&p.build.source),
        escape(&p.build.revision)
    ));
    s
}
