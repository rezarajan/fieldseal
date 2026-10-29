//! The Registration page (WEB-150): how a device registers, a link to the factory portal and
//! the state of a registration, read from the factory (`GET /v1/registrations/{tenancy}`).
//! The page holds no registry and confirms nothing: the four-word comparison is made in the
//! factory portal.

use std::time::Duration;

use crate::http::{Request, Response};
use crate::state::AppState;
use crate::ui::{self, escape};

/// How long the page waits for the factory.
const FACTORY_TIMEOUT: Duration = Duration::from_secs(10);

/// Handles the routes of this page.
pub fn handle(state: &AppState, req: &Request) -> Option<Response> {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/registration") => Some(render(state, req.query.get("tenancy").map(|t| t.trim()).filter(|t| !t.is_empty()))),
        _ => None,
    }
}

/// The state of `tenancy` as the factory reports it, as a notice for the page.
fn status(state: &AppState, tenancy: &str) -> String {
    let Some(base) = &state.factory_url else {
        return "<p class=\"error\">No factory is configured, so the state cannot be read: set FIELDSEAL_FACTORY_URL.</p>".to_owned();
    };
    if tenancy.len() != 64 || !tenancy.bytes().all(|b| b.is_ascii_hexdigit()) {
        return "<p class=\"error\">A tenancy identifier is 64 hexadecimal digits. The Device page shows it under Device details.</p>".to_owned();
    }
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(FACTORY_TIMEOUT)).build().into();
    let target = format!("{}/v1/registrations/{}", base.trim_end_matches('/'), tenancy.to_ascii_lowercase());
    let unreachable = |why: String| format!("<p class=\"error\">The factory could not be reached at {}: {}</p>", escape(base), escape(&why));
    let mut response = match agent.get(&target).call() {
        Ok(r) => r,
        Err(e) => return unreachable(e.to_string()),
    };
    let code = response.status().as_u16();
    let body = match response.body_mut().with_config().limit(64 * 1024).read_to_vec() {
        Ok(b) => b,
        Err(e) => return unreachable(e.to_string()),
    };
    match (code, serde_json::from_slice::<serde_json::Value>(&body)) {
        (200, Ok(doc)) => {
            let state_name = doc["state"].as_str().unwrap_or("unknown");
            let reasons: Vec<String> = doc["reasons"].as_array().into_iter().flatten().filter_map(|r| r.as_str()).map(|r| format!("<li>{}</li>", escape(r))).collect();
            let reasons = if reasons.is_empty() { String::new() } else { format!("\n<ul>{}</ul>", reasons.join("")) };
            format!("<section id=\"status\" class=\"card\">\n<h2>Registration state</h2>\n<p>The factory reports <strong>{}</strong> for <code class=\"hash\">{}</code>.</p>{reasons}\n</section>", escape(state_name), escape(tenancy))
        }
        (404, _) => format!("<p class=\"error\">The factory does not know a registration <code class=\"hash\">{}</code>.</p>", escape(tenancy)),
        (code, _) => format!("<p class=\"error\">The factory answered {code} to the state request.</p>"),
    }
}

fn render(state: &AppState, tenancy: Option<&str>) -> Response {
    let mut b = String::from("<div class=\"page-head\"><div><h1>Registration</h1>\n<p class=\"lede\">A device registers in four short steps.</p></div>\n<div class=\"head-actions\"><a class=\"btn btn-primary\" href=\"/device\">Go to the Device page</a></div></div>\n");
    if let Some(t) = tenancy {
        b.push_str(&status(state, t));
        b.push('\n');
    }
    b.push_str("\n<section class=\"card\">\n<h2>How a device registers</h2>\n<ol class=\"flow\">\n<li><span>A collector signs in to the factory portal and asks for a registration token.</span></li>\n<li><span>On the <a href=\"/device\">Device page</a> the browser makes its keys and sends a registration request with the token.</span></li>\n<li><span>The device shows four words. The portal shows four words too.</span></li>\n<li><span>The collector confirms in the portal only if the two sets of words are equal. The registration is then complete and the device can receive its bundle.</span></li>\n</ol>\n");
    match &state.factory_url {
        Some(url) => b.push_str(&format!("<p>The factory portal is a separate origin, where the sign-in happens: <a class=\"btn\" href=\"{0}/\" target=\"_blank\" rel=\"noopener\">Open the factory portal</a> <span class=\"muted\">{0} (opens in a new tab)</span></p>\n", escape(url.trim_end_matches('/')))),
        None => b.push_str("<p>No factory is configured: set FIELDSEAL_FACTORY_URL.</p>\n"),
    }
    b.push_str("</section>\n<section class=\"card\">\n<h2>Check a registration</h2>\n<p>The factory reports the state of a registration to anyone who has its identifier. Nothing is confirmed here.</p>\n<form method=\"get\" action=\"/registration\"><label class=\"field-label\" for=\"tenancy\">Tenancy identifier</label>\n<input id=\"tenancy\" name=\"tenancy\" class=\"text-input\" autocomplete=\"off\" spellcheck=\"false\">\n<button type=\"submit\" class=\"btn\">Check the state</button></form>\n</section>\n");
    ui::page("Registration", "/registration", &b, &[])
}
