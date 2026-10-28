//! The Registration page (WEB-150): how a device registers, a link to the factory portal and,
//! with the demo authority, a registration token shortcut and the registry with a confirm
//! button per pending registration.

use crate::http::{Request, Response, parse_query};
use crate::state::AppState;
use crate::ui::{self, escape};

/// Handles the routes of this page.
pub fn handle(state: &AppState, req: &Request) -> Option<Response> {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/registration") => Some(render(state, "")),
        ("POST", "/registration/token") => Some(match state.demo {
            None => render(state, "<p class=\"error\">Tokens come from the demo authority or the factory portal.</p>"),
            Some(d) => match d.0.issue_registration_token("alice") {
                Ok(token) => render(state, &format!("<section id=\"token\" class=\"card\">\n<h2>Registration token</h2>\n<pre class=\"token\">{}</pre>\n<p>It works once. Paste it into the Device page.</p>\n</section>", escape(&token))),
                Err(e) => render(state, &format!("<p class=\"error\">No token could be issued: {}</p>", escape(&e))),
            },
        }),
        ("POST", "/registration/confirm") => Some(match state.demo {
            None => render(state, "<p class=\"error\">There is no demo authority to confirm against.</p>"),
            Some(d) => {
                let form = parse_query(&String::from_utf8_lossy(&req.body));
                let tenancy = form.get("tenancy").map(String::as_str).unwrap_or("");
                match d.0.confirm_registration(tenancy) {
                    Ok(()) => render(state, "<p class=\"ok\">Confirmed. The registration is now registered.</p>"),
                    Err(e) => render(state, &format!("<p class=\"error\">Not confirmed: {}</p>", escape(&e))),
                }
            }
        }),
        _ => None,
    }
}

fn render(state: &AppState, notice: &str) -> Response {
    let mut b = String::from("<div class=\"page-head\"><div><h1>Registration</h1>\n<p class=\"lede\">A device registers in four short steps.</p></div>\n<div class=\"head-actions\"><a class=\"btn btn-primary\" href=\"/device\">Go to the Device page</a></div></div>\n");
    b.push_str(notice);
    b.push_str("\n<section class=\"card\">\n<h2>How a device registers</h2>\n<ol class=\"flow\">\n<li><span>A collector signs in to the factory portal and asks for a registration token.</span></li>\n<li><span>On the <a href=\"/device\">Device page</a> the browser makes its keys and sends a registration request with the token.</span></li>\n<li><span>The device shows four words. The portal shows four words too.</span></li>\n<li><span>The collector confirms in the portal only if the two sets of words are equal. The registration is then complete and the device can receive its bundle.</span></li>\n</ol>\n");
    match &state.factory_url {
        Some(url) => b.push_str(&format!("<p>The factory portal is a separate origin, where the sign-in happens: <a class=\"btn\" href=\"{0}/\" target=\"_blank\" rel=\"noopener\">Open the factory portal</a> <span class=\"muted\">{0} (opens in a new tab)</span></p>\n", escape(url.trim_end_matches('/')))),
        None => b.push_str("<p>No factory is configured: set FIELDSEAL_FACTORY_URL, or start with FIELDSEAL_WEB_DEMO_AUTHORITY=true.</p>\n"),
    }
    b.push_str("</section>\n");
    if let Some(d) = state.demo {
        let regs = d.0.registrations();
        let open = if notice.is_empty() { "" } else { " open" };
        b.push_str(&format!("<details id=\"demo\" class=\"card disclosure\"{open}>\n<summary>Demo shortcuts</summary>\n<section>\n<h2>Issue a token</h2>\n<p>Demo shortcut: in the demo the portal signs in as the dev user alice; the token below is the same kind the portal issues.</p>\n<form method=\"post\" action=\"/registration/token\"><button type=\"submit\" class=\"btn\">Issue a registration token</button></form>\n</section>\n"));
        b.push_str("<section id=\"registrations\">\n<h2>Registrations</h2>\n<p>Confirm only if the four words equal the ones the device shows; the portal does the same.</p>\n");
        if regs.is_empty() {
            b.push_str("<p>No device has registered yet.</p>\n");
        } else {
            b.push_str("<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Table, scrolls sideways\"><table>\n<tr><th>Tenancy</th><th>State</th><th>Words</th><th>Label</th><th>Keys attested</th><th></th></tr>\n");
            for r in regs {
                let attested = if r.keys_attested { "yes" } else { "no" };
                let button = if r.state == "pending" {
                    format!("<form method=\"post\" action=\"/registration/confirm\"><input type=\"hidden\" name=\"tenancy\" value=\"{}\"><button type=\"submit\" class=\"btn\">Confirm</button></form>", escape(&r.tenancy))
                } else {
                    String::new()
                };
                b.push_str(&format!(
                    "<tr><td><code class=\"hash\">{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    escape(&r.tenancy),
                    escape(&r.state),
                    escape(r.words.as_deref().unwrap_or("")),
                    escape(r.label.as_deref().unwrap_or("")),
                    attested,
                    button
                ));
            }
            b.push_str("</table></div>\n<p class=\"note\">\"no\" means the keys carry no hardware attestation, as a browser's never do; in the demo a bundle build may mark them attested, which is a demo action, not evidence.</p>\n");
        }
        b.push_str("<p class=\"note\">Pages are server-rendered snapshots; reload to see new registrations.</p>\n</section>\n</details>\n");
    }
    ui::page("Registration", "/registration", &b, &[])
}
