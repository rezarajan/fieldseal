//! Routing: one function from request to response. Each page lives in its own module with
//! `handle(state, req) -> Option<Response>`; add a module and one line in [`dispatch`].

use crate::http::{Request, Response, proxy};
use crate::state::AppState;
use crate::{assets, demo_steps, device, instruments, publishing, registration, ui};

/// Routes `req`; every response carries the security headers.
pub fn dispatch(state: &AppState, req: &Request) -> Response {
    let response = route(state, req).unwrap_or_else(|| ui::error_page(404, "There is nothing at this address."));
    match &state.results_url {
        Some(url) => ui::with_results_link(response, url).secured(),
        None => response.secured(),
    }
}

fn route(state: &AppState, req: &Request) -> Option<Response> {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => return Some(Response::redirect("/demo")),
        // No icon: an empty answer keeps browser consoles free of a 404.
        ("GET", "/favicon.ico") => return Some(Response::new(204, "image/x-icon", Vec::new())),
        ("GET", "/healthz") => return Some(Response::json(200, "{\"status\":\"ok\"}")),
        _ => {}
    }
    assets::handle(state, req)
        .or_else(|| demo_steps::handle(state, req))
        .or_else(|| instruments::handle(state, req))
        .or_else(|| publishing::handle(state, req))
        .or_else(|| registration::handle(state, req))
        .or_else(|| device::handle(state, req))
        .or_else(|| proxied(state, req))
}

/// `/proxy/{factory,upload,log}/*` to the configured upstreams.
fn proxied(state: &AppState, req: &Request) -> Option<Response> {
    let rest = req.path.strip_prefix("/proxy/")?;
    let (name, upstream) = match rest.split('/').next()? {
        "factory" => ("factory", &state.factory_url),
        "upload" => ("upload", &state.upload_url),
        "log" => ("log", &state.log_url),
        _ => return None,
    };
    Some(match upstream {
        Some(base) => proxy(base, req, &format!("/proxy/{name}")),
        None => Response::text(404, format!("No {name} service is configured: set FIELDSEAL_{}_URL.", name.to_ascii_uppercase())),
    })
}
