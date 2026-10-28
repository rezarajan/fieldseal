//! The Device page: the browser device (the real format core compiled to WebAssembly, run in a
//! worker) with PIN tenancy, registration, bundle verification, capture, review, export,
//! upload, receipts and clear. The page shows one step at a time (Session, Capture, Review and
//! seal, Export) and one screen of it, each with a single primary action. This module serves
//! the page and the few things the device fetches: its provisioning, a bundle built by the
//! demo authority, and a blank frame.

use crate::http::{Request, Response};
use crate::state::AppState;
use crate::ui;

/// Handles the routes of this page.
pub fn handle(state: &AppState, req: &Request) -> Option<Response> {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/device") => Some(page(state)),
        ("GET", "/device/provisioning") => Some(provisioning(state)),
        ("GET", "/device/bundle") => Some(bundle(state, req)),
        // A blank, header-free document the page writes the rendered instrument into, so the
        // instrument's own content security policy (hashes of its inline script and style)
        // applies to it alone.
        ("GET", "/device/frame") => Some(Response::document("<!doctype html><html><head><meta charset=\"utf-8\"><title>instrument</title></head><body></body></html>".to_owned())),
        _ => None,
    }
}

fn provisioning(state: &AppState) -> Response {
    if let Some(d) = state.demo {
        return Response::json(200, d.0.provisioning_json());
    }
    if state.stack.is_some() {
        return match crate::stack::provisioning(state) {
            Ok(json) => Response::json(200, json),
            Err(e) => Response::json(500, format!("{{\"error\":{}}}", fieldseal_adapters_web::json::quote(&e))),
        };
    }
    match state.provisioning_file.as_ref().map(std::fs::read_to_string) {
        Some(Ok(text)) => Response::json(200, text),
        Some(Err(e)) => Response::json(500, format!("{{\"error\":{}}}", fieldseal_adapters_web::json::quote(&format!("FIELDSEAL_WEB_PROVISIONING_FILE: {e}")))),
        None => Response::json(404, "{\"error\":\"no authority is configured: start with FIELDSEAL_WEB_DEMO_AUTHORITY=true, or set FIELDSEAL_WEB_PROVISIONING_FILE\"}"),
    }
}

/// `GET /device/bundle?tenancy=<hex>[&instrument=<name>]`: with the demo authority, the bundle
/// the real builder seals to the registered tenancy's agreement key.
fn bundle(state: &AppState, req: &Request) -> Response {
    if let Some(cli) = &state.stack {
        let (Some(tenancy), Some(survey)) = (req.param("tenancy"), req.param("instrument")) else { return Response::text(400, "tenancy and instrument are required") };
        return match crate::stack::bundle(cli, tenancy, survey) {
            Ok(bytes) => Response::new(200, "application/octet-stream", bytes).with("X-Bundle-Development-Allowance", "true"),
            Err(e) if e.contains("does not know this tenancy") => Response::text(404, "no such tenancy: the factory does not know this device"),
            Err(e) => Response::text(422, &e),
        };
    }
    let Some(d) = state.demo else { return Response::text(404, "Bundles come from the demo authority here; with another authority, pick the bundle file instead.") };
    let Some(tenancy) = req.param("tenancy") else { return Response::text(400, "tenancy is required") };
    let built = match req.param("instrument") {
        Some(name) => d.0.build_bundle_for(tenancy, &[name]),
        None => d.0.build_bundle_for(tenancy, &[d.0.examples().first().map(String::as_str).unwrap_or("household-water-access")]),
    };
    match built {
        Ok(r) => Response::new(200, "application/octet-stream", r.bytes)
            .with("X-Bundle-Development-Allowance", if r.development_allowance { "true" } else { "false" })
            .with("X-Bundle-Instruments", &r.instruments.to_string())
            .with("X-Bundle-Layouts", &r.layouts.to_string())
            .with("X-Bundle-Rosters", &r.rosters.to_string()),
        Err(e) => Response::text(409, e),
    }
}

fn page(state: &AppState) -> Response {
    let mode = match (state.demo.is_some(), state.provisioning_file.is_some()) {
        _ if state.stack.is_some() => "stack",
        (true, _) => "demo",
        (false, true) => "file",
        _ => "none",
    };
    let wasm = if state.wasm_available() { "" } else { "<p class=\"notice warn\">The WebAssembly bundle is not available (set FIELDSEAL_WEB_WASM_DIR); the device cannot run.</p>" };
    let instruments = if state.stack.is_some() { crate::stack::surveys().join(",") } else { state.demo.map(|d| d.0.examples().join(",")).unwrap_or_default() };
    let body = DEVICE_BODY
        .replace("{{wasm}}", wasm)
        .replace("{{mode}}", mode)
        .replace("{{instruments}}", &crate::ui::escape(&instruments))
        .replace("{{factory_label}}", &crate::ui::escape(state.factory_url.as_deref().unwrap_or("(no factory configured)")))
        .replace("{{factory}}", &crate::ui::escape(state.factory_url.as_deref().unwrap_or("")));
    let body = format!("<link rel=\"stylesheet\" href=\"/assets/device.css\">\n{body}");
    ui::page("Device", "/device", &body, &["/assets/device.js"])
}

/// The markup of the Device page: one section per step (`data-step`), and in each section one
/// container per screen (`data-screen`). The script shows exactly one screen of one step at a
/// time, and every screen carries at most one primary action (`btn-primary`): Hick's law, and
/// the tests in `tests/device_page.rs` check it from this text.
const DEVICE_BODY: &str = r##"<div id="device" class="device" data-mode="{{mode}}" data-instruments="{{instruments}}" data-factory="{{factory}}">
{{wasm}}
<div class="devbar">
<ol id="pills" class="pills" aria-label="Steps">
<li data-pill="session" aria-current="step">Session</li>
<li data-pill="about">Capture</li>
<li data-pill="review">Review &amp; seal</li>
<li data-pill="export">Export</li>
</ol>
<span class="devbar-end"><span class="chip" id="chip" title="Software keys in this browser: for assessing the system, not for field use (CLI-007, REG-017)">Unattested software device (development policy allows it)</span><button id="lock" type="button" class="btn btn-quiet btn-icon" hidden aria-label="Lock the device">Lock</button></span>
</div>
<div id="device-error" class="notice warn" role="alert" hidden></div>
<noscript><p class="notice warn">The device needs JavaScript and WebAssembly.</p></noscript>

<section data-step="session" id="step-session" class="step" aria-label="Session" hidden>
<div data-screen="starting" id="screen-starting" class="screen center"><p id="device-state" class="lead">Starting the device...</p></div>

<div data-screen="unavailable" id="screen-unavailable" class="screen center" hidden>
<h1>The device cannot start</h1><p id="unavailable-why" class="lead"></p>
<button type="button" id="retry" class="btn btn-primary">Try again</button>
</div>

<form data-screen="create" id="form-create" class="screen center pin-screen" hidden>
<div class="lock-badge" aria-hidden="true"><svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="10" rx="2"></rect><path d="M8 11V7a4 4 0 018 0v4"></path></svg></div>
<h1 id="create-title">Create your PIN</h1>
<p class="lead" id="create-hint">Six or more digits. It protects everything this device keeps.</p>
<div class="pin" data-pin><input id="pin-new" class="pin-input" type="password" inputmode="numeric" autocomplete="new-password" aria-label="PIN" minlength="6"><div class="dots" aria-hidden="true"></div><div class="pad"></div></div>
<p id="create-error" class="msg bad" role="alert"></p>
<button type="submit" id="create-go" class="btn btn-primary">Continue</button>
</form>

<form data-screen="unlock" id="form-unlock" class="screen center pin-screen" hidden>
<div class="lock-badge" aria-hidden="true"><svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="10" rx="2"></rect><path d="M8 11V7a4 4 0 018 0v4"></path></svg></div>
<h1>Enter your PIN</h1>
<p class="lead">This device is locked.</p>
<div class="pin" data-pin><input id="pin" class="pin-input" type="password" inputmode="numeric" autocomplete="current-password" aria-label="PIN"><div class="dots" aria-hidden="true"></div><div class="pad"></div></div>
<p id="unlock-error" class="msg bad" role="alert"></p>
<button type="submit" id="unlock-go" class="btn btn-primary">Unlock</button>
</form>

<form data-screen="register" id="form-register" class="screen center" hidden>
<h1>Register this device</h1>
<p class="lead">Paste the registration token from the factory portal. The request is built and sealed here, from this device's own keys.</p>
<p id="factory-forgot" class="msg warn" role="status" hidden>The factory does not know this device: it may have been reset. Register it again, or reset this device to start over.</p>
<label class="field-label" for="token">Registration token</label>
<input id="token" class="text-input" autocomplete="off" spellcheck="false">
<div id="register-result" class="register-result"></div>
<button type="submit" id="register-go" class="btn btn-primary">Register</button>
<button type="button" class="btn btn-danger reset-device">Reset this device</button>
<a id="portal-link" class="btn btn-secondary" href="{{factory}}" target="_blank" rel="noopener">Open the factory portal</a>
<details class="more"><summary>Options</summary>
<label class="field-label" for="label">Name for this device</label><input id="label" class="text-input" value="web device">
<p class="note">Registration status is read from {{factory_label}}. Already registered? <label for="bundle-file" class="link">Open a bundle file</label>.</p>
</details>
</form>

<div data-screen="bundle" id="screen-bundle" class="screen center" hidden>
<h1>Choose a survey</h1>
<p class="lead">This device can carry any published survey. Pick one: its bundle (the survey and the people to visit) is fetched and verified here, step by step, before anything in it is used. You can come back and load another.</p>
<fieldset id="instrument-pick" class="choice-list survey-pick" hidden><legend class="visually-hidden">Surveys</legend></fieldset>
<button type="button" id="fetch-bundle" class="btn btn-primary" hidden disabled>Load the survey</button>
<label for="bundle-file" id="open-bundle" class="btn btn-secondary">or open a bundle file</label>
<input id="bundle-file" type="file" class="visually-hidden">
<p id="bundle-error" class="msg bad" role="alert"></p>
</div>

<form data-screen="consent" id="form-consent" class="screen center" hidden>
<h1 id="consent-title">Consent</h1>
<p class="lead" id="consent-text"></p>
<fieldset id="consent-basis" class="choice-list" aria-label="Basis"></fieldset>
<p id="consent-error" class="msg bad" role="alert"></p>
<button type="submit" id="consent-go" class="btn btn-primary">Record consent and start</button>
<button type="button" id="consent-back" class="btn btn-secondary">Back to the list</button>
</form>

<div data-screen="roster" id="screen-roster" class="screen roster" hidden>
<aside class="card roster-side">
<h1 id="roster-title">Session</h1><p id="roster-sub" class="lead"></p>
<div class="progress" aria-hidden="true"><span id="roster-bar"></span></div>
<p id="roster-count" class="note"></p>
<p id="capture-error" class="msg bad" role="alert"></p>
<button type="button" id="start-next" class="btn btn-primary">Start</button>
<button type="button" id="to-export" class="btn btn-secondary">Hand over the records</button>
<button type="button" id="another-survey" class="btn btn-secondary">Load another survey</button>
<button type="button" class="btn btn-danger reset-device">Reset this device</button>
</aside>
<div id="subjects" class="subjects"></div>
</div>
</section>

<section data-step="about" id="step-about" class="step step-about" aria-label="Capture" hidden>
<div data-screen="capture" id="capture" class="screen capture">
<div class="capture-bar"><span class="capture-who"><span id="capture-subject" class="capture-subject"></span><span id="capture-title" class="capture-title"></span></span><span id="close-box"><button type="button" id="discard" class="btn btn-quiet">Close</button><span id="close-confirm" hidden> Discard this capture? <button type="button" id="discard-yes" class="btn btn-danger">Discard</button> <button type="button" id="discard-no" class="btn btn-quiet">Keep going</button></span></span><button type="button" id="to-review" class="btn btn-primary">Review &amp; seal</button></div>
<iframe id="frame" title="Instrument" sandbox="allow-same-origin allow-scripts" src="/device/frame"></iframe>
<div id="verdicts" class="verdicts" role="status" aria-live="polite"></div>
</div>
</section>

<section data-step="review" id="step-review" class="step" aria-label="Review and seal" hidden>
<div data-screen="review" id="screen-review" class="screen review">
<div class="review-grid">
<div class="card review-list"><h1 id="review-title">Check the answers</h1><div id="review-out"></div></div>
<aside class="card seal-card">
<h2>Ready to seal</h2>
<ul id="seal-checks" class="checks"></ul>
<button type="button" id="ack" class="check-row" aria-pressed="false" hidden><span class="box" aria-hidden="true"></span><span id="ack-text">Items stay unanswered</span></button>
<button type="button" id="seal" class="btn btn-primary hold" aria-describedby="seal-note"><span class="hold-fill" aria-hidden="true"></span><span class="hold-label">Hold to seal</span></button>
<p id="seal-note" class="note"><strong>Sealing is final.</strong> Press and hold for a moment; letting go early cancels. With the keyboard, hold Space or Enter.</p>
<p id="seal-error" class="msg bad" role="alert"></p>
<details class="more"><summary>Cannot hold?</summary><button type="button" id="seal-confirm" class="btn btn-secondary">Seal now</button><p class="note">Press twice to confirm. This does the same as holding.</p></details>
<button type="button" id="back-to-form" class="btn btn-quiet">Back to the form</button>
</aside>
</div>
</div>

<div data-screen="sealed" id="screen-sealed" class="screen center" hidden>
<h1>Sealed</h1><p id="sealed-text" class="lead"></p>
<button type="button" id="sealed-next" class="btn btn-primary">Back to the list</button>
<button type="button" id="sealed-export" class="btn btn-secondary">Hand over the records</button>
</div>
</section>

<section data-step="export" id="step-export" class="step" aria-label="Export" hidden>
<div data-screen="ready" id="screen-ready" class="screen center">
<h1>Hand over</h1><p id="export-sum" class="lead"></p>
<button type="button" id="upload" class="btn btn-primary">Upload</button>
<button type="button" id="export" class="btn btn-secondary">Download the export file</button>
<div id="export-out" class="note"></div>
<p id="upload-error" class="msg bad" role="alert"></p>
<details class="more"><summary>Export options</summary>
<label class="check-inline"><input type="checkbox" id="parity" checked> Verify parity of the export</label>
<p><label for="receipt-file" class="btn btn-secondary">Apply a receipt file</label><input id="receipt-file" type="file" class="visually-hidden"></p>
</details>
<button type="button" id="export-back" class="btn btn-quiet">Back to the list</button>
</div>
<div data-screen="done" id="screen-done" class="screen center" hidden>
<h1>Receipt verified</h1><p id="upload-out" class="lead"></p>
<button type="button" id="export-done" class="btn btn-primary">Done</button>
</div>
<details id="clear-box" class="more clear-box"><summary>Clear records from this device</summary>
<p class="note">Only what an authority receipt covers is removed from the journal. Preview first, then confirm with the PIN, twice.</p>
<button type="button" id="clear-preview" class="btn btn-secondary">Preview a clear</button>
<p id="clear-preview-out" class="note"></p>
<form id="form-clear" hidden><label class="field-label" for="clear-pin1">PIN</label><input id="clear-pin1" class="text-input" type="password" inputmode="numeric" autocomplete="current-password"><label class="field-label" for="clear-pin2">PIN again</label><input id="clear-pin2" class="text-input" type="password" inputmode="numeric" autocomplete="current-password"><button type="submit" class="btn btn-danger">Clear</button></form>
<p id="clear-out" class="note" role="status"></p>
</details>
</section>

<div class="devfoot">
<p id="latest" class="latest" role="status"></p>
<details id="log-box" class="more"><summary>Security log <span id="log-count" class="count">0</span></summary><p class="note">Every step the device took, and what it found.</p><ol id="log" class="steps"></ol></details>
<details id="device-box" class="more"><summary>Device details</summary>
<p class="note">An <strong>unattested software device</strong> running in this browser: the format core compiled to WebAssembly, in a worker, with software keys stored in IndexedDB. It is for assessing the system, not for field use (CLI-007, REG-017). Production deployments refuse it.</p>
<div id="device-info" class="kv"></div>
<p id="posture" class="note"></p>
<p><button type="button" id="keys-link" class="btn btn-secondary">Show this device's public keys</button> <span class="note">for <code>fieldseal bundle build</code></span></p><pre id="keys-out" hidden></pre>
<ol id="bundle-steps" class="steps"></ol>
<p id="tenancy-info" class="note"></p>
<p><button type="button" id="forget" class="btn btn-danger">Forget this device</button> <span class="note">Deletes the keys, journal and local record from this browser; a new tenancy must be created afterwards.</span></p>
</details>
</div>
</div>"##;
