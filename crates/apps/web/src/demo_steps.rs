//! The guided demo (WEB-195 to WEB-199): `GET /demo` and `GET /demo/{1..8}`, the eight steps of
//! the pipeline in order, over pages and services that already exist. Each step page says what
//! happens, who does it in production, how to do it (a link to the page where it is done, or
//! the exact command to copy, which the stepper never runs) and shows a confirmation that was
//! read from the service that did the work, with a "check it" link to a place where the same
//! value exists on its own.
//!
//! The stepper performs nothing for the authority. It holds no key and no session, makes no
//! request except `GET`, and has no route that records a confirmation: the server reads the
//! transparency log and the surveys, and the script (`assets/demo.js`) reads the factory's
//! registration state through the proxy and the device's own view, which the Device page keeps
//! in this browser (and which the confirmation labels as the device's own).

use crate::catalogue;
use crate::http::{Request, Response};
use crate::publishing;
use crate::state::AppState;
use crate::ui::{self, escape};

/// One step: the words on its page and in the table on `/demo`.
struct Step {
    /// The title.
    title: &'static str,
    /// One sentence on what happens.
    what: &'static str,
    /// Who performs the step in production.
    who: &'static str,
    /// The production component that does it in this demo, and what stands in.
    component: &'static str,
    /// Where the confirmation is read from.
    source: &'static str,
}

/// The eight steps, in order. This table is the data of every page.
const STEPS: [Step; 8] = [
    Step {
        title: "Compile the survey",
        what: "The survey folder is checked and compiled into an instrument and its layouts, each with a content address.",
        who: "The survey author, and CI for publishers: fieldseal survey check, then the compile commands.",
        component: "The fieldseal CLI (production binary). The Instruments page shows the same compile; it is part of the stand-in.",
        source: "Computed in this app by the same core as the CLI, not read from a service. The command output is the cross-check.",
    },
    Step {
        title: "Publish to the factory",
        what: "Two of three publishers sign the survey, and it goes into the transparency log and the artefact registry.",
        who: "The publishers, two of three threshold signatures. The factory has no publish endpoint: it builds only from what is published.",
        component: "The fieldseal CLI and the transparency log (production binaries), with the development authority's keys.",
        source: "Read in this app from the transparency log, and verified here against the trust bundle (WEB-141).",
    },
    Step {
        title: "Register a device",
        what: "A collector asks the factory portal for a registration token, the device sends a sealed request, and the collector confirms the four words.",
        who: "A signed-in collector at the factory portal; the device on the native app.",
        component: "The factory portal and the factory (production). The device is the stand-in: this browser, not the Android app.",
        source: "The tenancy is the device's own view, kept in this browser. The state is read now from the factory.",
    },
    Step {
        title: "Load the published bundle",
        what: "The factory builds a bundle from the published surveys and the issued roster, and the device fetches it and verifies it before it holds anything.",
        who: "The factory builds and serves the bundle; the device on the native app fetches and verifies it. No operator step.",
        component: "The factory (production) builds and serves. The device verifies with the same core the native apps use; it runs in this browser.",
        source: "The headers of the factory's answer and the device's own checks, both the device's view. The factory's own log of the build is the independent source.",
    },
    Step {
        title: "Manage rosters",
        what: "The operator issues a new roster version; the factory journals it and builds the next bundle, which the device fetches.",
        who: "The operator, with fieldseal roster check, diff, issue and assign. Issue and assign are factory operations behind an operator sign-in.",
        component: "The fieldseal CLI and the factory (production). The sign-in is the development IdP, in the place Keycloak takes in the stack.",
        source: "The device's own view of the roster in the bundle it holds, cross-checked with the roster list command and the factory's build log.",
    },
    Step {
        title: "Conduct a survey",
        what: "A field collector captures answers for people on the roster and seals each record.",
        who: "The field collector, on the native app.",
        component: "The device in this browser. It stands in for the Android app.",
        source: "The device's own journal, labelled as the device's view. Step 7 confirms the same records with signed receipts.",
    },
    Step {
        title: "Export",
        what: "The device builds its export and uploads it to the intake upload endpoint, which runs its gate and returns a signed receipt.",
        who: "The runtime, in the background, on the native app.",
        component: "The intake upload endpoint (production). The device that sends is the stand-in.",
        source: "The export is the device's view. The receipt was verified in the browser against the trust bundle.",
    },
    Step {
        title: "Read the results",
        what: "An authorised person signs in to the results reader and reads or downloads the landed export.",
        who: "An authorised person on the results reader, or the fieldseal intake results command; with a lakehouse landing, the lakehouse tools.",
        component: "The intake app's results reader (production), signed in as presenter.",
        source: "Nothing is confirmed here, because the stepper has no access to the results.",
    },
];

/// Handles the routes of this page.
pub fn handle(state: &AppState, req: &Request) -> Option<Response> {
    if req.method != "GET" {
        return None;
    }
    if req.path == "/demo" {
        return Some(overview());
    }
    let n: usize = req.path.strip_prefix("/demo/")?.parse().ok()?;
    if req.path != format!("/demo/{n}") || !(1..=STEPS.len()).contains(&n) {
        return None;
    }
    Some(step(state, n))
}

/// The page shell with the stepper's own stylesheet.
fn page(title: &str, body: &str) -> Response {
    ui::page(title, "/demo", &format!("<link rel=\"stylesheet\" href=\"/assets/demo.css\">\n{body}"), &["/assets/demo.js"])
}

/// `/demo`: the banner, the eight steps and who does each one in production.
fn overview() -> Response {
    let mut b = String::from("<div class=\"page-head\"><div><h1>Guided demo</h1>\n<p class=\"lede\">Eight steps from a survey on disk to results a person can read. Each step is done by the component that does it in production, and each confirmation is read from the service that did the work.</p></div>\n<div class=\"head-actions\"><a class=\"btn btn-primary\" href=\"/demo/1\">Start the demo</a></div></div>\n");
    b.push_str(&ui::banner());
    b.push_str("\n<section class=\"card\">\n<h2>What is real in this demo</h2>\n<p>Everything except this collector stand-in is a production component: the command line, the transparency log, the factory, the intake app and the results reader. The stand-in is this web app, and the device that runs in its Device page stands in for the Android app. This guide only explains, links and reads. It performs nothing on behalf of the authority.</p>\n");
    b.push_str("<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Table of the eight steps, scrolls sideways\"><table>\n<tr><th scope=\"col\">Step</th><th scope=\"col\">Who does it in production</th><th scope=\"col\">Component in this demo</th></tr>\n");
    for (i, s) in STEPS.iter().enumerate() {
        b.push_str(&format!("<tr><td><a href=\"/demo/{0}\">{0}. {1}</a></td><td>{2}</td><td>{3}</td></tr>\n", i + 1, escape(s.title), escape(s.who), escape(s.component)));
    }
    b.push_str("</table></div>\n</section>\n");
    page("Guided demo", &b)
}

/// A command to copy, in a block that wraps instead of scrolling.
fn command(text: &str) -> String {
    format!("<pre class=\"command\"><code>{}</code></pre>\n", escape(text))
}

/// A secondary link that opens a page where the action is done.
fn link(label: &str, href: &str, new_tab: bool) -> String {
    let target = if new_tab { " target=\"_blank\" rel=\"noopener\"" } else { "" };
    format!("<a class=\"btn\" href=\"{}\"{target}>{}</a>\n", escape(href), escape(label))
}

/// A "check it" link in the list under the confirmation.
fn check(label: &str, href: &str) -> String {
    format!("<li><a href=\"{}\">{}</a></li>\n", escape(href), escape(label))
}

/// The base URL of a service, without a trailing slash, or the empty string.
fn base(url: &Option<String>) -> String {
    url.as_deref().unwrap_or("").trim_end_matches('/').to_owned()
}

/// A text line that tells the reader a service is not configured.
fn missing(what: &str, variable: &str) -> String {
    format!("<p class=\"error\">No {what} is configured: set {variable}.</p>\n")
}

fn step(state: &AppState, n: usize) -> Response {
    let s = &STEPS[n - 1];
    let factory = base(&state.factory_url);
    let log = base(&state.log_url);
    let results = base(&state.results_url);
    let store = "deploy/local/.state/dev-web/rosters";
    let mut how = String::new();
    let mut checks = String::new();
    let panel = match n {
        1 => {
            let entries = catalogue::load_all_cached(state);
            let first = entries.first().map_or("school-meals-baseline", |e| e.id.as_str()).to_owned();
            how.push_str(&command(&format!("fieldseal survey check examples/surveys/{first}\nfieldseal instrument hash examples/surveys/{first}/instrument.yaml")));
            how.push_str(&link("Open the instrument on the Instruments page", &format!("/instruments/{first}"), false));
            checks.push_str(&check("The addresses are the output of the instrument hash command", "/instruments"));
            checks.push_str(&check("The compile on the Instruments page", &format!("/instruments/{first}")));
            compile_panel(&entries)
        }
        2 => {
            how.push_str(&command("fieldseal new survey my-visit\njust publish my-visit"));
            how.push_str("<p class=\"note\">A name and version publish once: raise <code>survey.version</code> to publish a changed survey. The bundled examples are published when <code>just web</code> starts.</p>\n");
            how.push_str(&link("Open the Publishing page", "/publishing", false));
            checks.push_str(&check("The Publishing page verifies each artefact again", "/publishing#artefacts"));
            if !log.is_empty() {
                checks.push_str(&check("The log's own checkpoint", &format!("{log}/checkpoint")));
            }
            publish_panel(state)
        }
        3 => {
            how.push_str("<ol class=\"flow\">\n<li><span>Open the factory portal, sign in at the development IdP as <code>presenter</code> and issue a registration token.</span></li>\n<li><span>On the Device page, create a PIN, paste the token and register.</span></li>\n<li><span>Compare the four words on both screens, then confirm them in the factory portal.</span></li>\n</ol>\n");
            how.push_str("<p class=\"note\">To run the demo again, first retire the old device on the factory portal (REG-043), then register a new one: the factory keeps one active device for each cohort.</p>\n");
            if factory.is_empty() {
                how.push_str(&missing("factory", "FIELDSEAL_FACTORY_URL"));
            } else {
                how.push_str(&link("Open the factory portal", &format!("{factory}/"), true));
            }
            how.push_str(&link("Open the Device page", "/device", false));
            if !factory.is_empty() {
                checks.push_str(&check("The device in the factory portal's list", &format!("{factory}/")));
            }
            checks.push_str("<li><a id=\"check-registration\" href=\"/registration\">The factory's registration state on the Registration page</a></li>\n");
            live_panel(n)
        }
        4 => {
            how.push_str("<p>No operator step. When the device is registered, the Device page asks the factory for the bundle by itself (it holds the surveys assigned to the account); press <strong>Load my surveys</strong> to ask again.</p>\n");
            how.push_str(&link("Open the Device page", "/device", false));
            checks.push_str(&check("Each publication in the bundle appears in step 2", "/demo/2"));
            checks.push_str(&check("The factory's own record of the build, on the factory's output", "/demo/4#build-log"));
            let mut live = live_panel(n);
            live.push_str("<div id=\"build-log\"><h3>The factory's build event</h3>\n<p>Find the sequence above in the factory's own output:</p>\n");
            live.push_str(&command("grep '\"event\":\"bundle-built\"' deploy/local/.state/dev-web/logs/factory.log"));
            live.push_str("<p class=\"note\">In the container stack: <code>tools/stack-compose.sh logs factory</code>. A tenancy is shown by its first 16 digits.</p></div>\n");
            live
        }
        5 => {
            how.push_str(&command(&format!(
                "export FIELDSEAL_OIDC_ISSUER=http://localhost:8180/realms/fieldseal FIELDSEAL_OIDC_CLIENT_ID=fieldseal-cli\nfieldseal roster check examples/rosters/next/village-a.yaml --instrument examples/surveys/household-water-access\nfieldseal roster diff village-a@3 examples/rosters/next/village-a.yaml --store {store}\nfieldseal roster issue --factory-url {} --browser none --login presenter examples/rosters/next/village-a.yaml\nfieldseal roster list --store {store}",
                if factory.is_empty() { "http://localhost:8080" } else { &factory }
            )));
            how.push_str("<p class=\"note\">The file is version 4, one above the stored version 3. Then press <strong>Check for new surveys</strong> on the Device page, in the list of your surveys. The roster counts below never show a subject.</p>\n");
            how.push_str(&link("Open the Device page", "/device", false));
            checks.push_str(&check("The roster page shows counts only", "/instruments/household-water-access/roster?cohort=village-a"));
            checks.push_str(&check("The factory's build event for the new sequence", "/demo/4#build-log"));
            live_panel(n)
        }
        6 => {
            how.push_str("<p>On the Device page, open a person on the roster, record consent, answer the survey and hold to seal. Do this for a few people.</p>\n");
            how.push_str(&link("Open the Device page", "/device", false));
            checks.push_str(&check("Step 7 confirms the same records with signed receipts", "/demo/7"));
            live_panel(n)
        }
        7 => {
            how.push_str("<p>On the Device page, choose <strong>Hand over the records</strong>, then <strong>Download the export file</strong> and <strong>Upload</strong>.</p>\n");
            how.push_str(&link("Open the Device page", "/device", false));
            if !results.is_empty() {
                checks.push_str(&check("What landed, in the results reader", &format!("{results}/")));
            }
            live_panel(n)
        }
        _ => {
            if results.is_empty() {
                how.push_str(&missing("results reader", "FIELDSEAL_WEB_RESULTS_URL"));
            } else {
                how.push_str("<p>Sign in as <code>presenter</code> at the development IdP, open the results and download the export.</p>\n");
                how.push_str(&format!("<a class=\"btn btn-primary\" href=\"{}/\" target=\"_blank\" rel=\"noopener\">Open the results reader</a>\n", escape(&results)));
                checks.push_str(&check("The results reader", &format!("{results}/")));
            }
            "<p id=\"confirm-status\">Nothing is confirmed here. This guide has no access to the results; the results reader shows the row count, the manifest digest and the export schema version to a person who is signed in and authorised.</p>\n".to_owned()
        }
    };
    let mut b = String::new();
    b.push_str(&format!(
        "<div class=\"page-head\"><div><p class=\"crumbs\">Step {n} of {total}</p>\n<h1>{title}</h1>\n<p class=\"lede\">{what}</p></div></div>\n",
        total = STEPS.len(),
        title = escape(s.title),
        what = escape(s.what)
    ));
    b.push_str(&format!("<ol class=\"stepper\" aria-label=\"The eight steps\">\n{}</ol>\n", stepper(n)));
    b.push_str(&format!("<section class=\"card\">\n<dl class=\"facts\">\n<div><dt>Who does this in production</dt><dd>{}</dd></div>\n<div><dt>In this demo</dt><dd>{}</dd></div>\n</dl>\n</section>\n", escape(s.who), escape(s.component)));
    b.push_str(&format!("<section class=\"card\">\n<h2>How to do it</h2>\n{how}</section>\n"));
    b.push_str(&format!(
        "<section id=\"confirmation\" class=\"card\" data-step=\"{n}\" aria-labelledby=\"confirmation-h\">\n<h2 id=\"confirmation-h\">Confirmation</h2>\n<p class=\"source\"><strong>Read from:</strong> {}</p>\n{panel}",
        escape(s.source)
    ));
    if !checks.is_empty() {
        b.push_str(&format!("<h3>Check it</h3>\n<ul class=\"checks\">\n{checks}</ul>\n"));
    }
    b.push_str("</section>\n");
    if n == STEPS.len() {
        b.push_str("<section class=\"card\">\n<h2>Check the production path</h2>\n<p>This demo runs the production components on one machine with development adapters. Two commands run the whole production path:</p>\n<ul>\n<li><code>just acceptance</code> runs every walkthrough step headless against a fresh container stack.</li>\n<li><code>just release</code> builds the release images and the signed release record.</li>\n</ul>\n<p class=\"note\">The device in the Device page runs only in a browser and cannot run in production; it stands in for the Android app.</p>\n</section>\n");
    }
    b.push_str("<nav class=\"stepnav\" aria-label=\"Previous and next step\">\n");
    b.push_str(&if n > 1 { format!("<a class=\"btn\" href=\"/demo/{}\">Back</a>\n", n - 1) } else { "<a class=\"btn\" href=\"/demo\">Back</a>\n".to_owned() });
    if n < STEPS.len() {
        b.push_str(&format!("<a class=\"btn btn-primary\" href=\"/demo/{}\">Next</a>\n", n + 1));
    }
    b.push_str("</nav>\n");
    page(&format!("Step {n}: {}", s.title), &b)
}

/// The list of the eight steps with the current one marked.
fn stepper(current: usize) -> String {
    STEPS
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let now = if i + 1 == current { " aria-current=\"step\"" } else { "" };
            format!("<li><a href=\"/demo/{0}\"{now}><span class=\"num\">{0}</span> {1}</a></li>\n", i + 1, escape(s.title))
        })
        .collect()
}

/// Step 1: what each survey compiles to, computed here by the same core as the CLI.
fn compile_panel(entries: &[catalogue::Entry]) -> String {
    if entries.is_empty() {
        return "<p class=\"error\">No survey is listed: set FIELDSEAL_WEB_EXAMPLES_DIR.</p>\n".to_owned();
    }
    let mut out = String::from("<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Compiled surveys, scrolls sideways\"><table>\n<tr><th scope=\"col\">Survey</th><th scope=\"col\">Instrument address</th><th scope=\"col\">Layouts and their addresses</th><th scope=\"col\">Languages</th><th scope=\"col\">Instrument warnings</th><th scope=\"col\">Instrument lints</th></tr>\n");
    for e in entries {
        let layouts: String = e.layouts.iter().map(|l| format!("<div>{} <code class=\"hash\">{}</code></div>", escape(&l.name), escape(&l.address))).collect();
        match &e.status {
            Ok(s) => out.push_str(&format!(
                "<tr data-survey=\"{0}\"><th scope=\"row\">{0}</th><td><code class=\"hash\">{1}</code></td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>\n",
                escape(&e.id),
                escape(&s.address),
                layouts,
                escape(&s.languages.join(", ")),
                s.warnings.len(),
                s.lints.len()
            )),
            Err(findings) => out.push_str(&format!("<tr data-survey=\"{0}\"><th scope=\"row\">{0}</th><td colspan=\"5\"><span class=\"bad\">does not compile</span>: {1} finding(s)</td></tr>\n", escape(&e.id), findings.len())),
        }
    }
    out.push_str("</table></div>\n<p class=\"note\">Layout findings are on the Instruments page. The address of a published instrument (step 2) differs from these, because each publication uses its own random salt (ADR 0027).</p>\n");
    out
}

/// Step 2: each published artefact as the stand-in verifies it against the trust bundle, with the
/// log index of its entry.
fn publish_panel(state: &AppState) -> String {
    let v = match publishing::verified(state) {
        Ok(v) => v,
        Err(e) => return format!("<p class=\"error\">Nothing is verified: {}</p>\n", escape(&e)),
    };
    let mut out = match v.log_size {
        Some(size) => format!("<p>The log's checkpoint verifies against the pinned log key. It holds <strong id=\"log-size\">{size}</strong> entries.</p>\n"),
        None => "<p class=\"error\">The log did not answer, or its checkpoint does not verify against the pinned log key.</p>\n".to_owned(),
    };
    if v.reports.is_empty() {
        out.push_str("<p>No artefact has been published yet. Run the commands above.</p>\n");
        return out;
    }
    out.push_str("<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Published artefacts, scrolls sideways\"><table>\n<tr><th scope=\"col\">Artefact</th><th scope=\"col\">Address</th><th scope=\"col\">Verified</th><th scope=\"col\">Signatures</th><th scope=\"col\">Log index</th><th scope=\"col\">In the log now</th></tr>\n");
    for p in &v.reports {
        let verdict = if p.verified.is_ok() { "<span class=\"ok\">verified</span>".to_owned() } else { "<span class=\"bad\">not verified</span>".to_owned() };
        let index = p.log_entries.iter().map(|l| l.leaf_index.to_string()).collect::<Vec<_>>().join(", ");
        let held = match p.log_entries.iter().map(|l| l.held_by_log).collect::<Option<Vec<_>>>() {
            Some(all) if all.iter().all(|h| *h) => "<span class=\"ok\">yes</span>",
            Some(_) => "<span class=\"bad\">NO</span>",
            None => "<span class=\"muted\">not asked</span>",
        };
        out.push_str(&format!(
            "<tr data-artefact=\"{name}\"><th scope=\"row\">{kind} {name} {version}</th><td><code class=\"hash\">sha256:{address}</code></td><td>{verdict}</td><td>{valid} of {required} required</td><td>{index}</td><td>{held}</td></tr>\n",
            kind = escape(&p.kind),
            name = escape(&p.name),
            version = escape(&p.version),
            address = escape(&p.address),
            valid = p.threshold.valid_signatures,
            required = p.threshold.required,
        ));
    }
    out.push_str("</table></div>\n");
    out
}

/// The panel the script fills (steps 3 to 7) from the device's own view and the factory.
fn live_panel(n: usize) -> String {
    format!(
        "<p id=\"confirm-status\" role=\"status\">Reading the device and the services...</p>\n<noscript><p class=\"error\">This confirmation is read in the browser and needs JavaScript.</p></noscript>\n<dl id=\"facts\" class=\"facts\" data-step=\"{n}\"></dl>\n"
    )
}
