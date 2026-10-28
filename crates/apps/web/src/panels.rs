//! The panels of the instrument detail page: picker, rendered instrument, findings, element
//! tree, code lists, concepts, rules, languages and identity.

use fieldseal_instrument::domain::compiled::{CompiledAction, NodeKind};
use fieldseal_instrument::domain::{LocalisedText, Nonresponse, WindowClass};
use fieldseal_adapters_web::workbench::Workbench;

use crate::catalogue::{Entry, Summary};
use crate::instruments::Choice;
use crate::ui::{self, escape};

/// The whole detail page body: the instrument is the page. One filled action ("Open full
/// page"); the layout, language and window pickers sit behind one "View options" disclosure;
/// everything else is a secondary tab.
pub fn detail(entry: &Entry, choice: &Choice, wasm: bool) -> String {
    let id = escape(&entry.id);
    let crumbs = "<p class=\"crumbs\"><a href=\"/instruments\">All instruments</a></p>\n";
    let Ok(summary) = &entry.status else {
        let mut out = format!("{crumbs}<div class=\"page-head\"><div><h1>Instrument <code>{id}</code></h1>\n<p class=\"muted\">This instrument cannot be drawn.</p></div>\n<div class=\"head-actions\"><a class=\"btn btn-primary\" href=\"/instruments/{id}/source\">View source</a></div></div>\n");
        out.push_str(&findings_invalid(entry));
        out.push_str(&format!("<section class=\"card\">{}</section>\n", sources(entry, choice, false)));
        return out;
    };
    let q = escape(&choice.query());
    let sep = if q.is_empty() { "?" } else { "&amp;" };
    let langs = summary.languages.join(", ");
    let mut out = format!(
        "{crumbs}<div class=\"page-head\"><div><h1>{}</h1>\n<p class=\"muted\"><code>{id}</code> &middot; version {} &middot; {}</p></div>\n<div class=\"head-actions\"><a class=\"btn btn-primary\" href=\"/instruments/{id}/render{q}{sep}full=1\">Open full page</a></div></div>\n",
        escape(&summary.name),
        escape(&summary.version),
        escape(&langs)
    );
    out.push_str(&picker(entry, summary, choice));
    out.push_str(&frame(entry, choice));
    out.push_str(&live(entry, choice, wasm));
    let mut items = vec![ui::Tab { id: "findings", label: checks_label(summary, entry), html: findings(entry, summary) }];
    match entry.workbench(&[]) {
        Ok(bench) => {
            let lang = choice.lang.clone().unwrap_or_else(|| summary.default_language.clone());
            items.push(ui::Tab { id: "tree", label: "Structure".into(), html: tree(&bench, &lang) });
            items.push(ui::Tab { id: "code-lists", label: "Code lists".into(), html: code_lists(&bench, &lang) });
            items.push(ui::Tab { id: "rules", label: "Rules".into(), html: rules(&bench) });
            items.push(ui::Tab { id: "details", label: "Details".into(), html: format!("{}{}{}", identity(entry, summary), concepts(&bench), sources(entry, choice, true)) });
        }
        Err(e) => {
            items.push(ui::Tab { id: "details", label: "Details".into(), html: format!("<p class=\"error\">{}</p>{}{}", escape(&e.to_string()), identity(entry, summary), sources(entry, choice, true)) });
        }
    }
    out.push_str(&ui::tabs("More about this instrument", &items));
    out
}

fn checks_label(s: &Summary, entry: &Entry) -> String {
    let n = s.warnings.len() + s.lints.len() + entry.layout_errors.len();
    if n == 0 { "Checks".to_owned() } else { format!("Checks ({n})") }
}

fn findings_invalid(entry: &Entry) -> String {
    let items: String = entry.status.as_ref().err().into_iter().flatten().map(|m| format!("<li class=\"error\">{}</li>", escape(m))).collect();
    let mut s = format!("<section id=\"findings\" class=\"card\"><h2>Findings</h2>\n<p class=\"error\">This instrument is invalid and cannot be drawn.</p>\n<ul>{items}</ul></section>\n");
    for (name, msgs) in &entry.layout_errors {
        let items: String = msgs.iter().map(|m| format!("<li>{}</li>", escape(m))).collect();
        s.push_str(&format!("<section class=\"card\"><h2>Layout {}</h2><ul>{items}</ul></section>\n", escape(name)));
    }
    s
}

fn selected(on: bool) -> &'static str {
    if on { " selected" } else { "" }
}

fn picker(entry: &Entry, summary: &Summary, c: &Choice) -> String {
    let mut layout_opts = format!("<option value=\"\"{}>Automatic: by window class</option><option value=\"default\"{}>default layout</option>", selected(c.layout.is_none()), selected(c.layout.as_deref() == Some("default")));
    for (i, l) in entry.layouts.iter().enumerate() {
        let window = l.window.map(WindowClass::name).unwrap_or("any window");
        layout_opts.push_str(&format!("<option value=\"{i}\"{}>{} ({window})</option>", selected(c.layout.as_deref() == Some(&i.to_string())), escape(&l.name)));
    }
    let current_lang = c.lang.as_deref().unwrap_or(&summary.default_language);
    let lang_opts: String = summary.languages.iter().map(|l| format!("<option value=\"{0}\"{1}>{0}</option>", escape(l), selected(l == current_lang))).collect();
    let window_opts: String = std::iter::once(("", "Automatic: expanded unless the layout says"))
        .chain(WindowClass::ALL.iter().map(|w| (w.name(), w.name())))
        .map(|(v, label)| format!("<option value=\"{v}\"{}>{label}</option>", selected(c.window.as_deref().unwrap_or("") == v)))
        .collect();
    let id = escape(&entry.id);
    let mut links = String::new();
    let link = |label: &str, q: Choice| format!("<li><a href=\"/instruments/{id}{}\">{}</a></li>", escape(&q.query()), escape(label));
    links.push_str(&link("by window class", Choice { layout: None, ..c.clone() }));
    links.push_str(&link("default layout", Choice { layout: Some("default".into()), ..c.clone() }));
    for (i, l) in entry.layouts.iter().enumerate() {
        links.push_str(&link(&format!("layout {}", l.name), Choice { layout: Some(i.to_string()), ..c.clone() }));
    }
    for l in &summary.languages {
        links.push_str(&link(&format!("language {l}"), Choice { lang: Some(l.clone()), ..c.clone() }));
    }
    for w in WindowClass::ALL {
        links.push_str(&link(&format!("window {}", w.name()), Choice { window: Some(w.name().to_owned()), ..c.clone() }));
    }
    format!(
        "<details class=\"view-options\" id=\"picker\">\n<summary class=\"btn\">View options</summary>\n<div class=\"options-body\">\n<form class=\"picker\" method=\"get\" action=\"/instruments/{id}\">\n<label>Layout <select name=\"layout\">{layout_opts}</select></label>\n<label>Language <select name=\"lang\">{lang_opts}</select></label>\n<label>Window class <select name=\"window\">{window_opts}</select></label>\n<button type=\"submit\" class=\"btn\">Apply</button>\n</form>\n<details class=\"quiet\"><summary>The same choices as plain links</summary><ul>{links}</ul></details>\n</div>\n</details>\n"
    )
}

fn frame(entry: &Entry, c: &Choice) -> String {
    let id = escape(&entry.id);
    let q = escape(&c.query());
    format!(
        "<section id=\"rendered\" class=\"stage\">\n<iframe class=\"instrument\" src=\"/instruments/{id}/render{q}\" sandbox=\"allow-same-origin allow-scripts\" title=\"Rendered instrument {id}\"></iframe>\n</section>\n"
    )
}

fn live(entry: &Entry, c: &Choice, wasm: bool) -> String {
    let name = |f: fieldseal_adapters_authoring::Format| if f == fieldseal_adapters_authoring::Format::Json { "json" } else { "yaml" };
    let which = c.layouts(entry).unwrap_or_default().iter().map(|i| format!("{i}:{}", name(entry.layouts[*i].format))).collect::<Vec<_>>().join(",");
    let format = name(entry.format);
    let attr = |v: &Option<String>| escape(v.as_deref().unwrap_or(""));
    let status = if wasm {
        "Waiting for the WebAssembly core to load. Change an answer in the instrument above and the result appears here; nothing is sent to the server."
    } else {
        "Live evaluation needs the WASM bundle: set FIELDSEAL_WEB_WASM_DIR; the rest of this page is unaffected."
    };
    format!(
        "<section id=\"live\" class=\"card live\" data-instrument=\"{}\" data-format=\"{format}\" data-layouts=\"{which}\" data-lang=\"{}\" data-window=\"{}\" data-wasm=\"{}\">\n<p class=\"label\">Live evaluation</p>\n<dl id=\"live-result\"></dl>\n<p id=\"live-status\" class=\"muted\">{status}</p></section>\n",
        escape(&entry.id),
        attr(&c.lang),
        attr(&c.window),
        if wasm { "1" } else { "0" }
    )
}

fn findings(entry: &Entry, s: &Summary) -> String {
    let list = |items: &[String]| if items.is_empty() { "<p>None.</p>".to_owned() } else { format!("<ul>{}</ul>", items.iter().map(|i| format!("<li>{}</li>", escape(i))).collect::<String>()) };
    let mut out = format!("<h3>Findings</h3>\n<p>Valid. Warnings: {}, lints: {}.</p>\n<h3>Warnings</h3>{}<h3>Lints</h3>{}", s.warnings.len(), s.lints.len(), list(&s.warnings), list(&s.lints));
    for (name, msgs) in &entry.layout_errors {
        out.push_str(&format!("<h3>Layout {} does not validate</h3>{}", escape(name), list(msgs)));
    }
    out
}

fn text(t: &LocalisedText, lang: &str, fallback: &str) -> String {
    t.get_str(lang).or_else(|| t.get_str(fallback)).or_else(|| t.iter().next().map(|(_, s)| s)).unwrap_or("").to_owned()
}

fn tree(bench: &Workbench, lang: &str) -> String {
    let compiled = bench.instrument().compiled();
    let default = bench.instrument().definition().languages.default.as_str().to_owned();
    fn walk(bench: &Workbench, idx: usize, lang: &str, default: &str, out: &mut String) {
        let compiled = bench.instrument().compiled();
        let node = &compiled.nodes()[idx];
        let rules = compiled.rules().iter().filter(|r| r.refs.contains(&node.path)).count();
        let description = match &node.kind {
            NodeKind::Group(g) => {
                let repeat = g.repeat_over.as_ref().map(|r| format!(", repeats over {}", escape(r))).unwrap_or_default();
                format!("group <code>{}</code> {}{repeat}", escape(&node.path), escape(&text(&g.label, lang, default)))
            }
            NodeKind::Question(q) => {
                let control = q.control.as_ref().map(|c| c.control_type().name()).unwrap_or("from roster");
                let nr: Vec<&str> = q.nonresponse.iter().map(|n: &Nonresponse| n.code()).collect();
                format!(
                    "question <code>{}</code> {} [{}; {}; nonresponse: {}; rules: {rules}{}]",
                    escape(&node.path),
                    escape(&text(&q.label, lang, default)),
                    q.data.data_type.name(),
                    control,
                    if nr.is_empty() { "none".to_owned() } else { nr.join(", ") },
                    if q.optional { "; optional" } else { "" }
                )
            }
            NodeKind::Display(d) => format!("display <code>{}</code> {}", escape(&node.path), escape(&d.text.as_ref().map(|t| text(t, lang, default)).unwrap_or_default())),
        };
        out.push_str(&format!("<li>{description}"));
        if !node.children.is_empty() {
            out.push_str("<ul class=\"tree\">");
            for &c in &node.children {
                walk(bench, c, lang, default, out);
            }
            out.push_str("</ul>");
        }
        out.push_str("</li>\n");
    }
    let mut items = String::new();
    for &r in compiled.roots() {
        walk(bench, r, lang, &default, &mut items);
    }
    format!("<h3>Element tree</h3>\n<p>Labels in {}.</p>\n<ul class=\"tree\">{items}</ul>\n", escape(lang))
}

fn code_lists(bench: &Workbench, lang: &str) -> String {
    let def = bench.instrument().definition();
    let default = def.languages.default.as_str();
    if def.code_lists.is_empty() {
        return "<h3>Code lists</h3><p>This instrument has no code lists.</p>\n".to_owned();
    }
    let mut out = String::from("<h3>Code lists</h3>\n");
    for (id, list) in &def.code_lists {
        let rows: String = list
            .codes
            .iter()
            .map(|c| format!("<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>", escape(&c.code), escape(&text(&c.label, lang, default)), c.value.as_ref().map(|v| v.to_string()).unwrap_or_default()))
            .collect();
        out.push_str(&format!(
            "<h4><code>{}</code>{}</h4>\n<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Table, scrolls sideways\"><table><thead><tr><th>Code</th><th>Label</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table></div>\n",
            escape(id),
            if list.ordered { " (ordered)" } else { "" }
        ));
    }
    out
}

fn concepts(bench: &Workbench) -> String {
    let compiled = bench.instrument().compiled();
    let def = bench.instrument().definition();
    let mut rows = String::new();
    let mut add = |at: &str, c: &fieldseal_instrument::domain::Concept| {
        rows.push_str(&format!("<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>", escape(at), escape(&c.system), escape(&c.code), escape(c.display.as_deref().unwrap_or(""))));
    };
    for n in compiled.nodes() {
        match &n.kind {
            NodeKind::Question(q) => q.concept.iter().chain(q.data.concept.iter()).for_each(|c| add(&n.path, c)),
            NodeKind::Group(g) => g.concept.iter().for_each(|c| add(&n.path, c)),
            NodeKind::Display(_) => {}
        }
    }
    for (id, list) in &def.code_lists {
        for code in &list.codes {
            code.concept.iter().for_each(|c| add(&format!("{id}.{}", code.code), c));
        }
    }
    if rows.is_empty() {
        return "<div id=\"concepts\"><h3>Concepts</h3><p>This instrument links no external terminology concepts.</p></div>\n".to_owned();
    }
    format!("<div id=\"concepts\"><h3>Concepts</h3>\n<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Table, scrolls sideways\"><table><thead><tr><th>On</th><th>System</th><th>Code</th><th>Display</th></tr></thead><tbody>{rows}</tbody></table></div></div>\n")
}

fn rules(bench: &Workbench) -> String {
    let compiled = bench.instrument().compiled();
    if compiled.rules().is_empty() {
        return "<h3>Rules</h3><p>This instrument has no rules.</p>\n".to_owned();
    }
    let rows: String = compiled
        .rules()
        .iter()
        .map(|r| {
            let (kind, class) = match &r.action {
                CompiledAction::Hard { .. } => ("hard", "blocks sealing"),
                CompiledAction::Soft { .. } => ("soft", "asks again"),
                CompiledAction::Skip { .. } => ("skip", "hides elements"),
                CompiledAction::Derive { .. } => ("derive", "computes a value"),
            };
            format!("<tr><td><code>{}</code></td><td>{kind}</td><td>{class}</td><td>{}</td></tr>", escape(&r.id), escape(&r.refs.join(", ")))
        })
        .collect();
    format!("<h3>Rules</h3>\n<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Table, scrolls sideways\"><table><thead><tr><th>Id</th><th>Kind</th><th>Effect</th><th>Reads</th></tr></thead><tbody>{rows}</tbody></table></div>\n")
}

fn identity(entry: &Entry, s: &Summary) -> String {
    let langs: Vec<String> = s.languages.iter().map(|l| if *l == s.default_language { format!("{l} (default)") } else { l.clone() }).collect();
    let layouts: String = entry
        .layouts
        .iter()
        .enumerate()
        .map(|(i, l)| format!("<tr><td>{i}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>", escape(&l.name), l.window.map(WindowClass::name).unwrap_or("any"), escape(&l.address)))
        .collect();
    format!(
        "<div id=\"identity\"><h3>Languages and identity</h3>\n<p>{} elements, {} layouts, {} warnings, {} lints.</p>\n<p>Languages: {}.</p>\n<p>Content address: <code>{}</code></p>\n<p>The short fingerprint (INS-104) is shown only when a salt exists; this app uses none, so the instrument has no fingerprint here.</p>\n<h4>Layouts</h4>{}</div>\n",
        s.elements,
        entry.layouts.len(),
        s.warnings.len(),
        s.lints.len(),
        escape(&langs.join(", ")),
        escape(&s.address),
        if layouts.is_empty() { "<p>No layouts; the default layout is used.</p>".to_owned() } else { format!("<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Table, scrolls sideways\"><table><thead><tr><th>#</th><th>Name</th><th>Window class</th><th>Content address</th></tr></thead><tbody>{layouts}</tbody></table></div>") }
    )
}

fn sources(entry: &Entry, c: &Choice, valid: bool) -> String {
    let id = escape(&entry.id);
    let plan = if valid { format!(" | <a href=\"/instruments/{id}/plan{}\">download plan</a>", escape(&c.query())) } else { String::new() };
    let layouts: String = entry.layouts.iter().enumerate().map(|(i, l)| format!(" | <a href=\"/instruments/{id}/layout/{i}/source\">layout source: {}</a>", escape(&l.name))).collect();
    format!("<div id=\"source\"><h3>Source</h3><p><a href=\"/instruments/{id}/source\">view source</a>{plan}{layouts}</p></div>\n")
}
