//! The documentation bundle generator (DEP-030–033): what a deployment runs, as Markdown and
//! HTML, plus a scan that it holds no secret values or personal data. Pure: the caller
//! resolves the artefacts and passes their summaries in.

use std::collections::BTreeMap;

use fieldseal_kernel::id::ContentAddress;

use crate::domain::DocumentationBundle;
use crate::manifest::{ConfigValue, Manifest};
use crate::validate::looks_like_secret;

/// One item of an instrument's codebook.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ItemDoc {
    /// The item path.
    pub path: String,
    /// The data type.
    pub value_type: String,
    /// The unit, if any.
    pub unit: String,
    /// Whether it is required whenever shown.
    pub required: bool,
    /// Allowed values: codes, or a range.
    pub allowed: String,
    /// The nonresponse codes offered.
    pub nonresponse: String,
}

/// A rule or field check of an instrument.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CheckDoc {
    /// Its id.
    pub id: String,
    /// Its kind.
    pub kind: String,
    /// Its severity.
    pub severity: String,
    /// The items it concerns.
    pub items: String,
}

/// An instrument's codebook and data dictionary (DEP-031).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InstrumentDoc {
    /// The reference name used in the manifest.
    pub reference: String,
    /// The instrument's title or name.
    pub title: String,
    /// Its content address, as text.
    pub address: String,
    /// Its languages.
    pub languages: Vec<String>,
    /// Its items.
    pub items: Vec<ItemDoc>,
    /// Its rules and field checks.
    pub checks: Vec<CheckDoc>,
    /// Its consent requirements, as `key: value` lines.
    pub consent: Vec<String>,
}

/// One control of the effective policy and the layer that set it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PolicyRow {
    /// The control path.
    pub control: String,
    /// The effective value.
    pub value: String,
    /// The layer that last set it, or `schema default`.
    pub layer: String,
}

/// A trust fingerprint row.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TrustRow {
    /// `root`, a purpose such as `factory`, or `publisher`.
    pub kind: String,
    /// The key identifier.
    pub key: String,
    /// Validity, as text.
    pub validity: String,
}

/// Everything `docs build` needs, already resolved.
pub struct DocsInput<'a> {
    /// The manifest (base form).
    pub manifest: &'a Manifest,
    /// The environment documented.
    pub environment: &'a str,
    /// The release the documentation belongs to (DEP-032).
    pub release: ContentAddress,
    /// The instruments the manifest references, resolved.
    pub instruments: Vec<InstrumentDoc>,
    /// The policy layers the manifest references, resolved: reference name to layer label.
    pub policy_layers: BTreeMap<String, String>,
    /// The effective policy (DEP-031).
    pub policy: Vec<PolicyRow>,
    /// The trust bundle's keys; empty when the bundle was not supplied.
    pub trust: Vec<TrustRow>,
}

enum Block {
    Para(String),
    Table(Vec<String>, Vec<Vec<String>>),
    Code(String),
    Heading(String),
}

struct Page {
    title: String,
    blocks: Vec<Block>,
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

impl Page {
    fn new(title: &str) -> Self {
        Self { title: title.to_owned(), blocks: vec![] }
    }

    fn h(&mut self, t: &str) {
        self.blocks.push(Block::Heading(t.to_owned()));
    }

    fn p(&mut self, t: impl Into<String>) {
        self.blocks.push(Block::Para(t.into()));
    }

    fn code(&mut self, t: impl Into<String>) {
        self.blocks.push(Block::Code(t.into()));
    }

    fn table(&mut self, head: &[&str], rows: Vec<Vec<String>>) {
        self.blocks.push(Block::Table(head.iter().map(|s| (*s).to_owned()).collect(), rows));
    }

    fn markdown(&self) -> String {
        let cell = |s: &str| s.replace('|', "\\|").replace('\n', " ");
        let mut out = format!("# {}\n\n", self.title);
        for b in &self.blocks {
            match b {
                Block::Heading(t) => out.push_str(&format!("## {t}\n\n")),
                Block::Para(t) => out.push_str(&format!("{t}\n\n")),
                Block::Code(t) => out.push_str(&format!("```\n{t}\n```\n\n")),
                Block::Table(head, rows) => {
                    out.push_str(&format!("| {} |\n|{}|\n", head.iter().map(|h| cell(h)).collect::<Vec<_>>().join(" | "), vec!["---"; head.len()].join("|")));
                    for r in rows {
                        out.push_str(&format!("| {} |\n", r.iter().map(|c| cell(c)).collect::<Vec<_>>().join(" | ")));
                    }
                    out.push('\n');
                }
            }
        }
        out
    }

    fn html(&self) -> String {
        let mut out = format!(
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{t}</title></head><body><main><h1>{t}</h1>\n",
            t = escape(&self.title)
        );
        for b in &self.blocks {
            match b {
                Block::Heading(t) => out.push_str(&format!("<h2>{}</h2>\n", escape(t))),
                Block::Para(t) => out.push_str(&format!("<p>{}</p>\n", escape(t))),
                Block::Code(t) => out.push_str(&format!("<pre><code>{}</code></pre>\n", escape(t))),
                Block::Table(head, rows) => {
                    out.push_str("<table><thead><tr>");
                    for h in head {
                        out.push_str(&format!("<th>{}</th>", escape(h)));
                    }
                    out.push_str("</tr></thead><tbody>\n");
                    for r in rows {
                        out.push_str("<tr>");
                        for c in r {
                            out.push_str(&format!("<td>{}</td>", escape(c)));
                        }
                        out.push_str("</tr>\n");
                    }
                    out.push_str("</tbody></table>\n");
                }
            }
        }
        out.push_str("</main></body></html>\n");
        out
    }
}

fn s(x: impl Into<String>) -> String {
    x.into()
}

fn config_shown(v: &ConfigValue) -> String {
    match v {
        ConfigValue::Secret(r) => format!("secretRef: {}", r.0),
        other => other.display(),
    }
}

/// Generates the documentation bundle (DEP-030, DEP-031). Fails with `UnresolvableArtefact`
/// when the manifest references an instrument or policy layer the input doesn't resolve.
pub fn build_documentation(input: &DocsInput<'_>) -> Result<DocumentationBundle, String> {
    let m = input.manifest;
    let resolved = m.resolve(input.environment).map_err(|f| f.iter().map(|x| x.message().to_owned()).collect::<Vec<_>>().join("; "))?;
    for i in &resolved.instruments {
        if !input.instruments.iter().any(|d| d.reference == i.name) {
            return Err(format!("UnresolvableArtefact: instrument `{}` was not supplied", i.name));
        }
    }
    for l in &resolved.policy_layers {
        if !input.policy_layers.contains_key(&l.name) {
            return Err(format!("UnresolvableArtefact: policy layer `{}` was not supplied", l.name));
        }
    }
    let release = input.release.to_text();
    let mut pages: Vec<(&str, Page)> = vec![];

    let mut index = Page::new(&format!("{}: deployment documentation", m.display_name));
    index.p(format!("Deployment `{}`, environment `{}`.", m.name, input.environment));
    index.p(format!("Release: {release}"));
    index.p("This documentation was generated from the release's manifest and the artefacts it references. It holds no secret values and no personal data.");
    index.table(
        &["Section", "File"],
        ["adapters", "policy", "instruments", "trust", "provisioning", "runbooks"].iter().map(|n| vec![s(*n), format!("{n}.md")]).collect(),
    );
    pages.push(("index", index));

    let mut adapters = Page::new("Adapter inventory");
    let mut rows = vec![];
    for (component, spec) in &resolved.components {
        for (port, b) in &spec.adapters {
            let resources: Vec<String> = b.config.iter().map(|(k, v)| format!("{k}={}", config_shown(v))).collect();
            rows.push(vec![component.name().into(), port.clone(), b.adapter.clone(), b.version.clone().unwrap_or_else(|| "build default".into()), resources.join("; ")]);
        }
    }
    adapters.table(&["Component", "Port", "Adapter", "Version", "Attached resources and configuration"], rows);
    adapters.p("Secrets appear only as references; they are resolved from the secret store inside the component at run time.");
    pages.push(("adapters", adapters));

    let mut policy = Page::new("Policy");
    policy.h("Layers");
    policy.table(
        &["Order", "Reference", "Layer"],
        resolved.policy_layers.iter().enumerate().map(|(i, l)| vec![(i + 1).to_string(), l.label(), input.policy_layers.get(&l.name).cloned().unwrap_or_default()]).collect(),
    );
    policy.h("Effective controls");
    policy.table(&["Control", "Effective value", "Set by layer"], input.policy.iter().map(|r| vec![r.control.clone(), r.value.clone(), r.layer.clone()]).collect());
    pages.push(("policy", policy));

    let mut inst = Page::new("Instruments: codebook and data dictionary");
    if input.instruments.is_empty() {
        inst.p("This deployment references no instruments.");
    }
    for d in &input.instruments {
        inst.h(&format!("{} ({})", d.title, d.reference));
        inst.p(format!("Content address: {}. Languages: {}.", d.address, d.languages.join(", ")));
        inst.table(
            &["Item", "Type", "Unit", "Required", "Allowed values", "Nonresponse"],
            d.items.iter().map(|i| vec![i.path.clone(), i.value_type.clone(), i.unit.clone(), if i.required { "yes".into() } else { String::new() }, i.allowed.clone(), i.nonresponse.clone()]).collect(),
        );
        inst.table(&["Rule or field check", "Kind", "Severity", "Items"], d.checks.iter().map(|c| vec![c.id.clone(), c.kind.clone(), c.severity.clone(), c.items.clone()]).collect());
        inst.p(if d.consent.is_empty() { s("Consent requirements: none declared.") } else { format!("Consent requirements: {}", d.consent.join("; ")) });
    }
    pages.push(("instruments", inst));

    let mut trust = Page::new("Trust material");
    trust.p(format!("Trust bundle: {}", m.trust_bundle.label()));
    trust.table(&["Kind", "Key", "Validity"], input.trust.iter().map(|t| vec![t.kind.clone(), t.key.clone(), t.validity.clone()]).collect());
    if input.trust.is_empty() {
        trust.p("The trust bundle was not supplied when this documentation was built, so its keys are not listed.");
    }
    trust.p(format!("Transparency log: {}", m.transparency_log));
    pages.push(("trust", trust));

    let mut prov = Page::new("Provisioning configuration");
    prov.p("Delivered through the platform's managed-configuration mechanism, not compiled into the build (DEP-021).");
    prov.table(
        &["Setting", "Value"],
        {
            let mut r = vec![
                vec![s("Trust bundle"), m.trust_bundle.label()],
                vec![s("Factory URL (untrusted hint)"), resolved.provisioning.factory_url.clone()],
                vec![s("Destination URL (untrusted hint)"), resolved.provisioning.destination_url.clone().unwrap_or_else(|| "same as factory".into())],
                vec![s("Initial runtime policy"), resolved.policy_layers.iter().map(|l| l.label()).collect::<Vec<_>>().join(", ")],
            ];
            for (plat, p) in &resolved.provisioning.platforms {
                r.push(vec![format!("{plat}: device management"), p.management.as_str().into()]);
                for (k, v) in &p.settings {
                    r.push(vec![format!("{plat}: {k}"), config_shown(v)]);
                }
            }
            r
        },
    );
    pages.push(("provisioning", prov));

    let mut rb = Page::new("Runbooks");
    let env = input.environment;
    let reg = &m.artefact_registry;
    let env_prefix = format!("FIELDSEAL_ENVIRONMENT={env} FIELDSEAL_RELEASE={release}");
    for (title, why, cmds) in [
        ("Registration exceptions", "A device cannot attest, or a request needs a manual decision.", vec!["registration inspect <request>", "registration approve <request>"]),
        ("Forced close", "End a tenancy before its window, for example for a lost device.", vec!["device simulate --script <close.yaml>   # rehearse first", "registration approve <close-request>"]),
        ("Deny-listing", "Stop a key or a build from being accepted.", vec!["trust revoke <certificate> --reason <reason>", "artefact withdraw <address> --reason <reason>"]),
        ("Rollback", "Deploy the previous release unchanged (DEP-013).", vec!["deployment render <manifest> --environment <env>   # for the earlier release's manifest", "# redeploy the earlier release's builds with that environment"]),
        ("Key rotation", "Issue a successor online key and republish the trust bundle.", vec!["trust issue --purpose <purpose> --validity <days> --csr <csr> --out <dir>", "trust bundle --roots <roots> --pins <pins> --out <bundle>", "artefact publish <bundle>"]),
    ] {
        rb.h(title);
        rb.p(why);
        rb.code(format!("{env_prefix} FIELDSEAL_REGISTRY_URL={reg} \\\n  fieldseal {}", cmds.join("\n  fieldseal ")));
    }
    pages.push(("runbooks", rb));

    let mut files = BTreeMap::new();
    for (name, page) in &pages {
        files.insert(format!("{name}.md"), page.markdown().into_bytes());
        files.insert(format!("{name}.html"), page.html().into_bytes());
    }
    let bundle = DocumentationBundle { release: input.release, files };
    let found = scan_bundle(&bundle);
    if found.is_empty() { Ok(bundle) } else { Err(format!("the documentation holds secrets or personal data: {}", found.join("; "))) }
}

/// Scans a bundle for secret values and personal data (DEP-033): key-like tokens, PEM
/// blocks, credentials in URLs, e-mail addresses and phone numbers. Exactly 64 lowercase hex
/// digits are content addresses and key identifiers, which are public, and pass.
pub fn scan_bundle(bundle: &DocumentationBundle) -> Vec<String> {
    let mut out = vec![];
    for (name, bytes) in &bundle.files {
        let text = String::from_utf8_lossy(bytes);
        for (n, line) in text.lines().enumerate() {
            let at = format!("{name}:{}", n + 1);
            if line.contains("-----BEGIN") {
                out.push(format!("{at}: a PEM block"));
            }
            for token in line.split(|c: char| !(c.is_ascii_alphanumeric() || "+/=_-@.:".contains(c))) {
                let token = token.trim_matches(|c: char| ".:,;".contains(c));
                if token.len() < 6 {
                    continue;
                }
                let hex64 = token.len() == 64 && token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
                let bare = token.strip_prefix("sha256:").unwrap_or(token);
                let bare_hex64 = bare.len() == 64 && bare.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
                if hex64 || bare_hex64 {
                    continue;
                }
                if token.contains("://") && looks_like_secret(token) {
                    out.push(format!("{at}: credentials in a URL"));
                } else if looks_like_secret(token) {
                    out.push(format!("{at}: a value that looks like a key, password or token"));
                }
                if token.split_once('@').is_some_and(|(l, d)| !l.is_empty() && d.contains('.')) {
                    out.push(format!("{at}: an e-mail address"));
                }
            }
            for run in line.split(|c: char| !(c.is_ascii_digit() || " -+()".contains(c))) {
                let run = run.trim();
                let digits = run.chars().filter(char::is_ascii_digit).count();
                let groups = run.split(|c: char| !c.is_ascii_digit()).filter(|g| !g.is_empty()).count();
                if (9..=15).contains(&digits) && (run.starts_with('+') || groups >= 3) {
                    out.push(format!("{at}: a phone number"));
                }
            }
        }
    }
    out
}
