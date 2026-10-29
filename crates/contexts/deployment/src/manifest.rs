//! The `kind: Deployment` manifest model (DEP §2, §6), decoded from the canonical [`Value`]
//! with unknown fields rejected (DEP-001).

use std::collections::BTreeMap;

use fieldseal_kernel::Value;
use fieldseal_kernel::id::ContentAddress;

use crate::application::ManifestFinding;
use crate::custody::{CustodyBinding, Tier};
use crate::domain::{Component, SecretRef};
use fieldseal_policy::domain::{Assurance, CustodyMode};

/// The API version every manifest declares (DEP-001).
pub const API_VERSION: &str = "fieldseal.dev/v1alpha1";

/// A reference to a published artefact: by content address, or by registry plus channel
/// (DEP-003). Never content.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ArtefactRef {
    /// The registry key in `spec.registries`, when not the default artefact registry.
    pub registry: Option<String>,
    /// The artefact's name (`kind/name`).
    pub name: String,
    /// The pinned content address.
    pub digest: Option<ContentAddress>,
    /// The channel followed, when not pinned.
    pub channel: Option<String>,
}

impl ArtefactRef {
    /// `name@sha256:…` or `name#channel`.
    pub fn label(&self) -> String {
        match (&self.digest, &self.channel) {
            (Some(d), _) => format!("{}@{}", self.name, d.to_text()),
            (None, Some(c)) => format!("{}#{c}", self.name),
            (None, None) => self.name.clone(),
        }
    }
}

/// An adapter's configuration value: plain, or a secret by reference (DEP-004).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ConfigValue {
    /// A non-secret text.
    Text(String),
    /// A number.
    Number(i128),
    /// A boolean.
    Bool(bool),
    /// A secret held in the secret store.
    Secret(SecretRef),
}

impl ConfigValue {
    /// The value as environment text; a secret renders as its reference name only.
    pub fn display(&self) -> String {
        match self {
            Self::Text(t) => t.clone(),
            Self::Number(n) => n.to_string(),
            Self::Bool(b) => b.to_string(),
            Self::Secret(r) => format!("secretRef:{}", r.0),
        }
    }
}

/// A port, the adapter chosen for it and its configuration (DEP §2 `AdapterBinding`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AdapterBinding {
    /// The adapter's name.
    pub adapter: String,
    /// The adapter's version, when the deployment pins one.
    pub version: Option<String>,
    /// Configuration by key.
    pub config: BTreeMap<String, ConfigValue>,
}

/// The second listener of a component, such as the intake app's staff portal.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct PortalSpec {
    /// The address the portal listens on.
    pub bind: Option<String>,
    /// The base URL people reach the portal at; the sign-in callback follows it.
    pub public_url: Option<String>,
}

/// The directories a component names that no adapter's configuration carries.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DirsSpec {
    /// Published instruments (`*.published`).
    pub published: Option<String>,
    /// Rosters the factory issued, for intake.
    pub issued: Option<String>,
    /// Landing files, when the `DataPlatform` binding does not carry one.
    pub landing: Option<String>,
    /// Roster history that intake reads.
    pub roster_history: Option<String>,
    /// The directory that holds the export pseudonymisation key.
    pub export_key: Option<String>,
}

/// One service component's declaration.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ComponentSpec {
    /// Adapters by port name.
    pub adapters: BTreeMap<String, AdapterBinding>,
    /// Scaling settings, such as `replicas`.
    pub scaling: BTreeMap<String, i128>,
    /// The address the service listens on, if not the default.
    pub bind: Option<String>,
    /// The base URL devices bind their tokens to, if it is not the provisioned destination.
    pub public_url: Option<String>,
    /// The largest upload body in bytes.
    pub max_body_bytes: Option<i128>,
    /// The staff portal listener.
    pub portal: PortalSpec,
    /// Named directories.
    pub dirs: DirsSpec,
}

/// Who manages a platform's devices (DEP-024, ADR 0031).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ManagementMode {
    /// The runtime is device owner (default).
    SelfManaged,
    /// An EMM is device owner.
    EmmManaged,
}

impl ManagementMode {
    /// The manifest spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfManaged => "self-managed",
            Self::EmmManaged => "emm-managed",
        }
    }
}

/// Provisioning settings for one platform profile.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlatformSpec {
    /// The device-management mode.
    pub management: ManagementMode,
    /// Further platform settings.
    pub settings: BTreeMap<String, ConfigValue>,
}

/// What devices are provisioned with (DEP-020).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProvisioningSpec {
    /// The factory address hint (untrusted).
    pub factory_url: String,
    /// The destination address hint (untrusted), if different.
    pub destination_url: Option<String>,
    /// Settings per platform.
    pub platforms: BTreeMap<String, PlatformSpec>,
}

/// An environment's overrides (DEP-006).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct EnvironmentSpec {
    /// Overrides by dotted path.
    pub overrides: BTreeMap<String, ConfigValue>,
    /// Policy layers added for this environment.
    pub extra_layers: Vec<ArtefactRef>,
    /// The environment's tier, if it declares one (DEP-073).
    pub tier: Option<Tier>,
    /// Custody bindings that replace the manifest's for this environment (DEP-074).
    pub custody: BTreeMap<String, CustodyBinding>,
}

/// A decoded deployment manifest.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Manifest {
    /// `metadata.name`.
    pub name: String,
    /// `metadata.schemaVersion`.
    pub schema_version: String,
    /// The authority's display name.
    pub display_name: String,
    /// The trust bundle.
    pub trust_bundle: ArtefactRef,
    /// The artefact registry URL.
    pub artefact_registry: String,
    /// The transparency log URL.
    pub transparency_log: String,
    /// The container registry for service images.
    pub container_registry: Option<String>,
    /// Where runtime packages are distributed.
    pub runtime_distribution: Option<String>,
    /// Policy layers, outermost first.
    pub policy_layers: Vec<ArtefactRef>,
    /// Instruments the deployment runs.
    pub instruments: Vec<ArtefactRef>,
    /// The service components.
    pub components: BTreeMap<Component, ComponentSpec>,
    /// Device provisioning.
    pub provisioning: ProvisioningSpec,
    /// Declared environments.
    pub environments: BTreeMap<String, EnvironmentSpec>,
    /// Authority key custody bindings by purpose (DEP-074).
    pub custody: BTreeMap<String, CustodyBinding>,
}

type Map = BTreeMap<String, Value>;

struct Cx {
    findings: Vec<ManifestFinding>,
}

impl Cx {
    fn err(&mut self, path: &str, msg: &str) {
        self.findings.push(ManifestFinding::SchemaError(format!("{path}: {msg}")));
    }

    fn map<'a>(&mut self, v: &'a Value, path: &str) -> Option<&'a Map> {
        let m = v.as_map();
        if m.is_none() {
            self.err(path, &format!("must be a map, not {}", v.kind()));
        }
        m
    }

    fn only(&mut self, m: &Map, allowed: &[&str], path: &str) {
        for k in m.keys() {
            if !allowed.contains(&k.as_str()) {
                self.err(&format!("{path}.{k}"), "unknown field");
            }
        }
    }

    fn text(&mut self, m: &Map, key: &str, path: &str) -> Option<String> {
        match m.get(key) {
            Some(Value::Text(t)) if !t.is_empty() => Some(t.clone()),
            Some(_) => {
                self.err(&format!("{path}.{key}"), "must be non-empty text");
                None
            }
            None => {
                self.err(&format!("{path}.{key}"), "is required");
                None
            }
        }
    }

    fn opt_text(&mut self, m: &Map, key: &str, path: &str) -> Option<String> {
        m.get(key).and_then(|_| self.text(m, key, path))
    }

    fn config_value(&mut self, v: &Value, path: &str) -> Option<ConfigValue> {
        match v {
            Value::Text(t) => Some(ConfigValue::Text(t.clone())),
            Value::Int(n) => Some(ConfigValue::Number(*n)),
            Value::Bool(b) => Some(ConfigValue::Bool(*b)),
            Value::Map(m) => {
                self.only(m, &["secretRef"], path);
                match m.get("secretRef") {
                    Some(Value::Text(r)) if !r.is_empty() && r.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_/.".contains(&b)) => {
                        Some(ConfigValue::Secret(SecretRef(r.clone())))
                    }
                    _ => {
                        self.err(path, "a map value must be `{ secretRef: <name> }`");
                        None
                    }
                }
            }
            other => {
                self.err(path, &format!("must be text, a number, a boolean or a secretRef, not {}", other.kind()));
                None
            }
        }
    }

    fn config_map(&mut self, v: &Value, path: &str) -> BTreeMap<String, ConfigValue> {
        let mut out = BTreeMap::new();
        if let Some(m) = self.map(v, path) {
            for (k, v) in m {
                if let Some(c) = self.config_value(v, &format!("{path}.{k}")) {
                    out.insert(k.clone(), c);
                }
            }
        }
        out
    }

    fn artefact(&mut self, v: &Value, path: &str) -> Option<ArtefactRef> {
        let m = self.map(v, path)?;
        self.only(m, &["registry", "ref", "digest", "channel"], path);
        let name = self.text(m, "ref", path)?;
        let digest = match m.get("digest") {
            None => None,
            Some(Value::Text(t)) => match ContentAddress::parse_text(t) {
                Ok(d) => Some(d),
                Err(_) => {
                    self.err(&format!("{path}.digest"), "must be `sha256:` and 64 lowercase hex digits");
                    None
                }
            },
            Some(_) => {
                self.err(&format!("{path}.digest"), "must be text");
                None
            }
        };
        let channel = self.opt_text(m, "channel", path);
        if !m.contains_key("digest") && channel.is_none() {
            self.err(path, "must pin a `digest` or follow a `channel` (DEP-003)");
        }
        if m.contains_key("digest") && m.contains_key("channel") {
            self.err(path, "must pin a `digest` or follow a `channel`, not both (DEP-003)");
        }
        Some(ArtefactRef { registry: self.opt_text(m, "registry", path), name, digest, channel })
    }

    fn artefacts(&mut self, v: Option<&Value>, path: &str) -> Vec<ArtefactRef> {
        match v {
            None => vec![],
            Some(Value::Array(a)) => {
                let refs: Vec<ArtefactRef> = a.iter().enumerate().filter_map(|(i, x)| self.artefact(x, &format!("{path}[{i}]"))).collect();
                let mut seen = std::collections::BTreeSet::new();
                for r in &refs {
                    if !seen.insert((r.registry.clone(), r.name.clone(), r.digest.map(|d| d.to_text()), r.channel.clone())) {
                        self.err(path, &format!("`{}` is listed twice", r.label()));
                    }
                }
                refs
            }
            Some(_) => {
                self.err(path, "must be a list");
                vec![]
            }
        }
    }
}

/// Decodes a manifest, collecting every schema finding (DEP-001–003, DEP-006, DEP-024).
/// Unknown fields are findings.
pub fn decode_manifest(value: &Value) -> Result<Manifest, Vec<ManifestFinding>> {
    let mut cx = Cx { findings: vec![] };
    let m = decode(&mut cx, value);
    match m {
        Some(m) if cx.findings.is_empty() => Ok(m),
        _ => Err(cx.findings),
    }
}

fn decode(cx: &mut Cx, value: &Value) -> Option<Manifest> {
    let root = cx.map(value, "$")?;
    cx.only(root, &["apiVersion", "kind", "metadata", "spec"], "$");
    if root.get("apiVersion").and_then(Value::as_text) != Some(API_VERSION) {
        cx.err("apiVersion", &format!("must be `{API_VERSION}`"));
    }
    if root.get("kind").and_then(Value::as_text) != Some("Deployment") {
        cx.err("kind", "must be `Deployment`");
    }
    let meta = root.get("metadata").and_then(|v| cx.map(v, "metadata"));
    let (mut name, mut schema_version) = (String::new(), String::new());
    if let Some(meta) = meta {
        cx.only(meta, &["name", "schemaVersion"], "metadata");
        name = cx.text(meta, "name", "metadata").unwrap_or_default();
        schema_version = cx.text(meta, "schemaVersion", "metadata").unwrap_or_default();
    } else if !root.contains_key("metadata") {
        cx.err("metadata", "is required");
    }
    let spec = match root.get("spec") {
        Some(v) => cx.map(v, "spec")?,
        None => {
            cx.err("spec", "is required");
            return None;
        }
    };
    cx.only(spec, &["authority", "registries", "policies", "instruments", "components", "runtime", "environments", "custody"], "spec");

    let mut display_name = String::new();
    let mut trust_bundle = None;
    if let Some(a) = section(cx, spec, "authority") {
        cx.only(a, &["displayName", "trustBundle"], "spec.authority");
        display_name = cx.text(a, "displayName", "spec.authority").unwrap_or_default();
        trust_bundle = match a.get("trustBundle") {
            Some(v) => cx.artefact(v, "spec.authority.trustBundle"),
            None => {
                cx.err("spec.authority.trustBundle", "is required");
                None
            }
        };
    }
    let (mut artefact_registry, mut transparency_log, mut container_registry, mut runtime_distribution) = (String::new(), String::new(), None, None);
    let mut registry_names: Vec<String> = vec![];
    if let Some(r) = section(cx, spec, "registries") {
        cx.only(r, &["artefacts", "builds"], "spec.registries");
        registry_names = r.keys().cloned().collect();
        if let Some(a) = r.get("artefacts").and_then(|v| cx.map(v, "spec.registries.artefacts")) {
            cx.only(a, &["url", "transparencyLog"], "spec.registries.artefacts");
            artefact_registry = cx.text(a, "url", "spec.registries.artefacts").unwrap_or_default();
            transparency_log = cx.text(a, "transparencyLog", "spec.registries.artefacts").unwrap_or_default();
        } else if !r.contains_key("artefacts") {
            cx.err("spec.registries.artefacts", "is required");
        }
        if let Some(b) = r.get("builds").and_then(|v| cx.map(v, "spec.registries.builds")) {
            cx.only(b, &["container", "runtime"], "spec.registries.builds");
            container_registry = cx.opt_text(b, "container", "spec.registries.builds");
            runtime_distribution = cx.opt_text(b, "runtime", "spec.registries.builds");
        }
    }
    let mut policy_layers = vec![];
    if let Some(p) = section(cx, spec, "policies") {
        cx.only(p, &["layers"], "spec.policies");
        policy_layers = cx.artefacts(p.get("layers"), "spec.policies.layers");
        if policy_layers.is_empty() {
            cx.err("spec.policies.layers", "needs at least the deployment layer");
        }
    }
    let instruments = cx.artefacts(spec.get("instruments"), "spec.instruments");

    let mut components = BTreeMap::new();
    if let Some(cs) = section(cx, spec, "components") {
        for (cname, cv) in cs {
            let path = format!("spec.components.{cname}");
            let Some(component) = Component::parse(cname).filter(|c| Component::SERVICES.contains(c)) else {
                cx.err(&path, "unknown component (use factory, intake or publishing)");
                continue;
            };
            let Some(cm) = cx.map(cv, &path) else { continue };
            cx.only(cm, &["adapters", "scaling", "bind", "publicUrl", "maxBodyBytes", "portal", "dirs"], &path);
            let mut spec_c = ComponentSpec { bind: cx.opt_text(cm, "bind", &path), public_url: cx.opt_text(cm, "publicUrl", &path), ..Default::default() };
            match cm.get("maxBodyBytes") {
                None => {}
                Some(v) => match v.as_int() {
                    Some(n) if n > 0 => spec_c.max_body_bytes = Some(n),
                    _ => cx.err(&format!("{path}.maxBodyBytes"), "must be a positive integer"),
                },
            }
            if let Some(p) = cm.get("portal").and_then(|v| cx.map(v, &format!("{path}.portal"))) {
                let pp = format!("{path}.portal");
                cx.only(p, &["bind", "publicUrl"], &pp);
                spec_c.portal = PortalSpec { bind: cx.opt_text(p, "bind", &pp), public_url: cx.opt_text(p, "publicUrl", &pp) };
            }
            if let Some(d) = cm.get("dirs").and_then(|v| cx.map(v, &format!("{path}.dirs"))) {
                let dp = format!("{path}.dirs");
                cx.only(d, &["published", "issued", "landing", "rosterHistory", "exportKey"], &dp);
                spec_c.dirs = DirsSpec {
                    published: cx.opt_text(d, "published", &dp),
                    issued: cx.opt_text(d, "issued", &dp),
                    landing: cx.opt_text(d, "landing", &dp),
                    roster_history: cx.opt_text(d, "rosterHistory", &dp),
                    export_key: cx.opt_text(d, "exportKey", &dp),
                };
            }
            if let Some(ads) = cm.get("adapters").and_then(|v| cx.map(v, &format!("{path}.adapters"))) {
                for (port, bv) in ads {
                    let bp = format!("{path}.adapters.{port}");
                    let Some(bm) = cx.map(bv, &bp) else { continue };
                    cx.only(bm, &["adapter", "version", "config"], &bp);
                    let adapter = cx.text(bm, "adapter", &bp);
                    let version = cx.opt_text(bm, "version", &bp);
                    let config = bm.get("config").map(|c| cx.config_map(c, &format!("{bp}.config"))).unwrap_or_default();
                    if let Some(adapter) = adapter {
                        spec_c.adapters.insert(port.clone(), AdapterBinding { adapter, version, config });
                    }
                }
            } else if !cm.contains_key("adapters") {
                cx.err(&format!("{path}.adapters"), "is required");
            }
            if let Some(sc) = cm.get("scaling").and_then(|v| cx.map(v, &format!("{path}.scaling"))) {
                for (k, v) in sc {
                    match v.as_int() {
                        Some(n) if n >= 0 => {
                            spec_c.scaling.insert(k.clone(), n);
                        }
                        _ => cx.err(&format!("{path}.scaling.{k}"), "must be a non-negative integer"),
                    }
                }
            }
            components.insert(component, spec_c);
        }
    }

    let mut provisioning = ProvisioningSpec { factory_url: String::new(), destination_url: None, platforms: BTreeMap::new() };
    if let Some(r) = section(cx, spec, "runtime") {
        cx.only(r, &["provisioning"], "spec.runtime");
        if let Some(p) = r.get("provisioning").and_then(|v| cx.map(v, "spec.runtime.provisioning")) {
            let pp = "spec.runtime.provisioning";
            cx.only(p, &["factoryUrl", "destinationUrl", "platforms"], pp);
            provisioning.factory_url = cx.text(p, "factoryUrl", pp).unwrap_or_default();
            provisioning.destination_url = cx.opt_text(p, "destinationUrl", pp);
            if let Some(ps) = p.get("platforms").and_then(|v| cx.map(v, &format!("{pp}.platforms"))) {
                for (plat, v) in ps {
                    let path = format!("{pp}.platforms.{plat}");
                    let Some(pm) = cx.map(v, &path) else { continue };
                    let mode = match pm.get("management").and_then(Value::as_text) {
                        Some("self-managed") => Some(ManagementMode::SelfManaged),
                        Some("emm-managed") => Some(ManagementMode::EmmManaged),
                        _ => {
                            cx.err(&format!("{path}.management"), "must be `self-managed` or `emm-managed` (DEP-024)");
                            None
                        }
                    };
                    let mut settings = BTreeMap::new();
                    for (k, sv) in pm.iter().filter(|(k, _)| *k != "management") {
                        if let Some(c) = cx.config_value(sv, &format!("{path}.{k}")) {
                            settings.insert(k.clone(), c);
                        }
                    }
                    if let Some(management) = mode {
                        provisioning.platforms.insert(plat.clone(), PlatformSpec { management, settings });
                    }
                }
            }
            match p.get("platforms") {
                None => cx.err(&format!("{pp}.platforms"), "is required (DEP-024)"),
                Some(Value::Map(ps)) if ps.is_empty() => cx.err(&format!("{pp}.platforms"), "must declare at least one platform (DEP-024)"),
                Some(_) => {}
            }
        } else if !r.contains_key("provisioning") {
            cx.err("spec.runtime.provisioning", "is required");
        }
    }

    let mut environments = BTreeMap::new();
    if let Some(es) = section(cx, spec, "environments") {
        for (ename, ev) in es {
            let path = format!("spec.environments.{ename}");
            let Some(em) = cx.map(ev, &path) else { continue };
            cx.only(em, &["overrides", "policies", "tier", "custody"], &path);
            let mut e = EnvironmentSpec::default();
            if let Some(o) = em.get("overrides").and_then(|v| cx.map(v, &format!("{path}.overrides"))) {
                for (k, v) in o {
                    if let Some(c) = cx.config_value(v, &format!("{path}.overrides.{k}")) {
                        e.overrides.insert(k.clone(), c);
                    }
                }
            }
            if let Some(p) = em.get("policies").and_then(|v| cx.map(v, &format!("{path}.policies"))) {
                cx.only(p, &["extraLayers"], &format!("{path}.policies"));
                e.extra_layers = cx.artefacts(p.get("extraLayers"), &format!("{path}.policies.extraLayers"));
            }
            if let Some(t) = em.get("tier") {
                match t.as_text().and_then(Tier::parse) {
                    Some(t) => e.tier = Some(t),
                    None => cx.err(&format!("{path}.tier"), "must be `development`, `staging` or `production` (DEP-073)"),
                }
            }
            if let Some(c) = em.get("custody") {
                e.custody = custody_map(cx, c, &format!("{path}.custody"));
            }
            environments.insert(ename.clone(), e);
        }
        if environments.is_empty() && es.is_empty() {
            cx.err("spec.environments", "must declare at least one environment (DEP-006)");
        }
    }

    let custody = match spec.get("custody") {
        Some(c) => custody_map(cx, c, "spec.custody"),
        None => BTreeMap::new(),
    };

    // A named registry must be one the manifest declares (DEP-003).
    let named = trust_bundle.iter().map(|r| ("spec.authority.trustBundle", r)).chain(policy_layers.iter().map(|r| ("spec.policies.layers", r))).chain(instruments.iter().map(|r| ("spec.instruments", r))).chain(
        environments.values().flat_map(|e| e.extra_layers.iter().map(|r| ("spec.environments.*.policies.extraLayers", r))),
    );
    for (path, r) in named {
        if let Some(reg) = &r.registry
            && !registry_names.contains(reg)
        {
            cx.err(path, &format!("`{}` names the registry `{reg}`, which spec.registries does not declare (DEP-003)", r.name));
        }
    }

    Some(Manifest {
        custody,
        name,
        schema_version,
        display_name,
        trust_bundle: trust_bundle?,
        artefact_registry,
        transparency_log,
        container_registry,
        runtime_distribution,
        policy_layers,
        instruments,
        components,
        provisioning,
        environments,
    })
}

/// Decodes `{purpose: {adapter, assurance, mode, offline?}}` (DEP-074).
fn custody_map(cx: &mut Cx, v: &Value, path: &str) -> BTreeMap<String, CustodyBinding> {
    let mut out = BTreeMap::new();
    let Some(m) = cx.map(v, path) else { return out };
    for (purpose, b) in m {
        let at = format!("{path}.{purpose}");
        let Some(bm) = cx.map(b, &at) else { continue };
        cx.only(bm, &["adapter", "assurance", "mode", "offline"], &at);
        let adapter = cx.text(bm, "adapter", &at);
        let assurance = cx.text(bm, "assurance", &at).and_then(|t| {
            let a = Assurance::parse(&t);
            if a.is_none() {
                cx.err(&format!("{at}.assurance"), "must be `development`, `custody-bound` or `attested`");
            }
            a
        });
        let mode = cx.text(bm, "mode", &at).and_then(|t| {
            let m = CustodyMode::parse(&t);
            if m.is_none() {
                cx.err(&format!("{at}.mode"), "must be `hot` or `cold`");
            }
            m
        });
        let offline = match bm.get("offline") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => {
                cx.err(&format!("{at}.offline"), "must be a boolean");
                false
            }
        };
        if let (Some(adapter), Some(assurance), Some(mode)) = (adapter, assurance, mode) {
            out.insert(purpose.clone(), CustodyBinding { adapter, assurance, mode, offline });
        }
    }
    out
}

fn section<'a>(cx: &mut Cx, spec: &'a Map, key: &str) -> Option<&'a Map> {
    match spec.get(key) {
        Some(v) => cx.map(v, &format!("spec.{key}")),
        None => {
            cx.err(&format!("spec.{key}"), "is required");
            None
        }
    }
}

impl Manifest {
    /// The manifest as one environment sees it: only attached-resource references, scaling
    /// settings and policy layers change (DEP-006). Returns the findings of an override that
    /// strays further.
    pub fn resolve(&self, environment: &str) -> Result<Manifest, Vec<ManifestFinding>> {
        let Some(env) = self.environments.get(environment) else {
            return Err(vec![ManifestFinding::SchemaError(format!("spec.environments.{environment}: no such environment"))]);
        };
        let mut out = self.clone();
        let mut findings = vec![];
        for (path, value) in &env.overrides {
            let parts: Vec<&str> = path.split('.').collect();
            let at = format!("spec.environments.{environment}.overrides.{path}");
            let bad = |why: &str| ManifestFinding::SchemaError(format!("{at}: {why}"));
            match parts.as_slice() {
                ["components", c, "adapters", port, "config", key] => {
                    let binding = Component::parse(c).and_then(|c| out.components.get_mut(&c)).and_then(|c| c.adapters.get_mut(*port));
                    match binding {
                        Some(b) => {
                            b.config.insert((*key).to_owned(), value.clone());
                        }
                        None => findings.push(bad("names an adapter the manifest does not declare")),
                    }
                }
                ["components", c, "scaling", key] => match (Component::parse(c).and_then(|c| out.components.get_mut(&c)), value) {
                    (Some(cs), ConfigValue::Number(n)) if *n >= 0 => {
                        cs.scaling.insert((*key).to_owned(), *n);
                    }
                    _ => findings.push(bad("must be a non-negative number on a declared component")),
                },
                ["runtime", "provisioning", "factoryUrl"] => match value {
                    ConfigValue::Text(t) => out.provisioning.factory_url.clone_from(t),
                    _ => findings.push(bad("must be text")),
                },
                _ => findings.push(bad("environments may override only attached-resource references, scaling settings and policy layers (DEP-006)")),
            }
        }
        out.policy_layers.extend(env.extra_layers.iter().cloned());
        out.custody.extend(env.custody.clone());
        if findings.is_empty() { Ok(out) } else { Err(findings) }
    }
}
