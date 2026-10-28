//! The policy document (POL-001, POL-002): decoded from a [`Value`] tree with unknown-field
//! rejection, collecting every finding rather than stopping at the first.

use std::collections::BTreeMap;

use fieldseal_kernel::id::ContentAddress;
use fieldseal_kernel::value::Value;

use super::control::{ControlValue, decode_value};
use super::finding::{Finding, has_errors};
use super::invariant::check_floors;
use super::schema::{PER_KIND_GROUPS, SCHEMA_VERSION_MAJOR, SECTIONS, control_spec, is_group};
use super::choice::ARTEFACT_KINDS;
use super::units::Version;

/// The `apiVersion` every policy carries (POL-001).
pub const API_VERSION: &str = "fieldseal.dev/v1alpha1";
/// The `kind` every policy carries (POL-001).
pub const KIND: &str = "Policy";

/// An instrument named by a layer: by name or by content address.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum InstrumentRef {
    /// By name.
    Name(String),
    /// By content address.
    Address(ContentAddress),
}

/// Where a policy applies (POL §2).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Layer {
    /// The whole deployment.
    Deployment,
    /// A named programme: a set of cohorts and instruments.
    Programme(String),
    /// One instrument, by name or content address.
    Instrument(InstrumentRef),
}

impl Layer {
    /// The position in the application order: deployment, then programme, then instrument (POL-020).
    pub fn rank(&self) -> u8 {
        match self {
            Self::Deployment => 0,
            Self::Programme(_) => 1,
            Self::Instrument(_) => 2,
        }
    }

    /// A short label for diagnostics, for example `programme:programme-a`.
    pub fn label(&self) -> String {
        match self {
            Self::Deployment => "deployment".to_owned(),
            Self::Programme(name) => format!("programme:{name}"),
            Self::Instrument(InstrumentRef::Name(name)) => format!("instrument:{name}"),
            Self::Instrument(InstrumentRef::Address(a)) => format!("instrument:{a:?}"),
        }
    }
}

/// A policy's identity (POL-001).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Metadata {
    /// Lower-case, hyphenated name, unique per kind within an authority.
    pub name: String,
    /// Semantic version.
    pub version: Version,
    /// Free labels.
    pub labels: BTreeMap<String, String>,
}

/// One decoded policy document: the controls it sets, by full path from `spec`
/// (for example `runtime.pin.minLength`).
#[derive(Clone, PartialEq, Debug)]
pub struct PolicyDocument {
    /// Name, version and labels.
    pub metadata: Metadata,
    /// The schema version the document declares.
    pub schema_version: Version,
    /// Where it applies.
    pub layer: Layer,
    /// The controls it sets. Controls it does not set are absent, not defaulted.
    pub controls: BTreeMap<String, ControlValue>,
}

/// The result of decoding: a document when it is usable, and every finding.
#[derive(Clone, PartialEq, Debug)]
pub struct Decoded {
    /// The document, when decoding found no error.
    pub document: Option<PolicyDocument>,
    /// Every finding, errors and warnings.
    pub findings: Vec<Finding>,
}

fn is_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn parse_hex_address(s: &str) -> Option<ContentAddress> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(ContentAddress::from(bytes))
}

fn map_at<'a>(
    value: &'a Value,
    path: &str,
    findings: &mut Vec<Finding>,
) -> Option<&'a BTreeMap<String, Value>> {
    match value.as_map() {
        Some(m) => Some(m),
        None => {
            findings.push(Finding::error("POL-002", path, format!("expected a map, found {}", value.kind())));
            None
        }
    }
}

fn text_at<'a>(value: &'a Value, path: &str, findings: &mut Vec<Finding>) -> Option<&'a str> {
    match value.as_text() {
        Some(t) => Some(t),
        None => {
            findings.push(Finding::error("POL-001", path, format!("expected text, found {}", value.kind())));
            None
        }
    }
}

fn reject_unknown(map: &BTreeMap<String, Value>, known: &[&str], path: &str, findings: &mut Vec<Finding>) {
    for key in map.keys() {
        if !known.contains(&key.as_str()) {
            findings.push(Finding::error("POL-002", format!("{path}.{key}"), "unknown field"));
        }
    }
}

fn decode_layer(value: &Value, findings: &mut Vec<Finding>) -> Option<Layer> {
    let path = "spec.layer";
    let map = map_at(value, path, findings)?;
    reject_unknown(map, &["scope", "programme", "instrument"], path, findings);
    let Some(scope) = map.get("scope") else {
        findings.push(Finding::error("POL-001", "spec.layer.scope", "missing"));
        return None;
    };
    let scope = text_at(scope, "spec.layer.scope", findings)?;
    let require = |key: &str, findings: &mut Vec<Finding>| -> Option<String> {
        let Some(v) = map.get(key) else {
            findings.push(Finding::error("POL-001", format!("{path}.{key}"), format!("a {scope} layer needs `{key}`")));
            return None;
        };
        text_at(v, &format!("{path}.{key}"), findings).map(str::to_owned)
    };
    let forbid = |key: &str, findings: &mut Vec<Finding>| {
        if map.contains_key(key) {
            findings.push(Finding::error("POL-001", format!("{path}.{key}"), format!("a {scope} layer takes no `{key}`")));
        }
    };
    match scope {
        "deployment" => {
            forbid("programme", findings);
            forbid("instrument", findings);
            Some(Layer::Deployment)
        }
        "programme" => {
            forbid("instrument", findings);
            let name = require("programme", findings)?;
            if !is_name(&name) {
                findings.push(Finding::error("POL-001", "spec.layer.programme", "must be lower-case and hyphenated"));
                return None;
            }
            Some(Layer::Programme(name))
        }
        "instrument" => {
            forbid("programme", findings);
            let reference = require("instrument", findings)?;
            if let Some(address) = parse_hex_address(&reference) {
                Some(Layer::Instrument(InstrumentRef::Address(address)))
            } else if is_name(&reference) {
                Some(Layer::Instrument(InstrumentRef::Name(reference)))
            } else {
                findings.push(Finding::error(
                    "POL-001",
                    "spec.layer.instrument",
                    "must be a lower-case hyphenated name or a 64-digit hexadecimal content address",
                ));
                None
            }
        }
        other => {
            findings.push(Finding::error(
                "POL-001",
                "spec.layer.scope",
                format!("`{other}` is not a scope; use deployment, programme or instrument"),
            ));
            None
        }
    }
}

fn decode_metadata(value: &Value, findings: &mut Vec<Finding>) -> Option<Metadata> {
    let map = map_at(value, "metadata", findings)?;
    reject_unknown(map, &["name", "version", "labels"], "metadata", findings);
    let mut ok = true;
    let mut name = String::new();
    match map.get("name") {
        None => {
            findings.push(Finding::error("POL-001", "metadata.name", "missing"));
            ok = false;
        }
        Some(v) => match text_at(v, "metadata.name", findings) {
            Some(t) if is_name(t) => name = t.to_owned(),
            Some(_) => {
                findings.push(Finding::error("POL-001", "metadata.name", "must be lower-case and hyphenated"));
                ok = false;
            }
            None => ok = false,
        },
    }
    let mut version = Version { major: 0, minor: 0, patch: 0 };
    match map.get("version") {
        None => {
            findings.push(Finding::error("POL-001", "metadata.version", "missing"));
            ok = false;
        }
        Some(v) => match text_at(v, "metadata.version", findings).map(Version::parse) {
            Some(Ok(parsed)) => version = parsed,
            Some(Err(e)) => {
                findings.push(Finding::error("POL-001", "metadata.version", e));
                ok = false;
            }
            None => ok = false,
        },
    }
    let mut labels = BTreeMap::new();
    if let Some(lm) = map.get("labels").and_then(|l| map_at(l, "metadata.labels", findings)) {
        for (k, v) in lm {
            match v.as_text() {
                Some(t) => {
                    labels.insert(k.clone(), t.to_owned());
                }
                None => findings.push(Finding::error("POL-001", format!("metadata.labels.{k}"), "labels are text")),
            }
        }
    }
    ok.then_some(Metadata { name, version, labels })
}

fn decode_leaf(
    control: &super::schema::ControlSpec,
    value: &Value,
    doc_path: &str,
    out: &mut BTreeMap<String, ControlValue>,
    findings: &mut Vec<Finding>,
) {
    match decode_value(control.kind, value) {
        Ok(v) => {
            out.insert(control.path.clone(), v);
        }
        Err(e) => findings.push(Finding::error("POL-002", doc_path, e)),
    }
}

fn walk(
    prefix: &str,
    value: &Value,
    doc_path: &str,
    out: &mut BTreeMap<String, ControlValue>,
    findings: &mut Vec<Finding>,
) {
    let Some(map) = map_at(value, doc_path, findings) else { return };
    for (key, v) in map {
        let path = format!("{prefix}.{key}");
        let doc_child = format!("{doc_path}.{key}");
        if let Some(control) = control_spec(&path) {
            decode_leaf(control, v, &doc_child, out, findings);
        } else if PER_KIND_GROUPS.contains(&path.as_str()) {
            let flat = match v {
                Value::Map(m) => m.contains_key("m") || m.contains_key("n"),
                _ => true,
            };
            if flat {
                // One value for every artefact kind: decode once, report once.
                let mut decoded = BTreeMap::new();
                if let Some(first) = control_spec(&format!("{path}.{}", ARTEFACT_KINDS[0])) {
                    decode_leaf(first, v, &doc_child, &mut decoded, findings);
                }
                if let Some(value) = decoded.into_values().next() {
                    for kind in ARTEFACT_KINDS {
                        out.insert(format!("{path}.{kind}"), value.clone());
                    }
                }
            } else {
                walk(&path, v, &doc_child, out, findings);
            }
        } else if is_group(&path) {
            walk(&path, v, &doc_child, out, findings);
        } else {
            findings.push(Finding::error("POL-002", doc_child, "unknown field"));
        }
    }
}

/// Decodes a policy document from its canonical value tree (POL-001, POL-002): checks the
/// resource envelope, the schema version, the layer, every control's type and value, and
/// rejects unknown fields; then checks the invariant floors on the controls the document
/// sets (POL-010). Every finding is collected.
pub fn decode_document(value: &Value) -> Decoded {
    let mut findings = Vec::new();
    let Some(root) = map_at(value, "$", &mut findings) else {
        return Decoded { document: None, findings };
    };
    reject_unknown(root, &["apiVersion", "kind", "metadata", "spec"], "$", &mut findings);
    let mut envelope_ok = true;
    match root.get("apiVersion").and_then(Value::as_text) {
        Some(API_VERSION) => {}
        _ => {
            findings.push(Finding::error("POL-001", "apiVersion", format!("must be `{API_VERSION}`")));
            envelope_ok = false;
        }
    }
    match root.get("kind").and_then(Value::as_text) {
        Some(KIND) => {}
        _ => {
            findings.push(Finding::error("POL-001", "kind", format!("must be `{KIND}`")));
            envelope_ok = false;
        }
    }
    let metadata = match root.get("metadata") {
        Some(m) => decode_metadata(m, &mut findings),
        None => {
            findings.push(Finding::error("POL-001", "metadata", "missing"));
            None
        }
    };
    let mut controls = BTreeMap::new();
    let mut schema_version = None;
    let mut layer = None;
    match root.get("spec") {
        None => findings.push(Finding::error("POL-001", "spec", "missing")),
        Some(spec) => {
            if let Some(spec_map) = map_at(spec, "spec", &mut findings) {
                let mut known = vec!["schemaVersion", "layer"];
                known.extend(SECTIONS);
                reject_unknown(spec_map, &known, "spec", &mut findings);
                match spec_map.get("schemaVersion") {
                    None => findings.push(Finding::error("POL-002", "spec.schemaVersion", "missing")),
                    Some(v) => match text_at(v, "spec.schemaVersion", &mut findings).map(Version::parse) {
                        Some(Ok(parsed)) if parsed.major == SCHEMA_VERSION_MAJOR => schema_version = Some(parsed),
                        Some(Ok(parsed)) => findings.push(Finding::error(
                            "POL-012",
                            "spec.schemaVersion",
                            format!("schema major version {} is not understood (this build reads {SCHEMA_VERSION_MAJOR}.x)", parsed.major),
                        )),
                        Some(Err(e)) => findings.push(Finding::error("POL-002", "spec.schemaVersion", e)),
                        None => {}
                    },
                }
                match spec_map.get("layer") {
                    None => findings.push(Finding::error("POL-001", "spec.layer", "missing")),
                    Some(v) => layer = decode_layer(v, &mut findings),
                }
                for section in SECTIONS {
                    if let Some(v) = spec_map.get(*section) {
                        walk(section, v, &format!("spec.{section}"), &mut controls, &mut findings);
                    }
                }
            }
        }
    }
    findings.extend(check_floors(&controls, "spec."));
    let document = match (envelope_ok, metadata, schema_version, layer) {
        (true, Some(metadata), Some(schema_version), Some(layer)) if !has_errors(&findings) => {
            Some(PolicyDocument { metadata, schema_version, layer, controls })
        }
        _ => None,
    };
    Decoded { document, findings }
}
