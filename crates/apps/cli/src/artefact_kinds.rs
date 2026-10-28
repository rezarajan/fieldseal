//! Kind-specific validation of artefacts (PUB-003, CLI-300): one table from artefact kind to the
//! validator of its context. `artefact provenance` and the publication verifier both go through
//! [`validate_kind`], so a kind has no path that checks only the envelope. Adding a kind is one
//! line in [`KINDS`] (plus its validator function).

use std::collections::BTreeMap;
use std::path::Path;

use fieldseal_deployment::application::{DeploymentTools, ValidateManifest};
use fieldseal_instrument::application::{LayoutBinding, LayoutOptions, ValidationOptions, validate_instrument_with, validate_layout_with};
use fieldseal_instrument::domain::{Instrument, InstrumentReference, Severity};
use fieldseal_kernel::Value;
use fieldseal_kernel::cbor;
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::Salt;
use fieldseal_policy::application::{PolicyValidator, ValidatePolicy};
use fieldseal_publishing::domain::{ArtefactKind, Diagnostic};
use fieldseal_trust::domain::TrustBundle;

/// A validated instrument with its canonical bytes: what a layout is validated against.
pub(crate) struct LoadedInstrument {
    /// The instrument.
    pub(crate) instrument: Instrument,
    /// Its canonical bytes (the identity a layout binds to is computed from them).
    pub(crate) canonical: Vec<u8>,
}

/// What a validator may need besides the document.
pub(crate) struct KindCx<'a> {
    /// The instrument a layout is validated against (`--instrument`).
    pub(crate) instrument: Option<&'a LoadedInstrument>,
    /// The salt the layout's instrument identity uses (INS-200), if any.
    pub(crate) salt: Option<Salt>,
    /// The directory of the artefact file, against which a layout's `spec.instrument` source
    /// path resolves.
    pub(crate) dir: &'a Path,
}

/// A kind validator: the document to publish (its canonical form) or the blocking diagnostics.
pub(crate) type KindCheck = fn(&KindCx<'_>, &Value) -> Result<Value, Vec<Diagnostic>>;

/// The kind -> validator table. A new kind is one line here.
pub(crate) const KINDS: &[(ArtefactKind, KindCheck)] = &[
    (ArtefactKind::Instrument, check_instrument),
    (ArtefactKind::Layout, check_layout),
    (ArtefactKind::Localisation, check_localisation),
    (ArtefactKind::Policy, check_policy),
    (ArtefactKind::TrustBundle, check_trust_bundle),
    (ArtefactKind::Deployment, check_deployment),
];

/// The metadata key that carries an artefact's version: a deployment manifest names it
/// `schemaVersion` (DEP-001), every other kind `version`.
pub(crate) fn version_key(kind: &str) -> &'static str {
    if kind == "Deployment" { "schemaVersion" } else { "version" }
}

/// Validates `doc` with the validator the table names for `kind`; a kind with none is refused.
pub(crate) fn validate_kind(kind: ArtefactKind, cx: &KindCx<'_>, doc: &Value) -> Result<Value, Vec<Diagnostic>> {
    match KINDS.iter().find(|(k, _)| *k == kind) {
        Some((_, check)) => check(cx, doc),
        None => Err(vec![diag("PUB-003", format!("no validator is registered for the artefact kind {kind}"))]),
    }
}

fn diag(code: &str, message: String) -> Diagnostic {
    Diagnostic { code: code.to_owned(), blocking: true, message }
}

/// The envelope every artefact source has (PUB-001): exactly `apiVersion`, `kind`, `metadata`
/// and `spec`, with `apiVersion: fieldseal.dev/v1alpha1` and `metadata.name` and the kind's
/// version key as text. The body (`spec`) is checked by the kind's own validator.
pub(crate) fn check_envelope(m: &BTreeMap<String, Value>) -> Result<(), String> {
    if let Some(k) = m.keys().find(|k| !matches!(k.as_str(), "apiVersion" | "kind" | "metadata" | "spec")) {
        return Err(format!("unknown field {k}"));
    }
    if m.get("apiVersion").and_then(Value::as_text) != Some("fieldseal.dev/v1alpha1") {
        return Err("apiVersion (expected fieldseal.dev/v1alpha1)".into());
    }
    if !m.contains_key("spec") {
        return Err("spec".into());
    }
    let meta = m.get("metadata").and_then(Value::as_map).ok_or("metadata")?;
    let kind = m.get("kind").and_then(Value::as_text).unwrap_or_default();
    for key in ["name", version_key(kind)] {
        if meta.get(key).and_then(Value::as_text).is_none() {
            return Err(format!("metadata.{key}"));
        }
    }
    Ok(())
}

fn findings_of(findings: &fieldseal_instrument::domain::Findings) -> Vec<Diagnostic> {
    findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .map(|f| diag(f.requirement, format!("{}: {}", f.path, f.message)))
        .collect()
}

fn check_instrument(_: &KindCx<'_>, doc: &Value) -> Result<Value, Vec<Diagnostic>> {
    let digest = |b: &[u8]| *sha256(b).as_bytes();
    match validate_instrument_with(doc, ValidationOptions { media_digest: Some(&digest) }) {
        Ok(v) => Ok(v.instrument.to_value()),
        Err(findings) => Err(findings_of(&findings)),
    }
}

/// A layout is validated against its instrument (INS-200 to INS-215), including the binding of
/// `spec.instrument` to it.
fn check_layout(cx: &KindCx<'_>, doc: &Value) -> Result<Value, Vec<Diagnostic>> {
    let Some(ins) = cx.instrument else {
        return Err(vec![diag("INS-200", "a layout is validated against its instrument; none was given".to_owned())]);
    };
    let identity = |canonical: &[u8]| crate::commands::identity(canonical, cx.salt.as_ref());
    let resolve = |r: &InstrumentReference| {
        let InstrumentReference::Source(source) = r else { return None };
        let file = cx.dir.join(source);
        let value = fieldseal_adapters_authoring::decode_path(&file).ok()?;
        Some(identity(&cbor::encode(&value).ok()?))
    };
    let binding = LayoutBinding { expected: identity(&ins.canonical), resolve: &resolve };
    match validate_layout_with(doc, &ins.instrument, LayoutOptions { binding: Some(binding) }) {
        Ok(layout) => Ok(layout.to_value()),
        Err(findings) => Err(findings_of(&findings)),
    }
}

/// A localisation catalogue has a closed schema (PLAT-053, PLAT-050).
fn check_localisation(_: &KindCx<'_>, doc: &Value) -> Result<Value, Vec<Diagnostic>> {
    match crate::i18n_cmd::read_catalogue(doc) {
        Ok(_) => Ok(doc.clone()),
        Err(issues) => Err(issues.into_iter().map(|(id, at, why)| diag(id, format!("{at}: {why}"))).collect()),
    }
}

fn check_policy(_: &KindCx<'_>, doc: &Value) -> Result<Value, Vec<Diagnostic>> {
    let errors: Vec<Diagnostic> = PolicyValidator
        .validate(doc)
        .findings
        .iter()
        .filter(|f| f.severity == fieldseal_policy::domain::Severity::Error)
        .map(|f| diag(f.requirement, format!("{}: {}", f.path, f.message)))
        .collect();
    if errors.is_empty() { Ok(doc.clone()) } else { Err(errors) }
}

/// A trust bundle artefact is the envelope around the bundle's canonical map (TRU-030): `spec`
/// decodes as a signed trust bundle, and `metadata` agrees with it.
fn check_trust_bundle(_: &KindCx<'_>, doc: &Value) -> Result<Value, Vec<Diagnostic>> {
    let bad = |at: &str, why: &str| vec![diag("TRU-030", format!("{at}: {why}"))];
    let Some(top) = doc.as_map() else { return Err(bad("", "a trust bundle artefact is a map")) };
    if let Err(why) = check_envelope(top) {
        return Err(bad("", &why));
    }
    if top.get("kind").and_then(Value::as_text) != Some("TrustBundle") {
        return Err(bad("kind", "must be `TrustBundle`"));
    }
    let meta = top.get("metadata").and_then(Value::as_map).ok_or_else(|| bad("metadata", "required map"))?;
    if let Some(k) = meta.keys().find(|k| !["name", "version", "labels"].contains(&k.as_str())) {
        return Err(bad(&format!("metadata.{k}"), "unknown field; expected name, version, labels"));
    }
    if let Some(l) = meta.get("labels")
        && !l.as_map().is_some_and(|m| m.values().all(|v| v.as_text().is_some()))
    {
        return Err(bad("metadata.labels", "labels are a map of text"));
    }
    let spec = top.get("spec").cloned().ok_or_else(|| bad("spec", "required"))?;
    let bundle = TrustBundle::from_value(spec).map_err(|e| vec![diag(e.code().map_or("TRU-030", |c| c.as_str()), format!("spec: {e}"))])?;
    if meta.get("name").and_then(Value::as_text) != Some(bundle.name()) {
        return Err(bad("metadata.name", "must equal spec.name"));
    }
    if meta.get("version").and_then(Value::as_text) != Some(bundle.version().to_string().as_str()) {
        return Err(bad("metadata.version", "must equal spec.version"));
    }
    Ok(doc.clone())
}

fn check_deployment(_: &KindCx<'_>, doc: &Value) -> Result<Value, Vec<Diagnostic>> {
    let errors: Vec<Diagnostic> = DeploymentTools.validate(doc).iter().map(|f| diag(f.requirement(), format!("{}: {}", f.kind(), f.message()))).collect();
    if errors.is_empty() { Ok(doc.clone()) } else { Err(errors) }
}
