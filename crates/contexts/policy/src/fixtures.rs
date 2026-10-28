//! Policy documents built as [`Value`] trees, for tests of this crate and of the adapters that
//! implement its ports. A real deployment decodes YAML or JSON into the same trees.

use std::collections::BTreeMap;

use fieldseal_kernel::value::{Decimal, Value};

/// Text.
pub fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// An integer.
pub fn int(n: i128) -> Value {
    Value::Int(n)
}

/// A decimal written in plain notation, for example `"0.05"`.
pub fn dec(s: &str) -> Value {
    Value::Decimal(Decimal::parse(s).expect("fixture decimal"))
}

/// A list of text.
pub fn words(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| text(s)).collect())
}

/// A map.
pub fn map(entries: &[(&str, Value)]) -> Value {
    Value::Map(entries.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect())
}

/// Builds a policy document one control at a time.
///
/// ```
/// use fieldseal_policy::fixtures::{DocBuilder, int};
/// let doc = DocBuilder::deployment("baseline", "1.0.0")
///     .set("runtime.pin.minLength", int(8))
///     .build();
/// assert!(doc.as_map().is_some());
/// ```
#[derive(Clone, Debug)]
pub struct DocBuilder {
    name: String,
    version: String,
    layer: Value,
    spec: BTreeMap<String, Value>,
    extra_root: BTreeMap<String, Value>,
}

impl DocBuilder {
    fn new(name: &str, version: &str, layer: Value) -> Self {
        Self {
            name: name.to_owned(),
            version: version.to_owned(),
            layer,
            spec: BTreeMap::new(),
            extra_root: BTreeMap::new(),
        }
    }

    /// A deployment-layer document.
    pub fn deployment(name: &str, version: &str) -> Self {
        Self::new(name, version, map(&[("scope", text("deployment"))]))
    }

    /// A programme-layer document.
    pub fn programme(name: &str, version: &str, programme: &str) -> Self {
        Self::new(name, version, map(&[("scope", text("programme")), ("programme", text(programme))]))
    }

    /// An instrument-layer document, naming the instrument by name or content address.
    pub fn instrument(name: &str, version: &str, instrument: &str) -> Self {
        Self::new(name, version, map(&[("scope", text("instrument")), ("instrument", text(instrument))]))
    }

    /// Sets the control at the dotted `path` from `spec` (for example `runtime.pin.minLength`),
    /// creating the maps on the way. Nothing is checked: invalid paths and values are how the
    /// tests build invalid documents.
    pub fn set(mut self, path: &str, value: Value) -> Self {
        let mut parts: Vec<&str> = path.split('.').collect();
        let last = parts.pop().expect("path");
        let mut cursor = &mut self.spec;
        for part in parts {
            let entry = cursor
                .entry(part.to_owned())
                .or_insert_with(|| Value::Map(BTreeMap::new()));
            cursor = match entry {
                Value::Map(m) => m,
                _ => panic!("fixture path {path} crosses a non-map"),
            };
        }
        cursor.insert(last.to_owned(), value);
        self
    }

    /// Adds a field to the document root (for example an unknown one).
    pub fn root_field(mut self, key: &str, value: Value) -> Self {
        self.extra_root.insert(key.to_owned(), value);
        self
    }

    /// Replaces the layer.
    pub fn layer(mut self, layer: Value) -> Self {
        self.layer = layer;
        self
    }

    /// The document as a value tree.
    pub fn build(self) -> Value {
        let mut spec = self.spec;
        spec.insert("schemaVersion".to_owned(), text("1.0.0"));
        spec.insert("layer".to_owned(), self.layer);
        let mut root: BTreeMap<String, Value> = BTreeMap::from([
            ("apiVersion".to_owned(), text("fieldseal.dev/v1alpha1")),
            ("kind".to_owned(), text("Policy")),
            (
                "metadata".to_owned(),
                map(&[("name", Value::Text(self.name)), ("version", Value::Text(self.version))]),
            ),
            ("spec".to_owned(), Value::Map(spec)),
        ]);
        root.extend(self.extra_root);
        Value::Map(root)
    }
}

/// The deployment policy of the spec's example (POL §6.4), `authority-baseline` 3.1.0.
pub fn default_deployment_policy() -> Value {
    DocBuilder::deployment("authority-baseline", "3.1.0")
        .set("factory.registration.maxDevicesPerAccount", int(2))
        .set("factory.registration.tokenTtl", text("10m"))
        .set("factory.registration.airGappedTokenTtl", text("24h"))
        .set("factory.registration.requireFingerprintConfirmation", Value::Bool(true))
        .set("factory.registration.serialCheck", text("optional"))
        .set("factory.registration.requirePhishingResistantAuth", Value::Bool(true))
        .set("factory.registration.deviceNonceRegistrations", text("flag"))
        .set(
            "factory.registration.batchTokens",
            map(&[
                ("allowed", Value::Bool(true)),
                ("roles", words(&["device-preparation"])),
                ("maxUses", int(50)),
                ("ttl", text("4h")),
            ]),
        )
        .set(
            "factory.attestation.acceptedFormats",
            words(&["android-key-attestation", "apple-app-attest", "tpm2-quote"]),
        )
        .set("factory.attestation.minSecurityLevel", text("tee"))
        .set("factory.attestation.minOsPatchLevel", text("2026-06-01"))
        .set("factory.attestation.requireVerifiedBoot", Value::Bool(true))
        .set("factory.attestation.requireBootloaderLocked", Value::Bool(true))
        .set("factory.attestation.acceptedRuntimeVersions", text(">=1.0.0 <2.0.0"))
        .set("factory.cohorts", map(&[("maxActiveTenanciesPerCohort", int(1))]))
        .set("factory.posture", map(&[("recheckInterval", text("7d")), ("onFailure", text("pause-release"))]))
        .set(
            "runtime.pin",
            map(&[
                ("minLength", int(6)),
                ("failuresBeforeLockout", int(5)),
                ("lockoutSteps", words(&["30s", "1m", "5m", "15m", "1h"])),
            ]),
        )
        .set(
            "runtime.session",
            map(&[
                ("idleLock", text("2m")),
                ("lockOnBackground", Value::Bool(true)),
                ("lockOnScreenOff", Value::Bool(true)),
            ]),
        )
        .set(
            "runtime.export",
            map(&[
                ("parityDefault", text("on")),
                ("allowParityOff", Value::Bool(true)),
                ("destinations", words(&["upload", "local", "removable", "share", "cloud"])),
            ]),
        )
        .set("runtime.upload", map(&[("background", Value::Bool(true))]))
        .set(
            "runtime.retention",
            map(&[("offerClearOnReceipt", Value::Bool(true)), ("remindAfter", text("7d"))]),
        )
        .set("runtime.device", map(&[("kiosk", Value::Bool(false))]))
        .set("runtime.publishing", map(&[("maxTreeHeadAge", text("90d"))]))
        .set(
            "intake.consent",
            map(&[
                ("autoAcceptWithEvidence", Value::Bool(true)),
                ("sampleRate", dec("0.05")),
                ("withoutEvidence", text("review")),
                ("excludePendingFromAnalysis", Value::Bool(true)),
            ]),
        )
        .set("intake.time", map(&[("grace", text("30d")), ("provablyLate", text("flag"))]))
        .set("intake.ticks", map(&[("fastRunning", text("flag"))]))
        .set(
            "publishing",
            map(&[
                (
                    "requiredApprovals",
                    map(&[("Instrument", int(2)), ("Policy", int(2)), ("TrustBundle", int(2)), ("Deployment", int(2))]),
                ),
                ("authorMayApprove", Value::Bool(false)),
                ("publisherThreshold", map(&[("m", int(2)), ("n", int(3))])),
                ("allowedBuilders", words(&["https://ci.example.org/builders/fieldseal-publish"])),
                ("allowedSources", words(&["https://git.example.org/authority/artefacts"])),
                ("requireTransparencyLog", Value::Bool(true)),
            ]),
        )
        .build()
}

/// The spec's programme layer that only tightens one control (POL §6.4).
pub fn programme_a_policy() -> Value {
    DocBuilder::programme("programme-a", "1.0.0", "programme-a")
        .set("factory.registration", map(&[("maxDevicesPerAccount", int(1))]))
        .set("runtime.retention", map(&[("remindAfter", text("3d"))]))
        .build()
}

/// A document that sets nothing, so every control takes its schema default.
pub fn empty_deployment_policy() -> Value {
    DocBuilder::deployment("defaults-only", "1.0.0").build()
}

/// Validates and merges `documents` (outermost first) into an effective policy named by one
/// fixed content address per layer. Panics if a fixture is invalid.
pub fn effective(documents: &[Value]) -> crate::domain::EffectivePolicy {
    let decoded: Vec<crate::domain::PolicyDocument> = documents
        .iter()
        .map(|v| {
            let d = crate::domain::decode_document(v);
            d.document.unwrap_or_else(|| panic!("invalid fixture: {:?}", d.findings))
        })
        .collect();
    let refs: Vec<&crate::domain::PolicyDocument> = decoded.iter().collect();
    let (controls, findings) = crate::domain::merge_layers(&refs);
    assert!(!crate::domain::has_errors(&findings), "invalid fixture stack: {findings:?}");
    crate::domain::EffectivePolicy {
        sources: (0..documents.len())
            .map(|i| fieldseal_kernel::id::ContentAddress::from([9 + i as u8; 32]))
            .collect(),
        controls,
    }
}

/// The effective policy of the default deployment policy alone.
pub fn effective_default() -> crate::domain::EffectivePolicy {
    effective(&[default_deployment_policy()])
}

/// Input facts from name and value pairs.
pub fn facts(entries: &[(&str, Value)]) -> crate::domain::Facts {
    entries.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect()
}
