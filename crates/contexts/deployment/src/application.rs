//! Use cases offered by the Deployment context (DEP §3).
//!
//! The driving ports take the decoded canonical [`Value`] of the manifest: reading YAML or
//! CBOR is an adapter's job (ADR 0028).

use std::collections::BTreeMap;

use fieldseal_kernel::Value;

use crate::docs::{DocsInput, build_documentation};
use crate::domain::{Component, DocumentationBundle, EnvironmentName};
use crate::manifest::decode_manifest;
use crate::render::{Rendered, render_environment};
use crate::validate::validate_manifest;

/// A finding from validating a deployment manifest. Each carries `path: message`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ManifestFinding {
    /// The manifest doesn't match the schema.
    SchemaError(String),
    /// An adapter isn't known for its port.
    UnknownAdapter(String),
    /// A secret value appears inline instead of by reference.
    InlineSecret(String),
    /// A policy layer or environment goes below an invariant floor.
    PolicyFloorViolation(String),
}

impl ManifestFinding {
    /// The requirement the finding enforces.
    pub fn requirement(&self) -> &'static str {
        match self {
            Self::SchemaError(_) => "DEP-001",
            Self::UnknownAdapter(_) => "DEP-002",
            Self::InlineSecret(_) => "DEP-004",
            Self::PolicyFloorViolation(_) => "DEP-023",
        }
    }

    /// The error class, as DEP §3 names it.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::SchemaError(_) => "SchemaError",
            Self::UnknownAdapter(_) => "UnknownAdapter",
            Self::InlineSecret(_) => "InlineSecret",
            Self::PolicyFloorViolation(_) => "PolicyFloorViolation",
        }
    }

    /// The `path: message` text.
    pub fn message(&self) -> &str {
        match self {
            Self::SchemaError(m) | Self::UnknownAdapter(m) | Self::InlineSecret(m) | Self::PolicyFloorViolation(m) => m,
        }
    }
}

/// `ValidateManifest`.
pub trait ValidateManifest {
    /// Findings for the manifest's value; empty means valid.
    fn validate(&self, manifest: &Value) -> Vec<ManifestFinding>;
}

/// `RenderEnvironment`: per-component environment variables for one environment.
pub trait RenderEnvironment {
    /// Environment variables per component and the provisioning configuration, or the
    /// missing references.
    fn render(&self, manifest: &Value, environment: &EnvironmentName) -> Result<Rendered, Vec<String>>;
}

/// `BuildDocumentation`: generates a release's documentation bundle.
pub trait BuildDocumentation {
    /// The documentation for the release described by `input`.
    fn build(&self, input: &DocsInput<'_>) -> Result<DocumentationBundle, String>;
}

/// The Deployment use cases, implemented by the domain functions.
#[derive(Clone, Copy, Default, Debug)]
pub struct DeploymentTools;

impl ValidateManifest for DeploymentTools {
    fn validate(&self, manifest: &Value) -> Vec<ManifestFinding> {
        validate_manifest(manifest)
    }
}

impl RenderEnvironment for DeploymentTools {
    fn render(&self, manifest: &Value, environment: &EnvironmentName) -> Result<Rendered, Vec<String>> {
        let m = decode_manifest(manifest).map_err(|f| f.iter().map(|x| x.message().to_owned()).collect::<Vec<_>>())?;
        render_environment(&m, environment)
    }
}

impl BuildDocumentation for DeploymentTools {
    fn build(&self, input: &DocsInput<'_>) -> Result<DocumentationBundle, String> {
        build_documentation(input)
    }
}

/// Environment variables of one component.
pub type ComponentEnvironment = BTreeMap<String, String>;

/// Environment variables per component.
pub type EnvironmentSet = BTreeMap<Component, ComponentEnvironment>;
