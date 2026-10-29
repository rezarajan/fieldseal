# fieldseal-deployment

## Overview
The Deployment bounded context: the `kind: Deployment` manifest model and the pure tooling around it. It validates a manifest, renders per-component environments and device provisioning configuration, creates immutable releases from signed builds, checks authority key-custody bindings, and generates a release's documentation bundle. Spec: [deployment.md](../../../docs/reference/spec/deployment.md); layering per ADR 0028. The crate is pure: reading YAML or CBOR is an adapter's job; use cases take the decoded canonical `Value`. All modules are single files (no sub-READMEs).

## Interface
`lib.rs` exposes `application`, `contract`, `custody`, `docs`, `domain`, `manifest`, `release`, `render`, `validate`, `ports`.
- `application`: traits `ValidateManifest::validate`, `RenderEnvironment::render`, `BuildDocumentation::build`, all implemented by the unit struct `DeploymentTools`; `ManifestFinding` (`SchemaError`, `UnknownAdapter`, `InlineSecret`, `PolicyFloorViolation`; `requirement`, `kind`, `message`); aliases `ComponentEnvironment`, `EnvironmentSet`.
- `events`: `development_adapters_event(service, adapters)`, the one `development-adapters` start-up event that the services print (DEP-051).
- `domain`: `Component` (`Factory`, `Intake`, `Publishing`, `Runtime`, `Cli`; `name`, `parse`), `SecretRef`, `SecretValue` (`new`, `expose`; redacted `Debug`), `StoredBuild`, `DocumentationBundle`, `EnvironmentName`.
- `manifest`: `Manifest`, `decode_manifest` (unknown fields rejected, DEP-001), `Manifest::resolve(environment)`, `ComponentSpec`, `AdapterBinding`, `EnvironmentSpec`, `PlatformSpec`, `ProvisioningSpec`, `ArtefactRef`, `ConfigValue`, `ManagementMode`, `API_VERSION` (`fieldseal.dev/v1alpha1`).
- `validate`: `validate_manifest`, `check_manifest`, `check_environment`, `check_policy_layers`, `is_deployment_layer`, `ports`, `key_names_secret`, `looks_like_secret`, `DEVELOPMENT_ADAPTERS`.
- `render`: `render_environment` (-> `Rendered`), `provisioning_configuration`, `env_file`, `snake_upper`.
- `release`: `create_release` (-> `Release`), `ReleaseError` (`UnpublishedManifest`, `UnsignedBuild`, `MissingBuild`, `DuplicateBuild`), `release_value`, `build_signing_message`.
- `custody`: `Tier` (`Development`, `Staging`, `Production`), `tier_of`, `CustodyBinding`, `KEY_CUSTODY_ADAPTERS`, `bindings`, `check_custody`, `env_name`, `startup_check`.
- `docs`: `build_documentation`, `scan_bundle`, `DocsInput`, `InstrumentDoc`, `ItemDoc`, `CheckDoc`, `PolicyRow`, `TrustRow`.
- `ports` (driven): `BuildRegistry` (`store`, `fetch`), `SecretStore` (`resolve`), `DocumentationSink` (`store`, `fetch`), each with an error enum. Also uses Publishing's `ArtefactRegistry`.
- `contract`: `build_registry_contract`, `secret_store_contract`, `documentation_sink_contract`.

## Invariants
- A manifest holds secret references, never values; inline secrets are findings. Rendering emits references only and is a pure function of the manifest and environment name.
- A release is immutable and content-addressed (DEP-011): it needs a published manifest (DEP-005), exactly one signed, verifying build per component and one for every required component (DEP-010).
- `BuildRegistry`: a digest always returns the same build. `SecretStore` resolves references only, offers no listing, and deployment tooling never calls it. `DocumentationSink` is addressed by release and immutable once stored.
- Custody (DEP-073 to DEP-075, TRU-112): validation refuses a binding below the policy minimum, a `development` binding in a `production` environment (INV-15), a software adapter claiming hardware assurance, and a `cold` binding that is not offline. An environment that declares no tier and is not named for one is treated as `production` (fail closed). `startup_check` skips purposes a service declares nothing for.
- Documentation bundles are scanned for secret values and personal data (DEP-030 to DEP-033); the caller supplies resolved artefact summaries.

## Side Effects
None in this crate. Adapters of `BuildRegistry`, `SecretStore` and `DocumentationSink` perform storage and secret resolution; `startup_check` reads the environment only through the `lookup` closure it is given.

## Verification
- Run: `cargo test -p fieldseal-deployment` (repo-wide: `just test`)

The Intake component binds `RecordKeyUnsealer`, `SubmissionStore`, `DataPlatform`, `PolicyEngine`, `TenancyRegistry`, `IdentityProvider` (`oidc`, `memory-dev`), `RosterHistory` and `InstrumentSource` (`file-dev`); its `ComponentSpec` also carries `publicUrl`, `maxBodyBytes`, `portal.{bind,publicUrl}` and `dirs.{published,issued,landing,rosterHistory,exportKey}`, decoded strictly.
