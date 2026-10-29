# Deployment

**Prefix:** `DEP` · **Context:** Deployment · **Runs in:** operations · **Status:** Draft

## 1. Scope

Deployment describes how one authority runs Fieldseal: which adapters and attached resources it uses, which trust bundles, policies and artefact registries apply, how a release is built and run, how devices are provisioned, and how the deployment's documentation is generated and shipped with each release. It applies the twelve-factor methodology to every component ([ADR 0025](../../explanation/adr/0025-twelve-factor-deployments.md)).

It does not own the services' behaviour (their own specs), the policies' content (POL), or the publishing flow (PUB), which deployment manifests go through like any artefact.

## 2. Domain model

| Element | Kind | Description |
|---|---|---|
| `Deployment` | Aggregate | One authority's running Fieldseal, described by a deployment manifest. |
| `DeploymentManifest` | Value object (artefact) | The declarative description (`kind: Deployment`), published with provenance. |
| `Environment` | Entity | A named instance of a deployment (for example `development`, `staging`, `production`), differing only in attached-resource references and policy layers. It also has a `tier` (DEP-073). |
| `AdapterBinding` | Value object | A port, the adapter chosen for it, and its configuration references. |
| `AttachedResource` | Value object | A backing service by reference (URL, resource name, secret reference); never an inline secret. |
| `Build` | Value object | An immutable, signed component artefact: container image, app package, CLI binary. |
| `Release` | Aggregate | One build per component, plus one manifest, plus the documentation generated from them; immutable, content-addressed. |
| `ProvisioningConfiguration` | Value object | What a device receives at provisioning: trust bundle, factory URL, initial runtime policy, platform settings. |
| `DocumentationBundle` | Value object | The generated documentation for a release. |

**Invariants**

- A release is immutable; changing anything makes a new release.
- No secret value appears in a manifest, a release or its documentation.
- Environments of one deployment differ only in references and policy layers, never in code or adapters' code.

**Domain events:** `ManifestPublished`, `ReleaseCreated`, `ReleaseDeployed`, `ReleaseRolledBack`, `DocumentationBuilt`.

## 3. Driving ports

| Port | Input | Output | Errors |
|---|---|---|---|
| `ValidateManifest` | manifest | findings | `SchemaError`, `UnknownAdapter`, `InlineSecret`, `PolicyFloorViolation` |
| `RenderEnvironment` | manifest, environment name | per-component environment variables and provisioning configuration | `MissingReference` |
| `CreateRelease` | builds, published manifest | `Release` | `UnpublishedManifest`, `UnsignedBuild` |
| `BuildDocumentation` | release | `DocumentationBundle` | `UnresolvableArtefact` |

## 4. Driven ports

| Port | Contract |
|---|---|
| `ArtefactRegistry` | Resolves trust bundles, policies, instruments and manifests by content address, with publishing evidence (PUB). |
| `BuildRegistry` | Stores and serves signed builds (container registry, app distribution, binary store); returns their digests. |
| `SecretStore` | Resolves secret references at run time inside the component. Deployment tooling MUST NOT read secret values. |
| `DocumentationSink` | Stores a documentation bundle next to its release, addressed by the release's content address. |

## 5. Requirements

### Manifest

- **DEP-001** Every deployment MUST be described by exactly one deployment manifest per environment set, of `kind: Deployment` and `apiVersion: fieldseal.dev/v1alpha1`.
- **DEP-002** The manifest MUST declare, for every driven port of every component it runs, the adapter used and its configuration references.
- **DEP-003** The manifest MUST reference trust bundles, policies and artefact registries by content address or by registry plus channel; it MUST NOT inline their content.
- **DEP-004** The manifest MUST reference secrets through a secret-store reference (`secretRef`); a manifest containing a value that looks like a key, password or token MUST fail validation.
- **DEP-005** The manifest MUST be published through the publishing flow (PUB) before a release can use it.
- **DEP-006** Environments MUST be declared in the manifest, and MAY override only attached-resource references, scaling settings and policy layers.
- **DEP-007** Every reader of a deployment manifest MUST reject unknown fields, enforce exact types, require every required field, and enforce every declared constraint: a reference pins a `digest` or follows a `channel` but not both; a digest is `sha256:` and 64 lowercase hexadecimal digits; a named registry is one the manifest declares; a reference is listed once per list; at least one policy layer, platform and environment is declared; scaling values are non-negative integers. The adapter `config`, the platform settings and the `scaling` keys are the only open key sets, because they are adapter- and platform-specific; their values are still restricted to text, integers, booleans and `secretRef` maps.

### Build, release, run

- **DEP-010** Every component build MUST be reproducible from its source revision, signed, and carry build provenance (PUB).
- **DEP-011** A release MUST be the tuple (component builds, published manifest) and MUST be content-addressed.
- **DEP-012** Running a release MUST NOT change it. Configuration MUST come only from the environment rendered from the manifest, and secrets only from the secret store at run time.
- **DEP-013** Rolling back MUST mean deploying an earlier release, unchanged.
- **DEP-014** The runtime build MUST be the same for every deployment and every environment; only its provisioning configuration and the bundles it receives may differ.

### Runtime provisioning

- **DEP-020** A device's provisioning configuration MUST contain: the trust bundle (or its content address and a pinned digest), factory and destination address hints (untrusted; [ADR 0021](../../explanation/adr/0021-export-upload-receipts.md)), the initial runtime policy, and platform settings for the platform profile.
- **DEP-021** Provisioning configuration MUST be delivered through the platform's managed-configuration mechanism (PLAT §DevicePolicy), not compiled into the build.
- **DEP-022** A runtime without a valid provisioning configuration MUST run only the built-in practice instrument and MUST NOT register.
- **DEP-023** Development provisioning configuration MAY trust development roots; production runtime policy MUST refuse unattested keys (REG).
- **DEP-024** The deployment manifest MUST declare the device-management mode per platform (`self-managed` or `emm-managed`, [ADR 0031](../../explanation/adr/0031-device-management-adapters.md)), and it MUST be carried in provisioning configuration.

### Documentation

- **DEP-030** Every release MUST have a documentation bundle generated by `fieldseal docs build` from the release's manifest and the published artefacts it references.
- **DEP-031** The documentation bundle MUST contain:
  - an adapter inventory (port, adapter, version, attached-resource name);
  - a policy table for every policy layer, showing each control's effective value and its layer;
  - a codebook and data dictionary for every instrument (items, controls, allowed values, units, rules, field checks, consent requirements), with content addresses;
  - trust fingerprints (roots, online keys and their validity, publisher keys);
  - the provisioning configuration with secrets shown only as references;
  - runbooks for registration exceptions, forced close, deny-listing, rollback and key rotation, with commands filled in for this deployment.
- **DEP-032** The documentation bundle MUST be addressed by the release's content address and stored with it; documentation for a different release MUST NOT be served as this release's.
- **DEP-033** The documentation bundle MUST NOT contain personal data or secret values.

### Twelve-factor compliance

- **DEP-040** Every service (factory, portal, intake, publishing pipeline) MUST meet all twelve factors as tabled in §7.
- **DEP-041** The runtime and CLI MUST meet each factor marked applicable in §7, and each component's spec MUST state how.
- **DEP-042** A component MUST NOT read configuration from a location not named in §7 for that component.
- **DEP-057** The development adapter `file-dev` is a Deployment adapter for the `Signer` and `RecordKeyUnsealer` ports (keys in a key directory, with `dir` and `trustBundle`) and for the `TenancyRegistry` port (state in a directory, with `dir`: the factory writes it, and the intake endpoint reads it read-only to resolve the factory's tenancies). The file stores for submissions (`SubmissionStore`), roster history (`RosterHistory`) and published instruments (`InstrumentSource`) are bound under the same name `file-dev`, and `memory-dev` stands for the identity provider and keys in memory. `landing-files` is not a development adapter. Each is a development adapter like `memory` and `software`: `fieldseal deployment validate` MUST refuse it in an environment named `production` (DEP-023). `fieldseal deployment render` writes `FIELDSEAL_CUSTODY=file-dev`, `FIELDSEAL_CUSTODY_DIR`, `FIELDSEAL_TRUST_BUNDLE` and `FIELDSEAL_STATE_DIR` for the factory, from its `ArtefactRegistry`, `RosterSource` and `BundleStore` ports `FIELDSEAL_FACTORY_REGISTRY_DIR`, `FIELDSEAL_ROSTER_DIR`, `FIELDSEAL_BUNDLE_DIR` and `FIELDSEAL_ISSUED_ROSTERS_DIR` (the `dir` and `issuedRostersDir` keys), and, when set, `FIELDSEAL_FACTORY_MAX_ANCHOR_AGE_S` (the `maxAnchorAgeS` key of `BundleStore`) and `FIELDSEAL_FACTORY_BUILD_INTERVAL_S` (the `scanIntervalS` key of `ArtefactRegistry`), which the factory defaults when they are absent. The `RuntimeProfiles` port (`file-dev`) names the same factory state directory as `TenancyRegistry` and has no variable of its own. The factory's file-backed `ArtefactRegistry`, `RosterSource`, `BundleStore` and `RuntimeProfiles` are development adapters too. For intake, the render writes `FIELDSEAL_INTAKE_BIND`, `FIELDSEAL_INTAKE_PUBLIC_URLS`, `FIELDSEAL_INTAKE_MAX_BODY`, `FIELDSEAL_INTAKE_PORTAL_BIND`, `FIELDSEAL_INTAKE_PORTAL_URL`, the identity variables, `FIELDSEAL_CUSTODY`, `FIELDSEAL_CUSTODY_DIR`, `FIELDSEAL_TRUST_BUNDLE`, `FIELDSEAL_TENANCY_DIR`, `FIELDSEAL_LANDING_DIR`, `FIELDSEAL_INTAKE_SUBMISSIONS_DIR`, `FIELDSEAL_INTAKE_PUBLISHED_DIR`, `FIELDSEAL_INTAKE_ROSTERS_DIR`, `FIELDSEAL_EXPORT_KEY_DIR`, `FIELDSEAL_INTAKE_ALLOWED_BUILDERS` and `FIELDSEAL_INTAKE_ALLOWED_SOURCES` (`FIELDSEAL_INTAKE_ROSTERS_DIR` is the directory in which the factory records the rosters it issues, `FIELDSEAL_ISSUED_ROSTERS_DIR`). There is no `FIELDSEAL_UPLOAD_AUTHORITY`. The listed publishing allow-lists are comma-separated text in the `PolicyEngine` configuration (`allowedBuilders`, `allowedSources`). For the factory the same keys render `FIELDSEAL_FACTORY_ALLOWED_BUILDERS` and `FIELDSEAL_FACTORY_ALLOWED_SOURCES` (the publishing policy its release policy is verified under in development), and `policyDigest` renders `FIELDSEAL_FACTORY_POLICY_DIGEST`, the content address of the release policy it trusts; `fieldseal deployment validate` MUST refuse a manifest whose factory has no `policyDigest` in `staging` or `production`. Because the example manifest binds `file-dev` stores for intake, `fieldseal deployment validate` refuses it in `production` until production adapters exist.
- **DEP-043** The whole stack MUST be runnable locally from one development manifest as a compose stack with a local identity provider, every service configured only by its rendered environment and every secret supplied by reference at run time ([run the local stack](../../how-to/run-the-local-stack.md), `examples/deployments/local-stack.yaml`). The `translog` adapter of the `TransparencyLog` port is the self-hosted log server, configured by `dir`, `origin` and `keyFile`. The stack has one authority, created once by an `init` service (the root ceremony, the purpose keys, the log's key and the trust bundle that pins the log), which the factory, the upload endpoint and the CLI all use (DEP-057); a restart keeps what was registered (REG-083).

### Strict documents and extensions ([ADR 0037](../../explanation/adr/0037-extensions-and-strict-schema-enforcement.md))

- **DEP-071** `ValidateManifest` MUST validate the manifest, every policy layer and every other document the deployment tooling reads against its closed schema (WIRE-208–WIRE-211), with no lenient mode.
- **DEP-072** The documentation bundle (DEP-031) MUST name, for each instrument, the standard catalogue and every extension it uses (name, version, content address), and list the extension units, code lists and concept schemes in the data dictionary.

### Authority key custody ([ADR 0038](../../explanation/adr/0038-authority-key-custody-classes.md))

- **DEP-073** Every environment MUST declare a `tier` of `development`, `staging` or `production`. Only a `production` tier MUST refuse the `development` assurance (INV-15). A `development` root MUST be listed only in the trust bundles of environments of tier `development`.
- **DEP-074** The manifest MUST bind, for each authority purpose in each environment, a `KeyCustody` adapter with a declared `assurance` (`development`, `custody-bound` or `attested`) and `mode` (`cold` or `hot`), and for `cold` also `offline: true`. `ValidateManifest` MUST fail with `PolicyFloorViolation`, naming the purpose, the declared assurance and mode, the effective minimums and the policy layer, when either is below the minimum (POL-065), when a `development` binding is in a `production` environment, or when a `cold` binding is not offline. `RenderEnvironment` MUST pass the declared assurance and mode to the service, and a service MUST refuse to start if either is below its effective policy's minimum.
- **DEP-075** The documentation bundle MUST list, for every key in each trust bundle, its purpose, mode, assurance and the digest of its evidence, taken from the issuance records (TRU-117); the release pipeline MUST run `fieldseal trust verify --audit` and fail the release on a finding.

### Observability

- **DEP-050** Every component MUST emit structured events (one JSON object per line, with timestamp, component, release, event name, severity and fields).
- **DEP-051** Events MUST NOT contain personal data: no names, subject IDs, item values, roster contents, evidence, or free text entered by a collector.
- **DEP-052** Services MUST write events to stdout. The runtime MUST write them to a bounded, sealed local diagnostic stream, uploaded with telemetry when online. The CLI MUST write them to stderr.
- **DEP-053** Each service MUST expose health and readiness through its bound port, without authentication details or personal data.
- **DEP-058** A service MAY bind a gRPC listener on a port separate from its HTTP port, enabled and configured by environment (`FIELDSEAL_<SERVICE>_GRPC_PORT`; TLS either terminated in front or by the service from a referenced certificate and key), never by code. Compose files for development expose both ports ([ADR 0035](../../explanation/adr/0035-service-contracts-and-transports.md); built in slice 2).
- **DEP-059** Each gRPC listener MUST implement `grpc.health.v1.Health` with the meaning of the HTTP health and readiness endpoints (DEP-053), which stay.
- **DEP-060** The gRPC reflection service MUST be enabled only when the deployment environment is development, and MUST be off by default and in production.

## 6. Resources and formats

```yaml
apiVersion: fieldseal.dev/v1alpha1
kind: Deployment
metadata:
  name: example-authority
  schemaVersion: 1.0.0
spec:
  authority:
    displayName: Example Authority
    trustBundle: { registry: artefacts, ref: trust/authority-root, digest: "sha256:…" }
  registries:
    artefacts: { url: https://artefacts.example.org, transparencyLog: https://log.example.org }
    builds: { container: registry.example.org/fieldseal, runtime: https://apps.example.org }
  policies:
    layers:
      - { ref: policy/deployment-default, digest: "sha256:…" }
      - { ref: policy/programme-2026, digest: "sha256:…" }
  instruments:
    - { ref: instrument/household-water-access, channel: stable }
  components:
    factory:
      adapters:
        IdentityProvider: { adapter: oidc, config: { issuer: https://login.example.org/tenant/v2.0, clientId: { secretRef: factory-oidc-client-id }, clientSecret: { secretRef: factory-oidc-client-secret } } }
        Signer: { adapter: pkcs11-hsm, config: { slot: factory-signing, pin: { secretRef: hsm-pin } } }
        AttestationVerifier: { adapter: android-key-attestation, config: { rootsRef: trust/google-attestation-roots } }
        PolicyEngine: { adapter: opa, config: { bundleRef: policy/factory } }
        TenancyRegistry: { adapter: postgres, config: { url: { secretRef: factory-db-url } } }
        ArtefactRegistry: { adapter: file-dev, config: { dir: /registry } }
        RosterSource: { adapter: file-dev, config: { dir: /rosters } }
        BundleStore: { adapter: file-dev, config: { dir: /bundles, issuedRostersDir: /issued } }
        RuntimeProfiles: { adapter: file-dev, config: { dir: /state/factory } }
      scaling: { replicas: 2 }
    intake:
      adapters:
        RecordKeyUnsealer: { adapter: pkcs11-hsm, config: { slot: record-keys, pin: { secretRef: hsm-pin } } }
        SubmissionStore: { adapter: s3, config: { bucket: intake-submissions, credentials: { secretRef: intake-s3 } } }
        DataPlatform: { adapter: lakehouse-delta, config: { volume: /Volumes/fieldseal/landing, credentials: { secretRef: lakehouse-sp } } }
        PolicyEngine: { adapter: opa, config: { bundleRef: policy/intake } }
        IdentityProvider: { adapter: oidc, config: { issuer: https://login.example.org, clientId: fieldseal-intake, clientSecret: { secretRef: intake-oidc-client-secret } } }
        RosterHistory: { adapter: file-dev, config: { dir: /issued } }
        InstrumentSource: { adapter: file-dev, config: { dir: /published } }
    publishing:
      adapters:
        TransparencyLog: { adapter: trillian, config: { url: https://log.example.org } }
        Signer: { adapter: pkcs11-hsm, config: { slot: publisher, pin: { secretRef: hsm-pin } } }
  runtime:
    provisioning:
      factoryUrl: https://factory.example.org
      platforms:
        android: { management: self-managed, deviceOwner: fieldseal, lockTask: false }
  environments:
    staging:
      overrides:
        components.factory.adapters.TenancyRegistry.config.url: { secretRef: staging-factory-db-url }
      policies: { extraLayers: [ { ref: policy/staging, digest: "sha256:…" } ] }
    production: {}
```

Each platform declares `management` (DEP-024). Instruments are referenced like policy layers, by digest or channel. A component may also set `bind`, the address it listens on. Environment overrides are keyed by dotted path and may name only `components.<c>.adapters.<Port>.config.<key>`, `components.<c>.scaling.<key>` and `runtime.provisioning.factoryUrl`. A secret-looking key (`pin`, `password`, `token`, …) must be a `secretRef`.

`fieldseal deployment render --environment production` turns this into per-component environment variables (`FIELDSEAL_*`) and the device provisioning configuration.

## 7. Twelve-factor

| Factor | Factory, portal | Intake | Publishing pipeline | Runtime | CLI |
|---|---|---|---|---|---|
| I. Codebase | One repository; one build per component for all deployments | Same | Same | One build per platform for all authorities | Same |
| II. Dependencies | Locked; container image | Locked; container image | Locked; container image | Locked; no code downloaded at run time | Locked; single binary where possible |
| III. Config | Environment rendered from the manifest; secrets from the secret store | Same | Same | Provisioning configuration, trust bundles, signed runtime policy | `FIELDSEAL_*` environment and flags; files only as an explicit override |
| IV. Backing services | IdP, HSM, registry, policy engine, roster registry via adapters | HSM, submission store, data platform, registries via adapters | Transparency log, HSM, artefact registry via adapters | Factory, upload endpoint and time source named in configuration and bundles | Same adapters as the services |
| V. Build, release, run | Image → release (image + manifest) → run | Same | Same | Signed package → package + provisioning → tenancy | Binary → binary + environment → invocation |
| VI. Processes | Stateless | Stateless workers | Stateless jobs | Durable state only in journal, local record and outbox | Stateless |
| VII. Port binding | HTTPS | HTTPS | HTTPS for the registry | Not applicable: no inbound services (an invariant) | Not applicable |
| VIII. Concurrency | Scale replicas | Scale workers | Scale jobs | Not applicable | Parallel invocations |
| IX. Disposability | Fast start, graceful stop, idempotent APIs | Idempotent, resumable gate | Idempotent, resumable jobs | Crash-safe writes; resumable seal, export, clear, close | Idempotent, resumable commands |
| X. Dev/prod parity | Same image; config differs | Same | Same | Same build; trust and policy differ | Same binary |
| XI. Logs | Structured stdout | Structured stdout | Structured stdout | Sealed local stream, uploaded with telemetry | Structured stderr; `--json` output |
| XII. Admin processes | `fieldseal` commands against the release | Same | Same | Not applicable on device | Is the admin tool |

## 8. Conformance

| Test | Covers | Check |
|---|---|---|
| Manifest schema, unknown adapter, inline secret, policy below floor | DEP-001–007 | `fieldseal deployment validate` against fixtures |
| Rendered environment is identical across runs and contains no secret values | DEP-012, DEP-033 | `fieldseal deployment render --json` |
| Release content address changes when any build or the manifest changes | DEP-011 | Golden releases |
| Documentation bundle contains every required section and no secrets or personal data | DEP-030–033 | `fieldseal docs build` with a scanning check |
| Services start with only rendered environment; nothing else read | DEP-040–042 | Container test with a read-only filesystem |
| gRPC listener, health and reflection configuration | DEP-058–DEP-060 | Container test against the compose stack |
| Events contain no personal data | DEP-050–052 | Log scanner over conformance runs |

## 9. Open questions

1. *Resolved (architecture review #40, 2026-10-26):* the API group `fieldseal.dev` is approved.
2. Which documentation formats ship by default: static HTML, Markdown, PDF, or all three?
3. Should environments be separate manifests instead of overrides in one manifest?

## 10. References

- ADRs: [0002](../../explanation/adr/0002-name-fieldseal.md), [0003](../../explanation/adr/0003-ddd-and-hexagonal-architecture.md), [0006](../../explanation/adr/0006-cli-reference-implementation.md), [0008](../../explanation/adr/0008-trust-hierarchy.md), [0009](../../explanation/adr/0009-publishing-with-provenance.md), [0011](../../explanation/adr/0011-policy-as-signed-files.md), [0025](../../explanation/adr/0025-twelve-factor-deployments.md)
- The Twelve-Factor App, https://12factor.net
