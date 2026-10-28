# Policy

**Prefix:** `POL` · **Context:** Policy · **Status:** Draft · **ADRs:** [0011](../../explanation/adr/0011-policy-as-signed-files.md), [0007](../../explanation/adr/0007-zero-trust-posture.md), [0009](../../explanation/adr/0009-publishing-with-provenance.md), [0014](../../explanation/adr/0014-multi-device-and-air-gapped.md), [0017](../../explanation/adr/0017-runtime-authentication.md), [0019](../../explanation/adr/0019-review-until-clear.md), [0022](../../explanation/adr/0022-consent-bases.md)

## 1. Scope

Policy owns every tunable control in Fieldseal: the policy model, its typed schemas for the factory, runtime, intake and publishing, how layers combine, the invariant floors no policy may cross, how decisions are evaluated, and how they are logged.

It does not own the behaviour the controls govern; each context's spec says where it consults policy. Policies are artefacts and are published through [Publishing](./publishing.md).

## 2. Domain model

| Element | Kind | Meaning |
|---|---|---|
| `Policy` | Aggregate, artefact | One signed, versioned policy document with any of the sections `factory`, `runtime`, `intake`, `publishing` |
| `Layer` | Value object | Where a policy applies: `deployment`, `programme` (a named set of cohorts and instruments), or `instrument` (one instrument by name or content address) |
| `Control` | Value object | One typed setting, with its merge rule (§5.3) |
| `EffectivePolicy` | Value object | The result of merging the layers that apply to one decision, with the content addresses it came from |
| `Invariant` | Value object | A floor in code (§6.1) |
| `DecisionPoint` | Value object | A named place where a context asks for a decision (§6.2) |
| `Decision` | Entity | The outcome of one evaluation: `allow`, `deny`, `hold` or `flag`, with reasons and obligations |

Domain events: `PolicyPublished`, `PolicyRejected` (an invariant breached), `DecisionMade`.

Invariants:
- An effective policy never weakens an invariant.
- Every decision names the effective policy that produced it.

## 3. Driving ports

| Port | Used by | Input | Output |
|---|---|---|---|
| `ValidatePolicy` | Authors, CI, Publishing | Policy document | Diagnostics, including invariant breaches |
| `ComputeEffectivePolicy` | Factory, intake, runtime | Layer selectors (deployment, programme, instrument) | `EffectivePolicy` |
| `Decide` | Factory, intake | Decision point, input facts | `Decision` |
| `DiffPolicies` | Authors, reviewers | Two policies | Control-by-control changes, marked tighter or looser |

## 4. Driven ports

| Port | Contract every adapter MUST meet | Example adapters |
|---|---|---|
| `PolicyEngine` | Evaluates a decision point against an effective policy and input facts; deterministic; side-effect free; returns reasons for every non-`allow` outcome; times out rather than hangs | Open Policy Agent (Rego compiled from the typed policy), a built-in evaluator |
| `PolicySource` | Returns published policies for the layers in scope, verified through [Publishing](./publishing.md) | Artefact registry; a bundle (runtime) |
| `DecisionLog` | Append-only store of decisions; tamper-evident; retains per the deployment manifest | Event stream to a log service, append-only table |

The runtime does not use `PolicyEngine`: it evaluates its typed `runtime` section directly in the format core (POL-031).

## 5. Requirements

### 5.1 Documents

- **POL-001** A policy MUST be a resource with `apiVersion: fieldseal.dev/v1alpha1`, `kind: Policy`, `metadata.name`, `metadata.version`, and `spec.layer`.
- **POL-002** A policy MUST conform to the schema in §6.3 for its `schemaVersion`. A validator MUST reject unknown fields.
- **POL-005** Every reader of a policy document, of decision facts, of an engine's answer or of a decision-log entry MUST reject unknown fields, enforce exact types (an integer is not a decimal, text is not a number or boolean), require every required field, reject repeated list items where the control is a set, and enforce every declared constraint (ranges, lengths, enumerations, patterns, units).
- **POL-003** Durations MUST be written as an integer followed by `s`, `m`, `h` or `d` (for example `10m`); sizes as an integer followed by `KiB`, `MiB` or `GiB`.
- **POL-004** A policy MUST be published through [Publishing](./publishing.md) before any component uses it. A component MUST NOT read policy from an unpublished file, except `fieldseal policy validate | evaluate | diff` on a workstation.

### 5.2 Invariants

- **POL-010** Every component MUST reject a policy whose effective value for any control in §6.1 is weaker than the invariant floor, with a diagnostic naming the invariant.
- **POL-011** Invariants MUST be implemented in code. No policy field may disable them; the schema MUST NOT contain fields that could.
- **POL-012** Changing an invariant MUST require a new ADR and a new `schemaVersion` major version.

### 5.3 Layering and merging

- **POL-020** Layers MUST be applied in the order `deployment`, then `programme`, then `instrument`. Each control merges by the rule its schema declares:

  | Merge rule | Effect | Used for |
  |---|---|---|
  | `tighten` | The stricter value wins (lower maximum, higher minimum, shorter lifetime, `required` over `optional` over `off`) | Security controls |
  | `override` | The later layer's value wins | Operational controls (for example sample rate, reminders) |
  | `intersect` | Only values present in every layer survive | Allow-lists (destinations, builders, evidence formats) |
  | `union` | Values from every layer are combined | Deny-lists, extra field checks |

- **POL-021** A later layer MUST NOT loosen a `tighten` control. A validator MUST report an attempt as an error, not silently ignore it.
- **POL-022** Missing controls MUST take the schema default (§6.3), which MUST itself satisfy every invariant.
- **POL-023** `ComputeEffectivePolicy` MUST return the content address of every layer that contributed.

### 5.4 Evaluation

- **POL-030** Factory and intake decisions MUST be made by `Decide` at a named decision point (§6.2). A context MUST NOT encode a tunable threshold in code.
- **POL-031** The runtime MUST evaluate the effective `runtime` section with the typed evaluator in the format core, and MUST take its effective policy only from the bundle it is running and the invariants.
- **POL-032** Evaluation MUST be deterministic: the same effective policy and input facts MUST give the same decision.
- **POL-033** A decision MUST be one of `allow`, `deny`, `hold` (wait for a person) or `flag` (proceed and mark for review), with machine-readable reasons, and MAY carry obligations (for example "sample for review").
- **POL-034** A `PolicyEngine` failure or timeout MUST result in `hold` for decisions that release sensitive data, and `flag` for decisions on data that has already been collected. It MUST NOT result in `allow`.
- **POL-035** The facts of a decision are closed: a `PolicyEngine` MUST reject a fact that is not defined for the decision point, a missing fact and a mistyped fact (including an integer given for a decimal fact), and MUST treat an answer that is not exactly `{verdict, reasons, obligations}` of the declared types as an engine failure (POL-034).

### 5.5 Decision logging

- **POL-040** Every decision MUST be written to the `DecisionLog` with: decision point, outcome, reasons, obligations, the effective policy's layer addresses, SHA-256 of the input facts, the subject of the decision (tenancy, registration or record ID) and authority time.
- **POL-041** Decision log entries MUST NOT contain personal data; inputs are referenced by hash and ID only.
- **POL-042** A held decision MUST be resolvable by a person with the right role, and the resolution MUST be logged as a new decision referencing the first.
- **POL-043** A decision log reader MUST accept only entries that carry exactly the declared fields, with lowercase hexadecimal for every hash and record, and records that carry exactly the declared record fields; any other entry makes the log fail verification.

### 5.6 Distribution of runtime policy

- **POL-050** The factory MUST include the effective `runtime` section, as a `Publication` of each contributing layer, in every bundle ([Distribution](./distribution.md)).
- **POL-051** A runtime MUST apply a bundle's runtime policy only after verifying it (PUB-071) and checking invariants (POL-010).
- **POL-052** A runtime MUST NOT apply a runtime policy whose version is lower than one it already applies for the same layer and name.

### 5.7 Extensions ([ADR 0037](../../explanation/adr/0037-extensions-and-strict-schema-enforcement.md))

- **POL-063** The `spec.publishing.extensions` control (Publishing §6.3) MUST decide which extensions may be published and referenced. `allow` and `kinds` merge by intersection and `maxPerInstrument` by tightening, so a later layer can only narrow what an earlier one permits (POL-021). The default `allow` is empty: no extension is accepted until a policy lists it.
- **POL-064** The `bundle.release` decision MUST deny a bundle that contains an extension the effective `publishing.extensions` no longer allows. No policy control MAY reference the content of an extension, and no extension MAY set, change or loosen a policy control.

### 5.8 Authority key custody ([ADR 0038](../../explanation/adr/0038-authority-key-custody-classes.md))

- **POL-065** `custody.minAssurance.<purpose>` and `custody.minMode.<purpose>` MUST set the minimum assurance and mode (TRU §6.7) an authority key of that purpose may have. Both merge by tightening, so a later layer can only raise a minimum (POL-021). Because an environment can override policy layers (DEP-006), the minimums MAY differ per environment. A policy whose effective `custody.minAssurance` for any purpose in a `production` environment is `development` MUST be refused (INV-15, POL-010).
- **POL-066** `custody.hotKey.maxValidity` and `custody.hotKey.rotateBefore` MUST tighten, and MUST NOT allow a validity beyond the TRU §6.1 maximum for the purpose (TRU-113).
- **POL-067** `IssuePurposeKey`, `OpenCollectionPeriod` and `RotatePurposeKey` MUST call `Decide` at `key.issue` with the key's purpose, mode, assurance and the verified claims as input facts. An assurance or mode below the effective minimum MUST yield `deny`, and a `cold` root or publisher issuance without its custodian threshold MUST yield `hold`. A `PolicyEngine` failure MUST NOT yield `allow` (POL-034).

## 6. Resources and formats

### 6.1 Invariant floors

| ID | Invariant | Floor |
|---|---|---|
| INV-1 | Records and export manifests are sealed to an authority key | Always |
| INV-2 | Inbound artefacts get minimal parse, authenticate, decrypt, strict decode, in that order | Always |
| INV-3 | Secure display on every runtime screen | Always |
| INV-4 | Runtime PIN length | ≥ 6 digits |
| INV-5 | Runtime PIN lockout | Escalating; first delay ≥ 30 s after 5 failures |
| INV-6 | Session idle lock | ≤ 15 minutes |
| INV-7 | Identity on storage | Never in plaintext |
| INV-8 | Biometric-only unlock | Never |
| INV-9 | Argon2id parameters for the session key | ≥ m 64 MiB, t 3, p 1 |
| INV-10 | Unattested (software) keys in production | Never registered; bundles with rosters never released to them. Outside production, the factory's non-production allowance for unattested keys (REG-017) lets policy release rosters with a `flag` (`unattestedAllowed`, configuration and not a device fact); the device is still unattested everywhere |
| INV-11 | Transparency log inclusion for published artefacts | Required |
| INV-12 | Publisher threshold | m ≥ 2 |
| INV-13 | Clear without the twice-entered PIN; deleting sealed journal records before a receipt covers them | Never ([ADR 0029](../../explanation/adr/0029-clear-anytime-with-pin-confirmation.md)) |
| INV-14 | Inbound network services on devices | Never |
| INV-15 | `development` assurance for an authority key in an environment of tier `production` | Never; `custody.minAssurance` is at least `custody-bound` there |

### 6.2 Decision points

| Decision point | Context | Typical outcomes |
|---|---|---|
| `registration.token.issue` | Registration | allow, deny |
| `registration.approve` | Registration | allow, hold, deny |
| `device.add` | Registration | allow, deny (limit) |
| `key.roll` | Registration | allow, hold |
| `bundle.release` | Distribution | allow, hold |
| `posture.recheck` | Registration | allow, flag (pauses release) |
| `artefact.publish` | Publishing | allow, deny |
| `intake.accept` | Intake | allow, flag, deny |
| `consent.decide` | Intake | allow (auto-accept), hold (review), deny |
| `tenancy.late` | Intake | allow, flag |
| `key.issue` | Trust | allow, hold (awaiting a second custodian), deny |

### 6.3 Schema (`schemaVersion: 1.0.0`)

**`spec.factory`**

| Control | Type | Default | Merge |
|---|---|---|---|
| `registration.maxDevicesPerAccount` | int ≥ 1 | 2 | tighten |
| `registration.tokenTtl` | duration | `10m` | tighten |
| `registration.airGappedTokenTtl` | duration | `24h` | tighten |
| `registration.requireFingerprintConfirmation` | bool | true | tighten |
| `registration.serialCheck` | `off` / `optional` / `required` | `optional` | tighten |
| `registration.requirePhishingResistantAuth` | bool | true | tighten |
| `registration.acceptAssertedAuthMethods` | bool | false | tighten |
| `registration.deviceNonceRegistrations` | `allow` / `flag` / `deny` | `flag` | tighten |
| `registration.batchTokens.allowed` | bool | false | tighten |
| `registration.batchTokens.roles` | list | `[]` | intersect |
| `registration.batchTokens.maxUses` | int | 50 | tighten |
| `registration.batchTokens.ttl` | duration | `4h` | tighten |
| `attestation.acceptedFormats` | list | all non-software formats | intersect |
| `attestation.minSecurityLevel` | `tee` / `strongbox` / `secure-element` / `tpm` | `tee` | tighten |
| `attestation.minOsPatchLevel` | date | none | tighten |
| `attestation.requireVerifiedBoot` | bool | true | tighten |
| `attestation.requireBootloaderLocked` | bool | true | tighten |
| `attestation.acceptedRuntimeVersions` | semver range | — | intersect |
| `cohorts.maxActiveTenanciesPerCohort` | int ≥ 1 | 1 | tighten |
| `posture.recheckInterval` | duration | `7d` | tighten |
| `posture.onFailure` | `flag` / `pause-release` | `pause-release` | tighten |
| `posture.unknownRestriction` | `flag` / `accept` | `flag` | tighten |
| `release.requireRegisteredTenancy` | bool (MUST be true) | true | tighten |
| `custody.minAssurance.<purpose>` | `development` / `custody-bound` / `attested`, for each authority purpose | `custody-bound` for every purpose | tighten (the higher assurance wins) |
| `custody.minMode.<purpose>` | `hot` / `cold`, for each authority purpose | `root`, `publisher`: `cold`; every other purpose: `hot` | tighten (`cold` is stricter than `hot`) |
| `custody.hotKey.maxValidity` | duration, at most the TRU §6.1 limit | `180d` | tighten |
| `custody.hotKey.rotateBefore` | duration | `30d` | tighten |

**`spec.runtime`**

| Control | Type | Default | Merge |
|---|---|---|---|
| `pin.minLength` | int ≥ 6 | 6 | tighten |
| `pin.lockoutSteps` | list of durations | `[30s, 1m, 5m, 15m, 1h]` | tighten |
| `pin.failuresBeforeLockout` | int ≤ 5 | 5 | tighten |
| `pin.argon2` | `{memory, iterations, parallelism}` | `{64MiB, 3, 1}` | tighten |
| `session.idleLock` | duration ≤ 15m | `2m` | tighten |
| `session.lockOnBackground` | bool | true | tighten |
| `session.lockOnScreenOff` | bool | true | tighten |
| `export.parityDefault` | `on` / `off` | `on` | override |
| `export.allowParityOff` | bool | true | tighten |
| `export.destinations` | list of `upload`, `local`, `removable`, `cloud`, `share` | all | intersect |
| `export.filePrefix` | string, no identifying content | `Fieldseal` | override |
| `export.fileExtension` | string | `fieldseal` | override |
| `upload.background` | bool | true | override |
| `upload.retryBackoff` | list of durations | `[1m, 5m, 30m, 2h]` | override |
| `retention.offerClearOnReceipt` | bool | true | override |
| `retention.remindAfter` | duration | `7d` | override |
| `time.warnOutsideWindow` | bool | true | override |
| `device.kiosk` | bool | false | override |
| `device.requiredRestrictions` | list of `uninstall-blocked`, `clear-data-blocked`, `debugging-disabled`, `safe-boot-disabled`, `factory-reset-disabled`, `backup-disabled`, `content-capture-disabled`, `input-methods-allow-listed`, `accessibility-allow-listed` | all | union |
| `publishing.maxTreeHeadAge` | duration | `90d` | tighten |
| `evidence.maxImageEdge` | int (pixels) | 2000 | tighten |

**`spec.intake`**

| Control | Type | Default | Merge |
|---|---|---|---|
| `consent.autoAcceptWithEvidence` | bool | true | override |
| `consent.sampleRate` | 0.0–1.0 | 0.05 | override |
| `consent.withoutEvidence` | `review` / `accept` / `deny` | `review` | tighten |
| `consent.heuristics` | list of named heuristics | built-in set | union |
| `consent.excludePendingFromAnalysis` | bool | true | tighten |
| `time.grace` | duration | `30d` | tighten |
| `time.provablyLate` | `flag` / `deny` | `flag` | tighten |
| `ticks.fastRunning` | `flag` / `deny` | `flag` | tighten |
| `parity.repair` | bool | true | override |
| `denyList.cutoffMode` | `highest-received` | `highest-received` | tighten |
| `limits.maxSubmissionSize` | size | `512MiB` | tighten |
| `dataQuality.onFailure` | `finding` / `quarantine` | `finding` | tighten |

**`spec.publishing`** — the fields in [Publishing](./publishing.md) §6.3; all `tighten` except `allowedBuilders` and `allowedSources` (`intersect`).

### 6.4 Example

```yaml
apiVersion: fieldseal.dev/v1alpha1
kind: Policy
metadata:
  name: authority-baseline
  version: 3.1.0
spec:
  schemaVersion: 1.0.0
  layer: { scope: deployment }
  factory:
    registration:
      maxDevicesPerAccount: 2
      tokenTtl: 10m
      airGappedTokenTtl: 24h
      requireFingerprintConfirmation: true
      serialCheck: optional
      requirePhishingResistantAuth: true
      deviceNonceRegistrations: flag
      batchTokens: { allowed: true, roles: [device-preparation], maxUses: 50, ttl: 4h }
    attestation:
      acceptedFormats: [android-key-attestation, apple-app-attest, tpm2-quote]
      minSecurityLevel: tee
      minOsPatchLevel: 2026-06-01
      requireVerifiedBoot: true
      requireBootloaderLocked: true
      acceptedRuntimeVersions: ">=1.0.0 <2.0.0"
    cohorts: { maxActiveTenanciesPerCohort: 1 }
    posture: { recheckInterval: 7d, onFailure: pause-release }
  runtime:
    pin: { minLength: 6, failuresBeforeLockout: 5, lockoutSteps: [30s, 1m, 5m, 15m, 1h] }
    session: { idleLock: 2m, lockOnBackground: true, lockOnScreenOff: true }
    export:
      parityDefault: on
      allowParityOff: true
      destinations: [upload, local, removable, share, cloud]
    upload: { background: true }
    retention: { offerClearOnReceipt: true, remindAfter: 7d }
    device: { kiosk: false }
    publishing: { maxTreeHeadAge: 90d }
  intake:
    consent:
      autoAcceptWithEvidence: true
      sampleRate: 0.05
      withoutEvidence: review
      excludePendingFromAnalysis: true
    time: { grace: 30d, provablyLate: flag }
    ticks: { fastRunning: flag }
  publishing:
    requiredApprovals: { Instrument: 2, Policy: 2, TrustBundle: 2, Deployment: 2 }
    authorMayApprove: false
    publisherThreshold: { m: 2, n: 3 }
    allowedBuilders: [ "https://ci.example.org/builders/fieldseal-publish" ]
    allowedSources: [ "https://git.example.org/authority/artefacts" ]
    requireTransparencyLog: true
```

A programme layer that only tightens one control:

```yaml
apiVersion: fieldseal.dev/v1alpha1
kind: Policy
metadata: { name: programme-a, version: 1.0.0 }
spec:
  schemaVersion: 1.0.0
  layer: { scope: programme, programme: programme-a }
  factory:
    registration: { maxDevicesPerAccount: 1 }
  runtime:
    retention: { remindAfter: 3d }
```

## 7. Twelve-factor

- **Config (III):** policy is versioned, published configuration; it is never baked into code or images. Which policy layers a deployment uses is named in its deployment manifest ([Deployment](./deployment.md)), not in the environment of a single process.
- **Backing services (IV):** the policy engine and decision log are attached resources.
- **Build, release, run (V):** publishing a policy is a release step; running services pick up new effective policies without a rebuild.
- **Processes (VI):** evaluation is stateless; state is in the decision log.
- **Dev/prod parity (X):** the same policies run in every environment; only the layers selected differ, and production layers cannot be loosened by development layers.
- **Logs (XI):** decisions are emitted as structured events (POL-040).
- **Admin processes (XII):** `fieldseal policy validate | evaluate | diff` run as one-off processes.
- **Port binding (VII), concurrency (VIII), disposability (IX):** follow the hosting service.

## 8. Conformance

- `fieldseal policy validate` MUST detect every invariant breach in §6.1, unknown fields, wrong types and loosening across layers.
- `fieldseal policy evaluate --point <decision point> --input <facts>` returns the decision and reasons; `fieldseal policy diff` lists changes marked tighter or looser.
- Golden vectors in `crates/contexts/policy/tests/vectors/` (`merging.json`, `defaults.json`, `decisions.json`) cover merging for each rule, defaults, every decision point, and engine failure handling (POL-034). They are regenerated with `FIELDSEAL_REGENERATE_VECTORS=1 cargo test -p fieldseal-policy --test vectors`, and every `PolicyEngine` adapter runs `decisions.json` (the built-in engine and the Open Policy Agent adapter do).
- `fieldseal conformance run --suite policy` runs the suite.

## 9. Open questions

1. Should `programme` be a first-class resource (`kind: Programme`) naming its cohorts and instruments, or remain a label on policies?
2. Should `consent.sampleRate` be allowed to vary by collector, for example higher for new collectors?
3. Is `deny` ever appropriate for `consent.withoutEvidence`, given that the authority's own consent records are incomplete?
4. Which policy engine should be the reference adapter, and should Rego be generated from the typed schema or written by hand?

## 10. References

- ADRs [0007](../../explanation/adr/0007-zero-trust-posture.md), [0011](../../explanation/adr/0011-policy-as-signed-files.md), [0014](../../explanation/adr/0014-multi-device-and-air-gapped.md), [0017](../../explanation/adr/0017-runtime-authentication.md), [0019](../../explanation/adr/0019-review-until-clear.md), [0022](../../explanation/adr/0022-consent-bases.md), [0025](../../explanation/adr/0025-twelve-factor-deployments.md)
- NIST SP 800-207 (policy decision and enforcement points), Open Policy Agent, NIST SP 800-63B-4
