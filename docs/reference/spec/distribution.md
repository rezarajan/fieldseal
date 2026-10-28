# Distribution

**Prefix:** `DIS` · **Kind:** `Bundle` · **apiVersion:** `fieldseal.dev/v1alpha1` · **Status:** Draft

## 1. Scope

**Owns:** deciding when a bundle may be released to a tenancy; building it from published artefacts and rosters; sealing it to one device key; signing it; delivering it in-app or out-of-app; and the order in which a runtime verifies it.

**Does not own:**
- publishing artefacts ([Publishing](./publishing.md));
- registering keys ([Registration](./registration.md));
- what the runtime does with a verified bundle ([Collection](./collection.md));
- bytes (WIRE §bundle).

## 2. Domain model

| Element | Type | Meaning |
|---|---|---|
| `Bundle` | Aggregate root | One sealed, signed package for one agreement key, identified by its content address. |
| `BundleManifest` | Value object | What the bundle contains, inside the seal: tenancy, agreement key, item list with content addresses, bundle sequence number, issue time. |
| `PublishedArtefactRef` | Value object | An instrument or policy content address with its publisher signatures, provenance and transparency-log inclusion proof. |
| `Roster` | Entity | A cohort's subjects: pseudonymous subject IDs, display fields the instrument reads, consent state (`granted`, `refused`, `unknown`), optional prior status. |
| `RosterVersion` | Value object | Cohort ID, version (monotonic), generation for this tenancy. |
| `TrustUpdate` | Value object | A newer trust bundle, published. |
| `Anchor` | Value object | An authority-signed time statement (WIRE §anchors). |
| `WithdrawalList` | Value object | Content addresses withdrawn from publishing, signed by the authority. |
| `ReleaseDecision` | Value object | The policy verdict to release, with the policy content address. |

**Domain events:**
- `BundleReleased`, `BundleWithheld(reason)`;
- `BundleDelivered(route)`, `BundleImported`, `BundleRejected(reason)`.

**Invariants:**
- A bundle is sealed to exactly one agreement key.
- Every artefact in it is published and not withdrawn at build time.
- Roster versions in successive bundles for a tenancy never decrease.

## 3. Driving ports

| Port | Caller | Input | Output | Errors |
|---|---|---|---|---|
| `BuildBundle` | Factory, on registration, assignment change, artefact or policy change, key roll | Tenancy | `Bundle` | `NotRegistered`, `Withheld(reason)`, `ArtefactNotPublished`, `IncompatibleSchema` |
| `FetchBundle` | Runtime (proof-of-possession token) | Tenancy, last bundle sequence held | Latest `Bundle` or `not-modified` | `NotRegistered`, `Withheld` |
| `DownloadBundle` | Portal (signed-in collector) | Device | Bundle file | `Withheld` |
| `ImportBundle` | Runtime | Bundle bytes | Verified contents | as §5.4 |

## 4. Driven ports

HPKE sealing and signature verification are pure functions of the format core ([Wire formats](./wire-formats.md)), not ports.

| Port | Contract |
|---|---|
| `ArtefactRegistry` | Returns published artefacts with their signatures, provenance and inclusion proofs, and the current withdrawal list. MUST NOT return unpublished artefacts. |
| `RosterSource` | Returns current roster versions for the tenancy's cohorts. |
| `RegistryStore` | Shared with [Registration](./registration.md): tenancy state, keys, generations, cutoffs. |
| `PolicyEngine` | Decides release, through Policy's `Decide` so every decision is logged. |
| `Signer` | Factory signing key, through the HSM or KMS. |
| `AnchorSource` | Authority time statements (time tokens), signed by the receipt and time key. |
| `RuntimeProfiles` | What each tenancy's runtime reported at registration: the instrument-schema version it implements and its UI reference-catalogue version (DIS-012, DIS-017). Returns `None` for a tenancy it has no record of. |

On the runtime:

| Port | Contract |
|---|---|
| `AgreementKey` | Performs the HPKE key-agreement step with the tenancy's agreement key inside the platform key store; the private key MUST NOT leave it ([Platform profiles](./platform-profiles.md)). |
| `TrustStore` | The runtime's current trust bundle. |
| `BundleStore` | Stores the sealed bundle as received, newest by sequence. Owned by Distribution so it doesn't depend on Collection's storage port. |

## 5. Requirements

### 5.1 Release

- **DIS-001** The factory MUST NOT release a bundle containing a roster to a tenancy that is not `registered`.
- **DIS-002** Release MUST be decided by `PolicyEngine`, and the decision MUST record the policy content address.
- **DIS-003** The factory MUST withhold new bundles from a `flagged`, `lost`, `closing`, `closed` or `retired` tenancy, and from a `registered` tenancy when policy says so (for example a failed posture check).
- **DIS-004** A tenancy that is not registered MAY receive a bundle with no rosters (a practice instrument), if policy allows.

### 5.2 Contents

- **DIS-010** A bundle MUST contain:
  - a `BundleManifest`;
  - each instrument it uses, as a `PublishedArtefactRef` with the instrument bytes;
  - the runtime policy, as a `PublishedArtefactRef`;
  - the rosters for the tenancy's cohorts;
  - the current withdrawal list;
  - at least one fresh anchor.

  It MAY contain trust updates.
- **DIS-011** The factory MUST build bundles only from artefacts that `ArtefactRegistry` reports as published and not withdrawn.
- **DIS-012** The factory MUST NOT include an instrument whose schema range is incompatible with the schema version the tenancy's runtime reported at registration (INS-093).
- **DIS-013** A roster MUST carry, per subject, a pseudonymous `subject_id`, only the display fields the instrument references, and a consent state. It MUST NOT carry fields the instrument does not reference.
- **DIS-014** Each roster MUST carry its cohort ID, a monotonic version and the tenancy's generation for that cohort.
- **DIS-015** The bundle sequence number MUST increase by one for each bundle built for a tenancy.
- **DIS-016** A bundle MAY contain, for each instrument, the published layouts that factory policy assigns to it, at most one per window class (INS-207), each as a `PublishedArtefactRef`. The factory MUST NOT include a layout bound to a different instrument fingerprint (INS-200).
- **DIS-017** A bundle MAY contain published `Localisation` artefacts for the runtime UI, as policy assigns them. The factory MUST NOT include a catalogue whose reference version the tenancy's runtime build did not report at registration (PLAT-053).

### 5.3 Sealing and signing

- **DIS-020** The bundle body MUST be sealed with HPKE (RFC 9180) to the tenancy's current agreement key (WIRE §bundle). The `info` input MUST be domain-tagged and include the tenancy ID (WIRE-023).
- **DIS-021** The factory MUST sign the sealed envelope (not the plaintext) with its factory signing key, chaining to the authority root, with the bundle domain tag (TRU, signature domains).
- **DIS-022** The envelope's outer fields MUST be limited to the format magic, the sealed envelope's suite, recipient key identifier and ciphertext, the signer, its certificate and the signature (WIRE-090). The tenancy ID and the bundle sequence are inside the seal; a store keeps the sequence beside the file. Nothing outside the seal may identify a subject, cohort, tenancy or instrument.
- **DIS-023** Bundle files MUST have a neutral name: `fieldseal-bundle-<date>-<sequence>.fsb`.

### 5.4 Verification on the runtime

- **DIS-030** The runtime MUST verify an imported or fetched bundle in this order, and MUST stop at the first failure without using anything from it:
  1. size within the runtime policy limit, and a well-formed envelope (bounded parse);
  2. the key identifier matches the tenancy's current agreement key;
  3. the factory signature, chained to the trust bundle (before the seal is opened, WIRE-093);
  4. decryption through `AgreementKey`, with the active tenancy ID as the HPKE context (DIS-020), so a bundle for another tenancy does not open;
  5. strict decoding of the manifest and contents against WIRE §bundle, and that the contents name the active tenancy, that the tenancy certificate (when present) verifies and names this agreement key, and that the time token verifies and is the issue time;
  6. the bundle sequence is greater than the last one held;
  7. each artefact's publisher signatures, provenance and transparency-log inclusion ([Publishing](./publishing.md)), and that none is on the withdrawal list;
  8. instrument schema compatibility (INS-092);
  9. roster versions not lower than those held.
- **DIS-031** A rejection MUST give the collector a one-line reason (wrong device, older version, damaged, unsupported) and MUST keep the previously held bundle.
- **DIS-032** On success, the runtime MUST chain the bundle's anchor and an import record into the journal ([Collection](./collection.md)).
- **DIS-033** The runtime MUST keep the bundle sealed at rest, exactly as received, and decrypt it into memory only inside a session.

### 5.5 Delivery

- **DIS-040** The runtime MUST fetch new bundles when online, through `FetchBundle` with a proof-of-possession token.
- **DIS-041** The portal MUST let the signed-in collector download the latest bundle for each of their registered devices as a file, for import through the platform's file picker.
- **DIS-042** Delivery MUST NOT require any particular transport. A bundle copied to another device MUST be unusable there (DIS-020, DIS-030 step 2).

### 5.6 Key roll and succession

- **DIS-050** After an agreement-key roll, the factory MUST build a new bundle for the new key. The runtime MUST discard bundles sealed to the old key once the new bundle is imported.
- **DIS-051** When a cohort moves to a successor tenancy, the successor's roster MUST carry `generation + 1` and MAY carry each subject's `prior_status`.

### Bundle sources and destinations

- **DIS-060** A bundle MUST be accepted from any source or route; its validity MUST rest only on its factory signature, sealing and contents.
- **DIS-061** A bundle MUST NOT be required to name an upload destination. It MAY carry advisory destination hints, which the runtime MUST treat as untrusted ([Delivery](./delivery.md), DEL-061).
- **DIS-062** Bundles MUST name instruments by fingerprint ([ADR 0027](../../explanation/adr/0027-salted-instrument-fingerprints.md)).
- **DIS-063** Every reader of a bundle file, bundle content, roster or time token MUST reject unknown fields, enforce exact types, require every required field, and enforce every declared constraint: sizes before parsing, no trailing bytes, strictly increasing roster ordinals, unique subjects within a roster, one roster per cohort, no publication listed twice in a list, and a consent state from the declared set. A reader that projects an already validated artefact (the schema range of an instrument, the instrument of a layout) reads only the fields composition needs and fails closed on anything it cannot read.

### 5.7 Extensions in bundles ([ADR 0037](../../explanation/adr/0037-extensions-and-strict-schema-enforcement.md))

- **DIS-074** A bundle MUST contain, as a `PublishedArtefactRef`, every `Extension` that any instrument or layout in it references, and no extension that none of them references. This closure is what lets a runtime compile every instrument offline (INS-247).
- **DIS-075** `BuildBundle` MUST fail with `ExtensionNotPublished` if an extension in the closure is unpublished, withdrawn, or not allowed by the effective `publishing.extensions` policy (POL-063, POL-064), and MUST NOT release a partial bundle.
- **DIS-076** In DIS-030, step 7 MUST also verify each extension's publication as it does an instrument's, and step 8 MUST also check that every extension address an instrument names is present in the bundle, that each extension validates against the meta-schema it declares (INS-251), and that the instrument's catalogue address is held (INS-236). The runtime MUST reject the whole bundle with the reason `unresolved-extension` otherwise, and MUST NOT fetch an extension from anywhere else.
- **DIS-077** The factory MUST NOT include an extension whose meta-schema version, or an instrument whose catalogue address, the tenancy's runtime did not report at registration (DIS-012). `RuntimeProfiles` MUST return both.

## 6. Resources and formats

Display form of a bundle's manifest, as shown by `fieldseal bundle inspect` with the agreement key available:

```yaml
apiVersion: fieldseal.dev/v1alpha1
kind: Bundle
spec:
  tenancy: sha256:41ab…
  sequence: 3
  issued: 2026-11-02T09:12:00Z
  instruments:
    - { address: sha256:77c1…, name: health-check, version: 1.0.0 }
  policy: { address: sha256:0b9e… }
  rosters:
    - { cohort: cohort:12a, version: 4, generation: 1, subjects: 28 }
  withdrawals: { address: sha256:e3f0…, count: 0 }
  anchors: 1
```

## 7. Twelve-factor

- **Config (III):** the release policy, size limits and registry locations come from policy and the environment.
- **Backing services (IV):** the artefact registry, roster source, HSM and policy engine are attached resources.
- **Processes (VI):** bundle building is a stateless function of the tenancy, artefacts, rosters and policy, so it can be rebuilt at any time.
- **Disposability (IX):** building and delivery are idempotent; the bundle sequence makes a retried import harmless.
- **Logs (XI):** release decisions are logged with policy addresses, never roster contents.

## 8. Conformance

| Test | Requirements | Command |
|---|---|---|
| Release refused before registration and for flagged tenancies | DIS-001–DIS-004 | `fieldseal policy evaluate`, `fieldseal conformance run --suite dis-release` |
| Contents and published-only rule | DIS-010–DIS-015, DIS-063 | `fieldseal bundle build`, `fieldseal bundle inspect` |
| Sealing, signing, outer fields, naming | DIS-020–DIS-023 | `fieldseal bundle verify`, golden vectors |
| Verification order and fail-closed with tampered bundles | DIS-030, DIS-031 | `fieldseal bundle open`, `fieldseal conformance run --suite dis-verify` |
| Wrong-device bundle unusable | DIS-042 | `fieldseal device simulate --import <other device's bundle>` |
| Key roll and succession | DIS-050, DIS-051 | `fieldseal keys roll`, `fieldseal bundle build` |

## 9. Open questions

1. Should a bundle also be sealed to an authority audit key, so the authority can reopen it later? The current position is no: the authority holds the plaintext rosters.
2. Maximum bundle size by default: 8 MiB?
3. Should practice bundles (DIS-004) be built by the factory or shipped with the runtime build?

## 10. References

- [ADR 0009](../../explanation/adr/0009-publishing-with-provenance.md), [ADR 0010](../../explanation/adr/0010-declarative-instruments.md), [ADR 0012](../../explanation/adr/0012-local-first-device-keys.md), [ADR 0015](../../explanation/adr/0015-bundles-sealed-per-device.md), [ADR 0020](../../explanation/adr/0020-monotonic-ticks.md), [ADR 0025](../../explanation/adr/0025-twelve-factor-deployments.md)
- [Wire formats](./wire-formats.md), [Trust](./trust.md), [Publishing](./publishing.md), [Registration](./registration.md), [Instrument](./instrument.md), [Collection](./collection.md)
- RFC 9180 (HPKE)
