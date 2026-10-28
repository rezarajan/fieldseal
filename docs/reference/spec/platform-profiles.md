# Platform profiles

**Prefix:** `PLAT` · **Context:** Collection (platform ports) · **Runs in:** runtime · **Status:** Draft

## 1. Scope

The runtime's domain and application code is the same on every operating system. Everything that depends on the operating system reaches it through the driven ports defined here. A **platform profile** is the set of adapters implementing these ports on one operating system, plus a declaration of how well each requirement is met.

This spec defines the port contracts, the requirement level of each, and how a profile declares what it meets. The [Android profile](./platform-android.md) is the first normative profile. It does not define UI, which is the runtime shell's concern, or byte formats (WIRE).

## 2. Domain model

| Element | Kind | Description |
|---|---|---|
| `PlatformProfile` | Aggregate | One operating system's adapters and its declaration. |
| `CapabilityDeclaration` | Value object | For each requirement: `hardware`, `software` or `unmet`, with notes. |
| `KeyHandle` | Value object | An opaque reference to a key in the platform key store; never the key material. |
| `AttestationEvidence` | Value object | Platform-specific evidence, with a format identifier, verified by the matching factory adapter. |
| `ElapsedReading` | Value object | Monotonic elapsed time since boot, and the boot count. |
| `StorageClass` | Value object | `device` (encrypted by the platform, available without a session) or `session` (encrypted under the session key). |
| `DestinationReport` | Value object | The destination class a file write went to, decided by the platform (DEL-020). |

**Invariants**

- Key material for keys marked non-exportable never crosses the port.
- The domain never learns a destination's path or name beyond its class.

## 3. Driving ports

Not applicable: platform profiles only implement driven ports for the runtime.

## 4. Driven ports

Each port lists its operations and the contract every adapter must meet. Contract tests (§8) run against every adapter.

| Port | Operations | Contract |
|---|---|---|
| `KeyStore` | `generate(purpose, protection, challenge?) → KeyHandle, evidence?`; `sign(handle, data)`; `agree(handle, peer_pub) → shared_secret`; `wrap/unwrap(handle, data)`; `delete(handle)`; `exists(handle)` | Keys are non-exportable; `purpose` is exactly one of sign, agree, wrap; `protection` includes "usable only while device unlocked"; `delete` is irreversible; shared secrets are returned once and the caller MUST zero them. |
| `Attestor` | `evidence(handle) → AttestationEvidence` | Evidence proves: the key is in secure hardware (or states it isn't), its purposes and protections, the app's identity and signing digest, OS and patch level, boot integrity, and the challenge supplied at generation. |
| `ElapsedClock` | `now() → ElapsedReading` | Elapsed time is monotonic within a boot and can't be set by any user; boot count increments on every boot and can't be decreased by apps. |
| `SecureDisplay` | `protect(window)`; `isProtected(window)` | Protected windows are excluded from screenshots, screen recording, task-switcher thumbnails and casting. |
| `DevicePolicy` | `mode() → self-managed / emm-managed`; `apply(required_restrictions)` (self-managed only); `effectiveRestrictions() → {restriction: in-force / missing / unknown}`, **read from the platform's live state, never from configuration**; `managedConfiguration() → provisioning configuration` | Prevents other users from uninstalling the runtime, clearing or reading its storage, debugging it, or factory-resetting without authority release; disables backup of runtime data and screen-content capture by other services; restricts input methods and accessibility services to an allow-list; reports what it couldn't enforce. |
| `FileAccess` | `pickDestination(class_filter) → handle`; `write(handle, bytes)`; `sync(handle)`; `readBack(handle) → bytes`; `report(handle) → DestinationReport`; `pickSource() → bytes` | `sync` returns only after the bytes are on the storage device; `readBack` reads through the same handle; `report` is decided by the platform from the provider, not by the user. |
| `ShareTarget` | `share(bytes, allowed_targets) → outcome` | Offers only allow-listed targets; reports only success or failure. |
| `Camera` | `capture(constraints) → image bytes in memory`; `scanQr() → bytes` | Images never touch disk, gallery or a media index; QR decoding works offline. |
| `Network` | `request(url, body, headers) → response`; `available() → bool` | TLS with platform roots and optional pins; no inbound listening sockets. |
| `Storage` | `open(class, name)`; atomic `write`; `fsync`; `delete` | `device` class is encrypted by the platform and available after boot without a session; `session` class contents are already encrypted by the runtime; writes are atomic (write-then-rename). |
| `Secrets` | `memory(bytes) → zeroing buffer` | Best-effort zeroing; declares whether the platform can guarantee it. |

## 5. Requirements

### Requirement levels

- **PLAT-001** A profile MUST implement every port in §4.
- **PLAT-002** A profile MUST declare each requirement in the table below as `hardware`, `software` or `unmet`, with notes, in its spec.
- **PLAT-003** The factory MUST receive the declaration through attestation evidence or the runtime build's identity, and factory policy MUST decide which declarations it accepts for registration.

| ID | Requirement | Level |
|---|---|---|
| **PLAT-010** | Signing and agreement keys MUST be generated in a key store that resists extraction by software on the device. | Required for registration |
| **PLAT-011** | Keys MUST be usable only while the device is unlocked. | Required |
| **PLAT-012** | The key store MUST produce attestation evidence binding a supplied challenge. | Required for registration |
| **PLAT-013** | Evidence SHOULD bind the device's identity (for example its serial number). | Optional; factory policy decides |
| **PLAT-014** | The elapsed clock MUST be monotonic and not user-settable; a boot count MUST be available. | Required |
| **PLAT-015** | Secure display MUST cover screenshots, recording, thumbnails and casting. | Required |
| **PLAT-016** | Device policy MUST prevent uninstall, clear-data, force-stop and debugging of the runtime by other users. | Required |
| **PLAT-017** | Device policy SHOULD prevent factory reset without authority release. | Strongly recommended |
| **PLAT-018** | Device policy MUST disable backup of runtime data and screen-content capture. | Required |
| **PLAT-019** | Device policy MUST restrict input methods and accessibility services to an allow-list. | Required |
| **PLAT-020** | File access MUST support sync-to-device and read-back through the same handle, and report destination classes. | Required |
| **PLAT-021** | Camera capture MUST go to memory only. | Required where consent evidence or QR is used |
| **PLAT-022** | The runtime MUST NOT open inbound network listeners. | Invariant |
| **PLAT-023** | Memory MUST NOT be swapped to persistent storage. | Recommended; declare if unmet |

### Behaviour

- **PLAT-030** A runtime whose profile declares any "Required for registration" item `unmet` MUST run only practice instruments, and MUST NOT send a registration request.
- **PLAT-031** *Withdrawn ([ADR 0031](../../explanation/adr/0031-device-management-adapters.md)): replaced by PLAT-040–PLAT-046, which flag device-policy gaps instead of refusing sessions.*
- **PLAT-032** Adapters MUST NOT log key handles, evidence, shared secrets, file names, or any data passing through `Camera`, `FileAccess` or `Storage`.
- **PLAT-033** Every adapter MUST pass its port's contract tests on the target operating system before a profile is released. The `DevicePolicy` contract suite MUST include, for each restriction, a device where it is in force and one where it has been removed out-of-band, and MUST fail if `effectiveRestrictions()` reports the second as `in-force`.

### Device management ([ADR 0031](../../explanation/adr/0031-device-management-adapters.md))

- **PLAT-040** Every profile MUST provide a **self-managed** `DevicePolicy` adapter, in which the runtime itself enforces the required restrictions, where the platform allows it.
- **PLAT-041** A profile MAY provide an **EMM-managed** adapter, in which another management service enforces them and the runtime only reads their state.
- **PLAT-042** `effectiveRestrictions()` MUST read each restriction from the platform's live state. It MUST NOT infer a restriction from configuration, managed configuration or the adapter's own earlier `apply` call. A restriction it can't read MUST be reported as `unknown`.
- **PLAT-043** At every session start and posture re-check, the runtime MUST compare `effectiveRestrictions()` with runtime policy's `device.requiredRestrictions`, and record each `missing` or `unknown` item as a posture finding.
- **PLAT-044** A posture finding MUST be included in the next posture report to the factory (REG §posture). It MUST NOT block sessions, collection, review, clear or delivery.
- **PLAT-045** Items that are invariants (secure display, hardware key storage) are not device-policy restrictions: if one becomes unmet, the runtime MUST refuse to open a session, as PLAT-030 requires for registration.
- **PLAT-046** Which adapter a device uses MUST come from its provisioning configuration ([Deployment](./deployment.md), DEP-024), never from the build.

### Transports ([ADR 0035](../../explanation/adr/0035-service-contracts-and-transports.md))

*Informative.* The `Network` port (§4) carries the runtime's calls to the factory and the upload endpoint. The Android runtime SHOULD use gRPC when it is simple to do so: through a gRPC client in the shared Rust core (`tonic` over rustls, compiled for the Android targets and exposed through the UniFFI binding behind the same client ports), so that no Kotlin gRPC stack is added. HTTP stays the fallback. The inbound-listener invariant (PLAT-022) is unaffected. This is built in slice 3, with the Android app; the gRPC contract itself is built in slice 2.

### The `web` profile ([ADR 0036](../../explanation/adr/0036-showcase-web-app-and-web-device.md))

A development-only profile for a browser tab, used by the showcase web app ([WEB](./web-app.md)). It runs the same domain and application code as every other profile, compiled to WebAssembly.

- **PLAT-100** The `web` profile MUST be development only. A build or deployment that selects it MUST present itself as an unattested software device wherever it shows or reports device state.
- **PLAT-101** The profile's `Storage` MUST meet the storage contract (PLAT §Storage): a write replaces a whole object, an append adds to the end, deleted objects are gone. Every change MUST be recorded in an ordered change log that the host persists transactionally (IndexedDB) before it reports an operation complete.
- **PLAT-102** The profile's `KeyStore` MUST use real P-256 signing, P-256 key agreement for HPKE and an authenticated wrapping cipher (AES-256-GCM), with keys from the browser's CSPRNG, and MUST meet the key-store contracts. Keys MUST NOT be exported through the port. Key material at rest SHOULD be wrapped by a non-extractable WebCrypto key.
- **PLAT-103** The profile's PIN hash MUST be Argon2id at or above the floor (COL §PIN); it MUST NOT be a weaker stand-in.
- **PLAT-104** `ElapsedClock` MUST be the page's monotonic clock with one boot per page load (ADR 0020). `WallClock` MAY be the page's `Date`. `FileAccess` MAY be a browser download; a download cannot be read back through its destination, so the profile MUST read back the bytes it handed to the browser and MUST NOT claim more.
- **PLAT-105** `DevicePolicy` MUST report every restriction as `unknown` (the management mode is "managed elsewhere"), so posture findings list them all (PLAT-043); findings do not block (PLAT-044).
- **PLAT-106** The `Attestor` MUST produce `software` evidence only, and the device MUST be registered as unattested (CLI-007, REG-017, TRU-061). It MUST NOT claim hardware protection.
- **PLAT-107** Deployment validation MUST refuse the adapter named `web` in an environment named `production` (DEP-023).
- **PLAT-108** `SecureDisplay` cannot be met by a tab. The profile MUST say so, MAY accept the runtime's request so the runtime can run, and SHOULD cover the capture while the tab is hidden. This is the one place the profile departs from PLAT-045, and it is acceptable only because of PLAT-107.
- **PLAT-110** A device on the profile MUST create its tenancy under a PIN, build a registration request from a token with its own keys (WIRE-130..134), verify and open a bundle in the order of WIRE-093 and DIS-030, and report the result of each security step.
- **PLAT-111** Registration requests from the profile MUST be byte-compatible with those a 64-bit device makes; the core MUST NOT depend on the pointer width.
- **PLAT-112** A bundle that fails any check MUST be refused and nothing in it used.
- **PLAT-113** Capture on the profile MUST evaluate rules and field checks with the core's evaluator, never with a re-implementation in the host language.
- **PLAT-114** A record MUST be sealed with the dual write of COL §4 on the profile's storage.
- **PLAT-115** The export MUST be assembled and verified by the core before it is offered (DEL §export).
- **PLAT-116** Upload MUST follow DEL §upload (receiver challenge against the trust bundle, proof of possession, upload), and receipts MUST be verified against the trust bundle before they are applied (DEL-064).

### Internationalisation and localisation ([ADR 0034](../../explanation/adr/0034-internationalisation-and-localisation.md))

- **PLAT-050** Every user-facing string of the runtime MUST come from a message catalogue in Unicode MessageFormat 2, keyed by stable message IDs. Strings MUST NOT be hard-coded or built by concatenation.
- **PLAT-051** The runtime UI language and the instrument language MUST be selectable separately. The collector MAY change the instrument language during a capture; the change MUST take effect at once and MUST NOT clear any value.
- **PLAT-052** Adapters MUST draw the render plan's direction: they MUST mirror layout for `rtl`, isolate bidirectional text, and never mirror numbers, scale step order or media. They MUST format and parse values with the format core's CLDR functions (INS-088), never the platform's default locale.
- **PLAT-053** A runtime build MUST ship a reference catalogue (all message IDs, with their variables and selectors) and catalogues for its built-in languages, and MUST report the reference version and the languages it can render at registration. It MAY load `Localisation` artefacts from bundles (DIS-017) after validating them against the reference catalogue. Messages that state a security outcome MUST show their message ID.
- **PLAT-054** Lists shown to collectors, such as rosters, MUST be sorted with CLDR collation for the UI language.
- **PLAT-055** Every profile's UI test suite MUST pass in the pseudo-locales `en-XA` (accented, about 40 % longer) and `ar-XB` (right-to-left), with no truncated, clipped or untranslated strings.

### Schema and constraint enforcement ([ADR 0037](../../explanation/adr/0037-extensions-and-strict-schema-enforcement.md))

- **PLAT-066** Every runtime MUST validate every document it reads (a bundle's contents, provisioning configuration, a localisation catalogue) with the format core's validator (WIRE-210). It MUST have no lenient mode.
- **PLAT-067** Every profile's UI MUST enforce every constraint of INS-252 in its input layer for every input path (typing, paste, hardware keyboard, assistive technology), MUST refuse as INS-253 defines, and MUST list in its `ControlCatalogue` the constraint kinds it enforces (INS-254).
- **PLAT-068** Every profile's UI test suite MUST pass the shared scenario corpus of INS-255 (suite `ins-ui-constraints`) in addition to PLAT-055.

## 6. Resources and formats

A profile's capability declaration is published with the runtime build:

```yaml
apiVersion: fieldseal.dev/v1alpha1
kind: PlatformProfile
metadata: { name: android, schemaVersion: 1.0.0 }
spec:
  os: { family: android, minVersion: "14" }
  declarations:
    PLAT-010: { level: hardware, notes: "StrongBox or TEE" }
    PLAT-013: { level: hardware, notes: "device-ID attestation when device owner" }
    PLAT-017: { level: software, notes: "factory reset blocked in settings; recovery reset caught by enterprise FRP" }
    PLAT-023: { level: unmet, notes: "depends on model; checked in the hardware spike" }
```

Attestation evidence formats are named by identifier (for example `android-key-attestation/1`, `apple-app-attest/1`, `tpm2-quote/1`); their byte layout is in WIRE §attestation.

### Future profiles

| Port | iOS / iPadOS | Windows | Linux |
|---|---|---|---|
| `KeyStore` | Secure Enclave (P-256 sign and ECDH) | TPM 2.0 via CNG / Platform Crypto Provider | TPM 2.0 via tpm2-tss |
| `Attestor` | App Attest | TPM key attestation, Windows Device Health Attestation | TPM 2.0 key certification and quotes |
| `ElapsedClock` | `mach_continuous_time` and boot session | `QueryUnbiasedInterruptTime` and boot ID | `CLOCK_BOOTTIME` and `/proc/sys/kernel/random/boot_id` |
| `SecureDisplay` | Partial: detect capture (`UIScreen.isCaptured`), hide in app switcher | `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` | Compositor-dependent; often `unmet` |
| `DevicePolicy` | Supervised device through MDM | Assigned Access and MDM (Intune or other) | Kiosk session, read-only system, full-disk encryption |
| `FileAccess` | Document picker, security-scoped URLs | Storage pickers | Portals (xdg-desktop-portal) |
| `Camera` | AVFoundation to memory | Media Foundation to memory | V4L2 / PipeWire to memory |

These are outlines only; each becomes normative in its own profile spec.

## 7. Twelve-factor

| Factor | Profiles |
|---|---|
| III. Config | Platform settings come from provisioning configuration via `DevicePolicy.managedConfiguration()` |
| IV. Backing services | Platform services (key store, camera, pickers) are attached through these ports |
| IX. Disposability | `Storage` writes are atomic, so the runtime can be killed at any point |
| X. Dev/prod parity | Same adapters in development; production differs only in trust and policy |
| XI. Logs | Adapter events go to the runtime's sealed diagnostic stream, without personal data |
| Other factors | Not applicable to adapters inside a device runtime |

## 8. Conformance

| Test | Covers | Check |
|---|---|---|
| Port contract suites run on device or emulator for every adapter | PLAT-001, PLAT-033 | Platform test harness; results attached to the profile release |
| The `web` profile's ports pass the port contracts; a browser device registers, verifies a bundle, captures, exports, uploads and lands in the intake | PLAT-100–PLAT-116 | `cargo test -p fieldseal-adapters-web` and the headless-browser run of the showcase |
| Declaration matches evidence produced on a real device | PLAT-002–003 | `fieldseal device simulate` cannot cover this; hardware lab |
| Practice-only mode when a registration requirement is unmet | PLAT-030 | Profile test with a stubbed key store |
| Session refused when device policy degrades | PLAT-031 | Profile test toggling a policy |
| Adapter logs contain no sensitive values | PLAT-032 | Log scanner |

## 9. Open questions

1. Is a profile acceptable whose secure display is `unmet` (some Linux compositors)? Factory policy could accept it for specific deployments only.
2. Should `PLAT-017` become Required once the Android hardware spike confirms enterprise factory-reset protection works on the procured model?

## 10. References

- ADRs: [0036](../../explanation/adr/0036-showcase-web-app-and-web-device.md), [0003](../../explanation/adr/0003-ddd-and-hexagonal-architecture.md), [0012](../../explanation/adr/0012-local-first-device-keys.md), [0017](../../explanation/adr/0017-runtime-authentication.md), [0024](../../explanation/adr/0024-platform-profiles.md), [0025](../../explanation/adr/0025-twelve-factor-deployments.md)
- OWASP MASVS v2 (storage, platform, resilience controls)
