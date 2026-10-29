# Collection

**Prefix:** `COL` · **apiVersion:** `fieldseal.dev/v1alpha1` · **Status:** Draft

## 1. Scope

This spec defines the runtime's behaviour on a device, independent of platform.

**Owns:**
- the tenancy lifecycle on the device;
- the runtime PIN and sessions;
- capture flows, consent recording and evidence capture;
- dual write to the journal and the local record;
- review with field checks;
- clear;
- close and forced close, and the outbox;
- identity handling in memory;
- crash safety.

**Does not own:**
- platform adapters and how they meet these requirements ([Platform profiles](./platform-profiles.md));
- registration ([Registration](./registration.md));
- bundle verification ([Distribution](./distribution.md));
- exports and uploads ([Delivery](./delivery.md));
- record bytes and ticks (WIRE §records, WIRE §journal, WIRE §ticks).

## 2. Domain model

| Element | Type | Meaning |
|---|---|---|
| `Tenancy` | Aggregate root | The device-side tenancy: keys (by reference), state, window, held bundle, journal, local record, outbox entries. |
| `Session` | Entity | An unlocked period, opened with the runtime PIN, closed by lock rules. Holds the session key and decrypted bundle contents in memory. |
| `RuntimePin` | Value object | The collector's PIN for this tenancy; never stored. |
| `Capture` | Entity | An in-progress collection for one subject: pending item values, the stage reached, verdicts and acknowledgements. Lives only in memory. |
| `Record` | Value object | An immutable sealed unit (WIRE §records): `survey`, `status`, `consent`, `evidence`, `anchor`, `import`, `checkpoint` or `closing`. |
| `Journal` | Entity | The append-only, hash-chained sequence of records, sealed to the authority. |
| `LocalRecord` | Entity | The readable copy of the tenancy's records under the session key, folded into current state per subject. |
| `FieldCheckResult` | Value object | A raised field check with the records involved ([Instrument](./instrument.md)). |
| `DeliveryState` | Value object | For each `seq`: `none`, `handed-over`, `saved-and-checked`, `received` ([Delivery](./delivery.md)). |
| `Checkpoint` | Value object | `cleared_through_seq` and the journal hash at that point. |
| `Outbox` | Entity (device level) | Closed tenancies' journals with their closing manifests, waiting for delivery. |
| `OperationMarker` | Value object | Persisted progress of a multi-step operation (seal, clear, close, export), for resumption. |

**Tenancy states:** `local` → `registered` → `closing` → `closed` → `erased`. A forced close moves from any state to `closing`.

**Domain events:**
- `TenancyCreated`, `SessionOpened`, `SessionLocked`, `PinLockedOut`;
- `RecordSealed`, `ConsentRecorded`, `EvidenceCaptured`;
- `FieldCheckRaised`, `LocalRecordCleared`;
- `TenancyClosed`, `TenancyErased`.

## 3. Driving ports

| Port | Input | Output | Errors |
|---|---|---|---|
| `CreateTenancy` | New PIN | Tenancy in `local` state, keys created | `PlatformUnsupported` |
| `OpenSession` | PIN | `Session` | `WrongPin(wait)`, `LockedOut(until)` |
| `LockSession` | — | — | — |
| `StartCapture` | Subject, survey (instrument), mode (`first`, `resume`, `resurvey`) | `Capture` with starting values | `ConsentRefused`, `ConsentNeeded`, `NotInRoster` |
| `SetValue` / `ClearValue` | Item path, value | Updated verdicts | `NotEditable`, `OutOfRange` |
| `AcknowledgeIncomplete` | — | — | — |
| `RecordConsent` | Subject, survey, basis, statement version, optional evidence | Consent record sealed | `NotAllowed` |
| `Seal` | `Capture` (or pause) | Record sealed in journal and local record | `HardVerdict`, `IncompleteNotAcknowledged`, `SealFailed` |
| `RecordStatus` | Subject, survey, `absent` / `declines` / `not-them` | Status record sealed | `ConsentRefused` |
| `Review` | Filter (cohort, subject, check) | Records from the local record, and field-check results | — |
| `Clear` | Through `seq` | Checkpoint sealed; data deleted | `DeliveryConditionNotMet` |
| `EndTenancy` | — | Tenancy closed and erased | — |
| `ApplyCloseCertificate` | Certificate | Tenancy closed and erased | `InvalidCertificate` |

## 4. Driven ports

Each is provided by a platform adapter; the contracts are in [Platform profiles](./platform-profiles.md).

| Port | Used for |
|---|---|
| `KeyStore` | Creating, using and deleting the signing, agreement and session-wrapping keys |
| `Attestor` | Attestation evidence when keys are created |
| `ElapsedClock` | Monotonic elapsed time and boot count, for ticks |
| `SecureStorage` | Atomic, durable writes of the journal, local record, markers and outbox |
| `SecureDisplay` | Preventing screenshots, recent-task snapshots, content capture and overlays |
| `DevicePolicy` | Preventing other people from removing, resetting, debugging or clearing the runtime |
| `Camera` | Capturing evidence images straight into memory |
| `MemoryHardHash` | Argon2id for the PIN (format core) |

## 5. Requirements

### 5.1 Tenancy lifecycle

- **COL-001** A device MUST have at most one tenancy in `local`, `registered` or `closing` state.
- **COL-002** `CreateTenancy` MUST work without a network. It MUST create the tenancy's signing key, agreement key and session-wrapping key through `KeyStore`, with attestation evidence through `Attestor`, and MUST derive `tenancy_id` as WIRE §identifiers.
- **COL-003** In `local` state, the runtime MUST allow practice with a bundle that has no rosters, and MUST NOT allow collection about real subjects.
- **COL-004** Records made with a practice bundle MUST be marked as practice and MUST NOT be exported.
- **COL-005** A tenancy MUST enter `registered` when a verified tenancy certificate is installed ([Registration](./registration.md)).
- **COL-006** `EndTenancy` MUST:
  1. seal a `closing` record (final `seq`, journal hash);
  2. sign a closing manifest;
  3. delete all the tenancy's keys and its local record, held bundles and progress data;
  4. move the journal and closing manifest to the outbox;
  5. remove the runtime PIN's material.

  It MUST be confirmed with hold-to-confirm.
- **COL-007** `ApplyCloseCertificate` MUST verify the certificate's chain and tenancy ID, then perform steps 3–5 of COL-006, attaching the certificate in place of a closing record. It MUST NOT require the runtime PIN.
- **COL-008** The journal MUST be stored so that `ApplyCloseCertificate` can move it without the PIN. It is already sealed and signed; it MUST NOT be under the session key.
- **COL-009** Outbox entries MUST be removed only on a verified receipt covering them, or by the authority when the device is returned and reset.
- **COL-010** The runtime MUST let anyone using the device export or upload the outbox, because it holds only data sealed to the authority. It MUST NOT show anything from it except counts.

### 5.2 Runtime PIN and sessions

- **COL-020** The runtime PIN MUST be separate from the device's lock credential, and the runtime MUST NOT accept the device credential in its place.
- **COL-021** The PIN MUST be at least 6 digits, or longer if runtime policy requires (an invariant floor, [Policy](./policy.md)).
- **COL-022** The session key MUST be `HKDF(unwrap(wrapped_secret) ‖ Argon2id(PIN, salt))` (WIRE §session-key), where `unwrap` is performed by `KeyStore` with a key that requires an unlocked device and cannot leave the platform key store.
- **COL-023** Wrong PIN attempts MUST impose increasing waits as set by runtime policy, by default 30 s, 1 min, 5 min, 15 min, then 1 h each. The attempt counter MUST be stored with integrity protection in storage the device's other users cannot reset (`DevicePolicy`, `SecureStorage`).
- **COL-024** A session MUST lock when the runtime leaves the foreground, when the screen turns off, and after the idle timeout in runtime policy (default 2 minutes). Locking MUST drop the session key and decrypted data from memory, as far as the platform allows.
- **COL-025** The runtime MUST NOT offer biometric unlock.
- **COL-026** The signing and agreement keys MUST be used only while a session is open, except for `ApplyCloseCertificate` and outbox delivery, which use no tenancy keys.
- **COL-027** If the collector forgets the PIN, the runtime MUST explain that the authority can close the tenancy (reason `forgotten-pin`) and that sealed work is not lost.

### 5.3 Capture

- **COL-030** `StartCapture` MUST refuse a subject whose roster consent is `refused`, for every survey, and MUST NOT write any record about them, including status records.
- **COL-031** If the instrument requires consent and the roster says `unknown`, `StartCapture` MUST require a consent record for the subject first (§5.4). A roster's `granted` counts only for the surveys that the roster version covers (its `consent_covers`, WIRE-095, DIS-013): for a survey it does not cover, `StartCapture` MUST require a consent record for the subject first, exactly as for `unknown`. A survey assigned to the cohort after the roster was issued is not covered by it.
- **COL-032** In `first` mode every control MUST start unselected (INS-020). In `resurvey` mode controls MUST start from the subject's current values in the local record, and the record sealed MUST contain only the item paths whose values changed.
- **COL-033** `resume` mode MUST continue a paused capture from its stored position, showing earlier values from the local record as editable.
- **COL-034** Pausing MUST seal what has been set so far as a normal record. No unsealed capture MUST ever be written to storage.
- **COL-035** Sealing MUST be blocked while any hard verdict is unresolved or any soft verdict lacks a changed answer or a reason.
- **COL-036** If items are unanswered in `first` mode, sealing MUST be blocked until the collector acknowledges the count.
- **COL-037** Records MUST NOT be changed after sealing. A correction MUST be a new record made through `resurvey` mode.
- **COL-038** Leaving a capture with unsealed values MUST ask the collector first, and discarding MUST erase them from memory.
- **COL-108** A capture MUST be drawn from the render plan compiled by the format core for the instrument, the bundle's layout for the device's current window class (or the default layout), and the session's language (INS-206–INS-208). The runtime MUST seal every record of a capture with that layout's content address (INS-209). If the window class changes during a capture, the runtime MAY switch layouts only between records.
- **COL-109** The unanswered count (COL-036, COL-063) MUST count a nonresponse as answered (INS-141), and MUST NOT count questions hidden by a skip rule or `when`.

- **COL-111** A bundle MAY carry several instruments, and the runtime MUST hold every one with the layouts bound to it (INS-200). `StartCapture`, `RecordConsent` and `RecordStatus` MUST name the survey (the instrument) as well as the subject. When the bundle carries assignments (WIRE-096), the runtime MUST refuse a survey for a subject whose cohort the survey is not assigned to. Only a bundle that carries no assignments at all (a practice bundle, a bundle built by `fieldseal bundle build`, and a bundle built before assignments existed) allows every survey for every roster; a bundle built for an account with assignments none of which survived carries no instrument (DIS-018), so it allows nothing. Each record carries its own instrument's fingerprint, the local record keeps one state for each subject and instrument, and Review names the instrument of each state. Consent is the instrument's own (COL-031), so a person surveyed with two instruments may need consent twice.

### 5.4 Consent and evidence

- **COL-040** `RecordConsent` MUST record a basis from the instrument's list, the statement version, and optionally evidence references, and MUST be confirmed with hold-to-confirm.
- **COL-041** Survey records about a subject MUST carry a `consent_ref`: the consent record's ID, or the roster version for `granted` where that roster covers the record's survey (COL-031), or `not-required` (INS-062).
- **COL-042** Evidence images MUST come only from `Camera` capture into memory. The runtime MUST NOT offer a gallery or file picker for evidence, and MUST NOT write images to shared storage.
- **COL-043** An evidence image MUST be re-encoded at the instrument's maximum dimension with metadata (including location) removed before its SHA-256 is computed. It MUST be sealed only into the journal (an `evidence` record), not into the local record. The local record MUST note only that evidence exists.
- **COL-044** After sealing, the runtime MUST NOT display the evidence image again.

### 5.5 Dual write

- **COL-050** `Seal` MUST write the record to the journal, sealed to the authority's record key for the collection period (WIRE §records), and to the local record under the session key, as one recoverable operation (§5.9).
- **COL-051** The journal copy is the source of truth. If the two disagree after recovery, the runtime MUST rebuild the local record from what it can verify, and MUST NOT alter the journal.
- **COL-052** The local record MUST NOT contain names or other roster display fields. It holds subject IDs, item values, verdicts, reasons and delivery state.
- **COL-053** Every record MUST carry a tick (§5.8) and be signed by the tenancy's signing key.

### 5.6 Review

- **COL-060** Within a session, the collector MUST be able to review every record in the local record, grouped by cohort and subject, until it is cleared.
- **COL-061** Review MUST show each subject's current state (records folded in `seq` order, last write wins per item), the records that produced it, and each record's delivery state.
- **COL-062** Review MUST evaluate the instrument's field checks over the local record (INS-050–INS-053), show raised checks with the records involved, and let the collector open each record and start a resurvey from it.
- **COL-063** Review MUST also show the unanswered count per subject and any soft verdicts kept with a reason.

### 5.7 Clear

- **COL-070** *Withdrawn; replaced by COL-100–COL-107 ([ADR 0029](../../explanation/adr/0029-clear-anytime-with-pin-confirmation.md)).*
- **COL-071** *Withdrawn; replaced by COL-100–COL-107.*
- **COL-072** *Withdrawn; replaced by COL-100–COL-107.*
- **COL-100** The collector MUST be able to clear the local record through any `seq` at any time, whatever its delivery state.
- **COL-101** Every clear MUST be confirmed by entering the runtime PIN twice, as two separate entries; a mismatch or wrong PIN MUST cancel the clear and count toward lockout.
- **COL-102** Before confirmation, the runtime MUST show the number of records being cleared and the number not yet received, and state that sealed copies of undelivered records stay on the device until delivered.
- **COL-103** By default the runtime MUST wait for a receipt; when a verified receipt covers records, it MUST offer to clear them, and the offer MUST remain available afterwards.
- **COL-104** The runtime MUST NOT clear without the confirmation in COL-101.
- **COL-105** A clear through `N` MUST: (1) seal a `checkpoint` record with `cleared_through_seq = N` and the journal hash at `N`; (2) delete the local record's data for `seq ≤ N`; (3) delete journal records with `seq ≤ N` only where a verified receipt covers them.
- **COL-106** Journal records cleared from the local record but not yet received MUST be kept until a verified receipt covers them, and MUST then be deleted without further prompting.
- **COL-107** The journal MUST remain verifiable from the checkpoint onward (WIRE §journal).
- **COL-073** After a clear, review MUST show, with counts only, which cleared records were delivered and which are awaiting delivery.

### 5.8 Ticks

- **COL-080** Each record's tick MUST combine:
  - the hash of the latest anchor chained into the journal;
  - the elapsed time since that anchor from `ElapsedClock`, continued across reboots from the high-water mark persisted with the previous record;
  - the boot count;
  - the wall-clock time as an untrusted hint (WIRE §ticks).
- **COL-081** Ticks MUST strictly increase along the journal.
- **COL-082** Anchors from bundles, receipts and time tokens MUST be chained into the journal as `anchor` records when first seen.
- **COL-083** No irreversible action MUST be triggered by time on the device. Outside the tenancy window the runtime MUST only warn.

### 5.9 Identity, persistence and crash safety

- **COL-090** Names and other roster display fields MUST exist only in memory, during a session, decrypted from the held bundle. They MUST NOT be written to any storage, log, saved state or navigation argument.
- **COL-091** The runtime MUST require from its platform adapters:
  - secure display on every window;
  - no backup of its data;
  - no content capture or suggestions;
  - no personalised keyboard learning;
  - an allow-list of accessibility services;
  - no core dumps.

  A platform profile that cannot meet one MUST declare it ([Platform profiles](./platform-profiles.md)).
- **COL-092** Every multi-step operation (seal, clear, end tenancy, apply close certificate, export) MUST persist an `OperationMarker` before its first irreversible step, and MUST resume or complete from it after a crash or power loss.
- **COL-093** Each storage write MUST be atomic. A torn journal frame MUST be detected and truncated on recovery without losing earlier records (WIRE §journal).
- **COL-094** The runtime MUST NOT listen for inbound network connections.
- **COL-110** Every reader of a structure the runtime reads back from its own storage or from a scenario file (the local-record note, PIN attempt state, capture progress, the applied-policy record, the outbox entry, the tenancy metadata and the tick state, and a `device simulate` scenario and its steps) MUST reject unknown fields, enforce exact types, and enforce every declared constraint: required fields, fixed byte lengths, enumerations matched exactly, ranges, and uniqueness of repeated entries. A structure that cannot be read this way MUST fail closed; it MUST NOT be read with defaults for what is missing or ignored.

## 6. Resources and formats

Collection defines no resource files. Runtime behaviour is configured by runtime policy ([Policy](./policy.md)), for example:

```yaml
runtime:
  pin: { minLength: 6, failuresBeforeLockout: 5, lockoutSteps: [30s, 1m, 5m, 15m, 1h] }
  session: { idleLock: 2m, lockOnBackground: true, lockOnScreenOff: true }
  retention: { offerClearOnReceipt: true, remindAfter: 7d }
```

## 7. Twelve-factor

- **Config (III):** nothing deployment-specific is in the runtime build. Trust bundles and initial configuration come from device provisioning; runtime policy comes in bundles.
- **Backing services (IV):** the factory and time source are named in tokens, certificates and bundles, and upload destinations are untrusted hints authorised by receiver keys (Delivery DEL-060–DEL-066); none are compiled in.
- **Build, release, run (V):** one signed runtime build per platform; a release is that build plus a deployment's provisioning configuration; a run is a tenancy.
- **Processes (VI):** all durable state is the journal, local record, markers and outbox, behind `SecureStorage`. The UI process can be killed at any time.
- **Disposability (IX):** COL-092 and COL-093.
- **Dev/prod parity (X):** the same build runs in development and production; only the trust bundle and policy differ.
- **Logs (XI):** structured diagnostic events to a bounded local stream, never containing personal data, uploaded with telemetry when online.
- **Port binding (VII):** deliberately not used (COL-094).
- **Concurrency (VIII) and admin processes (XII):** not applicable on the device. `fieldseal device simulate` runs the same use cases for tests.

## 8. Conformance

| Test | Requirements | Command |
|---|---|---|
| Tenancy lifecycle, including close and forced close | COL-001–COL-010 | `fieldseal device simulate --scenario lifecycle`, `fieldseal conformance run --suite col-lifecycle` |
| PIN derivation, lockout and session locks | COL-020–COL-027 | `fieldseal conformance run --suite col-session`; platform UI tests |
| Capture modes, pause, resurvey diffs, refused consent | COL-030–COL-038 | `fieldseal device simulate --scenario capture` with golden records |
| Consent and evidence handling | COL-040–COL-044 | `fieldseal device simulate --scenario consent`, `fieldseal export inspect` |
| Dual write and recovery | COL-050–COL-053, COL-092, COL-093 | `fieldseal conformance run --suite col-crash` (fault injection at every step) |
| Review and field checks | COL-060–COL-063 | `fieldseal device simulate --review` |
| A bundle holds every instrument it carries; a survey is conducted only with the cohorts it is assigned to; records carry their own instrument | COL-111 | `fieldseal conformance run --suite col-lifecycle` |
| Captures follow the render plan and name their layout; nonresponse counted as answered | COL-108, COL-109 | `fieldseal device simulate --layout`, `fieldseal export inspect` |
| Clear at any time with twice-entered PIN; journal kept until receipt | COL-073, COL-100–COL-107 | `fieldseal device simulate --scenario clear`, `fieldseal export verify` |
| Ticks | COL-080–COL-083 | `fieldseal export verify --ticks`, `fieldseal intake replay` |
| Persistence controls on a platform | COL-090, COL-091, COL-094 | Platform profile test suite |
| Closed schemas on every stored structure and scenario (an unknown field, a wrong type, a broken constraint, a missing field, and a valid input each) | COL-110 | `bundle.rs`, `pin.rs`, `local.rs` unit tests; `col_110_scenario_*` in `device.rs` |

## 9. Open questions

1. Should the local record be kept for a configurable time *after* clear for subjects still in the cohort, for example the latest values only, to support a later resurvey? The current position is no.
2. Should practice records (COL-004) be kept for the collector to review, or deleted when the session locks?
3. Is a 2-minute idle lock right for long measurement sessions, or should policy allow a longer lock while a capture is open?

## 10. References

- [ADR 0012](../../explanation/adr/0012-local-first-device-keys.md), [ADR 0016](../../explanation/adr/0016-tenancies-with-crypto-erase.md), [ADR 0017](../../explanation/adr/0017-runtime-authentication.md), [ADR 0018](../../explanation/adr/0018-dual-write-records.md), [ADR 0019](../../explanation/adr/0019-review-until-clear.md), [ADR 0020](../../explanation/adr/0020-monotonic-ticks.md), [ADR 0022](../../explanation/adr/0022-consent-bases.md), [ADR 0024](../../explanation/adr/0024-platform-profiles.md), [ADR 0025](../../explanation/adr/0025-twelve-factor-deployments.md)
- [Wire formats](./wire-formats.md), [Instrument](./instrument.md), [Policy](./policy.md), [Registration](./registration.md), [Distribution](./distribution.md), [Delivery](./delivery.md), [Platform profiles](./platform-profiles.md)
- NIST SP 800-88 Rev. 2 (cryptographic erase); RFC 9106 (Argon2)
