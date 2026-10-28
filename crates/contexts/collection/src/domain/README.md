# collection::domain

## Overview
Entities, value objects and invariants of the Collection context (spec: [collection.md](../../../../../docs/reference/spec/collection.md) section 2; see also `platform-profiles.md` in the same folder). It models the device-side tenancy lifecycle, captures, the local record, record payloads, PIN accounting, ticks and the types that Distribution and Registration plug in through. Pure: no I/O; a capture "lives only in memory; nothing here touches storage".

## Interface
Public submodules and the items defined in `mod.rs`:
- `mod.rs`: `TenancyState` (`Local`, `Registered`, `Closing`, `Closed`, `Erased`); `RuntimePin` (`MIN_LENGTH` = 6, `new`, `digits`; `Debug` redacted); `ClearConfirmation::confirm` and `ClearConfirmationError` (`Mismatch`, `WrongPin`); `plan_clear`, `ClearPlan`, `Checkpoint`; `DeliveryState`; `ReceiptClaim`, `ReceiptCoverage` (`verify`, `address`, `time`, `tenancy`, `through`, `journal_hash`); `OperationKind`, `OperationMarker`; `StorageClass`, `StorageName`, `WindowId`; `Restriction` (`name`), `RestrictionState`, `ManagementMode`, `PostureFinding`, `posture_findings`; `CaptureConstraints`, `CapturedImage` (redacted `Debug`); `HashParams` (`meets_floor`).
- `bundle`: `OpenedBundle`, `RegistrationGrant`, `TimeAnchor`, `RosterSubject` (`fields`), `HeldRoster`, `CloseCertificate`: what `BundleOpener` and `CloseCertificateCheck` return.
- `capture`: `Capture` (`new`, `set_value`, `clear_value`, `override_soft`, `acknowledge_incomplete`, `go_to`, `readiness`, `sealed`, accessors), `CaptureMode` (`wire`, `as_str`), `CaptureStart`, `SealContent`, `SealBlock`, `CaptureError`, `question_refs`.
- `local`: `LocalNote`, `LocalEntryView`, `SubjectState`, `fold`.
- `meta`: `TenancyMeta` (`encode`, `decode`, `next_seq`, `lockout_delay_ms`, `cleared_through`), `Marker`, `ClearedPoint`.
- `payload`: `Payload` (record payload enum; `kind`, `tick`, `subject`, `to_value`, `encode`, `from_value`, `decode`), `StatusCode`, `ClosingReason`, `EvidenceRef`, `ImportedRoster`, `anchor_kind_str`, `EVIDENCE_MEDIA_TYPES` (`image/jpeg`, `image/png`, `image/webp`).
- `pin`: `PinAttempts` (`remaining`, `fail`, `succeed`, `encode`, `decode`).
- `ticks`: `TickState` (`new`, `next`, `rebase`, `to_value`, `from_value`), `first_non_monotonic`.

## Invariants
- A PIN is at least 6 decimal digits, is never stored, and is redacted in `Debug`.
- A `ClearConfirmation` can only be created by `confirm` (two equal entries, then session verification), is neither `Clone` nor `Copy`, and is consumed by `plan_clear`: every clear needs a fresh confirmation (COL-101).
- Sealing a capture is refused while a hard verdict or value problem holds, while a soft verdict has neither a changed answer nor a reason (COL-035), and in a first capture until the unanswered count is acknowledged (COL-036, COL-109). Values hidden by `when`/`skip` are cleared (INS-124).
- The local record stores no evidence bytes, only that evidence exists (COL-043); `TenancyMeta` holds no names, item values or PIN-derived values (COL-052, TRU-072).
- Tick slots are strictly increasing under the same anchor (COL-081, WIRE-071); after a boot-count change the slot continues from the high-water mark plus elapsed time (WIRE-072).
- Wrong-PIN counters are persisted wrapped by the hardware key; waits use the monotonic clock and a reboot restarts the current wait in full (COL-023).
- Collection still verifies every `Publication` itself before relying on it (PUB-073).

## Side Effects
None. Encoders/decoders operate on in-memory bytes; storage is done by [`../application`](../application/README.md) through the `SecureStorage` port.

## Verification
- Run: `cargo test -p fieldseal-collection` (repo-wide: `just test`)
