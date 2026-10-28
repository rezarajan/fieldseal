# intake::gate

## Overview
The verification gate and landing of the Intake context (spec: [intake.md](../../../../../docs/reference/spec/intake.md), INT-001 to INT-014 and INT-020). It takes an unknown export or upload to landed records in the fixed stage order of INT-001. `mod.rs` defines `IntakeService` and the report types; the stage implementations live in private submodules (`framing`, `records`, `replay`, `consent`, `landing`). Pure: keys are used via `KeyCustody`, time is passed in, randomness comes from `RandomSource`, and all storage goes through ports.

## Interface
Public items (`mod.rs`):
- `IntakeService<'a>`: fields `store` (`SubmissionStore`), `registry` (`TenancyRegistry`), `rosters` (`RosterHistory`), `instruments` (`InstrumentSource`), `platform` (`DataPlatform`), `custody` (`KeyCustody`), `policy` (`PolicyEngine`), `effective` (`EffectivePolicy`), `random` (`RandomSource`), `trust` (`TrustBundle`), `revocations`, `receipt_key`, `caller`. Methods: `ingest(bytes, source, now)` and `dry_run(bytes, source, now)`, both returning `IngestReport`.
- `IngestReport` (submission, receipts, summary, losses, consent, records), `IssuedReceipt` (receipt and canonical bytes, at most 300), `LandingSummary` (landed, duplicates, held, conflicts, observations, flagged), `RecordOutcome` (`Landed`, `Duplicate`, `Held`, `Conflict`).
- Also `IngestReport::empty(submission)` for a report with no results.

Stages, by private module:

| Stage | Module | Fails with |
|---|---|---|
| 1 size and framing, 2 parity repair, 3 export signature | `framing.rs` | `INT-003`, `E_FRAME_*`, `E_VERSION`, `E_EXPORT_SECTION`, `E_SIG`, `INT-004`; repair or partial-loss path (INT-020) |
| 4 certificate chain, 5 key history, 6 journal chain and checkpoints, 7 record decryption, 8 payload decoding, 9 ticks and anchors | `records.rs` | `E_SIG`, `E_HASH`, `INT-006`, `E_CRC`, `E_CHAIN`, `E_SEQ`, `E_RECIPIENT`, `E_DECRYPT`, `E_UNKNOWN_FIELD`, `E_SIZE`, `E_TICK`, `INT-011` |
| 10 rule replay | `replay.rs` | quarantines records (INT-012) |
| 11 consent decisions | `consent.rs` | quarantines or excludes records (INT-030 to INT-039) |
| 12 replay and duplicates, 13 receipts | `landing.rs` | quarantines conflicts (INT-013); `E_SIG` |

The state machine is `crate::domain::GateState::may_move_to`; rejections are `crate::domain::Rejection` with a `Stage` and `Code`.

## Invariants
- A stage that rejects stops the run: no later stage executes, so a later fault is never reported while an earlier one exists.
- Nothing is landed unless every stage passed, and landing is one atomic `DataPlatform::land` write. Backend failure returns `Err(IntakeError::Backend)` and lands nothing.
- A refused submission is not an error: `ingest` returns `Ok` with state `Rejected`.
- Nothing is decrypted before file and record signatures are checked; ticks are inside the sealed payload so records are decrypted before ticks are checked; rule replay precedes consent decisions.
- Every `items` record about a subject must reference a consent basis preceding it in the chain; failing records are held (quarantined); rejected or pending bases exclude observations by flag, never deletion.
- Each `items` record is replayed alone, as the device sealed it, and quarantined if its verdicts differ from the runtime's.
- The same record hash landed twice is a `Duplicate` and changes no landed value (INT-013); receipts are issued per acknowledged tenancy part (INT-014).
- `dry_run` runs every stage and writes nothing to the data platform.

## Side Effects
- `ingest` stores the raw bytes first (`SubmissionStore::put`, write-once), then, on success, one `DataPlatform::land`.
- Uses authority keys through `KeyCustody` (record-key unsealing and receipt signing, recorded under `caller`); consumes randomness for consent sampling; reads registry, roster history and instruments.

## Verification
- Run: `cargo test -p fieldseal-intake` (repo-wide: `just test`)
