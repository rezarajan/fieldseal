# fieldseal-intake

## Overview
The Intake bounded context: the authority-side pipeline that receives exports and uploads, verifies them through a fixed-order gate, lands observations in a generic long format, issues receipts, manages consent decisions, derives subject state, and generates data contracts from published instruments. Spec: [intake.md](../../../docs/reference/spec/intake.md); layering per ADR 0028. The crate is pure and holds no instrument-specific code (INT-058): storage, registry, platform and keys come through ports.

## Interface
`lib.rs` exposes `application`, `contract`, `data_contract`, `domain`, `gate`, `landing`, `ports`, `upload`, `wire`.
- [`gate`](./src/gate/README.md): `IntakeService` (`ingest`, `dry_run`), `IngestReport`, `IssuedReceipt`, `LandingSummary`, `RecordOutcome`; the 13 stages of INT-001.
- `application`: traits `IngestSubmission`, `ReplaySubmission`, `QuerySubjectState`, `DecideConsent` (`decide`, `reverse`), all but the last implemented by `IntakeService`; `ConsentDesk::new(platform, custodians)` implements `DecideConsent`; function `data_contract`; `IntakeError` (`TooLarge`, `Unreadable`, `NotAuthorised`, `NotPending`, `InvalidDecision`, `UnknownSubmission`, `UnknownInstrument`, `Backend`).
- `domain`: `Submission` (`received`, `advance`, `record`, `reject`), `SubmissionId` (SHA-256 of raw bytes), `SubmissionSource`, `GateState` (`may_move_to`), `Stage`, `Code`, `Rejection`, `Finding`/`FindingKind`, `TenancyView`, `IssuedRoster`/`IssuedConsent`, `ConsentCase`/`ConsentDecision`/`ConsentBasis`/`DecisionTrail`, `LossLedgerEntry`, `Observation`/`ObservedValue`/`Nonresponse`/`Reading`, `LandedObservation`, `LandedEnvelope`.
- `landing`: `land_record`, `RunningState`, `RecordContext`, `RecordFrame`, `is_retraction`, `fold_subject_state`, `SubjectState`, `ItemState` (including `Conflict`), `Candidate`.
- `data_contract`: `generate_data_contract`, `DataContract`, `ContractItem`, `ContractGroup`, `ContractCode`, `ContractCodeList`, `ContractConcept`, `Expectation`, `Severity`, `LongColumn`, `LONG_COLUMNS` (20 columns), `decimal_text`.
- `upload`: `UploadService` (`answer_challenge`, `authenticate`, `receive`), `UploadRefusal` (`BadRequest`, `TokenRejected`, `Rejected`, `Backend`), `POP_WINDOW_MS` (300 000), `MAX_CHALLENGE` (256), `TOKEN_HEADER`.
- `wire`: `ExportManifest`, `TenancyCertificate`, `CloseCertificate`, `RegistrationBody`, `Receipt` (`encode`, `decode`, `to_text`, `from_text`), `Payload`, `KeyEntry`, `CertWindow`, `ManifestEnd`, `AnchorKind`, `ClosingReason`, `EvidenceRef`, `ImportedRoster`, `MAX_RECEIPT` (300), `EVIDENCE_MEDIA_TYPES`, helpers `record_id_hex`, `uint_of`.
- `ports` (driven): `PopLedger` (`first_use`), `SubmissionStore` (`put`, `get`), `TenancyRegistry` (`by_handle`, `by_id`), `RosterHistory` (`issued`), `InstrumentSource` (`instrument`), `DataPlatform` (`land`, `exclude`, `reinstate`, `observations`, `envelopes`, `evidence`, `consent_case`, `consent_cases`, `losses`, `findings`), `LandingBatch`, plus an error enum per port. Also used: Trust's `KeyCustody` and `RandomSource`, Policy's `PolicyEngine`.
- `contract`: `submission_store_contract`, `tenancy_registry_contract`, `roster_history_contract`, `instrument_source_contract`, `data_platform_contract`, `pop_ledger_contract`, helper `sample_observation`.

## Invariants
- Gate stages run in the fixed INT-001 order and the first failure stops the run; a refused submission comes back as `Ok` with state `Rejected`, not as an error.
- Landing is atomic and append-only; exclusion is a flag, never a deletion (INT-039, INT-055). Observations are keyed by instrument fingerprint, never by name (INT-070).
- Item values are converted with the instrument's exact unit factors (INS-161); `not-applicable` rows are derived for items hidden by `when`/`skip` (INS-142); absent items produce no rows (INT-052).
- Subject state: related tenancies apply in ascending `(generation, seq)`, last write wins; unrelated tenancies are never ordered, and differing latest values become `ItemState::Conflict` (INT-054); excluded rows are omitted and a retraction removes the value (INT-053 to INT-055).
- `SubmissionStore` is write-once, addressed by SHA-256; re-storing returns the same ID. `PopLedger::first_use` is true once per `(tenancy, jti)` until expiry. `InstrumentSource` returns only verified publications whose fingerprint matches. `TenancyRegistry` is read-only. `RosterHistory` is complete, ordered by cohort then ascending version. `DataPlatform::land` is atomic; consent cases replace by `(tenancy, subject, instrument)`.
- Wire decoders reject unknown fields (WIRE-005) and return a WIRE error code, never a partial value.
- Only configured custodians may decide consent, and a custodian may only accept or reject (`InvalidDecision`); reversal excludes dependent observations by flag.
- Uploads authenticate by proof-of-possession token within a 5-minute `iat` window with replay protection; the receiver challenge answer is independent of the address used (WIRE-182).

## Side Effects
None in this crate itself. Through ports: raw submissions stored (`SubmissionStore`), landing batches, exclusions and consent decisions written (`DataPlatform`), authority key use (`KeyCustody`: record unsealing and receipt signing), PoP identifiers remembered (`PopLedger`). Consent decisions are logged with who made them and when (INT-040, INT-061).

## Verification
- Run: `cargo test -p fieldseal-intake` (repo-wide: `just test`)
