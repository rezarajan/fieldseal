# fieldseal-adapters-memory

## Overview

In-memory adapters for every driven port (ADR 0003 and ADR 0028; see [0028-clean-architecture.md](../../../docs/explanation/adr/0028-clean-architecture.md)). All state lives in memory and is deterministic. They are used by tests, by `fieldseal device simulate`, and as the reference for the contract tests. Anything they produce that a real adapter would attest is marked unattested. The crate also holds simulated authorities, devices and whole demo worlds, and the catalogue of contract cases behind `fieldseal conformance run --suite contracts` (the generated [conformance.md](../../../docs/reference/conformance.md)).

Layer: adapter. Depends on the kernel and the contexts `trust`, `instrument`, `policy`, `publishing`, `registration`, `distribution`, `collection`, `delivery`, `intake`, `deployment`. `fieldseal-adapters-file` and `fieldseal-adapters-landing-files` build on it.

**Not for production. Not cryptography, not a platform** where marked: the device key store's "signatures", wrapping and "attestation", the toy memory-hard hash, receipt and close-certificate authorities, and `SeededRandom` are deterministic stand-ins from a non-cryptographic hash. Record signatures, seals, publications, time tokens, HPKE seals and transparency-log proofs are the real wire formats, but keys sit in process memory, not behind a hardware boundary.

## Interface

Modules (all public in `src/lib.rs`) and the ports they implement:

| Module | Main symbols | Ports implemented |
| --- | --- | --- |
| `trust` | `MemoryKeyCustody<R>`, `MemorySecureKeyStore`, `SoftwareAttestationVerifier`, `MemoryRevocationSource`, `FixedClock`, `SeededRandom`, `MemoryKeyHolderRegistry`, `toy_digest` | Trust: `KeyCustody`, `SecureKeyStore`, `Attestor`, `AttestationVerifier`, `RevocationSource`, `AuthorityClock`, `RandomSource`, `KeyHolderRegistry` |
| `instrument` | `FullCatalogue` | Instrument: `ControlCatalogue` |
| `policy` | `BuiltInPolicyEngine`, `MemoryPolicySource`, `MemoryDecisionLog` | Policy: `PolicyEngine`, `PolicySource`, `DecisionLog` |
| `publishing` | `MemorySourceRepository`, `MemoryReviewSystem`, `PassThroughBuilder`, `AcceptingValidator`, `MemoryTransparencyLog<T: LogTransport>`, `MemoryArtefactRegistry` | Publishing: `SourceRepository`, `ReviewSystem`, `Builder`, `ArtefactValidator`, `TransparencyLog`, `ArtefactRegistry` |
| `registration` | `MemoryRegistryStore`, `MemoryIdentityProvider`, `MemoryReceivedProgress`, `MemoryFleetRegistry`, `MemoryNotifier`, `DevAuthority<R>`, `dev_authority(...)`, `software_evidence(...)`, `SoftwareDevice` | Registration: `RegistryStore`, `IdentityProvider`, `ReceivedProgress`, `FleetRegistry`, `Notifier` |
| `distribution` | `MemoryRosterSource`, `MemoryAnchorSource`, `sign_time_token`, `MemoryTrustStore`, `MemoryBundleStore`, `SoftwareAgreementKey`, `MemoryRuntimeProfiles` | Distribution: `RosterSource`, `AnchorSource`, `TrustStore`, `BundleStore`, `AgreementKey`, `RuntimeProfiles` |
| `collection` | `MemoryElapsedClock`, `MemorySecureStorage`, `MemorySecureDisplay`, `MemoryDevicePolicy`, `MemoryCamera`, `ToyMemoryHardHash`, `ToyReceiptAuthority`, `SimulatedKeyStore`, `MemoryWallClock`, `MemoryFileSource`, `MemoryBundleOpener`, `ToyCloseAuthority`, `LocalTransport`, `SimulatedAuthority`, `SimulatedDevice`, `BundleSpec`, `roster_address`, `SIMULATION_T0` | Collection: `ElapsedClock`, `SecureStorage`, `SecureDisplay`, `DevicePolicy`, `Camera`, `MemoryHardHash`, `ReceiptCheck`, `SecureKeyStore`, `Attestor`, `WallClock`, `FileAccess`, `BundleOpener`, `CloseCertificateCheck`, `LogTransport` |
| `bundle_opener` | `FileBundleOpener<'a>` | Collection: `BundleOpener` over Distribution's `VerifyBundle` (real `FSB1` bundles, WIRE-090..095, DIS-030) |
| `delivery` | `MemoryFileAccess`, `MemoryShareTarget`, `MemoryPrivateStorage`, `MemoryQrScanner`, `MemoryRegistrationRecords`, `MemoryPopLedger`, `LoopbackTransport`, `refusal_to_error`, `POP_HEADER_NAME` | Delivery: `FileAccess`, `ShareTarget`, `PrivateStorage`, `QrScanner`, `RegistrationRecords`, `PopLedger`, `UploadTransport` (in-process endpoint to Intake's gate) |
| `delivery_world` | `Bench`, `Enrolled`, `Enrolment`, `IntakeSide`, `window()` | none (a simulated device and an intake in one process) |
| `intake` | `MemorySubmissionStore`, `MemoryTenancyRegistry`, `MemoryRosterHistory`, `MemoryInstrumentSource`, `MemoryDataPlatform` | Intake: `SubmissionStore`, `TenancyRegistry`, `RosterHistory`, `InstrumentSource`, `DataPlatform` |
| `intake::practice` | `PracticeAuthority`, `PracticeDevice`, `Written`, `JournalBuilder`, `ExportSpec`, `tick`, `manifest_for`, `key_entry`, `key_id_of`, `closing`, `at`, `T0`, `DAY`, `CALLER` | none (fixed-seed practice authority and device that build exports for gate tests) |
| `deployment` | `MemoryBuildRegistry`, `MemorySecretStore`, `MemoryDocumentationSink` | Deployment: `BuildRegistry`, `SecretStore`, `DocumentationSink` |
| `demo` | `DemoWorld`, `DemoDevice`, `DemoPolicy`, `EdgeServices`, `DEMO_SCHEMA` | none (a whole seeded demo factory: trust bundle, log, tenancies, rosters, release policy, bundle builder) |
| `conformance` | `ContractCase { context, port, contract, adapter, requirements, run }`, `contract_cases()` | none (runs each context's `contract` functions against the adapters above) |

## Invariants

- Deterministic: same inputs and seeds give the same bytes (`SeededRandom`, `FixedClock`, fixed-seed `demo` and `practice` worlds).
- Everything the simulated device key store produces is unattested (`SecurityLevel::Software`, evidence format `SOFTWARE_EVIDENCE_FORMAT`); production factory policy refuses it (TRU-061).
- `MemoryTransparencyLog` is a real RFC 9162 Merkle log (SHA-256) with C2SP signed-note checkpoints made with a real P-256 key, and it sends every request through its `LogTransport`, so the ADR 0030 contract applies unchanged. Its key derives from its origin unless given: a test or simulator log, never a public one.
- `FileBundleOpener` runs all of DIS-030 verification except the checks against what the runtime already holds (sequence number, roster versions), which Collection makes; verified trust updates are applied to the runtime's trust store.
- The practice device writes whatever records it is told to, in any order, so tests can break each rule on purpose.
- A `ContractCase::run` panics when an adapter breaks its contract; a runner that must survive failures runs each case in its own process.

## Side Effects

- None outside the process: the crate source contains no filesystem, network, environment or system-clock access. State is in memory (some behind `Mutex` or atomics). Time and randomness are injected (`FixedClock`, `SeededRandom`, `MemoryWallClock`, `now` closures).
- `LoopbackTransport` and `LocalTransport` connect components in-process without a network.
- `ContractCase::run` panics on contract violations by design.

## Verification

- Run: `cargo test -p fieldseal-adapters-memory` (repo-wide: `just test`)
