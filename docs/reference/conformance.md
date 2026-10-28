# Conformance

How Fieldseal checks itself against its specs: what `fieldseal conformance` runs, how port contracts are organised, and which adapter passes which contract. Specs are in [spec/](./spec/README.md); every test names the requirement IDs it covers.

## The command

```sh
fieldseal conformance run [--suite <name>[,<name>…]] [--json]   # run suites; report pass or fail per requirement ID
fieldseal conformance list                                       # the suites
fieldseal conformance matrix                                     # the table below
```

`run` exits `0` when every check passes and `1` otherwise. Each requirement ID passes only if every check that names it passes. `--json` prints one document with `requirements` (status, number of checks, failures), `external_contracts` and a `summary`.

Each unit (a golden vector file, or one contract against one adapter) runs in its own `fieldseal` process, so a contract that panics, or a release build that aborts, is reported as a failure of that unit's requirements and never as a missing result.

| Suite | What it runs |
|---|---|
| `wire` | The golden wire vectors (WIRE §8): CBOR, identifiers, signatures, seals, frames, records, exports, local record entries, animated QR sequences, proof-of-possession tokens, receipts, time tokens and the receiver challenge |
| `trust` | Certificate, revocation, trust-bundle and chain vectors, and the trust ports' contracts |
| `publishing` | Provenance, log-entry and publication vectors, and the publishing ports' contracts |
| `transparency-log` | The `TransparencyLog` contract and the log-entry vectors (PUB §8) |
| `distribution` (`dis-verify`) | The bundle file vector and the distribution ports' contracts |
| `ins-rules`, `ins-eval` | Rule grammar and bounds, unset propagation and verdicts |
| `policy` | The policy engine cases and the policy ports' contracts |
| `contracts` | Every port contract against every in-process adapter |
| `collection`, `delivery`, `deployment`, `instrument`, `intake`, `registration` | One context's port contracts |
| `all` (default) | Everything |

The context suites run the same cases as the context test suites, in process against the simulated authority, device and in-memory adapters; each check names the requirement IDs it exercises.

| Suite | Spec table row | Requirements named |
|---|---|---|
| `col-lifecycle` | Tenancy lifecycle, close and forced close | COL-001 to COL-003, COL-005 to COL-010 |
| `col-session` | PIN derivation, lockout and session locks | COL-021 to COL-024, COL-026, COL-027, COL-101 |
| `col-crash` | Dual write and recovery, with fault injection at every storage step | COL-050 to COL-053, COL-092, COL-093 |
| `reg-token` | Token fields, single use, factory-side expiry | REG-002, REG-002a, REG-004 to REG-006 |
| `reg-verify` | Verification order and fail-closed | REG-010, REG-011, REG-013 to REG-015, REG-017 |
| `reg-revoke` | Roll, lost, close certificate, forgotten PIN | REG-060 to REG-065 |
| `reg-attacks` | The attack table in the registration spec, 5.9 | REG-002, REG-003, REG-005 to REG-006, REG-010 to REG-015, REG-017, REG-021, REG-041, REG-062, REG-063, REG-070 |
| `dis-release` | Release refused before registration and for flagged tenancies | DIS-001 to DIS-004 |
| `ins-checks` | Field checks raise on golden record sets | INS-050 to INS-053 |
| `ins-locale` | Language lookup, locale formatting, native-digit input | INS-087 to INS-089 |
| `ins-codes` | Code lists: exclusive, other, ordered, numeric values | INS-048, INS-131 to INS-137 |
| `ins-nonresponse` | Nonresponse recorded, cleared and counted as answered | INS-140 to INS-143 |
| `ins-units` | Entry units and money convert exactly | INS-160 to INS-163 |

Not in these suites, because they need a platform or a feature no code exercises yet: the persistence controls of a platform (COL-090, COL-091, COL-094), practice records (COL-004), the PIN's separation from the device lock (COL-020), seal immutability and evidence handling (COL-037, COL-042, COL-044), the request and certificate field lists (REG-012 as a whole, REG-032), air-gapped operation (REG-050), and INS-051 beyond the review check. Their IDs stay uncovered in `tools/check-coverage.py` until a check names them.

## Port contracts

Every driven port (a trait in a context's `ports.rs`) has contract functions in that context's `contract.rs`. A contract is run against the in-memory adapter and against each real adapter ([ADR 0028](../explanation/adr/0028-clean-architecture.md)). The in-memory adapters' cases are catalogued in `crates/adapters/memory/src/conformance.rs`; the CLI's own adapters and the file adapters are registered in `crates/apps/cli/src/conformance_cmd/contracts.rs`. Adapters marked *(cargo test)* need a fixture the binary doesn't carry (a mock Rekor, an OIDC mock, a loopback intake server) and run under `cargo test` with the command shown by `conformance run --json` under `external_contracts`.

A test (`crates/apps/cli/tests/conformance.rs`) fails when a port in a `ports.rs` has no contract run, when an adapter implementing a port isn't registered, or when this table is out of date.

### Port, contract and adapters

<!-- Generated by `fieldseal conformance matrix`; do not edit by hand. A test keeps it current. -->

| Context | Port | Contract | Adapters that pass it |
|---|---|---|---|
| collection | `BundleOpener` | `bundle_opener_contract` | `MemoryBundleOpener`, `FileBundleOpener` (cargo test), `WebBundleOpener` (cargo test) |
| collection | `Camera` | `(web profile: always unavailable; no shared contract applies)` | `WebCamera` (cargo test) |
| collection | `Camera` | `camera_contract` | `MemoryCamera` |
| collection | `CloseCertificateCheck` | `close_certificate_check_contract` | `ToyCloseAuthority` |
| collection | `DevicePolicy` | `(web profile: every restriction unknown; no shared contract applies)` | `WebDevicePolicy` (cargo test) |
| collection | `DevicePolicy` | `device_policy_emm_contract` | `MemoryDevicePolicy` |
| collection | `DevicePolicy` | `device_policy_self_managed_contract` | `MemoryDevicePolicy` |
| collection | `ElapsedClock` | `elapsed_clock_contract` | `MemoryElapsedClock`, `WebElapsed` (cargo test) |
| collection | `FileAccess` | `file_access_contract` | `MemoryFileSource` |
| collection | `MemoryHardHash` | `memory_hard_hash_contract` | `ToyMemoryHardHash`, `ArgonHash` (cargo test) |
| collection | `ReceiptCheck` | `receipt_check_contract` | `ToyReceiptAuthority`, `TrustReceiptCheck` (cargo test) |
| collection | `SecureDisplay` | `secure_display_contract` | `MemorySecureDisplay`, `WebDisplay` (cargo test) |
| collection | `SecureKeyStore` | `record_signing_key_store_contract` | `SimulatedKeyStore` |
| collection | `SecureStorage` | `secure_storage_contract` | `MemorySecureStorage`, `WebStorage` (cargo test) |
| collection | `WallClock` | `wall_clock_contract` | `MemoryWallClock`, `WebWall` (cargo test) |
| delivery | `FileAccess` | `file_access_contract` | `MemoryFileAccess`, `WebDownloads` (cargo test) |
| delivery | `PrivateStorage` | `private_storage_contract` | `MemoryPrivateStorage` |
| delivery | `QrScanner` | `qr_scanner_contract` | `MemoryQrScanner` |
| delivery | `ReceiverCheck` | `receiver_check_contract` | `TrustReceiverCheck` (cargo test) |
| delivery | `RegistrationRecords` | `registration_records_contract` | `MemoryRegistrationRecords` |
| delivery | `ShareTarget` | `(web profile: no share sheet; no shared contract applies)` | `NoShare` (cargo test) |
| delivery | `ShareTarget` | `share_target_contract` | `MemoryShareTarget` |
| delivery | `UploadTransport` | `upload_transport_contract` | `LoopbackTransport` (cargo test), `HttpUploadTransport` (cargo test), `BrowserTransport` (cargo test) |
| deployment | `BuildRegistry` | `build_registry_contract` | `MemoryBuildRegistry` |
| deployment | `DocumentationSink` | `documentation_sink_contract` | `MemoryDocumentationSink` |
| deployment | `SecretStore` | `secret_store_contract` | `MemorySecretStore` |
| distribution | `AgreementKey` | `agreement_key_contract` | `SoftwareAgreementKey` |
| distribution | `AnchorSource` | `anchor_source_contract` | `MemoryAnchorSource` |
| distribution | `BundleStore` | `bundle_store_contract` | `MemoryBundleStore` |
| distribution | `RosterSource` | `roster_source_contract` | `MemoryRosterSource` |
| distribution | `RuntimeProfiles` | `runtime_profiles_contract` | `MemoryRuntimeProfiles` |
| distribution | `TrustStore` | `trust_store_contract` | `MemoryTrustStore` |
| instrument | `ControlCatalogue` | `control_catalogue_contract` | `FullCatalogue` |
| intake | `DataPlatform` | `data_platform_contract` | `MemoryDataPlatform`, `EventPlatform` (cargo test), `FileDataPlatform` |
| intake | `InstrumentSource` | `instrument_source_contract` | `PublishedInstruments` (cargo test), `MemoryInstrumentSource` (cargo test) |
| intake | `PopLedger` | `pop_ledger_contract` | `MemoryPopLedger` |
| intake | `RosterHistory` | `roster_history_contract` | `MemoryRosterHistory`, `FileRosterHistory` (cargo test) |
| intake | `SubmissionStore` | `(records what the gate stored for the Intake page)` | `RecordingStore (web demo)` (cargo test) |
| intake | `SubmissionStore` | `submission_store_contract` | `MemorySubmissionStore`, `FileSubmissionStore` (cargo test) |
| intake | `TenancyRegistry` | `(a live view of the demo registry)` | `LiveRegistry (web demo)` (cargo test) |
| intake | `TenancyRegistry` | `tenancy_registry_contract` | `MemoryTenancyRegistry`, `FileTenancyRegistry` (cargo test) |
| policy | `DecisionLog` | `decision_log_contract` | `MemoryDecisionLog`, `FileDecisionLog` (cargo test) |
| policy | `PolicyEngine` | `engine_cases` | `OpaEngine` (cargo test) |
| policy | `PolicyEngine` | `policy_engine_contract` | `BuiltInPolicyEngine` |
| policy | `PolicySource` | `policy_source_contract` | `MemoryPolicySource`, `BundlePolicySource` (cargo test) |
| policy | `PolicySource` | `registry verification tests (no shared contract run yet)` | `RegistryPolicySource` (cargo test) |
| publishing | `ArtefactRegistry` | `artefact_registry_contract` | `MemoryArtefactRegistry`, `FileRegistry` |
| publishing | `ArtefactValidator` | `artefact_validator_contract` | `AcceptingValidator`, `KindValidator` |
| publishing | `Builder` | `builder_contract` | `PassThroughBuilder` |
| publishing | `LogTransport` | `log_transport_contract` | `RecordingTransport`, `LocalTransport`, `NullTransport`, `HttpTransport (Rekor)` (cargo test) |
| publishing | `LogTransport` | `transparency_log_contract` | `HttpLogTransport` (cargo test) |
| publishing | `ReviewSystem` | `review_system_contract` | `MemoryReviewSystem` |
| publishing | `SourceRepository` | `source_repository_contract` | `MemorySourceRepository` |
| publishing | `TransparencyLog` | `transparency_log_contract` | `MemoryTransparencyLog`, `FileLog`, `RekorLog` (cargo test), `FileLogStore` (cargo test) |
| registration | `FleetRegistry` | `fleet_registry_contract` | `MemoryFleetRegistry` |
| registration | `IdentityProvider` | `identity_provider_contract` | `MemoryIdentityProvider`, `OidcIdentityProvider` (cargo test) |
| registration | `Notifier` | `notifier_contract` | `MemoryNotifier` |
| registration | `ReceivedProgress` | `received_progress_contract` | `MemoryReceivedProgress` |
| registration | `RegistryStore` | `(wraps the in-memory store to track changes)` | `TrackingStore (web demo)` (cargo test) |
| registration | `RegistryStore` | `registry_store_contract` | `MemoryRegistryStore`, `TokenFiles`, `FileRegistryStore` |
| trust | `AttestationVerifier` | `attestation_verifier_contract` | `SoftwareAttestationVerifier`, `Tpm2CertifyVerifier` (cargo test) |
| trust | `Attestor` | `(software evidence only; no shared contract applies)` | `WebKeyStore (Attestor)` (cargo test) |
| trust | `Attestor` | `attestor_contract` | `MemorySecureKeyStore` |
| trust | `AuthorityClock` | `(demo authority clock; no shared contract applies)` | `RealClock (web demo)` (cargo test) |
| trust | `AuthorityClock` | `authority_clock_contract` | `FixedClock`, `SystemClock (factory)` (cargo test) |
| trust | `KeyCustody` | `key_custody_contract` | `MemoryKeyCustody`, `DirCustody` |
| trust | `KeyHolderRegistry` | `key_holder_registry_contract` | `MemoryKeyHolderRegistry` |
| trust | `RandomSource` | `random_source_contract` | `SeededRandom`, `OsRandom`, `OsRandom (factory)` (cargo test), `WebRandom` (cargo test) |
| trust | `RevocationSource` | `revocation_source_contract` | `MemoryRevocationSource` |
| trust | `SecureKeyStore` | `secure_key_store_contract` | `MemorySecureKeyStore`, `SimulatedKeyStore`, `WebKeyStore` (cargo test) |

### Known gaps

- `LabelCustody` (the simulator authority's key custody) doesn't offer root keys, so it doesn't pass `key_custody_contract`. It is a fixture of the simulated authority, not a production adapter, and is exempt in the audit test.
- Platform ports on Android (`AND`, `PLAT`) have contract suites to run on a device; no platform adapter exists in this repository yet.
- `receiver_check_contract` and `unauthorised_destination_contract` run against the loopback transport only: both use addresses that nothing answers on over real HTTP. The impostor case over HTTP is `del_062_an_impostor_with_a_convincing_address_never_receives_a_record`.

## Coverage

`tools/check-coverage.py` reports which MUST requirements no test names. `tools/coverage-baseline.toml` records the MUST coverage reached per spec, as the floor for a later CI check (`--baseline tools/coverage-baseline.toml`).
