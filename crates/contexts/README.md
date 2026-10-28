# contexts

## Overview

The ten bounded contexts of Fieldseal ([ADR 0004](../../docs/explanation/adr/0004-bounded-contexts.md)), one crate each. Every context depends only on the kernel and on the contexts its edge list in [`architecture.toml`](../../architecture.toml) allows. Contexts are pure: they do no I/O, read no clock and draw no ambient randomness. Each declares driven ports (traits) for adapters to implement, and ships contract suites that adapters run against those ports. Normative specs are in [`docs/reference/spec/`](../../docs/reference/spec/README.md).

## Subdirectories & Boundaries

- trust: [./trust/README.md](./trust/README.md) - Authority use cases (root ceremony, certificates, revocations, trust bundles, chain verification). Ports: `KeyCustody`, `SecureKeyStore`, `Attestor`, `AttestationVerifier`, `RevocationSource`, `AuthorityClock`, `RandomSource`, `KeyHolderRegistry`.
- instrument: [./instrument/README.md](./instrument/README.md) - Instrument and layout validation, the rule language, compilation and render plans. Port: `ControlCatalogue`.
- policy: [./policy/README.md](./policy/README.md) - Policy documents, layer merge with invariant floors, and decisions that fail closed (never Allow on error). Ports: `PolicyEngine`, `PolicySource`, `DecisionLog`.
- publishing: [./publishing/README.md](./publishing/README.md) - Review, provenance, threshold-signed publication and withdrawal, and transparency-log proofs. Ports include `TransparencyLog` and `ArtefactRegistry`.
- registration: [./registration/README.md](./registration/README.md) - The `Factory`: single-use tokens, PoP, attestation and policy checks, and tenancy certificates. Ports: `IdentityProvider`, `RegistryStore`, `FleetRegistry`, `Notifier`, `ReceivedProgress`.
- distribution: [./distribution/README.md](./distribution/README.md) - Building bundles sealed to one device, and verifying and importing them in a fixed order. Ports: `RosterSource`, `AnchorSource`, `RuntimeProfiles`, `TrustStore`, `BundleStore`, `AgreementKey`.
- collection: [./collection/README.md](./collection/README.md) - The device `Runtime`: tenancy, PIN, capture, sealing, dual-write journal and recovery, clear and close. Platform ports include `SecureStorage`, `ElapsedClock`, `BundleOpener` and `Camera`.
- delivery: [./delivery/README.md](./delivery/README.md) - Export assembly, verification and repair, authorised upload, file and share copies, and receipt import. Ports: `UploadTransport`, `RegistrationRecords`, `ReceiverCheck`, `FileAccess`, `ShareTarget`, `PrivateStorage`, `QrScanner`.
- intake: [./intake/README.md](./intake/README.md) - The verification gate (13 stages, the first failure stops the run), atomic landing, consent, the upload service and data contracts. Ports: `SubmissionStore`, `TenancyRegistry`, `RosterHistory`, `InstrumentSource`, `DataPlatform`, `PopLedger`.
- deployment: [./deployment/README.md](./deployment/README.md) - Deployment manifests, environment rendering, immutable releases, custody-binding checks and documentation bundles. Ports: `BuildRegistry`, `SecretStore`, `DocumentationSink`.
