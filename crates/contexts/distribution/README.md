# fieldseal-distribution

## Overview
The Distribution bounded context (spec: [distribution.md](../../../docs/reference/spec/distribution.md); layering per ADR 0028). The factory builds, seals and signs per-tenancy bundles (`FSB1` files) of instruments, layouts, localisations, policy, rosters, trust updates and withdrawals; runtimes verify and import them. The crate is pure (no I/O): adapters implement its driven ports. Depends on kernel, trust, policy, instrument, publishing and registration.

## Interface
`lib.rs` exposes four public modules: `application`, `contract`, `domain`, `ports`.
- [`application`](./src/application/README.md): `BuildBundle`/`BundleBuilder`, `VerifyBundle`, `ImportBundle`/`BundleImporter`, `FetchBundle`, `DownloadBundle`, `BundleDelivery`, release policy (`check_state`, `decide_release`).
- [`domain`](./src/domain/README.md): `SealedBundle`, `BundleFile`, `BundleContent`, `BundleManifest`, `BundleSeq`, `Roster`, `TimeToken`, `ReleaseDecision`, `DistributionEvent`, errors (`DistributionError`, `BundleRejection`, `CompositionError`).
- `ports` (driven ports owned here, each with its error enum): `RosterSource` (`current_rosters`, `active_tenancies`), `AnchorSource` (`time_token`), `RuntimeProfiles` (`profile`), `TrustStore` (`current`, `replace`), `BundleStore` (`put`, `latest`), `AgreementKey` (`key_id`, `open`). Also used from other contexts: `ArtefactRegistry`, `RegistryStore`, `Decide`, `KeyCustody`, `RandomSource`.
- `contract`: reusable contract-test functions each adapter must pass: `roster_source_contract`, `anchor_source_contract`, `trust_store_contract`, `bundle_store_contract`, `agreement_key_contract`, `runtime_profiles_contract`, plus helper `sample_bundle`.

## Invariants
- Roster versions per cohort never decrease; unknown tenancy is an error, not an empty list (`RosterSource`).
- Time tokens never go back in authority time and verify against the trust bundle (`AnchorSource`).
- `TrustStore::replace` accepts only a bundle passing `TrustBundle::check_update`.
- `BundleStore` keeps bytes unchanged, accepts only a sequence number higher than the latest held (`NotNewer` otherwise), and returns the latest by sequence.
- `AgreementKey` opens only seals addressed to its `key_id` under the same tag and context, reporting `WrongRecipient` before attempting to open; the private key never leaves the platform key store.
- `RuntimeProfiles` returns `None` for an unrecorded tenancy, never a default.

## Side Effects
None in this crate. Adapters of the ports perform storage, key-store, and registry I/O. Opened plaintext returned by `AgreementKey::open` is zeroised on drop.

## Verification
- Run: `cargo test -p fieldseal-distribution` (repo-wide: `just test`)
