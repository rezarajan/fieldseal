# distribution::application

## Overview
Use cases (driving ports) of the Distribution context, spec [distribution.md](../../../../../docs/reference/spec/distribution.md) section 3. Factory side builds and releases bundles; delivery hands them out; runtime side verifies and imports them. Pure orchestration over ports: no I/O is performed here; adapters behind the ports do it.

## Interface
Re-exported from `mod.rs`:
- `build.rs`: trait `BuildBundle::build(&BuildRequest) -> Result<BuiltBundle, DistributionError>`; `BundleBuilder` (`new(FactoryPorts, &VerifyPublication, FactoryIdentity)`, `with_max_size`); `BuildRequest` (tenancy, instruments, layouts, localisations, trust_updates, practice, selector; `BuildRequest::new`); `FactoryPorts` (registry `RegistryStore`, artefacts `ArtefactRegistry`, rosters `RosterSource`, profiles `RuntimeProfiles`, policy `Decide`, anchors `AnchorSource`, custody `KeyCustody`, random `RandomSource`, bundles `BundleStore`); `FactoryIdentity` (signer, chain, caller, unattested); `BuiltBundle` (sealed, manifest, decision, decision_log_index, event).
- `release.rs`: `check_state(TenancyState, practice)`, `release_facts`, `decide_release`, `Released` (decision, log_index).
- `fetch.rs`: traits `FetchBundle::fetch(tenancy, held)` and `DownloadBundle::download(device)`; `BundleDelivery::new(registry, bundles)` implements both.
- `verify.rs`: `VerifyBundle` (`new(trust, publishing, agreement, profile)`, `with_max_size`, `verify(bytes, &ImportState) -> Result<VerifiedBundle, BundleRejection>`); trait `ImportBundle::import`; `BundleImporter::new(verifier, store)`; `ImportState`, `HeldState`, `HeldRoster`, `ImportRecord`, `VerifiedBundle` (`import_record`).

## Invariants
- Build steps run in a fixed order and each fails closed: tenancy state, artefact fetch and full verification (none withdrawn, DIS-011), composition checks (DIS-012/016/017), roster matching and field restriction (DIS-013/014), fresh time token and policy decision (DIS-002), policy layers included as publications (POL-050), seal to the agreement key with tenancy ID bound into HPKE `info` (DIS-020), signature through `KeyCustody` (DIS-021), encode (WIRE-090) and store.
- `check_state`: `Registered` passes; `Flagged`, `Lost`, `Closing`, `Closed`, `Retired` are withheld; `Pending`/`Held` pass only for practice bundles; `Rejected` is withheld for practice and `NotRegistered` otherwise.
- `decide_release`: `allow` and `flag` release; `hold`, `deny` and any policy failure withhold (POL-034).
- Verification order (DIS-030) is fixed and stops at the first failure: size/envelope, recipient/signer/chain/signature (before opening the seal, WIRE-093), open, contents, sequence strictly greater than held, artefacts (publication verification, INS-103 fingerprints, withdrawals, trust-update successors, policy floors POL-051), compatibility, rosters (no version or generation below held).
- A failed import stores nothing and keeps the held bundle (DIS-031); a success stores the bundle bytes unchanged.
- Fetch and download deliver the latest stored bundle only when the tenancy is eligible; they build nothing.

## Side Effects
- None directly. Through ports: `BundleStore::put`, `KeyCustody` signing (logged under the caller name), `RandomSource` use during sealing, policy decision log append (`decision_log_index`), reads of the registry, artefact registry, roster source and anchor source.

## Verification
- Run: `cargo test -p fieldseal-distribution` (repo-wide: `just test`)
