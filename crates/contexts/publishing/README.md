# fieldseal-publishing

## Overview

The Publishing bounded context: how an artefact (instrument, layout, localisation, policy, trust bundle or deployment) is validated, reviewed, built with provenance, signed by threshold publishers, recorded in a public transparency log, stored, verified and withdrawn. The crate is pure: it performs no I/O itself, and all effects go through the driven ports in `src/ports.rs` or the Trust context's `KeyCustody`, `KeyHolderRegistry` and `RandomSource`. Typed publishing policy is read from the Policy context. Normative behaviour is in [the publishing spec](../../../docs/reference/spec/publishing.md); see also [ADR 0009](../../../docs/explanation/adr/0009-publishing-with-provenance.md) and [ADR 0030](../../../docs/explanation/adr/0030-public-transparency-log.md). Layering follows `architecture.toml`: this crate depends on `fieldseal-kernel`, `fieldseal-trust`, `fieldseal-policy` and `thiserror` only.

## Interface

`src/lib.rs` exposes four public modules: `domain`, `application`, `ports`, `contract`.

- `domain` ([documented here](./src/domain/README.md)): entities, value objects, proofs, encodings and verification checks.
- `ports` (traits adapters implement):
  - `SourceRepository::fetch` (error `SourceError`)
  - `ReviewSystem::{record, reviews, roles}` (error `ReviewError`)
  - `Builder::build` returning `BuildOutput` (error `BuildError`)
  - `ArtefactValidator::validate`, kind-specific findings
  - `LogTransport::send` with `Transmission` and `LogRequest` (error `LogError`)
  - `TransparencyLog::{append, checkpoint, prove_inclusion, prove_consistency}` returning `LoggedEntry`
  - `ArtefactRegistry::{put, get, list, withdraw, withdrawals}` (error `RegistryError`: `Conflict`, `VersionTaken`, `Backend`)
- `application` (use cases, constructed over `&dyn` ports):
  - `hash_artefact`, `validate`
  - `SubmitForReview::submit` -> `ReviewRequest`
  - `RecordReview::record`
  - `BuildProvenance::build(BuildInput)` -> `PublicationDraft`
  - `VerifyPublication` (`verify_draft`, `verify`, `verify_withdrawal`, `verify_withdrawal_draft`; builders `with_validator`, `with_key_holders`, `with_provenance_check`) returning `DraftStatus` or `VerifiedPublication`; `ProvenanceCheck::{Full, DescribesOnly}`
  - `SignPublication::sign`, `Publish::publish`, `SignWithdrawal::sign`, `Withdraw::withdraw`, `ProveInclusion::prove`
  - `check_distinct_holders`
- `contract`: reusable adapter test suites `source_repository_contract`, `review_system_contract`, `builder_contract`, `transparency_log_contract`, `artefact_registry_contract`, `artefact_validator_contract`, `log_transport_contract`, plus `RecordingTransport`, `sample_entry`, `sample_publication`, `ALLOWED_FIELD_NAMES`.
- Errors: `domain::PublishingError` (use cases wrap port errors into its `Review`, `Log`, `Registry` and `Custody` string variants) and `domain::Diagnostic`.

## Invariants

- Use cases are the only place the pieces are composed; `Publish` and `Withdraw` verify the assembled result with `VerifyPublication` before writing to the registry, and a draft below threshold or failing any check is refused before anything is logged.
- `validate` always runs the built-in secrets check (PUB-004) in addition to any injected `ArtefactValidator`; any blocking finding fails with `PublishingError::Validation`.
- `RecordReview` refuses non-pseudonymous reviewer identities before reaching the `ReviewSystem`.
- `BuildProvenance::build` refuses a builder or source not in the policy allow-lists and signs provenance with the builder key only after the counted approvals meet the kind's threshold.
- `SignPublication` and `SignWithdrawal` refuse a key that is not a listed publisher for the kind or has already signed the draft, and sign twice (artefact or withdrawal structure, and the log statement).
- `VerifyPublication::verify` ignores withdrawals that do not themselves verify, so a forged withdrawal cannot deny service; certificates are checked at the provenance build time (or the withdrawal issue time).
- `check_distinct_holders` passes when no registry is supplied, and fails closed when a holder cannot be resolved.
- Port contracts: sources immutable per revision; reviews unalterable and returned in recording order; builders deterministic; registry immutable by address with a version used once per kind and name; a log adapter transmits only an appended entry's own fields and returns proofs that verify offline against the pinned key.

## Side Effects

The crate itself has none; effects happen only through injected ports:

- `KeyCustody::sign` and `public_key` (Trust): builder and publisher signing.
- `ReviewSystem::record`; `TransparencyLog::append` and proof/checkpoint lookups; `ArtefactRegistry::put` and `withdraw`.
- `KeyHolderRegistry::key_holder` lookups when distinct holders are checked.
- The `contract` module is test support: `RecordingTransport` holds an in-memory `Arc<Mutex<..>>` transmission record.

Time (`AuthorityTime`) and randomness enter as values or ports, never from the environment.

## Verification

`cargo test -p fieldseal-publishing` (repo-wide runner: `just test`).
