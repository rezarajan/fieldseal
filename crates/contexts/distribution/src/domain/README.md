# distribution::domain

## Overview
Entities, value objects and invariants of the Distribution context (spec: [distribution.md](../../../../../docs/reference/spec/distribution.md) section 2). Pure: no I/O, clock, randomness or environment. It defines the sealed bundle file (`FSB1`), the plaintext inside the seal, rosters, the authority time token, and the error taxonomy. `src/domain/mod.rs` also defines `SealedBundle`, `ReleaseDecision` and `DistributionEvent`.

## Interface
Re-exported from `mod.rs`:
- `roster.rs`: `Roster` (cohort, version, generation, entries), `RosterEntry` (ordinal, subject, display, attributes, consent, prior_status), `ConsentState` (`as_str`, `parse`; wire names per WIRE-095), `RosterError`. Methods on `Roster`: `may_be_followed_by`, `field_names`, `restricted_to`, `to_value`, `encode`, `from_value`.
- `time_token.rs`: `TimeToken` (authority_time, optional 16-byte nonce, signer, signature; `encode`, `decode`, `to_text`/`from_text` for the `FS1N:` QR form, `verify`), `AnchorKind`, `check_publication_tree_head_age`, constant `MAX_TIME_TOKEN` (300 bytes, not re-exported).
- `content.rs`: `BundleContent` (tenancy, seq, issued, optional certificate, time token, instruments, layouts, localisations, policy, rosters, trust updates, withdrawals; `to_value`, `encode`, `decode`, `manifest`), `BundleManifest`, `BundleSeq(u64)`.
- `file.rs`: `BundleFile` (sealed, signer, chain, sig; `signed_structure`, `structure`, `encode`, `decode`), constants `MAGIC` (`FSB1`), `MAX_BUNDLE_FILE` (64 MiB), function `file_name`; `MAX_CHAIN` (1) is module-public.
- `facts.rs`: `RuntimeProfile`, `InstrumentFacts`, `LayoutFacts`, `artefacts_of`, `instrument_facts`, `layout_facts`, `localisation_reference`, `check_composition`.
- `error.rs`: `CompositionError`, `DistributionError`, `BundleRejection` (`step`, `code`, `collector_reason`), `VerifyStep`, `CollectorReason` (`message_id`, `text`).
- `mod.rs`: `SealedBundle` (address, tenancy, seq, issued, bytes; `SealedBundle::new` computes the address), `ReleaseDecision` (`Release`, `Withhold`), `DistributionEvent` (`BundleReleased`, `BundleWithheld`, `BundleImported`, `BundleRejected`).

## Invariants
- A `SealedBundle` address is the SHA-256 content address of its file bytes, computed in `new` (DIS-033).
- A bundle file is checked in order: size against the limit, then magic `FSB1`, then canonical CBOR and fields (WIRE-093). Everything outside `sealed` reveals nothing about contents (DIS-022); the signature covers the sealed envelope and signer, never the plaintext (DIS-021).
- `BundleContent::decode` is strict: version 1, no unknown keys, canonical form, at least one instrument and one policy publication. At most one roster per cohort (DIS-014).
- A roster may be followed only by the same cohort with non-decreasing version and generation; `from_value` refuses unknown keys, repeated or unordered ordinals, repeated subjects and unknown consent states.
- Rosters in a bundle carry only fields instruments reference (DIS-013, `restricted_to`).
- A time token with no valid token, or a malformed or inauthentic one, counts as too old in `check_publication_tree_head_age`.
- `check_composition`: every instrument fits the runtime schema; each layout is bound to an instrument in the bundle, at most one per instrument and window class; every localisation names the runtime's reference version.

## Side Effects
None. All functions are pure; `decode`/`encode` operate on in-memory bytes.

## Verification
- Run: `cargo test -p fieldseal-distribution` (repo-wide: `just test`)
