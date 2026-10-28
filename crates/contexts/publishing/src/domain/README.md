# Publishing Domain

## Overview

The pure core of the Publishing bounded context: artefacts, reviews and approval counting, build provenance, the log-visible statement types, RFC 9162 Merkle proofs, C2SP signed checkpoints, publications and withdrawals with their canonical encodings, and the verification checks that make them valid. It does no I/O; the only effectful dependency is a `RandomSource` trait object passed to `new_salt`. Normative behaviour is in [the publishing spec](../../../../../docs/reference/spec/publishing.md); the log-privacy design is [ADR 0030](../../../../../docs/explanation/adr/0030-public-transparency-log.md).

## Interface

Re-exported from `mod.rs` (modules `artefact`, `checkpoint`, `encoding`, `error`, `merkle`, `provenance`, `publication`, `review`, `secrets`, `statement`, `verify` are all `pub`):

- Artefacts: `Artefact::new(kind, name, version, canonical, salt)`, `ArtefactKind` (`Instrument`, `Layout`, `Localisation`, `Policy`, `TrustBundle`, `Deployment`; `ALL`, `as_str`, `parse`), `artefact_address`, `is_valid_name`, `is_valid_version`, `new_salt`.
- Reviews: `Review`, `ReviewDecision`, `ReviewerRole`/`ReviewerRoles`, `RoleRules`, `RevisionId`, `SourceSnapshot`, `counted_approvals`, `is_pseudonymous`.
- Provenance: `ProvenanceStatement` (`for_artefact`, `describes`, `encode`/`decode`), `SignedProvenance`, `BuilderId`, `SourceRef`.
- Log statements: `PublicationStatement`, `LogEntry` (`new`, `for_statement`), `LogEntryType`, `LeafFormat`, `hashedrekord_json`.
- Proofs and checkpoints: `InclusionProof`, `ConsistencyProof`, `SignedCheckpoint` (`parse`, `sign`, `verify`), `CheckpointBody`, `NoteSignature`, `TreeHeadTracker`, `CheckpointError`, `CHECKPOINT_FORMAT`, `key_hash`; in `merkle`: `leaf_hash`, `node_hash`, `root`, `audit_path`, `consistency_path`, `verify_inclusion`, `verify_consistency`.
- Publications: `PublicationDraft`, `Publication`, `Approval`, `SignerSignature`, `LogRecord`, `WithdrawalStatement`, `WithdrawalDraft`, `Withdrawal` (each with `encode`/`decode` where defined), `artefact_signed_structure`.
- Verification (`verify` module): `thresholds`, `KindThresholds`, `FLOOR`, `check_provenance`, `check_signatures`, `check_tree_head_age`, `check_entry`, `check_log`.
- Errors: `PublishingError` (with `code()` mapping to a WIRE error code where one applies) and `Diagnostic { code, message, blocking }`; `secrets::find_secrets`.
- `encoding`: strict base64, hex, ECDSA DER/raw, P-256 SPKI DER and PEM helpers.

## Invariants

- An `Artefact`'s address is computed from its bytes, never supplied: a salted fingerprint for instruments, the SHA-256 content address for every other kind. An instrument must have a salt and no other kind may have one.
- Names are lower-case ASCII letters and digits in hyphen-separated words, at most 63 characters; versions are SemVer 2.0.0, at most 64 characters.
- `counted_approvals` counts distinct approvers of the exact address and revision who hold a reviewer role for the kind; the author is excluded unless policy allows; any rejection by a role-holder blocks; a non-pseudonymous reviewer (contains `@`, whitespace or control characters, or exceeds 128 bytes) is refused; each required language needs a counted approver holding that language role; at least one approval is always required.
- `LogEntry` has exactly four private fields (type, digest, signature, public key) and `PublicationStatement` holds only an entry type and two hashes, so names, versions, sources, reviewers and artefact bytes cannot reach the public log by construction.
- `thresholds` falls back to a floor of 2 for unlisted kinds and treats configured values below 1 as 1.
- `check_signatures` refuses the whole set if any signer repeats, is unlisted for the kind, or has an invalid signature, and requires at least the threshold of valid ones.
- `check_log` requires a checkpoint signed by a pinned log, exactly one log record per counted signer, each entry committing to the statement, and each inclusion proof reaching the checkpoint root at the checkpoint's size. Required witness cosignatures above zero are always refused (no witness keys are pinned).
- `TreeHeadTracker` stops permanently on the first inconsistent tree head and refuses all later ones. A missing checkpoint time token counts as too old.
- Merkle proofs longer than 128 hashes (`MAX_PATH`) are rejected; checkpoint notes are limited to 16 KiB and 32 signature lines.
- Messages from `find_secrets` never quote the secret.

## Side Effects

None on the outside world. Functions are deterministic except `new_salt`, which draws 32 bytes from the supplied `RandomSource` (a Trust-context port). `TreeHeadTracker::advance` mutates the tracker only. The crate's dependencies are the kernel, Trust and Policy domains and `thiserror`.

## Verification

`cargo test -p fieldseal-publishing` (repo-wide runner: `just test`).
