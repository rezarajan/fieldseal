# fieldseal-adapters-file

## Overview

File-backed adapters for development and for running the local stack. **Not for production**: keys are files in a directory, the factory's state is a journal on disk, and there is no encryption at rest, compaction or multi-process locking. Production uses an HSM or KMS custody and a database behind the same ports (ADR 0028, see [0028-clean-architecture.md](../../../docs/explanation/adr/0028-clean-architecture.md)).

Layer: adapter. Depends on the kernel and the contexts `trust`, `registration`, `intake`, `instrument`, `publishing`, `policy`, plus `fieldseal-adapters-memory` (the in-memory registry store it wraps).

## Interface

| Module | Symbol | Implements (port) |
| --- | --- | --- |
| `custody` | `DirCustody::new(dir)`, `dir()`, `keys()`, `holds(&KeyId)`, `sole_key(KeyRole)` | `fieldseal_trust::ports::KeyCustody` (`generate`, `sign`, `open`, `public_key`, `usage_log`) |
| `store` | `FileRegistryStore::open(dir)`, `snapshot(dir) -> MemoryRegistryStore`, `path()`; const `JOURNAL = "registry.journal"` | `fieldseal_registration::ports::RegistryStore` |
| `tenancy` | `FileTenancyRegistry::new(dir)`, `view_of(&TenancyRecord) -> Option<TenancyView>` | `fieldseal_intake::ports::TenancyRegistry` (read-only) |
| `rosters` | `record_issued(dir, &TenancyId, &IssuedRoster)`, `FileRosterHistory::new(dir)` | `fieldseal_intake::ports::RosterHistory` |
| `submissions` | `FileSubmissionStore::open(dir, now)`, `stored() -> Vec<(u64, Vec<u8>)>` | `fieldseal_intake::ports::SubmissionStore` (`put`, `get`) |
| `instruments` | `PublishedInstruments::new(dir, TrustBundle, PublishingPolicy)` | `fieldseal_intake::ports::InstrumentSource` |
| `codec` | `W`, `R`, `Res`, `put_*`/`get_*` record functions | none (journal record encoding) |

## Invariants

- `DirCustody`: a key refuses a use that does not match its role (`WrongPurpose`), a domain tag its role may not sign or open (`TagNotAllowed`), or the wrong algorithm (`Unsupported`); `generate` refuses role/algorithm pairs the role does not allow. Every key is unattested. Secrets are held in `Zeroizing` buffers.
- `FileRegistryStore` is single-writer: one factory process owns the directory. A change is applied to the inner store and journaled under one lock, so the journal order is the applied order. A journal is replayed on open; a truncated tail (crash mid-write) is ignored. Other processes read via `snapshot`.
- Journal records are a 4-byte big-endian length plus a payload (operation code and arguments, encoded by `codec`). The `codec` format is private to this adapter, is not a wire format, and may change between versions of the development stack.
- `FileTenancyRegistry` replays the journal on each lookup, so a device registered a moment ago is known at once; only tenancies registered at some point are visible.
- `FileSubmissionStore` is write-once and content-addressed (SHA-256, one file each); a duplicate `put` writes nothing. `stored()` lets the intake gate rebuild its duplicate state after a restart.
- `PublishedInstruments` reads the directory on every lookup and counts only `*.published` files that decode, are instrument artefacts with the requested fingerprint, and verify against the trust bundle and publishing policy; others are skipped. A missing directory yields `None`.
- Rosters keep only each subject's consent state, not display names or attributes.

## Side Effects

- Filesystem reads and writes:
  - `<dir>/<key id hex>.key` (lines `role`, `algorithm`, `secret`; mode 0600 on Unix) and an appended `<dir>/usage.log` (`key role operation caller`) in the custody directory.
  - `<state dir>/registry.journal`, appended to on every registry change.
  - `<dir>/<tenancy hex>.rosters`, appended to when a bundle with a roster is built (mode restricted on Unix).
  - `<dir>/<sha256 hex>` per submission (written via `.tmp` then rename) and an appended `<dir>/index`.
  - Reads of `*.published` files in the instruments directory.
- Randomness: key generation reads 32 bytes from `/dev/urandom`.
- Clock: only the injected `now` closure of `FileSubmissionStore`.
- No network.

## Verification

- Run: `cargo test -p fieldseal-adapters-file` (repo-wide: `just test`)
