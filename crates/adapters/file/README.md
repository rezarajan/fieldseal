# fieldseal-adapters-file

## Overview

File-backed adapters for development and for running the local stack. **Not for production**: keys are files in a directory, the factory's state is a journal on disk, and there is no encryption at rest, compaction or multi-process locking. Production uses an HSM or KMS custody and a database behind the same ports (ADR 0028, see [0028-clean-architecture.md](../../../docs/explanation/adr/0028-clean-architecture.md)).

Layer: adapter. Depends on the kernel and the contexts `trust`, `registration`, `intake`, `instrument`, `publishing`, `distribution`, `policy`, plus `fieldseal-adapters-memory` (the in-memory registry store it wraps).

## Interface

| Module | Symbol | Implements (port) |
| --- | --- | --- |
| `custody` | `DirCustody::new(dir)`, `dir()`, `keys()`, `holds(&KeyId)`, `sole_key(KeyRole)` | `fieldseal_trust::ports::KeyCustody` (`generate`, `sign`, `open`, `public_key`, `usage_log`) |
| `store` | `FileRegistryStore::open(dir)`, `snapshot(dir) -> MemoryRegistryStore`, `path()`; const `JOURNAL = "registry.journal"` | `fieldseal_registration::ports::RegistryStore` |
| `tenancy` | `FileTenancyRegistry::new(dir)`, `view_of(&TenancyRecord) -> Option<TenancyView>` | `fieldseal_intake::ports::TenancyRegistry` (read-only) |
| `rosters` | `record_issued(dir, &TenancyId, &IssuedRoster)`, `FileRosterHistory::new(dir)` | `fieldseal_intake::ports::RosterHistory` |
| `submissions` | `FileSubmissionStore::open(dir, now)`, `stored() -> Vec<(u64, Vec<u8>)>` | `fieldseal_intake::ports::SubmissionStore` (`put`, `get`) |
| `instruments` | `PublishedInstruments::new(dir, TrustBundle, PublishingPolicy)` | `fieldseal_intake::ports::InstrumentSource` |
| `registry` | `FileRegistry::new(dir)` | `fieldseal_publishing::ports::ArtefactRegistry` (the artefact registry `artefact publish` fills) |
| `roster_store` | `RosterStore::open(dir)` (`issue`, `get`, `latest`, `cohorts`), `FileRosterSource::new(store, tenancy_registry_dir)` | `fieldseal_distribution::ports::RosterSource` (over the roster store and the tenancy registry journal) |
| `bundles` | `FileBundleStore::new(dir)` | `fieldseal_distribution::ports::BundleStore` |
| `profiles` | `FileRuntimeProfiles::new(tenancy_registry_dir)` | `fieldseal_distribution::ports::RuntimeProfiles` (the profile each runtime reported at registration) |
| `atomic` | `write_atomic(path, bytes) -> io::Result<()>` | none (a helper: temporary file in the same directory, `fsync`, rename, directory sync) |
| `codec` | `W`, `R`, `Res`, `put_*`/`get_*` record functions | none (journal record encoding) |

## Invariants

- `DirCustody`: a key refuses a use that does not match its role (`WrongPurpose`), a domain tag its role may not sign or open (`TagNotAllowed`), or the wrong algorithm (`Unsupported`); `generate` refuses role/algorithm pairs the role does not allow. Every key is unattested. Secrets are held in `Zeroizing` buffers.
- `FileRegistryStore` is single-writer: one factory process owns the directory. A change is applied to the inner store and journaled under one lock, so the journal order is the applied order. A journal is replayed on open; a truncated tail (crash mid-write) is ignored. Other processes read via `snapshot`.
- Journal records are a 4-byte big-endian length plus a payload (operation code and arguments, encoded by `codec`). The `codec` format is private to this adapter, is not a wire format, and may change between versions of the development stack.
- `FileTenancyRegistry` replays the journal on each lookup, so a device registered a moment ago is known at once; only tenancies registered at some point are visible.
- `write_atomic` leaves the old file or the new one and never a torn file; a failed write leaves the old file and no temporary file. The landing files and the results export use it; the transparency log store keeps its own copy of the steps because its crate does not depend on this one.
- `FileSubmissionStore` is write-once and content-addressed (SHA-256, one file each, written with `write_atomic`); a duplicate `put` writes nothing. `stored()` lets the intake gate rebuild its duplicate state after a restart.
- `PublishedInstruments` reads the directory on every lookup and counts only `*.published` files that decode, are instrument artefacts with the requested fingerprint, and verify against the trust bundle and publishing policy; others are skipped. A missing directory yields `None`.
- Every adapter in this crate is a development adapter, and a production deployment refuses them. `FileRegistry`, `FileRosterSource`, `FileBundleStore` and `FileRuntimeProfiles` have the layouts below.
- `FileRegistry` is immutable: a publication is written once as `<address hex>.publication` and a withdrawal as `withdrawals/<n>.withdrawal`, both with `write_atomic`. The factory reads this directory, not the `*.published` copies intake reads.
- `RosterStore` writes `<cohort>/v<version>.roster` (canonical closed form) and, last, `v<version>.sha256`; a roster without its checksum is not stored, and one that does not match it is not served. A version never changes: the same content again is `Unchanged`, different content is `VersionTaken`, a lower version than the latest is `NotNewer`. A cohort name that is not letters, digits, `-`, `_` and inner dots is refused, so a name cannot leave the directory. Directories are 0700 and files 0600 on Unix.
- `FileRosterSource` serves the latest roster of each cohort the tenancy record holds at the tenancy's generation, and counts active tenancies (`Held`, `Registered`, `Flagged`) of a cohort from the tenancy registry journal.
- `FileBundleStore` keeps `<tenancy hex>/fieldseal-bundle-<date>-<sequence>.fsb` with a `.meta` file (address and issue time) written after it; a bundle without `.meta` is not served. `put` refuses a sequence not higher than the latest.
- `FileRuntimeProfiles` returns the instrument-schema version and catalogue version recorded with the tenancy (REG-091), `None` for an unknown tenancy. A tenancy journal written before the profile existed is not readable: run `just purge` on a development stack.
- Rosters (intake's `FileRosterHistory`) keep only each subject's consent state, not display names or attributes.

## Side Effects

- Filesystem reads and writes:
  - `<dir>/<key id hex>.key` (lines `role`, `algorithm`, `secret`; mode 0600 on Unix) and an appended `<dir>/usage.log` (`key role operation caller`) in the custody directory.
  - `<state dir>/registry.journal`, appended to on every registry change.
  - `<dir>/<publication address hex>.publication` and `<dir>/withdrawals/<n>.withdrawal` in the artefact registry; `<dir>/<cohort>/v<version>.roster` and `.sha256` in the roster store; `<dir>/<tenancy hex>/fieldseal-bundle-<date>-<sequence>.fsb` and `.meta` in the bundle store.
  - `<dir>/<tenancy hex>.rosters`, appended to when a bundle with a roster is built (mode restricted on Unix).
  - `<dir>/<sha256 hex>` per submission (written with `write_atomic`) and an appended `<dir>/index`.
  - Reads of `*.published` files in the instruments directory.
- Randomness: key generation reads 32 bytes from `/dev/urandom`.
- Clock: only the injected `now` closure of `FileSubmissionStore`.
- No network.

## Verification

- Run: `cargo test -p fieldseal-adapters-file` (repo-wide: `just test`)
