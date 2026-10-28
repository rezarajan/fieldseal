# collection::application

## Overview
The use cases (driving ports) of the Collection context (spec: [collection.md](../../../../../docs/reference/spec/collection.md) section 3), all implemented by one device-side application service, `Runtime`. It is pure in the ADR 0028 sense: time, randomness, keys, storage, display, device policy and camera arrive through the `Platform` ports. Every durable effect goes through `SecureStorage`, so a platform shell can be killed at any point (COL-092, COL-093). Submodules are private (`mod`), implementing `impl Runtime` blocks; the public surface is re-exported from `mod.rs`.

## Interface
Types in `mod.rs`: `Runtime<'a>` (`load`, `recovery`, `take_events`, `state`, `tenancy`, `is_unlocked`, `journal`, `key_history`, `checkpoints`, `anchors`, `posture_findings`), `Platform<'a>` (keys `SecureKeyStore`, attestor `Attestor`, clock `ElapsedClock`, wall `WallClock`, storage `SecureStorage`, display `SecureDisplay`, device `DevicePolicy`, camera `Camera`, hash `MemoryHardHash`, random `RandomSource`, bundles `BundleOpener`), `Provisioning<'a>` (trust, publishing, build_anchor, provisional_record_key, windows), `CollectionError`, `CollectionEvent`. Re-exports: `Held`, `CaptureView`, `ConsentInput`, `StatusOutcome`, `ClearOutcome`, `ClearPreview`, `ReceiptOutcome`, `OutboxEntry`, `OutboxSummary`, `ExportSource`, `RecoveryReport`, `CheckView`, `ClearedCounts`, `RecordView`, `ReviewFilter`, `ReviewReport`, `SubjectReview`, `SessionInfo`, `CaptureMode`.

Use cases by source file (`Runtime` methods):
- `session.rs`: `create_tenancy`, `open_session`, `posture_check`, `lock`, `on_lock_trigger`, `set_languages`, `set_window_class`, `forgotten_pin_help`.
- `capture.rs`: `start_capture`, `capture_view`, `set_value`, `clear_value`, `override_soft`, `acknowledge_incomplete`, `go_to_step`, `discard_capture`, `seal`, `pause`, `paused`, `record_status`, `record_consent`.
- `review.rs`: `review`, `delivery_state`.
- `clear.rs`: `clear_preview`, `clear`, `apply_receipt`, `clear_offer`, `mark_delivered`.
- `close.rs`: `end_tenancy`, `apply_close_certificate`, `outbox_summary`, `outbox`, `remove_outbox`.
- `bundle.rs`: `import_bundle`, `held`, `display_fields`, `applied_policies`, `see_anchor`.
- `export.rs`: `export_source` (what Delivery needs to build an export or sign an upload).
- `records.rs` (crate-internal): dual write `seal_record`, `seal_open`, `chain_anchor`, `chain_pending_anchors`.
- `recover.rs` (crate-internal): crash recovery, `RecoveryReport::is_clean`.

## Invariants
- At most one tenancy per device (COL-001); a second `create_tenancy` yields `TenancyExists`.
- Dual write order, each step persisted before the next: seal marker, pending local entry and note, tick state, journal append (the commit point), move pending to `local/`, save chain head and delete marker. Recovery completes the move when the journal holds the `seq`, otherwise discards the pending entry.
- Recovery on `load`: a torn journal tail is truncated, damage elsewhere is reported and left alone (COL-051); the chain head comes from the journal; interrupted clears with a checkpoint in the journal complete, otherwise are abandoned; interrupted closes complete without the PIN when the outbox entry exists.
- Open session needs the PIN; wrong PINs return `WrongPin(secs)` and then `LockedOut(secs)` (COL-023). A clear requires the PIN twice and counts failures toward lockout (COL-101); it seals a `checkpoint`, deletes local records through N, and deletes journal frames only where a verified receipt covers them.
- Consent must precede a capture (`ConsentNeeded`) and a refusal blocks everything (`ConsentRefused`, COL-030/031); a capture with unsealed values blocks other operations (`CaptureOpen`, COL-038).
- Closing signs a closing manifest before keys are deleted so the outbox can be delivered later without a live key (DEL-050); then keys, local record, held bundle, progress and PIN material are deleted (crypto-erase).
- Every publication in a bundle is verified with Publishing's verifier at import and every unlock; rosters are held only in memory for the session.
- The wall clock is an untrusted hint; nothing irreversible is triggered from it (COL-083).

## Side Effects
- Writes and appends via `SecureStorage` in two classes (device-encrypted, session-encrypted); object names include `tenancy`, `journal`, `pin-attempts`, `ticks`, `bundle`, `registration`, `policy-versions`, `progress`, `local/<seq>`, `note/<seq>`, `pending/...`, `marker/seal`, `marker/operation`, `outbox/<id>`.
- Key creation, signing and deletion via `SecureKeyStore`; attestation via `Attestor`; randomness via `RandomSource`; Argon2id via `MemoryHardHash`; window protection via `SecureDisplay`; restrictions via `DevicePolicy`; image capture via `Camera`.
- Domain events are queued in memory and drained by `take_events`.

## Verification
- Run: `cargo test -p fieldseal-collection` (repo-wide: `just test`)
