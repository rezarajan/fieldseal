# fieldseal-delivery

## Overview
The Delivery bounded context: getting a tenancy's sealed journal off the device. It assembles, self-verifies, inspects and repairs export files, uploads them to receivers that prove a trust-bundle-certified key, copies them to files or other apps, and imports authority receipts that unlock clearing. Spec: [delivery.md](../../../docs/reference/spec/delivery.md); layering per ADR 0028. The crate is pure: keys, time, randomness, storage, files and network all arrive through ports. Use cases run over Collection's `Runtime`.

## Interface
`lib.rs` exposes `application`, `checks`, `contract`, `domain`, `export`, `ports` (all single files, no sub-READMEs).
- `application`: `DeliveryService` (`new`, `take_events`, `attempts`, `build_export`, `build_outbox_export`, `deliver_file`, `deliver_share`, `import_receipt`, `import_receipt_text`, `import_receipt_scan`, `delivery_states`, `outstanding`, `condition_met`, `upload`, `upload_outbox`, `background_tick`), `Ports<'a>` (keys `SecureKeyStore`, random, wall `WallClock`, transport, receiver, receipts `ReceiptCheck`, files, share, storage, records), `UploadResult`, `Tick` (`Idle`, `Waiting`, `Uploaded`, `Failed`), `Target`, `DeliveryEvent`, `DeliveryError`, `ReceiptRejection` (`BadSignature`, `UnknownTenancy`, `HashMismatch`), function `part_context`.
- `domain`: `DestinationClass` (`Upload`, local, removable, cloud, share; `destination()`), `AttemptOutcome`, `DeliveryLabel` (`text()`), `label_for`, `DestinationAttempt`, `AddressHint`, `HintSource`, `ReceiverChallenge`, `ReceiverProof`, `AuthorisedDestination` (`authorise`), `UploadRoute` (`path`, `url`), `UploadRequest`, `Export`, `ExportId`, `PopToken`/`POP_HEADER` (re-exported from kernel), `civil_date`, `export_file_name`.
- `export`: `assemble` (-> `Assembled`, `AssembleError`), `verify` (-> `VerifyReport` with `Finding`, `ok()`), `inspect` (-> `Inspection`, `PartInfo`), `repair` (-> `Repair`), `reencode`, `merge_parts`, `first_signature`, `manifest_keys`, `check_manifest_shape`, `PartContext`.
- `checks`: `TrustReceiptCheck` (implements `ReceiptCheck`), `TrustReceiverCheck` (implements `ReceiverCheck`), `receipt_claim`, `receipt_qr_text`, `receipts_from_response`, `MAX_RECEIPT` (300).
- `ports` (driven ports owned here): `UploadTransport` (`challenge`, `upload`; `UploadError`), `RegistrationRecords` (`attachments` -> `ManifestAttachments`), `ReceiverCheck` (`verify`; `ReceiverCheckError`), `FileAccess` (`pick_destination`, `write`, `sync`, `read_back`, `report`; `DestinationHandle`, `DestinationReport`, `FileAccessError`), `ShareTarget` (`share` -> `ShareOutcome`), `PrivateStorage` (`put`, `get`, `delete`, `put_marker`, `get_marker`; `PrivateStorageError`), `QrScanner` (`scan`; `QrError`). Also used: Trust's `SecureKeyStore` and `RandomSource`; Collection's `ReceiptCheck` and `WallClock`.
- `contract`: `upload_transport_contract`, `unauthorised_destination_contract`, `receiver_check_contract`, `file_access_contract`, `share_target_contract`, `private_storage_contract`, `qr_scanner_contract`, `registration_records_contract`, helpers `hint`, `challenge`.

## Invariants
- An `AuthorisedDestination` can only be created by `authorise`, so nothing is uploaded to an address that has not passed the receiver challenge (DEL-062). Receivers and receipts are authorised solely by a certificate chaining to the trust root (current, unrevoked) and a verifying signature; never by address, domain name or TLS certificate (ADR 0021). Base URLs are never compiled in (DEL-060); all hint sources are untrusted (DEL-061).
- An export is verified in full before it is offered; failure yields `VerificationFailed` (DEL-013). Exports are cumulative: the whole journal (DEL-018). Parity defaults from policy; turning it off when policy forbids gives `ParityRequired`. Upload bodies carry no parity (DEL-016).
- Exporting the active tenancy needs an unlocked session (DEL-029).
- Labels: only a verified receipt on an upload is `Received`; only a matching read-back on local or removable storage is `Saved and checked`; anything else succeeding is `Handed over - not confirmed`, which never counts as delivered; failure is `Failed` (DEL-027). Destinations are not recorded (DEL-028).
- A file copy is written, synced and read back through the destination; a mismatch is `ReadBackMismatch` (DEL-023).
- A receipt whose journal hash differs from the device's record at that `seq` is rejected (`HashMismatch`).
- Port contracts: `UploadTransport::upload` is idempotent; `PrivateStorage` returns stored bytes unchanged and markers replace on write; `FileAccess::read_back` reads through the destination, not a cached copy; `RegistrationRecords` returns stable documents and `None` fields for unknown tenancies.

## Side Effects
None in this crate itself. Through ports: network via `UploadTransport`; file picker, write, sync and read-back via `FileAccess`; share sheet via `ShareTarget`; device-encrypted exports and the per-tenancy `export-counter/<tenancy>` marker via `PrivateStorage`; key-store signing and PoP tokens via `SecureKeyStore`; QR capture via `QrScanner`. Applying a receipt mutates the Collection `Runtime` (clear offer, delivery state). Events are queued in memory and drained by `take_events`.

## Verification
- Run: `cargo test -p fieldseal-delivery` (repo-wide: `just test`)
