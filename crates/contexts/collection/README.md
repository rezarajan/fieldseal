# fieldseal-collection

## Overview
The Collection bounded context: the device-side runtime that creates a tenancy, runs PIN-gated sessions, captures instrument answers and evidence, seals records into a hash-chained journal and a readable local record, reviews, clears after receipts, and closes with crypto-erase. Spec: [collection.md](../../../docs/reference/spec/collection.md); layering per ADR 0028. The crate is pure: platform effects come through the ports it owns (and Trust's `SecureKeyStore`, `Attestor`, `RandomSource`).

## Interface
`lib.rs` exposes `application`, `contract`, `domain`, `ports`.
- [`application`](./src/application/README.md): `Runtime`, `Platform`, `Provisioning`, `CollectionError`, `CollectionEvent` and the view/outcome types.
- [`domain`](./src/domain/README.md): `TenancyState`, `RuntimePin`, `ClearConfirmation`, `Capture`, `Payload`, `TenancyMeta`, `TickState`, `PinAttempts`, `ReceiptCoverage`, `OpenedBundle`, `CloseCertificate`, etc.
- `ports` (driven ports with their error enums): `ElapsedClock`, `SecureStorage` (`StorageError`), `SecureDisplay` (`DisplayError`), `DevicePolicy` (`DevicePolicyError`), `Camera` (`CameraError`), `MemoryHardHash`, `ReceiptCheck` (`ReceiptCheckError`; Delivery reuses it as its `ReceiptVerifier`), `WallClock`, `FileAccess` (source side, `FileAccessError`), `BundleOpener` (Distribution plugs in; `BundleOpenError`), `CloseCertificateCheck` (Registration plugs in; `CloseCertificateError`).
- `contract`: contract-test functions every adapter must pass: `elapsed_clock_contract`, `secure_storage_contract`, `record_signing_key_store_contract`, `wall_clock_contract`, `file_access_contract`, `bundle_opener_contract`, `secure_display_contract`, `device_policy_self_managed_contract`, `device_policy_emm_contract`, `camera_contract`, `memory_hard_hash_contract`, `receipt_check_contract`, `close_certificate_check_contract`.

## Invariants
- `ElapsedClock`: within one boot count readings never decrease; the user cannot set it.
- `SecureStorage`: write replaces fully or leaves the old object; append adds all bytes or none; data is synced before return; the two classes are separate namespaces; deleted objects are unrecoverable. The runtime does not rely on atomic append (a torn journal frame is truncated, COL-093).
- `SecureDisplay`: after `protect` succeeds, `is_protected` is true.
- `DevicePolicy::effective_restrictions` reads live platform state, `Unknown` when unreadable; in EMM mode `apply` returns `NotDeviceOwner`.
- `MemoryHardHash` is deterministic, distinguishes PINs and salts, and returns `None` below the parameter floor.
- `ReceiptCheck` accepts only receipts signed by a `receipt` key chaining to the trust root, whatever route.
- `FileAccess` returns exactly the picked file's bytes and offers no gallery or media index (COL-042).
- `BundleOpener` returns contents only for an envelope-verified bundle sealed to this device; same bytes open to the same contents.
- `CloseCertificateCheck` accepts only close/reset certificates under `fieldseal.dev/close-certificate/v1` or `.../reset-certificate/v1` from a registration key chaining to the trust root, with no PIN or tenancy key needed.

## Side Effects
None in this crate itself; all I/O is by adapters implementing the ports. Use-case side effects are listed in the [application contract](./src/application/README.md).

## Verification
- Run: `cargo test -p fieldseal-collection` (repo-wide: `just test`)
