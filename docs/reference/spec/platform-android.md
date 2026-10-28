# Android platform profile

**Prefix:** `AND` · **Context:** Collection (adapters) · **Runs in:** runtime on Android · **Status:** Draft

## 1. Scope

This profile implements every [platform port](./platform-profiles.md) on Android. It fixes the minimum OS, how the runtime is provisioned, which device policies it applies, and which Android APIs each adapter uses. Items marked **must verify** depend on device behaviour that has to be confirmed on the procured model before the profile is released (the hardware spike).

It does not define runtime UI or byte formats.

## 2. Domain model

The profile adds no domain concepts. It maps platform ports to Android:

| Port | Android adapter |
|---|---|
| `KeyStore` | AndroidKeyStore, through `DevicePolicyManager.generateKeyPair` when device owner, otherwise `KeyPairGenerator` / `KeyGenerator` |
| `Attestor` | Android key attestation certificate chain |
| `ElapsedClock` | `SystemClock.elapsedRealtime()`, `Settings.Global.BOOT_COUNT` |
| `SecureDisplay` | `WindowManager.LayoutParams.FLAG_SECURE` |
| `DevicePolicy` | `DevicePolicyManager` as device owner, or an EMM acting as device owner |
| `FileAccess` | Storage Access Framework (`ACTION_CREATE_DOCUMENT`, `ACTION_OPEN_DOCUMENT`) |
| `ShareTarget` | `Intent.ACTION_SEND` through a `FileProvider` |
| `Camera` | CameraX `ImageCapture` with an in-memory callback; bundled-model barcode scanning |
| `Network` | Platform HTTP stack with TLS; certificate pinning per bundle |
| `Storage` | Device-protected storage (`createDeviceProtectedStorageContext`) for the `device` class; app storage holding runtime-encrypted files for the `session` class |

## 3. Driving ports

Not applicable.

## 4. Driven ports

As in [platform profiles §4](./platform-profiles.md#4-driven-ports). The Android contracts below are additional.

## 5. Requirements

### Platform

- **AND-001** The runtime MUST require Android 14 (API 34) or later.
- **AND-002** The runtime MUST be distributed as an APK signed with the authority-independent Fieldseal release key; the signing-certificate digest MUST be published with the build so factories can pin it.

### Provisioning and management

- **AND-010** The runtime MUST support provisioning as device owner by: the setup-wizard QR code (download URL and signing-certificate checksum, with provisioning configuration in the admin extras bundle), zero-touch enrolment, and `adb shell dpm set-device-owner` on a bench.
- **AND-011** Alternatively, a deployment MAY use an EMM as device owner. The EMM MUST then enforce every policy in AND-020–029 and deliver provisioning configuration as managed configuration (`RestrictionsManager`); the runtime MUST verify, through `DevicePolicy.status()`, that they are in force.
- **AND-012** Provisioning configuration (DEP-020) MUST be read from the admin extras or managed configuration only.

### Device policies

When device owner, the runtime MUST apply, and an EMM MUST apply on its behalf:

- **AND-020** `setUninstallBlocked(admin, runtimePackage, true)`.
- **AND-021** `setUserControlDisabledPackages(admin, [runtimePackage])`, so users can't force-stop or clear the runtime's data.
- **AND-022** User restriction `DISALLOW_DEBUGGING_FEATURES`.
- **AND-023** User restriction `DISALLOW_SAFE_BOOT`.
- **AND-024** User restriction `DISALLOW_FACTORY_RESET`, and enterprise factory-reset protection (`setFactoryResetProtectionPolicy`) naming the authority's accounts, so a recovery-mode reset leaves the device unusable until the authority releases it. *Must verify.*
- **AND-025** `setBackupServiceEnabled(admin, false)`, and `android:allowBackup="false"` with data-extraction rules excluding all runtime data.
- **AND-026** User restrictions `DISALLOW_CONTENT_CAPTURE` and `DISALLOW_CONTENT_SUGGESTIONS`.
- **AND-027** `setPermittedInputMethods` and `setPermittedAccessibilityServices` set to the allow-lists in runtime policy (empty accessibility list by default).
- **AND-028** The runtime MAY apply `DISALLOW_ADD_USER` and `DISALLOW_USB_FILE_TRANSFER` only when runtime policy requests them, because USB file transfer may be needed for removable export (*must verify*).
- **AND-029** Lock-task mode (`setLockTaskPackages`) MUST be off by default and MUST be enabled when runtime policy `runtime.device.kiosk` is `true`; the allow-list MUST then include the documents UI and every allowed share target.

### Keys

- **AND-030** Signing keys MUST be EC P-256 with `PURPOSE_SIGN`, digest SHA-256; agreement keys MUST be EC P-256 with `PURPOSE_AGREE_KEY`; the session wrapping key MUST be AES-256-GCM with `PURPOSE_ENCRYPT | PURPOSE_DECRYPT`.
- **AND-031** Every key MUST be created with `setUnlockedDeviceRequired(true)` and without validity dates.
- **AND-032** Keys MUST be generated with `setAttestationChallenge(challenge)` set to the factory nonce when available, otherwise a local nonce (REG).
- **AND-033** The runtime MUST request StrongBox (`setIsStrongBoxBacked(true)`) and fall back to the TEE if StrongBox is unavailable or doesn't support the purpose. Whether StrongBox supports `PURPOSE_AGREE_KEY` on the procured model is *must verify*.
- **AND-034** When device owner, the runtime SHOULD generate keys through `DevicePolicyManager.generateKeyPair` with `ID_TYPE_SERIAL` to include device-ID attestation; when not device owner it MUST use `KeyPairGenerator` and declare PLAT-013 `unmet`.
- **AND-035** The runtime MUST NOT use `setUserAuthenticationRequired` bound to the device credential, because the device credential may be known to other users (ADR 0017); session protection comes from the runtime PIN.
- **AND-036** Shared secrets from `KeyAgreement.generateSecret()` MUST be passed to the format core and zeroed immediately.

### Display, input and storage

- **AND-040** Every runtime window MUST set `FLAG_SECURE`.
- **AND-041** Every text field MUST set `IME_FLAG_NO_PERSONALIZED_LEARNING` and `importantForAutofill="no"`.
- **AND-042** Names, item values and images MUST NOT be placed in saved-instance state, navigation arguments, notifications or the clipboard.
- **AND-043** The journal and outbox MUST be stored in device-protected storage, so forced close works without the runtime PIN; the local record, rosters and progress MUST be stored encrypted under the session key in app storage.
- **AND-044** The runtime MUST lock its session on `onStop`, on `ACTION_SCREEN_OFF`, and after the idle timeout in runtime policy.

### Files, sharing and camera

- **AND-050** Saves MUST use `ACTION_CREATE_DOCUMENT`; after writing, the runtime MUST call `ParcelFileDescriptor.getFileDescriptor().sync()`, close, reopen the same URI and compare SHA-256 (DEL-022).
- **AND-051** The destination class MUST be decided from the document URI's authority: `com.android.externalstorage.documents` with a primary volume is `local`; with a removable volume is `removable`; any allow-listed cloud provider authority is `cloud`; anything else MUST be refused unless runtime policy lists it. *Must verify* the volume identification on the procured model.
- **AND-052** Sharing MUST use `ACTION_SEND` with a `FileProvider` URI and `FLAG_GRANT_READ_URI_PERMISSION`, limited to share targets in runtime policy.
- **AND-053** Camera capture MUST use CameraX `ImageCapture.takePicture` with `OnImageCapturedCallback`; images MUST NOT be written to files or MediaStore.
- **AND-054** QR scanning MUST use a barcode decoder bundled in the APK (no model download through Play services).

### Clock

- **AND-060** `ElapsedClock` MUST use `SystemClock.elapsedRealtime()` and `Settings.Global.BOOT_COUNT`. Behaviour across reboot, deep sleep and battery exhaustion is *must verify*.

### Device-management adapters ([ADR 0031](../../explanation/adr/0031-device-management-adapters.md))

- **AND-061** The **self-managed** adapter MUST run the runtime as device owner and apply the restrictions through `DevicePolicyManager` (AND-020–AND-029).
- **AND-062** The **EMM-managed** adapter MUST NOT require device-owner rights, and MUST read state only: for example `DevicePolicyManager.isUninstallBlocked(null, <package>)` and `UserManager.getUserRestrictions()` for debugging, safe boot and factory-reset restrictions. *Must verify on hardware:* which restrictions a non-admin app can read; any it can't read MUST be reported as `unknown` (PLAT-042).
- **AND-063** Both adapters MUST report the same restriction names, so runtime policy and factory policy don't depend on the adapter.
- **AND-064** In EMM mode, device-ID attestation MAY be unavailable; the runtime MUST then omit it, and factory policy's serial check applies (`off` or `optional`).

## 6. Resources and formats

Provisioning QR (setup wizard) extras used by the profile:

| Extra | Value |
|---|---|
| `android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME` | The runtime's admin receiver |
| `android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION` | Build download URL |
| `android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM` | Signing-certificate SHA-256, URL-safe base64 |
| `android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE` | Provisioning configuration (DEP-020): trust-bundle digest, factory URL, initial runtime policy digest |

Attestation evidence format identifier: `android-key-attestation/1` (WIRE §attestation).

## 7. Twelve-factor

| Factor | Android profile |
|---|---|
| II. Dependencies | Gradle dependencies locked and checksum-verified; no code loaded at run time |
| III. Config | Admin extras or managed configuration only; nothing authority-specific in the APK |
| V. Build, release, run | One signed APK for every authority; release = APK + provisioning configuration |
| IX. Disposability | Atomic writes in device-protected storage; resumable operations survive process death |
| X. Dev/prod parity | Same APK on emulator and devices; emulator evidence is software-level and refused by production policy |
| XI. Logs | Structured events to the sealed diagnostic stream; `Log` calls stripped from release builds |
| VII, VIII, XII | Not applicable on device |

## 8. Conformance

| Test | Covers | Check |
|---|---|---|
| Policies applied after provisioning by QR, zero-touch and adb; status reports all in force | AND-010–029 | Instrumented test on device; `fieldseal device simulate` can't cover this |
| Keys have expected purposes, protections and challenge; evidence verifies at a test factory | AND-030–036 | Instrumented test plus `fieldseal registration inspect` on the produced request |
| No runtime window capturable; no IME learning; no saved state with names | AND-040–042 | Screenshot test, IME test, state dump scan |
| Session locks on stop, screen off and idle | AND-044 | Instrumented test |
| Save, sync, read-back and destination class for internal storage, USB OTG and one cloud provider | AND-050–051 | Hardware lab |
| Camera images never reach disk | AND-053 | File-system diff around capture |
| Elapsed clock and boot count across reboot and sleep | AND-060 | Hardware lab |

### Must verify (hardware spike)

| Item | Requirement |
|---|---|
| Enterprise factory-reset protection blocks reuse after recovery reset | AND-024 |
| `DISALLOW_USB_FILE_TRANSFER` does not block SAF writes to USB OTG | AND-028 |
| StrongBox support for `PURPOSE_AGREE_KEY` and AES-GCM | AND-033 |
| Device-ID attestation through `generateKeyPair` | AND-034 |
| Volume identification for removable storage | AND-051 |
| Elapsed clock behaviour across reboot, deep sleep, battery exhaustion | AND-060 |
| Whether the model swaps memory to flash | PLAT-023 |

## 9. Open questions

1. Device owner by the runtime, or an EMM (for example Intune) as device owner? Both are allowed by AND-011; a deployment must choose one.
2. Should `DISALLOW_INSTALL_UNKNOWN_SOURCES` and an app allow-list be defaults for household devices, or left to the deployment?

## 10. References

- ADRs: [0012](../../explanation/adr/0012-local-first-device-keys.md), [0017](../../explanation/adr/0017-runtime-authentication.md), [0021](../../explanation/adr/0021-export-upload-receipts.md), [0024](../../explanation/adr/0024-platform-profiles.md), [0025](../../explanation/adr/0025-twelve-factor-deployments.md)
- Android key attestation; Android Enterprise device-owner provisioning; NIST SP 800-124 Rev. 2
