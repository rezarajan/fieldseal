# ADR 0031: Device management through one port, self-managed by default

**Status:** Accepted (2026-10-26, decided by the project lead in architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Device lock-down sits behind a DevicePolicy port with a self-managed adapter (runtime as device owner, default) and an EMM adapter; either way the runtime verifies at start-up that the restrictions are really in force.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

On Android, exactly one app can be device owner and enforce the restrictions that keep household members out of the runtime ([ADR 0017](./0017-runtime-authentication.md)). Some authorities have no device-management service and need offline, portable provisioning; others already manage devices with an EMM such as Intune. In the EMM case, the restrictions are configured outside Fieldseal and could be wrong or missing.

## Decision

- Device restrictions MUST be reached only through the `DevicePolicy` port, with two adapters per platform where the platform allows:
  - **Self-managed (default):** the runtime is the device owner and applies the restrictions from its signed runtime policy.
  - **EMM-managed:** an EMM is device owner and applies them; the runtime only reads their state.
- The port MUST offer `effectiveRestrictions()`, returning what is actually in force, read from the platform rather than from configuration.
- At every start, and at each posture re-check, the runtime MUST compare the effective restrictions with the required set in runtime policy. On any gap it MUST flag the tenancy's posture, report it to the factory when online, and the factory MUST pause new bundle releases. Collection and delivery MUST NOT be blocked by it.
- Which adapter a deployment uses MUST be set in its deployment manifest and provisioning configuration, never in the build.
- Device-ID (serial) attestation MAY be unavailable in EMM mode; the serial check is already optional.
- Self-managed is **Must** for this delivery; EMM-managed is **Should**.

## Consequences

- One runtime build serves authorities with and without an EMM.
- A misconfigured EMM can't silently leave a device unprotected; the gap is detected and data release pauses.
- Each EMM adapter is tested against the same port contract.

## Specs

[platform-profiles](../../reference/spec/platform-profiles.md) · [platform-android](../../reference/spec/platform-android.md) · [registration](../../reference/spec/registration.md)
