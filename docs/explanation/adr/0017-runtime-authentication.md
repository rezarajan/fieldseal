# ADR 0017: Runtime authentication independent of the device lock

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** The runtime has its own hardware-bound PIN, separate from the device lock, with no biometric unlock.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Other people, including children, use the same device and may know its lock-screen credential. No unauthorised person may reach the runtime's data in any form.

## Decision

- The runtime MUST have its own PIN per tenancy and MUST NOT use the device's lock credential.
- The session key MUST combine a key-store-unwrapped secret with a memory-hard hash of the PIN.
- Wrong PINs MUST cause escalating delays; the session MUST lock on background, screen off and idle; secure display MUST be on everywhere.
- The runtime MUST NOT offer biometric unlock.
- The platform profile MUST stop other device users from removing, resetting, debugging or reading the runtime's storage.

## Consequences

- PIN length, lockout steps and timeouts are runtime policy above the invariant floors.
- A forgotten PIN loses only the local record; the sealed journal survives.

## Specs

[collection](../../reference/spec/collection.md) · [platform-profiles](../../reference/spec/platform-profiles.md)
