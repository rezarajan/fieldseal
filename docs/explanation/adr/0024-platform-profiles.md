# ADR 0024: Platform profiles

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Each OS gets a platform profile of adapters; Android first, other platforms later.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

The runtime must not be tied to one operating system, but each platform meets the security requirements differently.

## Decision

- Each operating system MUST have a platform profile defining adapters for key store, attestation, monotonic clock, secure display, device management, file access, camera and network.
- A profile MUST declare which requirements it meets in hardware, software or not at all.
- Android MUST be the first profile. Other profiles (iOS/iPadOS, Windows, Linux) are **Won't** for this delivery and MUST follow the same port contracts when built.

## Consequences

- Platform work is adapters and a UI shell over the shared core.

## Specs

[platform-profiles](../../reference/spec/platform-profiles.md)
