# ADR 0021: Export, upload and receipts, to any authorised destination

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Send records to any destination that proves it holds an authority-certified receiver key; addresses are hints from anywhere, never baked in or canonical.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Records must reach the authority by any route, with honest feedback about what is known to have arrived. Domain names and hosting change at any time, so an address can't be what makes a destination trustworthy, and a runtime build is shared by every authority, so it can't contain one. Bundles already work this way: they are trusted for their signature, whatever route they arrive by.

## Decision

- **Destinations are identified by keys, not addresses.** A destination is authorised to receive a tenancy's records only if it proves possession of a **receiver key** certified for that purpose by the authority root in the device's trust bundle ([ADR 0008](./0008-trust-hierarchy.md)).
- **Addresses are hints.** The runtime MUST NOT contain a destination address in its build, and bundles MUST NOT be required to carry one. An address MAY come from any source (device configuration, a scanned QR code, collector entry, a previous successful upload, or an advisory hint in a bundle), and the runtime MUST treat it as untrusted.
- **Prove before sending.** Before uploading anything, the runtime MUST send a fresh challenge, and the destination MUST answer with its receiver-key certificate and a signature over the challenge, the tenancy and the upload purpose. The runtime MUST NOT upload unless the certificate chains to its trust root, is current and unrevoked, and the signature verifies.
- **Receipts are verified the same way.** A receipt MUST be signed by a receipt key that chains to the same root; any other receipt MUST be ignored.
- **When online**, the runtime SHOULD upload new records in the background to the first authorised destination it can reach.
- **Otherwise** it MUST write one export file (opaque handle, sealed manifest, sealed records, signature) and MAY include Reed–Solomon parity, which MUST default to on for files. A file can go anywhere: it is sealed to the authority, so a wrong recipient learns nothing.
- **Labels say only what is known:** "Received" (verified receipt), "Saved and checked" (synced and read back), "Handed over — not confirmed" (anything else). File names MUST carry only a date and counter.

## Consequences

- An authority can move or add intake hosts, change domains or use mirrors with no change to runtimes or bundles; only its keys matter.
- A spoofed or hijacked address can't receive data: it can't produce a certified receiver signature.
- Each intake host needs a receiver key from the authority, rotated like any purpose key.

## Specs

[delivery](../../reference/spec/delivery.md) · [trust](../../reference/spec/trust.md) · [wire-formats](../../reference/spec/wire-formats.md)

## Note: the server binary

The upload endpoint is served by the intake app (`fieldseal-intake`, `crates/apps/intake`). The practice endpoint is the separate binary `fieldseal-upload-practice`; the former `fieldseal-upload-server` is gone.
