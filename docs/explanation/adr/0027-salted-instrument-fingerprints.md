# ADR 0027: Identify instruments by a salted fingerprint

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Every instrument version is identified only by a salted SHA-256 fingerprint of its contents; names and versions are labels, so look-alike sheets never collide.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Many authorities, programmes and authors will publish instruments, and names will overlap ("Health check", "Baseline survey v2"). Two instruments can even have identical contents yet be distinct sheets, for example the same form adopted by two programmes that must be analysed separately. Records, consent, intake and data contracts all need an identifier that can't be confused, can be verified from the instrument itself, and doesn't depend on a name.

## Decision

- Every published instrument version MUST be identified by its **fingerprint**: `SHA-256("fieldseal.dev/instrument-fingerprint/v1" ‖ salt ‖ canonical bytes)`.
- The **salt** MUST be 32 random bytes generated when the instrument version is first built for publishing, and MUST stay fixed for that version. It is not secret: it MUST be recorded in the artefact and its provenance, so anyone holding the instrument can recompute the fingerprint. *(Amended 2026-10-27: the salt is not in the transparency-log entry, which holds only a hash, a signature and a key ([ADR 0030](./0030-public-transparency-log.md), PUB-091).)*
- Two publications MUST therefore have different fingerprints even when their names, versions or contents are identical.
- `metadata.name` and `metadata.version` MUST be treated as human labels only and MUST NOT be used to identify, look up or join instruments.
- Records, consent records, bundles, intake landing and data contracts MUST reference instruments by fingerprint.
- User interfaces and documentation SHOULD show a short form (the first 8 bytes in base32) beside the name.
- Any change to an instrument MUST produce a new version with a new salt and fingerprint.

## Consequences

- Look-alike or reused sheets are always distinguishable in data and analysis.
- The registry, factory, runtime and intake verify an instrument by recomputing its fingerprint, with no lookup by name.
- Re-publishing identical content creates a distinct instrument; if two programmes should share data, they MUST share one published instrument.

## Specs

[instrument](../../reference/spec/instrument.md) · [publishing](../../reference/spec/publishing.md) · [wire-formats](../../reference/spec/wire-formats.md)
