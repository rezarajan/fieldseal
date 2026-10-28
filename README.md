# Fieldseal

Fieldseal collects structured data about people in the field, on devices that may be shared, offline or both, and delivers it to an authority by any route. Every step carries proof, from the definition of what is collected to the record that lands:
- **Instruments are published** with review, threshold signatures, provenance and a transparency log.
- **Devices make their own hardware-backed keys** and register them with the authority's factory through a portal. The factory doesn't care which identity provider the authority uses.
- **Bundles are sealed to one device**, and the runtime verifies the instrument's own signatures before rendering it.
- **Records are sealed to the authority** as they are written, and stay reviewable by the collector until delivery is confirmed and the local copy is cleared.
- **Intake verifies everything** before landing records in a generic format.

## Documentation

Start at [`docs/index.md`](docs/index.md):
- [System overview](docs/explanation/overview.md): architecture diagram, bounded contexts, hexagonal structure.
- [ADRs](docs/explanation/adr/README.md): every decision, one per file.
- [Specifications](docs/reference/spec/README.md): normative, per bounded context, with requirement IDs for spec-driven development.
- [Glossary](docs/reference/glossary.md).

## Status

**Design:** `fieldseal.dev/v1alpha1`, proposed. It is accepted through the architecture review issue.

**Code:** the format core, the bounded contexts, their adapters, the `fieldseal` CLI, the factory, the transparency log, the intake upload endpoint and the web app with its browser device, built against the specs. `just up` runs them as a local compose stack; [the hands-on tutorial](docs/tutorials/hands-on.md) walks every step.

> This repository contains design intent for handling personal data, including data about minors. Keep it private.
