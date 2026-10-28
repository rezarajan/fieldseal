# Fieldseal specifications

**Version:** `fieldseal.dev/v1alpha1` · **Status:** Draft, pending the architecture review · **Date:** 2026-10-26

These specs are normative. They are written for **spec-driven development**: implementations are built against them, and tests are traced to their requirement IDs. *Why* each decision was made is in the [ADRs](../../explanation/adr/README.md); terms are defined in the [glossary](../glossary.md); the [system overview](../../explanation/overview.md) shows how the parts fit.

## Conventions

- **Requirement levels.** MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119 and RFC 8174, and only in capitals.
- **Requirement IDs.** Every normative statement has an ID: `<PREFIX>-<NNN>`, for example `REG-014`. IDs are never reused or renumbered; a withdrawn requirement keeps its ID, marked *withdrawn*.
- **Traceability.** Every test names the requirement IDs it covers. A requirement without a test is a gap that blocks its context's release.
- **Resources.** Files that people write or exchange are resources with `apiVersion: fieldseal.dev/v1alpha1` and a `kind`. Their canonical encoding is deterministic CBOR; YAML and JSON are authoring forms, converted by `fieldseal` before signing or hashing.
- **Versioning.** Resource and schema versions follow semantic versioning in their content (`schemaVersion`), and Kubernetes-style maturity in `apiVersion` (`v1alpha1`, `v1beta1`, `v1`). Breaking changes require a new `apiVersion`.
- **Clean architecture.** Every context is specified in the layers of [ADR 0028](../../explanation/adr/0028-clean-architecture.md): the *domain model* section is the entities layer, *driving ports* are the use cases, and *driven ports* are interfaces owned by the use-case layer. No spec places a framework, SDK or transport type in the domain or use cases.
- **Neutral terms.** Specs use only glossary terms. Deployment-specific names belong in deployment documentation ([ADR 0002](../../explanation/adr/0002-name-fieldseal.md)).

## Specs

| Spec | Bounded context | Prefix | Runs in |
|---|---|---|---|
| [Wire formats](./wire-formats.md) | Shared kernel | `WIRE` | Everywhere |
| [Trust](./trust.md) | Trust | `TRU` | Everywhere |
| [Publishing](./publishing.md) | Publishing | `PUB` | Publishing pipeline, factory, runtime (verification) |
| [Instrument](./instrument.md) | Instrument | `INS` | Everywhere |
| [Policy](./policy.md) | Policy | `POL` | Factory, runtime, intake |
| [Registration](./registration.md) | Registration | `REG` | Factory, portal, runtime |
| [Distribution](./distribution.md) | Distribution | `DIS` | Factory, runtime (verification) |
| [Collection](./collection.md) | Collection | `COL` | Runtime |
| [Delivery](./delivery.md) | Delivery | `DEL` | Runtime, intake |
| [Intake](./intake.md) | Intake | `INT` | Intake |
| [Deployment](./deployment.md) | Deployment | `DEP` | Operations |
| [Platform profiles](./platform-profiles.md) | Collection (platform ports) | `PLAT` | Runtime |
| [Android platform profile](./platform-android.md) | Collection (adapters) | `AND` | Runtime on Android |
| [Showcase web app](./web-app.md) | App (development only) | `WEB` | Showcase web app and its browser device |
| [CLI](./cli.md) | All (reference implementation) | `CLI` | Workstations, CI |

## Template

Every spec has these sections, in this order. A section that doesn't apply says so in one line.

1. **Scope** — what the context owns and what it doesn't.
2. **Domain model** — entities, value objects, aggregates, invariants and domain events, in neutral terms.
3. **Driving ports** — the use cases the context offers, with inputs, outputs and errors.
4. **Driven ports** — the interfaces the context needs, with the contract every adapter must meet.
5. **Requirements** — numbered, normative.
6. **Resources and formats** — schemas and examples, where the context defines any.
7. **Twelve-factor** — how the context's components comply ([ADR 0025](../../explanation/adr/0025-twelve-factor-deployments.md)), and where a factor doesn't apply.
8. **Conformance** — the tests that must exist, and the `fieldseal` commands that check an implementation.
9. **Open questions** — anything the architecture review must decide.
10. **References** — ADRs and external standards.
