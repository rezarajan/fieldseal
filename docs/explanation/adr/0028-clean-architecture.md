# ADR 0028: Clean architecture and the dependency rule

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Within every context, source dependencies point only inward (domain ← use cases ← adapters ← frameworks), and CI fails any build that breaks this.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

[ADR 0003](./0003-ddd-and-hexagonal-architecture.md) splits each bounded context into domain, application, ports and adapters. Hexagonal architecture says *what the parts are*; it doesn't by itself stop an Android class, an HTTP type or an HSM SDK leaking into the domain over time. Clean architecture adds the rule that keeps the parts separate: the **dependency rule**. Without enforcement, the boundaries erode, and swapping a platform or provider stops being "a new adapter".

## Decision

Every bounded context MUST be organised in four concentric layers, refining ADR 0003:

| Layer (innermost first) | Contains | May depend on |
|---|---|---|
| **Entities** (domain) | Entities, value objects, aggregates, domain events, invariants; the shared kernel's formats | Only other entities, and pure libraries (cryptographic primitives, CBOR) |
| **Use cases** (application) | One use case per driving port; the **driven-port interfaces** it needs | Entities; nothing outward |
| **Interface adapters** | Adapters implementing driven ports; controllers, presenters and CLI commands driving use cases; mapping to and from transport and storage formats | Use cases and entities |
| **Frameworks and drivers** | Android SDK, Compose, HTTP servers, databases, HSM and KMS SDKs, identity-provider SDKs, the data platform | Adapters only, at the edge |

- **The dependency rule:** source-code dependencies MUST point only inward. An inner layer MUST NOT name, import or reference anything in an outer layer.
- **Dependency inversion:** driven ports MUST be declared by the use-case layer, as interfaces the use cases own; adapters implement them.
- **Plain data at boundaries:** data crossing a layer boundary MUST be plain values or DTOs defined by the inner layer. Framework types (an Android `Context`, an HTTP request, an ORM row, an SDK client) MUST NOT appear in entities or use cases.
- **No ambient dependencies:** time, randomness, I/O, configuration and logging MUST reach entities and use cases only through ports. Entities MUST NOT read the environment or a clock.
- **One composition root per deployable** (each service, the runtime, the CLI) MUST wire adapters to ports from configuration ([ADR 0025](./0025-twelve-factor-deployments.md)). No other code may choose an adapter.
- **Enforcement in CI.** Architecture tests MUST fail the build on any inward-rule violation:
  - Rust: a crate-graph check over `cargo metadata` (entity and use-case crates may depend only on allowed inner crates and pure libraries);
  - Kotlin: Konsist or ArchUnit rules;
  - Python: import-linter contracts.
- **Testing by layer.** Entities and use cases MUST be testable with in-memory adapters alone, with no framework on the test path.

## Consequences

- Swapping a platform, identity provider, HSM or data platform touches adapters and the composition root only, and the architecture tests prove it.
- The format core is the innermost ring shared by every context; bindings (UniFFI, PyO3) are interface adapters around it.
- Some convenience is given up: frameworks' own dependency-injection containers, annotations and models stay at the edge.
- This refines ADR 0003; it doesn't supersede it.

## Specs

[spec index](../../reference/spec/README.md) · [cli](../../reference/spec/cli.md)
