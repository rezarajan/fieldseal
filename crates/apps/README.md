# apps

## Overview

The outermost layer: binaries that wire adapters to context use cases (composition roots), and the test-harness crates that exercise the whole system. Apps may depend on the kernel, contexts and adapters ([ADR 0028](../../docs/explanation/adr/0028-clean-architecture.md)). `just up` runs the service binaries as a local compose stack ([how-to](../../docs/how-to/run-the-local-stack.md)).

## Subdirectories & Boundaries

- cli: [./cli/README.md](./cli/README.md) - The `fieldseal` binary: reference implementation of every operation, exit codes 0–6, and `fieldseal conformance` ([./cli/src/conformance_cmd/README.md](./cli/src/conformance_cmd/README.md)).
- intake: [./intake/README.md](./intake/README.md) - `fieldseal-intake`: the upload endpoint with start-up replay and the OIDC-protected results reader, configured from `FIELDSEAL_*` environment variables. Refuses development adapters in production.
- factory: [./factory/README.md](./factory/README.md) - `fieldseal-factory`: the registration API and portal, configured from `FIELDSEAL_*` environment variables. Refuses development settings in production.
- translog: [./translog/README.md](./translog/README.md) - `fieldseal-translog`: an append-only, fsynced Merkle transparency-log HTTP server.
- web: [./web/README.md](./web/README.md) - `fieldseal-web`: a development-only showcase web app (instrument viewer, WASM evaluation, device flow, service proxies). Refuses production.
- dev-idp: [./dev-idp/README.md](./dev-idp/README.md) - `fieldseal-dev-idp`: a development-only OpenID Connect provider that stands where Keycloak stands in `just web`. Refuses production and any non-loopback address; in no image.
- e2e: [./e2e/README.md](./e2e/README.md) - Test-only in-process Site/Phone/Intake harness for end-to-end and fault-injection suites.
- security-tests: [./security-tests/README.md](./security-tests/README.md) - Adversarial suites (hostile bytes, replay, injection, leaks), and the manual cargo-fuzz harness at [./security-tests/fuzz/README.md](./security-tests/fuzz/README.md).
