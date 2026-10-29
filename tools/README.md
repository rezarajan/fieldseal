# tools

## Overview

Repository scripts (bash and Python) behind the `just` entry points in [justfile](../justfile): building
artefacts, running the local container stack, releasing, and enforcing repository rules (architecture,
spec coverage, test inventory, test budget). Everything normally runs inside the Nix dev shell
(`nix develop path:.`); the justfile wraps recipes in it. Build background:
[build-system.md](../docs/explanation/build-system.md), [build-and-check.md](../docs/how-to/build-and-check.md),
[run-the-local-stack.md](../docs/how-to/run-the-local-stack.md). Browser and accessibility tests are in
[browser-tests](./browser-tests/README.md).

## Interface

### Build and checks

| Script | Purpose |
|---|---|
| `build.sh` | Builds every artefact into `$DIST` (default `dist/`): architecture and coverage checks, `cargo test --workspace --locked`, `cargo deny` if `deny.toml` exists, Android native libs and Kotlin bindings (when `FIELDSEAL_ANDROID_HOST=1`), a manylinux_2_28 abi3 Python wheel, the Android APK when the runtime exists, and `SHA256SUMS`. Needs `FIELDSEAL_ANDROID_MIN_SDK`; also reads `FIELDSEAL_ANDROID_HOST`. |
| `check-portable.sh [dist]` | Fails if artefacts in `dist/` (including inside wheels and APKs) depend on Nix, embed builder home paths, mislink Android libraries (16 KB alignment) or need glibc newer than 2.28. |
| `check-architecture.py` | Enforces the dependency rule from `architecture.toml` using `cargo metadata`: no outward dependencies, third-party allow-list for inner crates, no ambient I/O, time or randomness in inner layers. |
| `check-coverage.py` | Reports which spec requirement IDs (docs/reference/spec) have tests. Options: `--json`, `--list-uncovered PREFIX`, `--fail-under-must PREFIX=PCT ...`, `--baseline tools/coverage-baseline.toml`. Scans `crates`, `runtimes`, `tests`. |
| `coverage-baseline.toml` | The `[must]` coverage floor per spec prefix, read by `check-coverage.py --baseline`. (`check_coverage_test.py` tests the checker.) |
| `test-inventory.py` | Writes `docs/reference/test-inventory.md`; `--check` fails on unjustified tests or a stale document; `--report` lists unjustified tests. |
| `test-budget.sh` | Runs `cargo nextest` and doc tests; fails if over `FIELDSEAL_TEST_BUDGET` seconds (default 20). |
| `test-python-vectors.sh` | Builds `fieldseal-py`, copies the library as `fieldseal.abi3.so` into a temp dir and runs the Python golden-vector tests. |
| `build-adapter-font.sh` | Regenerates `crates/adapters/html/src/fonts.css` (Nunito Sans subset as woff2 data URIs). Needs nix. |
| `emulator.sh [--headless]` | Creates (once) and starts the Android test emulator; reads `FIELDSEAL_ANDROID_PLATFORM`, `FIELDSEAL_EMULATOR_ABI`. Run in the `emulator` dev shell. |

### Local stack (all honour `FIELDSEAL_CONTAINER_ENGINE`, `docker` default or `podman`)

| Script | Purpose |
|---|---|
| `stack-engine.sh` | Sourced by the others; picks the engine and compose; `FIELDSEAL_PODMAN_HOME` sets Podman's home. |
| `stack-cli.sh` | Prints the path of the `fieldseal` CLI (built on demand by Nix; `FIELDSEAL_BIN` overrides). |
| `stack-images.sh [names]` | Builds images with Nix and loads them (`factory upload translog cli web demo`). |
| `stack-up.sh` | Generates secrets once, renders per-service env files, loads images, starts compose, waits for endpoints. `FIELDSEAL_SKIP_IMAGE_BUILD=1` reuses images. |
| `dev-web.sh [--check [--browser]]` | `just web`: the log, the factory, the intake app, the development IdP and the collector stand-in natively from `examples/deployments/dev-web.yaml`, the bundled examples published, state in `deploy/local/.state/dev-web/`. `--check` starts them, waits for each, compares the development adapters each service reports with the manifest, checks the pages, the bundle fetch and the edit-and-reload loop, and stops them; `--browser` adds the cookie-scoping check (`browser-tests/cookies.sh`). Uses ports 8080, 8090, 8180, 8480, 8481, 9001. |
| `dev-publish.sh <survey>\|--all` | `just publish <survey>`: publishes a survey (and its layouts) through the log of `just web`; `--all` the bundled examples and the publishing policy. |
| `stack-init.sh` | Runs as the `init` compose service: root ceremony, purpose keys, log key and trust bundle (once). |
| `stack-compose.sh args...` | Runs compose for the stack; requires `just up` to have run. |
| `stack-status.sh` | Containers and endpoint health. |
| `stack-down.sh [--purge]` | Stops the stack; `--purge` also removes volumes, generated files and secrets. |
| `stack-run.sh step [arg]` | Runs one demo or walkthrough step (`demo`, `seed`, `resume`, `authority`, `publish`, `registry`, `fetch`, `enrol`, `register`, `wait`, `bundle`, `capture`, `upload`, `intake`); starts the stack if needed. |
| `stack-demo.sh` | The demo entry run inside the `demo` container (steps `demo`, `seed`, `resume`, ...). |
| `stack-enroll.sh` | Hook for `local-stack-passkey.py`: builds a sealed registration request from `FIELDSEAL_TOKEN` and submits it to `FIELDSEAL_FACTORY_URL`. |
| `local-stack-passkey.py` | Drives the portal in headless Chromium with a virtual WebAuthn authenticator (needs `websockets`); `--on-token CMD`, `--emit-json FILE`, `--chromium PATH`, `--show-token`. |
| `stack-smoke.sh [--no-up] [--keep] [--browser]` | Opt-in smoke check of the running stack; refuses to run in CI. |
| `stack-acceptance.sh` | Walks `docs/tutorials/hands-on.md` step by step against a fresh stack. |
| `demo-pipeline.sh [work-dir]` | Local end-to-end demo through the real `fieldseal` commands with software keys; uses `FIELDSEAL_BIN` (default `target/debug/fieldseal`). |

### Release

| Script | Purpose |
|---|---|
| `release-images.sh <registry/prefix> <tag> [--push] [--sign]` | Builds per-release service images with Nix, tags them, optionally pushes and cosign-signs; writes `release-docs/images.txt`. |
| `release-docs.sh <tag> <out-dir>` | Writes the signed release record `release.cbor`, the documentation bundle and a summary. Signing key: `FIELDSEAL_RELEASE_SIGNING_KEY_FILE` (absent means a practice release); also `FIELDSEAL_RELEASE_ENVIRONMENT`, `FIELDSEAL_BIN`. |

## Invariants

- Scripts use `set -euo pipefail` (shell) and locate the repository root relative to their own path.
- `check-architecture.py` and `test-inventory.py --check` gate `just test`; the test suite must finish within its budget.
- The coverage baseline only ratchets upward.
- Stack state (secrets, volumes, the registered device) persists across `just down` and `just up`; only `--purge` forgets it.
- Builds remap builder paths so artefacts contain no home directories or Nix store paths (`check-portable.sh`).

## Side Effects

- Stack scripts start and stop containers, create volumes, write generated secrets and env files under `deploy/local`, and load images into the engine.
- `stack-up.sh`, `stack-smoke.sh` and release scripts invoke Nix builds; `stack-smoke.sh` pulls the Keycloak image.
- `build.sh` deletes and recreates `dist/`; `release-docs.sh` and `release-images.sh` write `release-docs/`.
- `test-inventory.py` rewrites `docs/reference/test-inventory.md`; `build-adapter-font.sh` rewrites `fonts.css`.
- `demo-pipeline.sh` writes keys and state in a local work directory; nothing leaves the machine.

## Verification

- Run: `just test` (inventory check, test budget, clippy, architecture check)
- Run: `just check` (flake checks clippy, tests, architecture)
- Run: `just lint` (shellcheck on `tools/stack-*.sh`)
- Run: `just smoke` (opt-in stack check), `just a11y` (see [browser-tests](./browser-tests/README.md))
