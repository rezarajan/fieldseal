# Build and check the project

This guide covers building the Rust core, Android app and HQ wheel, locally or in the release container. For the tool versions and platform limits, see the [toolchain reference](../reference/toolchain.md). For why the build is set up this way, see [How the build works](../explanation/build-system.md).

## Before you start

- Install Nix with flakes enabled, and Podman or Docker with BuildKit.
- Check your host in the [platform support table](../reference/toolchain.md#platform-support). ARM Linux has no Android SDK, so build the APK in the container there.

## Enter the developer shell

```sh
nix develop path:.
```

Use `path:.` rather than `.`. jj does not stage files in git's index, and Nix uses the index to find flake files. Using the Android SDK through Nix means accepting Google's Android SDK licence (`android_sdk.accept_license = true` in `flake.nix`).

## Build and check locally

```sh
tools/build.sh && tools/check-portable.sh dist
```

`tools/build.sh` builds the core, the Android libraries and bindings, the APK and its unit tests (on hosts with the Android SDK), and the wheels into `dist/`. `check-portable.sh` fails if any artefact depends on Nix or leaks a builder path, and names the file and the reason.

## Run the Python vector tests

```sh
tools/test-python-vectors.sh
```

Inside the dev shell, this builds the Python binding, copies the module into a scratch directory and runs `crates/bindings/python/tests/test_vectors.py` against the kernel's golden vectors in `crates/kernel/tests/vectors/`. Nothing is installed.

## Run the end-to-end and fault-injection suites

```sh
cargo test -p fieldseal-e2e
```

`crates/apps/e2e` is a test-only crate (`publish = false`) that runs the whole flow in one process over the in-memory adapters, with the simulated phone standing in for Android: the connected flow (root ceremony, publishing with threshold signatures and the log, portal token, registration with confirmed words, a sealed bundle, capture, background upload, receipt, clear), the air-gapped flow (files and `FS1R:` text only, no network), two devices of one collector (the limit of two, bundles that cannot cross, intake keeping records apart), and fault injection (damaged and truncated exports, parity repair at 4 shards and failure at 5, reordered, duplicated and missing frames, power cuts at every storage step of seal, clear and close, a clock reset, a replayed upload token, an expired registration token, a bundle for another tenancy, a withdrawn artefact, a tampered log checkpoint). Each test is named by the requirement it proves.

To watch the connected flow through the real `fieldseal` commands instead, with software keys and a summary at the end:

```sh
tools/demo-pipeline.sh [work-dir]
```

It builds the CLI if needed and leaves every file it made in the work directory. The device and intake stages use the practice authority, as `fieldseal device simulate` and `fieldseal intake` do.

## Check which requirements have tests

```sh
python3 tools/check-coverage.py
```

Every test names the requirement IDs it covers ([spec conventions](../reference/spec/README.md#conventions)); a requirement without a test is a gap. The report counts, per spec, the defined requirements, the ones that say MUST, how many have a test, and how many MUST requirements don't. It only reports: `tools/build.sh` runs it after the architecture check and never fails on it.

A test names a requirement in either of two ways:

- its function name contains the lowercase ID, as `fn ins_126_repeat_expands_in_list_order` after `#[test]` (or `def test_ins_126_...` in Python, or a Kotlin function after `@Test`);
- a comment above it lists IDs: `// covers: INS-126, WIRE-002` (`# covers:` in Python). `INS-050..INS-053` names a range.

Useful options:

```sh
python3 tools/check-coverage.py --list-uncovered INS        # the gaps in one spec
python3 tools/check-coverage.py --json                      # for other tools
python3 tools/check-coverage.py --fail-under-must INS=80 WIRE=100   # exit 1 below a threshold
```

`--fail-under-must` is how CI can ratchet a spec's MUST coverage up once its tests exist. The tool's own tests are `python3 tools/check_coverage_test.py`.

## Build release artefacts in a container

```sh
podman build --target artifacts --output type=local,dest=dist .
```

With Docker, name the file, because Docker only looks for `Dockerfile` by default:

```sh
docker buildx build -f Containerfile --target artifacts --output type=local,dest=dist .
```

To skip provisioning the toolchain, build on the published builder image. See [Reuse the CI images](./reuse-ci-images.md).

## Smoke-test the HQ wheel

```sh
podman build --target smoke .
```

This installs the wheel on a plain Debian image and imports it.

## Only the container build makes release artefacts

Local builds are for development. Use the `artifacts` target above for anything that ships, and take the unsigned APK from `dist/` to HQ for signing.
