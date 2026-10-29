# Fieldseal's entry points. Everything runs inside the Nix dev shell (`path:.`, because the tree
# is jj-colocated and files may be untracked), so the host needs only nix, just and a container
# engine daemon: docker, or rootless podman (see docs/how-to/run-the-local-stack.md).
set shell := ["nix", "develop", "path:.", "--command", "bash", "-euo", "pipefail", "-c"]

# docker (default) or podman
engine := env("FIELDSEAL_CONTAINER_ENGINE", "docker")
export FIELDSEAL_CONTAINER_ENGINE := engine

# List the recipes.
default:
    @just --list

# The dev loop without containers: the log, the factory and the collector stand-in, natively, with the bundled examples published; edit a survey and reload (Ctrl-C stops).
web:
    tools/dev-web.sh

# Start the local stack (builds the images with Nix, waits for every endpoint).
up:
    tools/stack-up.sh

# Publish the sample instrument through the stack's transparency log.
seed:
    tools/stack-run.sh seed

# The end-to-end demo: passkey, device registration, capture, upload, receipts (starts the stack if needed).
demo:
    tools/stack-run.sh demo

# After `just down` and `just up`: the registered device is still registered and uploads again.
resume:
    tools/stack-run.sh resume

# --- The hands-on walkthrough (docs/tutorials/hands-on.md), one step at a time ---------------

# Walkthrough 1: the authority's root, purpose keys and trust bundle.
authority:
    tools/stack-run.sh authority

# Walkthrough 2: publish the instruments and the policy (two of three signatures, the log). With a survey (a name or a folder): publish that survey through the log of `just web`.
publish survey="":
    if [ -z "{{survey}}" ]; then tools/stack-run.sh publish; else tools/dev-publish.sh "{{survey}}"; fi

# Walkthrough 3: browse the register; give an address to see one artefact in full.
registry address="":
    tools/stack-run.sh registry {{address}}

# Walkthrough 4: download a published artefact by name or address (sha256:…), verify it, and
# render an instrument to deploy/local/.out. A name shared by several artefacts is refused.
fetch artefact="school-meals-baseline":
    tools/stack-run.sh fetch {{artefact}}

# Walkthrough 5: issue the example rosters (village-a, cohort-a) at the factory; you sign in as the operator.
issue:
    tools/stack-run.sh issue

# Walkthrough 6: assign those cohorts to the collector's account (one account; its tenancies, now and later).
assign:
    tools/stack-run.sh assign

# Walkthrough 7a: register a device headless (virtual passkey, words confirmed for you).
enrol:
    tools/stack-run.sh enrol

# Walkthrough 7b: register a device with a token you got from the portal yourself.
register token:
    tools/stack-run.sh register {{token}}

# Walkthrough 7b (cont.): after confirming the words in the portal, collect the certificate.
wait:
    tools/stack-run.sh wait

# Walkthrough 8: a bundle sealed to the registered device, verified as the device verifies it.
bundle:
    tools/stack-run.sh bundle

# Walkthrough 9: the device captures (scripted) and exports.
capture:
    tools/stack-run.sh capture

# Walkthrough 10: upload the export and verify every receipt.
upload:
    tools/stack-run.sh upload

# Walkthrough 11: what intake landed for this device.
intake:
    tools/stack-run.sh intake

# Every walkthrough step in the tutorial's order, headless, against a fresh stack.
acceptance:
    tools/stack-acceptance.sh

# Containers and endpoint health.
status:
    tools/stack-status.sh

# Follow the logs; name services to narrow: just logs factory
logs *services:
    tools/stack-compose.sh logs -f {{services}}

# Stop the stack; the registered device, the passkey and the log are kept.
down:
    tools/stack-down.sh

# Stop the stack and forget everything: volumes, generated files, secrets.
purge:
    tools/stack-down.sh --purge

# Opt-in smoke check of the running stack (add --browser for the whole demo).
smoke *flags:
    tools/stack-smoke.sh {{flags}}

# Build the stack's images with Nix and load them into the engine (add demo for the demo image).
images *names:
    tools/stack-images.sh {{names}}

# shellcheck on the stack's scripts and the dev loop's.
lint:
    shellcheck -x -P SCRIPTDIR -s bash tools/stack-*.sh tools/dev-web.sh tools/dev-publish.sh

# The three flake checks CI runs: clippy, tests, architecture.
check:
    for c in clippy tests architecture; do nix build "path:.#checks.x86_64-linux.$c" --no-link --print-build-logs; done

# The migration gate for address-preserving changes: every example's expanded documents and addresses equal the golden set (Technical Plan §5).
migration-gate:
    cargo nextest run -p fieldseal-e2e --test migration_gate

# Workspace tests (in parallel, within the 20 s budget), clippy, the architecture check, the example path check and the example licence check.
test:
    python3 tools/test-inventory.py --check
    python3 tools/check-example-paths.py
    tools/test-budget.sh
    cargo clippy --workspace --all-targets --locked -- -D warnings
    python3 tools/check-architecture.py
    python3 tools/check-example-licences.py
    python3 tools/check-example-licences.py --self-test

# A release, locally: the per-release service images (loaded and tagged, not pushed) and the
# signed release record with its documentation bundle in release-docs/ (CI does the same on v*).
release tag="v0.0.0-local":
    tools/release-images.sh localhost/fieldseal {{tag}}
    tools/release-docs.sh {{tag}} release-docs

# WCAG 2.2 AA: the rendered instruments, and the web app when its URL is given (WEB-192, INS-257).
a11y url="":
    tools/browser-tests/wcag.sh {{url}}
