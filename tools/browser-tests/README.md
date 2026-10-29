# browser-tests

## Overview

Headless-Chromium tests driven over the DevTools protocol with Python `websockets`: WCAG 2.2 AA
checks of rendered instruments and the web app, the HTML adapter's constraint enforcement, and an
end-to-end run of the guided demo (the browser device included) and of the device on a phone-sized window. They need `chromium` and `python3` with `websockets` on the
PATH (the shell wrappers obtain both from Nix when missing). Parent: [tools](../README.md). The
`vendor/` directory holds the pinned axe-core 4.10.2 (`axe-4.10.2.min.js`).

## Interface

| File | Purpose and usage |
|---|---|
| `wcag.sh [web-base-url]` | Renders the school-meals (compact and expanded layouts) and water-access (`es`) instruments with the `fieldseal` CLI (`FIELDSEAL_BIN`, default `target/debug/fieldseal`, built if missing), then runs `axe_run.py` at 1280 and 390 px and `wcag22.py`. With a URL it also checks `/demo`, `/demo/1` to `/demo/8`, `/instruments`, `/instruments/school-meals-baseline`, `/publishing`, `/registration`, `/device`. Exit 0 only with no finding. Run as `just a11y [url]`. |
| `axe_run.py WIDTHxHEIGHT url...` | Runs axe-core (WCAG 2.0, 2.1, 2.2 A and AA) on each page, walking steps and tabs so hidden panels are checked. Exports class `B`, the browser driver. |
| `wcag22.py url...` | Checks axe cannot make: 2.4.11 focus not obscured, 2.5.8 target size, 1.4.10 reflow at 320 px, 1.4.12 text spacing. |
| `constraints.py FOOD.html WATER.html` | Checks constraint enforcement in rendered pages (INS-025, INS-027, INS-133): multi-choice maximum, steppers, money maximum, exclusive options. Exit 0 if all pass. |
| `cookies.sh` / `cookies.py` | Control 4 of the design's section 7.2: with the collector stand-in on `127.0.0.1` and the factory and intake portal on `localhost`, the browser sends no `fs_session` or `fs_intake_session` cookie to the stand-in. Signs in at both services (`--login NAME` completes it at the development IdP), requests every stand-in page and checks the Cookie headers, with a positive control for the factory. Run by `tools/dev-web.sh --check --browser` and `tools/stack-smoke.sh --browser`. |
| `demo-e2e.sh` / `demo-e2e.py` | The eight steps of the guided demo, headless, against a running `just web` (CUJ 4). Runs the real `fieldseal` and `tools/dev-publish.sh` for steps 1, 2 and 5; signs in at the development IdP as `presenter` for the factory portal (token, four words, confirm) and the results reader; drives the Device page with `device-flow.js` for steps 3, 4, 6 and 7; reads `/demo/1` to `/demo/8`; and asserts each confirmation against its independent source (the CLI output, the log's checkpoint, `GET /v1/registrations`, `factory.log`, the downloaded export file, the results reader). Needs state it may change (it issues a roster version and registers a device). Options: `--collector`, `--factory`, `--results`, `--log`, `--state`; environment `FIELDSEAL_BIN`. Run by `tools/dev-web.sh --check --browser`. |
| `phone-fit.sh` / `phone-fit.py` | The browser device on a phone (WEB-189): for the presenter (water survey) and collector1 (school-meals survey) it registers a device, then in a 390 x 844 window checks that the list of surveys, the roster, the consent screen, every step of the form in the compact layout and the review need no scrolling (the page does not scroll, nothing on the screen is cut off, the form's own scroll height fits its frame, the primary action is fully in view). Only the lists of people, surveys and answers may scroll inside themselves; the test fills each to 12 rows to show the screen still fits and its primary action stays in view, and injects a tall element to show the check fails on overflow. Needs a running `just web` with those two assignments; run by `tools/dev-web.sh --check --browser` after the guided demo. Options: `--collector`, `--factory`, `--state`. |
| `picker.sh` / `picker.py` | The survey picker (WEB-188): collector2 is assigned both example surveys for one cohort (`fixtures/picker-a.yaml`, issued and assigned by `tools/dev-web.sh --check --browser` in its own state), so Your surveys shows one group; on the roster the test chooses each survey in turn, starts a capture for the first person and backs out. The roster's consent covers the water survey only, so the meals survey shows the person's consent as unknown and asks for it on the device before the capture. Options: `--collector`, `--factory`, `--state`. |
| `device-flow.js` | Defines `window.flow` and `window.flowStep(name)`: steps `starts`, `pin`, `register` (uses `window.TOKEN`), `registered`, `bundle` (the list of surveys, then the chosen one), `roster`, `about`, `foods`, `integrity`, `review`, `seal`, `export`, `upload`, `clear`, `newer` and `next-person`; records checks in `window.__checks`. Evaluated in the Device page by `demo-e2e.py`. |

## Invariants

- Scripts exit 0 only when every check passes, 1 otherwise.
- axe-core is vendored and pinned; do not substitute another version without updating the scripts.
- Pages are checked at both 1280 px and a narrow width so reflow regressions are caught.

## Side Effects

- Launch headless Chromium with a temporary user-data directory and a local debugging port.
- `wcag.sh` writes rendered HTML to a temp directory (removed on exit) and may run `cargo build -p fieldseal-cli`.
- `demo-e2e.sh` may invoke `nix shell`; `demo-e2e.py` writes a temporary directory (the survey it scaffolds and the export it downloads), removed at the end.
- Browsing the web app URLs requires a running instance; no other network access.

## Verification

- Run: `just a11y` (instruments only) or `just a11y http://127.0.0.1:18110` (with the web app)
- Run: `tools/browser-tests/demo-e2e.sh` against a running `just web`
