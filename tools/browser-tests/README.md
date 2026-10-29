# browser-tests

## Overview

Headless-Chromium tests driven over the DevTools protocol with Python `websockets`: WCAG 2.2 AA
checks of rendered instruments and the web app, the HTML adapter's constraint enforcement, and an
end-to-end run of the browser device. They need `chromium` and `python3` with `websockets` on the
PATH (the shell wrappers obtain both from Nix when missing). Parent: [tools](../README.md). The
`vendor/` directory holds the pinned axe-core 4.10.2 (`axe-4.10.2.min.js`).

## Interface

| File | Purpose and usage |
|---|---|
| `wcag.sh [web-base-url]` | Renders the school-meals (compact and expanded layouts) and water-access (`es`) instruments with the `fieldseal` CLI (`FIELDSEAL_BIN`, default `target/debug/fieldseal`, built if missing), then runs `axe_run.py` at 1280 and 390 px and `wcag22.py`. With a URL it also checks `/instruments`, `/instruments/school-meals-baseline`, `/publishing`, `/registration`, `/device`, `/intake`. Exit 0 only with no finding. Run as `just a11y [url]`. |
| `axe_run.py WIDTHxHEIGHT url...` | Runs axe-core (WCAG 2.0, 2.1, 2.2 A and AA) on each page, walking steps and tabs so hidden panels are checked. Exports class `B`, the browser driver. |
| `wcag22.py url...` | Checks axe cannot make: 2.4.11 focus not obscured, 2.5.8 target size, 1.4.10 reflow at 320 px, 1.4.12 text spacing. |
| `constraints.py FOOD.html WATER.html` | Checks constraint enforcement in rendered pages (INS-025, INS-027, INS-133): multi-choice maximum, steppers, money maximum, exclusive options. Exit 0 if all pass. |
| `device-flow.sh` / `device-flow.py` | Drives the `/device` page of a running `fieldseal-web` (demo authority) through `device-flow.js`. Environment: `BASE` (default `http://127.0.0.1:18110`), `INSTRUMENT` (default `household-water-access`), `SHOTS` (screenshot directory), `WIDTH`, `HEIGHT`, `FLOW` (alternative flow file). |
| `device-flow.js` | Defines `window.flow`: steps `starts`, `pin`, `register`, `bundle`, `roster`, `about`, `foods`, `integrity`, `review`, `seal`, `export`, `upload`, `clear`; records checks in `window.__checks`. |

## Invariants

- Scripts exit 0 only when every check passes, 1 otherwise.
- axe-core is vendored and pinned; do not substitute another version without updating the scripts.
- Pages are checked at both 1280 px and a narrow width so reflow regressions are caught.

## Side Effects

- Launch headless Chromium with a temporary user-data directory and a local debugging port.
- `wcag.sh` writes rendered HTML to a temp directory (removed on exit) and may run `cargo build -p fieldseal-cli`.
- `device-flow.py` writes screenshots into `SHOTS` when set; `device-flow.sh` may invoke `nix shell`.
- Browsing the web app URLs requires a running instance; no other network access.

## Verification

- Run: `just a11y` (instruments only) or `just a11y http://127.0.0.1:18110` (with the web app)
- Run: `tools/browser-tests/device-flow.sh` against a running `fieldseal-web`
