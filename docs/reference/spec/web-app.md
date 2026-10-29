# Showcase web app

**Prefix:** `WEB` · **Context:** none (an outer app, [ADR 0028](../../explanation/adr/0028-clean-architecture.md)) · **Runs in:** development and assessment only · **Status:** Draft

## 1. Scope

A plain, server-rendered web app that makes every stage of the system visible from a browser ([ADR 0036](../../explanation/adr/0036-showcase-web-app-and-web-device.md)): instruments, publishing, registration, a collection device and the intake. It adds no behaviour to any context. It is not a production client. The browser device it hosts is the `web` platform profile ([PLAT-100 and following](./platform-profiles.md)).

## 2. Requirements

### Pages and serving

- **WEB-100** The app MUST serve the pages Instruments, Publishing, Registration, Device and Intake, each reachable from every page, and a health probe at `/healthz`. Pages MUST be server-rendered HTML that is readable without scripts, except where a stage needs the core in the browser (WEB-122, PLAT-110).
- **WEB-130** The app MUST serve its scripts, style and the WebAssembly bundle itself, with a content security policy that allows only its own origin and WebAssembly. It MUST NOT enable cross-origin requests; other services MUST be reached through same-origin proxies.

### Instruments

- **WEB-110** The Instruments page MUST list every instrument in the configured directory, with its layouts, and MUST work with nothing but that directory (no other service).
- **WEB-111** An instrument that fails validation MUST still be listed, with its findings.
- **WEB-120** The rendered instrument MUST be byte-for-byte the output of `fieldseal instrument preview` for the same instrument, layouts, language and window class (CLI-011, INS-208).
- **WEB-121** The page MUST let the user pick the layout, the language and the window class, and MUST show the findings, the element tree, the code lists, the concepts and the rules.
- **WEB-122** The page MUST evaluate rules and field checks live from the answers typed into the rendered instrument, in the browser, using the core compiled to WebAssembly; the evaluation MUST NOT be reimplemented in script and MUST NOT be sent to the server.

### Publishing, registration, intake

- **WEB-140** The Publishing page MUST show the log's checkpoint and entries and, for each published artefact, its signatures against the threshold, its reviewers and its log inclusion proofs, each verified in the server by the publishing context, and the verdict (or the error).
- **WEB-141** Without a verifiable source the page MUST say what is and is not verified, and MUST NOT present a log's own claims as verified.
- **WEB-150** The Registration page MUST link to the factory portal where the sign-in and token happen, and explain the flow and the four-word comparison (REG-020, REG-021).
- **WEB-151** The demo authority MUST publish the example instruments with the threshold of publisher signatures and log entries that verify through the publishing context.
- **WEB-152** The demo authority MUST serve the registration API and portal through the real factory adapter.
- **WEB-153** The web app MUST build no bundle and serve none: the browser device MUST get its bundle from the factory (`GET /v1/bundle`, DIS-040), through the app's same-origin proxy, which MUST pass the device's `Fieldseal-PoP` header on and the factory's `Fieldseal-Bundle-Sequence` and `Content-Disposition` headers and a `304` back.
- **WEB-154** The demo authority MUST accept uploads through the real upload adapter and gate, and what lands MUST be visible on the Intake page.
- **WEB-155** The authority MUST provision the device with its trust bundle and publishing allow-lists as a document (DEP-024 style).
- **WEB-156** The web device MUST never be reported as attested: no component writes or alters attestation claims (TRU-061, TRU-063). To let it receive rosters, the development deployment MUST use the non-production allowance for unattested keys (REG-017) in release policy, which releases with a flag; production refuses it. The Device page MUST say "unattested software device (development policy allows it)".
- **WEB-160** The Intake page MUST run the real intake gate on an uploaded export and on what the browser device uploaded.
- **WEB-161** It MUST show the loss ledger, the landed long-format rows as they are in a table with paging and filtering by column, and the data contract. The app MUST NOT derive anything from the answers: no indicators, scores, unit conversions or per-question statistics (that is the downstream data platform's job). Operational counts the gate reports (records accepted, refused, and so on) are allowed.
- **WEB-162** It MUST offer the landed rows, unchanged, as CSV, with spreadsheet formula characters guarded.

### Device

- **WEB-170** The Device page MUST drive the browser device through: tenancy and PIN, registration (building the sealed request in the browser, submitting it, polling and showing the four words), bundle fetch and verification, capture with the real render, review, export, upload, receipts and clear, and MUST show each security step's result plainly, from the core's own report.

### Hick's Law ([ADR 0036](../../explanation/adr/0036-showcase-web-app-and-web-device.md))

The app and the device MUST conform to Hick's Law (decision time grows with the number and complexity of choices shown at once). The rules are concrete so that they can be tested from the rendered HTML:

- **WEB-180** Top-level navigation MUST have at most five destinations, in pipeline order: Instruments, Publishing, Registration, Device, Intake.
- **WEB-181** A screen MUST show exactly one primary action (one element with class `btn-primary`). Secondary actions MUST be visually quieter (outlined or text) and MUST NOT be presented as equal-weight rows or toolbars of buttons.
- **WEB-182** Secondary and advanced content (pickers, findings, trees, code lists, rules, per-artefact details, the security log, public keys, forget) MUST be behind a disclosure (`<details>`) or a tab, and MUST stay reachable without script. Pickers for layout, language and window class MUST be behind one "View options" disclosure with defaults.
- **WEB-183** The device MUST present one step at a time (Session, instrument steps following the layout, Review and seal, Export). The instrument's steps MUST follow the layout's grouping exactly (ADR 0033), and the choice-load findings of INS-210 (more than `maxDecisionsPerScreen`, default 7, questions per screen) and INS-211 (more than `maxVisibleOptions`, default 9, options without grouping) MUST be shown to the person who looks at a layout (the "Checks" tab of the instrument page), never hidden. The device does not regroup a layout to hide a finding. Note: the shipped food layouts breach INS-210 today (a category tab holds 15 to 30 questions because a food's frequency, amount and "yesterday" share one card); splitting them into smaller steps is a layout change, not a rendering one.
- **WEB-184** A recommended or default choice MUST be highlighted (the one primary action; the default layout and language in "View options"). A lengthy list (the roster, the examples) MUST be short by default.
- **WEB-185** Sealing a record MUST be a deliberate hold-to-confirm gesture with a keyboard-operable equivalent.

### Constraints shown and enforced

- **WEB-186** For every declared constraint of a control (minimum and maximum of number, stepper, money, date and measurement; maximum number of choices; maximum length; exclusive codes; tolerance of measurement pairs; required and nonresponse; `when` and protected display) the page MUST show it, MUST refuse values that break it at the page (typed input included, not only through attributes), and the core's problem (INS-025, INS-026, INS-027) MUST be shown; a value that breaks a constraint MUST NOT be stored or sealed by the device (COL-035).
- **WEB-187** The visual system MUST follow the Android app's design system (palette, type, radii, 52 px targets, flat surfaces): the fonts MUST be bundled locally with no runtime font fetch.

### Configuration

- **WEB-190** The app MUST refuse to start when `FIELDSEAL_ENVIRONMENT` is `production`.
- **WEB-191** Configuration MUST come from the environment only (twelve-factor III), documented at the top of `main.rs`; missing or invalid settings MUST be startup errors.
- **WEB-192** Every page of the web app MUST conform to WCAG 2.2 Level AA under the same tests as INS-257. Authentication MUST NOT rely on a cognitive function test without help (3.3.8): the PIN and passphrase fields MUST allow password managers and pasting (`autocomplete="new-password"` or `"current-password"`, never `"off"`).

## 3. Conformance

Server tests drive the routes without sockets; the instrument parity test compares bytes against the preview path for every layout, language and window class of the examples. Native device tests run the same Rust as the WebAssembly build against the demo authority over HTTP. A headless-browser run loads each page and checks that the WebAssembly loads without console errors.
