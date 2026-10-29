# Showcase web app

**Prefix:** `WEB` · **Context:** none (an outer app, [ADR 0028](../../explanation/adr/0028-clean-architecture.md)) · **Runs in:** development and assessment only · **Status:** Draft

## 1. Scope

A plain, server-rendered web app that makes every stage of the system visible from a browser ([ADR 0036](../../explanation/adr/0036-showcase-web-app-and-web-device.md)): instruments, publishing, registration, a collection device and the intake. It adds no behaviour to any context. It is not a production client. The browser device it hosts is the `web` platform profile ([PLAT-100 and following](./platform-profiles.md)).

## 2. Requirements

### Pages and serving

- **WEB-100** The app MUST serve the pages Guided demo, Instruments, Publishing, Registration and Device (Intake is a page of the intake app, WEB-154), each reachable from every page, and a health probe at `/healthz`. Pages MUST be server-rendered HTML that is readable without scripts, except where a stage needs the core in the browser (WEB-122, PLAT-110).
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
- **WEB-151** The app MUST be served against the real factory, transparency log and upload endpoint, whose base URLs it reads from its environment, and every page that shows authority state (publications, registration state, receipts) MUST read it from the service that holds it and say plainly when that service is unreachable.
- **WEB-152** The app MUST provision the device with the authority's trust bundle and the publishing allow-lists as a document (DEP-024 style), read from the trust bundle file and the rendered environment.
- **WEB-153** The web app MUST build no bundle and serve none: the browser device MUST get its bundle from the factory (`GET /v1/bundle`, DIS-040), through the app's same-origin proxy, which MUST pass the device's `Fieldseal-PoP` header on and the factory's `Fieldseal-Bundle-Sequence` and `Content-Disposition` headers and a `304` back.
- **WEB-154** The app MUST have no Intake page (`/intake` is 404): what the device uploads goes to the intake app's upload endpoint, and results are read in the results reader (INT-089). Pages MAY link to the results reader.
- **WEB-155** The app MUST hold no authority state: no key, seed, session or in-process authority. It MUST start and serve every page with no key material in its environment. Its proxy MUST forward only to the configured factory, upload and log URLs and never to the intake portal, and the content security policy of its pages MUST name no service origin.
- **WEB-156** The web device MUST never be reported as attested: no component writes or alters attestation claims (TRU-061, TRU-063). To let it receive rosters, the development deployment MUST use the non-production allowance for unattested keys (REG-017) in release policy, which releases with a flag; production refuses it. The Device page MUST say "unattested software device (development policy allows it)".
- **WEB-160** *Withdrawn.* The gate on an uploaded device export has no successor here: the upload endpoint is the production route and the file route is a CLI path.
- **WEB-161** *Withdrawn.* Became INT-092: the results reader derives nothing from the answers.
- **WEB-162** *Withdrawn.* Became the CSV rule of INT-085: text cells that start with a formula character are prefixed with `'`, and numeric values never are.

### Guided demo

- **WEB-195** The app MUST serve a guided demo at `/demo` and `/demo/{1..8}`. Each step page MUST show a title, one sentence on what happens, who performs the step in production, how to do it (a link to the page where the action is done, or for a command-line step the exact command, which the app never runs), a confirmation panel, and Back and Next links.
- **WEB-196** The guided demo MUST perform no action for the authority: it MUST hold no credential, MUST make no request to a service other than GET, and MUST have no route that records a confirmation.
- **WEB-197** Each confirmation MUST be read from the service or device state named beside it, MUST link to a place where the same value exists independently, and MUST label the device's own view as such. Step 8 MUST show only a link to the results reader and confirm nothing.
- **WEB-198** `/demo` and the Device page MUST show a banner stating that the collector stand-in stands in for the native Android and iOS apps, which do not exist yet.
- **WEB-199** Step 3 MUST tell a presenter who runs the demo again to retire the old device on the factory portal (REG-043) before registering a new one, and the last page MUST name `just acceptance` and `just release`.

### Device

- **WEB-170** The Device page MUST drive the browser device through: tenancy and PIN, registration (building the sealed request in the browser, submitting it, polling and showing the four words), bundle fetch and verification, capture with the real render, review, export, upload, receipts and clear, and MUST show each security step's result plainly, from the core's own report.

### Hick's Law ([ADR 0036](../../explanation/adr/0036-showcase-web-app-and-web-device.md))

The app and the device MUST conform to Hick's Law (decision time grows with the number and complexity of choices shown at once). The rules are concrete so that they can be tested from the rendered HTML:

- **WEB-180** Top-level navigation MUST have at most five destinations, in pipeline order: Guided demo, Instruments, Publishing, Registration, Device.
- **WEB-181** A screen MUST show exactly one primary action (one element with class `btn-primary`). Secondary actions MUST be visually quieter (outlined or text) and MUST NOT be presented as equal-weight rows or toolbars of buttons.
- **WEB-182** Secondary and advanced content (pickers, findings, trees, code lists, rules, per-artefact details, the security log, public keys, forget) MUST be behind a disclosure (`<details>`) or a tab, and MUST stay reachable without script. Pickers for layout, language and window class MUST be behind one "View options" disclosure with defaults.
- **WEB-183** The device MUST present one step at a time (Session, instrument steps following the layout, Review and seal, Export). The instrument's steps MUST follow the layout's grouping exactly (ADR 0033), and the choice-load findings of INS-210 (more than `maxDecisionsPerScreen`, default 7, questions per screen) and INS-211 (more than `maxVisibleOptions`, default 9, options without grouping) MUST be shown to the person who looks at a layout (the "Checks" tab of the instrument page), never hidden. The device does not regroup a layout to hide a finding. The shipped compact layouts show at most four questions on a step, one food to a step, so that INS-210 (an error for a compact layout) holds; the expanded food layout still breaches it as a warning.
- **WEB-184** A recommended or default choice MUST be highlighted (the one primary action; the default layout and language in "View options"). A lengthy list (the roster, the examples) MUST be short by default.
- **WEB-185** Sealing a record MUST be a deliberate hold-to-confirm gesture with a keyboard-operable equivalent.
- **WEB-188** After unlocking, the device MUST show "Your surveys": one row for each survey group in the held bundle's assignments (WIRE-096), a group being the surveys assigned to one cohort at one generation. A row MUST be titled by its survey titles, in the device's language, with the cohort shown only as who to visit and the number of people. The list MUST come from the bundle and from no other request, MUST be searchable when it has more than four rows, MUST offer "Check for new surveys" (the verified bundle fetch, DIS-040) and, when nothing is assigned, MUST say so and say that an operator assigns surveys in the factory portal. The collector chooses one group, which MUST stay the active group across sessions in this browser. A group of several surveys MUST let the collector choose which survey to conduct for the people in it (the choice stays across sessions in this browser, for each group); a survey the roster's consent does not cover MUST show the person's consent as unknown (COL-031); a survey that is no longer in the bundle MUST say so, with the way back to "Your surveys"; the device names a survey to the runtime by its fingerprint, never by its name; each person is sealed, consented and started for one survey at a time, and the device MUST refuse a survey for a person whose cohort it is not assigned to (COL-111); the roster screen MUST be titled by the survey, not the cohort, and a clear action MUST switch group. A device with no bundle MUST say that loading it loads the surveys assigned to the account.
- **WEB-189** At a phone window (390 x 844) no screen of the device MAY need scrolling: the page does not scroll, and the current task and its primary action are in view on the list of surveys, the roster, the consent screen, every step of the form in a compact layout and the review. The status line, the security log and the device's details MUST be behind one secondary "Details" control. A long list (the people, the surveys, the answers) MAY scroll inside its own area, and only those lists may; the primary action of the screen MUST stay fully in view however long the list is. `tools/browser-tests/phone-fit.sh` checks it for both example surveys, with a long list on each screen that has one, and checks that it fails when page content overflows.

### Constraints shown and enforced

- **WEB-186** For every declared constraint of a control (minimum and maximum of number, stepper, money, date and measurement; maximum number of choices; maximum length; exclusive codes; tolerance of measurement pairs; required and nonresponse; `when` and protected display) the page MUST show it, MUST refuse values that break it at the page (typed input included, not only through attributes), and the core's problem (INS-025, INS-026, INS-027) MUST be shown; a value that breaks a constraint MUST NOT be stored or sealed by the device (COL-035).
- **WEB-187** The visual system MUST follow the Android app's design system (palette, type, radii, 52 px targets, flat surfaces): the fonts MUST be bundled locally with no runtime font fetch.

### Configuration

- **WEB-190** The app MUST refuse to start when `FIELDSEAL_ENVIRONMENT` is `production`.
- **WEB-191** Configuration MUST come from the environment only (twelve-factor III), documented at the top of `main.rs`; missing or invalid settings MUST be startup errors.
- **WEB-192** Every page of the web app MUST conform to WCAG 2.2 Level AA under the same tests as INS-257. Authentication MUST NOT rely on a cognitive function test without help (3.3.8): the PIN and passphrase fields MUST allow password managers and pasting (`autocomplete="new-password"` or `"current-password"`, never `"off"`).

## 3. Conformance

Server tests drive the routes without sockets; the instrument parity test compares bytes against the preview path for every layout, language and window class of the examples. Native device tests run the same Rust as the WebAssembly build against the demo authority over HTTP. A headless-browser run loads each page and checks that the WebAssembly loads without console errors. `tools/browser-tests/demo-e2e.sh` runs the eight steps of the guided demo headless against a running `just web` and finds each confirmation's identifiers at their independent sources (WEB-195 to WEB-199), and `tools/browser-tests/phone-fit.sh` runs the device in a 390 x 844 window and checks that no screen scrolls (WEB-189).
