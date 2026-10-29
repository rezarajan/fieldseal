# Field Collection Aids: Probes, Broad Answers, Verified Entry and Survey Overlays

* **Author:** Reza Rajan
* **Date:** 2026-10-29 (revised with the owner's decisions of the same date)

## Overview

Collectors reported three problems from the field:

1. **Wording drifts.** They word the same question differently from one interview to the next, so results vary.
2. **Some answers are only known broadly.** When an interviewee does not understand a question, the collector needs to record the answer at a broader category (for example "cereals" when "rice" or "maize" can't be determined).
3. **Some answers need double confirmation.** The confirmation should be declared in the survey schema, with its own syntax and types.

A fourth need came from programmes: some want to use a standardised survey and add questions of their own, while still conforming to the standard. The standard's owner must be able to say, in a way that is checked cryptographically, whether the survey can be modified, added to, or not changed at all.

The work is now four features:

- **Probes.** Each interviewer question may list approved follow-ups (`probes`) with stable ids, shown only to the collector. There is no `script` field. For interviewer surveys `label` stays the exact words read aloud (INS-150 is unchanged). A separate read-aloud field is deferred until `administration: both` needs it.
- **Hierarchical code lists.** A code may have a parent, and the collector may answer at the parent level (a broad answer). The recorded code shows how specific the answer was. Fieldseal does not roll answers up; analysts do that downstream.
- **Verification.** `verify: retype | read-back` is declared in the survey. Retype is for typed values: the value is entered a second time without the first being visible. Read-back is for choices: the collector reads the selected answer back and the interviewee confirms it.
- **Overlays with a modification policy.** A base instrument declares `modification: locked | extend | modify`. An overlay names a published base by content address and adds only what the policy allows. Every verifier recomputes this.

The overlay feature and the aids are designed together. A standard survey must be able to forbid the very aids the collectors asked for (probes, broad answers, verification), because those change how a question is asked and what its answers mean. Otherwise the data of a locked survey stops being comparable between programmes.

**Motivating evidence.** As a test, the owner had a real, licence-restricted standard questionnaire ported locally (the Global Diet Quality Project's DQQ, Trinidad and Tobago edition, CC BY-NC-ND 4.0). The port was never committed and its text is not in this brief. It expressed fine as 33 yes/no questions in 8 groups with an introduction. But the form's own restrictions (read exactly as written, no added probing, no adding or removing items, supplementary questions only at the end) could not be expressed or enforced. Section 10 has the findings.

### Owner decisions of 2026-10-29

- **D1.** Amend instrument schema 1.0 in place before the first release (M4). No MAJOR version. Multi-major support becomes a follow-up issue for after the release.
- **D2.** No `script` field. `label` stays the words read aloud. Add `probes` only. A read-aloud field is deferred until `administration: both` needs it.
- **D3 to D13.** The reviewers' recommendations are taken as written (see Key Decisions). Each counter-argument is kept as a recorded risk.
- Hierarchical code lists and verification stay in scope.
- Overlays and the modification policy are new and in scope, with the decisions in section 9.

### What the six reviewers found

Six reviewers (design, codebase details, zoom-out, comprehension, implementation readiness and structure) stress-tested the earlier plan against the specs, ADRs, examples and code. They agreed that the problems are real and the features are worth building, but that parts of the plan clashed with rules the project already has. The owner's decisions resolve the first two:

- **The MAJOR version.** Resolved by D1.
- **`script` and `label`.** Resolved by D2.
- **Roll-up.** The "the tool derives nothing" rules (INS-226, INS-228, INT-083, INT-092) forbid Fieldseal from rolling answers up.
- **Evidence in the record.** The record value format is closed (WIRE-052).

Two of the three kinds of evidence can be worked out from the code and the instrument, so they don't need to be stored at all. Only "which probe was used" is genuinely new information per record. There is also no Android runtime to change today.

## Analysis

Findings are grouped by theme and ordered by severity within each theme. References are to `docs/reference/spec/*.md` requirement IDs and to paths under `crates/` unless stated otherwise. Sections 1 and 2 are rewritten for the decisions; sections 3 to 8 are the reviewers' findings, edited where a decision changes them; sections 9 and 10 are new.

### 1. Versioning: amend schema 1.0 in place (decided, D1)

**Decision.** The changes are made to schema 1.0 before the first release (M4). There is no MAJOR bump and no 1.1. Nothing is deployed: ADR 0040 says "nothing is released yet", `apiVersion` is `v1alpha1`, and M4 is the first release.

**Why this is allowed.**
- Schema 1.0 has already been changed in place: INS-011/INS-070 `hint` became `data` (amended 2026-10-27), and `groups` became `atomicGroups`. WIRE-212 is the precedent for amending a version before its first release.
- INS-090 defines these changes (`probes`, a code `parent`, `verify`, a `within()` rule function, `modification`, overlay documents) as additions. They would be minor in a released world, and amending 1.0 has the same effect without the cost.

**What this removes from the plan.**
- No dual-major runtime, no stranded registered devices, no re-registration, no key roll for the format change (INS-092, DIS-012, REG-091, REG-060 are not triggered).
- No "unsupported major" intake finding, no cross-fingerprint resume (COL-032/033), no mixed-major factory tests, no double publication of each survey for rollback.

**What still has to be done.**
- Every instrument and layout fingerprint changes (INS-200). Golden sets under `crates/apps/e2e/tests/golden/expanded/` and `crates/contexts/instrument/tests/golden/*.plan` must be regenerated deliberately, in one revertible commit.
- `just migration-gate` (ADR 0041 §5, `docs/designs/developer-experience-first.md` CUJ 7) asserts that example addresses don't change. It needs a deliberate re-baseline, not a silent one.
- `docs/reference/spec/README.md` line 13 says breaking changes need a new `apiVersion`, while INS-090 versions the schema independently of `apiVersion`. Reconcile them in the ADR.
- The compact dialect hard-codes `^1.0` (`crates/adapters/authoring/src/compact.rs:306`), so authors never see a schema range. That stays.
- INT-070 keys landed data by fingerprint. Because nothing is deployed there is no old data to strand, but the re-baseline must be done before any pilot data exists.

**Recorded risk (the counter-argument to D1).** The post-release multi-major question (INS-092, WIRE-130 `schema` as a list, intake keeping old decoders for INT-012 replay) is only postponed. If it is not answered before the first real major, that major causes a collection outage. It becomes its own issue, scheduled after the release (see the issue list).

**Constraint kept from the earlier findings.** The runtime still rejects an instrument whose range it does not cover (INS-092, strict readers INS-006). Amending in place means every runtime built before the amendment is simply out of date. Because nothing is released, this is acceptable, but a build of the CLI, factory and device from different commits will disagree on fingerprints. The runbook must say so.

### 2. Probes and the meaning of `label` (decided, D2)

**Decision.** No `script` field. For interviewer surveys `label` stays the exact words read aloud (INS-150, "the question as asked", is unchanged). The new field is `probes`: approved follow-ups for vague answers, each with a stable id, shown only to the collector, separate from `guidance`.

**What this removes.**
- The two-texts-both-claim-to-be-"as-asked" blocker: there is one text.
- The repeat-set problem for scripts (a read-aloud text naming the food in "How often does the pupil eat {food}?"). The existing `label` already has to solve it for repeats (INS-126, INS-047, INS-084). Probes inherit whatever `label` does, and the probe text may use the same variables.
- Doubling of per-question translatable text. Only probes add text.

**What stays open from the earlier findings.**
- The root cause of wording drift may lie in the authoring dialect: `compact.rs:721-725` fills in a missing label from the question id, the dialect has no `short-label` although the canonical `shortLabel` exists (`decode.rs:886`), and the `school-meals-baseline` labels are headings (`Weight`, `Height`, `School`) or third-person notes. So authors write headings and collectors improvise the question. Stage 0 fixes this (a `short-label` key, no filled-in labels for interviewer questions, a lint for labels that look like headings).
- **Lint noise.** A lint for labels that look like headings must be advisory (like INS-210 to INS-213), give one finding per declared question, and exempt roster items, `measure-twice`, observed items and repeat expansions, or `survey check --strict` fails the examples.

**Probes: rules.**
- **Stable ids.** INS-259 forbids positional `msgctxt`, and the "which probe" evidence must survive reordering. Probes behave like a per-question code list `{id, text}`, keyed `instrument/<path>.probes.<id>` (fits `crates/adapters/authoring/src/po.rs:46-64`), and stable like codes (INS-136).
- **Path namespace.** The role suffixes `.help`, `.guidance` and `.description` already share the path namespace (`compact.rs:565,727`). A question named `help` collides today. Reserve role words as path segments (INS-012), including `probes`.
- **Collector-only.** INS-151 hides `guidance` only for `self`. The HTML renderer filters only `self` (`crates/adapters/html/src/render.rs:693`), and the render plan has no idea who is holding the device (`render_plan.rs:289-291`). `household-water-access` is a `both` survey, so probes would leak to the subject. Until D11 is built, probes are rejected on `both` surveys or hidden whenever the mode is not known to be interviewer.
- **Translation.** INS-260 falls back to English when a translation is missing or stale. An English probe read aloud in a Spanish interview defeats the purpose. A missing or stale probe in any declared language is an error (D13).
- **Reuse.** `guidance` already flows end to end and `probes` can copy that path: model `element.rs:147`; decoder `decode.rs:888`; compact key `compact.rs:727-731`; `.po` contexts; render plan; self-mode stripping `application/render.rs:295`; lint `lint.rs:168`.
- **Cost.** Probes add translatable text and TRAPD review under INS-083. Bundle size is negligible (about 15 to 20 KB per language for 40 questions).

**Deferred.** A separate read-aloud field, needed only when `administration: both` must show different text to a collector and to a subject reading alone. Record this in the ADR so the name (`read-aloud` or `wording`, D12) is reserved.

### 3. Hierarchical code lists: roll-up is forbidden, and rules silently misfire

**Blocker: Fieldseal may not roll answers up.**
- INS-228 says a mapping from a code to a classification "MUST be expressed only as `concept` codes … No component MAY aggregate, sum, score or look them up to produce a value".
- INS-226, INT-083 and INT-092 forbid deriving values in intake and the results reader.
- "Exports can roll up" must therefore mean that the contract and `codebook.csv` carry each code's parent chain as unevaluated metadata, and analysts roll up downstream.
- A per-row "precision" column is a lookup from the code list. It would need an explicit INS-228 exception. It is also redundant, because the recorded value already is the parent code.

**Blocker: rules on a leaf ignore parent-level answers.**
- `{eq: [food, rice]}` is false when the answer is `cereals`. A follow-up gated on the leaf is hidden, and intake derives `not-applicable` for it (INS-142). That misstates the data: the follow-up did apply, but the answer was too coarse to show it.
- `lookup()` misses the parent key and returns *unset*, so soft rules never fire. The `low-use` check in `household-water-access` has exactly this shape. `value()` of a parent without a `value` is also *unset* (INS-048).
- Fix:
  - keep `==`, `!=` and `in` as exact equality, so existing records replay identically under INT-012;
  - add `within(path, code)` (ancestor-or-self) to the rule language, and `{under: [...]}` to the compact dialect;
  - add golden vectors in `crates/contexts/instrument/tests/vectors/rules.json`;
  - lint `eq`/`in` against a code that has a selectable ancestor.

**Major: there are now three hierarchy mechanisms.**
- Concept schemes already have `parent` forests (INS-242, depth 8 at most).
- `household-water-access` already classifies sources as improved or unimproved through `concept`.
- INS-211 mentions a "code-list grouping" that nothing defines.
- Concepts MUST NOT change validation (INS-171), and whether a parent can be answered is validation. So the boundary must be stated: a code-list `parent` is an answer at a coarser level; a concept is an unevaluated classification for later analysis.

**Major: the shape must stay flat.**
- Use `parent: <code>` on a flat list. Don't use dotted codes like `cereals.rice`, which break INS-012, INS-126, INS-136 stability, and `msgctxt` keys.
- `CodeList::contains`, `Scope::new` and `Reader::code` keep working unchanged.
- Moving a code under a different parent changes its meaning (INS-136). Extend the ADR 0040 code-pinning check to parents.
- Compact codes are slugs of labels (`compact.rs:457,462`), so two children both called "Other" under different parents collide. `parent:` must reference a pinned code.

**Major: interactions with other code-list features need a rule each.**
- Multi-choice: an ancestor and its descendant must be mutually exclusive, like INS-133; `max` counts selected codes.
- `exclusive` on a parent: forbid.
- `other`: keep one per list (INS-134/137 `.other` paths would collide).
- Repeats over a hierarchical list (`compile.rs:210` makes one instance per code): forbid, or repeat over leaves only.
- `scale` and `ordered` lists (INS-135): forbid hierarchy.
- `value` on parents (INS-132): forbid.
- Field checks `duplicates` and `straightlining` compare codes exactly: state that, and don't "fix" it.
- Extension code lists inherit the INS-131 shape (INS-241), which needs an extension meta-schema minor (INS-251).

**Major: a parent answer is a value, not a nonresponse.**
- The `nr` set is closed (WIRE-052, INS-143). Don't add `nr: partial`.
- Lint codes labelled like "cereal, don't know which", which are the sentinel codes INS-143 forbids.
- `dont-know` stays available, and it records a different fact.

**Major: the motivating example may not match the design.**
- "Rice under cereals" in `examples/surveys/school-meals-baseline/instrument.yaml:95-153` is a repeat per food (`categories:` → `foods:` → `ask:`), not a choice list.
- If the field complaint is "she can only tell me how often she eats cereals in general", a hierarchical code list doesn't help. That case needs a category-level repeat instance.
- Confirm with collectors which case they meant before writing the ADR.

**Major (collector UX): a selectable parent invites lazy answers.**
- If "Piped water" sits in the same list as its children, it is the cheapest tap. INS-140 already handles the same risk for nonresponse: it is offered as "distinct actions next to the control, never as options in it".
- Recommended UX:
  - show the leaves grouped under non-selectable parent headers, which also gives INS-211 its grouping;
  - offer the broad answer as a quieter secondary action ("Only knows: Piped water") after the script and probes;
  - make whether parents can be answered a property of the question (`broad-answer: allowed`), not of the list, so one list can serve a strict and a lenient question.
- **Performance:** `Reader::list` clones the whole `CodeList` on every evaluation (`evaluation.rs:521-525`), and `set_value` evaluates twice (`capture.rs:331,341`). Large food or occupation trees make this worse on low-end devices.

### 4. Confirmed entry: semantics, overlap and accessibility

**Blocker: the lifecycle is undefined.**
- **Pause between the two entries.** COL-034 seals whatever is set. The first blind entry must be UI-only state that is never written to the pending record and never sealed.
- **Mismatch clears both.** This contradicts INS-253 (a refused input leaves "the control keeps its previous state"). In a resurvey it would retract an existing value. Resurvey must restore the prior value, and a mismatch must not loop forever: after the second mismatch, offer the declared nonresponse actions or a reason.
- **Resurvey and correction.** `content()` re-emits unchanged values inside atomic groups and roster `record: true` items (`capture.rs:428-446`). Confirmation must be required only for values set or changed in the current capture.
- **Nonresponse** on a confirm item: recommend no confirmation needed.
- **Equality.** Compare after locale normalisation and NFC (INS-088, WIRE-004), not raw keystrokes.

**Major: `reenter` overlaps `measure-twice`.**
- `measurement-pair` / `measure-twice` (INS-026, `compact.rs:821-838`, `evaluation.rs:456-467`) is already "enter twice, agree within a tolerance", and it records both readings.
- `reenter` differs in two ways: it is blind, and it requires an exact match with one value recorded. Its real value is catching keying errors in IDs and phone numbers, which a range constraint can't catch.
- Forbid `confirm` on `measurement-pair` and `roster`, and give a clear error. Consider a check-digit rule function as a cheaper alternative for IDs.
- Implementation trap: `crates/apps/web/assets/answers.js:28-33` reads two numeric inputs in one question as a measurement pair, so a two-input re-entry UI would be misread.

**Major: `readback` is weak evidence and its semantics are unclear.**
- It is a self-attested tap by the same collector. An existing soft rule with reasons already models "please confirm it" (`school-meals-baseline` `large-amount`: "Confirmed with the pupil").
- It means nothing in self mode. Under `both`, no record says which mode a capture used.
- Zoom-out recommends dropping it. Comprehension and design say keep it only if it is inline, per question, never hold-to-confirm, and the record says the device never speaks.

**Major: new constraint kinds can't be checked yet.**
- INS-254 requires `ControlCatalogue` to list constraint kinds and `CheckCompatibility` to reject missing ones. Neither is implemented: `crates/contexts/instrument/src/ports.rs:11-43` and `application/compatibility.rs` check only controls, presentations and languages.
- Without this, an old UI could render a `confirm` item without confirming it. This is a prerequisite.

**Major: accessibility.**
- Blind re-entry runs into WCAG 2.2 SC 3.3.7 (Redundant Entry), which INS-257 and WEB-192 test. The "essential" exception applies, but it must be documented.
- The second field needs its own label, a live-region mismatch announcement (4.1.3), autofill and IME suggestions off, and paste refused. All of these need INS-255/256 corpus cases.
- On Android, AND-027 blocks TalkBack by default on managed devices.
- Show "this answer is entered twice" before typing (WEB-186).

**Major: collector fatigue.**
- Re-entry roughly doubles keying time on its items, and readback and probe logging add taps.
- Allow an optional `when:` condition, don't let `defaults:` switch verification on for every question, and add an advisory count lint.
- Existing `timing` checks (`min-seconds`) will shift.

### 5. Evidence in sealed records: most of it should not be stored

**Blocker: the record format has no room for it as described.**
- WIRE-052 allows exactly two map values (`{nr}` and `{retracted}`). INT-072 and `ItemsPayload::from_value` (`crates/kernel/src/payload.rs:293`) reject unknown fields.
- Wrapping a value (`{v, confirmed, probes}`) breaks every value reader.
- A new payload-level map next to WIRE-053 `overrides`/`flags` needs a record structure version (WIRE-151). That is a separate version axis from the instrument schema, and `record/v1` has no per-payload version.
- A payload-level map doesn't fold per item (INT-053). A resurvey that changes a value would leave the old evidence attached to the new value.
- Precedent warning: `overrides` sits in such a side map and is never landed. No code in `crates/contexts/intake` reads it, and `LONG_COLUMNS` has no column for it.

**Major: two of the three kinds of evidence can be worked out without storing them.**
- **Answered at category level:** the recorded code already says this. Put `parent` (and optionally a depth) on each code in the contract (`ContractCode`, `data_contract.rs:69`) and the codebook (`codebook.rs:26`). Storing it per row is a stored derived value (INS-226).
- **Confirmed:** if a `confirm` item cannot be sealed unconfirmed (a hard gate, re-checked at seal and at intake replay, INS-253 and INT-012), then every value of that item is confirmed by construction. The instrument fingerprint in the record proves the rule applied. A per-row flag would only carry information if confirmation could be skipped.
- **Probe used** is the only fact that is new per record.

**Major: the sibling-path route avoids any wire change.**
- `<path>.unit` (INS-161) and `<path>.other` (INS-137, `QuestionOrigin::OtherText` in `compiled.rs:42-55`) already carry metadata next to a value inside `values`.
- A synthesised `<path>.probes` item (an array of probe ids, data type `codes`) would:
  - need no wire bump;
  - be replayed automatically;
  - land with no new export columns;
  - follow the `.unit` fold rule: a value set without the annotation clears the earlier one.
- First centralise the suffix handling. `.unit` is hard-coded in at least seven places (`capture.rs:315,332`, `evaluation.rs:242-245,364-371`, `landing.rs:104-119,229,253`, `answers.js:50-51`).
- Possible existing bug: `local.rs:104-110` and `Capture::clear_value` (`capture.rs:345-349`) remove a retracted item but not its `.unit` sibling. Any new sibling would inherit this.

**Major: export and landing.**
- `LONG_COLUMNS` is a fixed `[LongColumn; 20]`, and the snapshot reader requires exactly that header (`landing-files/src/snapshot.rs:4-6,140`). New columns make existing `observations.csv` unreadable without migration or replay.
- `EXPORT_SCHEMA_VERSION` 1.0.0 must become 1.1.0 (INT-085). `docs/how-to/export-results-to-parquet.md` and `tools/browser-tests/demo-e2e.py:431` need updating.
- Rows from 1.x and items without `confirm` must read as null, never `confirmed=false`.

**Observability: what analysts and operators can see.**
- **Analysts**
  - The codebook carries `parent_code`, a leaf flag, and the probe texts in every language (INT-071).
  - The data contract says plainly that probe use and readback are recorded by the collector themselves, not independently verified.
  - An empty probe set means "none recorded", not "none used".
- **Collector QA**
  - Probe-usage rate and broad-answer rate fit as advisory field-check kinds (the `data_contract.rs:482-504` machinery, INS-053).
  - Re-entry mismatch counts per capture are useful process data (paradata), but storing them costs a wire change.
- **Operators**
  - Rejections caused by an unreadable instrument need their own reason in intake (`replay.rs:102`, `instruments.rs:47`), the export reader and the factory, rather than being swallowed. A failed overlay check (section 9) needs its own reason too.
- **Administration mode** isn't recorded per capture, so under `both` an analyst can't tell whether a readback had an interviewer present.

### 6. Platform scope

**Blocker: there is no Android runtime.** The UniFFI bindings export only `core_version()` and `runtime_profile()` (`crates/bindings/uniffi/src/lib.rs:7-31`). WEB-198 says the native apps "do not exist yet". "Works on Android offline" can't be accepted. In practice the scope is the format core, the wasm, uniffi and python bindings, the HTML preview, and the web device.

**Major: the shared conformance corpus doesn't exist yet.**
- There is no `tests/constraints/` directory (INS-255). The only constraint suites are `crates/apps/web/tests/browser_constraints.rs` and `tools/browser-tests/constraints.py`.
- The new scenarios depend on infrastructure that is specified but not built.

### 7. Naming collisions

Several proposed terms already mean something else in Fieldseal:

| Proposed term | Already means | Suggested alternative |
|---|---|---|
| `evidence` | consent photo evidence (WIRE-055/056), the `evidence` data type (INS-070), attestation evidence | "capture annotations" or "paradata" |
| `confirm` | hold-to-confirm (INS-024, WEB-185, COL-040), soft-check confirmation, consent "I confirm" | `verify: retype \| read-back` |
| `readback` | the delivery read-back check (DEL-023/024, PLAT-020) | `read-aloud` |
| `script` | writing systems (INS-089, `ControlCatalogue`); executable code (INS-244) | Not added (D2). `read-aloud` or `wording` reserved for the deferred field |
| `category`, `precision` | food `categories:` blocks; decimal precision in the export | "parent code", "broad answer" |
| `probe` | service health probes (`/readyz`) | keep it, with a glossary entry |

### 8. Spec and docs footprint

- **New ADR 0042.** It refines ADR 0032 (text roles, code lists, nonresponse) and ADR 0037 (derive nothing, entry enforcement), and depends on ADR 0034 and ADR 0041.
- **`instrument.md`.**
  - New IDs from INS-262 upward.
  - Amend INS-012, INS-090/092, INS-131–137, INS-140–143 (clarify), INS-150/151, INS-164, INS-228 and INS-252–256.
- **Other specs.**
  - `wire-formats.md` only if the side-map route is chosen.
  - `collection.md`: COL-032–036.
  - `intake.md`: INT-051, INT-056, INT-071, INT-085, INT-088.
  - `platform-profiles.md`: PLAT-067/068.
  - Reconcile `docs/reference/spec/README.md` line 13 with INS-090.
- **The compact dialect has no normative reference.** Its keys live only in ADR 0040 (Proposed) and in `compact.rs`. Give it a reference home (`docs/reference/survey-folder.md` or a new `survey-dialect.md`) before adding keys.
- **Docs to update:** the tutorials, `export-results-to-parquet.md`, the glossary, `conformance.md` and `test-inventory.md`.

### 9. Survey overlays and the modification policy (new)

**The need.** A programme wants a standardised survey plus a few questions of its own. The standard's publisher wants to state, and have checked, one of three things: nothing may change, things may be added in specified places, or the survey is a starting point to modify freely.

**What exists today.**
- INS-112: `spec.derivedFrom: [{title, version?, citation, url?}]` is a citation only. Nothing resolves it, checks it or limits what the derived survey does. INS-112 also requires `spec.copyright` (notice and SPDX licence id) when the source is under copyright, and INS-113 requires runtimes to show it.
- ADR 0041 (survey source tree) fixes how a survey is laid out and compiled in a folder. An overlay has to fit that layout (a survey folder that names a base instead of carrying the whole instrument) or it needs its own.
- `docs/reference/spec/publishing.md`: the content address is the SHA-256 of the canonical CBOR bytes (PUB-020, PUB-021, WIRE-011); approvals are tied to that address (PUB-011); a publication carries publisher signatures over `{kind, name, version, address, provenance_sha256}` (PUB-040, PUB-041); the public transparency log (ADR 0030, §5.10) records publications.
- `distribution.md` and `trust.md`: the factory builds bundles from published instruments, and devices verify what they import against the trust bundle.

**Mechanism.**
1. **Policy in the base.** The base instrument declares `modification: locked | extend | modify`.
   - `locked`: no change to anything that affects the questions, rules, code lists, checks or the data they produce. Presentation-neutral content (a programme name in a header) is only allowed if the base lists it.
   - `extend`: the overlay may add content only at the extension points the base names (for example `end`, or named points between sections). Everything else is locked.
   - `modify`: no restriction. A derived survey is a new survey that cites its source.
   - The policy is part of the base's content and so part of its signed publication. Changing it means a new base version with a new address.
2. **Overlay names its base by address.** The overlay holds `base: {name, version, address}`, where `address` is the base's content address as recorded in the transparency log. Its own publication records the same base address in the signed structure or its provenance, so the link is part of what publishers sign and reviewers approve (PUB-011).
3. **Digest of inherited content.** Define a canonical digest of the base content the overlay inherits (the base's canonical bytes with the extension-point slots empty). The overlay's resolved form is the base content plus the added content at the allowed points. The verifier recomputes the digest of the base-derived part of the resolved form and compares it with the base's own.
4. **What each verifier recomputes.**

| Verifier | Recomputes | Refuses |
|---|---|---|
| `survey check` (compiler) | Fetches or reads the base by address, checks the address against the bytes, recomputes the inherited-content digest, applies the policy | Overlay changes locked parts; adds content outside the extension points; adds probes, broad answers or verification to base questions; base address not found or not matching |
| Factory (bundle build) | Same check at build time, against the log entry for the base address; records both addresses in the bundle | Any failure above; a base address that is withdrawn (PUB §5.9) unless policy allows |
| Device (bundle import) | Same check from the base and overlay carried in the bundle, with signatures verified against the trust bundle | Bundle whose overlay does not verify against its base; policy downgrade (base in the bundle declares a weaker policy than the one the overlay's publication recorded) |
| Intake | Same check when it learns an instrument, and again for replay (INT-012); records the base address with the landed instrument | Records for an overlay that fails the check; records whose instrument has no resolvable base |

   The check must be the same code in all four places (the format core), not four implementations.
5. **Collection aids and the lock.** Under `locked` or `extend`, an overlay may not add probes, broad answers (parent-level answers) or verification to the base's questions. The overlay's own added questions may use them. Only the base publisher adds aids to base questions, in a new base version. Under `modify` there is no restriction.

**Threats and how the design answers them.**
- **An overlay claims a base it changed.** The overlay's digest of inherited content is recomputed from the base bytes found by address, never taken from the overlay. A verifier that cannot get the base bytes refuses; it does not trust the claim.
- **A forged base address.** The address is a hash of the base's canonical bytes (PUB-021), so a different base has a different address. An attacker can only point at a different real base, for example an old one with `modify`. Verifiers must check that the address is in the transparency log and that the log entry is signed by the publisher threshold (PUB-040). Whether the overlay's publisher is allowed to extend that particular base is a separate trust question (see D19).
- **Policy downgrade by republishing a base with `modify`.** A new base version has a new address. Existing overlays still name the old address and keep the old policy. A new overlay naming the new base is a different survey line. The risk is that a base publisher (or a stolen key) republishes the same name and version range with a weaker policy so that new overlays are accepted. Mitigations: the policy is signed (PUB-040/041) and logged; a weaker policy than the previous version of the same base name is flagged by the compiler and by the log checker as a downgrade and needs an explicit marker in the base's publication plus the usual approvals; tightening is not flagged.
- **Mixed-overlay data at intake.** Two overlays of one base have different fingerprints and so land as unrelated instruments (INT-070). The base's columns must still be comparable. See the data checks below.
- **Withdrawal of a base** (PUB §5.9). Existing overlays and their data are not invalidated, but new bundles must not be built from a withdrawn base unless policy allows.
- **Verifier disagreement.** A bug in one verifier would admit a bad overlay. The shared core, plus golden vectors for accepted and refused overlays, is the answer.

**What must be checked so a locked base's data columns stay comparable across overlays.**
- The base's questions keep the same paths, data types, code lists (codes, parents, `value`s), units, nonresponse sets and rules, so an overlay's contract contains the base's columns unchanged (INS-136 stability, INS-143).
- The intake data contract and codebook mark each column as `inherited` (with the base address) or `added` (by this overlay). A downstream analyst can select all inherited columns across overlays and know they mean the same thing.
- Added questions may not reuse or shadow a base path. Their paths live under a prefix the overlay owns (reserve the segment, INS-012).
- Rules in the overlay that depend on base answers (a follow-up gated on a base question) read them without changing them. Rules must not make a base question conditionally hidden: that changes its applicability (INS-142) and so the data.
- The export (`LONG_COLUMNS`, INT-085) needs an instrument-lineage column or a join to the contract so inherited rows can be pooled. Choosing between one table and two is an open decision (D16).
- Under `extend`, an overlay's added content at the `end` point cannot change a base question's applicability, because it comes after the last base question and cannot alter what was asked before it.

**Docs and specs to touch.**
- A new ADR (0043, after ADR 0042) on overlays, the policy, the base address and the digest. ADR 0042 covers the aids and the lock.
- `instrument.md`: amend INS-112 (a citation stays for `modify` and unrelated sources; `base` is the checked link); add `modification` and the overlay document. `publishing.md`: the base address in the publication record, the check at build and the downgrade flag. `distribution.md` and `trust.md`: bundle contents and import verification. `intake.md`: INT-070 lineage, INT-071 codebook, INT-085 export.

**Recorded risk.** Overlays add a second kind of instrument document, a resolution step in every verifier and a new trust relationship (who may extend which base). Each is a place for a bug. The alternative of allowing only `locked` bases that are copied unchanged avoids this, but gives programmes no way to add their own questions.


### 10. Findings from the DQQ test

The ported survey (never committed, text not reproduced here) showed what works and what does not.

**What worked.** 33 yes/no questions in 8 groups with an introduction to read aloud. `fieldseal survey check` passes, with one advice and one Hick's-law warning. The preview renders it faithfully. Intake generates its data contract. The format can hold a real standard questionnaire of this kind.

**What Fieldseal could not express**, from the form's stated restrictions:
1. **"Read exactly as written; no additional dialogue or probing questions."** Nothing prevents probes or broad answers being applied to such a survey. The new aids would break comparability if they were. Covered by `locked` plus "the lock covers collection aids" (section 9).
2. **"Do not add or remove food items. Supplementary questions can be placed at the end."** Nothing checks a derived survey against its source. Covered by `extend` with an `end` extension point, and by the inherited-content digest, which also catches removal.
3. **The licence (CC BY-NC-ND 4.0) is metadata only.** Nothing stops a translation or a modified copy, and both are derivatives under ND. Two questions follow, both open, see D17 and D18: whether the modification policy also governs translations, and whether the licence id should inform the policy.
4. **Why aids and overlays are designed together.** A standard survey must be able to forbid the very aids the collectors asked for. If probes, broad answers and verification could be added by anyone, a standard's data would not be comparable between programmes, and the standard's publisher could not enforce its own rules.

**Conformance fixture.** Do not use the real text. Build a test survey written for the project, original, with the same shape: a yes/no list in groups, an introduction, a `locked` or `extend` policy, and overlays that pass and fail each rule above.


## Goals vs. Non-Goals

**Goals**
- Collectors read the same approved wording (`label`) in every interview, in the interview's language, with approved follow-ups (`probes`) at hand.
- A collector can record a less specific answer when that is all the interviewee can give. It is recorded as a real code, and the analyst can see that it is less specific.
- Identifiers and other high-stakes typed values can be entered twice, blind, with a defined outcome on mismatch, pause and resurvey.
- Analysts get the parent chain and probe use in the contract, codebook and export. All of it is labelled honestly as self-reported where it is.
- A standard survey's publisher can declare `locked`, `extend` or `modify`. Every verifier (compiler, factory, device, intake) recomputes the check, and the declaration is part of the signed publication.
- A locked or extensible base cannot have collection aids added to its questions by an overlay.
- A locked base's data columns stay comparable across all overlays of it, and the contract says which columns are inherited.
- Every new constraint is refused at entry by every UI that exists, with corpus cases, and runtimes that lack it are rejected by `CheckCompatibility`.
- The web device, preview and bindings work offline.
- Schema 1.0 is amended in place before M4, so no version migration exists.

**Non-Goals**
- A MAJOR version, dual-major runtimes, or multi-major intake. Deferred to a follow-up issue after the release (D1).
- A `script` or read-aloud field. Deferred until `administration: both` needs it (D2).
- Fieldseal computing roll-ups, precision columns or aggregates (INS-226, INS-228, INT-092). Roll-up happens downstream.
- Encoding hierarchy in the code string itself.
- Treating a broad answer as nonresponse.
- Recording probe text, or probes that are not on the approved list (v1).
- Device text-to-speech for read-back.
- Enforcing a licence legally. The policy is a technical control; the licence id informs lint only (D18).
- Building the native Android UI. That is separate work. This feature only ensures the bindings and `ControlCatalogue` expose what it will need.
- Landing WIRE-053 `overrides` as part of this feature. It is worth doing separately.

## Key Decisions & Staging for Next Steps

### Decided by the owner (2026-10-29)

Each decision gives the choice, then the strongest counter-argument, which is kept as a recorded risk.

**D1. Versioning. Decided: amend schema 1.0 in place before M4.** No MAJOR version, as already done for `hint`→`data`, with WIRE-212 as precedent. Multi-major support (INS-092, WIRE-130, intake keeping old decoders) is a follow-up after the release.
- **Risk:** the multi-major question is only postponed. The first real major after M4 hits a collection outage if the follow-up is not done first.

**D2. `label`, `script` and `probes`. Decided: no `script`.** `label` stays the exact words read aloud for interviewer surveys (INS-150 unchanged). Add `probes` only: approved follow-ups with stable ids, collector-only. A read-aloud field is deferred until `administration: both` needs it.
- **Risk:** `both` surveys cannot show different wording to collector and subject until that field exists. Labels that are headings stay a problem until Stage 0 is done.

**D3. Where probe-use evidence lives. Decided: a synthesised sibling item `<path>.probes`** holding stable probe ids, on the `.unit` and `.other` precedent. No wire change. Centralise suffix handling first.
- **Risk:** it mixes process data into answer rows and multiplies suffixes. A typed `annotations` map is cleaner for analysts, at the cost of a record-structure bump, dual-version intake and a rollout order of intake, then factory, then devices.

**D4. Stored "confirmed" and "answered at category level". Decided: not stored.** Category level comes from the code plus the contract's `parent`. Verified is guaranteed because verification is a hard gate (nonresponse exempt), re-checked at seal and at replay.
- **Risk:** analysts want a ready filter column without a join. If read-back can ever be skipped, a per-value state becomes necessary, and a three-state value adds a third state to every analysis.

**D5. Probe tracking. Decided: show probes now as one-tap chips that record the probe id.** If no analyst has a concrete use, ship display only first.
- **Risk:** the data is self-reported by the collector being studied and under-reports under time pressure. Showing probes fixes wording drift; recording their use does not. Against that, process data not captured can never be added later.

**D6. Hierarchy and who may answer at a parent. Decided:** `parent:` on flat code-list codes decides what may be answered; `concept` stays descriptive, with a warning when the two disagree; a per-question opt-in `broad-answer: allowed`; the broad answer is a secondary action next to the control, not a peer option.
- **Risk:** one hierarchy (INS-242) would avoid drift between the two. A per-list setting is simpler to write. A two-step drill-down is more natural but adds a tap to every specific answer.

**D7. Choice answers or food-frequency repeats. Decided: confirm with the collectors before the ADR is written.** If it is the food-frequency case, design category-level repeat instances as well.
- **Risk:** hierarchical lists are the smaller step and help other surveys now, so waiting delays them for an answer that may not change the design.

**D8. Rule semantics over a hierarchy. Decided:** `==`, `!=` and `in` stay exact. Add `within(path, code)` and lint leaf comparisons where an ancestor can be answered.
- **Risk:** no new function at first would be simpler, with `in [...]` lists and a lint. Hand-written lists drift when the code list changes.

**D9. Verification semantics for retype. Decided:** the first entry is never written, including on pause; on mismatch clear the attempt and restore the prior value, and after the second mismatch offer nonresponse or a reason; paste is refused in the second field; verification is required only for values changed in the current capture; retype applies to typed number, money, text and date only, never `measurement-pair`, `stepper` or `roster`.
- **Risk:** clearing loses the first value, which an analyst studying entry error might want. Steppers can be mis-tapped too.

**D10. Keep read-back. Decided: keep it,** per question and inline, interviewer administration only (rejected on `self`), never hold-to-confirm, documented as the collector speaking and not the device.
- **Risk:** it is a self-attested ritual with little evidential value, and a soft rule with reasons already covers "please confirm". Auditable read-back belongs in consent (INS-060).

**D11. Administration mode under `both`. Decided:** choose the mode per capture and record it, hiding probes and read-back in self mode. Until that exists, forbid these features on `both` surveys.
- **Risk:** recording the mode per capture is a wire or annotation change that the feature otherwise avoids.

**D12. Names. Decided:** `probes` with explicit ids; `verify: retype | read-back` instead of `confirm`; `broad-answer: allowed`; "capture annotations" instead of "evidence". `read-aloud` (or `wording`) is reserved for the deferred field.
- **Risk:** field staff and other tools (CAPI) say "script", "probe" and "readback", so renaming loses familiarity. Add glossary entries and a collision note.

**D13. Platform scope and translation strictness. Decided:** acceptance covers the core, bindings, preview and web device, with Android UI conformance deferred; build the shared `tests/constraints/` corpus first; a missing or stale probe translation is an error, not an English fallback.
- **Risk:** the field request names Android explicitly. Strict translation blocks publishing over a single missing probe in one language.

### Open decisions: overlays

**D14. Extension-point syntax.**
- **Recommendation:** the base declares `modification: extend` with `extensionPoints: [end, <name>...]`. `end` always exists; other points are named markers placed between sections (`after-section: <group-id>`), so an overlay can only add whole questions or groups at a named point, never inside a group. Names are stable ids, reserved like code ids.
- **Counter:** named points inside groups give programmes more room, but each one lets added content change the base group's flow and screen. Only `end` (what the DQQ test needs) is simpler, and points can be added later.
- **Decided 2026-10-29:** as recommended (`end` plus named after-section points).

**D15. May an overlay be extended by another overlay?**
- **Recommendation:** no. An overlay names a base that is not itself an overlay. One level only.
- **Counter:** a national overlay extended by a regional programme is a real pattern. Chaining needs the policy to be transitive (the weakest policy in the chain governs), a digest per level, and verifiers that walk a chain, each a place for bugs. If needed later, allow it by an explicit `chainable` flag in the base.
- **Decided 2026-10-29:** as recommended (one level; a `chainable` flag may come later).

**D16. Does intake land base and overlay columns in one table?**
- **Recommendation:** keep the current rule that each instrument fingerprint lands as its own instrument (INT-070), and add lineage: the contract and codebook mark each column `inherited` (with the base address) or `added`, and the export carries the base address so inherited columns can be pooled across overlays with a single filter. Do not merge tables.
- **Counter:** one table per base, with added columns null for other overlays, is easier for analysts. It needs intake to merge instruments with different fingerprints, which breaks the "fingerprint is the unit" assumption, makes sparse columns, and risks silently mixing data from overlays whose rules interact with base answers.
- **Decided 2026-10-29:** as recommended (one table per fingerprint, with lineage columns).

**D17. Do translations fall under the modification policy?**
- **Recommendation:** yes. Under `locked`, a translation is allowed only if the base publisher signed it: it is part of a base version, or of a translation publication that names the base address and is signed by the base's publisher keys. Under `extend`, translations of the base part follow the same rule; the overlay may translate its own added questions. Under `modify` anyone may translate.
- **Counter:** this makes a `locked` base hard to use in a language its publisher does not provide, which is the main reason programmes want it. A translation changes the wording, but so does interpreting; some standards allow certified translations by third parties. A rule requiring a signature from the base publisher blocks those.
- **Decided 2026-10-29 (amended):** the base may list `translators:` (publisher keys). With no list, only the base publisher may translate a `locked` or `extend` base; this allows certified third-party translators when listed.

**D18. Should the licence id inform the policy?**
- **Recommendation:** lint only. `survey check` warns when an `-ND` licence id is paired with `modify`, and warns when an `-ND` licence base has no `locked` or `extend` policy. The licence is never enforced by the policy.
- **Counter:** a warning is easy to ignore, and the licence says the opposite of the policy. An error would be stricter but would block legitimate cases (the publisher holds the rights and can modify) and makes the SPDX string drive behaviour, which INS-112 only requires as metadata.
- **Decided 2026-10-29:** as recommended (lint only).

**D19. Who may publish an overlay of a given base?**
- **Recommendation:** the base may list `overlayPublishers` (publisher keys or an identity set). If it does, only those can publish overlays; if it does not, any publisher in the trust bundle can, subject to the policy. The check is done in the same verifiers.
- **Counter:** the policy already controls what an overlay can do, so an allow-list adds a second thing to manage and can block a programme that has done nothing wrong. Without it, anyone can attach their content to a standard and have it appear related to it.
- **Decided 2026-10-29:** as recommended (optional `overlay-publishers:`; one allow-list mechanism shared with D17).

### Proposed staging

- **Stage 0, no format change.**
  - `short-label` in the dialect, and no labels filled in from ids for interviewer questions.
  - Lint labels that look like headings.
  - Probes written as `guidance` text for now.
  - Broad "unspecified" codes plus a `concept` parent in the examples.
  - Confirm D7 with collectors.
- **Stage 1, the format change (schema 1.0 amended in place, D1).**
  - `probes` with ids.
  - Code-list `parent` with a per-question opt-in, on `choice` only first.
  - `within()`.
  - `verify: retype` as an INS-252 constraint kind (needs INS-254 first).
  - `parent` and leaf flag in the contract and codebook.
  - The `.probes` sibling (D3).
  - Web device, preview and bindings.
- **Stage 2, overlays.**
  - `modification` in the schema and compiler.
  - Overlay authoring, the shared inherited-content check, and the check in the factory, device and intake.
  - Lineage in the contract and export.
  - Licence and translation lint.
  - The conformance fixture.
- **Stage 3, on demonstrated need.**
  - Read-back.
  - Drill-down presentation for large trees.
  - Hierarchy in `multi-choice`.
  - Recording the administration mode per capture.
  - Process data such as mismatch counts.
  - Overlay chaining (D15).
- **After M4:** multi-major runtime and intake policy.

### Proposed GitHub issues

Labels follow the project's area labels; each issue also carries a type. Milestone M4 unless noted.

1. **docs(adr): record field collection aids and the in-place amendment of schema 1.0**
   - Records D1 to D13: amending 1.0 before M4, probes without `script`, the verification and hierarchy semantics, and the self-reported nature of probe data.
   - States that code-list parents are metadata and Fieldseal never rolls up (amend INS-228). Reconciles `spec/README.md` line 13 with INS-090. Amends ADR 0032 and ADR 0037 where needed.
   - Labels: `area/docs`, `architecture`.
2. **feat(cli): add `short-label`, stop filling labels from ids, lint heading-like labels**
   - Stage 0 dialect changes in `crates/adapters/authoring/src/compact.rs` and `lint.rs`, as an advisory lint with exemptions. Gives the compact dialect a normative reference page.
   - Labels: `area/cli`, `task`.
3. **feat(cli): add question `probes` with stable ids**
   - Amend INS-150/151/152 and INS-012 (reserved role words). Add `msgctxt` `instrument/<path>.probes.<id>`, make missing translations an error, and reject on `both` surveys until D11 exists.
   - Carry probes through the model, decoder, render plan, self-mode stripping and `.po` extraction.
   - Labels: `area/cli`, `task`.
4. **feat(cli): add hierarchical code lists and the `within()` rule function**
   - `parent:` on INS-131 codes, a forest with depth at most 8, a per-question `broad-answer` opt-in, rules for multi-choice, `exclusive`, `other`, repeats, `scale` and `value`, rule vectors, lints, and the INS-136 check for moved codes.
   - Labels: `area/cli`, `task`.
5. **feat(cli): report constraint kinds in `ControlCatalogue` and `CheckCompatibility` (INS-254)**
   - A prerequisite for any new constraint kind. Today `compatibility.rs` checks only controls, presentations and languages.
   - Labels: `area/cli`, `task`.
6. **feat(cli): add `verify: retype` and `verify: read-back` entry constraints**
   - D9 and D10 semantics: the first entry is never sealed, mismatch and resurvey behaviour, nonresponse exemption, NFC equality. A seal gate in `capture.rs` `readiness()`, an INS-164 value problem and INS-252 table rows. Forbidden on `measurement-pair`.
   - Labels: `area/cli`, `task`.
7. **refactor(cli): centralise annotation suffixes and add the `.probes` sibling item**
   - One suffix helper and a typed `QuestionOrigin::Annotation` replacing hard-coded `.unit` handling. Fix the stray-`.unit`-on-retract bug if confirmed. Add the synthesised `.probes` item and its fold rule.
   - Labels: `area/cli`, `task`.
8. **feat(intake): add parent, leaf flag and self-reported caveats to the contract, codebook and export**
   - `ContractCode.parent`, codebook `parent_code` and leaf flag, and the self-reported caveat text. Export schema 1.1.0 and a snapshot-reader migration only if columns are added. Parquet how-to and demo test updates.
   - Labels: `area/intake`, `task`.
9. **test(ci): create the shared `tests/constraints/` conformance corpus**
   - Retype, paste, read-back, ancestor/descendant exclusion, for first collection and resurvey (INS-255/256), plus WIRE-213 authoring corpus entries and rule vectors for parent codes.
   - Labels: `area/ci`, `task`.
10. **feat(web): add probe chips, the broad-answer action, blind re-entry and read-back**
    - Fix the `answers.js` two-input pairing trap. WCAG 3.3.7 essential-exception note, live-region mismatch, autofill and IME off. Pass `ins-ui-constraints` and `just a11y`.
    - Labels: `area/web`, `task`.
11. **feat(cli): expose the new render-plan nodes and constraint kinds through UniFFI and wasm**
    - Add a read-back acknowledgement call modelled on `acknowledge_incomplete`. Android UI is deferred until the app exists.
    - Labels: `area/cli`, `task`.
12. **chore(docs): migrate the examples, re-baseline goldens and the migration gate, update tutorials and glossary**
    - Regenerate `crates/apps/e2e/tests/golden/expanded/**` and the instrument `.plan` goldens deliberately in one revertible commit. Add glossary entries for the new terms.
    - Labels: `area/docs`, `task`.
13. **docs(devshell): write the rollout runbook for the in-place schema amendment**
    - Order: core and intake, then factory, then examples, then device. All components must be built from the same commit because fingerprints change. Revisit at M5.
    - Labels: `area/docs`, `documentation`.
14. **feat(cli): add `modification: locked | extend | modify` to the instrument schema and compiler**
    - Schema field, extension points (D14), signed as part of the base content. Reject `extend` without extension points. Amend INS-112 and add INS-IDs. Includes the policy-downgrade check against the previous version of the same base name.
    - Labels: `area/cli`, `architecture`.
15. **feat(cli): add overlay authoring and `survey check` base verification**
    - Overlay document naming a base by content address, the shared inherited-content digest in the format core, refusal of changed locked parts and content outside extension points, and refusal of probes, broad answers and verification added to base questions. Fits ADR 0041's survey folder.
    - Labels: `area/cli`, `task`.
16. **feat(factory): verify overlay and base at bundle build, device import and intake**
    - Run the same core check in the factory, on device import and in intake (including replay, INT-012). Record both addresses in the bundle and the landed instrument. Handle a withdrawn base. Add the base address to the publication record and check it against the transparency log.
    - Labels: `area/factory`, `area/intake`, `area/translog`, `task`.
17. **feat(intake): add overlay lineage to the data contract, codebook and export**
    - Mark columns `inherited` or `added`, carry the base address in the export, and check that a locked base's columns are identical across overlays (D16). Export schema bump if columns change.
    - Labels: `area/intake`, `task`.
18. **feat(cli): lint licence and translation against the modification policy**
    - Warn on an `-ND` licence paired with `modify` (D18). Implement the D17 translation rule as amended: optional `translators:` keys; with no list, only base-publisher-signed translations pass for a `locked` or `extend` base.
    - Labels: `area/cli`, `task`.
19. **test(ci): add a DQQ-style conformance fixture from an original survey**
    - A survey written for the project (never the DQQ text): a yes/no list in groups with an introduction, a `locked` or `extend` base, and overlays that pass and fail each rule (changed locked part, content outside `end`, added probe, forged base address, policy downgrade, mixed overlays at intake).
    - Labels: `area/ci`, `task`.
20. **docs(adr): record survey overlays and the modification policy**
    - ADR 0043: the policy, the base address, the inherited-content digest, threats, D14 to D19, and the data-comparability checks. Amend `publishing.md`, `distribution.md`, `trust.md` and `intake.md`.
    - Labels: `area/docs`, `architecture`.
21. **feat(cli): support multiple schema majors after the release**
    - Follow-up, after M4. INS-092, WIRE-130 `schema` as a list, intake keeping old decoders for INT-012 replay, resume across fingerprints, and an explicit "unsupported major" finding. Answers the risk recorded under D1.
    - Labels: `area/cli`, `area/intake`, `architecture`. Milestone after M4.
